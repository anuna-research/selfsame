//! The three routes SPEC-001 adds to the `did-crdt` service.
//!
//! SPEC-001 §6.12 places the rendezvous mailbox, signed-closure resolution, and
//! state publication on *"the `did-crdt` service (existing)"* — routes on a
//! service already deployed for resolution. This crate is the **reference
//! implementation of those three routes**, so the contracts can be exercised
//! end to end here before they are upstreamed.
//!
// SIMPLIFY: in-memory storage with a sweeper — adequate for development and for
// the TEST-020/025/029/036 integration suites; replace with the `did-crdt`
// service's SQLite persistence layer when these routes are upstreamed
// (trace: SPEC-001 §6.12, SPEC-034 in did-crdt).
//!
//! ```text
//!   PUT/GET /rendezvous/{slot}       CON-002  blind: sees H(s) and ciphertext
//!   POST    /dids/{did}/deltas       CON-006  idempotent, durable-ack
//!   GET     /dids/{did}/closure      CON-005  signed deltas, not a document
//! ```
//!
//! # The one thing this server must not do
//!
//! **It makes no trust decision.** CON-002: *"it is a blind mailbox and MUST NOT
//! inspect the ciphertext or hold any key"*. CON-005 post-condition 3:
//! *"the server applies no profile and its opinion is not consumed"*. The
//! closure route hands back signed deltas precisely so the verifier can apply
//! REQ-003 and REQ-008 itself — upstream's `GET /:did` returns a *resolved* W3C
//! document, which carries no signatures, and a verifier consuming that would
//! simply be trusting the resolver's authorisation decisions (REQ-025).
//!
//! The one check the publication route *does* perform is a signature check
//! against the DID's own genesis — not to decide trust on a client's behalf,
//! but so the store cannot be filled with garbage by anyone who knows a DID.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use did_crdt::core::delta::{DeltaOp, SignedDelta};
use did_crdt::core::document::Document;
use did_crdt::Did;
use serde::{Deserialize, Serialize};

/// `PROTO-003` `CON-405`'s relay and `PROTO-002`'s mailbox.
pub mod pairing;

/// Maximum accepted rendezvous body (CON-002).
pub const MAX_SLOT_BYTES: usize = 4096;

/// The largest `CON-409` record this store accepts.
///
/// Six short members and a timestamp; the contract's own recogniser bounds it at
/// 4 KiB, and a store that accepted more would be holding bytes no conforming
/// resolver will read.
pub const MAX_RECORD_BYTES: usize = 4096;

/// Slot lifetime in seconds (CON-002).
pub const SLOT_TTL_SECONDS: u64 = 600;

/// A stored mailbox entry.
struct Slot {
    ciphertext: Vec<u8>,
    stored_at: u64,
    read: bool,
}

/// Server state. Deliberately holds no key material of any kind.
#[derive(Clone, Default)]
pub struct Service {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Default)]
struct Inner {
    slots: HashMap<String, Slot>,
    documents: HashMap<Did, Document>,
    /// Deltas exactly as published, so the closure route can return the bytes
    /// the signer produced rather than a re-serialisation of them. REQ-003
    /// hashes those exact bytes, so a re-serialisation is not the same artefact.
    closures: HashMap<Did, Vec<serde_json::Value>>,
    /// `CON-409` records, keyed by the base64url meeting address.
    records: HashMap<String, Record>,
    /// `PROTO-003` `CON-405` sessions, keyed by nameplate.
    sessions: HashMap<String, pairing::Session>,
    /// `PROTO-002` `CON-304` slots. Separate from `slots` because the two
    /// contracts disagree about size, retry, and whether a read is repeatable —
    /// see the table in [`pairing`].
    mailbox: HashMap<String, pairing::MailboxSlot>,
}

/// A published `CON-409` record, exactly as its publisher signed it.
struct Record {
    /// The RFC 8785 octets. Held verbatim, because a verifier checks a signature
    /// over the bytes it received and a re-serialisation is a different artefact
    /// — the same reason `closures` keeps published deltas as they arrived.
    payload: Vec<u8>,
    signature: [u8; 64],
    stored_at: Now,
}

/// A monotonic second counter injected by the caller.
///
/// The service is effectful by nature, but keeping "now" a parameter means the
/// expiry rules are testable without sleeping.
pub type Now = u64;

impl Service {
    /// Build an empty service.
    pub fn new() -> Self {
        Self::default()
    }

    /// The axum router.
    ///
    /// Two mailbox routes, and the second is not a duplicate. `/rendezvous/:slot`
    /// is SPEC-001's `CON-002` — 4 KiB, read-once, `409` on any second write.
    /// `/proto002/rendezvous/:slot` is `PROTO-002`'s `CON-304`/`CON-305` —
    /// 69,632 octets, repeatable reads, `204` on an identical retry. `CON-408`
    /// requires a pairing to follow the second "without alteration", and
    /// `CON-303` addresses a mailbox from a base URL precisely so one origin can
    /// serve both without either having to bend.
    pub fn router(self) -> Router {
        Router::new()
            .route("/rendezvous/:slot", get(get_slot).put(put_slot))
            .route("/pairing/records/:address", get(get_record).put(put_record))
            .route("/dids/:did/deltas", post(publish_delta))
            .route("/dids/:did/closure", get(get_closure))
            .route("/healthz", get(|| async { "ok" }))
            // PROTO-003 CON-405: allocate, claim, and the four frames.
            .route("/pair/v1/healthz", get(pairing::health))
            .route("/pair/v1/sessions", post(pairing::allocate))
            .route(
                "/pair/v1/sessions/:nameplate/:resource",
                post(pairing::claim).put(pairing::put_frame).get(pairing::get_frame),
            )
            // PROTO-002 CON-304/CON-305.
            .route(
                "/proto002/rendezvous/:slot",
                get(pairing::get_mailbox).put(pairing::put_mailbox),
            )
            .with_state(self)
    }

    /// Drop expired slots. Called on every request, so an idle server does not
    /// need a background task to honour the 600 s lifetime.
    fn sweep(inner: &mut Inner, now: Now) {
        inner.slots.retain(|_, s| now.saturating_sub(s.stored_at) < SLOT_TTL_SECONDS);
        // A record's own `expiresAt` is the verifier's bound; this is the
        // STORE's, so an abandoned ceremony does not sit at a public address
        // indefinitely. Both are 600 s and neither is a substitute for the other:
        // this one cannot read the record, and that one cannot free memory.
        inner.records.retain(|_, r| now.saturating_sub(r.stored_at) < SLOT_TTL_SECONDS);
    }
}

fn now_seconds() -> Now {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

// ── CON-002: the blind rendezvous ───────────────────────────────────────────

/// `PUT /rendezvous/{slot}` — single-write, 201 | 409 | 400.
///
/// Single-write is not tidiness: it is what stops the operator, or anyone who
/// guesses a slot, from overwriting a record mid-exchange. The client and the
/// phone each write once and the mailbox is then immutable.
async fn put_slot(
    State(service): State<Service>,
    Path(slot): Path<String>,
    body: Bytes,
) -> StatusCode {
    if !is_well_formed_slot(&slot) || body.is_empty() || body.len() > MAX_SLOT_BYTES {
        // No diagnostic: CON-002's error model gives the client nothing to
        // probe with, and the server has made no trust decision to explain.
        return StatusCode::BAD_REQUEST;
    }
    let now = now_seconds();
    let mut inner = service.inner.lock().unwrap_or_else(|p| p.into_inner());
    Service::sweep(&mut inner, now);
    if inner.slots.contains_key(&slot) {
        return StatusCode::CONFLICT;
    }
    inner.slots.insert(slot, Slot { ciphertext: body.to_vec(), stored_at: now, read: false });
    StatusCode::CREATED
}

/// `GET /rendezvous/{slot}` — read-once, 200 | 404.
///
/// Read-once bounds the window in which a captured slot address is worth
/// anything. It is not a security control on its own — the AEAD is — but it
/// means a leaked address is stale almost immediately.
async fn get_slot(
    State(service): State<Service>,
    Path(slot): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    if !is_well_formed_slot(&slot) {
        return Err(StatusCode::NOT_FOUND);
    }
    let now = now_seconds();
    let mut inner = service.inner.lock().unwrap_or_else(|p| p.into_inner());
    Service::sweep(&mut inner, now);
    match inner.slots.get_mut(&slot) {
        Some(entry) if !entry.read => {
            entry.read = true;
            Ok(entry.ciphertext.clone())
        }
        _ => Err(StatusCode::NOT_FOUND),
    }
}

/// A slot is 26 characters of RFC 4648 lowercase base32 (128 bits).
///
/// Validated so a path traversal, an oversized key, or a probe with a
/// human-meaningful name is refused before it reaches the map.
fn is_well_formed_slot(slot: &str) -> bool {
    slot.len() == 26
        && slot.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}

// ── CON-006: state publication ──────────────────────────────────────────────

/// `POST /dids/{did}/deltas` — 202 | 409 | 400.
///
/// Idempotent by content hash: re-submitting identical bytes yields the same
/// result and no duplicate state, which is what makes REQ-020's
/// retry-until-acknowledged safe to run from a phone on a flaky connection.
async fn publish_delta(
    State(service): State<Service>,
    Path(did): Path<String>,
    body: Bytes,
) -> StatusCode {
    let Ok(did) = did.parse::<Did>() else {
        return StatusCode::BAD_REQUEST;
    };
    if body.len() > did_crdt::core::delta::MAX_DELTA_SIZE {
        return StatusCode::BAD_REQUEST;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return StatusCode::BAD_REQUEST;
    };
    let Ok(delta) = serde_json::from_value::<SignedDelta>(value.clone()) else {
        return StatusCode::BAD_REQUEST;
    };
    if delta.did != did {
        return StatusCode::BAD_REQUEST;
    }

    let mut inner = service.inner.lock().unwrap_or_else(|p| p.into_inner());

    // Genesis bootstraps the document. The DID commits to the genesis signer
    // key (REQ-003), so a genesis for a DID it does not derive is refused —
    // that is a structural check, not an authorisation decision.
    if delta.parents.is_empty() {
        let DeltaOp::AddVerificationMethod { ref public_key_multibase, .. } = delta.op else {
            return StatusCode::BAD_REQUEST;
        };
        let Ok(root_pk) = selfsame_core::mb::decode_exact::<32>(public_key_multibase) else {
            return StatusCode::BAD_REQUEST;
        };
        let Ok(derived) = selfsame_core::identity::derive_did(&root_pk) else {
            return StatusCode::BAD_REQUEST;
        };
        if derived != did {
            return StatusCode::BAD_REQUEST;
        }
        if inner.documents.contains_key(&did) {
            return StatusCode::CONFLICT;
        }
        let Ok((doc, _)) = selfsame_core::identity::bootstrap(&root_pk) else {
            return StatusCode::BAD_REQUEST;
        };
        inner.documents.insert(did.clone(), doc);
        inner.closures.insert(did, vec![value]);
        return StatusCode::ACCEPTED;
    }

    // No genesis yet: the delta may be perfectly good but there is nothing to
    // attach it to. CON-006 makes that retriable, not fatal.
    if !inner.documents.contains_key(&did) {
        return StatusCode::CONFLICT;
    }

    // Re-publication of identical bytes is `409 already present`, never a
    // duplicate in the closure. REQ-020 retries until acknowledged, so this is
    // what makes the retry loop terminate rather than growing the store.
    let hash = match delta.content_hash() {
        Ok(h) => h,
        Err(_) => return StatusCode::BAD_REQUEST,
    };
    if inner.closures.get(&did).is_some_and(|c| closure_contains(c, &hash.0)) {
        return StatusCode::CONFLICT;
    }

    let doc = inner.documents.get_mut(&did).expect("presence checked above");
    match doc.merge_verified_delta(delta) {
        Ok(()) => {
            inner.closures.entry(did).or_default().push(value);
            StatusCode::ACCEPTED
        }
        Err(did_crdt::core::Error::DeltaPending { .. }) => StatusCode::CONFLICT,
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

fn closure_contains(closure: &[serde_json::Value], hash: &str) -> bool {
    closure.iter().any(|v| {
        serde_json::from_value::<SignedDelta>(v.clone())
            .ok()
            .and_then(|d| d.content_hash().ok())
            .is_some_and(|h| h.0 == hash)
    })
}


// ── CON-409: the code-derived meeting point ─────────────────────────────────
//
// A DIFFERENT STORE FROM THE MAILBOX ABOVE, and the difference is the phase.
//
// The mailbox is keyed by a slot derived from `mailbox_secret_16`, which exists
// only after the PAKE, and it carries ciphertext. A record is keyed by
// `meet_addr` — derived from `C` before anything has been agreed — and carries a
// signed, PLAINTEXT routing hint that tells a scanning wallet which application
// and nameplate to meet at. A QR carries only `C`, so without this a scanned code
// resolves to nothing.
//
// The store still holds no key material and makes no trust decision. It does not
// verify the signature: the address is a public key and the resolving party
// checks the signature against it, which is the only check that means anything
// and is not one an operator can be trusted to have made.
//
// SINGLE-WRITE, like the mailbox, and for a sharper reason here: `CON-409`
// requires a resolver to "reject a second record at the same address", and an
// address that accepted two would let whoever holds `C` show one application to
// the wallet and another to an observer.

/// The publication envelope. Exactly two members.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordEnvelope {
    /// The RFC 8785 record, base64url.
    pub payload: String,
    /// Ed25519 over exactly those octets, base64url.
    pub signature: String,
}

/// A meeting address is 32 octets as unpadded base64url — 43 characters.
fn is_well_formed_address(address: &str) -> bool {
    address.len() == 43
        && address.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// `PUT /pairing/records/{address}` — single-write, 201 | 409 | 400.
async fn put_record(
    State(service): State<Service>,
    Path(address): Path<String>,
    Json(envelope): Json<RecordEnvelope>,
) -> StatusCode {
    use base64ct::Encoding as _;
    if !is_well_formed_address(&address) {
        return StatusCode::BAD_REQUEST;
    }
    let (Ok(payload), Ok(signature)) = (
        base64ct::Base64UrlUnpadded::decode_vec(&envelope.payload),
        base64ct::Base64UrlUnpadded::decode_vec(&envelope.signature),
    ) else {
        return StatusCode::BAD_REQUEST;
    };
    let Ok(signature): Result<[u8; 64], _> = signature.try_into() else {
        return StatusCode::BAD_REQUEST;
    };
    if payload.is_empty() || payload.len() > MAX_RECORD_BYTES {
        return StatusCode::BAD_REQUEST;
    }

    let now = now_seconds();
    let mut inner = service.inner.lock().unwrap_or_else(|p| p.into_inner());
    Service::sweep(&mut inner, now);
    if inner.records.contains_key(&address) {
        return StatusCode::CONFLICT;
    }
    inner.records.insert(address, Record { payload, signature, stored_at: now });
    StatusCode::CREATED
}

/// `GET /pairing/records/{address}` — 200 | 404.
///
/// Readable more than once, unlike a mailbox slot. A record is a routing hint
/// that a wallet may legitimately re-read — after a dropped connection, or while
/// a person re-reads the code — and read-once here would turn a retry into a
/// dead ceremony. Nothing is spent by reading it: the disclosure is bounded by
/// `OQ-402` and is the same on the first read as the tenth.
async fn get_record(
    State(service): State<Service>,
    Path(address): Path<String>,
) -> Result<Json<RecordEnvelope>, StatusCode> {
    use base64ct::Encoding as _;
    if !is_well_formed_address(&address) {
        return Err(StatusCode::NOT_FOUND);
    }
    let now = now_seconds();
    let mut inner = service.inner.lock().unwrap_or_else(|p| p.into_inner());
    Service::sweep(&mut inner, now);
    let record = inner.records.get(&address).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(RecordEnvelope {
        payload: base64ct::Base64UrlUnpadded::encode_string(&record.payload),
        signature: base64ct::Base64UrlUnpadded::encode_string(&record.signature),
    }))
}

// ── CON-005: signed-closure resolution ──────────────────────────────────────

/// The closure response. **Signed deltas, not a resolved document.**
#[derive(Serialize)]
pub struct ClosureResponse {
    /// The DID the closure belongs to.
    pub did: String,
    /// Every signed delta, in the exact bytes the signer produced.
    pub deltas: Vec<serde_json::Value>,
}

/// `GET /dids/{did}/closure` — 200 | 404 | 410.
async fn get_closure(
    State(service): State<Service>,
    Path(did): Path<String>,
) -> Result<Json<ClosureResponse>, StatusCode> {
    let did = did.parse::<Did>().map_err(|_| StatusCode::NOT_FOUND)?;
    let inner = service.inner.lock().unwrap_or_else(|p| p.into_inner());
    let doc = inner.documents.get(&did).ok_or(StatusCode::NOT_FOUND)?;
    if doc.is_deactivated() {
        return Err(StatusCode::GONE);
    }
    let deltas = inner.closures.get(&did).cloned().unwrap_or_default();
    Ok(Json(ClosureResponse { did: did.to_string(), deltas }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_addresses_outside_the_grammar_are_refused() {
        assert!(is_well_formed_slot(&"a".repeat(26)));
        assert!(is_well_formed_slot("abcdefghijklmnopqrstuvwxyz"));
        assert!(is_well_formed_slot(&"2".repeat(26)));

        // Every slot the core can produce is accepted.
        for seed in 0u8..32 {
            for role in [selfsame_core::seal::Role::Offer, selfsame_core::seal::Role::Bundle] {
                assert!(is_well_formed_slot(&selfsame_core::seal::slot(role, &[seed; 16])));
            }
        }

        assert!(!is_well_formed_slot(""));
        assert!(!is_well_formed_slot(&"a".repeat(25)));
        assert!(!is_well_formed_slot(&"a".repeat(27)));
        assert!(!is_well_formed_slot("../../etc/passwd0123456789"));
        assert!(!is_well_formed_slot(&"A".repeat(26)), "uppercase is a second spelling");
        assert!(!is_well_formed_slot(&"1".repeat(26)), "1 and 8 are not in RFC 4648 base32");
        assert!(!is_well_formed_slot(&"8".repeat(26)));
    }

    /// Every address the contract's own derivation produces is accepted.
    ///
    /// The same shape as the slot test above, and for the same reason: a store
    /// whose grammar is narrower than the deriver's refuses live ceremonies, and
    /// one that is wider accepts addresses no code can reach.
    #[test]
    fn meeting_addresses_outside_the_grammar_are_refused() {
        for seed in 0u8..32 {
            let code = selfsame_app_identity::pairing_code::Code::from_octets([seed; 16]);
            assert!(is_well_formed_address(&code.meeting_point().address_text()));
        }
        assert!(!is_well_formed_address(""));
        assert!(!is_well_formed_address(&"a".repeat(42)), "32 octets is 43 characters");
        assert!(!is_well_formed_address(&"a".repeat(44)));
        assert!(!is_well_formed_address(&format!("{}=", "a".repeat(42))), "unpadded only");
        assert!(!is_well_formed_address(&format!("{}+", "a".repeat(42))), "url-safe alphabet only");
    }

}
