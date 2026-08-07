//! A browser device client for [SPEC-001] linking — the wasm half of EXP-002.
//!
//! `selfsame-cli` is the reference device client: it draws a 128-bit secret,
//! signs an offer, seals it into a rendezvous slot, shows the person a link
//! code, and polls for the reply. This crate is the same client with the
//! effectful parts removed, so a browser can supply them instead.
//!
//! ```text
//!   JavaScript                         this crate                selfsame-core
//!   ──────────                         ──────────                ─────────────
//!   crypto.getRandomValues  ─secret─▶  LinkSession::new()  ────▶  Offer::sign
//!   fetch(PUT slot)         ◀─bytes──  sealed_offer()      ◀────  seal::seal_offer
//!   fetch(GET slot)         ─sealed─▶  accept()            ────▶  accept()
//!   IndexedDB                          (holds nothing)
//! ```
//!
//! # The split is the one the repository already draws
//!
//! Randomness, HTTP, and storage are the shell's; recognition and the
//! authorization decision are the core's. Nothing here decides anything — every
//! predicate below is `selfsame_core`'s, called in the order
//! `selfsame-cli/src/main.rs` calls it. A second implementation of the offer
//! format, the slot derivation, or the acceptance predicate is exactly the
//! parser differential this codebase spends `CON-205` avoiding, so there is not
//! one.
//!
//! # What this crate deliberately does not do
//!
//! It draws no randomness. `LinkSession::new` takes the secret and the device
//! seed as arguments rather than generating them, because a wasm module that
//! reached for an RNG would need one compiled in, and the browser already has
//! `crypto.getRandomValues` — a better source than anything this crate could
//! link. It also keeps the shell honest: the secret is visible at the boundary
//! where it is drawn.
//!
//! It stores nothing. The CLI persists an identity because a CLI is a device;
//! the harness's browser page is a fixture that is thrown away after each run,
//! and a store would be state the test has to clean up.
//!
//! [SPEC-001]: ../../../specs/SPEC-001-device-key-provisioning.md

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ed25519_dalek::SigningKey;
use wasm_bindgen::prelude::*;
use serde::Deserialize;

use selfsame_core::code::{LinkCode, LinkSecret};
use selfsame_core::record::{Application, Offer};
use selfsame_core::{accept, seal, LinkContext, UnixSeconds};
use selfsame_app_identity::accept::{ClosureSource, IssuerState, Projection};
use selfsame_app_identity::alias::{AcctUri, Jrd};
use selfsame_app_identity::path_b::{rehydrate_verified_grant, GrantRequest, VerifiedGrant};
use selfsame_app_identity::profile::ApplicationProfile;
use selfsame_app_identity::accept::{VerificationMethod};
use selfsame_app_identity::profile::Ed25519Jwk;
use selfsame_app_identity::path_b::{union_resolver_revocations, ResolverRevocations};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserClosure { resolver_id: String, did: String, did_recomputed_ok: bool, deltas_verified: bool, causally_complete: bool, deactivated: bool, assertion_methods: Vec<BrowserMethod>, revoked_credential_ids: Vec<String>, closure_age_seconds: i64, also_known_as: Vec<String> }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserMethod { id: String, kind: String, public_key: Vec<u8>, has_private_component: bool }

/// Browser JSON facade for a distributed Path-B VC. Every JSON object is closed;
/// resolver facts originate in the browser's own resolver path, never a hub.
#[wasm_bindgen]
pub fn verify_path_b_peer_json(profile: &[u8], account: &str, device_key: &[u8], permissions_json: &str, now: f64, clock_skew_seconds: i64, jrd: &[u8], grant: &[u8], closures_json: &str) -> Result<String, JsError> {
    let result = (|| -> Result<VerifiedGrant, DeviceError> {
        let profile = ApplicationProfile::recognise(profile).map_err(|_| DeviceError::Refused)?;
        let account = AcctUri::parse(account).map_err(|_| DeviceError::Refused)?;
        let device_key: [u8;32] = device_key.try_into().map_err(|_| DeviceError::Refused)?;
        let permissions: Vec<String> = serde_json::from_str(permissions_json).map_err(|_| DeviceError::Refused)?;
        let permission_refs: Vec<&str> = permissions.iter().map(String::as_str).collect();
        let jrd = selfsame_app_identity::alias::recognise_jrd(jrd).map_err(|_| DeviceError::Refused)?;
        let closures: Vec<BrowserClosure> = serde_json::from_str(closures_json).map_err(|_| DeviceError::Refused)?;
        let first = closures.first().ok_or(DeviceError::Refused)?;
        let observations: Vec<ResolverRevocations<'_>> = closures.iter().map(|c| ResolverRevocations { resolver_id: &c.resolver_id, revoked_credential_ids: &c.revoked_credential_ids }).collect();
        let revoked = union_resolver_revocations(&profile, &observations).map_err(|_| DeviceError::Refused)?;
        if closures.iter().any(|c| c.did != first.did || c.did_recomputed_ok != first.did_recomputed_ok || c.deltas_verified != first.deltas_verified || c.causally_complete != first.causally_complete || c.deactivated != first.deactivated || c.assertion_methods.len() != first.assertion_methods.len() || c.also_known_as != first.also_known_as) { return Err(DeviceError::Refused); }
        let methods = first.assertion_methods.iter().map(|m| { let key: [u8;32] = m.public_key.as_slice().try_into().map_err(|_| DeviceError::Refused)?; Ok(VerificationMethod { id: m.id.clone(), kind: m.kind.clone(), jwk: Ed25519Jwk { public_key:key, x:String::new() }, has_private_component:m.has_private_component }) }).collect::<Result<Vec<_>,DeviceError>>()?;
        let issuer = IssuerState { did:first.did.clone(), did_recomputed_ok:first.did_recomputed_ok, deltas_verified:first.deltas_verified, causally_complete:first.causally_complete, deactivated:first.deactivated, assertion_methods:methods, revoked_credential_ids:revoked, closure_age_seconds:closures.iter().map(|c|c.closure_age_seconds).max().unwrap(), source:ClosureSource::StateResolver, also_known_as:first.also_known_as.clone() };
        verify_path_b_peer(&profile, &account, &device_key, &permission_refs, now as UnixSeconds, clock_skew_seconds, &issuer, &jrd, None, grant)
    })();
    result.map(|g| format!(r#"{{"accountDid":{},"grantId":{},"validUntil":{}}}"#, json_string(&g.account_did), json_string(&g.grant_id), g.valid_until)).map_err(|_| JsError::new("Path-B grant refused"))
}

/// Verify a distributed Path-B grant for a peer without consulting any hub.
///
/// The browser supplies only its own already-resolved, locally verified closure
/// and reciprocal JRD. This replays CON-206 steps 1--12 over the opaque VC; it
/// intentionally has no hub assertion, cache fallback, or proof-bypass flag.
pub fn verify_path_b_peer(
    profile: &ApplicationProfile, account: &AcctUri, device_key: &[u8; 32],
    permissions: &[&str], now: UnixSeconds, clock_skew_seconds: i64,
    issuer: &IssuerState, jrd: &Jrd, projection: Option<Projection>, grant: &[u8],
) -> Result<VerifiedGrant, DeviceError> {
    if issuer.source != ClosureSource::StateResolver { return Err(DeviceError::Refused); }
    let now = i64::try_from(now).map_err(|_| DeviceError::Refused)?;
    rehydrate_verified_grant(
        &GrantRequest::new(profile, account, device_key, permissions, now, clock_skew_seconds),
        issuer, jrd, projection, grant,
    ).map_err(|_| DeviceError::Refused)
}

/// The application this client links for.
///
/// One variant exists (`ADR-011` keeps a single application), and it is named
/// here rather than taken from an argument for the reason `selfsame-cli` gives
/// about its own endpoint table: values that decide *who you are talking to*
/// are compiled in, and are never read off the wire or out of a link code.
const APPLICATION: Application = Application::CbclChat;

/// Why a call was refused.
///
/// A real error type rather than `JsError`, because `JsError` cannot be built
/// or read outside a wasm host — it panics — and that would make every refusal
/// path in this crate testable only in a browser. The refusal paths are the
/// ones worth testing, so they get a type that exists everywhere and the
/// [`LinkSession`] wasm surface adapts it at the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceError {
    /// The link secret was not exactly 16 octets.
    SecretLength,
    /// The device seed was not exactly 32 octets.
    SeedLength,
    /// The reply was not for this device.
    ///
    /// Carries nothing. `SCREEN-002` S4: the reason "would teach the user
    /// nothing and would leak which check failed."
    Refused,
}

impl core::fmt::Display for DeviceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::SecretLength => "the link secret is exactly 16 octets",
            Self::SeedLength => "the device seed is exactly 32 octets",
            Self::Refused => "Couldn't link — the reply didn't match this device.",
        })
    }
}

/// One linking attempt, from the secret being drawn to the reply being judged.
///
/// Holds the offer because [`accept`] needs it: `LinkContext` binds the reply to
/// the exact offer this client wrote, and re-parsing it from bytes on the way
/// back would be a second chance to get it wrong.
///
/// Pure and host-independent. The browser-facing type is [`LinkSession`], which
/// is this with its errors translated.
///
/// `Debug` prints no secret: the 16-octet link secret and the sealing key are
/// the two things in here worth protecting, and neither appears.
pub struct Device {
    secret: [u8; 16],
    key: [u8; 32],
    offer: Offer,
}

/// Deliberately opaque, following `hierarchy::HomeKey`.
///
/// Two of the three fields are secret — the 128-bit link secret and the key
/// derived from it — and a derived `Debug` would put both in any log line, any
/// panic message, and any `unwrap_err()` a test writes. The offer is public but
/// is omitted too, because a redaction that lists what it is hiding beside what
/// it is not invites someone to add "just one more" field.
impl core::fmt::Debug for Device {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Device(<redacted>)")
    }
}

impl Device {
    /// Begin an attempt.
    ///
    /// `secret` is 16 octets from the caller's CSPRNG and `device_seed` is 32
    /// octets for this device's signing key. Both are the caller's to draw and
    /// the caller's to keep; this crate treats them as inputs.
    ///
    /// `expires` is the absolute Unix second the offer stops being valid —
    /// `now + OFFER_TTL_SECONDS` at the call site, so the clock stays in the
    /// shell where it belongs.
    pub fn new(
        secret: &[u8],
        device_seed: &[u8],
        description: &str,
        expires: UnixSeconds,
    ) -> Result<Device, DeviceError> {
        let secret: [u8; 16] = secret.try_into().map_err(|_| DeviceError::SecretLength)?;
        let seed: [u8; 32] = device_seed.try_into().map_err(|_| DeviceError::SeedLength)?;

        let signing = SigningKey::from_bytes(&seed);
        let offer = Offer::sign(APPLICATION, &signing, description, expires);

        Ok(Device { secret, key: seal::derive_key(&secret), offer })
    }

    /// The code the person types into the wallet, or scans.
    ///
    /// `SCREEN-002` S2 treats the typed code and the QR as equal paths rather
    /// than one behind the other, and the harness uses the typed one — which
    /// also keeps the emulator's camera out of the loop entirely.
    pub fn link_code(&self) -> String {
        LinkCode { application: APPLICATION, secret: LinkSecret::from_bytes(self.secret) }.render()
    }

    /// Where the sealed offer is written.
    pub fn offer_slot(&self) -> String {
        seal::slot(seal::Role::Offer, &self.secret)
    }

    /// Where the reply will appear.
    ///
    /// A different slot from the offer's, derived from the same secret — which
    /// is what lets the rendezvous hold `H(s)` and never `s`.
    pub fn bundle_slot(&self) -> String {
        seal::slot(seal::Role::Bundle, &self.secret)
    }

    /// The octets to `PUT` into [`Self::offer_slot`].
    pub fn sealed_offer(&self) -> Vec<u8> {
        seal::seal_offer(&self.key, &self.offer.to_bytes())
    }

    /// Judge the reply that appeared in [`Self::bundle_slot`].
    ///
    /// Returns a JSON object on success. On refusal it returns
    /// [`DeviceError::Refused`] and nothing else, which is `SCREEN-002` S4's
    /// rule. The harness asserting *that* a bad reply is refused is the point;
    /// asserting *which* clause refused it is `selfsame-core`'s own suite's
    /// job, and it already does that.
    pub fn accept(&self, sealed: &[u8], now: UnixSeconds) -> Result<String, DeviceError> {
        let ctx = LinkContext { secret: self.secret, offer: self.offer.clone() };
        let identity = accept(sealed, &ctx, now).map_err(|_| DeviceError::Refused)?;

        // A JSON string rather than a serde-wasm-bindgen conversion: four
        // fields, one `JSON.parse` on the other side, and one fewer dependency
        // in a crate that exists to avoid adding them.
        Ok(format!(
            r#"{{"did":{},"fingerprintHex":{},"fingerprintLabel":{},"ownMethodId":{}}}"#,
            json_string(&identity.did),
            json_string(&identity.fingerprint.hex()),
            json_string(&identity.fingerprint.label()),
            json_string(&identity.own_method_id),
        ))
    }
}

/// The browser-facing surface: [`Device`] with its errors translated.
///
/// Nothing but translation happens here. Every decision is [`Device`]'s, which
/// is in turn every decision `selfsame_core` makes — this type exists so that
/// `JsError`, which only works inside a wasm host, stays at the very edge.
#[wasm_bindgen(js_name = LinkSession)]
pub struct LinkSession(Device);

#[wasm_bindgen(js_class = LinkSession)]
impl LinkSession {
    /// Begin an attempt. See [`Device::new`].
    #[wasm_bindgen(constructor)]
    pub fn new(
        secret: &[u8],
        device_seed: &[u8],
        description: &str,
        expires: f64,
    ) -> Result<LinkSession, JsError> {
        Device::new(secret, device_seed, description, expires as UnixSeconds)
            .map(LinkSession)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// See [`Device::link_code`].
    #[wasm_bindgen(getter)]
    pub fn link_code(&self) -> String {
        self.0.link_code()
    }

    /// See [`Device::offer_slot`].
    #[wasm_bindgen(getter)]
    pub fn offer_slot(&self) -> String {
        self.0.offer_slot()
    }

    /// See [`Device::bundle_slot`].
    #[wasm_bindgen(getter)]
    pub fn bundle_slot(&self) -> String {
        self.0.bundle_slot()
    }

    /// See [`Device::sealed_offer`].
    pub fn sealed_offer(&self) -> Vec<u8> {
        self.0.sealed_offer()
    }

    /// See [`Device::accept`].
    pub fn accept(&self, sealed: &[u8], now: f64) -> Result<String, JsError> {
        self.0.accept(sealed, now as UnixSeconds).map_err(|e| JsError::new(&e.to_string()))
    }
}

/// Quote a string as a JSON literal.
///
/// Every value this escapes is a DID, a hex fingerprint, a nickname, or a
/// method id — none of which can contain a quote or a control character. It
/// escapes anyway, because "cannot contain" is an argument about today's
/// producers and this is a boundary.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 16] = [7u8; 16];
    const SEED: [u8; 32] = [9u8; 32];

    fn session() -> Device {
        Device::new(&SECRET, &SEED, "Chrome on a test bench", 1_800_000_300)
            .expect("well-formed inputs")
    }

    #[test]
    fn the_two_slots_differ_and_are_a_function_of_the_secret_alone() {
        // The rendezvous holds H(s) and never s, and it holds two of them. A
        // client that wrote both roles to one slot would let the operator
        // overwrite a reply with an offer.
        let s = session();
        assert_ne!(s.offer_slot(), s.bundle_slot());
        assert_eq!(s.offer_slot(), seal::slot(seal::Role::Offer, &SECRET));
        assert_eq!(s.bundle_slot(), seal::slot(seal::Role::Bundle, &SECRET));
    }

    #[test]
    fn the_link_code_round_trips_through_the_cores_own_parser() {
        // The wallet parses what this renders. Rendering something the core's
        // parser refuses would be a parser differential across the ceremony's
        // two halves — with both halves in this repository.
        let s = session();
        let parsed = LinkCode::parse(&s.link_code()).expect("the core parses what it rendered");
        assert_eq!(parsed.application, APPLICATION);
        assert_eq!(parsed.secret.as_bytes(), &SECRET);
    }

    #[test]
    fn the_sealed_offer_opens_under_the_derived_key_and_not_another() {
        let s = session();
        let sealed = s.sealed_offer();
        let opened = seal::open_offer(&seal::derive_key(&SECRET), &sealed).expect("opens");
        assert_eq!(opened, s.offer.to_bytes());

        let wrong = seal::derive_key(&[8u8; 16]);
        assert!(seal::open_offer(&wrong, &sealed).is_err(), "a different secret must not open it");
    }

    #[test]
    fn a_reply_that_is_not_for_this_device_is_refused_without_saying_why() {
        // SCREEN-002 S4. The harness asserts the refusal; the reason stays in
        // the core's own suite, where naming it costs nothing.
        let s = session();
        let err = s.accept(b"not a sealed bundle at all", 1_800_000_000).unwrap_err();
        assert_eq!(err, DeviceError::Refused);
        let message = err.to_string();
        assert!(message.contains("didn't match this device"), "{message}");
        for leak in ["transcript", "signature", "genesis", "RejectReason", "Unrecognised"] {
            assert!(!message.contains(leak), "the refusal leaked `{leak}`: {message}");
        }
    }

    #[test]
    fn malformed_inputs_are_refused_at_the_constructor() {
        // Distinguished from each other here, because a caller that passed two
        // byte slices in the wrong order should be told which one is wrong. The
        // browser surface collapses both to one message; that is the edge's
        // job, not this one's.
        assert_eq!(Device::new(&[0u8; 15], &SEED, "d", 1).unwrap_err(), DeviceError::SecretLength);
        assert_eq!(Device::new(&[0u8; 17], &SEED, "d", 1).unwrap_err(), DeviceError::SecretLength);
        assert_eq!(Device::new(&SECRET, &[0u8; 31], "d", 1).unwrap_err(), DeviceError::SeedLength);
        assert!(Device::new(&SECRET, &SEED, "d", 1).is_ok(), "the exact lengths");
    }

    #[test]
    fn json_strings_are_escaped_even_though_todays_values_need_none() {
        assert_eq!(json_string("did:crdt:abc"), r#""did:crdt:abc""#);
        assert_eq!(json_string(r#"a"b"#), r#""a\"b""#);
        assert_eq!(json_string("a\\b"), r#""a\\b""#);
        assert_eq!(json_string("a\nb"), r#""a\nb""#);
        assert_eq!(json_string("a\u{1}b"), r#""a\u0001b""#);
    }

    #[test]
    fn the_accepted_json_carries_the_four_fields_the_page_reads() {
        // The shape is a contract with the page, and a `format!` breaks
        // silently. Pinned here without adding a JSON parser to a crate that
        // exists to avoid adding dependencies.
        let out = format!(
            r#"{{"did":{},"fingerprintHex":{},"fingerprintLabel":{},"ownMethodId":{}}}"#,
            json_string("did:crdt:abc"),
            json_string("0C 57 68 F9 50 37"),
            json_string("topaz-adder-57"),
            json_string("did:crdt:abc#dev-1"),
        );
        for field in ["\"did\":", "\"fingerprintHex\":", "\"fingerprintLabel\":", "\"ownMethodId\":"] {
            assert!(out.contains(field), "missing {field} in {out}");
        }
        assert!(out.starts_with('{') && out.ends_with('}'));
    }
}
