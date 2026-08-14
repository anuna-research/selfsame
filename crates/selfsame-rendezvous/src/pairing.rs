//! `PROTO-003` `CON-405`/`CON-406`'s four-frame relay, and `PROTO-002`'s mailbox.
//!
//! A reference provider, so a pairing can be run end to end before any of this
//! is deployed anywhere. It exists for the same reason the rest of this crate
//! does: the contracts are exercised here first.
//!
//! # What the relay is
//!
//! A blind pipe for four 32-octet values and nothing else. `CON-405` states the
//! negative space in full — it "never offers list, search, prefix, transcript,
//! reset, retry-count, password-verifier, application-ID, DID, account, grant, or
//! mailbox-key endpoints" — and `REQ-404` adds that it is not a PAKE endpoint:
//! the application and the wallet are the two SPAKE2 endpoints, and this sees
//! neither a word, nor a password verifier, nor a key. It cannot tell a correct
//! confirmation from an incorrect one, which is why it can be operated by anyone.
//!
//! # Why the mailbox is served on its own base URL
//!
//! `CON-303` addresses a mailbox as `base_url || "/rendezvous/" || slot`, and the
//! base URL is what lets one origin serve two contracts whose semantics differ.
//! They differ here in three ways that matter:
//!
//! | | SPEC-001 `CON-002` | PROTO-002 `CON-304`/`CON-305` |
//! |---|---|---|
//! | body bound | 4 KiB | 69,632 octets |
//! | identical retry | `409` | `204` |
//! | reads | once | repeatable until expiry |
//!
//! `CON-408` requires a pairing's mailbox to follow `CON-302` through `CON-308`
//! *"without alteration"*, so a `PROTO-003` ceremony cannot use the SPEC-001
//! route: a `PROTO-004` record is sixteen times its body bound, and a read-once
//! mailbox loses the offer permanently if a client retries after a dropped
//! response. Serving both under one path would mean choosing one contract and
//! quietly breaking the other, so they get a base URL each and the difference
//! stays visible.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::{Now, Service};

/// A session's lifetime, from allocation. `CON-405`: "exactly 600 seconds".
pub const SESSION_TTL_SECONDS: u64 = 600;

/// How long a known-expired nameplate answers `410` rather than `404`.
///
/// `CON-405` permits a tombstone "only while a short non-enumerable tombstone is
/// required to make a client's in-flight retry unambiguous, for at most 60
/// additional seconds".
pub const TOMBSTONE_SECONDS: u64 = 60;

/// `CON-304`'s record bound — one `PROTO-004` sealed record, exactly.
pub const MAX_MAILBOX_BYTES: usize = 69_632;

/// One live pairing session.
#[derive(Default)]
pub(crate) struct Session {
    /// SHA-256 of the initiator's token. `CON-405`: "The provider stores only a
    /// cryptographic hash of a role token."
    initiator: [u8; 32],
    responder: Option<[u8; 32]>,
    p_a: Option<[u8; 32]>,
    p_b: Option<[u8; 32]>,
    c_a: Option<[u8; 32]>,
    c_b: Option<[u8; 32]>,
    allocated_at: Now,
}

/// A PROTO-002 mailbox slot: written once, read as often as you like.
pub(crate) struct MailboxSlot {
    pub(crate) record: Vec<u8>,
    pub(crate) stored_at: Now,
}

/// Which of the four frames a path names, and who may touch it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Frame {
    PA,
    PB,
    CA,
    CB,
}

impl Frame {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "pA" => Some(Frame::PA),
            "pB" => Some(Frame::PB),
            "cA" => Some(Frame::CA),
            "cB" => Some(Frame::CB),
            _ => None,
        }
    }

    /// Whether the initiator writes this frame. `CON-405`'s endpoint table gives
    /// `pA` and `cA` to role A's token and `pB` and `cB` to role B's — and the
    /// reader is always the other one.
    fn written_by_initiator(self) -> bool {
        matches!(self, Frame::PA | Frame::CA)
    }
}

impl Session {
    fn frame(&self, which: Frame) -> &Option<[u8; 32]> {
        match which {
            Frame::PA => &self.p_a,
            Frame::PB => &self.p_b,
            Frame::CA => &self.c_a,
            Frame::CB => &self.c_b,
        }
    }

    fn frame_mut(&mut self, which: Frame) -> &mut Option<[u8; 32]> {
        match which {
            Frame::PA => &mut self.p_a,
            Frame::PB => &mut self.p_b,
            Frame::CA => &mut self.c_a,
            Frame::CB => &mut self.c_b,
        }
    }

    /// `CON-405`: "A frame cannot be written before every preceding frame in
    /// `pA, pB, cA, cB` exists."
    ///
    /// This is the ordering that makes the ceremony a ceremony rather than four
    /// independent uploads, and it is enforced here as well as in each client
    /// because a client cannot enforce it against its peer.
    fn predecessors_exist(&self, which: Frame) -> bool {
        match which {
            Frame::PA => true,
            Frame::PB => self.p_a.is_some(),
            Frame::CA => self.p_a.is_some() && self.p_b.is_some(),
            Frame::CB => self.p_a.is_some() && self.p_b.is_some() && self.c_a.is_some(),
        }
    }

    /// Whether the presented token holds the role that may write or read this
    /// frame in this direction.
    fn authorised(&self, which: Frame, token: &[u8; 32], writing: bool) -> bool {
        let wants_initiator = which.written_by_initiator() == writing;
        if wants_initiator {
            &self.initiator == token
        } else {
            self.responder.as_ref() == Some(token)
        }
    }
}

fn digest(token: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(token).into()
}

/// The `Authorization: Bearer` token, recognised before anything is looked up.
///
/// `CON-406`: accepted "only from an `Authorization: Bearer` value whose token is
/// canonical unpadded base64url decoding to exactly 32 bytes", and anything else
/// is `404` rather than a distinguishable refusal.
fn bearer(headers: &HeaderMap) -> Option<[u8; 32]> {
    use base64ct::Encoding as _;
    let raw = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    let text = raw.strip_prefix("Bearer ")?;
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    let bytes = base64ct::Base64UrlUnpadded::decode_vec(text).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    Some(digest(&bytes))
}

/// Exactly six ASCII digits, checked before the map is touched.
fn is_nameplate(text: &str) -> bool {
    text.len() == 6 && text.bytes().all(|b| b.is_ascii_digit())
}

/// `no-store` on every response, per `CON-405`.
fn no_store(status: StatusCode) -> Response {
    let mut response = status.into_response();
    response
        .headers_mut()
        .insert(axum::http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// The allocation response's exactly-four members.
#[derive(serde::Serialize)]
pub struct Allocation {
    version: i64,
    nameplate: String,
    #[serde(rename = "expiresInSeconds")]
    expires_in_seconds: u64,
    #[serde(rename = "initiatorToken")]
    initiator_token: String,
}

/// `POST /pair/v1/sessions` — allocate a nameplate for role A.
pub(crate) async fn allocate(State(service): State<Service>) -> Response {
    use base64ct::Encoding as _;
    let now = crate::now_seconds();
    let mut inner = service.inner.lock().unwrap_or_else(|p| p.into_inner());
    sweep(&mut inner.sessions, now);

    let mut token = [0u8; 32];
    getrandom_bytes(&mut token);

    // "an unused uniformly random six-digit nameplate". Uniform over the whole
    // six-digit space including leading zeros — a generator that skipped them
    // would shrink the space by a tenth and make the shortfall invisible.
    let mut nameplate = String::new();
    for _ in 0..64 {
        let mut raw = [0u8; 4];
        getrandom_bytes(&mut raw);
        let candidate = format!("{:06}", u32::from_le_bytes(raw) % 1_000_000);
        if !inner.sessions.contains_key(&candidate) {
            nameplate = candidate;
            break;
        }
    }
    if nameplate.is_empty() {
        return no_store(StatusCode::SERVICE_UNAVAILABLE);
    }

    inner.sessions.insert(
        nameplate.clone(),
        Session { initiator: digest(&token), allocated_at: now, ..Session::default() },
    );

    let body = Allocation {
        version: 1,
        nameplate,
        expires_in_seconds: SESSION_TTL_SECONDS,
        initiator_token: base64ct::Base64UrlUnpadded::encode_string(&token),
    };
    let mut response = (StatusCode::CREATED, Json(body)).into_response();
    response
        .headers_mut()
        .insert(axum::http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// `POST /pair/v1/sessions/{nameplate}/claim` — role B takes the session.
pub(crate) async fn claim(
    State(service): State<Service>,
    Path((nameplate, resource)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if resource != "claim" || !is_nameplate(&nameplate) {
        return no_store(StatusCode::NOT_FOUND);
    }
    let Some(token) = bearer(&headers) else {
        return no_store(StatusCode::NOT_FOUND);
    };
    let now = crate::now_seconds();
    let mut inner = service.inner.lock().unwrap_or_else(|p| p.into_inner());
    sweep(&mut inner.sessions, now);
    let Some(session) = inner.sessions.get_mut(&nameplate) else {
        return no_store(StatusCode::NOT_FOUND);
    };
    if let Some(expired) = expiry_status(session, now) {
        return no_store(expired);
    }
    // "The first claim after `pA` exists returns `201 Created`." Before that
    // there is nothing to claim, and the response is the same `404` an unknown
    // nameplate gets — a distinguishable answer here would tell a stranger that a
    // ceremony is in progress.
    if session.p_a.is_none() {
        return no_store(StatusCode::NOT_FOUND);
    }
    // The one bearer that could otherwise hold both relay roles.
    if session.initiator == token {
        return no_store(StatusCode::CONFLICT);
    }
    match &session.responder {
        None => {
            session.responder = Some(token);
            no_store(StatusCode::CREATED)
        }
        // "An identical retry using the same token returns `200 OK`."
        Some(held) if *held == token => no_store(StatusCode::OK),
        // "Every different token returns `409 Conflict`."
        Some(_) => no_store(StatusCode::CONFLICT),
    }
}

/// `PUT /pair/v1/sessions/{nameplate}/{frame}` — one immutable 32-octet write.
pub(crate) async fn put_frame(
    State(service): State<Service>,
    Path((nameplate, resource)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (Some(which), true) = (Frame::parse(&resource), is_nameplate(&nameplate)) else {
        return no_store(StatusCode::NOT_FOUND);
    };
    let Some(token) = bearer(&headers) else {
        return no_store(StatusCode::NOT_FOUND);
    };
    // "Every `pA`, `pB`, `cA`, and `cB` wire value is exactly 32 bytes."
    let Ok(value): Result<[u8; 32], _> = body.as_ref().try_into() else {
        return no_store(StatusCode::BAD_REQUEST);
    };

    let now = crate::now_seconds();
    let mut inner = service.inner.lock().unwrap_or_else(|p| p.into_inner());
    sweep(&mut inner.sessions, now);
    let Some(session) = inner.sessions.get_mut(&nameplate) else {
        return no_store(StatusCode::NOT_FOUND);
    };
    if let Some(expired) = expiry_status(session, now) {
        return no_store(expired);
    }
    if !session.authorised(which, &token, true) {
        return no_store(StatusCode::NOT_FOUND);
    }
    if !session.predecessors_exist(which) {
        return no_store(StatusCode::CONFLICT);
    }
    match session.frame(which) {
        None => {
            *session.frame_mut(which) = Some(value);
            no_store(StatusCode::CREATED)
        }
        Some(held) if *held == value => no_store(StatusCode::OK),
        Some(_) => no_store(StatusCode::CONFLICT),
    }
}

/// `GET /pair/v1/sessions/{nameplate}/{frame}` — exactly 32 octets, or nothing.
pub(crate) async fn get_frame(
    State(service): State<Service>,
    Path((nameplate, resource)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let (Some(which), true) = (Frame::parse(&resource), is_nameplate(&nameplate)) else {
        return no_store(StatusCode::NOT_FOUND);
    };
    let Some(token) = bearer(&headers) else {
        return no_store(StatusCode::NOT_FOUND);
    };
    let now = crate::now_seconds();
    let mut inner = service.inner.lock().unwrap_or_else(|p| p.into_inner());
    sweep(&mut inner.sessions, now);
    let Some(session) = inner.sessions.get(&nameplate) else {
        return no_store(StatusCode::NOT_FOUND);
    };
    if let Some(expired) = expiry_status(session, now) {
        return no_store(expired);
    }
    if !session.authorised(which, &token, false) {
        return no_store(StatusCode::NOT_FOUND);
    }
    match session.frame(which) {
        Some(value) => {
            let mut response = value.to_vec().into_response();
            let headers = response.headers_mut();
            headers.insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            headers.insert(axum::http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        // "A GET before its frame exists returns `404 Not Found` with
        // `Retry-After: 1`; it does not consume or extend the session."
        None => {
            let mut response = no_store(StatusCode::NOT_FOUND);
            response
                .headers_mut()
                .insert(axum::http::header::RETRY_AFTER, HeaderValue::from_static("1"));
            response
        }
    }
}

/// `CON-401`'s capability response for the pairing role.
pub(crate) async fn health() -> Response {
    let body = serde_json::json!({
        "protocol": "selfsame-pairing-v1",
        "status": "ok",
        "nameplateDigits": 6,
        "sessionTtlSeconds": SESSION_TTL_SECONDS,
        "frameBytes": 32,
        "claimSemantics": "single-responder",
        "relaySemantics": "opaque-four-frame",
        "providerPakeRole": "none",
    });
    let mut response = Json(body).into_response();
    response
        .headers_mut()
        .insert(axum::http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// `410` inside the tombstone window, `404` after it, `None` while live.
fn expiry_status(session: &Session, now: Now) -> Option<StatusCode> {
    let age = now.saturating_sub(session.allocated_at);
    if age < SESSION_TTL_SECONDS {
        None
    } else if age < SESSION_TTL_SECONDS + TOMBSTONE_SECONDS {
        Some(StatusCode::GONE)
    } else {
        Some(StatusCode::NOT_FOUND)
    }
}

/// Drop sessions past their tombstone. `CON-405`: expiry "is not extended by a
/// claim, frame, read, retry, or health probe", so this is measured from
/// allocation and from nothing else.
fn sweep(sessions: &mut HashMap<String, Session>, now: Now) {
    sessions.retain(|_, s| {
        now.saturating_sub(s.allocated_at) < SESSION_TTL_SECONDS + TOMBSTONE_SECONDS
    });
}

// ── PROTO-002 CON-304 / CON-305: the pairing's mailbox ─────────────────────

/// `PUT {base}/rendezvous/{slot}` — 201 | 204 | 409 | 400 | 413.
///
/// `204` on an identical retry is the difference that matters against SPEC-001's
/// route: a client whose response was lost retries the same bytes and must be
/// told it succeeded, not that it conflicts with itself.
pub(crate) async fn put_mailbox(
    State(service): State<Service>,
    Path(slot): Path<String>,
    body: Bytes,
) -> Response {
    if !crate::is_well_formed_slot(&slot) || body.is_empty() {
        return no_store(StatusCode::BAD_REQUEST);
    }
    if body.len() > MAX_MAILBOX_BYTES {
        return no_store(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let now = crate::now_seconds();
    let mut inner = service.inner.lock().unwrap_or_else(|p| p.into_inner());
    inner.mailbox.retain(|_, s| now.saturating_sub(s.stored_at) < crate::SLOT_TTL_SECONDS);
    match inner.mailbox.get(&slot) {
        None => {
            inner.mailbox.insert(slot, MailboxSlot { record: body.to_vec(), stored_at: now });
            no_store(StatusCode::CREATED)
        }
        Some(existing) if existing.record == body.as_ref() => no_store(StatusCode::NO_CONTENT),
        Some(_) => no_store(StatusCode::CONFLICT),
    }
}

/// `GET {base}/rendezvous/{slot}` — repeatable until expiry.
///
/// `CON-305`: "The server returns the same bytes on every successful read before
/// expiry. A read does not change any server state visible to later protocol
/// requests." SPEC-001's route is read-once, and a pairing served by that one
/// would lose its offer to any client that retried after a dropped response.
pub(crate) async fn get_mailbox(
    State(service): State<Service>,
    Path(slot): Path<String>,
) -> Response {
    if !crate::is_well_formed_slot(&slot) {
        return no_store(StatusCode::NOT_FOUND);
    }
    let now = crate::now_seconds();
    let mut inner = service.inner.lock().unwrap_or_else(|p| p.into_inner());
    inner.mailbox.retain(|_, s| now.saturating_sub(s.stored_at) < crate::SLOT_TTL_SECONDS);
    match inner.mailbox.get(&slot) {
        Some(entry) => {
            let mut response = entry.record.clone().into_response();
            let headers = response.headers_mut();
            headers.insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            headers.insert(axum::http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        None => no_store(StatusCode::NOT_FOUND),
    }
}

/// Fill from the operating system's CSPRNG.
///
/// `getrandom` directly rather than through `rand`, because the only two draws
/// in this module are a role token and a nameplate and neither wants a
/// distribution — `rand` would be a second RNG stack in a crate that has none.
fn getrandom_bytes(out: &mut [u8]) {
    getrandom::getrandom(out).expect("the operating system CSPRNG is available");
}
