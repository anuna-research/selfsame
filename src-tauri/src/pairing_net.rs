//! The two wires a pairing runs over — `PROTO-003` `CON-405`/`CON-406` and
//! `PROTO-002` `CON-303`/`CON-305`.
//!
//! Two origins, deliberately. The selected descriptor's `pairingUrl` is the only
//! PAKE relay origin for a ceremony and its `url` is the only mailbox origin, and
//! `NFR-206` requires that no wire identifier assume they are the same operator.
//! [`selfsame_app_identity::pairing::BoundOrigins`] is what holds the caller to
//! that; this module is only the sockets.
//!
//! # What the provider is
//!
//! A blind relay for four 32-octet frames. `REQ-404` and `CON-405` are emphatic
//! about the negative space: it "never offers list, search, prefix, transcript,
//! reset, retry-count, password-verifier, application-ID, DID, account, grant, or
//! mailbox-key endpoints", and `REQ-428` adds that operating both roles "confers
//! no application, account, DID-state, credential, or PAKE authority". So there
//! is nothing here but PUT, GET, and one POST — a relay that grew a fifth verb
//! would be a party to the ceremony.
//!
//! # Why the response policy is the pure core's
//!
//! `CON-213` rejects redirects, credentials, cookies, content encoding, oversized
//! responses, unrecognized statuses, destructive reads, and "any attempt by the
//! server to choose another endpoint or protocol". That is a predicate, it is
//! already written and tested in
//! [`selfsame_app_identity::pairing::recognise_transport_response`], and a second
//! copy of it here would be a second thing to keep in step. Every response in
//! this module goes through it before its body is read.

use selfsame_app_identity::pairing::{recognise_transport_response, TransportResponse};

/// The deadline on any single request. `CON-303`: "the application's bounded
/// request deadline".
const REQUEST_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// A frame is exactly 32 octets, on the wire and in memory.
const FRAME_OCTETS: usize = 32;

/// How long to wait for a peer's frame before giving up on the ceremony.
///
/// Generous against a slow network and far short of the provider's 600-second
/// session, because nothing here waits on a *person*: by the time a wallet claims
/// a nameplate the application has already stored `pA` and is waiting, so every
/// frame after that is machine-paced.
pub const PEER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(45);

/// How long to wait for the application to write its sealed offer.
///
/// Longer, because this one *can* wait on the application deriving an
/// application-account branch and signing enrollment evidence.
pub const OFFER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(90);

/// The gap between polls.
///
/// `CON-306` bounds mailbox reads at two per second per slot; one per second is
/// inside that for both wires and is the value `CON-405` itself suggests by
/// returning `Retry-After: 1` on an absent frame.
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// What a relay or mailbox request came back as.
///
/// Mapped from `CON-406`'s closed status set and `CON-306`'s error model, and
/// deliberately narrower than either: the caller's only decisions are "wait",
/// "burn", or "fail", so the variants are those.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RelayError {
    /// DNS, TLS, connection, or deadline failure. `CON-306`'s
    /// `ProviderUnreachable`.
    #[error("PairingProviderUnreachable")]
    Unreachable,
    /// A redirect, a cookie, content encoding, an unrecognised status, a
    /// wrong-length body, or a server nominating another endpoint.
    /// `CON-306`'s `ProviderProtocolViolation` — never retried in this ceremony.
    #[error("PairingProviderRefused")]
    ProtocolViolation,
    /// The frame or record is not there yet. Not a failure at the polling layer.
    #[error("PairingNotYet")]
    NotYet,
    /// `409`. A second claim, or a different value for a frame already written.
    /// Burns.
    #[error("PairingConflict")]
    Conflict,
    /// `410`, or the local deadline passed. The ceremony is over.
    #[error("PairingExpired")]
    Expired,
}

/// Which of `CON-405`'s four frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame {
    /// The application's SPAKE2 message.
    PA,
    /// The wallet's SPAKE2 message.
    PB,
    /// The application's confirmation MAC.
    CA,
    /// The wallet's confirmation MAC.
    CB,
}

impl Frame {
    fn path(self) -> &'static str {
        match self {
            Frame::PA => "pA",
            Frame::PB => "pB",
            Frame::CA => "cA",
            Frame::CB => "cB",
        }
    }
}

/// One ceremony's session on one provider's relay.
///
/// Holds the role token, which `CON-405` calls "an ephemeral relay capability,
/// not application or user authentication". It is not the wallet's identity and
/// carries none: the provider stores only a hash of it.
pub struct Relay {
    base: String,
    token: String,
    client: reqwest::Client,
}

impl Relay {
    /// Open a session against a descriptor's exact `pairingUrl`.
    ///
    /// The base URL is `pairingUrl || "/pair/v1"`, so an origin-only descriptor
    /// keeps `https://provider.example/pair/v1` and a path-bearing one keeps its
    /// path. Joining with a URL library instead would silently drop the path on
    /// the second form.
    pub fn at(pairing_url: &str) -> Result<Self, RelayError> {
        // `CON-406`: a role token is "canonical unpadded base64url decoding to
        // exactly 32 bytes", drawn here and never derived from anything in the
        // ceremony — `REQ-229` requires a retry to generate a new one.
        let mut token = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token);

        Ok(Self {
            base: format!("{}/pair/v1", pairing_url.trim_end_matches('/')),
            token: selfsame_app_identity::codec::b64url(&token),
            client: client()?,
        })
    }

    /// Claim the nameplate as role B (`CON-405`).
    ///
    /// The first claim after `pA` exists returns `201`; an identical retry with
    /// the same token returns `200`; **every different token returns `409`**. So
    /// a `409` here is not a race this client can resolve — someone else holds
    /// the nameplate — and the caller burns.
    ///
    /// # One other implementation answers differently, and it is not deployed
    ///
    /// `cbcl-bus` carries a `CON-405` relay — `cbcl-chat-selfsame-pair-http`,
    /// served at `/selfsame/pair/v1` — which deliberately projects the claim
    /// outcomes differently, to avoid an enumeration oracle: an identical retry
    /// is `409` and *every* conflict, including the whole pre-`pA` window, is
    /// `404`. Its own comment gives the reason: "a fresh responder credential is
    /// the sole authority that may learn a plate is live", so a stranger's claim
    /// must not be distinguishable from an absent session.
    ///
    /// It is **not a provider this client will meet**, at least not yet:
    /// `cbcl-chat-selfsame-pair-gate:routed?/0` is a hard-coded `'false` under
    /// SPEC-053 GATE-00 clause 4, so the routes are not compiled into a release
    /// dispatch at all, and only that repository's own EXP-004 harness shims the
    /// gate open. The conforming provider is `selfsame-rendezvous`, which
    /// `tests/a_live_pairing.rs` runs this client against.
    ///
    /// It is recorded because the divergence is real and will have to be settled
    /// before that gate opens, and because this client is safe under both
    /// readings anyway — it holds exactly one token and never re-claims after a
    /// success:
    ///
    /// * `409` can only ever be a first response here, and the provider's
    ///   `identical` is unreachable for a token that has not yet succeeded — so
    ///   burning on it is right under both.
    /// * `404` is polled, which is exactly what the pre-`pA` window needs.
    ///
    /// The cost is one degraded message: against that provider a nameplate
    /// somebody else already holds reads as `PairingExpired` after the deadline
    /// rather than `PairingConflict` at once. Reading `404` as a conflict instead
    /// would trade that for failing every honest ceremony that arrives before the
    /// application has stored `pA`, which is the common case.
    ///
    /// The divergence itself is a conformance question for `PROTO-003` — either
    /// `CON-405`'s codes or the provider's have to move — and it is not this
    /// client's to settle.
    pub async fn claim(&self, nameplate: &str) -> Result<(), RelayError> {
        let url = format!("{}/sessions/{nameplate}/claim", self.base);
        let response = self
            .client
            .post(&url)
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", self.token))
            .header(reqwest::header::CONTENT_LENGTH, "0")
            .send()
            .await
            .map_err(|_| RelayError::Unreachable)?;
        match status(&response, &[200, 201, 404, 409, 410, 429, 503])? {
            200 | 201 => Ok(()),
            // `404` covers "session absent" and "role token not accepted"
            // indistinguishably, on purpose — `CON-406` says it must not be an
            // oracle. Before `pA` exists it is also simply "not yet", which is
            // why the caller polls this rather than failing on the first one.
            404 => Err(RelayError::NotYet),
            409 => Err(RelayError::Conflict),
            410 => Err(RelayError::Expired),
            _ => Err(RelayError::Unreachable),
        }
    }

    /// Claim, retrying while the application has not yet stored `pA`.
    pub async fn claim_when_ready(
        &self,
        nameplate: &str,
        deadline: std::time::Duration,
    ) -> Result<(), RelayError> {
        // Retrying is permitted here on `CON-406`'s own terms — the request is
        // byte-identical, uses the same role token, and no peer value has been
        // processed — and an identical retry is defined to return `200`.
        poll(deadline, || self.claim(nameplate)).await
    }

    /// Read one frame. Exactly 32 octets or nothing.
    pub async fn get_frame(
        &self,
        nameplate: &str,
        frame: Frame,
    ) -> Result<[u8; FRAME_OCTETS], RelayError> {
        let url = format!("{}/sessions/{nameplate}/{}", self.base, frame.path());
        let response = self
            .client
            .get(&url)
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", self.token))
            .header(reqwest::header::ACCEPT, "application/octet-stream")
            .send()
            .await
            .map_err(|_| RelayError::Unreachable)?;
        match status(&response, &[200, 404, 410, 429, 503])? {
            200 => {
                let body = response.bytes().await.map_err(|_| RelayError::ProtocolViolation)?;
                // "Every successful GET returns exactly 32 octets." A response of
                // any other length is a provider that is not implementing this
                // contract, not a frame to be padded or truncated into shape.
                body.as_ref().try_into().map_err(|_| RelayError::ProtocolViolation)
            }
            404 => Err(RelayError::NotYet),
            410 => Err(RelayError::Expired),
            _ => Err(RelayError::Unreachable),
        }
    }

    /// Wait for a frame the peer has not written yet.
    pub async fn await_frame(
        &self,
        nameplate: &str,
        frame: Frame,
        deadline: std::time::Duration,
    ) -> Result<[u8; FRAME_OCTETS], RelayError> {
        poll(deadline, || self.get_frame(nameplate, frame)).await
    }

    /// Write one frame. Immutable: `201` first, `200` on an identical retry,
    /// `409` on a different body.
    pub async fn put_frame(
        &self,
        nameplate: &str,
        frame: Frame,
        value: &[u8; FRAME_OCTETS],
    ) -> Result<(), RelayError> {
        let url = format!("{}/sessions/{nameplate}/{}", self.base, frame.path());
        let response = self
            .client
            .put(&url)
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", self.token))
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(value.to_vec())
            .send()
            .await
            .map_err(|_| RelayError::Unreachable)?;
        match status(&response, &[200, 201, 400, 404, 409, 410, 413, 429, 503])? {
            200 | 201 => Ok(()),
            409 => Err(RelayError::Conflict),
            410 => Err(RelayError::Expired),
            404 => Err(RelayError::NotYet),
            _ => Err(RelayError::ProtocolViolation),
        }
    }
}

// ── PROTO-002 CON-303/CON-305: the mailbox ─────────────────────────────────

/// Read a mailbox slot from the descriptor's exact `url` (`CON-305`).
pub async fn fetch_slot(mailbox_url: &str, slot: &str) -> Result<Vec<u8>, RelayError> {
    let response = client()?
        .get(format!("{}/rendezvous/{slot}", mailbox_url.trim_end_matches('/')))
        .header(reqwest::header::ACCEPT, "application/octet-stream")
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .await
        .map_err(|_| RelayError::Unreachable)?;
    match status(&response, &[200, 404, 429, 503])? {
        200 => Ok(response.bytes().await.map_err(|_| RelayError::ProtocolViolation)?.to_vec()),
        404 => Err(RelayError::NotYet),
        _ => Err(RelayError::Unreachable),
    }
}

/// Wait for a slot the peer has not written yet.
pub async fn await_slot(
    mailbox_url: &str,
    slot: &str,
    deadline: std::time::Duration,
) -> Result<Vec<u8>, RelayError> {
    poll(deadline, || fetch_slot(mailbox_url, slot)).await
}

/// Write a mailbox slot (`CON-304`).
///
/// `204` is success: the slot already holds these exact bytes, which is what an
/// acknowledged write looks like on a retry. `409` is not — it means the slot
/// holds *different* bytes, and `CON-306` requires the ceremony be abandoned
/// rather than the existing value assumed equal.
pub async fn put_slot(mailbox_url: &str, slot: &str, body: Vec<u8>) -> Result<(), RelayError> {
    let response = client()?
        .put(format!("{}/rendezvous/{slot}", mailbox_url.trim_end_matches('/')))
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .body(body)
        .send()
        .await
        .map_err(|_| RelayError::Unreachable)?;
    match status(&response, &[201, 204, 400, 409, 413, 415, 429, 503])? {
        201 | 204 => Ok(()),
        409 => Err(RelayError::Conflict),
        429 | 503 => Err(RelayError::Unreachable),
        _ => Err(RelayError::ProtocolViolation),
    }
}

// ── the shared parts ───────────────────────────────────────────────────────

/// A client that follows no redirect and carries no ambient credential.
///
/// `CON-303`: "no redirect, cookie, HTTP authentication, client certificate, URL
/// query, fragment, or protocol-level application identifier". Redirects are
/// refused at the client rather than inspected afterwards, so a `3xx` arrives as
/// a status this module can reject rather than as a request already re-sent to
/// wherever the provider pointed.
fn client() -> Result<reqwest::Client, RelayError> {
    reqwest::Client::builder()
        .timeout(REQUEST_DEADLINE)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| RelayError::Unreachable)
}

/// Put a response through `CON-213`'s policy, then return its status.
///
/// The `recognised` list is per-endpoint because `CON-406`'s set is closed per
/// endpoint: "All other statuses fail the ceremony."
fn status(response: &reqwest::Response, recognised: &[u16]) -> Result<u16, RelayError> {
    let code = response.status().as_u16();
    let headers = response.headers();
    let observed = TransportResponse {
        // With `Policy::none()` a redirect is never followed, so it presents as a
        // `3xx` status here — which is exactly the condition `CON-303` calls
        // "terminal `ProviderProtocolViolation`".
        redirected: response.status().is_redirection(),
        carried_credentials: headers.contains_key(reqwest::header::WWW_AUTHENTICATE),
        carried_cookies: headers.contains_key(reqwest::header::SET_COOKIE),
        content_encoding: headers
            .get(reqwest::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        // `content_length` is what the provider claims; the body length is
        // checked separately by the caller that reads one.
        octets: response.content_length().unwrap_or(0) as usize,
        status: code,
        // Neither contract has a destructive read: `CON-305` says "a read does not
        // change any server state visible to later protocol requests", and
        // `CON-405` says a GET "does not consume or extend the session".
        destructive_read: false,
        // `CON-213`'s load-bearing clause. A provider that could nominate an
        // endpoint would be choosing where the ceremony happens.
        server_nominated_endpoint: headers
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok()),
    };
    recognise_transport_response(&observed, MAX_RESPONSE_OCTETS, recognised)
        .map_err(|_| RelayError::ProtocolViolation)?;
    Ok(code)
}

/// The largest response either wire can produce: one `PROTO-004` record.
///
/// `CON-502` fixes every sealed record at 69,632 octets and `CON-304` makes that
/// the mailbox bound, so anything larger is a provider exceeding a contract
/// rather than a document to parse.
const MAX_RESPONSE_OCTETS: usize = selfsame_core::envelope::SEALED_OCTETS;

/// Repeat an operation while it answers [`RelayError::NotYet`].
///
/// Every other error stops immediately. A poll loop that retried a `409` would be
/// retrying the one status `CON-306` says to abandon on, and one that retried a
/// protocol violation would be re-asking a provider that has already answered
/// outside its own contract.
async fn poll<T, F, Fut>(deadline: std::time::Duration, mut attempt: F) -> Result<T, RelayError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, RelayError>>,
{
    let until = std::time::Instant::now() + deadline;
    loop {
        match attempt().await {
            Err(RelayError::NotYet) => {}
            other => return other,
        }
        if std::time::Instant::now() >= until {
            // The local deadline, not the provider's. `CON-306`: a `404` "is not
            // evidence that the enclosing pairing ceremony is invalid until the
            // local offer deadline passes" — and now it has.
            return Err(RelayError::Expired);
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `CON-405`: the base URL is `pairingUrl || "/pair/v1"`, and a descriptor
    /// with a path keeps it.
    ///
    /// The contract gives both examples explicitly, because they are what a URL
    /// join gets wrong: resolving `/pair/v1` against
    /// `https://cbcl.chat/selfsame` yields `https://cbcl.chat/pair/v1` and sends
    /// the whole ceremony to the wrong place on a provider that is doing nothing
    /// unusual.
    ///
    /// # The path prefix is not decoration
    ///
    /// `CON-401` says why it exists, and names the exact collision: "one operated
    /// service may expose the blind mailbox at its origin and the pairing relay
    /// below `/selfsame` **without colliding with another protocol at
    /// `/pair/v1`**". That other protocol is real — `cbcl-bus` serves SPEC-016's
    /// agent pairing, a WebSocket, at an ungated `/pair/v1`, and serves
    /// `PROTO-003`'s relay at `/selfsame/pair/v1`. A client that resolved instead
    /// of appending would take a descriptor pointing at the second and arrive at
    /// the first: a different protocol, on a different transport, answering.
    #[test]
    fn the_base_url_appends_rather_than_resolving() {
        assert_eq!(
            Relay::at("https://cbcl.chat/selfsame").unwrap().base,
            "https://cbcl.chat/selfsame/pair/v1",
        );
        // The shape a `cbcl-bus` descriptor has to declare, spelled out because
        // it is the deployment this is aimed at.
        assert_eq!(
            Relay::at("https://chat.anuna.io/selfsame").unwrap().base,
            "https://chat.anuna.io/selfsame/pair/v1",
        );
        assert_eq!(
            Relay::at("https://provider.example").unwrap().base,
            "https://provider.example/pair/v1",
        );
        // A trailing slash is the same descriptor, not a second path segment.
        assert_eq!(
            Relay::at("https://provider.example/").unwrap().base,
            "https://provider.example/pair/v1",
        );
    }

    /// `CON-406`: a role token decodes to exactly 32 bytes, and two sessions
    /// never share one — `REQ-229` requires a retry to generate a new token.
    #[test]
    fn every_session_draws_its_own_token() {
        let one = Relay::at("https://provider.example").unwrap();
        let other = Relay::at("https://provider.example").unwrap();
        assert_ne!(one.token, other.token);
        assert_eq!(
            selfsame_app_identity::codec::decode_b64url_32(&one.token).unwrap().len(),
            32,
        );
    }

    #[test]
    fn the_four_frames_are_the_only_paths() {
        let paths: Vec<_> =
            [Frame::PA, Frame::PB, Frame::CA, Frame::CB].iter().map(|f| f.path()).collect();
        assert_eq!(paths, ["pA", "pB", "cA", "cB"]);
    }
}
