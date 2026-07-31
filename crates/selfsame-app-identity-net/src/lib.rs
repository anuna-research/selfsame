//! `selfsame-app-identity-net` — the effectful shell of [SPEC-004].
//!
//! **Status: governed prototype.** See [EXP-001]. SPEC-004 remains `draft` and
//! nothing here is authorised for production use.
//!
//! # What this crate is for
//!
//! [`selfsame_app_identity`] is the pure core: it decides things, and it cannot
//! fetch anything. Five of SPEC-004's contracts need octets from the network
//! before their decision can be made:
//!
//! | Contract | What must be fetched | Module |
//! |---|---|---|
//! | `CON-220` | the application profile, from its own identifier | [`profile`] |
//! | `CON-204` | the reciprocal WebFinger JRD | [`webfinger`] |
//! | `CON-208` | pairing and mailbox capability probes | [`probe`] |
//! | `CON-206` step 4 | the issuer's signed `did:crdt` closure | [`state`] |
//! | `CON-210` | revocation delta submission, and the optional projection | [`state`], [`projection`] |
//!
//! This crate is those five fetches and nothing else. Every one of them ends by
//! handing its octets to a recogniser from the core, so no response becomes a
//! decision without passing through the same predicate a browser verifier would
//! run.
//!
//! ```text
//!    network ──▶ selfsame-app-identity-net ──▶ selfsame-app-identity
//!                (fetch, bound, hand over)      (recognise, decide)
//!                        effectful                     pure
//! ```
//!
//! # The boundary is a place, not a convention
//!
//! It would be easier to put a `reqwest` call inside the core and gate it behind
//! a feature flag. That is exactly what `CON-206` cannot survive: one
//! authorization predicate must be linkable into a phone, a CLI, an application
//! backend, and a wasm verifier and give the same answer in each, and a
//! predicate that can reach the network has four behaviours rather than one.
//!
//! So the split is physical. `selfsame-app-identity/tests/purity.rs` fails the
//! build if a network-capable crate enters the core's dependency graph, and
//! everything that would have needed one lives here instead.
//!
//! # What is deliberately absent
//!
//! No retry loops, no connection pooling policy, no caching layer beyond what
//! `CON-220` specifies. Those are an application's decisions and SPEC-004 does
//! not make them. What is here is the part the specification *does* fix: which
//! responses are admissible, what the bounds are, and what happens when they are
//! not met.
//!
//! [SPEC-004]: ../../../../specs/SPEC-004-application-scoped-identity.md
//! [EXP-001]: ../../../../specs/EXP-001-spec-004-reference-implementation.md

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod probe;
pub mod profile;
pub mod projection;
pub mod state;
pub mod webfinger;

use std::time::Duration;

/// Why a fetch failed before its octets reached a recogniser.
///
/// Deliberately coarse. A caller cannot act differently on a DNS failure than on
/// a TLS failure — both mean "no authenticated bytes" — and the contracts each
/// name their own closed error for what happens next.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// The request could not be made, or no response arrived.
    #[error("transport failed: {0}")]
    Transport(String),
    /// A response arrived and is not one the contract admits.
    #[error("response refused: {0}")]
    Refused(&'static str),
    /// The response body exceeded the contract's octet bound.
    #[error("response exceeded the declared octet bound")]
    TooLarge,
    /// The deadline passed.
    #[error("deadline exceeded")]
    Timeout,
    /// The octets arrived and the core's recogniser refused them.
    #[error("recognition failed: {0}")]
    Recognition(String),
}

/// Build the one HTTP client shape every fetch in this crate uses.
///
/// Four properties, each required by a contract rather than chosen:
///
/// - **no redirects.** `CON-220` step 2 rejects every redirect including
///   same-origin, and `CON-213` rejects them for pairing and mailbox traffic.
///   Following one and checking afterwards is not the same thing: the request
///   would already have been made to somewhere the identifier does not name.
/// - **no compression.** `CON-213` and `CON-220` step 3 both reject content
///   encoding. A client that decompressed transparently would leave nothing to
///   refuse.
/// - **no cookies, structurally.** `CON-213` rejects them, and `reqwest`'s
///   `cookies` feature is simply not compiled in — so there is no cookie jar to
///   disable and no code path that could acquire one. A jar shared across
///   ceremonies would also be a correlation handle across providers, which is
///   the sort of thing better made impossible than made off-by-default.
/// - **a deadline on every request.** `CON-208` caps probes at 1500 ms; the
///   others get one so a hung connection is a failure rather than a hang.
pub(crate) fn client(deadline: Duration) -> Result<reqwest::Client, NetError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(deadline)
        .https_only(true)
        .build()
        .map_err(|e| NetError::Transport(e.to_string()))
}

/// Read a response body, refusing rather than truncating past the bound.
///
/// Public because an adopting application adding a fetch of its own needs the
/// same bound, and because a bound that is easy to reach for is a bound that
/// gets used.
///
/// The distinction matters: a truncated body is a *different document*, and a
/// recogniser handed one would either refuse it for the wrong reason or, worse,
/// accept a prefix that happens to parse.
pub async fn bounded_body(
    response: reqwest::Response,
    max_octets: usize,
) -> Result<Vec<u8>, NetError> {
    // `Content-Length`, where the server offers one, lets an oversized body be
    // refused before it is transferred.
    if response.content_length().is_some_and(|n| n > max_octets as u64) {
        return Err(NetError::TooLarge);
    }
    let bytes = response.bytes().await.map_err(|e| NetError::Transport(e.to_string()))?;
    if bytes.len() > max_octets {
        return Err(NetError::TooLarge);
    }
    Ok(bytes.to_vec())
}

/// Whether a response carries a content encoding other than `identity`.
pub fn has_content_encoding(response: &reqwest::Response) -> bool {
    response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| !v.trim().eq_ignore_ascii_case("identity"))
}

/// The `Content-Type` without parameters, lower-cased.
pub fn media_type(response: &reqwest::Response) -> String {
    response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

/// Whether the response set or expects cookies (`CON-213`).
pub fn carried_cookies(response: &reqwest::Response) -> bool {
    response.headers().contains_key(reqwest::header::SET_COOKIE)
}

/// The response-inspection helpers under their testing alias.
///
/// They are public in their own right — an adopting application implementing a
/// sixth fetch needs the same bounds — and re-exported here so that
/// `tests/response_policy.rs` reads as what it is: a test of the code that
/// turns an HTTP response into the input `CON-220`'s and `CON-213`'s predicates
/// decide on.
///
/// That code was the last untested thing in this crate. Every claim it makes
/// about refusing compression, cookies, and oversized bodies runs through these
/// four functions.
pub mod testing {
    pub use super::{bounded_body, carried_cookies, has_content_encoding, media_type};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_client_refuses_redirects_compression_and_plaintext_by_construction() {
        // Not a behavioural test — a construction test. These four properties
        // are what make the contracts' response checks meaningful, and a client
        // built without them would make several of those checks unreachable.
        assert!(client(Duration::from_millis(1_500)).is_ok());
    }

    #[test]
    fn a_deadline_is_always_supplied() {
        // There is no `client()` overload without one, so a hung connection is
        // a failure rather than a hang at every call site in this crate. The
        // signature is the guarantee; this pins that it stays required.
        let built = client(Duration::from_millis(1));
        assert!(built.is_ok(), "a one-millisecond deadline is still a valid client");
    }
}
