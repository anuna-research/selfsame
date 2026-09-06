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

pub mod pairing_status;
pub mod profile;
pub mod projection;
pub mod state;
pub mod webfinger;

#[cfg(all(feature = "native-test-support", not(target_arch = "wasm32")))]
pub mod test_support;

#[cfg(test)]
mod test_tls;

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
    /// The authority answered, and holds no record for this resource.
    ///
    /// Distinct from [`NetError::Refused`] because `CON-221` turns on the
    /// difference: "the authority holds no binding" is a first enrolment, and
    /// "the authority could not be asked" must fail closed. A type that could
    /// not tell them apart would force an implementation either to treat every
    /// outage as first use — the substitution the fingerprint comparison exists
    /// to catch — or to refuse every genuine first enrolment.
    #[error("the account authority holds no record for that account")]
    NotFound,
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
/// - **a deadline on every request.** A hung connection is a failure rather
///   than an unbounded wait.
pub(crate) fn client(deadline: Duration) -> Result<reqwest::Client, NetError> {
    build_client(client_builder(deadline))
}

// WebFinger has its own production redirect policy, but shares the explicit
// test routing boundary so canonical account authorities cannot escape the rig.
pub(crate) fn build_client(builder: reqwest::ClientBuilder) -> Result<reqwest::Client, NetError> {
    #[cfg(all(feature = "native-test-support", not(target_arch = "wasm32")))]
    let builder = test_support::configure(builder);
    builder
        .build()
        .map_err(|e| NetError::Transport(e.to_string()))
}

fn client_builder(deadline: Duration) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(deadline)
        .https_only(true)
}

/// Join a declared base URL to an absolute path with exactly one separator.
///
/// `CON-201` does not require a `stateResolvers` entry to be spelled without a
/// trailing `/`, and `https://state.example` and `https://state.example/` name
/// the same origin. Concatenation makes them two different requests: the second
/// produces `https://state.example//did:crdt:…`, and nothing obliges a server to
/// treat an empty first path segment as absent. A conforming profile could
/// therefore make every closure resolution and every revocation submission miss
/// the endpoint the pinned method's `CON-003` defines — resolution falling
/// through to the issuer's own bundled state, and revocation silently reaching
/// nobody.
///
/// The boundary is normalised, and only the boundary: the caller's path is used
/// as given.
///
/// # Exactly one separator, not every one
///
/// The base loses **at most one** trailing `/`. `CON-201` gives a provider URL
/// the `PathRule::Any` grammar — "any RFC 3986 path, including empty segments
/// and a trailing `/`" — and `FINDING-002` records that this is deliberate:
/// only `applicationId` segments must be non-empty, because `CON-201`'s own
/// `credentialBaseUrl` example ends in `/`. So `https://state.example/api//` is
/// a conforming declaration whose path really does end in an empty segment, and
/// RFC 3986 keeps it. Trimming every trailing slash would request `/api/did:crdt:…`
/// where the profile declared `/api//did:crdt:…`, which is a different resource
/// and possibly a different service: the same silent miss the trailing-slash
/// normalisation exists to prevent, arrived at from the other side.
pub(crate) fn join(base: &str, path: &str) -> String {
    debug_assert!(path.starts_with('/'), "join takes an absolute path");
    format!("{}{path}", base.strip_suffix('/').unwrap_or(base))
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
///
/// # The bound holds during transfer, not after it
///
/// `Content-Length` is a courtesy, not a guarantee: a chunked response, or one
/// with no length at all, offers nothing to check up front. Buffering the whole
/// body first and measuring afterwards would make this function a bound on what
/// a *cooperative* server sends and no bound at all on what a hostile one does —
/// an endpoint could stream indefinitely past `max_octets` and exhaust memory
/// while every caller in this crate believed it was protected.
///
/// So the body is consumed a chunk at a time and abandoned the moment the total
/// exceeds the bound. The connection is dropped with it, so an endpoint that
/// keeps sending is talking to nobody.
pub async fn bounded_body(
    mut response: reqwest::Response,
    max_octets: usize,
) -> Result<Vec<u8>, NetError> {
    // `Content-Length`, where the server offers one, lets an oversized body be
    // refused before it is transferred at all. Where it does not, the loop below
    // is what enforces the bound.
    if response
        .content_length()
        .is_some_and(|n| n > max_octets as u64)
    {
        return Err(NetError::TooLarge);
    }
    // Capacity from the advertised length where there is one, capped at the
    // bound so a dishonest `Content-Length` cannot make this allocate either.
    let hint = response
        .content_length()
        .unwrap_or(0)
        .min(max_octets as u64) as usize;
    let mut body = Vec::with_capacity(hint);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| NetError::Transport(e.to_string()))?
    {
        if body.len() + chunk.len() > max_octets {
            // Refused before the oversized octets are retained. `response` is
            // dropped on return, which closes the connection.
            return Err(NetError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Whether a response carries a content encoding other than `identity`.
///
/// # Every value, and unreadable is encoded
///
/// Two ways a permissive reading of this header lets a prohibited encoding
/// through, and `CON-213` and `CON-220` step 3 both refuse encoding outright, so
/// either one is a check that can be walked past:
///
/// - **More than one field line.** `Content-Encoding: identity` followed by
///   `Content-Encoding: gzip` is two values in the header map. Reading only the
///   first answers "no encoding" for a body that has one, so every value is
///   inspected.
/// - **Octets that are not UTF-8.** A value that cannot be read as a string
///   cannot be compared with `identity`, and a header a reader cannot read is
///   not evidence that the header said nothing. It counts as an encoding.
pub fn has_content_encoding(response: &reqwest::Response) -> bool {
    response
        .headers()
        .get_all(reqwest::header::CONTENT_ENCODING)
        .iter()
        .any(|value| match value.to_str() {
            Ok(text) => !text.trim().eq_ignore_ascii_case("identity"),
            Err(_) => true,
        })
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
    fn a_base_url_is_joined_to_a_path_with_exactly_one_separator() {
        // Both spellings of the same origin have to produce the same request,
        // or a profile's punctuation decides whether revocation propagates.
        assert_eq!(
            join("https://state.example", "/did:crdt:abc"),
            "https://state.example/did:crdt:abc"
        );
        assert_eq!(
            join("https://state.example/", "/did:crdt:abc"),
            "https://state.example/did:crdt:abc"
        );
        assert_eq!(
            join("https://state.example/", "/dids/did:crdt:abc/deltas"),
            "https://state.example/dids/did:crdt:abc/deltas"
        );
    }

    #[test]
    fn a_declared_empty_path_segment_survives_the_join() {
        // `CON-201` gives provider URLs the "any RFC 3986 path, including empty
        // segments and a trailing `/`" grammar, so this base is conforming and
        // its path genuinely ends in an empty segment. Trimming every trailing
        // slash sent the request one segment short of the declared endpoint —
        // a different resource, and a resolution or revocation that quietly
        // reaches the wrong service or none.
        assert_eq!(
            join("https://state.example/api//", "/did:crdt:abc"),
            "https://state.example/api//did:crdt:abc"
        );
        assert_eq!(
            join("https://state.example/api/", "/did:crdt:abc"),
            "https://state.example/api/did:crdt:abc"
        );
        // A base that is nothing but slashes keeps all but the boundary one.
        assert_eq!(
            join("https://state.example//", "/x"),
            "https://state.example//x"
        );
    }

    #[test]
    fn a_deadline_is_always_supplied() {
        // There is no `client()` overload without one, so a hung connection is
        // a failure rather than a hang at every call site in this crate. The
        // signature is the guarantee; this pins that it stays required.
        let built = client(Duration::from_millis(1));
        assert!(
            built.is_ok(),
            "a one-millisecond deadline is still a valid client"
        );
    }
}
