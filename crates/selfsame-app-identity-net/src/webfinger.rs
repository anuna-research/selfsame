//! The reciprocal account binding — `CON-204`.
//!
//! `CON-206` step 9 is the sole gate on alias provisioning: a deterministically
//! named but unprovisioned alias fails closed there, whatever order issuance and
//! provisioning happened to take. This module is the fetch that step depends on.
//!
//! # What a successful response proves, and what it does not
//!
//! `CON-204` is careful, and the care is worth preserving at the call site:
//!
//! > The response proves the account authority's reciprocal assertion. It does
//! > **not** prove that the provider's internal mapping to a human is correct,
//! > and no Selfsame verifier may infer such a claim.
//!
//! So this returns a [`Jrd`] and never a person. The binding it establishes is
//! between an `acct:` URI and a DID, and that is all any part of the profile
//! relies on.
//!
//! # Redirects here, unlike everywhere else
//!
//! `CON-204` step 2 permits redirects that "remain HTTPS and are permitted by
//! RFC 7033", which is the one place in SPEC-004 where a redirect is admissible
//! — WebFinger's own specification allows an authority to redirect within its
//! own service. The bound below is deliberately tight: HTTPS only, and a small
//! fixed number, because an unbounded redirect chain is a request amplifier
//! pointed at whoever the authority names.

use std::time::Duration;

use selfsame_app_identity::alias::{self, AcctUri, AliasError, Jrd, MAX_JRD_OCTETS};

use crate::{bounded_body, has_content_encoding, media_type, NetError};

/// Deadline for a WebFinger lookup.
///
/// Chosen, not specified: `CON-204` fixes no bound.
pub const FETCH_DEADLINE: Duration = Duration::from_millis(5_000);

/// `CON-204` step 2: how many HTTPS redirects a JRD lookup may follow.
///
/// RFC 7033 permits redirection; an unbounded chain is a request amplifier, so
/// the count is small and fixed.
pub const MAX_REDIRECTS: usize = 3;

/// The media type RFC 7033 defines for a JRD.
pub const JRD_MEDIA_TYPE: &str = "application/jrd+json";

/// Fetch the reciprocal JRD for an account URI (`CON-204`).
pub async fn fetch(acct: &AcctUri) -> Result<Jrd, NetError> {
    // Unlike every other fetch in this crate, redirects are permitted — within
    // HTTPS and within a bound.
    let http = crate::build_client(
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS))
            .timeout(FETCH_DEADLINE)
            .https_only(true),
    )?;

    let url = format!("https://{}{}", acct.authority(), alias::webfinger_query(acct));
    let response = http
        .get(&url)
        .header(reqwest::header::ACCEPT, JRD_MEDIA_TYPE)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() { NetError::Timeout } else { NetError::Transport(e.to_string()) }
        })?;

    if !response.status().is_success() {
        // An authority that holds no record answers 404, and that is the
        // ordinary "not provisioned yet" case CON-206 step 9 fails closed on.
        // 404 is the authority answering "no such account", which `CON-221`
        // reads as a first enrolment. Every other unsuccessful status is the
        // authority failing to answer, which must fail closed instead.
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(NetError::NotFound);
        }
        return Err(NetError::Refused("the account authority returned no record"));
    }
    if has_content_encoding(&response) {
        return Err(NetError::Refused("the JRD response carried a content encoding"));
    }
    let content_type = media_type(&response);
    if content_type != JRD_MEDIA_TYPE && content_type != "application/json" {
        return Err(NetError::Refused("the JRD response is not application/jrd+json"));
    }

    let body = bounded_body(response, MAX_JRD_OCTETS).await?;
    alias::recognise_jrd(&body).map_err(|e: AliasError| NetError::Recognition(e.to_string()))
}

/// Fetch and apply `CON-204`'s steps 3 to 5 in one call.
///
/// The convenience the acceptance path actually wants: it needs the binding
/// *verified*, and a caller holding an unverified [`Jrd`] is a caller one
/// forgotten line away from treating a fetched document as a proof.
pub async fn fetch_and_verify(
    acct: &AcctUri,
    home_did: &str,
    also_known_as: &[String],
) -> Result<Jrd, NetError> {
    let jrd = fetch(acct).await?;
    alias::verify_reciprocal_binding(&jrd, acct, home_did, also_known_as)
        .map_err(|e| NetError::Recognition(e.to_string()))?;
    Ok(jrd)
}

/// Fetch, recognise and verify a reciprocal JRD, retaining its exact octets.
///
/// The Path-B NIF re-runs CON-206 over these bytes; returning the fetched bytes
/// avoids inventing a second JRD serializer in a sidecar.
pub async fn fetch_and_verify_bytes(
    acct: &AcctUri, home_did: &str, also_known_as: &[String],
) -> Result<Vec<u8>, NetError> {
    fetch_reciprocal_bytes(acct, home_did, also_known_as, false)
        .await
        .map(Option::unwrap_or_default)
}

/// As [`fetch_and_verify_bytes`], but a resource the authority does not host
/// yet answers `Ok(None)` instead of refusing.
///
/// FIRST CONTACT is the one moment where no reciprocal JRD can exist: the
/// application publishes its half of CON-204's binding only once it accepts
/// the credential, and it accepts only after this resolution. A pairing with
/// a never-before-seen account therefore cannot present a JRD, and treating
/// that as a refusal deadlocks the ceremony permanently — the account is never
/// bound, so the JRD is never published, so the account is never bound.
///
/// Exactly one condition is tolerated: a `404`, which is the authority
/// answering that it hosts no such resource. EVERY other outcome refuses as
/// before — any other status, a content encoding, a wrong media type, an
/// unrecognisable JRD, or a JRD whose binding does not match. A published
/// binding is still proof, and a WRONG published binding is still a refusal;
/// only its absence is now a distinguishable state rather than an error.
pub async fn fetch_reciprocal_or_absent(
    acct: &AcctUri, home_did: &str, also_known_as: &[String],
) -> Result<Option<Vec<u8>>, NetError> {
    fetch_reciprocal_bytes(acct, home_did, also_known_as, true).await
}

async fn fetch_reciprocal_bytes(
    acct: &AcctUri,
    home_did: &str,
    also_known_as: &[String],
    absence_is_answerable: bool,
) -> Result<Option<Vec<u8>>, NetError> {
    let http = crate::build_client(
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS))
            .timeout(FETCH_DEADLINE)
            .https_only(true),
    )?;
    let url = format!("https://{}{}", acct.authority(), alias::webfinger_query(acct));
    let response = http.get(&url).header(reqwest::header::ACCEPT, JRD_MEDIA_TYPE).header(reqwest::header::ACCEPT_ENCODING, "identity").send().await.map_err(|e| if e.is_timeout() { NetError::Timeout } else { NetError::Transport(e.to_string()) })?;
    if absence_is_answerable && absence_is_an_answer(response.status()) {
        return Ok(None);
    }
    if !response.status().is_success() || has_content_encoding(&response) || (media_type(&response) != JRD_MEDIA_TYPE && media_type(&response) != "application/json") { return Err(NetError::Refused("the JRD response was not acceptable")); }
    let body = bounded_body(response, MAX_JRD_OCTETS).await?;
    let jrd = alias::recognise_jrd(&body).map_err(|e| NetError::Recognition(e.to_string()))?;
    alias::verify_reciprocal_binding(&jrd, acct, home_did, also_known_as).map_err(|e| NetError::Recognition(e.to_string()))?;
    Ok(Some(body))
}

/// `404` — and only `404` — is the authority saying it hosts no such account.
///
/// Kept a pure function of the status so the tolerance boundary is testable:
/// every other status, including `410 Gone` (the resource existed and was
/// withdrawn) and any server-side failure, must still refuse.
fn absence_is_an_answer(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::NOT_FOUND
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only a `404` may be read as "this authority hosts no such account".
    /// Everything else — a withdrawn resource, a refusal, a server fault, or a
    /// success — keeps its meaning, so first-contact tolerance can never widen
    /// into ignoring a reciprocal binding that exists or a resolver that broke.
    #[test]
    fn only_a_404_answers_that_no_reciprocal_binding_exists() {
        use reqwest::StatusCode;
        assert!(absence_is_an_answer(StatusCode::NOT_FOUND));
        for refused in [
            StatusCode::OK,
            StatusCode::NO_CONTENT,
            StatusCode::MOVED_PERMANENTLY,
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::GONE,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            assert!(!absence_is_an_answer(refused), "{refused} must not read as absence");
        }
    }

    #[test]
    fn the_query_is_the_rfc_7033_one_with_upper_case_percent_encoding() {
        let acct = AcctUri::parse("acct:alice@accounts.photos.example").unwrap();
        let query = alias::webfinger_query(&acct);
        assert!(query.starts_with("/.well-known/webfinger?resource="));
        assert!(query.contains("acct%3Aalice%40accounts.photos.example"));
        // The host comes from the URI's own authority, never from a caller.
        assert_eq!(acct.authority(), "accounts.photos.example");
    }

    #[test]
    fn redirects_are_bounded_and_this_is_the_only_fetch_that_allows_any() {
        // CON-204 step 2 permits them; CON-220 step 2 and CON-213 forbid them.
        // Keeping the count small and stated is what stops "RFC 7033 allows
        // redirection" becoming an unbounded chain.
        assert_eq!(MAX_REDIRECTS, 3);
    }
}
