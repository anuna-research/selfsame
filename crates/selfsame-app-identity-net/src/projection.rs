//! The optional Bitstring Status List projection — `CON-210`.
//!
//! A projection is a **cache**, and `CON-210` is emphatic about what that means:
//! "it cannot un-revoke a grant, authorize a device, or supersede a newer
//! verified CRDT closure." A Selfsame verifier under `CON-206` step 10 never
//! relies on it at all — it resolves CRDT state regardless — so this module
//! exists for two narrower purposes:
//!
//! - **early rejection.** A set bit is permanently true, so a verifier that sees
//!   one may reject before paying for a resolver round trip.
//! - **generic VC consumers.** Software that speaks W3C Bitstring Status List
//!   and nothing else can read a projection and inherit its bounded freshness
//!   tradeoff.
//!
//! # The publication host is not a trust anchor
//!
//! > Its publication host only stores signed bytes and allocation metadata; the
//! > host possesses no home signing key and is not an authorization trust
//! > anchor.
//!
//! Which is why [`fetch`] returns octets and an observation rather than a
//! verdict. Whether the projection is *usable* is
//! [`selfsame_app_identity::revocation::read_projection`]'s decision, made in
//! the pure core against the profile's own `maxAgeSeconds`, and it is where the
//! asymmetry between a set and an unset bit lives.
//!
//! # Retrieval leaks which credential is being checked
//!
//! `CON-210`: "Fetchers SHOULD use privacy-preserving caches or proxies rather
//! than reveal individual authorization events to the publication host." This
//! module does not implement one — that is a deployment decision — but it takes
//! the whole status list rather than querying an index, which is the cheap half
//! of the same idea: the host learns which list was read, not which entry.

use std::time::Duration;

use selfsame_app_identity::profile::ProjectionPolicy;

use crate::{bounded_body, client, NetError};

/// Deadline for a projection fetch. Chosen, not specified.
pub const FETCH_DEADLINE: Duration = Duration::from_millis(3_000);

/// Octet bound on a status list credential.
///
/// `CON-210` requires the uncompressed bitstring to hold at least 131,072
/// entries. Compressed and base64-encoded inside a credential that is itself
/// JSON, a megabyte is generous; the bound exists so an unbounded response is a
/// failure rather than a memory cost.
pub const MAX_PROJECTION_OCTETS: usize = 1_048_576;

/// A fetched status list credential, unverified.
///
/// Deliberately not a verdict. The name says `Fetched` rather than `Status`
/// because turning these octets into a decision requires the issuer check, the
/// window check, and the bit — none of which happen here.
pub struct FetchedProjection {
    /// The credential octets, exactly as served.
    pub octets: Vec<u8>,
    /// The URL it came from, for diagnostics.
    pub source: String,
}

/// Fetch a status list credential (`CON-210`).
///
/// The caller supplies `statusListCredential` from the grant's
/// `BitstringStatusListEntry`. What comes back is signed bytes; the signature is
/// the issuer's, not the host's, and verifying it is the caller's next step.
///
/// # Containment, not concatenation
///
/// In a conforming W3C `BitstringStatusListEntry` this value is already an
/// **absolute URL**. Appending it to the profile's declared base produces
/// nonsense — `https://status-cache/lists/https://status-cache/…` — and the
/// fetch simply fails, which reads to a caller as an unavailable projection
/// rather than as the malformed request it is.
///
/// The property that concatenation was reaching for is real and is kept: a
/// grant must not be able to name a host the profile never declared, or the
/// credential would choose where its own revocation status is read from. So the
/// absolute URL is *checked to be within* `credential_base_url` and then
/// requested exactly as given.
pub async fn fetch(
    policy: &ProjectionPolicy,
    status_list_credential: &str,
) -> Result<FetchedProjection, NetError> {
    let url = contained_url(&policy.credential_base_url, status_list_credential)?;

    let response = client(FETCH_DEADLINE)?
        .get(&url)
        .header(reqwest::header::ACCEPT, "application/vc+jwt, application/json")
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() { NetError::Timeout } else { NetError::Transport(e.to_string()) }
        })?;

    if response.status().is_redirection() {
        return Err(NetError::Refused("the projection host redirected"));
    }
    if !response.status().is_success() {
        // Unavailable is a legitimate outcome, not an error in the ceremony:
        // CON-210 says an unavailable projection is treated as unavailable and
        // never as evidence of non-revocation. The caller maps this to
        // `ProjectionReading::Unavailable`.
        return Err(NetError::Refused("the projection is unavailable"));
    }

    let octets = bounded_body(response, MAX_PROJECTION_OCTETS).await?;
    Ok(FetchedProjection { octets, source: url })
}

/// The declared absolute URL, once it is established to be under `base`.
///
/// "Under" is a path-boundary test, not a prefix test. `https://status.example`
/// as a base must not admit `https://status.example.attacker.test/…`, which a
/// bare `starts_with` would.
///
/// # The comparison runs on the parsed URL, not on the string
///
/// The check the request will actually be made against is the one that has to
/// pass, and the request goes through a URL parser. That parser resolves dot
/// segments — including their percent-encoded spellings, which the WHATWG URL
/// Standard treats as dot segments — so
/// `https://status.example/lists/%2E%2E/admin` is a string containing no `/..`
/// and a *request* to `https://status.example/admin`. A raw-string test passes
/// it and the fetch then leaves the configured base entirely.
///
/// So the value is parsed first, checked as an origin and a path, and returned
/// in its canonical serialisation — the same form the client will re-parse, so
/// what was checked and what is requested cannot come apart.
fn contained_url(base: &str, declared: &str) -> Result<String, NetError> {
    let base = reqwest::Url::parse(base)
        .map_err(|_| NetError::Refused("the profile's credentialBaseUrl is not a URL"))?;
    let url = reqwest::Url::parse(declared)
        .map_err(|_| NetError::Refused("statusListCredential is not an absolute HTTPS URL"))?;
    if url.scheme() != "https" {
        return Err(NetError::Refused("statusListCredential is not an absolute HTTPS URL"));
    }
    // A fragment or a query would let one string denote two resources, and
    // neither belongs on a status list credential.
    if url.fragment().is_some() || url.query().is_some() {
        return Err(NetError::Refused("statusListCredential is not a canonical URL"));
    }
    if url.origin() != base.origin() {
        return Err(NetError::Refused(
            "statusListCredential names a host the profile never declared",
        ));
    }
    // The path boundary, over the parsed paths, so a segment the parser already
    // resolved cannot climb out after the check.
    let mut boundary = base.path().trim_end_matches('/').to_string();
    boundary.push('/');
    if !url.path().starts_with(&boundary) || url.path().len() <= boundary.len() {
        return Err(NetError::Refused(
            "statusListCredential names a host the profile never declared",
        ));
    }
    Ok(url.to_string())
}

/// Allocate a `(credential, index)` pair at issuance (`CON-210`).
///
/// > Issuance MAY additionally obtain a random free
/// > `(statusListCredential, statusListIndex)` allocation … indexes SHOULD be
/// > assigned randomly as recommended by W3C Bitstring Status List 1.0.
///
/// Randomly, because sequential indexes leak issuance order and volume to
/// anyone who can read the list — which is everyone, since the list is public by
/// construction.
pub async fn allocate(policy: &ProjectionPolicy) -> Result<Allocation, NetError> {
    let response = client(FETCH_DEADLINE)?
        .post(&policy.allocation_url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() { NetError::Timeout } else { NetError::Transport(e.to_string()) }
        })?;
    if !response.status().is_success() {
        return Err(NetError::Refused("the allocation host refused"));
    }
    let body = bounded_body(response, 8_192).await?;
    recognise_allocation(policy, &body)
}

/// Recognise an allocation response (`CON-210`).
///
/// Separated from the fetch so the whole of what this crate *decides* about an
/// allocation is reachable without a network, which is the same split every
/// other module here makes. Both members arrive from a host `CON-210` states
/// plainly "is not an authorization trust anchor", and both go straight into a
/// credential the home key signs.
fn recognise_allocation(
    policy: &ProjectionPolicy,
    body: &[u8],
) -> Result<Allocation, NetError> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| NetError::Recognition(e.to_string()))?;

    let credential = value
        .get("statusListCredential")
        .and_then(|v| v.as_str())
        .ok_or(NetError::Refused("the allocation named no credential"))?
        .to_string();
    let index = value
        .get("statusListIndex")
        .and_then(|v| v.as_str())
        .ok_or(NetError::Refused("the allocation named no index"))?
        .to_string();

    // `CON-210`: "`statusListIndex` MUST be a canonical base-10 integer with no
    // leading zeroes." Checked here rather than trusted, because the value
    // arrives from a host that is not a trust anchor and goes straight into a
    // signed credential.
    if index.is_empty()
        || !index.bytes().all(|b| b.is_ascii_digit())
        || (index.len() > 1 && index.starts_with('0'))
    {
        return Err(NetError::Refused("the allocated index is not a canonical integer"));
    }

    // The allocation host is not a trust anchor either, and this half of its
    // answer travels further than the index does: the credential URL is signed
    // into the grant, where every future verifier reads it. An off-base value
    // here mints a conforming-looking grant that points its own revocation
    // status at a host the profile never declared — the same property
    // [`fetch`] refuses at read time, applied at the moment the value is
    // accepted rather than only when it is used.
    let status_list_credential = contained_url(&policy.credential_base_url, &credential)?;

    Ok(Allocation { status_list_credential, status_list_index: index })
}

/// A projection slot obtained at issuance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Allocation {
    /// The status list credential this grant's bit lives in.
    pub status_list_credential: String,
    /// The index, a canonical base-10 integer with no leading zeroes.
    pub status_list_index: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ProjectionPolicy {
        ProjectionPolicy {
            kind: "BitstringStatusList".into(),
            allocation_url: "https://status.example/slots".into(),
            credential_base_url: "https://status.example/lists/".into(),
            max_age_seconds: 900,
        }
    }

    #[test]
    fn a_declared_url_under_the_profiles_base_is_requested_exactly_as_given() {
        // A conforming BitstringStatusListEntry carries an absolute URL.
        // Appending it to the base produced `https://…/lists/https://…`, which
        // no host serves — every projection fetch failed, and failed looking
        // like an unavailable projection rather than a malformed request.
        let p = policy();
        let declared = "https://status.example/lists/list-7";
        assert_eq!(contained_url(&p.credential_base_url, declared).unwrap(), declared);
    }

    #[test]
    fn a_url_outside_the_declared_base_is_refused() {
        // The property concatenation was reaching for, kept: a grant must not
        // choose where its own revocation status is read from.
        let p = policy();
        for outside in [
            "https://attacker.example/lists/list-7",
            // Prefix-matching without a path boundary would admit this.
            "https://status.example.attacker.test/lists/list-7",
            // A dot segment climbs out of the base after the check.
            "https://status.example/lists/../../elsewhere/list-7",
            // …and its percent-encoded spelling, which the raw-string test did
            // not contain a `/..` for and which the URL parser resolves to
            // `/admin` before the request is made.
            "https://status.example/lists/%2E%2E/admin",
            "https://status.example/lists/%2e%2e/%2e%2e/admin",
            // A query makes one string denote two resources.
            "https://status.example/lists/list-7?as=admin",
            // Not absolute: the old shape, now refused rather than concatenated.
            "list-7",
            "/lists/list-7",
            // Plaintext.
            "http://status.example/lists/list-7",
            // The base itself names no list.
            "https://status.example/lists/",
        ] {
            assert!(
                contained_url(&p.credential_base_url, outside).is_err(),
                "{outside} was accepted"
            );
        }
    }

    #[test]
    fn the_bound_is_generous_enough_for_the_minimum_bitstring() {
        // CON-210 requires at least 131,072 entries uncompressed, which is
        // 16 KiB of bits before any encoding. The bound has to clear that with
        // room for base64 expansion and the surrounding credential.
        let minimum_bits = selfsame_app_identity::revocation::MIN_PROJECTION_ENTRIES;
        let raw_octets = minimum_bits / 8;
        let base64_expanded = raw_octets * 4 / 3;
        assert!(
            MAX_PROJECTION_OCTETS > base64_expanded,
            "{MAX_PROJECTION_OCTETS} does not clear {base64_expanded} octets of encoded bitstring"
        );
    }

    #[test]
    fn a_non_canonical_index_is_refused() {
        let p = policy();
        let body = |index: &str| {
            format!(
                r#"{{"statusListCredential":"https://status.example/lists/list-7","statusListIndex":"{index}"}}"#
            )
        };
        for index in ["", "007", "1a", "-1"] {
            assert!(
                recognise_allocation(&p, body(index).as_bytes()).is_err(),
                "{index} should not be canonical"
            );
        }
        for index in ["0", "1", "131071"] {
            let out = recognise_allocation(&p, body(index).as_bytes())
                .unwrap_or_else(|e| panic!("{index} should be canonical: {e}"));
            assert_eq!(out.status_list_index, index);
        }
    }

    #[test]
    fn an_allocated_credential_outside_the_profiles_base_is_refused() {
        // The index is validated because the allocation host is not a trust
        // anchor, and the credential URL travels further than the index does:
        // it is signed into the grant and every future verifier reads its own
        // revocation status from it. An unchecked one lets the allocation host
        // choose where that is — which is the property `fetch` refuses at read
        // time, and refusing it only there leaves a nonconforming grant already
        // signed.
        let p = policy();
        for credential in [
            "https://attacker.example/lists/list-7",
            "https://status.example/elsewhere/list-7",
            "https://status.example/lists/%2E%2E/admin",
            "http://status.example/lists/list-7",
            "list-7",
        ] {
            let body = format!(
                r#"{{"statusListCredential":"{credential}","statusListIndex":"4"}}"#
            );
            assert!(
                recognise_allocation(&p, body.as_bytes()).is_err(),
                "{credential} was accepted into an allocation"
            );
        }

        let body = r#"{"statusListCredential":"https://status.example/lists/list-7","statusListIndex":"4"}"#;
        let out = recognise_allocation(&p, body.as_bytes()).expect("an on-base allocation");
        assert_eq!(out.status_list_credential, "https://status.example/lists/list-7");
    }
}
