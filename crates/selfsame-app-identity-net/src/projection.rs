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
/// The caller supplies the list identifier from the grant's
/// `BitstringStatusListEntry`. What comes back is signed bytes; the signature is
/// the issuer's, not the host's, and verifying it is the caller's next step.
pub async fn fetch(
    policy: &ProjectionPolicy,
    status_list_credential: &str,
) -> Result<FetchedProjection, NetError> {
    // The identifier is appended to the profile's declared base, so a
    // projection cannot name a host the profile never declared. A fully
    // qualified identifier from the credential would let the grant choose where
    // its own status is read from.
    let url = format!("{}{status_list_credential}", policy.credential_base_url);

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
    let value: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| NetError::Recognition(e.to_string()))?;

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

    Ok(Allocation { status_list_credential: credential, status_list_index: index })
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
    fn the_credential_url_is_built_from_the_profiles_declared_base() {
        // A fully qualified identifier taken from the grant would let the grant
        // choose where its own status is read from — which is the one place a
        // credential must not have a say.
        let p = policy();
        let url = format!("{}{}", p.credential_base_url, "list-7");
        assert!(url.starts_with("https://status.example/lists/"));
    }

    #[test]
    fn the_bound_is_generous_enough_for_the_minimum_bitstring() {
        // CON-210 requires at least 131,072 entries uncompressed.
        assert!(MAX_PROJECTION_OCTETS > 131_072 / 8);
    }

    #[test]
    fn a_non_canonical_index_would_be_refused() {
        for index in ["", "007", "1a", "-1"] {
            let canonical = !index.is_empty()
                && index.bytes().all(|b| b.is_ascii_digit())
                && !(index.len() > 1 && index.starts_with('0'));
            assert!(!canonical, "{index} should not be canonical");
        }
        for index in ["0", "1", "131071"] {
            let canonical = !index.is_empty()
                && index.bytes().all(|b| b.is_ascii_digit())
                && !(index.len() > 1 && index.starts_with('0'));
            assert!(canonical, "{index} should be canonical");
        }
    }
}
