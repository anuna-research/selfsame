//! `did:crdt` closure resolution and revocation submission — `CON-206` step 4,
//! `CON-210`.
//!
//! # Resolution: prefer a resolver, and record when you could not
//!
//! `CON-206`'s freshness split makes the source of a closure part of the
//! decision, not an implementation detail:
//!
//! > Where any declared `stateResolvers` entry is reachable, the closure SHALL
//! > be resolved from one rather than taken from the `CON-219` bundle or a
//! > cache.
//!
//! The reasoning is worth keeping next to the code, because the rule looks like
//! belt-and-braces and is not: a closure taken from the bundle is **the issuer's
//! own account of its own revocations**, and the issuer is precisely the party a
//! revocation constrains. An issuer that omits its own `RevokeCredential` deltas
//! produces a closure that is internally valid and materially incomplete.
//!
//! So [`resolve_closure`] tries the declared resolvers and reports which source
//! it ended up with, and the caller passes that to `CON-206` as
//! [`ClosureSource`]. It never silently substitutes.
//!
//! # Submission: fan-out, not fallback
//!
//! > Submits the complete signed delta to **every reachable** profile-declared
//! > state resolver — including the application's own node where it declares one
//! > — and to every directly connected peer. Submission is best-effort and
//! > parallel.
//!
//! A resolver roster is a fan-out. `CON-210` forbids treating delivery to the
//! application's own node as a substitute for the others, "because a grant may
//! be verified by a peer or by another device", and forbids a failed submission
//! to any one resolver from abandoning the revocation or letting the controller
//! report success.
//!
//! [`submit_revocation`] therefore returns a [`Submission`] that is still
//! `Pending` no matter how many resolvers acknowledged. Only
//! [`confirm_revocation`] — which re-resolves and looks for the credential ID in
//! a verified closure — can move it.

use std::time::Duration;

use did_crdt::core::delta::SignedDelta;
use did_crdt::core::document::Document;

use selfsame_app_identity::accept::ClosureSource;
use selfsame_app_identity::profile::{ApplicationProfile, StateResolver};
use selfsame_app_identity::revocation::Submission;

use crate::{bounded_body, client, NetError};

/// Deadline for one resolver request. Chosen, not specified.
pub const RESOLVER_DEADLINE: Duration = Duration::from_millis(3_000);

/// Octet bound on a resolved closure.
///
/// `CON-219` budgets roughly 3,821 octets for an inlined closure inside a
/// bundle; a directly resolved one has no such constraint, so this is a
/// defensive bound rather than a specified one.
pub const MAX_CLOSURE_OCTETS: usize = 1_048_576;

/// The `did:crdt` `CON-003` resolution path.
const RESOLUTION_PATH: &str = "/did-crdt/v1/resolve";

/// The `did:crdt` `CON-004` delta submission path.
const SUBMISSION_PATH: &str = "/did-crdt/v1/deltas";

/// A closure and where it came from.
pub struct ResolvedClosure {
    /// The verified document.
    pub document: Document,
    /// Which source produced it — an input to `CON-206` step 10.
    pub source: ClosureSource,
    /// Which resolver answered, when one did.
    pub resolver_id: Option<String>,
}

/// Resolve the issuer's closure, preferring a declared resolver (`CON-206`
/// step 4).
///
/// `bundled` is the optional closure a `CON-219` bundle carried. It is used only
/// when no declared resolver answers, and the returned [`ClosureSource`] says so
/// — which is what lets `CON-206` record the reliance rather than hide it.
pub async fn resolve_closure(
    profile: &ApplicationProfile,
    did: &str,
    bundled: Option<&[u8]>,
) -> Result<ResolvedClosure, NetError> {
    for resolver in &profile.state_resolvers {
        match fetch_closure(resolver, did).await {
            Ok(document) => {
                return Ok(ResolvedClosure {
                    document,
                    source: ClosureSource::StateResolver,
                    resolver_id: Some(resolver.id.clone()),
                })
            }
            // A resolver that is down is not a failure of the operation: the
            // roster exists so that one operator withholding state is survivable.
            Err(_) => continue,
        }
    }

    // Every declared resolver is unreachable. CON-206: a verifier "MAY rely on
    // the bundle-supplied closure only when it is accepting a grant ID for the
    // first time and no declared resolver is reachable, and SHALL record that
    // it did so."
    let Some(octets) = bundled else {
        return Err(NetError::Refused("no declared resolver answered and no closure was bundled"));
    };
    let document = parse_closure(octets)?;
    Ok(ResolvedClosure {
        document,
        source: ClosureSource::BundleOrCache,
        resolver_id: None,
    })
}

async fn fetch_closure(resolver: &StateResolver, did: &str) -> Result<Document, NetError> {
    let url = format!("{}{RESOLUTION_PATH}?did={did}", resolver.url);
    let response = client(RESOLVER_DEADLINE)?
        .get(&url)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() { NetError::Timeout } else { NetError::Transport(e.to_string()) }
        })?;
    if !response.status().is_success() {
        return Err(NetError::Refused("the resolver returned no closure"));
    }
    let body = bounded_body(response, MAX_CLOSURE_OCTETS).await?;
    parse_closure(&body)
}

/// Parse a serialised closure into a document.
///
/// The method owns the format. What matters here is that nothing about the
/// resulting document is trusted because of *where it came from* — `CON-206`
/// step 5 recomputes the self-certifying DID and verifies every delta, and this
/// function performs no authentication of its own.
fn parse_closure(octets: &[u8]) -> Result<Document, NetError> {
    serde_json::from_slice::<Document>(octets)
        .map_err(|e| NetError::Recognition(format!("closure is not a did:crdt document: {e}")))
}

/// The outcome of fanning one delta out to every declared resolver.
pub struct SubmissionReport {
    /// Still `Pending` however many resolvers acknowledged.
    pub submission: Submission,
    /// Resolvers that acknowledged receipt. Evidence of nothing.
    pub acknowledged: Vec<String>,
    /// Resolvers that did not answer. The delta is retained and retried.
    pub unreachable: Vec<String>,
}

/// Submit a signed revocation delta to every declared resolver, in parallel
/// (`CON-210` step 5).
///
/// Best-effort by construction: a resolver that fails lands in `unreachable`
/// and changes nothing else. `CON-210`: "A failed or unacknowledged submission
/// to any one resolver SHALL NOT abandon the revocation, discard the delta, or
/// cause the controller to report success."
pub async fn submit_revocation(
    profile: &ApplicationProfile,
    delta: &SignedDelta,
    credential_id: &str,
) -> SubmissionReport {
    let body = match serde_json::to_vec(delta) {
        Ok(b) => b,
        Err(_) => {
            return SubmissionReport {
                submission: Submission::begin(credential_id),
                acknowledged: Vec::new(),
                unreachable: profile.state_resolvers.iter().map(|r| r.id.clone()).collect(),
            }
        }
    };

    let results = crate::probe::join_all_public(
        profile.state_resolvers.iter().map(|r| submit_one(r, body.clone())).collect(),
    )
    .await;

    let mut acknowledged = Vec::new();
    let mut unreachable = Vec::new();
    for (resolver, ok) in profile.state_resolvers.iter().zip(results) {
        if ok {
            acknowledged.push(resolver.id.clone());
        } else {
            unreachable.push(resolver.id.clone());
        }
    }

    // Every acknowledgement is recorded and none of them confirms anything.
    // `Submission::acknowledged` deliberately cannot change the state.
    let mut submission = Submission::begin(credential_id);
    for id in &acknowledged {
        submission = submission.acknowledged(id.clone());
    }
    SubmissionReport { submission, acknowledged, unreachable }
}

async fn submit_one(resolver: &StateResolver, body: Vec<u8>) -> bool {
    let url = format!("{}{SUBMISSION_PATH}", resolver.url);
    let Ok(http) = client(RESOLVER_DEADLINE) else { return false };
    match http
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
    {
        Ok(response) => response.status().is_success(),
        Err(_) => false,
    }
}

/// Re-resolve and look for the credential ID in a verified closure.
///
/// The **only** path from `Pending` to `Confirmed`. `CON-210`: "The initiating
/// application reports pending until a newly resolved, cryptographically
/// verified closure includes `grant_id`. It reports success only then. A
/// resolver's acknowledgement is not evidence of revocation."
pub async fn confirm_revocation(
    profile: &ApplicationProfile,
    did: &str,
    submission: Submission,
) -> Result<Submission, NetError> {
    let resolved = resolve_closure(profile, did, None).await?;
    Ok(submission.observe(&resolved.document))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_acknowledgement_leaves_the_submission_pending() {
        // The rule this whole module is arranged around, restated where the
        // fan-out happens rather than only where the type is defined.
        let submission = Submission::begin("did:crdt:x#grant-AAAA")
            .acknowledged("state-1")
            .acknowledged("anuna-public");
        assert!(!submission.is_confirmed());
    }

    #[test]
    fn the_paths_are_the_method_service_contract_ones() {
        assert_eq!(RESOLUTION_PATH, "/did-crdt/v1/resolve");
        assert_eq!(SUBMISSION_PATH, "/did-crdt/v1/deltas");
    }

    #[test]
    fn a_closure_that_is_not_a_did_crdt_document_is_refused() {
        assert!(parse_closure(b"{}").is_err());
        assert!(parse_closure(b"not json").is_err());
    }
}
