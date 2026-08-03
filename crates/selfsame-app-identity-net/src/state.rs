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
//! # Unreachable is not the same as "answered no"
//!
//! `CON-206` permits the bundled closure "only when it is accepting a grant ID
//! for the **first time** and **no declared resolver is reachable**". Both
//! qualifiers are load-bearing, and collapsing either one hands the issuer back
//! the authority the rule exists to take away.
//!
//! A resolver that returns `404`, `410 Gone`, or unparseable octets *is
//! reachable*. It answered; the answer was negative. Treating that as
//! indistinguishable from DNS failure would let an issuer whose resolvers all
//! answer `410` — the code for a deactivated DID — fall through to its own
//! bundled account of its own state, which is precisely the substitution the
//! contract forbids. [`ResolverOutcome`] therefore separates *no answer* from
//! *an answer we did not like*, and only the first kind permits fallback.
//!
//! The second qualifier is [`Acceptance`]. A closure taken from the bundle is
//! admissible at first acceptance because there is nothing else to have; it is
//! not admissible for a grant this verifier has accepted before, because by then
//! a revoked device presenting stale state that omits its own revocation is
//! exactly the attack, and the verifier already knows enough to refuse.
//!
//! # What a resolver has to return
//!
//! The `did:crdt` service contract this profile pins (`CON-003`) exposes
//! `GET /{did}`, and its response is a **resolution result** — a projected W3C
//! DID Document with no signatures on it. That is not something a verifier can
//! check, and `CON-206` step 5 requires one that is: "recompute the
//! self-certifying DID, verify every required delta and authorization rule".
//!
//! So what this module accepts from that endpoint is a **signed closure**: the
//! `SignedDelta` chain, replayed locally through
//! `Document::merge_verified_bundle`, which verifies each signature against the
//! keys its own causal predecessors materialise. A resolution result is refused
//! — reached, but unverifiable, which under the rule above does *not* open the
//! bundle path. Failing closed is the right direction here: the alternative is a
//! verifier that believes whatever a resolver projects.
//!
//! That the pinned service defines no signed-closure media type is a genuine gap
//! between SPEC-004 and the method it pins, recorded as `FINDING-015`. The wire
//! shape read here is stated explicitly in [`SignedClosure`] rather than
//! inferred, so a second implementation can produce it.
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

use did_crdt::core::delta::{DeltaHash, DeltaOp, SignedDelta};
use did_crdt::core::document::Document;
use did_crdt::core::recon::ClosureBundle;

use selfsame_app_identity::accept::ClosureSource;
use selfsame_app_identity::profile::{ApplicationProfile, StateResolver};
use selfsame_app_identity::revocation::Submission;

use crate::{bounded_body, client, join, NetError};

/// Recognise a `did:crdt` identifier before it is interpolated into a URL.
///
/// The DID this module is asked to resolve reaches it from
/// [`selfsame_app_identity::accept::peek_issuer`], which reads `issuer` out of a
/// grant **whose signature has not been checked** — that is the whole point of
/// `peek_issuer`, and it is correct there because the value is used to derive a
/// name. Here it is used to build a request path, and an unrecognised value
/// carrying `/../`, a `?`, or a `#` chooses which same-origin resolver endpoint
/// gets called before the closure replay below ever gets to refuse it.
///
/// The recogniser is the pinned method's own `Did::from_str`, never a second
/// one: `did:crdt:` followed by 64 hexadecimal characters and nothing else,
/// which is a single path segment by construction.
fn recognise_did(did: &str) -> Result<(), NetError> {
    did.parse::<did_crdt::Did>()
        .map(|_| ())
        .map_err(|_| NetError::Refused("the issuer is not a did:crdt identifier"))
}

/// Deadline for one resolver request. Chosen, not specified.
pub const RESOLVER_DEADLINE: Duration = Duration::from_millis(3_000);

/// Octet bound on a resolved closure.
///
/// `CON-219` budgets roughly 3,821 octets for an inlined closure inside a
/// bundle; a directly resolved one has no such constraint, so this is a
/// defensive bound rather than a specified one.
pub const MAX_CLOSURE_OCTETS: usize = 1_048_576;

/// The `did:crdt` `CON-003` resolution path: `GET /{did}`.
const RESOLUTION_PATH: &str = "/";

/// The `did:crdt` `CON-003` delta submission path: `POST /dids/{did}/deltas`.
fn submission_path(did: &str) -> String {
    format!("/dids/{did}/deltas")
}

/// Whether this verifier has accepted this grant ID before (`CON-206` step 10).
///
/// The bundled closure is admissible only at **first-ever** acceptance, so a
/// verifier that cannot answer this question must not use one. `CON-206` sets
/// the direction for the uncertain case: a verifier "whose record of an accepted
/// grant ID is lost or unreadable SHALL treat the next acceptance as
/// establishment" — the stricter branch, not the more convenient one. Uncertain
/// therefore maps to [`Repeat`](Self::Repeat) here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acceptance {
    /// This verifier has a record, and it says this grant ID has never been
    /// accepted. The bundle may stand in for an unreachable resolver.
    First,
    /// This verifier has accepted this grant ID before — or has no readable
    /// record and cannot rule it out. The bundle may not stand in for anything:
    /// a revoked device presenting stale state that omits its own revocation is
    /// the case this closes.
    Repeat,
}

/// What one resolver did when asked (`CON-206`).
///
/// The distinction between the last two is the whole point: only
/// [`Unreachable`](ResolverOutcome::Unreachable) permits the bundle fallback.
#[derive(Debug, PartialEq, Eq)]
pub enum ResolverOutcome {
    /// A verifiable closure arrived and replayed.
    Resolved,
    /// The resolver answered, and the answer was not a usable closure: a
    /// `404`, a `410 Gone`, an unsigned resolution result, a bundle whose
    /// signatures did not verify, or octets that did not parse.
    Reached(&'static str),
    /// No answer: DNS failure, TLS failure, refused connection, or timeout.
    Unreachable,
}

/// A closure and where it came from.
pub struct ResolvedClosure {
    /// The verified document.
    pub document: Document,
    /// Which source produced it — an input to `CON-206` step 10.
    pub source: ClosureSource,
    /// Which resolver answered, when one did.
    pub resolver_id: Option<String>,
    /// What each declared resolver did, in profile order. Kept because
    /// `CON-206` requires a verifier that relied on a bundle to "record that it
    /// did so", and the reason is as much a part of that record as the fact.
    pub outcomes: Vec<(String, ResolverOutcome)>,
}

/// A signed `did:crdt` closure, as this module reads it off the wire.
///
/// The pinned `CON-003` API returns a projected resolution result, which carries
/// no signatures and therefore cannot satisfy `CON-206` step 5. This is the
/// shape that can: the signed deltas themselves, plus the frontier head they
/// were extracted for, mirroring the method's own `ClosureBundle`.
#[derive(serde::Deserialize, serde::Serialize)]
pub struct SignedClosure {
    /// The head delta this closure was extracted for.
    pub target: DeltaHash,
    /// Every signed delta in that head's causal closure.
    pub deltas: Vec<SignedDelta>,
}

/// Resolve the issuer's closure, preferring a declared resolver (`CON-206`
/// step 4).
///
/// `bundled` is the optional closure a `CON-219` bundle carried. It is used only
/// when **every** declared resolver was unreachable *and* this is the grant's
/// first acceptance, and the returned [`ClosureSource`] says so — which is what
/// lets `CON-206` record the reliance rather than hide it.
pub async fn resolve_closure(
    profile: &ApplicationProfile,
    did: &str,
    bundled: Option<&[u8]>,
    acceptance: Acceptance,
) -> Result<ResolvedClosure, NetError> {
    // Full recognition before any request. Nothing below may build a URL out of
    // a value a grant chose and nobody parsed.
    recognise_did(did)?;
    let mut outcomes: Vec<(String, ResolverOutcome)> = Vec::new();

    for resolver in &profile.state_resolvers {
        match fetch_closure(resolver, did).await {
            Ok(document) => {
                outcomes.push((resolver.id.clone(), ResolverOutcome::Resolved));
                return Ok(ResolvedClosure {
                    document,
                    source: ClosureSource::StateResolver,
                    resolver_id: Some(resolver.id.clone()),
                    outcomes,
                });
            }
            // A resolver that is down is not a failure of the operation: the
            // roster exists so that one operator withholding state is
            // survivable. A resolver that *answered* is a different matter.
            Err(e) => outcomes.push((resolver.id.clone(), outcome_of(&e))),
        }
    }

    bundle_is_admissible(&outcomes, acceptance)?;
    let Some(octets) = bundled else {
        return Err(NetError::Refused("no declared resolver answered and no closure was bundled"));
    };
    let document = replay_closure(octets, did)?;
    Ok(ResolvedClosure {
        document,
        source: ClosureSource::BundleOrCache,
        resolver_id: None,
        outcomes,
    })
}

/// Whether `CON-206` permits the issuer's own bundled closure to stand in.
///
/// > A verifier MAY rely on the bundle-supplied closure **only when** it is
/// > accepting a grant ID for the first time **and** no declared resolver is
/// > reachable, and SHALL record that it did so.
///
/// Both conditions, or neither. Kept as its own function because it is the one
/// place in this module where an over-permissive reading returns authority to
/// the party a revocation constrains, and it should be readable and testable
/// without a network or a profile.
fn bundle_is_admissible(
    outcomes: &[(String, ResolverOutcome)],
    acceptance: Acceptance,
) -> Result<(), NetError> {
    if outcomes.iter().any(|(_, o)| matches!(o, ResolverOutcome::Reached(_))) {
        return Err(NetError::Refused(
            "a declared resolver was reachable and returned no usable closure; \
             the issuer's own bundled state cannot stand in for it",
        ));
    }
    if acceptance == Acceptance::Repeat {
        return Err(NetError::Refused(
            "no declared resolver answered, and this grant has been accepted before, \
             so a bundled closure is not admissible",
        ));
    }
    Ok(())
}

/// Which side of `CON-206`'s reachability line a failure falls on.
fn outcome_of(error: &NetError) -> ResolverOutcome {
    match error {
        // No answer arrived.
        NetError::Transport(_) | NetError::Timeout => ResolverOutcome::Unreachable,
        // An answer arrived and was not usable. `TooLarge` belongs here too: the
        // resolver is up and serving, it is serving something inadmissible.
        NetError::Refused(why) => ResolverOutcome::Reached(why),
        NetError::TooLarge => ResolverOutcome::Reached("the closure exceeded its octet bound"),
        NetError::Recognition(_) => ResolverOutcome::Reached("the closure did not verify"),
    }
}

async fn fetch_closure(resolver: &StateResolver, did: &str) -> Result<Document, NetError> {
    // CON-003: `GET /{did}`. `resolve_closure` has recognised the DID, so it is
    // a canonical `did:crdt:` string with no reserved characters and stands as a
    // path segment; `join` supplies exactly one separator whether or not the
    // profile spelled the resolver URL with a trailing `/`.
    let url = join(&resolver.url, &format!("{RESOLUTION_PATH}{did}"));
    let response = client(RESOLVER_DEADLINE)?
        .get(&url)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() { NetError::Timeout } else { NetError::Transport(e.to_string()) }
        })?;
    // Every one of these is an *answer*. `410 Gone` in particular means the DID
    // is deactivated, which is a reason to refuse the grant outright rather than
    // to go looking for a more agreeable account of its state.
    if !response.status().is_success() {
        return Err(NetError::Refused("the resolver returned no closure"));
    }
    let body = bounded_body(response, MAX_CLOSURE_OCTETS).await?;
    replay_closure(&body, did)
}

/// Replay a signed closure into a document, verifying every delta.
///
/// This is `CON-206` step 5 — "recompute the self-certifying DID, verify every
/// required delta and authorization rule" — and it is the reason nothing here
/// deserialises a materialised `Document`. A `Document` on the wire is a claim
/// about state with no evidence attached; deserialising one would make the
/// resolver, or the issuer that wrote the bundle, the authority on its own
/// revocations. Replaying the deltas makes the *signatures* the authority.
///
/// Three things are established, in this order:
///
/// 1. the closure contains exactly one genesis delta, and the DID derived from
///    its root key equals the DID we asked about — so a closure for a different
///    identity cannot be returned under this one's name;
/// 2. every delta's signature verifies against the keys its own causal
///    predecessors materialise (`merge_verified_bundle`); and
/// 3. the closure is causally complete, with no dangling parent.
fn replay_closure(octets: &[u8], expected_did: &str) -> Result<Document, NetError> {
    let closure: SignedClosure = serde_json::from_slice(octets).map_err(|e| {
        NetError::Recognition(format!("closure is not a signed did:crdt closure: {e}"))
    })?;

    // The genesis delta is the one with no parents, and its `AddVerificationMethod`
    // op carries the root key the DID commits to.
    let mut genesis = closure.deltas.iter().filter(|d| d.parents.is_empty());
    let (Some(root), None) = (genesis.next(), genesis.next()) else {
        return Err(NetError::Recognition(
            "a closure has exactly one genesis delta".to_owned(),
        ));
    };
    let DeltaOp::AddVerificationMethod { public_key_multibase, .. } = &root.op else {
        return Err(NetError::Recognition(
            "the genesis delta does not add a verification method".to_owned(),
        ));
    };

    // `Document::new` derives the DID from the root key, so this both bootstraps
    // the replica and recomputes the self-certifying identifier.
    let (mut document, _) = Document::new(public_key_multibase)
        .map_err(|e| NetError::Recognition(format!("genesis is not admissible: {e}")))?;
    if document.did.as_str() != expected_did {
        return Err(NetError::Recognition(
            "the closure's genesis derives a different DID than the one asked about".to_owned(),
        ));
    }

    let bundle = ClosureBundle { target: closure.target, deltas: closure.deltas };
    document
        .merge_verified_bundle(bundle)
        .map_err(|e| NetError::Recognition(format!("a delta in the closure did not verify: {e}")))?;
    Ok(document)
}

/// The credential a `RevokeCredential` delta revokes.
///
/// Any other operation is refused rather than tracked. `Submission` exists to
/// answer one question — has *this* credential appeared in a verified closure —
/// and there is no credential a `Deactivate` or a `RevokeVerificationMethod`
/// makes that question true about.
fn revoked_credential_id(delta: &SignedDelta) -> Result<&str, NetError> {
    match &delta.op {
        DeltaOp::RevokeCredential { credential_id } => Ok(credential_id),
        _ => Err(NetError::Refused("the delta is not a RevokeCredential operation")),
    }
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
///
/// # The tracked credential comes from the delta
///
/// The identifier the returned [`Submission`] watches is read out of the
/// delta's own `RevokeCredential` operation rather than taken as a parameter,
/// for the same reason the DID is: *"taking it from the delta rather than from
/// a parameter means the two can never disagree."* A caller that passed an
/// independent string could submit the revocation of credential A and be handed
/// a `Submission` that waits for credential B — and since only
/// [`confirm_revocation`] can move it, it would wait forever, reporting
/// `Pending` for a revocation that landed and never reporting the one that did.
///
/// A delta carrying any other operation is refused. This function submits
/// revocations, and there is no correct credential to track for anything else.
pub async fn submit_revocation(
    profile: &ApplicationProfile,
    delta: &SignedDelta,
) -> Result<SubmissionReport, NetError> {
    let credential_id = revoked_credential_id(delta)?;
    let body = match serde_json::to_vec(delta) {
        Ok(b) => b,
        Err(_) => {
            return Ok(SubmissionReport {
                submission: Submission::begin(credential_id),
                acknowledged: Vec::new(),
                unreachable: profile.state_resolvers.iter().map(|r| r.id.clone()).collect(),
            })
        }
    };

    // The delta names the DID it targets, and CON-003's submission path is
    // scoped by it. Taking it from the delta rather than from a parameter means
    // the two can never disagree.
    let did = delta.did.to_string();
    let results = crate::probe::join_all_public(
        profile.state_resolvers.iter().map(|r| submit_one(r, &did, body.clone())).collect(),
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
    Ok(SubmissionReport { submission, acknowledged, unreachable })
}

/// Whether a response to a delta submission is an **acknowledgement**.
///
/// `202 Accepted` exactly, because that is the acknowledgement the pinned
/// `CON-003` submission API defines and this predicate decides which of two
/// lists a resolver lands in. `is_success()` would count a `200` or a `204` — a
/// proxy's own answer, a node that accepted the request and not the delta — as
/// an acknowledgement, and the resolver would then be dropped from
/// `unreachable` and lose its place in the retry set. `CON-210` says a failed or
/// unacknowledged submission "SHALL NOT abandon the revocation"; treating a
/// non-acknowledging endpoint as done is how one would be quietly abandoned.
///
/// Nothing is lost by being strict: an acknowledgement is "evidence of nothing"
/// either way, and only [`confirm_revocation`] can move the submission. Its own
/// function so the rule is testable without a resolver to talk to.
fn acknowledged(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::ACCEPTED
}

async fn submit_one(resolver: &StateResolver, did: &str, body: Vec<u8>) -> bool {
    // CON-003: `POST /dids/{did}/deltas`, which answers `202 Accepted`.
    let url = join(&resolver.url, &submission_path(did));
    let Ok(http) = client(RESOLVER_DEADLINE) else { return false };
    match http
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
    {
        Ok(response) => acknowledged(response.status()),
        Err(_) => false,
    }
}

/// Re-resolve and look for the credential ID in a verified closure.
///
/// The **only** path from `Pending` to `Confirmed`. `CON-210`: "The initiating
/// application reports pending until a newly resolved, cryptographically
/// verified closure includes `grant_id`. It reports success only then. A
/// resolver's acknowledgement is not evidence of revocation."
///
/// "Cryptographically verified" is why no bundle is offered here and why
/// [`Acceptance::Repeat`] is passed: confirmation reads state to decide whether
/// a revocation has *landed*, and the only party who benefits from a stale or
/// selective answer is the one being revoked. A closure that did not come from a
/// resolver and replay under signature check leaves the submission `Pending`,
/// which is the honest report — the delta is retained and retried.
pub async fn confirm_revocation(
    profile: &ApplicationProfile,
    did: &str,
    submission: Submission,
) -> Result<Submission, NetError> {
    let resolved = resolve_closure(profile, did, None, Acceptance::Repeat).await?;
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
    fn only_the_acknowledgement_con_003_defines_counts_as_one() {
        use reqwest::StatusCode;
        assert!(acknowledged(StatusCode::ACCEPTED));
        // A `2xx` that is not the acknowledgement: a node that took the request
        // and not the delta, or a proxy answering for one. Counting these
        // dropped the resolver out of `unreachable` and out of the retry set,
        // so the fan-out lost a target and nothing said so.
        for other in [StatusCode::OK, StatusCode::CREATED, StatusCode::NO_CONTENT, StatusCode::PARTIAL_CONTENT] {
            assert!(!acknowledged(other), "{other} is not an acknowledgement");
        }
        for refused in [StatusCode::BAD_REQUEST, StatusCode::CONFLICT, StatusCode::NOT_FOUND] {
            assert!(!acknowledged(refused), "{refused}");
        }
    }

    #[test]
    fn the_paths_are_the_method_service_contract_ones() {
        // CON-003 exposes `GET /{did}` and `POST /dids/{did}/deltas`. Any other
        // spelling is a 404 from every conforming node, which would mean every
        // resolution silently fell through to bundled state and every
        // revocation missed the node it was aimed at.
        assert_eq!(RESOLUTION_PATH, "/");
        assert_eq!(submission_path("did:crdt:abc"), "/dids/did:crdt:abc/deltas");
    }

    #[test]
    fn a_resolver_url_with_a_trailing_slash_produces_the_same_two_requests() {
        // `CON-201` does not forbid the trailing form, and the two spellings
        // name one origin. Concatenating produced `//did:crdt:…` and
        // `//dids/…/deltas` from one of them — a 404 from every conforming
        // node, which is the shape of a resolution that silently falls back to
        // the issuer's own bundled state and a revocation that reaches nobody.
        let did = "did:crdt:abc";
        for base in ["https://state.example", "https://state.example/"] {
            assert_eq!(
                crate::join(base, &format!("{RESOLUTION_PATH}{did}")),
                "https://state.example/did:crdt:abc"
            );
            assert_eq!(
                crate::join(base, &submission_path(did)),
                "https://state.example/dids/did:crdt:abc/deltas"
            );
        }
    }

    #[test]
    fn an_issuer_that_is_not_a_did_crdt_identifier_never_reaches_a_url() {
        // The value arrives from `accept::peek_issuer`, which reads it out of a
        // grant nobody has verified. Interpolated unrecognised, it chooses which
        // same-origin resolver path is requested — before the closure replay
        // that would have refused it ever runs.
        for bad in [
            "did:crdt:../../admin",
            "did:crdt:abc/../../admin",
            "did:crdt:abc?as=admin",
            "did:crdt:abc#frag",
            "did:key:z6Mk",
            "",
            // Right alphabet, wrong length — the boundary a hand-rolled
            // recogniser gets wrong.
            "did:crdt:4b8e2f7a91c05d63e8f240ab17c9d3e56082f4a1bc7d90e35f61a284c093db7",
        ] {
            assert!(recognise_did(bad).is_err(), "`{bad}` was recognised");
        }
        assert!(recognise_did(
            "did:crdt:4b8e2f7a91c05d63e8f240ab17c9d3e56082f4a1bc7d90e35f61a284c093db7e"
        )
        .is_ok());
    }

    #[test]
    fn the_tracked_credential_comes_from_the_delta_and_not_from_a_parameter() {
        // The `Submission` returned watches one credential id, and only
        // `confirm_revocation` can move it. Taking that id independently of the
        // delta lets the two disagree: the revocation of A is submitted, a
        // submission watching B is returned, and it stays `Pending` forever —
        // reporting failure for a revocation that landed, and never reporting
        // the one that did not.
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let (mut document, genesis) =
            selfsame_core::identity::sign_genesis(&key).expect("genesis signs");
        document.merge(genesis).expect("genesis merges");
        let method = selfsame_core::identity::root_method_id(&document.did);
        let credential = format!(
            "{}#grant-{}",
            document.did,
            selfsame_app_identity::codec::b64url(&[3u8; 32])
        );

        let delta = selfsame_app_identity::revocation::revoke_credential(
            &document,
            &key,
            &method,
            &credential,
            1_000,
        )
        .expect("a well-formed grant id is revocable");
        assert_eq!(revoked_credential_id(&delta).unwrap(), credential);

        // Anything else is refused rather than tracked against a credential the
        // operation says nothing about.
        let other = SignedDelta::new_with_parents(
            document.did.clone(),
            DeltaOp::Deactivate,
            delta.timestamp,
            document.frontier(),
            method,
            &did_crdt::core::delta::SigningKey::Ed25519(key),
        )
        .expect("a deactivate delta signs");
        assert!(revoked_credential_id(&other).is_err());
    }

    #[test]
    fn a_closure_that_is_not_a_signed_did_crdt_closure_is_refused() {
        for octets in [&b"{}"[..], b"not json", br#"{"deltas":[]}"#, br#"{"target":"x"}"#] {
            assert!(replay_closure(octets, "did:crdt:whatever").is_err());
        }
    }

    #[test]
    fn a_forged_proof_on_the_genesis_delta_buys_nothing() {
        // `Document::new` bootstraps the replica with the genesis it derives
        // from the root key, and `merge_verified_bundle` skips a delta it
        // already holds *before* verifying its signature — so the received
        // genesis's proof is never checked. That is not a way in, and this is
        // why: `content_hash` covers `{did, op, parents, timestamp}` and not
        // the proof, so a received genesis is skipped only when it is
        // byte-for-byte the delta the root key already determined. Its content
        // is authenticated by the self-certifying DID, which is what
        // `did.as_str() != expected_did` above checks; the signature would be a
        // second statement about a value that is already pinned.
        //
        // The check that matters is therefore the DID comparison, and the two
        // ways of getting past it both fail below.
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let (document, genesis) =
            selfsame_core::identity::sign_genesis(&key).expect("genesis signs");
        let did = document.did.to_string();
        let target = genesis.content_hash().expect("a delta hashes");
        let closure = |deltas: Vec<SignedDelta>, target: DeltaHash| {
            serde_json::to_vec(&SignedClosure { target, deltas }).expect("serialises")
        };

        let honest = replay_closure(&closure(vec![genesis.clone()], target.clone()), &did)
            .expect("a signed closure replays");

        // The same closure with the genesis proof emptied. It replays — and it
        // replays to the *same document*, because the proof was the only thing
        // that differed and nothing from the received delta was applied.
        let mut blanked = genesis.clone();
        blanked.proof.proof_value = String::new();
        assert_eq!(
            blanked.content_hash().expect("hashes"),
            target,
            "the proof is not part of the content hash"
        );
        let forged = replay_closure(&closure(vec![blanked], target.clone()), &did)
            .expect("skipped, because it is the genesis already held");
        assert_eq!(forged.did.to_string(), honest.did.to_string());
        assert_eq!(forged.delta_count(), honest.delta_count());

        // Way one: a genesis naming a different root key. It derives a
        // different DID, which is not the one asked about.
        let other = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let (_, other_genesis) =
            selfsame_core::identity::sign_genesis(&other).expect("genesis signs");
        let other_target = other_genesis.content_hash().expect("hashes");
        assert!(
            replay_closure(&closure(vec![other_genesis], other_target), &did).is_err(),
            "a closure for another identity was accepted under this DID"
        );

        // Way two: the right root key and anything else altered. The content
        // hash moves, so the delta is no longer one the replica holds, and the
        // skip does not apply — its signature is checked, and it is the
        // original signature over different content.
        let mut altered = genesis.clone();
        altered.timestamp.wall_ms += 1;
        let altered_target = altered.content_hash().expect("hashes");
        assert!(
            replay_closure(&closure(vec![altered], altered_target), &did).is_err(),
            "an altered genesis was accepted without its signature verifying"
        );
    }

    #[test]
    fn a_materialised_document_is_not_a_closure() {
        // The defect this replaced: `serde_json::from_slice::<Document>` accepted
        // a resolver's or an issuer's *assertion* about state, revocation set and
        // all, with nothing signed. A projected DID Document has no `deltas`, so
        // it now fails to parse — and even a hand-built one carrying a `deltas`
        // member has to survive signature replay.
        let projected = br#"{
            "@context":["https://www.w3.org/ns/did/v1"],
            "id":"did:crdt:abc",
            "verificationMethod":[],
            "didDocumentMetadata":{"deactivated":false}
        }"#;
        assert!(replay_closure(projected, "did:crdt:abc").is_err());
    }

    #[test]
    fn a_reached_resolver_is_not_an_unreachable_one() {
        // The distinction CON-206's bundle fallback turns on. A 410 Gone or a
        // malformed closure is an answer; only silence permits the issuer's own
        // account of its own revocations to stand in.
        assert_eq!(outcome_of(&NetError::Timeout), ResolverOutcome::Unreachable);
        assert_eq!(
            outcome_of(&NetError::Transport("dns".into())),
            ResolverOutcome::Unreachable
        );
        assert!(matches!(
            outcome_of(&NetError::Refused("gone")),
            ResolverOutcome::Reached(_)
        ));
        assert!(matches!(outcome_of(&NetError::TooLarge), ResolverOutcome::Reached(_)));
        assert!(matches!(
            outcome_of(&NetError::Recognition("bad signature".into())),
            ResolverOutcome::Reached(_)
        ));
    }

    fn outcomes(os: &[ResolverOutcome]) -> Vec<(String, ResolverOutcome)> {
        os.iter()
            .enumerate()
            .map(|(i, o)| {
                (
                    format!("state-{i}"),
                    match o {
                        ResolverOutcome::Resolved => ResolverOutcome::Resolved,
                        ResolverOutcome::Reached(w) => ResolverOutcome::Reached(w),
                        ResolverOutcome::Unreachable => ResolverOutcome::Unreachable,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn a_bundle_stands_in_only_when_every_resolver_was_silent_and_this_is_the_first_acceptance() {
        use ResolverOutcome::{Reached, Unreachable};

        // The one admissible case.
        assert!(bundle_is_admissible(
            &outcomes(&[Unreachable, Unreachable]),
            Acceptance::First
        )
        .is_ok());

        // Reachable-but-negative: an issuer whose resolvers all answer 410 must
        // not thereby get to supply its own account of its own revocations.
        assert!(bundle_is_admissible(
            &outcomes(&[Unreachable, Reached("410 Gone")]),
            Acceptance::First
        )
        .is_err());

        // A grant accepted before: a revoked device must not wait out an outage
        // and present stale state that omits its revocation.
        assert!(bundle_is_admissible(
            &outcomes(&[Unreachable, Unreachable]),
            Acceptance::Repeat
        )
        .is_err());

        // Neither condition met.
        assert!(bundle_is_admissible(&outcomes(&[Reached("404")]), Acceptance::Repeat).is_err());
    }

    #[test]
    fn an_empty_resolver_roster_still_gates_on_first_acceptance() {
        // No declared resolver is vacuously "no reachable resolver", so the
        // first-acceptance condition is the only thing standing between a
        // repeat session and issuer-supplied state.
        assert!(bundle_is_admissible(&[], Acceptance::First).is_ok());
        assert!(bundle_is_admissible(&[], Acceptance::Repeat).is_err());
    }
}
