//! Path-B verifier adapter tests.
//!
//! The adapter is deliberately a thin, typed route into CON-206.  These tests
//! prove it cannot accidentally weaken an admission to continuation freshness
//! or accept a grant for a different offered device.

mod common;

use common::*;
use selfsame_app_identity::accept::{ClosureSource, Freshness};
use selfsame_app_identity::path_b::{
    union_resolver_revocations, verify_session_establishment, GrantEvidence, GrantRequest,
    ResolverRevocations, VerifyError,
};

#[test]
fn accepts_the_complete_con_206_ceremony_at_session_establishment() {
    let ceremony = Ceremony::accepted();
    let accepted = verify_session_establishment(
        &GrantRequest::new(
            &ceremony.profile,
            &ceremony.account,
            &ceremony.device_public_key,
            &[],
            ceremony.now,
            0,
        ),
        &GrantEvidence::new(
            &ceremony.issuer,
            &ceremony.jrd,
            None,
            &ceremony.challenge,
            &ceremony.signature,
            VERIFIER_SESSION,
        ),
        &ceremony.grant_bytes,
    )
    .expect("the reference CON-206 ceremony must be accepted");

    assert_eq!(accepted.account_did, ceremony.home_did);
    assert_eq!(accepted.device_public_key, ceremony.device_public_key);
}

#[test]
fn refuses_a_closure_that_is_only_fresh_enough_for_continuation() {
    let ceremony = Ceremony::accepted();
    let mut issuer = ceremony.issuer.clone();
    issuer.closure_age_seconds = ceremony.profile.revocation.propagation_sla_seconds + 1;
    issuer.source = ClosureSource::StateResolver;

    let err = verify_session_establishment(
        &GrantRequest::new(
            &ceremony.profile,
            &ceremony.account,
            &ceremony.device_public_key,
            &[],
            ceremony.now,
            0,
        ),
        &GrantEvidence::new(
            &issuer,
            &ceremony.jrd,
            None,
            &ceremony.challenge,
            &ceremony.signature,
            VERIFIER_SESSION,
        ),
        &ceremony.grant_bytes,
    )
    .expect_err("Path B admission must not select continuation freshness");

    let VerifyError::Grant(err) = err else {
        panic!("a resolver-derived but stale closure must reach CON-206 step 10")
    };
    assert_eq!(err.step as u8, 10);
    assert!(err.state_unavailable);
}

#[test]
fn refuses_a_bundle_closure_even_when_con_206_would_record_its_use() {
    let ceremony = Ceremony::accepted();
    let mut issuer = ceremony.issuer.clone();
    issuer.source = ClosureSource::BundleOrCache;

    let err = verify_session_establishment(
        &GrantRequest::new(
            &ceremony.profile,
            &ceremony.account,
            &ceremony.device_public_key,
            &[],
            ceremony.now,
            0,
        ),
        &GrantEvidence::new(
            &issuer,
            &ceremony.jrd,
            None,
            &ceremony.challenge,
            &ceremony.signature,
            VERIFIER_SESSION,
        ),
        &ceremony.grant_bytes,
    )
    .expect_err("a Path-B hub must never establish from a bundle closure");

    assert_eq!(err, VerifyError::NonResolverClosure);
}

#[test]
fn request_has_no_freshness_switch_for_a_nif_caller_to_weaken() {
    let ceremony = Ceremony::accepted();
    let request = GrantRequest::new(
        &ceremony.profile,
        &ceremony.account,
        &ceremony.device_public_key,
        &[],
        ceremony.now,
        0,
    );

    assert_eq!(request.freshness(), Freshness::SessionEstablishment);
}

#[test]
fn path_b_unions_revocations_across_distinct_declared_resolvers() {
    let ceremony = Ceremony::accepted();
    let first = vec!["urn:grant:a".to_owned(), "urn:grant:shared".to_owned()];
    let second = vec!["urn:grant:b".to_owned(), "urn:grant:shared".to_owned()];
    let observations = [
        ResolverRevocations { resolver_id: "app-own", revoked_credential_ids: &first },
        ResolverRevocations { resolver_id: "state-1", revoked_credential_ids: &second },
    ];
    assert_eq!(
        union_resolver_revocations(&ceremony.profile, &observations).unwrap(),
        vec!["urn:grant:a", "urn:grant:b", "urn:grant:shared"],
    );

    // A REPEATED LABEL IS STILL REFUSED, and this is the check that has to
    // survive the quorum reduction. `MINIMUM_RESOLVER_QUORUM` is 1, so one
    // observation is now enough — but "one resolver answering twice" must not
    // become a way to manufacture a second, and at a quorum of 2 this is the
    // whole substance of "distinct".
    let repeated = [
        ResolverRevocations { resolver_id: "app-own", revoked_credential_ids: &first },
        ResolverRevocations { resolver_id: "app-own", revoked_credential_ids: &second },
    ];
    assert!(union_resolver_revocations(&ceremony.profile, &repeated).is_err());

    // An UNDECLARED resolver is refused whatever the quorum is: the profile is
    // the roster, and an observation from outside it is not a weaker answer but
    // no answer at all.
    let undeclared = [ResolverRevocations { resolver_id: "not-in-the-profile", revoked_credential_ids: &first }];
    assert!(union_resolver_revocations(&ceremony.profile, &undeclared).is_err());
}

/// A SINGLE declared resolver is admitted, and that is the reduction rather
/// than a property worth having.
///
/// This test exists to make the change visible: it passes only while
/// `MINIMUM_RESOLVER_QUORUM` is 1, and raising the constant back to 2 turns it
/// red — which is the intended way to find every place that assumed one
/// resolver was enough. There is nothing to contradict the single observation,
/// so a resolver that omits a revoked id is believed.
#[test]
fn path_b_admits_a_single_declared_resolver_at_the_reduced_quorum() {
    assert_eq!(selfsame_app_identity::path_b::MINIMUM_RESOLVER_QUORUM, 1);

    let ceremony = Ceremony::accepted();
    let only = vec!["urn:grant:a".to_owned()];
    let observations = [ResolverRevocations { resolver_id: "app-own", revoked_credential_ids: &only }];

    assert_eq!(
        union_resolver_revocations(&ceremony.profile, &observations).unwrap(),
        vec!["urn:grant:a"],
    );
}
