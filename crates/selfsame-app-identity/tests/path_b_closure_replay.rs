//! Credential/v2 resolver evidence must be derived from replayed signed
//! `did:crdt` history, never caller-asserted booleans.

mod common;

use common::{mnemonic, ACCOUNT_AUTHORITY, APPLICATION_ID};
use selfsame_app_identity::{
    hierarchy, issuer,
    path_b::{replay_resolver_closure, ClosureReplayError},
    profile::ApplicationId,
    scope::AccountScopeId,
};

const FETCHED_AT: i64 = 1_787_500_000;

fn created(entropy: u8, scope: u8) -> selfsame_app_identity::issuer::IssuerIdentity {
    let application = ApplicationId::parse(APPLICATION_ID).expect("application id");
    let scope = AccountScopeId::from_octets([scope; 32]);
    let key = hierarchy::derive_from_mnemonic(&mnemonic(entropy), &application, &scope)
        .signing_key()
        .clone();
    issuer::create(&key, ACCOUNT_AUTHORITY, 1_787_499_000_000).expect("issuer")
}

#[test]
fn replay_projects_only_verified_resolver_facts() {
    let issuer = created(21, 22);
    let observation = replay_resolver_closure(
        issuer.closure.clone(),
        &issuer.did,
        "https://did.anuna.io/",
        FETCHED_AT,
    )
    .expect("signed closure replays");

    assert_eq!(observation.resolver_id, "https://did.anuna.io/");
    assert_eq!(observation.did, issuer.did);
    assert!(observation.did_recomputed_ok);
    assert!(observation.deltas_verified);
    assert!(observation.locally_closed);
    assert!(!observation.deactivated);
    assert_eq!(observation.fetched_at_seconds, FETCHED_AT);
    assert_eq!(observation.also_known_as, vec![issuer.acct_uri.as_str()]);
    assert_eq!(observation.assertion_methods.len(), 1);
    assert_eq!(
        observation.assertion_methods[0].id,
        format!("{}#jwk-0", issuer.did)
    );
    assert_eq!(observation.assertion_methods[0].kind, "JsonWebKey");
    assert!(!observation.assertion_methods[0].has_private_component);
}

#[test]
fn a_closure_for_another_did_is_not_resolver_evidence() {
    let issuer = created(23, 24);
    assert_eq!(
        replay_resolver_closure(
            issuer.closure,
            "did:crdt:not-the-issuer",
            "https://did.anuna.io/",
            FETCHED_AT,
        ),
        Err(ClosureReplayError::DidMismatch)
    );
}

#[test]
fn a_second_genesis_is_rejected_before_delta_replay() {
    let mut issuer = created(25, 26);
    let other = created(27, 28);
    issuer.closure.deltas.push(
        other
            .closure
            .deltas
            .into_iter()
            .find(|delta| delta.parents.is_empty())
            .expect("other genesis"),
    );

    assert_eq!(
        replay_resolver_closure(
            issuer.closure,
            &issuer.did,
            "https://did.anuna.io/",
            FETCHED_AT,
        ),
        Err(ClosureReplayError::GenesisCount)
    );
}
