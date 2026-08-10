//! Creating the application-account identity — `CON-203` stages one and two.
//!
//! `F3` of the G2 review was that a home key was derived and signed with while
//! its `did:crdt` document was never constructed, so every grant it issued was
//! unverifiable at `CON-206` step 4. These tests are about the document
//! existing and being the right one.

mod common;

use common::*;
use selfsame_app_identity::{alias, hierarchy, issuer, profile::ApplicationId, scope::AccountScopeId};

const NOW_MS: u64 = 1_785_412_800_000;

fn home_key(entropy: u8, scope_byte: u8) -> ed25519_dalek::SigningKey {
    let app = ApplicationId::parse(APPLICATION_ID).unwrap();
    let scope = AccountScopeId::from_octets([scope_byte; 32]);
    hierarchy::derive_from_mnemonic(&mnemonic(entropy), &app, &scope).signing_key().clone()
}

#[test]
fn the_did_is_the_one_the_home_key_derives() {
    let key = home_key(0, 1);
    let created = issuer::create(&key, ACCOUNT_AUTHORITY, NOW_MS).expect("constructs");

    // `did:crdt` is self-certifying: the identifier commits to the key. If the
    // genesis were built over anything else, a verifier recomputing the DID at
    // `CON-206` step 5 would get a different answer from the one the grant
    // names, and this is the cheapest place to catch that.
    let expected = selfsame_core::identity::derive_did(&key.verifying_key().to_bytes())
        .expect("the key derives a DID");
    assert_eq!(created.did, expected.as_str());
}

#[test]
fn the_alias_is_the_one_con_203_computes_from_that_did() {
    let key = home_key(1, 2);
    let created = issuer::create(&key, ACCOUNT_AUTHORITY, NOW_MS).expect("constructs");

    assert_eq!(created.acct_uri, alias::stable_acct_uri(&created.did, ACCOUNT_AUTHORITY));
}

/// `CON-203`'s ordering rule, checked as a property rather than trusted as a
/// comment: *"This ordering prevents a circular definition in which the alias
/// hashes the DID while the DID hashes the alias."*
///
/// The DID must be a function of the key alone. Changing the authority changes
/// the alias and must leave the identifier untouched.
#[test]
fn the_authority_changes_the_alias_and_never_the_did() {
    let key = home_key(2, 3);
    let a = issuer::create(&key, ACCOUNT_AUTHORITY, NOW_MS).expect("constructs");
    let b = issuer::create(&key, "accounts.other.example", NOW_MS).expect("constructs");

    assert_eq!(a.did, b.did, "the identifier commits to the key, not to the authority");
    assert_ne!(a.acct_uri, b.acct_uri);
}

/// The closure must carry **both** deltas. Genesis alone satisfies step 5 and
/// leaves `alsoKnownAs` absent, and `CON-203` says a resolver accepts the alias
/// *"only when that document-data update is present in the verified signed
/// closure"* — so a genesis-only closure fails step 9 instead, which is a
/// harder failure to read.
#[test]
fn the_closure_carries_the_genesis_and_the_alias_update() {
    let key = home_key(3, 4);
    let created = issuer::create(&key, ACCOUNT_AUTHORITY, NOW_MS).expect("constructs");

    assert_eq!(created.deltas.len(), 2);
    assert_eq!(created.closure.deltas.len(), 2);
}

/// The alias update commits to a frontier that already contains the genesis.
///
/// Without that, a verifier holds a delta whose parent it has never seen and
/// refuses the whole closure — the exact defect `SPEC-001`'s `authorise` records
/// having shipped once, where parenting on the wrong frontier made every bundle
/// unresolvable.
#[test]
fn the_alias_update_is_causally_after_the_genesis() {
    let key = home_key(4, 5);
    let created = issuer::create(&key, ACCOUNT_AUTHORITY, NOW_MS).expect("constructs");

    let genesis_hash = created.deltas[0].content_hash().expect("a delta hashes");
    let parents = &created.deltas[1].parents;
    assert!(
        parents.contains(&genesis_hash),
        "the alsoKnownAs update must name the genesis as a parent"
    );

    // And the closure's target is the head, not the root.
    let head = created.deltas[1].content_hash().expect("a delta hashes");
    assert_eq!(created.closure.target, head);
}

/// Two accounts under one application produce unrelated identities, which is
/// what `REQ-216` requires of the branches and what makes the account scope
/// worth having at all.
#[test]
fn distinct_accounts_produce_distinct_identities() {
    let a = issuer::create(&home_key(5, 6), ACCOUNT_AUTHORITY, NOW_MS).expect("constructs");
    let b = issuer::create(&home_key(5, 7), ACCOUNT_AUTHORITY, NOW_MS).expect("constructs");

    assert_ne!(a.did, b.did);
    assert_ne!(a.acct_uri, b.acct_uri);
}

/// Construction is deterministic in everything a verifier checks.
///
/// The signatures need not be byte-identical — Ed25519 as `did:crdt` uses it is
/// deterministic, but nothing here depends on that — while the identifier and
/// the alias must be, because they are what a person compares and what an
/// authority binds.
#[test]
fn the_identifier_and_alias_do_not_depend_on_the_clock() {
    let key = home_key(6, 8);
    let early = issuer::create(&key, ACCOUNT_AUTHORITY, NOW_MS).expect("constructs");
    let late = issuer::create(&key, ACCOUNT_AUTHORITY, NOW_MS + 86_400_000).expect("constructs");

    assert_eq!(early.did, late.did);
    assert_eq!(early.acct_uri, late.acct_uri);
}
