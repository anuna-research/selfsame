//! `TEST-224` — `did:crdt` method-boundary compatibility.
//!
//! **Validates:** `REQ-201`, `REQ-203`, `REQ-205`, `REQ-208`.
//!
//! > Use two account-derived Ed25519 public keys to create two ordinary
//! > independent `did:crdt` genesis documents. Apply a root-signed
//! > `SetDocumentData` update for `alsoKnownAs` to each and require resolution
//! > to expose the exact RFC 7565 URI at the DID Document top level.
//! >
//! > Require the issuer key to resolve at `#jwk-0` as `type: JsonWebKey` with
//! > `publicKeyJwk` and membership in `assertionMethod`. Confirm that adding
//! > this resolver representation does not change the genesis bytes or DID
//! > identifier computed by the pinned method.
//! >
//! > Issue a grant ID, apply a valid `RevokeCredential` delta, merge concurrent
//! > revocations in different orders, and require the existing
//! > `Document::is_revoked` interface to return the same permanent result.
//!
//! # This test is where a Tier-1 gate item is measured rather than asserted
//!
//! The gate says of the `JsonWebKey` projection:
//!
//! > As of the pinned revision `adb5c7ac`, `resolve()` emits
//! > `publicKeyMultibase` and the crate contains no `publicKeyJwk`, so the
//! > `CON-203` document shape and the `CON-206` step 6 check are **not
//! > producible today**.
//!
//! So this suite splits in two. What the method *can* do today is tested
//! normally. What it cannot is pinned by
//! [`the_jsonwebkey_projection_is_still_not_producible`], which asserts the
//! current shape and will fail the moment upstream lands the projection — at
//! which point the gate item closes and the test is replaced by the positive one
//! `TEST-224` actually asks for.
//!
//! Pinning it as a failing-when-fixed test rather than a `#[ignore]` is
//! deliberate. An ignored test is invisible; this one is counted, green, and
//! says in its own assertion message what closing it requires.

mod common;

use common::*;
use selfsame_app_identity::alias;
use selfsame_app_identity::hierarchy;
use selfsame_app_identity::profile::ApplicationId;
use selfsame_app_identity::revocation;
use selfsame_app_identity::scope::AccountScopeId;

use did_crdt::core::delta::{DeltaOp, SignedDelta, SigningKey as DidSigningKey};
use did_crdt::core::document::Document;
use did_crdt::core::hlc::HlcTimestamp;
use did_crdt::core::validate::node_id_from_pubkey;

/// One account's home identity, brought all the way up to a live replica.
struct Home {
    document: Document,
    key: ed25519_dalek::SigningKey,
    method_id: String,
    did: String,
    acct: String,
}

fn home(application_id: &str, scope_byte: u8) -> Home {
    let app = ApplicationId::parse(application_id).expect("canonical");
    let scope = AccountScopeId::from_octets([scope_byte; 32]);
    let derived = hierarchy::derive_from_mnemonic(&mnemonic(0), &app, &scope);
    let key = derived.signing_key().clone();

    // "two ordinary independent did:crdt genesis documents" — ordinary meaning
    // the method's own genesis, with no Selfsame-specific step.
    let (mut document, genesis) =
        selfsame_core::identity::sign_genesis(&key).expect("genesis signs");
    document.merge(genesis).expect("genesis merges");

    let did = document.did.to_string();
    let method_id = selfsame_core::identity::root_method_id(&document.did);
    let acct = alias::stable_acct_uri(&did, ACCOUNT_AUTHORITY);
    Home { document, key, method_id, did, acct }
}

fn signed_op(h: &Home, op: DeltaOp, now_ms: u64) -> SignedDelta {
    let public = h.key.verifying_key().to_bytes();
    SignedDelta::new_with_parents(
        h.document.did.clone(),
        op,
        HlcTimestamp { wall_ms: now_ms, logical: 0, node_id: node_id_from_pubkey(&public) },
        h.document.frontier(),
        h.method_id.clone(),
        &DidSigningKey::Ed25519(h.key.clone()),
    )
    .expect("delta signs")
}

/// The `CON-203` step 2 update: a root-signed `SetDocumentData` setting
/// `alsoKnownAs` to the deterministically named alias.
fn publish_alias(h: &mut Home, aliases: &[&str]) {
    let op = DeltaOp::SetDocumentData {
        key: "alsoKnownAs".into(),
        value: serde_json::json!(aliases),
    };
    let delta = signed_op(h, op, 1_000);
    h.document.merge_verified_delta(delta).expect("the update is admitted");
}

// ── the two independent identities ─────────────────────────────────────────

#[test]
fn two_account_derived_keys_produce_two_independent_genesis_documents() {
    let a = home(APPLICATION_ID, 1);
    let b = home(OTHER_APPLICATION_ID, 1);

    assert_ne!(a.did, b.did, "two application nodes, two DIDs");
    assert_ne!(a.acct, b.acct);
    assert!(a.did.starts_with("did:crdt:"), "{}", a.did);

    // Independent: neither document knows anything of the other.
    assert!(a.document.resolve().is_ok());
    assert!(b.document.resolve().is_ok());
    assert_ne!(a.document.frontier(), b.document.frontier());
}

#[test]
fn a_root_signed_update_exposes_the_exact_rfc_7565_uri_at_the_document_top_level() {
    for (application_id, scope) in [(APPLICATION_ID, 1u8), (OTHER_APPLICATION_ID, 2u8)] {
        let mut h = home(application_id, scope);
        let expected = h.acct.clone();
        publish_alias(&mut h, &[&expected]);

        let resolved = h.document.resolve().expect("resolves");
        let document = resolved.did_document.expect("not deactivated");

        // `SetDocumentData` lands in the flattened `extra` map, which serialises
        // at the top level of the DID Document — which is what CON-203's shape
        // requires and what a verifier reads.
        let also_known_as = document
            .extra
            .get("alsoKnownAs")
            .unwrap_or_else(|| panic!("alsoKnownAs is absent for {application_id}"));
        let entries: Vec<&str> =
            also_known_as.as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(entries, vec![expected.as_str()], "the exact URI, not a normalisation of it");
        assert_eq!(document.id, h.did);
    }
}

#[test]
fn the_alias_is_absent_until_the_update_is_applied() {
    // CON-203: "A resolver accepts `alsoKnownAs` only when that document-data
    // update is present in the verified signed closure." Before it, the alias
    // is nameable by the controller and asserted by nobody.
    let h = home(APPLICATION_ID, 1);
    let document = h.document.resolve().unwrap().did_document.unwrap();
    assert!(!document.extra.contains_key("alsoKnownAs"));
}

#[test]
fn both_the_stable_and_the_optional_alias_survive_one_update() {
    // CON-212 step 5 sets `alsoKnownAs` to `[stable_acct_uri, human_acct_uri]`.
    let mut h = home(APPLICATION_ID, 1);
    let stable = h.acct.clone();
    let human = alias::username_acct_uri("alice", ACCOUNT_AUTHORITY);
    publish_alias(&mut h, &[&stable, &human]);

    let document = h.document.resolve().unwrap().did_document.unwrap();
    let entries: Vec<&str> = document.extra["alsoKnownAs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(entries, vec![stable.as_str(), human.as_str()]);
}

// ── the resolver representation must not disturb the identifier ────────────

#[test]
fn publishing_an_alias_changes_neither_the_did_nor_the_genesis_derivation() {
    // "Confirm that adding this resolver representation does not change the
    // genesis bytes or DID identifier computed by the pinned method." A DID that
    // moved when its document was updated would make every issued grant's
    // `issuer` wrong.
    let mut h = home(APPLICATION_ID, 1);
    let before = h.did.clone();
    let recomputed_before =
        selfsame_core::identity::derive_did(&h.key.verifying_key().to_bytes()).unwrap();

    let acct = h.acct.clone();
    publish_alias(&mut h, &[&acct]);

    assert_eq!(h.document.did.to_string(), before);
    let recomputed_after =
        selfsame_core::identity::derive_did(&h.key.verifying_key().to_bytes()).unwrap();
    assert_eq!(recomputed_before, recomputed_after);
    assert_eq!(recomputed_after.to_string(), before);
}

// ── the assertionMethod half, which the gate records as already satisfied ──

#[test]
fn the_root_key_renders_into_the_resolved_document_with_its_relationships() {
    // The Tier-1 gate: "The `assertionMethod` half of this item is already
    // satisfied: verification-method relationships render into the resolved
    // document."
    let h = home(APPLICATION_ID, 1);
    let document = h.document.resolve().unwrap().did_document.unwrap();

    assert_eq!(document.verification_method.len(), 1, "one root key at genesis");
    let method = &document.verification_method[0];
    assert_eq!(method.id, h.method_id);
    assert_eq!(method.controller, h.did);
    assert!(!method.public_key_multibase.as_deref().unwrap_or_default().is_empty());

    // Some relationship set renders. Which relationships genesis grants is the
    // method's business; that they render at all is what CON-206 step 6 needs.
    let rendered = !document.assertion_method.is_empty()
        || !document.authentication.is_empty()
        || !document.capability_invocation.is_empty();
    assert!(rendered, "no verification relationship rendered into the document");
}

/// The `JsonWebKey` projection the Tier-1 gate is waiting on.
///
/// `CON-203` requires the resolved document to carry
/// `type: JsonWebKey` with `publicKeyJwk`, and `CON-206` step 6 requires a
/// verifier to find one. Neither is producible at the pinned revision.
///
/// This test asserts the **current** shape. When upstream lands the projection
/// it fails, and the message says what to do — which is the behaviour a
/// `#[ignore]` would not give, because an ignored test never tells anyone the
/// world changed.
#[test]
fn the_jsonwebkey_projection_is_still_not_producible() {
    let h = home(APPLICATION_ID, 1);
    let document = h.document.resolve().unwrap().did_document.unwrap();
    let method = &document.verification_method[0];

    assert_ne!(
        method.r#type, "JsonWebKey",
        "did:crdt now emits JsonWebKey — close the Tier-1 gate item, adopt the \
         positive TEST-224 assertion, and delete this test"
    );
    assert!(
        !method.public_key_multibase.as_deref().unwrap_or_default().is_empty(),
        "the pinned revision represents keys as publicKeyMultibase"
    );

    // The consequence for this crate, stated where it is visible: `accept`
    // takes `VerificationMethod { kind, jwk, .. }` as an *injected* value, so
    // the shell is currently obliged to perform the multibase → JWK conversion
    // that the method does not. That conversion is a Tier-1-gated dependency
    // and is deliberately not written here — doing it in the core would make
    // this crate the accidental standard for a projection the method owns.
    let fragment = h.method_id.rsplit('#').next().unwrap();
    assert_eq!(fragment, "key-0", "the method names the root key #key-0, not #jwk-0");
}

// ── revocation across the boundary ─────────────────────────────────────────

/// A grant ID for `did`, with the canonical 43-character token `CON-205` fixes.
///
/// `label` selects a token and is not one: the token is 32 octets base64url, and
/// `revoke_credential` checks that, so a short stand-in would exercise a shape no
/// grant ever has.
fn grant_id(did: &str, label: &str) -> String {
    let mut octets = [0u8; 32];
    for (i, b) in label.bytes().enumerate().take(32) {
        octets[i] = b;
    }
    format!("{did}#grant-{}", selfsame_app_identity::codec::b64url(&octets))
}

#[test]
fn a_grant_id_revokes_and_converges_under_every_merge_order() {
    // The last paragraph of TEST-224, and the one part of it that "is already
    // part of the inspected method and requires no new did:crdt amendment".
    let base = home(APPLICATION_ID, 1);
    let ids: Vec<String> =
        ["AAAA", "BBBB", "CCCC"].iter().map(|t| grant_id(&base.did, t)).collect();

    let deltas: Vec<SignedDelta> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            revocation::revoke_credential(
                &base.document,
                &base.key,
                &base.method_id,
                id,
                1_000 + i as u64,
            )
            .expect("signs")
        })
        .collect();

    for order in [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
        let mut replica = base.document.clone();
        for i in order {
            revocation::admit_revocation(&mut replica, deltas[i].clone()).expect("admitted");
        }
        for id in &ids {
            assert!(replica.is_revoked(id), "order {order:?} lost {id}");
        }
    }
}

#[test]
fn revocation_is_permanent_across_the_method_interface() {
    let mut h = home(APPLICATION_ID, 1);
    let id = grant_id(&h.did, "AAAA");
    let delta = revocation::revoke_credential(&h.document, &h.key, &h.method_id, &id, 1_000)
        .expect("signs");
    revocation::admit_revocation(&mut h.document, delta).expect("admitted");
    assert!(h.document.is_revoked(&id));

    // A later document-data update — the operation CON-212 uses for a username
    // change — must not disturb it.
    let acct = h.acct.clone();
    publish_alias(&mut h, &[&acct]);
    assert!(h.document.is_revoked(&id), "a SetDocumentData update cleared a revocation");
}

#[test]
fn one_accounts_revocation_does_not_reach_a_sibling_account() {
    // REQ-216: a revocation entry belonging to A1 "SHALL confer no authority in
    // A2, even though both accounts share an applicationId".
    let mut a1 = home(APPLICATION_ID, 1);
    let a2 = home(APPLICATION_ID, 2);

    let id = grant_id(&a1.did, "AAAA");
    let delta = revocation::revoke_credential(&a1.document, &a1.key, &a1.method_id, &id, 1_000)
        .expect("signs");
    revocation::admit_revocation(&mut a1.document, delta.clone()).expect("admitted");

    assert!(a1.document.is_revoked(&id));
    assert!(!a2.document.is_revoked(&id), "the sibling account knows nothing of it");

    // And A1's delta is not admissible into A2 at all: the DIDs differ.
    let mut sibling = a2.document.clone();
    assert!(
        sibling.merge_verified_delta(delta).is_err(),
        "a delta for one DID must not be admitted by another"
    );
}
