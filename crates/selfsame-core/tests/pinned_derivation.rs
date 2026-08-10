//! ADR-010 pin enforcement — SPEC-001 TEST-003, Tier-1 gate condition B.
//!
//! ADR-010 depends on `did-crdt` at `9a53bff1ed3eb88680fe19db0366ffd13d6b240a`,
//! adopts its DID derivation and `u`-multibase encoding **verbatim**, and
//! declares that *any change to either is a breaking change to the
//! specification*. A comment cannot enforce that. This file can: it restates
//! the derivation independently of the upstream helper and asserts the two
//! agree, so a change to upstream's `serde_json` field order, its proto-op
//! shape, or its zero-timestamp convention fails the build here rather than
//! silently re-deriving every user's identity.
//!
//! ADR-001 records the underlying fragility honestly: the derivation hashes a
//! `serde_json` tuple, so it depends on serde field ordering rather than on a
//! declared canonicalisation. That is OQ-009, and it is pinned rather than
//! solved. This test is what "pinned" means operationally.

use selfsame_core::identity;
use did_crdt::core::delta::{default_relationships, DeltaOp, SuiteType};
use did_crdt::core::hlc::HlcTimestamp;
use ed25519_dalek::SigningKey;

/// Restate the pinned rule without calling `Document::new`, so agreement is
/// evidence rather than tautology.
fn derive_did_independently(root_public_key: &[u8; 32]) -> String {
    let public_key_multibase = selfsame_core::mb::encode(root_public_key);
    let timestamp = HlcTimestamp::default();
    let proto_op = DeltaOp::AddVerificationMethod {
        id: "#key-0".to_owned(),
        public_key_multibase: public_key_multibase.clone(),
        suite_type: SuiteType::default(),
        relationships: default_relationships(),
    };
    let seed = serde_json::to_vec(&(&timestamp, &proto_op, &public_key_multibase)).unwrap();
    format!("did:crdt:{}", blake3::hash(&seed).to_hex())
}

#[test]
fn the_pinned_derivation_still_holds() {
    for seed in [0u8, 1, 0x42, 0xff] {
        let root = SigningKey::from_bytes(&[seed; 32]);
        let pk = root.verifying_key().to_bytes();
        assert_eq!(
            identity::derive_did(&pk).unwrap().to_string(),
            derive_did_independently(&pk),
            "upstream DID derivation has moved away from the ADR-010 pin"
        );
    }
}

#[test]
fn the_zero_timestamp_convention_still_holds() {
    // The DID commits to an all-zero HLC timestamp. If upstream ever seeded
    // creation from a wall clock, DIDs would stop being reproducible from the
    // root key alone and NFR-006 (offline verification) would break.
    assert_eq!(
        HlcTimestamp::default(),
        HlcTimestamp { wall_ms: 0, logical: 0, node_id: 0 }
    );
}

#[test]
fn the_default_suite_is_still_ed25519() {
    // The proto-op hashed into the DID carries `SuiteType::default()`. A change
    // of default upstream would re-derive every DID.
    assert_eq!(SuiteType::default(), SuiteType::Ed25519Signature2020);
}

#[test]
fn the_default_relationship_set_is_still_authentication_only() {
    assert_eq!(default_relationships().len(), 1);
    // The serialised spelling matters, not just the variant: this string is
    // part of the bytes hashed into every DID.
    assert_eq!(
        serde_json::to_string(&default_relationships()).unwrap(),
        r#"["Authentication"]"#
    );
}

#[test]
fn the_multibase_spelling_is_still_u_base64url_no_pad() {
    // REQ-027 and `validate.rs:224`. If upstream moved to `z` base58btc, every
    // key in every document would change spelling and no signature over a
    // document would verify across the boundary.
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    let key = [0x42u8; 32];
    assert_eq!(
        selfsame_core::mb::encode(&key),
        format!("u{}", Base64UrlUnpadded::encode_string(&key))
    );
}

#[test]
fn the_root_method_fragment_is_still_key_zero() {
    let root = SigningKey::from_bytes(&[9u8; 32]);
    let (doc, genesis) = identity::bootstrap(&root.verifying_key().to_bytes()).unwrap();
    match &genesis.op {
        DeltaOp::AddVerificationMethod { id, .. } => {
            assert_eq!(*id, format!("{}#key-0", doc.did));
            assert_eq!(*id, identity::root_method_id(&doc.did));
        }
        other => panic!("genesis op is no longer AddVerificationMethod: {other:?}"),
    }
}
