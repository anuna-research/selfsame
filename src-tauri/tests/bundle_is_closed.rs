//! A bundle must be causally closed — regression for the bug that shipped.
//!
//! `crates/selfsame-rendezvous/tests/end_to_end.rs` builds its bundle from an
//! identity whose only delta is the genesis, so the chain
//! `genesis → add → label` was closed by accident and the test passed. **The
//! real application is never in that state**: ADR-006's profile declaration is
//! written at identity creation, so by the time anyone links a device the
//! identity already has a second delta.
//!
//! With the add parented on the *frontier*, the bundle then carried a delta
//! whose parent it did not contain, and every client refused the whole closure
//! with *"Couldn't link — the reply didn't match this device."* CON-002 caps
//! the bundle at three deltas, so the only way it can be closed is for the add
//! to be parented on the genesis itself.
//!
//! This test asserts the property directly — the bundle resolves under the
//! same predicate a client applies — and it does so from an identity carrying
//! extra deltas, which is the state the bug needed and the old test never had.

use selfsame_core::{
    accept, identity,
    record::{Application, Grant, Offer},
    seal, LinkContext, RejectReason,
};
use did_crdt::core::delta::{DeltaOp, SignedDelta, SigningKey as DidSigningKey};
use did_crdt::core::document::Document;
use did_crdt::core::hlc::HlcTimestamp;
use did_crdt::core::validate::node_id_from_pubkey;
use ed25519_dalek::SigningKey;

const NOW: u64 = 1_790_000_000;

fn root() -> SigningKey {
    SigningKey::from_bytes(&[0x11; 32])
}

fn device() -> SigningKey {
    SigningKey::from_bytes(&[0x22; 32])
}

/// An identity in the state the application actually keeps it in: genesis, the
/// ADR-006 profile declaration, and `extra_devices` already linked.
fn realistic_identity(extra_devices: usize) -> (Document, SignedDelta, Vec<SignedDelta>) {
    let root = root();
    let (mut doc, genesis) = identity::sign_genesis(&root).unwrap();
    let mut history = vec![genesis.clone()];

    let profile = identity::declare_profile(&doc, &root, NOW * 1_000).unwrap();
    doc.merge_verified_delta(profile.clone()).unwrap();
    history.push(profile);

    for i in 0..extra_devices {
        let key = SigningKey::from_bytes(&[0x30 + i as u8; 32]);
        let add = identity::add_device(
            &doc,
            &root,
            &key.verifying_key().to_bytes(),
            &format!("dev-{}", i + 1),
            NOW * 1_000 + i as u64 + 1,
        )
        .unwrap();
        doc.merge_verified_delta(add.clone()).unwrap();
        history.push(add);
    }

    (doc, genesis, history)
}

/// Build the bundle the way `commands::authorise` does: parented on the
/// genesis, so the three deltas are closed among themselves.
fn bundle_for(offer: &Offer, fragment: &str) -> Grant {
    let root = root();
    let (mut from_genesis, genesis) = identity::sign_genesis(&root).unwrap();
    let ms = NOW * 1_000 + 500;
    let add =
        identity::add_device(&from_genesis, &root, &offer.device_key, fragment, ms).unwrap();
    from_genesis.merge_verified_delta(add.clone()).unwrap();
    let method_id = format!("{}#{fragment}", from_genesis.did);
    let label = identity::set_device_label(
        &from_genesis,
        &root,
        &method_id,
        &offer.device_description,
        ms + 1,
    )
    .unwrap();

    let deltas: Vec<Vec<u8>> =
        [genesis, add, label].iter().map(|d| serde_json::to_vec(d).unwrap()).collect();
    Grant::new(from_genesis.did.to_string(), deltas)
}

fn offer() -> Offer {
    Offer::sign(Application::CbclChat, &device(), "Chrome on macOS", NOW + 300)
}

#[test]
fn a_bundle_from_an_identity_with_history_is_accepted() {
    // Two, three, and four existing deltas: the bug appeared at the *first*
    // delta beyond the genesis, so the smallest case is the important one.
    for extra in 0..3 {
        let (_, _, _) = realistic_identity(extra);
        let offer = offer();
        let grant = bundle_for(&offer, &format!("dev-{}", extra + 1));
        let secret = [0x5au8; 16];
        let sealed =
            seal::seal_bundle(&seal::derive_key(&secret), &grant.to_bytes(), &offer.transcript());

        let accepted = accept(&sealed, &LinkContext { secret, offer }, NOW)
            .unwrap_or_else(|e| panic!("bundle rejected with {extra} extra deltas: {e}"));
        assert_eq!(accepted.did, grant.did);
        assert_eq!(accepted.deltas.len(), 3, "CON-002 admits 2-3 deltas");
    }
}

/// The failure mode itself, stated as a test: parent the add on the frontier of
/// an identity that has other deltas, and the bundle is unresolvable. This is
/// what the application used to do.
#[test]
fn a_frontier_parented_bundle_is_refused_because_it_is_not_closed() {
    let (doc, genesis, _) = realistic_identity(0);
    let root = root();
    let offer = offer();

    let add =
        identity::add_device(&doc, &root, &offer.device_key, "dev-1", NOW * 1_000 + 9).unwrap();
    assert_ne!(
        add.parents,
        vec![genesis.content_hash().unwrap()],
        "this test is only meaningful if the add is parented past the genesis"
    );

    let deltas: Vec<Vec<u8>> =
        [genesis, add].iter().map(|d| serde_json::to_vec(d).unwrap()).collect();
    let grant = Grant::new(doc.did.to_string(), deltas);
    let secret = [0x5au8; 16];
    let sealed =
        seal::seal_bundle(&seal::derive_key(&secret), &grant.to_bytes(), &offer.transcript());

    assert_eq!(
        accept(&sealed, &LinkContext { secret, offer }, NOW),
        Err(RejectReason::Unrecognised),
        "a bundle missing a causal parent must be refused whole (CON-005)"
    );
}

/// Concurrency is the point, not a workaround: a device added off the genesis
/// converges with everything else, because verification methods are a G-Set.
#[test]
fn a_genesis_parented_device_converges_with_the_rest_of_the_identity() {
    let (mut doc, _, _) = realistic_identity(1);
    let offer = offer();
    let grant = bundle_for(&offer, "dev-2");

    for bytes in &grant.deltas {
        let delta: SignedDelta = serde_json::from_slice(bytes).unwrap();
        if delta.parents.is_empty() {
            continue; // the genesis is already applied
        }
        doc.merge_verified_delta(delta).unwrap();
    }

    let resolved = doc.resolve().unwrap().did_document.unwrap();
    let wanted = identity::key_multibase(&offer.device_key);
    assert!(
        resolved.verification_method.iter().any(|vm| vm.public_key_multibase.as_deref() == Some(wanted.as_str())),
        "the concurrently-added device must appear in the merged document"
    );
    // …and the pre-existing device is still there, which is what "converges"
    // means and what a non-CRDT would have got wrong.
    assert_eq!(
        resolved.verification_method.len(),
        3,
        "root, the earlier device, and the new one"
    );
    // The profile declaration survives too.
    assert_eq!(
        resolved.extra.get(identity::PROFILE_KEY).and_then(|v| v.as_str()),
        Some(identity::PROFILE_VALUE)
    );
}

/// The label must be a causal descendant of the add, or a verifier can resolve
/// a name for a method it has not yet seen.
#[test]
fn the_label_is_parented_on_the_add() {
    let offer = offer();
    let grant = bundle_for(&offer, "dev-1");
    let deltas: Vec<SignedDelta> =
        grant.deltas.iter().map(|b| serde_json::from_slice(b).unwrap()).collect();

    let add = deltas
        .iter()
        .find(|d| matches!(d.op, DeltaOp::AddVerificationMethod { .. }) && !d.parents.is_empty())
        .expect("an add delta");
    let label = deltas
        .iter()
        .find(|d| matches!(d.op, DeltaOp::SetDocumentData { .. }))
        .expect("a label delta");
    assert_eq!(label.parents, vec![add.content_hash().unwrap()]);
}

/// Guard the assumption the fix rests on: the signed genesis keeps the content
/// hash `Document::new` records, so bootstrapping from the root public key
/// reproduces the exact parent the add names.
#[test]
fn the_genesis_a_verifier_bootstraps_is_the_one_the_add_names() {
    let offer = offer();
    let grant = bundle_for(&offer, "dev-1");
    let deltas: Vec<SignedDelta> =
        grant.deltas.iter().map(|b| serde_json::from_slice(b).unwrap()).collect();
    let add = deltas.iter().find(|d| !d.parents.is_empty()).unwrap();

    let (_, bootstrapped) = identity::bootstrap(&root().verifying_key().to_bytes()).unwrap();
    assert_eq!(add.parents, vec![bootstrapped.content_hash().unwrap()]);
}

/// A delta signed with a node id that is not bound to the root key is refused,
/// so the parenting change cannot be used to smuggle one in.
#[test]
fn the_node_id_binding_still_holds_for_the_genesis_parented_deltas() {
    let (doc, _, _) = realistic_identity(0);
    let forged = SignedDelta::new_with_parents(
        doc.did.clone(),
        DeltaOp::SetDocumentData { key: "x".into(), value: serde_json::Value::Null },
        HlcTimestamp { wall_ms: NOW * 1_000, logical: 0, node_id: 1 },
        doc.frontier(),
        identity::root_method_id(&doc.did),
        &DidSigningKey::Ed25519(root()),
    )
    .unwrap();
    assert_ne!(forged.timestamp.node_id, node_id_from_pubkey(&root().verifying_key().to_bytes()));
    assert!(selfsame_core::profile::check_delta(
        &forged,
        &doc.did,
        &root().verifying_key().to_bytes()
    )
    .is_err());
}
