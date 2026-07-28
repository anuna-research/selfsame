//! The single-controller profile — SPEC-001 REQ-008, ADR-006, REQ-025.
//!
//! Upstream `did-crdt` authorises *any* known, non-revoked verification method
//! to sign *any* operation (`validate.rs:199`), and additionally admits
//! `AddVerificationMethod` from *any* signer on an empty document
//! (`validate.rs:192-196`). Without a profile, **a linked browser could add
//! devices or revoke the root** — linking would be a privilege escalation.
//!
//! The profile is stated over the *signer* rather than over an enumeration of
//! dangerous operations. An enumeration must be kept in step with an upstream
//! `DeltaOp` that will grow, and the day it falls out of step is a silent
//! privilege escalation; a signer filter cannot drift. [`TEST-008`] enumerates
//! every `DeltaOp` variant exhaustively so a new upstream variant fails this
//! crate's tests until it has been considered.
//!
//! # Reject, do not filter
//!
//! ADR-006 speaks of "filtering the delta set to genesis-key signatures". CON-003
//! post-condition 4 and CON-005's error model are stricter and win: a closure
//! containing *any* non-genesis signer is **discarded whole**, and no partial
//! document is built from it. Silently dropping a foreign delta would leave the
//! verifier believing it had seen the whole story.
//!
//! [`TEST-008`]: ../../../../anuna-ssi/specs/SPEC-001-device-key-provisioning.md

use did_crdt::core::delta::{SignedDelta, SuiteType};
use did_crdt::core::document::Document;
use did_crdt::core::validate::node_id_from_pubkey;
use did_crdt::Did;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::identity::root_method_id;

/// Why a delta closure failed the profile.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// A delta named a signer other than the genesis key (REQ-008).
    #[error("delta signed by a verification method other than the genesis key")]
    ForeignSigner,
    /// A delta targeted a different DID.
    #[error("delta targets a different identity")]
    WrongDid,
    /// A delta declared a suite other than Ed25519.
    #[error("unsupported signature suite")]
    WrongSuite,
    /// A signature was absent, malformed, or did not verify.
    #[error("delta signature does not verify under the genesis key")]
    BadSignature,
    /// A post-genesis delta did not carry the upstream node-id binding.
    #[error("delta node_id is not bound to the signer's public key")]
    UnboundNodeId,
    /// The closure contained no genesis delta, or more than one.
    #[error("closure does not contain exactly one genesis delta")]
    NotExactlyOneGenesis,
    /// A delta could not be merged into the document.
    #[error("did:crdt refused the delta: {0}")]
    Upstream(String),
}

/// Verify a signed delta against the single-controller profile.
///
/// Every clause is stated separately so a failure attributes to one rule.
pub fn check_delta(
    delta: &SignedDelta,
    did: &Did,
    root_public_key: &[u8; 32],
) -> Result<(), ProfileError> {
    if delta.did != *did {
        return Err(ProfileError::WrongDid);
    }
    // REQ-008: the signer, not the operation. Any other verification method is
    // invalid *regardless of what it is trying to do*.
    if delta.proof.verification_method != root_method_id(did) {
        return Err(ProfileError::ForeignSigner);
    }
    if delta.proof.suite != SuiteType::Ed25519Signature2020 {
        return Err(ProfileError::WrongSuite);
    }

    // The node-id binding stops an authorised signer choosing a favourable HLC
    // tiebreak. The genesis is exempt because upstream fixes its timestamp at
    // all-zero to make creation reproducible — there is no freedom to abuse.
    let is_genesis = delta.parents.is_empty();
    if !is_genesis && delta.timestamp.node_id != node_id_from_pubkey(root_public_key) {
        return Err(ProfileError::UnboundNodeId);
    }

    let signature = crate::mb::decode_exact::<64>(&delta.proof.proof_value)
        .map_err(|_| ProfileError::BadSignature)?;
    let vk = VerifyingKey::from_bytes(root_public_key).map_err(|_| ProfileError::BadSignature)?;
    let input = delta.signing_input().map_err(|e| ProfileError::Upstream(e.to_string()))?;
    vk.verify(&input, &Signature::from_bytes(&signature)).map_err(|_| ProfileError::BadSignature)
}

/// Apply the profile to a whole delta closure and resolve it locally (REQ-025).
///
/// This is what a verifier does instead of trusting a server-resolved DID
/// document: `GET /:did` upstream returns a *resolved* W3C document
/// (`handlers.rs:127`), which carries no signatures, so the signer profile
/// cannot be applied to it and the verifier would simply be trusting the
/// resolver's authorisation decisions.
///
/// The document is bootstrapped from `root_public_key`, which is where the DID
/// comes from in the first place (REQ-003), so a caller cannot smuggle in a
/// different root by reordering the closure.
pub fn resolve_closure(
    deltas: &[SignedDelta],
    root_public_key: &[u8; 32],
) -> Result<Document, ProfileError> {
    let (mut doc, genesis) = crate::identity::bootstrap(root_public_key)
        .map_err(|e| ProfileError::Upstream(e.to_string()))?;
    let did = doc.did.clone();

    let genesis_hash =
        genesis.content_hash().map_err(|e| ProfileError::Upstream(e.to_string()))?;

    let mut seen_genesis = 0usize;
    for delta in deltas {
        check_delta(delta, &did, root_public_key)?;
        let hash = delta.content_hash().map_err(|e| ProfileError::Upstream(e.to_string()))?;
        if hash == genesis_hash {
            seen_genesis += 1;
        }
    }
    if seen_genesis != 1 {
        return Err(ProfileError::NotExactlyOneGenesis);
    }

    // Genesis is already applied by `bootstrap`; merge the rest in causal order.
    // `Document::merge` re-checks structure and causality; signatures were
    // checked above under the profile, which is stricter than upstream's rule.
    let mut pending: Vec<&SignedDelta> = deltas
        .iter()
        .filter(|d| !d.parents.is_empty())
        .collect();
    while !pending.is_empty() {
        let before = pending.len();
        pending.retain(|delta| match doc.merge((*delta).clone()) {
            Ok(()) => false,
            Err(did_crdt::core::Error::DeltaPending { .. }) => true,
            Err(_) => false,
        });
        if pending.len() == before {
            // Nothing merged this round: the remaining deltas name parents the
            // closure does not contain. CON-005 requires the gap be named, not
            // silently tolerated.
            return Err(ProfileError::Upstream(
                "closure is not causally closed: a parent delta is missing".to_owned(),
            ));
        }
    }
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;
    use did_crdt::core::delta::{DeltaOp, SigningKey as DidSigningKey};
    use did_crdt::core::hlc::HlcTimestamp;
    use ed25519_dalek::SigningKey;

    fn root() -> SigningKey {
        SigningKey::from_bytes(&[0x11; 32])
    }

    fn device() -> SigningKey {
        SigningKey::from_bytes(&[0x22; 32])
    }

    fn linked() -> (Document, Vec<SignedDelta>, String) {
        let (mut doc, genesis) = identity::sign_genesis(&root()).unwrap();
        let dev = device().verifying_key().to_bytes();
        let add = identity::add_device(&doc, &root(), &dev, "dev-1", 1_000).unwrap();
        let method_id = match &add.op {
            DeltaOp::AddVerificationMethod { id, .. } => id.clone(),
            _ => unreachable!(),
        };
        doc.merge_verified_delta(add.clone()).unwrap();
        let label =
            identity::set_device_label(&doc, &root(), &method_id, "Chrome on macOS", 1_001).unwrap();
        doc.merge_verified_delta(label.clone()).unwrap();
        (doc, vec![genesis, add, label], method_id)
    }

    // TEST-008 positive: a genesis-signed delta is admitted.
    #[test]
    fn a_genesis_signed_closure_resolves() {
        let (_, deltas, method_id) = linked();
        let root_pk = root().verifying_key().to_bytes();
        let doc = resolve_closure(&deltas, &root_pk).unwrap();
        let resolved = doc.resolve().unwrap().did_document.unwrap();
        assert!(resolved.verification_method.iter().any(|vm| vm.id == method_id));
    }

    // TEST-008 negative-input: a device-key-signed delta is rejected for
    // **every** `DeltaOp` variant. The match below is exhaustive over the
    // upstream enum, so adding a variant upstream fails to compile here until
    // it has been considered.
    #[test]
    fn a_device_signed_delta_is_rejected_for_every_operation() {
        let (doc, _, method_id) = linked();
        let did = doc.did.clone();
        let root_pk = root().verifying_key().to_bytes();
        let dev_pk = device().verifying_key().to_bytes();

        let ops: Vec<DeltaOp> = vec![
            DeltaOp::AddVerificationMethod {
                id: format!("{did}#dev-2"),
                public_key_multibase: identity::key_multibase(&dev_pk),
                suite_type: SuiteType::Ed25519Signature2020,
                relationships: did_crdt::core::delta::default_relationships(),
            },
            DeltaOp::AddServiceEndpoint {
                id: format!("{did}#svc"),
                service_type: "x".into(),
                endpoint: "https://evil.example".into(),
            },
            DeltaOp::RemoveServiceEndpoint { id: format!("{did}#svc") },
            DeltaOp::SetDocumentData {
                key: "profile".into(),
                value: serde_json::Value::String("anything".into()),
            },
            DeltaOp::RotateKey { seq: 9, key_ref: method_id.clone() },
            DeltaOp::RevokeCredential { credential_id: "c".into() },
            // The two that matter most: a device promoting itself and a device
            // revoking the root.
            DeltaOp::RevokeVerificationMethod { key_id: identity::root_method_id(&did) },
            DeltaOp::Deactivate,
        ];

        // Exhaustiveness guard: if upstream gains a variant, this match stops
        // compiling and the list above must be extended.
        for op in &ops {
            match op {
                DeltaOp::AddVerificationMethod { .. }
                | DeltaOp::AddServiceEndpoint { .. }
                | DeltaOp::RemoveServiceEndpoint { .. }
                | DeltaOp::SetDocumentData { .. }
                | DeltaOp::RotateKey { .. }
                | DeltaOp::RevokeCredential { .. }
                | DeltaOp::RevokeVerificationMethod { .. }
                | DeltaOp::Deactivate => {}
            }
        }
        assert_eq!(ops.len(), 8, "every upstream DeltaOp variant must appear");

        for op in ops {
            let delta = SignedDelta::new_with_parents(
                did.clone(),
                op.clone(),
                HlcTimestamp {
                    wall_ms: 2_000,
                    logical: 0,
                    node_id: node_id_from_pubkey(&dev_pk),
                },
                doc.frontier(),
                method_id.clone(),
                &DidSigningKey::Ed25519(device()),
            )
            .unwrap();
            assert_eq!(
                check_delta(&delta, &did, &root_pk),
                Err(ProfileError::ForeignSigner),
                "device-signed {op:?} was not rejected"
            );
        }
    }

    // TEST-008 negative-input: an unsigned genesis-add on an empty document is
    // rejected. Upstream admits this (`validate.rs:192-196`); the profile does
    // not.
    #[test]
    fn an_unsigned_genesis_is_rejected() {
        // Upstream admits an unsigned `AddVerificationMethod` on an empty
        // document (`validate.rs:192-196`). The profile does not — twice over.
        let root_pk = root().verifying_key().to_bytes();
        let (_, mut unsigned) = identity::bootstrap(&root_pk).unwrap();
        let did = unsigned.did.clone();
        assert!(unsigned.proof.proof_value.is_empty());

        // As upstream builds it, the proof names the raw key rather than the
        // `#key-0` method id, so the signer rule fires first.
        assert_eq!(check_delta(&unsigned, &did, &root_pk), Err(ProfileError::ForeignSigner));

        // Repair that, and the missing signature is what refuses it.
        unsigned.proof.verification_method = identity::root_method_id(&did);
        assert_eq!(check_delta(&unsigned, &did, &root_pk), Err(ProfileError::BadSignature));
    }

    #[test]
    fn a_closure_missing_its_genesis_is_rejected() {
        let (_, deltas, _) = linked();
        let root_pk = root().verifying_key().to_bytes();
        assert_eq!(
            resolve_closure(&deltas[1..], &root_pk).unwrap_err(),
            ProfileError::NotExactlyOneGenesis
        );
    }

    #[test]
    fn a_closure_missing_a_causal_parent_is_named_not_silently_partial() {
        // CON-005 post-condition 2.
        let (_, deltas, _) = linked();
        let root_pk = root().verifying_key().to_bytes();
        let gapped = vec![deltas[0].clone(), deltas[2].clone()];
        match resolve_closure(&gapped, &root_pk) {
            Err(ProfileError::Upstream(msg)) => assert!(msg.contains("causally closed"), "{msg}"),
            other => panic!("expected a named causal gap, got {other:?}"),
        }
    }

    #[test]
    fn a_tampered_signature_is_rejected() {
        let (_, mut deltas, _) = linked();
        let root_pk = root().verifying_key().to_bytes();
        let did = deltas[0].did.clone();
        deltas[1].proof.proof_value = crate::mb::encode(&[0u8; 64]);
        assert_eq!(check_delta(&deltas[1], &did, &root_pk), Err(ProfileError::BadSignature));
    }

    #[test]
    fn a_delta_for_another_did_is_rejected() {
        let (_, deltas, _) = linked();
        let root_pk = root().verifying_key().to_bytes();
        let other_did = identity::derive_did(&device().verifying_key().to_bytes()).unwrap();
        assert_eq!(check_delta(&deltas[1], &other_did, &root_pk), Err(ProfileError::WrongDid));
    }

    #[test]
    fn a_post_genesis_delta_with_an_unbound_node_id_is_rejected() {
        let (doc, _, _) = linked();
        let root_pk = root().verifying_key().to_bytes();
        let delta = SignedDelta::new_with_parents(
            doc.did.clone(),
            DeltaOp::SetDocumentData {
                key: "x".into(),
                value: serde_json::Value::Null,
            },
            HlcTimestamp { wall_ms: 3_000, logical: 0, node_id: 42 },
            doc.frontier(),
            identity::root_method_id(&doc.did),
            &DidSigningKey::Ed25519(root()),
        )
        .unwrap();
        assert_eq!(check_delta(&delta, &doc.did, &root_pk), Err(ProfileError::UnboundNodeId));
    }

    // TEST-010 negative-input: a revoke signed by the device itself is
    // rejected; only the root may revoke.
    #[test]
    fn a_device_cannot_revoke_itself_or_the_root() {
        let (doc, _, method_id) = linked();
        let root_pk = root().verifying_key().to_bytes();
        let dev_pk = device().verifying_key().to_bytes();
        let delta = SignedDelta::new_with_parents(
            doc.did.clone(),
            DeltaOp::RevokeVerificationMethod { key_id: identity::root_method_id(&doc.did) },
            HlcTimestamp { wall_ms: 4_000, logical: 0, node_id: node_id_from_pubkey(&dev_pk) },
            doc.frontier(),
            method_id,
            &DidSigningKey::Ed25519(device()),
        )
        .unwrap();
        assert_eq!(check_delta(&delta, &doc.did, &root_pk), Err(ProfileError::ForeignSigner));
    }
}
