//! Identity state — SPEC-001 REQ-003, REQ-020, REQ-021, ADR-006, ADR-010.
//!
//! Construction of the four deltas that make up a [`Selfsame`] identity, and
//! the pinned DID derivation every verifier recomputes.
//!
//! ```text
//!   genesis ──▶ AddVerificationMethod ──▶ SetDocumentData (label)
//!   (root key)   (#dev-N, device key)      (keyed by the method id)
//!       │
//!       └──────▶ RevokeVerificationMethod  (needs only the root key — REQ-010)
//! ```
//!
//! # The derivation is pinned, not designed
//!
//! ADR-010: `did-crdt` is depended on at `adb5c7ac…` and its derivation is
//! adopted **verbatim** — `BLAKE3(serde_json(⟨zero HLC timestamp, proto-op,
//! signer_key⟩))` where the proto-op is an `AddVerificationMethod` carrying the
//! placeholder fragment `#key-0`. v0.1.0 of the spec invented
//! `blake3(canonical(genesis))` and `z6Mk…` keys; a literal implementation of
//! that contract would have rejected every genuine DID. [`derive_did`]
//! therefore calls upstream rather than restating the rule, and
//! `tests/pinned_derivation.rs` fails if upstream's answer ever moves.
//!
//! # Genesis timestamps, and why they are all zero
//!
//! Upstream derives the DID from a **zero** HLC timestamp so that creation is
//! reproducible on every replica, and `Document::new` records the genesis at
//! that same zero timestamp. The signed genesis this module produces therefore
//! also carries `HlcTimestamp::default()`, so its content hash equals the one
//! `Document::new` puts in the DAG and a verifier can bootstrap from the root
//! key alone. Every *post*-genesis delta carries the node-id binding upstream
//! requires (`node_id = BLAKE3(signer_pubkey)[0..8]`), so the resolver accepts
//! them through its ordinary verified path.
//!
//! [`Selfsame`]: ../../../apps/selfsame/README.md

use did_crdt::core::delta::{
    default_relationships, DeltaOp, SignedDelta, SigningKey as DidSigningKey, SuiteType,
    VerificationRelationship,
};
use did_crdt::core::document::Document;
use did_crdt::core::hlc::HlcTimestamp;
use did_crdt::core::validate::node_id_from_pubkey;
use did_crdt::Did;
use ed25519_dalek::SigningKey;

use crate::mb;

/// `SetDocumentData` key carrying the profile declaration (ADR-006).
///
/// The single-controller profile gives the same DID **different meanings** to a
/// conforming and a non-conforming resolver: upstream would accept a
/// device-signed `AddVerificationMethod` that this profile rejects. That is a
/// genuine interoperability defect, not merely a fence — so the profile is
/// declared *in the document* and the divergence is stated rather than silent.
pub const PROFILE_KEY: &str = "profile";

/// The profile this build enforces.
pub const PROFILE_VALUE: &str = "anuna-ssi/v1/single-controller";

/// The document-data key `CON-203` sets to the account's `acct:` alias.
///
/// An array, because the DID Document member is one, and `CON-203`'s example
/// carries exactly one entry: a verifier accepts `alsoKnownAs` only when the
/// document-data update setting it is present in the verified signed closure.
// `ALSO_KNOWN_AS_KEY` is deliberately gone. It named a documentData key that
// upstream now REFUSES, so keeping it would advertise a route that no longer
// exists — and a constant naming an illegal key is an invitation to use it.
// Aliases are written with `DeltaOp::SetAlsoKnownAs`.

/// Maximum user-visible device label, in characters (REQ-021).
pub const MAX_DEVICE_LABEL_CHARS: usize = 64;

/// The verification-method fragment the root key occupies. Fixed by upstream.
pub const ROOT_FRAGMENT: &str = "#key-0";

/// Why an identity operation was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// The device label exceeded [`MAX_DEVICE_LABEL_CHARS`] (REQ-021).
    #[error("device label exceeds {MAX_DEVICE_LABEL_CHARS} characters")]
    LabelTooLong,
    /// `did-crdt` refused the operation.
    #[error("did:crdt error: {0}")]
    Upstream(String),
}

impl From<did_crdt::core::Error> for IdentityError {
    fn from(e: did_crdt::core::Error) -> Self {
        IdentityError::Upstream(e.to_string())
    }
}

/// The multibase spelling of a public key, as `did:crdt` requires it.
pub fn key_multibase(public_key: &[u8; 32]) -> String {
    mb::encode(public_key)
}

/// Recompute the DID from a root public key using the pinned upstream rule
/// (REQ-003).
///
/// A verifier holding a bundle calls this and rejects the bundle if the
/// asserted DID differs. Because the DID commits to the genesis, forging a
/// genesis for an existing DID requires a BLAKE3 preimage (threat T4).
pub fn derive_did(root_public_key: &[u8; 32]) -> Result<Did, IdentityError> {
    Ok(bootstrap(root_public_key)?.0.did.clone())
}

/// Build the genesis document from a root public key.
///
/// Returns the document with the genesis op applied, and the **unsigned**
/// genesis delta upstream produces. [`sign_genesis`] turns the second into the
/// signed form that travels in a bundle.
pub fn bootstrap(root_public_key: &[u8; 32]) -> Result<(Document, SignedDelta), IdentityError> {
    Ok(Document::new(&key_multibase(root_public_key))?)
}

/// The root key's verification-method id — `did:crdt:…#key-0`.
pub fn root_method_id(did: &Did) -> String {
    format!("{did}{ROOT_FRAGMENT}")
}

/// Produce the **signed** genesis delta.
///
/// ADR-001 records that upstream's `Document::new` returns a genesis delta with
/// an empty signature ("no signing infrastructure is wired in this phase").
/// Signing it is the implementation work the specification assumes, and this is
/// that work: the same op and the same zero timestamp, with a real Ed25519
/// proof over `signing_input()`.
pub fn sign_genesis(root: &SigningKey) -> Result<(Document, SignedDelta), IdentityError> {
    let public = root.verifying_key().to_bytes();
    let (doc, unsigned) = bootstrap(&public)?;
    let signed = SignedDelta::new_genesis(
        unsigned.did.clone(),
        unsigned.op.clone(),
        HlcTimestamp::default(),
        root_method_id(&unsigned.did),
        &DidSigningKey::Ed25519(root.clone()),
    )?;
    Ok((doc, signed))
}

/// Sign a post-genesis delta on the document's current frontier.
///
/// The node-id binding upstream enforces is applied here: `node_id` is the low
/// 8 bytes of `BLAKE3(root_public_key)`, so the signer cannot choose a
/// favourable HLC tiebreak.
fn sign_on_frontier(
    doc: &Document,
    root: &SigningKey,
    op: DeltaOp,
    now_ms: u64,
) -> Result<SignedDelta, IdentityError> {
    let public = root.verifying_key().to_bytes();
    let timestamp =
        HlcTimestamp { wall_ms: now_ms, logical: 0, node_id: node_id_from_pubkey(&public) };
    Ok(SignedDelta::new_with_parents(
        doc.did.clone(),
        op,
        timestamp,
        doc.frontier(),
        root_method_id(&doc.did),
        &DidSigningKey::Ed25519(root.clone()),
    )?)
}

/// Declare the single-controller profile in the document (ADR-006).
pub fn declare_profile(
    doc: &Document,
    root: &SigningKey,
    now_ms: u64,
) -> Result<SignedDelta, IdentityError> {
    sign_on_frontier(
        doc,
        root,
        DeltaOp::SetDocumentData {
            key: PROFILE_KEY.to_owned(),
            value: serde_json::Value::String(PROFILE_VALUE.to_owned()),
        },
        now_ms,
    )
}

/// Authorise the identity's own key to make assertions — `SPEC-004` `CON-206`
/// step 6.
///
/// A `did:crdt` genesis creates `#key-0` with `Authentication` alone, and the
/// DID is a hash of that operation *including its relationships* — so the
/// genesis cannot be changed without changing every identifier ever derived.
/// There is also no operation that adds a relationship to an existing method.
///
/// So an identity that must **issue credentials** authorises its own key a
/// second time, under a fresh fragment, carrying `AssertionMethod`. The key
/// material is identical; what differs is what the document says it may do.
///
/// The resolver then projects that method into the `JsonWebKey` twin the W3C VC
/// JOSE/COSE profile requires, at `#jwk-0`, because it is the first
/// assertion-capable method. `CON-206` step 6 resolves there.
///
/// This is only for identities that issue. A `SPEC-001` root key authenticates
/// and controls; it does not assert, and calling this on one would widen its
/// authority for no reason.
pub fn add_assertion_method(
    doc: &Document,
    controller: &SigningKey,
    fragment: &str,
    now_ms: u64,
) -> Result<SignedDelta, IdentityError> {
    let public = controller.verifying_key().to_bytes();
    sign_on_frontier(
        doc,
        controller,
        DeltaOp::AddVerificationMethod {
            id: format!("{}#{fragment}", doc.did),
            public_key_multibase: key_multibase(&public),
            suite_type: SuiteType::Ed25519Signature2020,
            relationships: vec![VerificationRelationship::AssertionMethod],
        },
        now_ms,
    )
}

/// Set `alsoKnownAs` to one `acct:` URI — `SPEC-004` `CON-203` stage two.
///
/// `CON-203` builds an application-account identity in two stages, and is
/// explicit about the order: create the genesis and compute the DID from the
/// public key, *then* apply a root-signed document-data update setting
/// `alsoKnownAs`. The alias is never an input to genesis or to identifier
/// derivation, because the alias hashes the DID and a DID that hashed the alias
/// would have no fixed point.
///
/// It lives here rather than in `selfsame-app-identity` for the same reason
/// `derive_did` does: this module owns `did:crdt` delta construction, and a
/// second place that built deltas would be a second answer to what a signed
/// delta is.
///
/// The signer is the identity's own controlling key — for `SPEC-004` that is
/// the application-account home key, not a `SPEC-001` root.
pub fn set_also_known_as(
    doc: &Document,
    controller: &SigningKey,
    acct_uri: &str,
    now_ms: u64,
) -> Result<SignedDelta, IdentityError> {
    sign_on_frontier(
        doc,
        controller,
        // The typed op, not a documentData key. `alsoKnownAs` is a DID Core
        // property, and an untyped entry of that name projected into the same
        // JSON object as the typed fields — shadowing it for any last-wins
        // parser (did-crdt BUG-001). Upstream now refuses such a key outright.
        //
        // One URI, exactly as before: this wrapped a single acct_uri in an array
        // and the register replaces the whole set, so emitted state is unchanged.
        DeltaOp::SetAlsoKnownAs { uris: vec![acct_uri.to_owned()] },
        now_ms,
    )
}

/// Authorise a device key — the one delta that *is* linking (REQ-015).
///
/// `fragment` is the user-facing method suffix, e.g. `dev-1`.
pub fn add_device(
    doc: &Document,
    root: &SigningKey,
    device_public_key: &[u8; 32],
    fragment: &str,
    now_ms: u64,
) -> Result<SignedDelta, IdentityError> {
    sign_on_frontier(
        doc,
        root,
        DeltaOp::AddVerificationMethod {
            id: format!("{}#{fragment}", doc.did),
            public_key_multibase: key_multibase(device_public_key),
            suite_type: SuiteType::Ed25519Signature2020,
            relationships: default_relationships(),
        },
        now_ms,
    )
}

/// Record a device's user-visible label in **signed state** (REQ-021).
///
/// A phone restored from the mnemonic holds no local device list, so the label
/// must live here or the HP-5 revoke screen cannot name what it is revoking.
/// *Last seen* is deliberately not stored: it is local UX and is explicitly not
/// reconstructible.
pub fn set_device_label(
    doc: &Document,
    root: &SigningKey,
    method_id: &str,
    label: &str,
    now_ms: u64,
) -> Result<SignedDelta, IdentityError> {
    if label.chars().count() > MAX_DEVICE_LABEL_CHARS {
        return Err(IdentityError::LabelTooLong);
    }
    sign_on_frontier(
        doc,
        root,
        DeltaOp::SetDocumentData {
            key: method_id.to_owned(),
            value: serde_json::Value::String(label.to_owned()),
        },
        now_ms,
    )
}

/// Revoke a device, using only the root key (REQ-010).
///
/// No action by, and no availability of, the revoked device is required — that
/// is the whole point of HP-5. Upstream resolves the 2P-Set as
/// `authorised = added \ revoked`, so the method stays in the audit log and
/// leaves the authorised set.
pub fn revoke_device(
    doc: &Document,
    root: &SigningKey,
    method_id: &str,
    now_ms: u64,
) -> Result<SignedDelta, IdentityError> {
    sign_on_frontier(
        doc,
        root,
        DeltaOp::RevokeVerificationMethod { key_id: method_id.to_owned() },
        now_ms,
    )
}

/// Read a device label back out of resolved document data.
pub fn device_label(doc: &Document, method_id: &str) -> Option<String> {
    doc.resolve()
        .ok()?
        .did_document?
        .extra
        .get(method_id)
        .and_then(|v| v.as_str().map(str::to_owned))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> SigningKey {
        SigningKey::from_bytes(&[0x11; 32])
    }

    fn device() -> SigningKey {
        SigningKey::from_bytes(&[0x22; 32])
    }

    // TEST-003 positive: the DID recomputed by the pinned rule matches the DID
    // upstream's `Document::new` produces.
    #[test]
    fn the_did_is_the_one_upstream_derives() {
        let pk = root().verifying_key().to_bytes();
        let (doc, _) = bootstrap(&pk).unwrap();
        assert_eq!(derive_did(&pk).unwrap(), doc.did);
        assert!(doc.did.as_str().starts_with("did:crdt:"));
        assert_eq!(doc.did.method_specific_id().len(), 64);
    }

    #[test]
    fn distinct_root_keys_yield_distinct_dids() {
        let a = derive_did(&root().verifying_key().to_bytes()).unwrap();
        let b = derive_did(&device().verifying_key().to_bytes()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn the_signed_genesis_keeps_the_content_hash_upstream_recorded() {
        // The signature is excluded from delta identity upstream, so signing
        // the genesis must not move it in the DAG — otherwise a verifier that
        // bootstraps from the root key would build a second, unrelated root.
        let (doc, unsigned) = bootstrap(&root().verifying_key().to_bytes()).unwrap();
        let (_, signed) = sign_genesis(&root()).unwrap();
        assert_eq!(unsigned.content_hash().unwrap(), signed.content_hash().unwrap());
        assert_eq!(doc.frontier(), vec![signed.content_hash().unwrap()]);
        assert!(!signed.proof.proof_value.is_empty(), "genesis must be signed");
    }

    #[test]
    fn a_device_can_be_added_labelled_and_revoked_with_only_the_root_key() {
        let (mut doc, _) = sign_genesis(&root()).unwrap();
        let dev = device().verifying_key().to_bytes();

        let add = add_device(&doc, &root(), &dev, "dev-1", 1_000).unwrap();
        let method_id = match &add.op {
            DeltaOp::AddVerificationMethod { id, .. } => id.clone(),
            _ => unreachable!(),
        };
        doc.merge_verified_delta(add).unwrap();
        assert!(doc.resolve().unwrap().did_document.unwrap().verification_method.len() == 2);

        let label = set_device_label(&doc, &root(), &method_id, "Chrome on macOS", 1_001).unwrap();
        doc.merge_verified_delta(label).unwrap();
        assert_eq!(device_label(&doc, &method_id).as_deref(), Some("Chrome on macOS"));

        // REQ-010: revocation needs nothing from the device.
        let revoke = revoke_device(&doc, &root(), &method_id, 1_002).unwrap();
        doc.merge_verified_delta(revoke).unwrap();
        assert!(doc.is_vm_revoked(&method_id));
        let resolved = doc.resolve().unwrap().did_document.unwrap();
        assert!(resolved.verification_method.iter().all(|vm| vm.id != method_id));
    }

    // TEST-021 negative-input: a label over the cap is rejected at signing.
    #[test]
    fn an_oversized_label_is_rejected_at_signing() {
        let (doc, _) = sign_genesis(&root()).unwrap();
        let long = "x".repeat(MAX_DEVICE_LABEL_CHARS + 1);
        assert_eq!(
            set_device_label(&doc, &root(), "did:crdt:x#dev-1", &long, 1).unwrap_err(),
            IdentityError::LabelTooLong
        );
    }

    #[test]
    fn the_profile_is_declared_in_the_document() {
        let (mut doc, _) = sign_genesis(&root()).unwrap();
        let delta = declare_profile(&doc, &root(), 1_000).unwrap();
        doc.merge_verified_delta(delta).unwrap();
        let resolved = doc.resolve().unwrap().did_document.unwrap();
        assert_eq!(
            resolved.extra.get(PROFILE_KEY).and_then(|v| v.as_str()),
            Some(PROFILE_VALUE)
        );
    }
}
