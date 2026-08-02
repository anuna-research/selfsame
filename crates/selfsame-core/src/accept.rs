//! The acceptance predicate — SPEC-001 CON-003.
//!
//! One pure, total function decides whether a device joins an identity. It
//! reads no clock, touches no storage, and makes no network call: `now` is
//! injected and the whole of its input is the sealed bundle plus the context
//! the client already holds. That is what makes NFR-006 true — the DID↔device-
//! key binding is verifiable offline, from the bundle and the device's own key
//! alone — and what makes REQ-017 free: a function that mutates nothing cannot
//! leave partial state behind on a failed check.
//!
//! # The seven post-conditions
//!
//! Named one per requirement, so a failure attributes to a single obligation
//! rather than to "the bundle was bad":
//!
//! | # | Conjunct | Requirement | [`RejectReason`] |
//! |---|---|---|---|
//! | 1 | `transcript_ok` | REQ-006 | [`RejectReason::TranscriptMismatch`] |
//! | 2 | `not_expired` | REQ-016 | [`RejectReason::Expired`] |
//! | 3 | `did_matches_genesis` | REQ-003 | [`RejectReason::DidMismatch`] |
//! | 4 | `profile_signer_ok` | REQ-008 | [`RejectReason::ForeignSigner`] |
//! | 5 | `own_key_authorised` | REQ-015 | [`RejectReason::OwnKeyNotAuthorised`] |
//! | 6 | `no_capabilities` | REQ-013 | — dropped, never a rejection |
//! | 7 | `atomic` | REQ-017 | — guaranteed by the signature |
//!
//! Acceptance is the conjunction of 1–5 with 6 applied to the result; 7 governs
//! failure. Conjunct 6 is deliberately *not* a rejection: a bundle carrying
//! capability-shaped document data links normally and the capability is
//! ignored, because refusing it would let a hostile phone deny linking by
//! adding a field.
//!
//! # What the user is told
//!
//! Nothing from this enum. SCREEN-002 S4 shows one line — *"Couldn't link — the
//! reply didn't match this browser."* — because a `RejectReason` would teach
//! the user nothing and would leak which check failed.

use std::collections::BTreeMap;

use did_crdt::core::delta::{DeltaOp, SignedDelta};

use crate::{
    fingerprint::{fingerprint_did, Fingerprint},
    identity, mb,
    profile::{self, ProfileError},
    record::Grant,
    seal, UnixSeconds, MAX_SEALED_BYTES,
};

/// Everything the client already knows when the reply arrives.
///
/// `offer` is **the offer this client itself built and signed**, not the one it
/// read back from the rendezvous. That distinction is REQ-006: binding to a
/// re-fetched offer would let the operator substitute both halves.
///
/// The context carries the whole offer rather than a transcript hash, a device
/// key, and a deadline. Those three would have to agree with each other, and a
/// caller that got one wrong would silently weaken a check — so the type makes
/// the disagreement unrepresentable: the transcript, the key REQ-015 looks for,
/// and the REQ-016 deadline are all read off the same signed structure.
pub struct LinkContext {
    /// The 128-bit secret this client drew and displayed (REQ-005).
    pub secret: [u8; 16],
    /// The offer this client wrote to the rendezvous.
    pub offer: crate::record::Offer,
}

impl LinkContext {
    /// The client's own device public key — the key REQ-015 requires the
    /// resolved document to authorise.
    pub fn own_key(&self) -> &[u8; 32] {
        &self.offer.device_key
    }

    /// The REQ-016 deadline: the offer's own expiry, which the client set to
    /// mint time plus [`crate::OFFER_TTL_SECONDS`] and signed.
    pub fn deadline(&self) -> UnixSeconds {
        self.offer.expiry
    }
}

/// The identity a client joined.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AcceptedIdentity {
    /// The `did:crdt:…` identifier, recomputed and verified against the genesis.
    pub did: String,
    /// What SCREEN-002 S3 shows for comparison against the phone.
    pub fingerprint: Fingerprint,
    /// The root public key the DID commits to.
    pub root_public_key: [u8; 32],
    /// This client's verification-method id — `did:crdt:…#dev-<fragment>`.
    ///
    /// Found by matching this client's key against the resolved methods, not
    /// by any convention about the fragment: the phone chooses it, older
    /// identities carry `dev-1`, and newer ones carry 128 random bits.
    pub own_method_id: String,
    /// The signed deltas, retained verbatim so the client can re-verify offline
    /// and republish without a network round trip (NFR-006).
    pub deltas: Vec<Vec<u8>>,
    /// Device labels from signed state, keyed by verification-method id
    /// (REQ-021). Capability-shaped document data is **not** here — see
    /// [`AcceptedIdentity::dropped_document_data`].
    pub device_labels: BTreeMap<String, String>,
    /// The profile the document declares (ADR-006), if any.
    pub declared_profile: Option<String>,
    /// Document-data keys that were present and deliberately ignored (REQ-013).
    ///
    /// Recorded rather than silently discarded so an operator can see that a
    /// bundle tried to carry something this verifier does not interpret.
    pub dropped_document_data: Vec<String>,
}

/// Why a bundle was refused. A closed enum, one variant per post-condition.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RejectReason {
    /// The bundle did not authenticate under `HKDF(s)` with *our* offer hash
    /// as associated data (REQ-006). This is the T1 signature: a rise in this
    /// reason is a substitution attempt, and OBS-001 counts it.
    #[error("bundle is not a reply to this client's offer")]
    TranscriptMismatch,
    /// The bundle arrived after the offer expired (REQ-016).
    #[error("offer expired before the bundle arrived")]
    Expired,
    /// The asserted DID is not the one the genesis delta derives (REQ-003).
    #[error("asserted DID does not commit to the genesis signer key")]
    DidMismatch,
    /// A delta was signed by something other than the genesis key (REQ-008).
    #[error("closure violates the single-controller profile")]
    ForeignSigner,
    /// The resolved document does not authorise this client's key (REQ-015).
    #[error("this device's key is not authorised by the resolved document")]
    OwnKeyNotAuthorised,
    /// The input was not a well-formed bundle at all.
    #[error("bundle not recognised")]
    Unrecognised,
}

/// Decide whether to accept a credential bundle.
///
/// Pure and total: on any failed check it returns a [`RejectReason`] and
/// mutates nothing (REQ-017).
pub fn accept(
    sealed: &[u8],
    ctx: &LinkContext,
    now: UnixSeconds,
) -> Result<AcceptedIdentity, RejectReason> {
    if sealed.len() > MAX_SEALED_BYTES {
        return Err(RejectReason::Unrecognised);
    }

    // 1. transcript_ok (REQ-006) — the clause that makes the rendezvous
    //    untrusted. The operator holds `H(s)`, never `s`, so it cannot forge
    //    this tag; it can withhold but not substitute.
    let key = seal::derive_key(&ctx.secret);
    let grant_bytes = seal::open_bundle(&key, sealed, &ctx.offer.transcript())
        .map_err(|_| RejectReason::TranscriptMismatch)?;

    // 2. not_expired (REQ-016).
    if now > ctx.deadline() {
        return Err(RejectReason::Expired);
    }

    // Full recognition before any semantic action (Constitutional Principle 14).
    let grant = Grant::parse(&grant_bytes).map_err(|_| RejectReason::Unrecognised)?;
    let deltas: Vec<SignedDelta> = grant
        .deltas
        .iter()
        .map(|bytes| serde_json::from_slice::<SignedDelta>(bytes))
        .collect::<Result<_, _>>()
        .map_err(|_| RejectReason::Unrecognised)?;

    // 3. did_matches_genesis (REQ-003). The root key comes out of the genesis
    //    delta the bundle carries; the DID is then *recomputed* from it, so a
    //    bundle whose asserted DID does not commit to that key is refused.
    let root_public_key = genesis_root_key(&deltas).ok_or(RejectReason::Unrecognised)?;
    let derived = identity::derive_did(&root_public_key).map_err(|_| RejectReason::Unrecognised)?;
    if derived.as_str() != grant.did {
        return Err(RejectReason::DidMismatch);
    }

    // 4. profile_signer_ok (REQ-008) and local resolution (REQ-025).
    let document = profile::resolve_closure(&deltas, &root_public_key).map_err(|e| match e {
        ProfileError::ForeignSigner
        | ProfileError::BadSignature
        | ProfileError::WrongSuite
        | ProfileError::UnboundNodeId
        | ProfileError::WrongDid => RejectReason::ForeignSigner,
        ProfileError::NotExactlyOneGenesis | ProfileError::Upstream(_) => {
            RejectReason::Unrecognised
        }
    })?;
    let resolved = document
        .resolve()
        .map_err(|_| RejectReason::Unrecognised)?
        .did_document
        .ok_or(RejectReason::Unrecognised)?;

    // 5. own_key_authorised (REQ-015). Revoked methods are already excluded by
    //    upstream's 2P-Set resolution (`authorised = added \ revoked`).
    let own_multibase = mb::encode(ctx.own_key());
    let own_method_id = resolved
        .verification_method
        .iter()
        .find(|vm| vm.public_key_multibase == own_multibase)
        .map(|vm| vm.id.clone())
        .ok_or(RejectReason::OwnKeyNotAuthorised)?;

    // 6. no_capabilities (REQ-013). Document data is partitioned into the two
    //    things this version interprets — device labels and the declared
    //    profile — and everything else is dropped. A capability-bearing bundle
    //    links normally and confers nothing.
    let method_ids: Vec<&str> =
        resolved.verification_method.iter().map(|vm| vm.id.as_str()).collect();
    let mut device_labels = BTreeMap::new();
    let mut declared_profile = None;
    let mut dropped_document_data = Vec::new();
    for (key, value) in &resolved.extra {
        match key.as_str() {
            identity::PROFILE_KEY => declared_profile = value.as_str().map(str::to_owned),
            k if method_ids.contains(&k) => {
                if let Some(label) = value.as_str() {
                    device_labels.insert(k.to_owned(), label.to_owned());
                } else {
                    dropped_document_data.push(k.to_owned());
                }
            }
            other => dropped_document_data.push(other.to_owned()),
        }
    }

    Ok(AcceptedIdentity {
        fingerprint: fingerprint_did(&grant.did),
        did: grant.did,
        root_public_key,
        own_method_id,
        deltas: grant.deltas,
        device_labels,
        declared_profile,
        dropped_document_data,
    })
}

/// Extract the root public key from the closure's genesis delta.
///
/// The genesis is the delta with no causal parents carrying an
/// `AddVerificationMethod`. Exactly one must exist; anything else is not a
/// recognised closure.
fn genesis_root_key(deltas: &[SignedDelta]) -> Option<[u8; 32]> {
    let mut found = None;
    for delta in deltas {
        if !delta.parents.is_empty() {
            continue;
        }
        let key = match &delta.op {
            DeltaOp::AddVerificationMethod { public_key_multibase, .. } => {
                mb::decode_exact::<32>(public_key_multibase).ok()?
            }
            _ => return None,
        };
        if found.is_some() {
            return None;
        }
        found = Some(key);
    }
    found
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Application, Offer};
    use ed25519_dalek::SigningKey;

    fn root() -> SigningKey {
        SigningKey::from_bytes(&[0x11; 32])
    }
    fn device() -> SigningKey {
        SigningKey::from_bytes(&[0x22; 32])
    }
    fn intruder() -> SigningKey {
        SigningKey::from_bytes(&[0x33; 32])
    }

    const SECRET: [u8; 16] = [7u8; 16];
    const MINTED: UnixSeconds = 1_790_000_000;
    const DEADLINE: UnixSeconds = MINTED + crate::OFFER_TTL_SECONDS;

    /// Build a signed offer the way a device client would.
    fn offer_from(device_key: &SigningKey) -> Offer {
        Offer::sign(Application::CbclChat, device_key, "Chrome on macOS", DEADLINE)
    }

    /// Run the phone's half: create the identity, authorise `device_key`, and
    /// seal the grant against `offer`'s transcript.
    fn seal_grant_for(
        offer: &Offer,
        root_key: &SigningKey,
        secret: &[u8; 16],
        extra_data: Option<(&str, serde_json::Value)>,
    ) -> Vec<u8> {
        use did_crdt::core::delta::SigningKey as DidSigningKey;
        use did_crdt::core::hlc::HlcTimestamp;
        use did_crdt::core::validate::node_id_from_pubkey;

        let (mut doc, genesis) = identity::sign_genesis(root_key).unwrap();
        let add =
            identity::add_device(&doc, root_key, &offer.device_key, "dev-1", MINTED * 1_000)
                .unwrap();
        doc.merge_verified_delta(add.clone()).unwrap();

        let third = match extra_data {
            Some((key, value)) => {
                let root_pk = root_key.verifying_key().to_bytes();
                let d = SignedDelta::new_with_parents(
                    doc.did.clone(),
                    DeltaOp::SetDocumentData { key: key.to_owned(), value },
                    HlcTimestamp {
                        wall_ms: MINTED * 1_000 + 1,
                        logical: 0,
                        node_id: node_id_from_pubkey(&root_pk),
                    },
                    doc.frontier(),
                    identity::root_method_id(&doc.did),
                    &DidSigningKey::Ed25519(root_key.clone()),
                )
                .unwrap();
                doc.merge_verified_delta(d.clone()).unwrap();
                d
            }
            None => {
                let method_id = format!("{}#dev-1", doc.did);
                let d = identity::set_device_label(
                    &doc,
                    root_key,
                    &method_id,
                    "Chrome on macOS",
                    MINTED * 1_000 + 1,
                )
                .unwrap();
                doc.merge_verified_delta(d.clone()).unwrap();
                d
            }
        };

        let deltas: Vec<Vec<u8>> =
            [genesis, add, third].iter().map(|d| serde_json::to_vec(d).unwrap()).collect();
        let grant = Grant::new(doc.did.to_string(), deltas);
        seal::seal_bundle(&seal::derive_key(secret), &grant.to_bytes(), &offer.transcript())
    }

    /// The whole happy path, assembled the way the two shells would.
    fn scenario(
        device_key: &SigningKey,
        root_key: &SigningKey,
        extra_data: Option<(&str, serde_json::Value)>,
    ) -> (Vec<u8>, LinkContext) {
        let offer = offer_from(device_key);
        let sealed = seal_grant_for(&offer, root_key, &SECRET, extra_data);
        (sealed, LinkContext { secret: SECRET, offer })
    }

    // The dominant happy path, HP-2.
    #[test]
    fn a_well_formed_bundle_is_accepted() {
        let (sealed, ctx) = scenario(&device(), &root(), None);
        let accepted = accept(&sealed, &ctx, MINTED).unwrap();
        let expected_did = identity::derive_did(&root().verifying_key().to_bytes()).unwrap();
        assert_eq!(accepted.did, expected_did.to_string());
        assert_eq!(accepted.own_method_id, format!("{expected_did}#dev-1"));
        assert_eq!(accepted.fingerprint, fingerprint_did(&accepted.did));
        assert_eq!(accepted.root_public_key, root().verifying_key().to_bytes());
        assert_eq!(
            accepted.device_labels.get(&accepted.own_method_id).map(String::as_str),
            Some("Chrome on macOS")
        );
        assert!(accepted.dropped_document_data.is_empty());
        assert_eq!(accepted.deltas.len(), 3);
    }

    // TEST-006 negative-input: a bundle bound to a *different* offer.
    #[test]
    fn a_bundle_sealed_against_a_different_offer_is_refused() {
        let ours = offer_from(&device());
        let theirs =
            Offer::sign(Application::CbclChat, &device(), "Safari on iOS", DEADLINE);
        assert_ne!(ours.transcript(), theirs.transcript());
        let sealed = seal_grant_for(&theirs, &root(), &SECRET, None);
        let ctx = LinkContext { secret: SECRET, offer: ours };
        assert_eq!(accept(&sealed, &ctx, MINTED), Err(RejectReason::TranscriptMismatch));
    }

    #[test]
    fn a_bundle_under_a_different_secret_is_refused() {
        let (sealed, mut ctx) = scenario(&device(), &root(), None);
        ctx.secret[0] ^= 1;
        assert_eq!(accept(&sealed, &ctx, MINTED), Err(RejectReason::TranscriptMismatch));
    }

    #[test]
    fn a_tampered_bundle_is_refused() {
        let (mut sealed, ctx) = scenario(&device(), &root(), None);
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert_eq!(accept(&sealed, &ctx, MINTED), Err(RejectReason::TranscriptMismatch));
    }

    // TEST-016: 299 s accepted, 301 s refused.
    #[test]
    fn the_expiry_boundary_is_exact() {
        let (sealed, ctx) = scenario(&device(), &root(), None);
        assert!(accept(&sealed, &ctx, MINTED + 299).is_ok());
        assert!(accept(&sealed, &ctx, ctx.deadline()).is_ok());
        assert_eq!(accept(&sealed, &ctx, ctx.deadline() + 1), Err(RejectReason::Expired));
        assert_eq!(accept(&sealed, &ctx, MINTED + 301), Err(RejectReason::Expired));
    }

    // TEST-015 negative-input · TEST-034 / NFR-007: a bundle naming a
    // *different* device's key. This is also the stolen-bundle case: without
    // the matching device private key the bundle claims nothing, because the
    // offer that binds it was signed by a key the thief does not hold.
    #[test]
    fn a_bundle_for_someone_elses_key_is_refused() {
        // The phone authorised `device()`; this client holds `intruder()`.
        let thief_offer = offer_from(&intruder());
        let sealed = seal_grant_for(&thief_offer, &root(), &SECRET, None);

        // Re-seal the *victim's* grant against the thief's transcript: the
        // thief has `s` and the victim's bundle, and still cannot use it.
        let victim_offer = offer_from(&device());
        let victim_bundle = seal_grant_for(&victim_offer, &root(), &SECRET, None);
        let victim_grant = seal::open_bundle(
            &seal::derive_key(&SECRET),
            &victim_bundle,
            &victim_offer.transcript(),
        )
        .unwrap();
        let restolen = seal::seal_bundle(
            &seal::derive_key(&SECRET),
            &victim_grant,
            &thief_offer.transcript(),
        );

        let ctx = LinkContext { secret: SECRET, offer: thief_offer };
        assert_eq!(accept(&restolen, &ctx, MINTED), Err(RejectReason::OwnKeyNotAuthorised));
        // Sanity: the thief's own legitimate flow does work, so the rejection
        // above is about the key and not about the scaffolding.
        assert!(accept(&sealed, &ctx, MINTED).is_ok());
    }

    // TEST-003 negative-input: the asserted DID is one nibble off.
    #[test]
    fn a_bundle_whose_did_does_not_commit_to_the_genesis_is_refused() {
        let (sealed, ctx) = scenario(&device(), &root(), None);
        let key = seal::derive_key(&ctx.secret);
        let grant_bytes = seal::open_bundle(&key, &sealed, &ctx.offer.transcript()).unwrap();
        let grant = Grant::parse(&grant_bytes).unwrap();

        let mut hex: Vec<char> = grant.did["did:crdt:".len()..].chars().collect();
        hex[0] = if hex[0] == 'a' { 'b' } else { 'a' };
        let forged = Grant::new(
            format!("did:crdt:{}", hex.into_iter().collect::<String>()),
            grant.deltas.clone(),
        );
        let resealed = seal::seal_bundle(&key, &forged.to_bytes(), &ctx.offer.transcript());
        assert_eq!(accept(&resealed, &ctx, MINTED), Err(RejectReason::DidMismatch));
    }

    // TEST-013 positive: capability-shaped document data links normally and
    // confers nothing.
    #[test]
    fn capability_shaped_document_data_is_dropped_not_interpreted() {
        let (sealed, ctx) = scenario(
            &device(),
            &root(),
            Some(("capabilityInvocation", serde_json::json!({"admin": true, "rooms": ["*"]}))),
        );
        let accepted = accept(&sealed, &ctx, MINTED).unwrap();
        assert_eq!(accepted.dropped_document_data, vec!["capabilityInvocation".to_owned()]);
        assert!(accepted.device_labels.is_empty());
    }

    // T1 / TEST-029: the substitution a rendezvous operator would attempt. An
    // attacker may add *any* public key to *their own* DID, so "our key is
    // listed" is no defence on its own — the transcript binding is what stops
    // the substitution, and the fingerprint comparison (A6) is the backstop.
    #[test]
    fn an_attacker_rooted_did_authorising_our_key_cannot_be_substituted() {
        let ours = offer_from(&device());
        let ctx = LinkContext { secret: SECRET, offer: ours };

        // The attacker mints a DID under their own root that authorises our
        // device key, and — being the operator — knows the slot but not `s`.
        // Model the strongest realistic operator: it does not hold `s`, so it
        // cannot produce a tag at all.
        let attacker_offer = Offer::sign(
            Application::CbclChat,
            &device(),
            "Chrome on macOS (attacker copy)",
            DEADLINE,
        );
        let substituted = seal_grant_for(&attacker_offer, &intruder(), &SECRET, None);
        assert_eq!(accept(&substituted, &ctx, MINTED), Err(RejectReason::TranscriptMismatch));

        // Now grant the attacker everything short of the user's eyes: `s` *and*
        // our exact offer bytes. The bundle then opens — and resolves to the
        // attacker's DID, never to ours, which is precisely the case the
        // fingerprint comparison exists to catch.
        let attacker_bundle = seal_grant_for(&ctx.offer, &intruder(), &SECRET, None);
        let accepted = accept(&attacker_bundle, &ctx, MINTED).unwrap();
        let ours_did = identity::derive_did(&root().verifying_key().to_bytes()).unwrap();
        assert_ne!(accepted.did, ours_did.to_string());
        assert_ne!(accepted.fingerprint, fingerprint_did(ours_did.as_str()));
    }

    #[test]
    fn garbage_is_refused_without_panicking() {
        let (_, ctx) = scenario(&device(), &root(), None);
        for case in [vec![], vec![0u8; 1], vec![0xffu8; 64], vec![0u8; MAX_SEALED_BYTES + 1]] {
            assert!(accept(&case, &ctx, MINTED).is_err());
        }
    }

    // TEST-017: a rejected bundle leaves nothing behind. The predicate takes
    // `&LinkContext` and returns a value, so there is no storage for it to
    // mutate — the property is structural, and this test states it.
    #[test]
    fn rejection_mutates_nothing() {
        let (mut sealed, ctx) = scenario(&device(), &root(), None);
        sealed[0] ^= 0xff;
        let before = (ctx.secret, ctx.offer.clone());
        assert!(accept(&sealed, &ctx, MINTED).is_err());
        assert_eq!(before, (ctx.secret, ctx.offer.clone()));
    }
}
