//! Credential revocation and the optional status projection — `CON-210`,
//! `REQ-208`.
//!
//! Unlinking a device creates a signed `did:crdt` `RevokeCredential` delta whose
//! `credential_id` is the exact grant `id`. The revocation set in the verified
//! issuer state is the normative source of truth, and because it is **grow-only**
//! *"no operation, provider response, projection, key rotation, or concurrent
//! merge may make a revoked grant valid again."*
//!
//! # Submission is not revocation
//!
//! The single most important rule here, and the easiest to get wrong:
//!
//! > The initiating application reports **pending** until a newly resolved,
//! > cryptographically verified closure includes `grant_id`. It reports success
//! > only then. **A resolver's acknowledgement is not evidence of revocation.**
//!
//! An HTTP `200` from a state resolver says the resolver received something. It
//! does not say the delta was admitted, that it will be served to the next
//! verifier, or that the resolver is honest. [`Submission`] models the
//! distinction as a type, so "we sent it" cannot be mistaken for "it is
//! revoked" by a caller reading a boolean.
//!
//! Submission is parallel and best-effort to *every* reachable declared
//! resolver. `CON-210` forbids treating delivery to the application's own node
//! as a substitute, because a grant may be verified by a peer or by another
//! device — a resolver roster is a fan-out, not a fallback chain.
//!
//! # Why an application endpoint may accept unauthenticated deltas
//!
//! `CON-201` recommends an application list its own origin as a resolver, which
//! looks alarming until the monotonicity argument is stated: the revocation set
//! is grow-only, deltas are signed by the home key, and no method operation can
//! clear an entry. A forged delta fails the signature check, a replayed delta is
//! idempotent, and the worst an accepted delta can do is **revoke** — which
//! reduces authority and therefore fails safe.
//!
//! `CON-210` adds the caveat that matters more than the argument: *"the
//! reasoning SHOULD be re-checked against any future method operation that is
//! not grow-only."* [`monotonic_operations`] is that check, written down.
//!
//! # The projection's two bit values are not symmetric
//!
//! A **set** bit is permanently true — no later state can unset it, so age never
//! makes it wrong and a consumer may act on it at any age. An **unset** bit is a
//! claim about the world at `validFrom` and it decays; past `validUntil` a
//! consumer treats the projection as *unavailable*, never as evidence of
//! non-revocation. [`ProjectionReading`] is that asymmetry as a function.

use crate::profile::ProjectionPolicy;
use crate::UnixSeconds;

use did_crdt::core::delta::{DeltaOp, SignedDelta, SigningKey as DidSigningKey};
use did_crdt::core::document::Document;
use did_crdt::core::hlc::HlcTimestamp;
use did_crdt::core::validate::node_id_from_pubkey;

/// `CON-210`: the minimum uncompressed bitstring size a projection carries.
pub const MIN_PROJECTION_ENTRIES: usize = 131_072;

/// Why a revocation could not be constructed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RevocationError {
    /// The grant identifier is not the shape `CON-205` constructs.
    #[error("credential id is not a grant identifier")]
    NotAGrantId,
    /// The pinned `did:crdt` method refused to build or sign the delta.
    #[error("did:crdt refused the revocation delta: {0}")]
    Method(String),
}

/// The state of a revocation the controller has started.
///
/// `CON-210`: "A resolver's acknowledgement is not evidence of revocation." The
/// two states are deliberately not a boolean, so a caller cannot read
/// "submitted" as "done".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Submission {
    /// The delta is signed and has been offered to the declared resolvers.
    ///
    /// Retained and retried until a verified closure confirms it. A failed or
    /// unacknowledged submission to any one resolver does not abandon the
    /// revocation, discard the delta, or let the controller report success.
    Pending {
        /// The exact credential identifier being revoked.
        credential_id: String,
        /// Resolver ids that acknowledged receipt. Evidence of nothing.
        acknowledged_by: Vec<String>,
    },
    /// A newly resolved, cryptographically verified closure contains the exact
    /// credential identifier.
    Confirmed {
        /// The exact credential identifier.
        credential_id: String,
    },
}

impl Submission {
    /// Begin a revocation. Always starts pending, whatever the resolvers said.
    pub fn begin(credential_id: impl Into<String>) -> Self {
        Submission::Pending { credential_id: credential_id.into(), acknowledged_by: Vec::new() }
    }

    /// Record that one resolver acknowledged receipt.
    ///
    /// Deliberately does not change the state. This method exists so that the
    /// tempting call — "the resolver said OK, mark it done" — has nowhere to go.
    pub fn acknowledged(self, resolver_id: impl Into<String>) -> Self {
        match self {
            Submission::Pending { credential_id, mut acknowledged_by } => {
                acknowledged_by.push(resolver_id.into());
                Submission::Pending { credential_id, acknowledged_by }
            }
            confirmed => confirmed,
        }
    }

    /// Re-resolve against a verified closure. The only path to `Confirmed`.
    pub fn observe(self, verified_closure: &Document) -> Self {
        let credential_id = match &self {
            Submission::Pending { credential_id, .. } => credential_id.clone(),
            Submission::Confirmed { .. } => return self,
        };
        if verified_closure.is_revoked(&credential_id) {
            Submission::Confirmed { credential_id }
        } else {
            self
        }
    }

    /// Whether the application may report success to the person.
    pub fn is_confirmed(&self) -> bool {
        matches!(self, Submission::Confirmed { .. })
    }
}

/// Build and sign the `RevokeCredential` delta on the document's frontier
/// (`CON-210` steps 2 to 4).
///
/// This specification does not redefine `SignedDelta`, its proof, canonical
/// signing bytes, causal-admission rules, or hash — the pinned method owns all
/// of them. A standalone HTTP "revoke" signature or provider database update
/// does not revoke a Selfsame grant.
pub fn revoke_credential(
    document: &Document,
    home_key: &ed25519_dalek::SigningKey,
    home_method_id: &str,
    credential_id: &str,
    now_milliseconds: u64,
) -> Result<SignedDelta, RevocationError> {
    if !credential_id.contains("#grant-") {
        return Err(RevocationError::NotAGrantId);
    }
    let public = home_key.verifying_key().to_bytes();
    // The node-id binding the method enforces: the low octets of a hash of the
    // public key, so a signer cannot choose a favourable HLC tiebreak.
    let timestamp =
        HlcTimestamp { wall_ms: now_milliseconds, logical: 0, node_id: node_id_from_pubkey(&public) };
    SignedDelta::new_with_parents(
        document.did.clone(),
        DeltaOp::RevokeCredential { credential_id: credential_id.to_owned() },
        timestamp,
        document.frontier(),
        home_method_id.to_owned(),
        &DidSigningKey::Ed25519(home_key.clone()),
    )
    .map_err(|e| RevocationError::Method(e.to_string()))
}

/// Admit a revocation delta into a replica, **with** signature verification.
///
/// # The one call that must not be got wrong
///
/// `CON-210` says a replica "accepts the operation only after normal `did:crdt`
/// signature, authorization, DID, parent-closure, deactivation, and causal
/// checks", and the contract's whole argument for letting an application
/// endpoint accept deltas rests on the first of those: *"A forged delta fails
/// the signature check."*
///
/// At the pinned revision that is true only of `Document::merge_verified_delta`.
/// The obviously-named `Document::merge` documents that "cryptographic signature
/// verification is deferred to a later phase … Callers that operate in a trust
/// boundary MUST call `validate::verify_signature` before calling this method."
/// So a replica built on `merge` admits a delta signed by **any** key, and
/// `CON-210`'s monotonicity argument silently stops holding: the worst an
/// accepted delta can do is no longer "revoke", because nothing established that
/// the home controller authored it.
///
/// This function exists so the correct call is the easy one, and so the hazard is
/// recorded in code rather than in a reviewer's memory. Recorded as `FINDING-005`
/// in the `EXP-001` report, with the recommendation that `CON-210` name the
/// verifying entry point rather than the operation.
pub fn admit_revocation(
    replica: &mut Document,
    delta: SignedDelta,
) -> Result<(), RevocationError> {
    replica.merge_verified_delta(delta).map_err(|e| RevocationError::Method(e.to_string()))
}

/// The method operations whose monotonicity the unauthenticated-write argument
/// rests on.
///
/// `CON-210` permits an application endpoint to accept deltas because the worst
/// an accepted one can do is reduce authority. That holds only while every
/// operation an attacker could submit is monotone in that direction. This
/// function is the re-check `CON-210` asks for, and it is a `const` list rather
/// than prose so that adding a non-monotone operation upstream forces a decision
/// here.
pub const fn monotonic_operations() -> &'static [&'static str] {
    &["RevokeCredential", "RevokeVerificationMethod", "Deactivate"]
}

/// What a generic consumer may infer from a Bitstring projection (`CON-210`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionReading {
    /// The credential is revoked. Permanently true at any age.
    Revoked,
    /// The projection says nothing usable: unset and in date.
    ///
    /// Not "not revoked" — a Selfsame verifier still resolves CRDT state, and a
    /// generic consumer treats this as the weakest possible signal.
    NoInformationYet,
    /// The projection is unavailable: stale, invalid, or unreachable.
    Unavailable,
}

/// Read a projection observation under `CON-210`'s asymmetry.
///
/// `bit_set` is the bit for this credential; `valid_from` and `valid_until` come
/// from the projection credential itself, whose publisher was forbidden from
/// signing a window longer than `maxAgeSeconds`.
pub fn read_projection(
    bit_set: bool,
    valid_from: UnixSeconds,
    valid_until: UnixSeconds,
    now: UnixSeconds,
    policy: &ProjectionPolicy,
) -> ProjectionReading {
    // A publisher may not sign a window longer than the profile's bound, so a
    // consumer applying nothing but W3C validity rules already rejects an
    // over-age projection. Expressing the bound as Selfsame-specific policy
    // instead would have made it advisory to exactly the consumers it exists
    // for.
    if valid_until - valid_from > policy.max_age_seconds {
        return ProjectionReading::Unavailable;
    }
    // A set bit is permanently true: no later state can unset it, so age never
    // makes it wrong. This check comes *before* the freshness check for that
    // reason, and the ordering is the whole asymmetry.
    if bit_set {
        return ProjectionReading::Revoked;
    }
    if now < valid_from || now >= valid_until {
        return ProjectionReading::Unavailable;
    }
    ProjectionReading::NoInformationYet
}

/// Whether a projection may be published for this credential yet (`CON-210`).
///
/// "A bit may be set only after a verified CRDT closure contains the exact grant
/// ID mapped to that index, and no later projection may clear a previously set
/// bit."
pub fn may_set_bit(verified_closure: &Document, credential_id: &str) -> bool {
    verified_closure.is_revoked(credential_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use did_crdt::core::delta::DeltaOp;

    fn key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    /// A genesis document controlled by one key, signed the way SPEC-001 does.
    fn document(seed: u8) -> (Document, ed25519_dalek::SigningKey, String) {
        let k = key(seed);
        let (mut doc, genesis) =
            selfsame_core::identity::sign_genesis(&k).expect("genesis signs");
        doc.merge(genesis).expect("genesis merges");
        let method = selfsame_core::identity::root_method_id(&doc.did);
        (doc, k, method)
    }

    fn grant_id(doc: &Document, token: &str) -> String {
        format!("{}#grant-{token}", doc.did)
    }

    fn revoke(doc: &mut Document, k: &ed25519_dalek::SigningKey, method: &str, id: &str, ms: u64) {
        let delta = revoke_credential(doc, k, method, id, ms).expect("delta signs");
        admit_revocation(doc, delta).expect("delta is admitted");
    }

    // TEST-213 positive: the exact grant ID appears in a resolved closure.
    #[test]
    fn a_revoked_grant_id_appears_in_the_revocation_set() {
        let (mut doc, k, method) = document(1);
        let id = grant_id(&doc, "AAAA");
        assert!(!doc.is_revoked(&id));
        revoke(&mut doc, &k, &method, &id, 1_000);
        assert!(doc.is_revoked(&id));
    }

    #[test]
    fn a_credential_id_that_is_not_a_grant_identifier_is_refused() {
        let (doc, k, method) = document(1);
        assert!(matches!(
            revoke_credential(&doc, &k, &method, "not-a-grant", 1_000),
            Err(RevocationError::NotAGrantId)
        ));
    }

    // TEST-213: idempotence.
    #[test]
    fn applying_the_same_revocation_repeatedly_is_idempotent() {
        let (mut doc, k, method) = document(1);
        let id = grant_id(&doc, "AAAA");
        let delta = revoke_credential(&doc, &k, &method, &id, 1_000).unwrap();
        admit_revocation(&mut doc, delta.clone()).unwrap();
        admit_revocation(&mut doc, delta.clone()).unwrap();
        admit_revocation(&mut doc, delta).unwrap();
        assert!(doc.is_revoked(&id));
    }

    // TEST-213: concurrent revocations on three replicas, merged in every
    // order, converge to the same set containing every ID.
    #[test]
    fn concurrent_revocations_converge_under_every_merge_order() {
        let (base, k, method) = document(1);
        let ids: Vec<String> = ["AAAA", "BBBB", "CCCC"].iter().map(|t| grant_id(&base, t)).collect();

        let deltas: Vec<SignedDelta> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| {
                revoke_credential(&base, &k, &method, id, 1_000 + i as u64).expect("signs")
            })
            .collect();

        // Every permutation of three deltas.
        let orders = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
        for order in orders {
            let mut replica = base.clone();
            for i in order {
                admit_revocation(&mut replica, deltas[i].clone()).expect("is admitted");
            }
            for id in &ids {
                assert!(replica.is_revoked(id), "order {order:?} lost {id}");
            }
        }
    }

    // TEST-213: no operation or merge can make `is_revoked` false again.
    #[test]
    fn no_later_operation_can_clear_a_revocation() {
        let (mut doc, k, method) = document(1);
        let id = grant_id(&doc, "AAAA");
        revoke(&mut doc, &k, &method, &id, 1_000);
        assert!(doc.is_revoked(&id));

        // Every other operation the controller can author, applied afterwards.
        // Key rotation is the one an implementer might expect to reset state.
        for (label, op) in [
            (
                "another revocation",
                DeltaOp::RevokeCredential { credential_id: grant_id(&doc, "BBBB") },
            ),
            (
                "a document-data update",
                DeltaOp::SetDocumentData {
                    key: "alsoKnownAs".into(),
                    value: serde_json::json!(["acct:x@y.example"]),
                },
            ),
        ] {
            let public = k.verifying_key().to_bytes();
            let delta = SignedDelta::new_with_parents(
                doc.did.clone(),
                op,
                HlcTimestamp {
                    wall_ms: 2_000,
                    logical: 0,
                    node_id: node_id_from_pubkey(&public),
                },
                doc.frontier(),
                method.clone(),
                &DidSigningKey::Ed25519(k.clone()),
            )
            .expect("signs");
            doc.merge_verified_delta(delta).expect("is admitted");
            assert!(doc.is_revoked(&id), "{label} cleared a revocation");
        }
    }

    // TEST-213: a delta signed by another DID's key is not admitted.
    #[test]
    fn a_delta_signed_by_an_unknown_key_is_not_admitted() {
        let (mut doc, _, method) = document(1);
        let stranger = key(9);
        let id = grant_id(&doc, "AAAA");
        // Signing succeeds — anyone can sign anything. Admission is where the
        // forgery is caught, and it must be caught there.
        let forged = revoke_credential(&doc, &stranger, &method, &id, 1_000).expect("signs");
        assert!(admit_revocation(&mut doc, forged).is_err(), "a forged delta was admitted");
        assert!(!doc.is_revoked(&id));
    }

    /// FINDING-005, pinned as a test so it cannot be lost.
    ///
    /// `Document::merge` does **not** verify signatures at the pinned revision —
    /// it says so in its own documentation — while `merge_verified_delta` does.
    /// `CON-210`'s argument for permitting unauthenticated writes at an
    /// application endpoint depends entirely on "a forged delta fails the
    /// signature check", so a replica built on the obviously-named call has that
    /// argument quietly stop holding.
    ///
    /// This test demonstrates the divergence rather than asserting a
    /// preference. If a later revision makes `merge` verify, it fails, and the
    /// finding is closed.
    #[test]
    fn the_non_verifying_merge_admits_a_forgery_that_the_verifying_one_refuses() {
        let (mut permissive, _, method) = document(1);
        let stranger = key(9);
        let id = grant_id(&permissive, "AAAA");

        let forged = revoke_credential(&permissive, &stranger, &method, &id, 1_000).unwrap();
        let admitted_without_verification = permissive.merge(forged.clone()).is_ok();

        let (mut strict, _, _) = document(1);
        let refused_with_verification = strict.merge_verified_delta(forged).is_err();

        assert!(
            admitted_without_verification && refused_with_verification,
            "the two entry points no longer diverge — re-read FINDING-005 and close it"
        );
        assert!(permissive.is_revoked(&id), "the permissive replica accepted a forgery");
        assert!(!strict.is_revoked(&id), "the verifying replica must refuse it");
    }

    // ── submission reporting ───────────────────────────────────────────────

    #[test]
    fn an_acknowledgement_never_makes_a_revocation_confirmed() {
        // The rule that costs the most to get wrong, and the reason `Submission`
        // is a type rather than a boolean.
        let (doc, _, _) = document(1);
        let id = grant_id(&doc, "AAAA");
        let submission = Submission::begin(&id)
            .acknowledged("state-1")
            .acknowledged("anuna-public")
            .acknowledged("app-own");
        assert!(!submission.is_confirmed());
        match &submission {
            Submission::Pending { acknowledged_by, .. } => assert_eq!(acknowledged_by.len(), 3),
            _ => panic!("three acknowledgements must not confirm anything"),
        }
    }

    #[test]
    fn only_a_verified_closure_containing_the_id_confirms_it() {
        let (mut doc, k, method) = document(1);
        let id = grant_id(&doc, "AAAA");

        let submission = Submission::begin(&id).acknowledged("state-1");
        // The closure does not yet contain it.
        let submission = submission.observe(&doc);
        assert!(!submission.is_confirmed());

        revoke(&mut doc, &k, &method, &id, 1_000);
        let submission = submission.observe(&doc);
        assert!(submission.is_confirmed());
    }

    #[test]
    fn a_closure_containing_a_different_id_does_not_confirm_this_one() {
        let (mut doc, k, method) = document(1);
        let mine = grant_id(&doc, "AAAA");
        let theirs = grant_id(&doc, "BBBB");
        revoke(&mut doc, &k, &method, &theirs, 1_000);
        assert!(!Submission::begin(&mine).observe(&doc).is_confirmed());
    }

    #[test]
    fn confirmation_is_terminal() {
        let (mut doc, k, method) = document(1);
        let id = grant_id(&doc, "AAAA");
        revoke(&mut doc, &k, &method, &id, 1_000);
        let confirmed = Submission::begin(&id).observe(&doc);
        assert!(confirmed.clone().acknowledged("state-1").is_confirmed());
        assert!(confirmed.observe(&doc).is_confirmed());
    }

    // ── the projection asymmetry ───────────────────────────────────────────

    fn policy() -> ProjectionPolicy {
        ProjectionPolicy {
            kind: "BitstringStatusList".into(),
            allocation_url: "https://s.example/slots".into(),
            credential_base_url: "https://s.example/lists/".into(),
            max_age_seconds: 900,
        }
    }

    #[test]
    fn a_set_bit_is_permanently_true_at_any_age() {
        // No later state can unset it, so age never makes it wrong.
        let p = policy();
        assert_eq!(read_projection(true, 1_000, 1_900, 1_500, &p), ProjectionReading::Revoked);
        assert_eq!(
            read_projection(true, 1_000, 1_900, 9_999_999, &p),
            ProjectionReading::Revoked,
            "a set bit past validUntil is still revoked"
        );
    }

    #[test]
    fn an_unset_bit_decays_to_unavailable_rather_than_to_not_revoked() {
        let p = policy();
        assert_eq!(
            read_projection(false, 1_000, 1_900, 1_500, &p),
            ProjectionReading::NoInformationYet
        );
        assert_eq!(
            read_projection(false, 1_000, 1_900, 1_900, &p),
            ProjectionReading::Unavailable,
            "at validUntil the projection is unavailable, not evidence of anything"
        );
        assert_eq!(
            read_projection(false, 1_000, 1_900, 999, &p),
            ProjectionReading::Unavailable
        );
    }

    #[test]
    fn a_projection_whose_window_exceeds_the_policy_bound_is_unavailable() {
        // The publisher was forbidden from signing one this long, so a consumer
        // applying only W3C validity rules already rejects it.
        let p = policy();
        assert_eq!(
            read_projection(false, 1_000, 1_000 + 901, 1_100, &p),
            ProjectionReading::Unavailable
        );
        assert_eq!(
            read_projection(true, 1_000, 1_000 + 901, 1_100, &p),
            ProjectionReading::Unavailable,
            "an over-long window is refused before the bit is read"
        );
    }

    #[test]
    fn a_bit_may_be_set_only_after_the_crdt_closure_contains_the_id() {
        let (mut doc, k, method) = document(1);
        let id = grant_id(&doc, "AAAA");
        assert!(!may_set_bit(&doc, &id));
        revoke(&mut doc, &k, &method, &id, 1_000);
        assert!(may_set_bit(&doc, &id));
    }

    #[test]
    fn the_monotonicity_re_check_is_written_down() {
        // CON-210 asks that the unauthenticated-write argument "SHOULD be
        // re-checked against any future method operation that is not
        // grow-only". A list forces that decision to be made here rather than
        // discovered in production.
        let ops = monotonic_operations();
        assert!(ops.contains(&"RevokeCredential"));
        assert!(!ops.contains(&"SetDocumentData"), "SetDocumentData is not monotone");
    }
}
