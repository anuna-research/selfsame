//! Closed Selfsame logical bodies carried by credential/v2 objects.

use super::{
    compact_jws_payload_digest, migration_confirmation_digest_parts,
    recognise_authority_status_response, CredentialV2AuthorityStatus, RecognisedCredentialV2Offer,
};
use cbcl_pairing::credential_v2::{
    CredentialV2BodyVerifier, CredentialV2Error, CredentialV2Kind, CredentialV2LogicalBody,
    CredentialV2Object,
};
use ciborium::Value;
use selfsame_app_identity::profile::ApplicationProfile;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex, MutexGuard};

/// Person's preliminary exact-intent decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialV2IntentDecision {
    /// Continue to pure identity preview.
    Approve,
    /// End without preview or identity effects.
    Decline,
}

/// Person's final decision after authenticated comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialV2FinalDecision {
    /// Authorise the declared final provisioning effects.
    Approve,
    /// End without a final identity effect.
    Decline,
}

/// Closed pre-payload refusal reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialV2RefusalReason {
    /// The reciprocal authority result could not be authenticated.
    AuthorityUnknown,
    /// The authenticated binding did not match the local preview.
    BindingMismatch,
    /// The authenticated application service was unavailable.
    HubUnavailable,
    /// A declared exclusive deadline passed.
    Expired,
    /// The person or shell cancelled the attempt.
    Cancelled,
    /// A closed protocol invariant failed.
    ProtocolError,
}

impl CredentialV2RefusalReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorityUnknown => "authority-unknown",
            Self::BindingMismatch => "binding-mismatch",
            Self::HubUnavailable => "hub-unavailable",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::ProtocolError => "protocol-error",
        }
    }

    fn recognise(value: &str) -> Result<Self, CredentialV2Error> {
        match value {
            "authority-unknown" => Ok(Self::AuthorityUnknown),
            "binding-mismatch" => Ok(Self::BindingMismatch),
            "hub-unavailable" => Ok(Self::HubUnavailable),
            "expired" => Ok(Self::Expired),
            "cancelled" => Ok(Self::Cancelled),
            "protocol-error" => Ok(Self::ProtocolError),
            _ => Err(CredentialV2Error::Schema),
        }
    }
}

/// Wallet-owned values added only after final provisioning succeeds.
pub struct CredentialV2PayloadInput {
    /// Raw 32-octet grant identifier.
    pub grant_id: [u8; 32],
    /// Exact compact VC-JWT grant.
    pub grant: String,
}

/// Browser-authenticated immutable hub status returned to the claimant.
pub struct CredentialV2ReceiptInput {
    /// Exact compact final-status JWS.
    pub final_status_jws: String,
    /// SHA-256 of the exact canonical JWS payload/core octets.
    pub final_status_digest: [u8; 32],
}

/// Exact immutable hub status carried by an endpoint-authenticated Receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecognisedCredentialV2Receipt {
    /// Exact compact final-status JWS.
    pub final_status_jws: String,
    /// SHA-256 of the exact canonical JWS payload/core octets.
    pub final_status_digest: [u8; 32],
}

/// Recognise the closed Receipt body and bind it to the exact durable payload.
pub fn recognise_receipt(
    receipt: &CredentialV2Object,
    carrier_ceremony_id: [u8; 32],
    payload_content_hash: [u8; 32],
) -> Result<RecognisedCredentialV2Receipt, CredentialV2Error> {
    if receipt.kind() != CredentialV2Kind::Receipt {
        return Err(CredentialV2Error::Schema);
    }
    let entries = body_entries(receipt.body())?;
    verify_receipt(&entries)?;
    expect_fixed(&entries, "carrierCeremonyId", &carrier_ceremony_id)?;
    expect_fixed(&entries, "predecessorDigest", &payload_content_hash)?;
    Ok(RecognisedCredentialV2Receipt {
        final_status_jws: text_field(&entries, "finalStatusJws")?.into(),
        final_status_digest: fixed_field(&entries, "finalStatusDigest")?,
    })
}

/// Reconstruct the exact terminal Receipt object from a retained payload
/// content hash and an authenticated HTTPS final status.
///
/// This adapter has no authority to create or resend a payload. The caller
/// supplies the intent and predecessor digests retained in the sealed claimant
/// checkpoint; the restored cbcl-pairing endpoint checks both before accepting
/// the object through its private recovered-receipt transition.
pub fn recovered_receipt_object(
    intent_digest: [u8; 32],
    carrier_ceremony_id: [u8; 32],
    payload_content_hash: [u8; 32],
    input: CredentialV2ReceiptInput,
) -> Result<CredentialV2Object, CredentialV2Error> {
    if !valid_compact_jws(&input.final_status_jws)
        || input.final_status_jws.len() > 8_192
        || compact_jws_payload_digest(&input.final_status_jws)
            .map_err(|_| CredentialV2Error::Schema)?
            != input.final_status_digest
    {
        return Err(CredentialV2Error::Schema);
    }
    let body = cbor2::to_canonical_vec(&Value::Map(vec![
        (
            Value::Text("finalStatusJws".into()),
            Value::Text(input.final_status_jws),
        ),
        (
            Value::Text("finalStatusDigest".into()),
            Value::Bytes(input.final_status_digest.to_vec()),
        ),
        (
            Value::Text("carrierCeremonyId".into()),
            Value::Bytes(carrier_ceremony_id.to_vec()),
        ),
        (
            Value::Text("predecessorDigest".into()),
            Value::Bytes(payload_content_hash.to_vec()),
        ),
    ]))
    .map_err(|_| CredentialV2Error::Schema)?;
    CredentialV2Object::new(CredentialV2Kind::Receipt, intent_digest, body)
}

/// Authenticated preview retained only after the closed preparation body was
/// built or verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialV2RetainedPreview {
    did: String,
    fingerprint_digest: [u8; 32],
}

impl CredentialV2RetainedPreview {
    /// Borrow the exact preview issuer DID.
    #[must_use]
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Borrow SHA-256 over the exact issuer-DID UTF-8 bytes.
    #[must_use]
    pub const fn fingerprint_digest(&self) -> &[u8; 32] {
        &self.fingerprint_digest
    }
}

/// Authenticated reverse-payload values retained only after the closed body
/// has been built locally or verified by the endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialV2RetainedPayload {
    offer_core_digest: [u8; 32],
    preview_issuer_did: String,
    preview_fingerprint_digest: [u8; 32],
    account_principal_digest: [u8; 32],
    account_scope_id: [u8; 32],
    device_did: String,
    grant_id: [u8; 32],
    grant: String,
    migration_confirmation_digest: [u8; 32],
}

impl CredentialV2RetainedPayload {
    /// Borrow the authenticated offer-core digest.
    #[must_use]
    pub const fn offer_core_digest(&self) -> &[u8; 32] {
        &self.offer_core_digest
    }

    /// Borrow the authenticated issuer DID compared by the person.
    #[must_use]
    pub fn preview_issuer_did(&self) -> &str {
        &self.preview_issuer_did
    }

    /// Borrow SHA-256 over the exact preview-DID UTF-8 bytes.
    #[must_use]
    pub const fn preview_fingerprint_digest(&self) -> &[u8; 32] {
        &self.preview_fingerprint_digest
    }

    /// Borrow the hub-authenticated opaque application-account principal.
    #[must_use]
    pub const fn account_principal_digest(&self) -> &[u8; 32] {
        &self.account_principal_digest
    }

    /// Borrow the hub-authenticated application-account scope.
    #[must_use]
    pub const fn account_scope_id(&self) -> &[u8; 32] {
        &self.account_scope_id
    }

    /// Borrow the installation DID bound by the signed offer.
    #[must_use]
    pub fn device_did(&self) -> &str {
        &self.device_did
    }

    /// Borrow the raw grant identifier carried by the payload.
    #[must_use]
    pub const fn grant_id(&self) -> &[u8; 32] {
        &self.grant_id
    }

    /// Borrow the exact compact VC-JWT grant.
    #[must_use]
    pub fn grant(&self) -> &str {
        &self.grant
    }

    /// Borrow the authenticated transition confirmation digest.
    #[must_use]
    pub const fn migration_confirmation_digest(&self) -> &[u8; 32] {
        &self.migration_confirmation_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Preview {
    did: String,
    fingerprint_digest: [u8; 32],
}

struct BoundBodyAuthority {
    profile: ApplicationProfile,
    kid: String,
    ceremony: [u8; 32],
    intent_digest: [u8; 32],
    offer_core_digest: [u8; 32],
    account_principal_digest: [u8; 32],
    account_scope_id: [u8; 32],
    device_did: String,
    device_key_digest: [u8; 32],
    legacy_key_digest: [u8; 32],
    room_set_digest: [u8; 32],
    migration_snapshot_digest: [u8; 32],
    snapshot_nonce: [u8; 32],
    preview: Option<Preview>,
    payload: Option<CredentialV2RetainedPayload>,
}

type SharedAuthority = Arc<Mutex<Option<BoundBodyAuthority>>>;

struct BoundGuard<'a>(MutexGuard<'a, Option<BoundBodyAuthority>>);

impl std::ops::Deref for BoundGuard<'_> {
    type Target = BoundBodyAuthority;

    fn deref(&self) -> &Self::Target {
        self.0
            .as_ref()
            .expect("bound authority checked at creation")
    }
}

impl std::ops::DerefMut for BoundGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
            .as_mut()
            .expect("bound authority checked at creation")
    }
}

/// Shared one-attempt authority used by builders and the endpoint verifier.
#[derive(Clone)]
pub struct CredentialV2BodyAuthority {
    shared: SharedAuthority,
}

impl std::fmt::Debug for CredentialV2BodyAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CredentialV2BodyAuthority([REDACTED])")
    }
}

/// Endpoint adapter for the nine closed Selfsame successor grammars.
pub struct SelfsameCredentialV2BodyVerifier {
    shared: SharedAuthority,
    restore_profile: Option<ApplicationProfile>,
}

impl std::fmt::Debug for SelfsameCredentialV2BodyVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SelfsameCredentialV2BodyVerifier([REDACTED])")
    }
}

/// Construct one initially unbound authority and its endpoint verifier.
///
/// The verifier refuses every successor until [`CredentialV2BodyAuthority::bind_offer`]
/// receives the independently authenticated signed offer.
#[must_use]
pub fn credential_v2_body_authority(
) -> (CredentialV2BodyAuthority, SelfsameCredentialV2BodyVerifier) {
    body_authority(None)
}

/// Construct an initially unbound authority whose verifier may restore only a
/// checkpoint bound to this independently authenticated profile.
#[must_use]
pub fn credential_v2_body_authority_for_restore(
    profile: ApplicationProfile,
) -> (CredentialV2BodyAuthority, SelfsameCredentialV2BodyVerifier) {
    body_authority(Some(profile))
}

fn body_authority(
    restore_profile: Option<ApplicationProfile>,
) -> (CredentialV2BodyAuthority, SelfsameCredentialV2BodyVerifier) {
    let shared = Arc::new(Mutex::new(None));
    (
        CredentialV2BodyAuthority {
            shared: Arc::clone(&shared),
        },
        SelfsameCredentialV2BodyVerifier {
            shared,
            restore_profile,
        },
    )
}

impl CredentialV2BodyAuthority {
    /// Require an independently re-recognised offer to be the exact authority
    /// already recovered from the sealed endpoint checkpoint.
    pub fn require_bound_offer(
        &self,
        profile: &ApplicationProfile,
        offer: &RecognisedCredentialV2Offer,
    ) -> Result<(), CredentialV2Error> {
        let bound = self.bound()?;
        let transition = offer
            .claims
            .transition()
            .as_path_a_to_b()
            .ok_or(CredentialV2Error::Profile)?;
        if bound.profile.digest() != profile.digest()
            || bound.kid != offer.kid
            || bound.ceremony != *offer.claims.carrier_ceremony_id()
            || bound.intent_digest
                != cbcl_pairing::credential_v2::credential_v2_intent_digest(
                    *offer.claims.offer_core_digest(),
                )
            || bound.offer_core_digest != *offer.claims.offer_core_digest()
            || bound.account_principal_digest
                != *offer.claims.account_provenance().account_principal_digest()
            || bound.account_scope_id != *offer.claims.account_provenance().account_scope_id()
            || bound.device_did != offer.claims.device_binding().device_did()
            || bound.device_key_digest != *offer.claims.device_binding().device_key_digest()
            || bound.legacy_key_digest != *transition.legacy_key_digest()
            || bound.room_set_digest != *transition.room_set_digest()
            || bound.migration_snapshot_digest != *transition.migration_snapshot_digest()
            || bound.snapshot_nonce != *transition.snapshot_nonce()
        {
            return Err(CredentialV2Error::Profile);
        }
        Ok(())
    }

    /// Return the authenticated preview only after preparation has retained it.
    pub fn retained_preview(&self) -> Result<CredentialV2RetainedPreview, CredentialV2Error> {
        let bound = self.bound()?;
        let preview = bound.preview.as_ref().ok_or(CredentialV2Error::Phase)?;
        Ok(CredentialV2RetainedPreview {
            did: preview.did.clone(),
            fingerprint_digest: preview.fingerprint_digest,
        })
    }

    /// Return the authenticated reverse payload only after its closed body has
    /// been built or verified. Raw transport bytes never populate this view.
    pub fn retained_payload(&self) -> Result<CredentialV2RetainedPayload, CredentialV2Error> {
        self.bound()?
            .payload
            .clone()
            .ok_or(CredentialV2Error::Phase)
    }

    /// Rebuild transient retained facts from the endpoint's authenticated last
    /// peer object after restoring a sealed checkpoint. Large payload bytes are
    /// deliberately retained only once, by the endpoint checkpoint itself.
    pub fn restore_retained_received_object(
        &self,
        object: &CredentialV2Object,
    ) -> Result<(), CredentialV2Error> {
        let mut bound = self.bound()?;
        if object.intent_digest() != &bound.intent_digest {
            return Err(CredentialV2Error::Profile);
        }
        let entries = body_entries(object.body())?;
        expect_fixed(&entries, "carrierCeremonyId", &bound.ceremony)?;
        match object.kind() {
            CredentialV2Kind::Preparation => verify_preparation(&entries, &mut bound),
            CredentialV2Kind::Payload => verify_payload(&entries, &mut bound),
            _ => Ok(()),
        }
    }

    /// Bind this one-attempt grammar to a completely authenticated signed offer.
    pub fn bind_offer(
        &self,
        profile: ApplicationProfile,
        offer: &RecognisedCredentialV2Offer,
    ) -> Result<(), CredentialV2Error> {
        if offer.signed_offer.is_empty()
            || offer.kid.is_empty()
            || offer.profile_digest != *profile.digest()
            || offer.claims.application_id() != profile.application_id.as_str()
        {
            return Err(CredentialV2Error::Profile);
        }
        let transition = offer
            .claims
            .transition()
            .as_path_a_to_b()
            .ok_or(CredentialV2Error::Profile)?;
        let mut slot = lock(&self.shared)?;
        if slot.is_some() {
            return Err(CredentialV2Error::Phase);
        }
        *slot = Some(BoundBodyAuthority {
            profile,
            kid: offer.kid.clone(),
            ceremony: *offer.claims.carrier_ceremony_id(),
            intent_digest: cbcl_pairing::credential_v2::credential_v2_intent_digest(
                *offer.claims.offer_core_digest(),
            ),
            offer_core_digest: *offer.claims.offer_core_digest(),
            account_principal_digest: *offer.claims.account_provenance().account_principal_digest(),
            account_scope_id: *offer.claims.account_provenance().account_scope_id(),
            device_did: offer.claims.device_binding().device_did().into(),
            device_key_digest: *offer.claims.device_binding().device_key_digest(),
            legacy_key_digest: *transition.legacy_key_digest(),
            room_set_digest: *transition.room_set_digest(),
            migration_snapshot_digest: *transition.migration_snapshot_digest(),
            snapshot_nonce: *transition.snapshot_nonce(),
            preview: None,
            payload: None,
        });
        Ok(())
    }

    /// Build the exact preliminary decision successor.
    pub fn intent_decision(
        &self,
        predecessor: &CredentialV2Object,
        decision: CredentialV2IntentDecision,
    ) -> Result<CredentialV2Object, CredentialV2Error> {
        let bound = self.bound()?;
        require_predecessor(&bound, predecessor, &[CredentialV2Kind::Offer])?;
        let (kind, decision) = match decision {
            CredentialV2IntentDecision::Approve => (CredentialV2Kind::IntentApprove, "approve"),
            CredentialV2IntentDecision::Decline => (CredentialV2Kind::IntentDecline, "decline"),
        };
        object(
            &bound,
            predecessor,
            kind,
            vec![
                bytes("offerCoreDigest", bound.offer_core_digest),
                text("decision", decision),
            ],
        )
    }

    /// Build the exact pure-preview successor and retain its local binding.
    pub fn preparation(
        &self,
        predecessor: &CredentialV2Object,
        preview_issuer_did: &str,
    ) -> Result<CredentialV2Object, CredentialV2Error> {
        let preview = recognise_preview(preview_issuer_did, None)?;
        let mut bound = self.bound()?;
        require_predecessor(&bound, predecessor, &[CredentialV2Kind::IntentApprove])?;
        retain_preview(&mut bound, &preview)?;
        object(
            &bound,
            predecessor,
            CredentialV2Kind::Preparation,
            vec![
                bytes("offerCoreDigest", bound.offer_core_digest),
                text("previewIssuerDid", &preview.did),
                bytes("previewFingerprintDigest", preview.fingerprint_digest),
            ],
        )
    }

    /// Build an authenticated comparison or binding successor from the exact
    /// signed authority-status response.
    pub fn comparison(
        &self,
        predecessor: &CredentialV2Object,
        authority_status_response: &[u8],
    ) -> Result<CredentialV2Object, CredentialV2Error> {
        let bound = self.bound()?;
        require_predecessor(&bound, predecessor, &[CredentialV2Kind::Preparation])?;
        let preview = bound.preview.as_ref().ok_or(CredentialV2Error::Phase)?;
        let (kind, result) = comparison_status(&bound, authority_status_response, preview)?;
        object(
            &bound,
            predecessor,
            kind,
            vec![
                text("result", result),
                text("previewIssuerDid", &preview.did),
                bytes("previewFingerprintDigest", preview.fingerprint_digest),
                (
                    "authorityStatusResponse",
                    Value::Bytes(authority_status_response.to_vec()),
                ),
                bytes(
                    "authorityStatusDigest",
                    Sha256::digest(authority_status_response).into(),
                ),
            ],
        )
    }

    /// Build the exact final decision successor.
    pub fn final_decision(
        &self,
        predecessor: &CredentialV2Object,
        decision: CredentialV2FinalDecision,
    ) -> Result<CredentialV2Object, CredentialV2Error> {
        let bound = self.bound()?;
        require_predecessor(
            &bound,
            predecessor,
            &[
                CredentialV2Kind::ComparisonConfirmed,
                CredentialV2Kind::BindingConfirmed,
            ],
        )?;
        let preview = bound.preview.as_ref().ok_or(CredentialV2Error::Phase)?;
        let (kind, decision) = match decision {
            CredentialV2FinalDecision::Approve => (CredentialV2Kind::FinalApprove, "approve"),
            CredentialV2FinalDecision::Decline => (CredentialV2Kind::FinalDecline, "decline"),
        };
        object(
            &bound,
            predecessor,
            kind,
            vec![
                text("previewIssuerDid", &preview.did),
                bytes("previewFingerprintDigest", preview.fingerprint_digest),
                text("decision", decision),
            ],
        )
    }

    /// Build one closed pre-payload refusal successor.
    pub fn refusal(
        &self,
        predecessor: &CredentialV2Object,
        reason: CredentialV2RefusalReason,
    ) -> Result<CredentialV2Object, CredentialV2Error> {
        let bound = self.bound()?;
        require_predecessor(
            &bound,
            predecessor,
            &[
                CredentialV2Kind::Offer,
                CredentialV2Kind::IntentApprove,
                CredentialV2Kind::Preparation,
                CredentialV2Kind::ComparisonConfirmed,
                CredentialV2Kind::BindingConfirmed,
                CredentialV2Kind::FinalApprove,
            ],
        )?;
        object(
            &bound,
            predecessor,
            CredentialV2Kind::Refusal,
            vec![text("reason", reason.as_str())],
        )
    }

    /// Build the exact reverse payload after final provisioning succeeds.
    pub fn payload(
        &self,
        predecessor: &CredentialV2Object,
        input: CredentialV2PayloadInput,
    ) -> Result<CredentialV2Object, CredentialV2Error> {
        if !valid_compact_jws(&input.grant) || input.grant.len() > 49_152 {
            return Err(CredentialV2Error::Schema);
        }
        let mut bound = self.bound()?;
        require_predecessor(&bound, predecessor, &[CredentialV2Kind::FinalApprove])?;
        let preview = bound.preview.as_ref().ok_or(CredentialV2Error::Phase)?;
        let confirmation = migration_confirmation_digest(&bound, preview)?;
        let retained = CredentialV2RetainedPayload {
            offer_core_digest: bound.offer_core_digest,
            preview_issuer_did: preview.did.clone(),
            preview_fingerprint_digest: preview.fingerprint_digest,
            account_principal_digest: bound.account_principal_digest,
            account_scope_id: bound.account_scope_id,
            device_did: bound.device_did.clone(),
            grant_id: input.grant_id,
            grant: input.grant,
            migration_confirmation_digest: confirmation,
        };
        let built = object(
            &bound,
            predecessor,
            CredentialV2Kind::Payload,
            vec![
                bytes("offerCoreDigest", bound.offer_core_digest),
                text("previewIssuerDid", &preview.did),
                bytes("previewFingerprintDigest", preview.fingerprint_digest),
                bytes("accountPrincipalDigest", bound.account_principal_digest),
                bytes("accountScopeId", bound.account_scope_id),
                text("deviceDid", &bound.device_did),
                bytes("grantId", retained.grant_id),
                text("grantMediaType", "application/vc+jwt"),
                text("grant", &retained.grant),
                bytes("migrationConfirmationDigest", confirmation),
            ],
        )?;
        retain_payload(&mut bound, retained)?;
        Ok(built)
    }

    /// Build the sole allocator receipt after the hub status has been
    /// cryptographically checked and durably activated by the browser.
    pub fn receipt(
        &self,
        predecessor: &CredentialV2Object,
        input: CredentialV2ReceiptInput,
    ) -> Result<CredentialV2Object, CredentialV2Error> {
        if !valid_compact_jws(&input.final_status_jws)
            || input.final_status_jws.len() > 8_192
            || compact_jws_payload_digest(&input.final_status_jws)
                .map_err(|_| CredentialV2Error::Schema)?
                != input.final_status_digest
        {
            return Err(CredentialV2Error::Schema);
        }
        let bound = self.bound()?;
        require_predecessor(&bound, predecessor, &[CredentialV2Kind::Payload])?;
        object(
            &bound,
            predecessor,
            CredentialV2Kind::Receipt,
            vec![
                text("finalStatusJws", &input.final_status_jws),
                bytes("finalStatusDigest", input.final_status_digest),
            ],
        )
    }

    fn bound(&self) -> Result<BoundGuard<'_>, CredentialV2Error> {
        let slot = lock(&self.shared)?;
        if slot.is_none() {
            return Err(CredentialV2Error::Phase);
        }
        Ok(BoundGuard(slot))
    }
}

impl CredentialV2BodyVerifier for SelfsameCredentialV2BodyVerifier {
    fn verify(&mut self, body: &CredentialV2LogicalBody<'_>) -> Result<(), CredentialV2Error> {
        let mut slot = lock(&self.shared)?;
        let bound = slot.as_mut().ok_or(CredentialV2Error::Phase)?;
        if body.carrier_ceremony_id() != &bound.ceremony {
            return Err(CredentialV2Error::Profile);
        }
        let entries = body_entries(body.bytes())?;
        match body.kind() {
            CredentialV2Kind::IntentApprove => verify_intent_decision(&entries, bound, "approve"),
            CredentialV2Kind::IntentDecline => verify_intent_decision(&entries, bound, "decline"),
            CredentialV2Kind::Preparation => verify_preparation(&entries, bound),
            CredentialV2Kind::ComparisonConfirmed => {
                verify_comparison(&entries, bound, CredentialV2Kind::ComparisonConfirmed)
            }
            CredentialV2Kind::BindingConfirmed => {
                verify_comparison(&entries, bound, CredentialV2Kind::BindingConfirmed)
            }
            CredentialV2Kind::Refusal => verify_refusal(&entries),
            CredentialV2Kind::FinalApprove => verify_final(&entries, bound, "approve"),
            CredentialV2Kind::FinalDecline => verify_final(&entries, bound, "decline"),
            CredentialV2Kind::Payload => verify_payload(&entries, bound),
            CredentialV2Kind::Receipt => verify_receipt(&entries),
            // The Offer and the pre-offer AccountSelect are recognised by the
            // endpoint itself and never reach a successor verifier.
            CredentialV2Kind::Offer | CredentialV2Kind::AccountSelect => {
                Err(CredentialV2Error::Schema)
            }
        }
    }

    fn checkpoint_state(&self) -> Result<Vec<u8>, CredentialV2Error> {
        let slot = lock(&self.shared)?;
        let Some(bound) = slot.as_ref() else {
            return Ok(Vec::new());
        };
        encode_authority_checkpoint(bound)
    }

    fn restore_checkpoint_state(&mut self, state: &[u8]) -> Result<(), CredentialV2Error> {
        if state.is_empty() {
            return Ok(());
        }
        let profile = self
            .restore_profile
            .as_ref()
            .ok_or(CredentialV2Error::Profile)?;
        let restored = decode_authority_checkpoint(state, profile)?;
        let mut slot = lock(&self.shared)?;
        if slot.is_some() {
            return Err(CredentialV2Error::Phase);
        }
        *slot = Some(restored);
        Ok(())
    }
}

const AUTHORITY_CHECKPOINT_DOMAIN: &str = "selfsame credential/v2 body authority v1";
const MAX_AUTHORITY_CHECKPOINT_BYTES: usize = 60_000;

fn encode_authority_checkpoint(bound: &BoundBodyAuthority) -> Result<Vec<u8>, CredentialV2Error> {
    let preview_did = bound
        .preview
        .as_ref()
        .map_or(Value::Null, |value| Value::Text(value.did.clone()));
    let preview_digest = bound.preview.as_ref().map_or(Value::Null, |value| {
        Value::Bytes(value.fingerprint_digest.to_vec())
    });
    let value = Value::Map(
        vec![
            text("domain", AUTHORITY_CHECKPOINT_DOMAIN),
            bytes("profileDigest", *bound.profile.digest()),
            text("kid", &bound.kid),
            bytes("carrierCeremonyId", bound.ceremony),
            bytes("intentDigest", bound.intent_digest),
            bytes("offerCoreDigest", bound.offer_core_digest),
            bytes("accountPrincipalDigest", bound.account_principal_digest),
            bytes("accountScopeId", bound.account_scope_id),
            text("deviceDid", &bound.device_did),
            bytes("deviceKeyDigest", bound.device_key_digest),
            bytes("legacyKeyDigest", bound.legacy_key_digest),
            bytes("roomSetDigest", bound.room_set_digest),
            bytes("migrationSnapshotDigest", bound.migration_snapshot_digest),
            bytes("snapshotNonce", bound.snapshot_nonce),
            ("previewIssuerDid", preview_did),
            ("previewFingerprintDigest", preview_digest),
        ]
        .into_iter()
        .map(|(name, value)| (Value::Text(name.into()), value))
        .collect(),
    );
    let encoded = cbor2::to_canonical_vec(&value).map_err(|_| CredentialV2Error::Schema)?;
    if encoded.is_empty() || encoded.len() > MAX_AUTHORITY_CHECKPOINT_BYTES {
        return Err(CredentialV2Error::Size);
    }
    Ok(encoded)
}

fn decode_authority_checkpoint(
    input: &[u8],
    profile: &ApplicationProfile,
) -> Result<BoundBodyAuthority, CredentialV2Error> {
    if input.is_empty() || input.len() > MAX_AUTHORITY_CHECKPOINT_BYTES {
        return Err(CredentialV2Error::Size);
    }
    let entries = body_entries(input)?;
    exact_fields(
        &entries,
        &[
            "domain",
            "profileDigest",
            "kid",
            "carrierCeremonyId",
            "intentDigest",
            "offerCoreDigest",
            "accountPrincipalDigest",
            "accountScopeId",
            "deviceDid",
            "deviceKeyDigest",
            "legacyKeyDigest",
            "roomSetDigest",
            "migrationSnapshotDigest",
            "snapshotNonce",
            "previewIssuerDid",
            "previewFingerprintDigest",
        ],
    )?;
    expect_text(&entries, "domain", AUTHORITY_CHECKPOINT_DOMAIN)?;
    expect_fixed(&entries, "profileDigest", profile.digest())?;
    let kid = text_field(&entries, "kid")?;
    let device_did = text_field(&entries, "deviceDid")?;
    if kid.is_empty()
        || kid.len() > 2_048
        || device_did.is_empty()
        || device_did.len() > 512
        || !device_did.starts_with("did:key:")
    {
        return Err(CredentialV2Error::Schema);
    }
    let offer_core_digest = fixed_field(&entries, "offerCoreDigest")?;
    let intent_digest = fixed_field(&entries, "intentDigest")?;
    if intent_digest != cbcl_pairing::credential_v2::credential_v2_intent_digest(offer_core_digest)
    {
        return Err(CredentialV2Error::Profile);
    }

    let preview_did = optional_text_field(&entries, "previewIssuerDid")?;
    let preview_digest = optional_fixed_field(&entries, "previewFingerprintDigest")?;
    let preview = match (preview_did, preview_digest) {
        (None, None) => None,
        (Some(did), Some(digest)) => Some(recognise_preview(&did, Some(digest))?),
        _ => return Err(CredentialV2Error::Schema),
    };

    Ok(BoundBodyAuthority {
        profile: profile.clone(),
        kid: kid.into(),
        ceremony: fixed_field(&entries, "carrierCeremonyId")?,
        intent_digest,
        offer_core_digest,
        account_principal_digest: fixed_field(&entries, "accountPrincipalDigest")?,
        account_scope_id: fixed_field(&entries, "accountScopeId")?,
        device_did: device_did.into(),
        device_key_digest: fixed_field(&entries, "deviceKeyDigest")?,
        legacy_key_digest: fixed_field(&entries, "legacyKeyDigest")?,
        room_set_digest: fixed_field(&entries, "roomSetDigest")?,
        migration_snapshot_digest: fixed_field(&entries, "migrationSnapshotDigest")?,
        snapshot_nonce: fixed_field(&entries, "snapshotNonce")?,
        preview,
        payload: None,
    })
}

fn optional_fixed_field<const N: usize>(
    entries: &[(Value, Value)],
    name: &str,
) -> Result<Option<[u8; N]>, CredentialV2Error> {
    match field(entries, name)? {
        Value::Null => Ok(None),
        Value::Bytes(value) => value
            .as_slice()
            .try_into()
            .map(Some)
            .map_err(|_| CredentialV2Error::Schema),
        _ => Err(CredentialV2Error::Schema),
    }
}

fn optional_text_field(
    entries: &[(Value, Value)],
    name: &str,
) -> Result<Option<String>, CredentialV2Error> {
    match field(entries, name)? {
        Value::Null => Ok(None),
        Value::Text(value) => Ok(Some(value.clone())),
        _ => Err(CredentialV2Error::Schema),
    }
}

fn verify_intent_decision(
    entries: &[(Value, Value)],
    bound: &BoundBodyAuthority,
    decision: &str,
) -> Result<(), CredentialV2Error> {
    exact_fields(
        entries,
        &[
            "carrierCeremonyId",
            "predecessorDigest",
            "offerCoreDigest",
            "decision",
        ],
    )?;
    expect_fixed(entries, "offerCoreDigest", &bound.offer_core_digest)?;
    expect_text(entries, "decision", decision)
}

fn verify_preparation(
    entries: &[(Value, Value)],
    bound: &mut BoundBodyAuthority,
) -> Result<(), CredentialV2Error> {
    exact_fields(
        entries,
        &[
            "carrierCeremonyId",
            "predecessorDigest",
            "offerCoreDigest",
            "previewIssuerDid",
            "previewFingerprintDigest",
        ],
    )?;
    expect_fixed(entries, "offerCoreDigest", &bound.offer_core_digest)?;
    let preview = recognise_preview(
        text_field(entries, "previewIssuerDid")?,
        Some(fixed_field(entries, "previewFingerprintDigest")?),
    )?;
    retain_preview(bound, &preview)
}

fn verify_comparison(
    entries: &[(Value, Value)],
    bound: &BoundBodyAuthority,
    kind: CredentialV2Kind,
) -> Result<(), CredentialV2Error> {
    exact_fields(
        entries,
        &[
            "carrierCeremonyId",
            "predecessorDigest",
            "result",
            "previewIssuerDid",
            "previewFingerprintDigest",
            "authorityStatusResponse",
            "authorityStatusDigest",
        ],
    )?;
    let preview = recognised_retained_preview(entries, bound)?;
    let response = bytes_field(entries, "authorityStatusResponse")?;
    if response.is_empty() || response.len() > 768 {
        return Err(CredentialV2Error::Schema);
    }
    let digest: [u8; 32] = Sha256::digest(response).into();
    expect_fixed(entries, "authorityStatusDigest", &digest)?;
    let (expected_kind, result) = comparison_status(bound, response, preview)?;
    if expected_kind != kind {
        return Err(CredentialV2Error::Profile);
    }
    expect_text(entries, "result", result)
}

fn verify_refusal(entries: &[(Value, Value)]) -> Result<(), CredentialV2Error> {
    exact_fields(
        entries,
        &["carrierCeremonyId", "predecessorDigest", "reason"],
    )?;
    CredentialV2RefusalReason::recognise(text_field(entries, "reason")?).map(|_| ())
}

fn verify_receipt(entries: &[(Value, Value)]) -> Result<(), CredentialV2Error> {
    exact_fields(
        entries,
        &[
            "carrierCeremonyId",
            "predecessorDigest",
            "finalStatusJws",
            "finalStatusDigest",
        ],
    )?;
    let jws = text_field(entries, "finalStatusJws")?;
    if !valid_compact_jws(jws) || jws.len() > 8_192 {
        return Err(CredentialV2Error::Schema);
    }
    let digest = compact_jws_payload_digest(jws).map_err(|_| CredentialV2Error::Schema)?;
    expect_fixed(entries, "finalStatusDigest", &digest)
}

fn verify_final(
    entries: &[(Value, Value)],
    bound: &BoundBodyAuthority,
    decision: &str,
) -> Result<(), CredentialV2Error> {
    exact_fields(
        entries,
        &[
            "carrierCeremonyId",
            "predecessorDigest",
            "previewIssuerDid",
            "previewFingerprintDigest",
            "decision",
        ],
    )?;
    let _ = recognised_retained_preview(entries, bound)?;
    expect_text(entries, "decision", decision)
}

fn verify_payload(
    entries: &[(Value, Value)],
    bound: &mut BoundBodyAuthority,
) -> Result<(), CredentialV2Error> {
    exact_fields(
        entries,
        &[
            "carrierCeremonyId",
            "predecessorDigest",
            "offerCoreDigest",
            "previewIssuerDid",
            "previewFingerprintDigest",
            "accountPrincipalDigest",
            "accountScopeId",
            "deviceDid",
            "grantId",
            "grantMediaType",
            "grant",
            "migrationConfirmationDigest",
        ],
    )?;
    let preview = recognised_retained_preview(entries, bound)?;
    expect_fixed(entries, "offerCoreDigest", &bound.offer_core_digest)?;
    expect_fixed(
        entries,
        "accountPrincipalDigest",
        &bound.account_principal_digest,
    )?;
    expect_fixed(entries, "accountScopeId", &bound.account_scope_id)?;
    expect_text(entries, "deviceDid", &bound.device_did)?;
    let grant_id: [u8; 32] = fixed_field(entries, "grantId")?;
    expect_text(entries, "grantMediaType", "application/vc+jwt")?;
    let grant = text_field(entries, "grant")?;
    if grant.len() > 49_152 || !valid_compact_jws(grant) {
        return Err(CredentialV2Error::Schema);
    }
    let migration_confirmation_digest = migration_confirmation_digest(bound, preview)?;
    expect_fixed(
        entries,
        "migrationConfirmationDigest",
        &migration_confirmation_digest,
    )?;
    retain_payload(
        bound,
        CredentialV2RetainedPayload {
            offer_core_digest: bound.offer_core_digest,
            preview_issuer_did: preview.did.clone(),
            preview_fingerprint_digest: preview.fingerprint_digest,
            account_principal_digest: bound.account_principal_digest,
            account_scope_id: bound.account_scope_id,
            device_did: bound.device_did.clone(),
            grant_id,
            grant: grant.into(),
            migration_confirmation_digest,
        },
    )
}

fn recognised_retained_preview<'a>(
    entries: &[(Value, Value)],
    bound: &'a BoundBodyAuthority,
) -> Result<&'a Preview, CredentialV2Error> {
    let retained = bound.preview.as_ref().ok_or(CredentialV2Error::Phase)?;
    let found = recognise_preview(
        text_field(entries, "previewIssuerDid")?,
        Some(fixed_field(entries, "previewFingerprintDigest")?),
    )?;
    if &found != retained {
        return Err(CredentialV2Error::Profile);
    }
    Ok(retained)
}

fn comparison_status(
    bound: &BoundBodyAuthority,
    response: &[u8],
    preview: &Preview,
) -> Result<(CredentialV2Kind, &'static str), CredentialV2Error> {
    match recognise_authority_status_response(
        &bound.profile,
        response,
        &bound.kid,
        bound.ceremony,
        bound.offer_core_digest,
    )
    .map_err(|_| CredentialV2Error::Profile)?
    {
        CredentialV2AuthorityStatus::NoBinding => Ok((
            CredentialV2Kind::ComparisonConfirmed,
            "no-binding-person-compared",
        )),
        CredentialV2AuthorityStatus::Bound(did) if did == preview.did => {
            Ok((CredentialV2Kind::BindingConfirmed, "bound-same-did"))
        }
        CredentialV2AuthorityStatus::Bound(_) => Err(CredentialV2Error::Profile),
    }
}

fn migration_confirmation_digest(
    bound: &BoundBodyAuthority,
    preview: &Preview,
) -> Result<[u8; 32], CredentialV2Error> {
    migration_confirmation_digest_parts(
        bound.offer_core_digest,
        &preview.did,
        bound.legacy_key_digest,
        bound.room_set_digest,
        bound.migration_snapshot_digest,
        bound.snapshot_nonce,
        bound.device_key_digest,
    )
}

fn recognise_preview(
    did: &str,
    claimed_digest: Option<[u8; 32]>,
) -> Result<Preview, CredentialV2Error> {
    if did.is_empty() || did.len() > 512 || !did.is_ascii() || did.parse::<did_crdt::Did>().is_err()
    {
        return Err(CredentialV2Error::Schema);
    }
    let fingerprint_digest = Sha256::digest(did.as_bytes()).into();
    if claimed_digest.is_some_and(|claimed| claimed != fingerprint_digest) {
        return Err(CredentialV2Error::Profile);
    }
    Ok(Preview {
        did: did.into(),
        fingerprint_digest,
    })
}

fn retain_preview(
    bound: &mut BoundBodyAuthority,
    preview: &Preview,
) -> Result<(), CredentialV2Error> {
    match &bound.preview {
        None => {
            bound.preview = Some(preview.clone());
            Ok(())
        }
        Some(retained) if retained == preview => Ok(()),
        Some(_) => Err(CredentialV2Error::Profile),
    }
}

fn retain_payload(
    bound: &mut BoundBodyAuthority,
    payload: CredentialV2RetainedPayload,
) -> Result<(), CredentialV2Error> {
    match &bound.payload {
        None => {
            bound.payload = Some(payload);
            Ok(())
        }
        Some(retained) if retained == &payload => Ok(()),
        Some(_) => Err(CredentialV2Error::Profile),
    }
}

fn require_predecessor(
    bound: &BoundBodyAuthority,
    predecessor: &CredentialV2Object,
    kinds: &[CredentialV2Kind],
) -> Result<(), CredentialV2Error> {
    if predecessor.intent_digest() != &bound.intent_digest || !kinds.contains(&predecessor.kind()) {
        return Err(CredentialV2Error::Phase);
    }
    Ok(())
}

fn object(
    bound: &BoundBodyAuthority,
    predecessor: &CredentialV2Object,
    kind: CredentialV2Kind,
    mut members: Vec<(&str, Value)>,
) -> Result<CredentialV2Object, CredentialV2Error> {
    members.push(bytes("carrierCeremonyId", bound.ceremony));
    members.push(bytes("predecessorDigest", predecessor.content_hash()));
    let value = Value::Map(
        members
            .into_iter()
            .map(|(name, value)| (Value::Text(name.into()), value))
            .collect(),
    );
    let body = cbor2::to_canonical_vec(&value).map_err(|_| CredentialV2Error::Schema)?;
    CredentialV2Object::new(kind, bound.intent_digest, body)
}

fn bytes<const N: usize>(name: &'static str, value: [u8; N]) -> (&'static str, Value) {
    (name, Value::Bytes(value.to_vec()))
}

fn text<'a>(name: &'a str, value: &str) -> (&'a str, Value) {
    (name, Value::Text(value.into()))
}

fn body_entries(bytes: &[u8]) -> Result<Vec<(Value, Value)>, CredentialV2Error> {
    let mut cursor = std::io::Cursor::new(bytes);
    let value: Value =
        ciborium::de::from_reader(&mut cursor).map_err(|_| CredentialV2Error::MalformedCbor)?;
    if usize::try_from(cursor.position()).map_err(|_| CredentialV2Error::TrailingBytes)?
        != bytes.len()
        || cbor2::to_canonical_vec(&value).map_err(|_| CredentialV2Error::NonDeterministic)?
            != bytes
    {
        return Err(CredentialV2Error::NonDeterministic);
    }
    value.as_map().cloned().ok_or(CredentialV2Error::Schema)
}

fn exact_fields(entries: &[(Value, Value)], names: &[&str]) -> Result<(), CredentialV2Error> {
    if entries.len() != names.len() || names.iter().any(|name| field(entries, name).is_err()) {
        return Err(CredentialV2Error::Schema);
    }
    Ok(())
}

fn field<'a>(entries: &'a [(Value, Value)], name: &str) -> Result<&'a Value, CredentialV2Error> {
    let mut matches = entries
        .iter()
        .filter_map(|(key, value)| (key.as_text() == Some(name)).then_some(value));
    let value = matches.next().ok_or(CredentialV2Error::Schema)?;
    if matches.next().is_some() {
        return Err(CredentialV2Error::DuplicateKey);
    }
    Ok(value)
}

fn fixed_field<const N: usize>(
    entries: &[(Value, Value)],
    name: &str,
) -> Result<[u8; N], CredentialV2Error> {
    field(entries, name)?
        .as_bytes()
        .ok_or(CredentialV2Error::Schema)?
        .as_slice()
        .try_into()
        .map_err(|_| CredentialV2Error::Schema)
}

fn bytes_field<'a>(
    entries: &'a [(Value, Value)],
    name: &str,
) -> Result<&'a [u8], CredentialV2Error> {
    field(entries, name)?
        .as_bytes()
        .map(Vec::as_slice)
        .ok_or(CredentialV2Error::Schema)
}

fn text_field<'a>(entries: &'a [(Value, Value)], name: &str) -> Result<&'a str, CredentialV2Error> {
    field(entries, name)?
        .as_text()
        .ok_or(CredentialV2Error::Schema)
}

fn expect_fixed<const N: usize>(
    entries: &[(Value, Value)],
    name: &str,
    expected: &[u8; N],
) -> Result<(), CredentialV2Error> {
    if &fixed_field::<N>(entries, name)? != expected {
        return Err(CredentialV2Error::Profile);
    }
    Ok(())
}

fn expect_text(
    entries: &[(Value, Value)],
    name: &str,
    expected: &str,
) -> Result<(), CredentialV2Error> {
    if text_field(entries, name)? != expected {
        return Err(CredentialV2Error::Profile);
    }
    Ok(())
}

fn valid_compact_jws(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
}

fn lock(
    shared: &SharedAuthority,
) -> Result<MutexGuard<'_, Option<BoundBodyAuthority>>, CredentialV2Error> {
    shared.lock().map_err(|_| CredentialV2Error::Terminal)
}
