//! Closed Selfsame logical bodies carried by credential/v2 objects.

use super::{
    migration_confirmation_digest_parts, recognise_authority_status_response,
    CredentialV2AuthorityStatus, RecognisedCredentialV2Offer,
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
    let shared = Arc::new(Mutex::new(None));
    (
        CredentialV2BodyAuthority {
            shared: Arc::clone(&shared),
        },
        SelfsameCredentialV2BodyVerifier { shared },
    )
}

impl CredentialV2BodyAuthority {
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
            CredentialV2Kind::Offer | CredentialV2Kind::Receipt => Err(CredentialV2Error::Schema),
        }
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
