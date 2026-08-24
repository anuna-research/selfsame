//! Selfsame's closed credential/v2 signed-offer authority.

mod bodies;

pub use bodies::{
    credential_v2_body_authority, CredentialV2BodyAuthority, CredentialV2FinalDecision,
    CredentialV2IntentDecision, CredentialV2PayloadInput, CredentialV2RefusalReason,
    CredentialV2RetainedPayload, CredentialV2RetainedPreview, SelfsameCredentialV2BodyVerifier,
};

use cbcl_pairing::credential_v2::{
    credential_v2_intent_digest, CredentialV2AccountProvenance, CredentialV2Advance,
    CredentialV2Carrier, CredentialV2ClaimantOfferVerifier, CredentialV2DeviceBinding,
    CredentialV2Endpoint, CredentialV2Error, CredentialV2IntentAuthority, CredentialV2IntentClaims,
    CredentialV2IntentInput, CredentialV2IntentVerifier, CredentialV2Object,
    CredentialV2OfferParser, CredentialV2TofuState, CredentialV2Transition,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use ciborium::Value;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use selfsame_app_identity::{
    codec, didkey,
    json::{self, Json, Limits},
    profile::{ApplicationId, ApplicationProfile, CbclRelayDescriptor},
};
use sha2::{Digest, Sha256};

const SIGNED_OFFER_DOMAIN: &str = "selfsame credential/v2 signed offer v1";
const OFFER_SIGNATURE_DOMAIN: &[u8] = b"selfsame credential/v2 offer signature\0";
const DEVICE_POSSESSION_DOMAIN: &[u8] = b"cbcl-chat credential/v2 device possession proof v1\0";
const AUTHORITY_STATUS_DOMAIN: &str = "cbcl-chat credential/v2 authority status v1";
const AUTHORITY_SIGNATURE_DOMAIN: &[u8] =
    b"cbcl-chat credential/v2 authority status signature v1\0";
const ACCOUNT_PRINCIPAL_DOMAIN: &str = "selfsame-application-account-principal/v1";
const LEGACY_KEY_DOMAIN: &[u8] = b"cbcl-chat credential/v2 legacy key v1\0";
const ROOM_SET_DOMAIN: &[u8] = b"cbcl-chat credential/v2 room set v1\0";
const SNAPSHOT_DOMAIN: &[u8] = b"cbcl-chat credential/v2 migration snapshot v1\0";
const BROWSER_STAGING_DOMAIN: &str =
    "cbcl-chat credential/v2 browser staging receipt v1";
const BROWSER_STAGING_SIGNATURE_DOMAIN: &[u8] =
    b"cbcl-chat credential/v2 browser staging receipt signature v1\0";
const MAX_OFFER_CORE_BYTES: usize = 56_000;
const MAX_SIGNED_OFFER_BYTES: usize = 56_640;
const MAX_BROWSER_STAGING_RECEIPT_BYTES: usize = 4_608;
const FINAL_STATUS_TYPE: &str = "selfsame-pairing-final-status+jws";
const MAX_FINAL_STATUS_CORE_BYTES: usize = 4_096;
const MAX_FINAL_STATUS_JWS_BYTES: usize = 8_192;
const MAX_JSON_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Provenance of one captured Path-A room membership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialV2RoomProvenance {
    /// Standing membership.
    Standing,
    /// Redeemed invitation membership.
    Invite,
}

/// One exact hub snapshot row used by the migration digest graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialV2RoomSnapshot {
    /// Raw Mnesia primary key bytes.
    pub raw_primary_key: Vec<u8>,
    /// Canonical room text.
    pub room: String,
    /// Exact legacy handle.
    pub legacy_handle: String,
    /// Raw enrolled Ed25519 key.
    pub enrolled_key: [u8; 32],
    /// Non-negative grant timestamp.
    pub granted: u64,
    /// Standing or invitation provenance.
    pub provenance: CredentialV2RoomProvenance,
    /// Optional non-negative membership sequence.
    pub since: Option<u64>,
}

/// Hub-owned inputs for one proof-free signed offer.
pub struct CredentialV2OfferBuildInput {
    /// Exact request identifier from authenticated allocation.
    pub request_id: [u8; 32],
    /// Finished transcript hash.
    pub transcript_hash: [u8; 64],
    /// Hub-private random account identifier.
    pub application_account_id: [u8; 32],
    /// Pending account scope.
    pub account_scope_id: [u8; 32],
    /// Installation Ed25519 public key.
    pub device_public_key: [u8; 32],
    /// Exact canonical requested permissions.
    pub requested_permissions: Vec<String>,
    /// Browser intent nonce.
    pub intent_nonce: [u8; 32],
    /// Whole-UTC issue time.
    pub issued_at: u64,
    /// Exclusive pending deadline.
    pub expires_at: u64,
    /// Exact Path-A handle.
    pub legacy_handle: String,
    /// Raw currently enrolled Path-A key.
    pub enrolled_key: [u8; 32],
    /// Complete sorted migration-room snapshot.
    pub snapshot_rows: Vec<CredentialV2RoomSnapshot>,
    /// Fresh snapshot nonce.
    pub snapshot_nonce: [u8; 32],
}

/// Complete producer result retained by the hub.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedCredentialV2Offer {
    /// Exact RFC-8785 OfferCoreV2 bytes.
    pub offer_core: Vec<u8>,
    /// SHA-256 of the exact core.
    pub offer_core_digest: [u8; 32],
    /// Shared endpoint intent digest.
    pub intent_digest: [u8; 32],
    /// Stable account-principal digest.
    pub account_principal_digest: [u8; 32],
    /// Installation did:key.
    pub device_did: String,
    /// Digest of the exact canonical installation JWK.
    pub device_key_digest: [u8; 32],
    /// Legacy enrolled-key digest.
    pub legacy_key_digest: [u8; 32],
    /// Canonical room-set digest.
    pub room_set_digest: [u8; 32],
    /// Complete migration-snapshot digest.
    pub migration_snapshot_digest: [u8; 32],
}

/// An offer core whose exact installation-device possession proof passed.
///
/// Its private field prevents a caller from reaching the signing operation by
/// merely asserting that it performed the proof check elsewhere.
pub struct VerifiedPreparedCredentialV2Offer {
    prepared: PreparedCredentialV2Offer,
}

/// Complete signed producer result retained by the hub.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltCredentialV2Offer {
    /// Exact RFC-8785 OfferCoreV2 bytes.
    pub offer_core: Vec<u8>,
    /// SHA-256 of the exact core.
    pub offer_core_digest: [u8; 32],
    /// Shared endpoint intent digest.
    pub intent_digest: [u8; 32],
    /// Exact deterministic-CBOR signed offer.
    pub signed_offer: Vec<u8>,
    /// Signing-key identifier retained for final status.
    pub kid: String,
    /// Stable account-principal digest.
    pub account_principal_digest: [u8; 32],
    /// Installation did:key.
    pub device_did: String,
    /// Digest of the exact canonical installation JWK.
    pub device_key_digest: [u8; 32],
    /// Legacy enrolled-key digest.
    pub legacy_key_digest: [u8; 32],
    /// Canonical room-set digest.
    pub room_set_digest: [u8; 32],
    /// Complete migration-snapshot digest.
    pub migration_snapshot_digest: [u8; 32],
}

/// Signed reciprocal-alias authority returned before the offer is released.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltCredentialV2AuthorityStatus {
    /// Exact deterministic-CBOR six-member response.
    pub response: Vec<u8>,
    /// SHA-256 of the complete response including its signature.
    pub digest: [u8; 32],
    /// Signing key identifier shared with the signed offer.
    pub kid: String,
}

/// Exact authenticated facts signed by a browser before hub finalisation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialV2BrowserStagingInput {
    /// Canonical application identifier.
    pub application_id: String,
    /// Sole credential/v2 carrier ceremony identifier.
    pub carrier_ceremony_id: [u8; 32],
    /// Stable application-account principal digest.
    pub account_principal_digest: [u8; 32],
    /// Application-account scope identifier.
    pub account_scope_id: [u8; 32],
    /// Installation device DID bound by the signed offer.
    pub device_did: String,
    /// Digest of the exact signed offer core.
    pub offer_core_digest: [u8; 32],
    /// Digest of the authenticated reverse payload object.
    pub payload_digest: [u8; 32],
    /// Identifier of the delivered account grant.
    pub grant_id: [u8; 32],
    /// Canonical account issuer DID verified from resolver closure.
    pub issuer_did: String,
    /// Digest of the independently authenticated application profile.
    pub profile_digest: [u8; 32],
    /// Public commitment to the Rust-confined recovery token.
    pub receipt_recovery_commitment: [u8; 32],
}

/// Exact accepted facts committed by the hub's immutable final status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialV2FinalStatusInput {
    /// Canonical application identifier.
    pub application_id: String,
    /// Sole carrier ceremony identifier.
    pub carrier_ceremony_id: [u8; 32],
    /// Original browser request identifier.
    pub request_id: [u8; 32],
    /// Stable account-principal digest.
    pub account_principal_digest: [u8; 32],
    /// Stable application-account scope.
    pub account_scope_id: [u8; 32],
    /// Installation device DID.
    pub device_did: String,
    /// Digest of the exact signed offer core.
    pub offer_core_digest: [u8; 32],
    /// Digest of the authenticated reverse payload.
    pub payload_digest: [u8; 32],
    /// Raw account-grant identifier.
    pub grant_id: [u8; 32],
    /// Canonical account issuer DID.
    pub issuer_did: String,
    /// Commitment to the endpoint-confined recovery token.
    pub receipt_recovery_commitment: [u8; 32],
    /// Whole UTC second at the atomic finalization point.
    pub finalized_at: u64,
}

/// Exact immutable final-status bytes retained by hub, browser, and wallet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltCredentialV2FinalStatus {
    /// Canonical RFC-8785 final-status core.
    pub core: Vec<u8>,
    /// Compact EdDSA JWS whose payload is the exact core.
    pub jws: String,
    /// Raw SHA-256 of the exact core.
    pub digest: [u8; 32],
    /// Profile key identifier used by offer and status.
    pub kid: String,
}

/// Closed reciprocal-alias state authenticated by the hub response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialV2AuthorityStatus {
    /// The stable application account has no reciprocal alias binding.
    NoBinding,
    /// A pre-existing reciprocal alias binds the stable account to this DID.
    Bound(String),
}

/// Completely recognised signed offer and typed display claims.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecognisedCredentialV2Offer {
    /// Exact signed offer bytes.
    pub signed_offer: Vec<u8>,
    /// Exact core bytes.
    pub offer_core: Vec<u8>,
    /// Signing key identifier.
    pub kid: String,
    /// Typed claims consumable by cbcl-pairing display authority.
    pub claims: CredentialV2IntentClaims,
    /// Exact request identifier.
    pub request_id: [u8; 32],
    /// Peer-bound profile digest.
    pub profile_digest: [u8; 32],
    /// Selected complete relay-descriptor digest.
    pub descriptor_digest: [u8; 32],
    /// Digest of the exact protected carrier.
    pub carrier_digest: [u8; 32],
    /// One-use intent nonce allocated for this attempt.
    pub intent_nonce: [u8; 32],
    /// Finished transcript hash.
    pub transcript_hash: [u8; 64],
    /// Exclusive offer expiry.
    pub expires_at: u64,
}

/// Closed signed-offer refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CredentialV2OfferError {
    /// One input was outside the closed grammar or did not match authority.
    #[error("credential/v2 offer was refused")]
    Refused,
}

/// Wallet-side authenticated-display adapter for the allocator's first offer.
///
/// The peer object is not display authority. This adapter first verifies the
/// signed offer under the independently fetched profile, checks every local
/// carrier/transcript binding, and only then supplies cbcl-pairing's separate
/// authority input.
#[derive(Debug)]
pub struct CredentialV2WalletOfferVerifier {
    profile: ApplicationProfile,
    carrier: CredentialV2Carrier,
    transcript_hash: [u8; 64],
    tofu_state: CredentialV2TofuState,
    body_authority: Option<CredentialV2BodyAuthority>,
}

impl CredentialV2WalletOfferVerifier {
    /// Bind one verifier to the exact live profile, carrier, transcript, and
    /// person-owned exact-pair policy state.
    pub fn new(
        profile: ApplicationProfile,
        carrier: CredentialV2Carrier,
        transcript_hash: [u8; 64],
        tofu_state: CredentialV2TofuState,
    ) -> Result<Self, CredentialV2OfferError> {
        let _ = selected_descriptor(&profile, &carrier)?;
        Ok(Self {
            profile,
            carrier,
            transcript_hash,
            tofu_state,
            body_authority: None,
        })
    }

    /// Bind the closed successor grammar only after this verifier accepts the
    /// signed offer and every independent carrier/profile comparison.
    #[must_use]
    pub fn with_body_authority(mut self, authority: CredentialV2BodyAuthority) -> Self {
        self.body_authority = Some(authority);
        self
    }
}

impl CredentialV2ClaimantOfferVerifier for CredentialV2WalletOfferVerifier {
    fn verify_offer(
        &mut self,
        endpoint: &mut CredentialV2Endpoint,
        object: &CredentialV2Object,
        now: u64,
    ) -> Result<CredentialV2Advance, CredentialV2Error> {
        let recognised = recognise_signed_offer(&self.profile, object.body())
            .map_err(|_| CredentialV2Error::Profile)?;
        let descriptor = selected_descriptor(&self.profile, &self.carrier)
            .map_err(|_| CredentialV2Error::Profile)?;
        let allocator_key = didkey::decode(recognised.claims.device_binding().device_did())
            .map_err(|_| CredentialV2Error::Profile)?;
        if recognised.profile_digest != *self.profile.digest()
            || recognised.descriptor_digest != descriptor.digest
            || recognised.carrier_digest != self.carrier.digest()
            || recognised.transcript_hash != self.transcript_hash
            || recognised.expires_at <= now
            || recognised.claims.application_id() != self.carrier.application_context()
            || recognised.claims.relay_origin() != self.carrier.relay_origin()
            || recognised.claims.carrier_ceremony_id() != self.carrier.carrier_ceremony_id()
            || self.carrier.expected_allocator_key() != Some(&allocator_key)
        {
            return Err(CredentialV2Error::Profile);
        }
        let authority =
            CredentialV2IntentAuthority::new(recognised.claims.clone(), self.tofu_state)?;
        let mut parser = AuthenticatedOfferParser {
            exact_body: recognised.signed_offer.clone(),
            claims: recognised.claims.clone(),
        };
        let mut verifier = AuthenticatedOfferVerdict;
        let advance = endpoint.receive_offer(object, &authority, &mut parser, &mut verifier)?;
        if let Some(body_authority) = &self.body_authority {
            body_authority.bind_offer(self.profile.clone(), &recognised)?;
        }
        Ok(advance)
    }
}

#[derive(Debug)]
struct AuthenticatedOfferParser {
    exact_body: Vec<u8>,
    claims: CredentialV2IntentClaims,
}

impl CredentialV2OfferParser for AuthenticatedOfferParser {
    fn parse_signed_offer(
        &mut self,
        body: &[u8],
    ) -> Result<CredentialV2IntentClaims, CredentialV2Error> {
        if body != self.exact_body {
            return Err(CredentialV2Error::Profile);
        }
        Ok(self.claims.clone())
    }
}

#[derive(Debug)]
struct AuthenticatedOfferVerdict;

impl CredentialV2IntentVerifier for AuthenticatedOfferVerdict {
    fn verify(
        &mut self,
        peer: &CredentialV2IntentInput,
        authority: &CredentialV2IntentAuthority,
    ) -> Result<(), CredentialV2Error> {
        if peer.application_id() != authority.application_id()
            || peer.https_origin() != authority.https_origin()
            || peer.relay_origin() != authority.relay_origin()
            || peer.carrier_ceremony_id() != authority.carrier_ceremony_id()
        {
            return Err(CredentialV2Error::Profile);
        }
        Ok(())
    }
}

/// Build one proof-free core from locked hub facts without touching a signing key.
pub fn prepare_offer_core(
    profile: &ApplicationProfile,
    carrier: &CredentialV2Carrier,
    input: &CredentialV2OfferBuildInput,
) -> Result<PreparedCredentialV2Offer, CredentialV2OfferError> {
    let descriptor = selected_descriptor(profile, carrier)?;
    if carrier.expected_allocator_key() != Some(&input.device_public_key)
        || input.expires_at <= input.issued_at
        || !(300..=600).contains(&(input.expires_at - input.issued_at))
    {
        return Err(CredentialV2OfferError::Refused);
    }
    recognise_permissions(profile, &input.requested_permissions)?;
    let rooms = validate_snapshot(input)?;
    let legacy_key_digest = labelled_hash(LEGACY_KEY_DOMAIN, &input.enrolled_key);
    let room_set_digest = room_set_digest(&rooms)?;
    let migration_snapshot_digest = migration_snapshot_digest(input)?;
    let transition = transition_json(
        &input.legacy_handle,
        legacy_key_digest,
        &rooms,
        room_set_digest,
        migration_snapshot_digest,
        input.snapshot_nonce,
    );
    let account_principal_digest = account_principal_digest(
        profile.application_id.as_str(),
        input.application_account_id,
    )?;
    let device_did = didkey::encode(&input.device_public_key);
    let device_jwk = device_jwk(input.device_public_key);
    let device_jwk_bytes = json::canonicalise(&device_jwk);
    let device_key_digest = Sha256::digest(&device_jwk_bytes).into();
    let core = Json::obj([
        ("payloadVersion", Json::int(2)),
        ("role", Json::text("offer")),
        (
            "carrierCeremonyId",
            Json::text(codec::b64url(carrier.carrier_ceremony_id())),
        ),
        ("requestId", Json::text(codec::b64url(&input.request_id))),
        ("applicationId", Json::text(profile.application_id.as_str())),
        ("profileVersion", Json::int(2)),
        ("profileDigest", Json::text(codec::b64url(profile.digest()))),
        (
            "descriptorDigest",
            Json::text(codec::b64url(&descriptor.digest)),
        ),
        ("relayOrigin", Json::text(&descriptor.relay_origin)),
        (
            "carrierDigest",
            Json::text(codec::b64url(&carrier.digest())),
        ),
        (
            "transcriptHash",
            Json::text(codec::b64url(&input.transcript_hash)),
        ),
        (
            "accountPrincipalDigest",
            Json::text(codec::b64url(&account_principal_digest)),
        ),
        (
            "accountScopeId",
            Json::text(codec::b64url(&input.account_scope_id)),
        ),
        ("deviceDid", Json::text(&device_did)),
        ("deviceKeyJwk", device_jwk),
        (
            "requestedPermissions",
            Json::Array(input.requested_permissions.iter().map(Json::text).collect()),
        ),
        (
            "intentNonce",
            Json::text(codec::b64url(&input.intent_nonce)),
        ),
        (
            "issuedAt",
            Json::int(i64::try_from(input.issued_at).map_err(|_| CredentialV2OfferError::Refused)?),
        ),
        (
            "expiresAt",
            Json::int(
                i64::try_from(input.expires_at).map_err(|_| CredentialV2OfferError::Refused)?,
            ),
        ),
        ("accountTransition", transition),
    ]);
    let offer_core = json::canonicalise(&core);
    if offer_core.is_empty() || offer_core.len() > MAX_OFFER_CORE_BYTES {
        return Err(CredentialV2OfferError::Refused);
    }
    let offer_core_digest: [u8; 32] = Sha256::digest(&offer_core).into();
    Ok(PreparedCredentialV2Offer {
        offer_core,
        offer_core_digest,
        intent_digest: credential_v2_intent_digest(offer_core_digest),
        account_principal_digest,
        device_did,
        device_key_digest,
        legacy_key_digest,
        room_set_digest,
        migration_snapshot_digest,
    })
}

/// Sign a previously prepared core only after the hub verifies device possession.
fn sign_verified_offer(
    profile: &ApplicationProfile,
    prepared: &PreparedCredentialV2Offer,
    kid: &str,
    signing_key: &SigningKey,
) -> Result<BuiltCredentialV2Offer, CredentialV2OfferError> {
    signing_key_declared(profile, kid, signing_key)?;
    if recognise_prepared_offer(profile, &prepared.offer_core)? != *prepared {
        return Err(CredentialV2OfferError::Refused);
    }
    let signature =
        signing_key.sign(&[OFFER_SIGNATURE_DOMAIN, &prepared.offer_core_digest].concat());
    let signed_offer = cbor2::to_canonical_vec(&Value::Array(vec![
        Value::Text(SIGNED_OFFER_DOMAIN.into()),
        Value::Bytes(prepared.offer_core.clone()),
        Value::Text(kid.into()),
        Value::Bytes(signature.to_bytes().to_vec()),
    ]))
    .map_err(|_| CredentialV2OfferError::Refused)?;
    if signed_offer.len() > MAX_SIGNED_OFFER_BYTES {
        return Err(CredentialV2OfferError::Refused);
    }
    Ok(BuiltCredentialV2Offer {
        offer_core: prepared.offer_core.clone(),
        offer_core_digest: prepared.offer_core_digest,
        intent_digest: prepared.intent_digest,
        signed_offer,
        kid: kid.into(),
        account_principal_digest: prepared.account_principal_digest,
        device_did: prepared.device_did.clone(),
        device_key_digest: prepared.device_key_digest,
        legacy_key_digest: prepared.legacy_key_digest,
        room_set_digest: prepared.room_set_digest,
        migration_snapshot_digest: prepared.migration_snapshot_digest,
    })
}

/// Verify the exact socket-, ceremony-, offer-, and installation-key-bound
/// possession proof before a signing key is needed by the caller.
pub fn verify_prepared_offer_device_proof(
    profile: &ApplicationProfile,
    prepared: &PreparedCredentialV2Offer,
    socket_generation_digest: [u8; 32],
    carrier_ceremony_id: [u8; 32],
    device_public_key: [u8; 32],
    device_possession_proof: [u8; 64],
) -> Result<VerifiedPreparedCredentialV2Offer, CredentialV2OfferError> {
    let recognised = recognise_offer_core(profile, &prepared.offer_core)?;
    let expected_device_key_digest: [u8; 32] =
        Sha256::digest(json::canonicalise(&device_jwk(device_public_key))).into();
    if recognise_prepared_offer(profile, &prepared.offer_core)? != *prepared
        || recognised.claims.carrier_ceremony_id() != &carrier_ceremony_id
        || recognised.claims.device_binding().device_did() != didkey::encode(&device_public_key)
        || recognised.claims.device_binding().device_key_digest() != &expected_device_key_digest
    {
        return Err(CredentialV2OfferError::Refused);
    }
    let proof_input = device_possession_proof_input(
        socket_generation_digest,
        carrier_ceremony_id,
        prepared.offer_core_digest,
    )?;
    VerifyingKey::from_bytes(&device_public_key)
        .map_err(|_| CredentialV2OfferError::Refused)?
        .verify(
            &proof_input,
            &Signature::from_bytes(&device_possession_proof),
        )
        .map_err(|_| CredentialV2OfferError::Refused)?;
    Ok(VerifiedPreparedCredentialV2Offer {
        prepared: prepared.clone(),
    })
}

/// Sign only a value returned by [`verify_prepared_offer_device_proof`].
pub fn finalize_verified_offer(
    profile: &ApplicationProfile,
    verified: &VerifiedPreparedCredentialV2Offer,
    kid: &str,
    signing_key: &SigningKey,
) -> Result<BuiltCredentialV2Offer, CredentialV2OfferError> {
    sign_verified_offer(profile, &verified.prepared, kid, signing_key)
}

/// Compute the exact 32-octet installation-device possession proof input.
pub fn device_possession_proof_input(
    socket_generation_digest: [u8; 32],
    carrier_ceremony_id: [u8; 32],
    offer_core_digest: [u8; 32],
) -> Result<[u8; 32], CredentialV2OfferError> {
    let body = cbor2::to_canonical_vec(&Value::Array(vec![
        Value::Bytes(socket_generation_digest.to_vec()),
        Value::Bytes(carrier_ceremony_id.to_vec()),
        Value::Bytes(offer_core_digest.to_vec()),
    ]))
    .map_err(|_| CredentialV2OfferError::Refused)?;
    Ok(labelled_hash(DEVICE_POSSESSION_DOMAIN, &body))
}

/// Compute the exact 32-octet installation-device signing input for one
/// browser-local inactive stage.
pub fn browser_staging_signature_input(
    input: &CredentialV2BrowserStagingInput,
) -> Result<[u8; 32], CredentialV2OfferError> {
    let unsigned = cbor2::to_canonical_vec(&Value::Array(browser_staging_members(input)?))
        .map_err(|_| CredentialV2OfferError::Refused)?;
    Ok(labelled_hash(BROWSER_STAGING_SIGNATURE_DOMAIN, &unsigned))
}

/// Verify the installation-device signature and construct the one canonical
/// browser staging receipt accepted by the hub.
pub fn build_browser_staging_receipt(
    input: &CredentialV2BrowserStagingInput,
    device_public_key: [u8; 32],
    signature: [u8; 64],
) -> Result<Vec<u8>, CredentialV2OfferError> {
    didkey::matches_jwk(&input.device_did, &device_public_key)
        .map_err(|_| CredentialV2OfferError::Refused)?;
    VerifyingKey::from_bytes(&device_public_key)
        .map_err(|_| CredentialV2OfferError::Refused)?
        .verify(
            &browser_staging_signature_input(input)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| CredentialV2OfferError::Refused)?;
    let mut members = browser_staging_members(input)?;
    members.push(Value::Bytes(signature.to_vec()));
    let receipt = cbor2::to_canonical_vec(&Value::Array(members))
        .map_err(|_| CredentialV2OfferError::Refused)?;
    if receipt.is_empty() || receipt.len() > MAX_BROWSER_STAGING_RECEIPT_BYTES {
        return Err(CredentialV2OfferError::Refused);
    }
    Ok(receipt)
}

/// Recognise one complete canonical staging receipt, require every expected
/// held fact, and verify its installation-device signature.
pub fn recognise_browser_staging_receipt(
    receipt: &[u8],
    expected: &CredentialV2BrowserStagingInput,
    device_public_key: [u8; 32],
) -> Result<(), CredentialV2OfferError> {
    if receipt.is_empty() || receipt.len() > MAX_BROWSER_STAGING_RECEIPT_BYTES {
        return Err(CredentialV2OfferError::Refused);
    }
    let mut cursor = std::io::Cursor::new(receipt);
    let value: Value =
        ciborium::de::from_reader(&mut cursor).map_err(|_| CredentialV2OfferError::Refused)?;
    if cursor.position() != receipt.len() as u64
        || cbor2::to_canonical_vec(&value).map_err(|_| CredentialV2OfferError::Refused)? != receipt
    {
        return Err(CredentialV2OfferError::Refused);
    }
    let members = value.as_array().ok_or(CredentialV2OfferError::Refused)?;
    let [domain, application_id, ceremony, principal, scope, device_did, offer, payload, grant, issuer, profile, commitment, signature] =
        members.as_slice()
    else {
        return Err(CredentialV2OfferError::Refused);
    };
    if domain.as_text() != Some(BROWSER_STAGING_DOMAIN) {
        return Err(CredentialV2OfferError::Refused);
    }
    let parsed = CredentialV2BrowserStagingInput {
        application_id: cbor_text(application_id)?.into(),
        carrier_ceremony_id: cbor_fixed(ceremony)?,
        account_principal_digest: cbor_fixed(principal)?,
        account_scope_id: cbor_fixed(scope)?,
        device_did: cbor_text(device_did)?.into(),
        offer_core_digest: cbor_fixed(offer)?,
        payload_digest: cbor_fixed(payload)?,
        grant_id: cbor_fixed(grant)?,
        issuer_did: cbor_text(issuer)?.into(),
        profile_digest: cbor_fixed(profile)?,
        receipt_recovery_commitment: cbor_fixed(commitment)?,
    };
    let signature: [u8; 64] = cbor_fixed(signature)?;
    if &parsed != expected
        || build_browser_staging_receipt(&parsed, device_public_key, signature)? != receipt
    {
        return Err(CredentialV2OfferError::Refused);
    }
    Ok(())
}

fn browser_staging_members(
    input: &CredentialV2BrowserStagingInput,
) -> Result<Vec<Value>, CredentialV2OfferError> {
    let application_id = ApplicationId::parse(&input.application_id)
        .map_err(|_| CredentialV2OfferError::Refused)?;
    if application_id.as_str() != input.application_id
        || input.application_id.len() > 2_048
        || input.device_did.len() != 56
        || didkey::decode(&input.device_did).is_err()
        || !valid_bound_did(&input.issuer_did)
    {
        return Err(CredentialV2OfferError::Refused);
    }
    Ok(vec![
        Value::Text(BROWSER_STAGING_DOMAIN.into()),
        Value::Text(input.application_id.clone()),
        Value::Bytes(input.carrier_ceremony_id.to_vec()),
        Value::Bytes(input.account_principal_digest.to_vec()),
        Value::Bytes(input.account_scope_id.to_vec()),
        Value::Text(input.device_did.clone()),
        Value::Bytes(input.offer_core_digest.to_vec()),
        Value::Bytes(input.payload_digest.to_vec()),
        Value::Bytes(input.grant_id.to_vec()),
        Value::Text(input.issuer_did.clone()),
        Value::Bytes(input.profile_digest.to_vec()),
        Value::Bytes(input.receipt_recovery_commitment.to_vec()),
    ])
}

fn cbor_text(value: &Value) -> Result<&str, CredentialV2OfferError> {
    value.as_text().ok_or(CredentialV2OfferError::Refused)
}

fn cbor_fixed<const N: usize>(value: &Value) -> Result<[u8; N], CredentialV2OfferError> {
    value
        .as_bytes()
        .ok_or(CredentialV2OfferError::Refused)?
        .as_slice()
        .try_into()
        .map_err(|_| CredentialV2OfferError::Refused)
}

/// Build and sign the one immutable final status accepted by browser and wallet.
pub fn build_final_status(
    profile: &ApplicationProfile,
    input: &CredentialV2FinalStatusInput,
    kid: &str,
    signing_key: &SigningKey,
) -> Result<BuiltCredentialV2FinalStatus, CredentialV2OfferError> {
    signing_key_declared(profile, kid, signing_key)?;
    let core = final_status_core(profile, input)?;
    let protected = json::canonicalise(&Json::obj([
        ("alg", Json::text("EdDSA")),
        ("kid", Json::text(kid)),
        ("typ", Json::text(FINAL_STATUS_TYPE)),
    ]));
    let encoded_header = codec::b64url(&protected);
    let encoded_payload = codec::b64url(&core);
    let signing_input = format!("{encoded_header}.{encoded_payload}");
    let signature = signing_key.sign(signing_input.as_bytes());
    let jws = format!("{signing_input}.{}", codec::b64url(&signature.to_bytes()));
    if jws.len() > MAX_FINAL_STATUS_JWS_BYTES {
        return Err(CredentialV2OfferError::Refused);
    }
    Ok(BuiltCredentialV2FinalStatus {
        digest: Sha256::digest(&core).into(),
        core,
        jws,
        kid: kid.into(),
    })
}

/// Verify one immutable final-status JWS and every retained accepted fact.
pub fn recognise_final_status(
    profile: &ApplicationProfile,
    jws: &str,
    expected_digest: [u8; 32],
    expected: &CredentialV2FinalStatusInput,
    expected_kid: &str,
) -> Result<(), CredentialV2OfferError> {
    if jws.is_empty() || jws.len() > MAX_FINAL_STATUS_JWS_BYTES || !jws.is_ascii() {
        return Err(CredentialV2OfferError::Refused);
    }
    let mut segments = jws.split('.');
    let (Some(encoded_header), Some(encoded_payload), Some(encoded_signature), None) =
        (segments.next(), segments.next(), segments.next(), segments.next())
    else {
        return Err(CredentialV2OfferError::Refused);
    };
    if encoded_header.is_empty() || encoded_payload.is_empty() || encoded_signature.is_empty() {
        return Err(CredentialV2OfferError::Refused);
    }
    let protected = decode_canonical_b64(encoded_header)?;
    let core = decode_canonical_b64(encoded_payload)?;
    let signature: [u8; 64] = decode_canonical_b64(encoded_signature)?
        .try_into()
        .map_err(|_| CredentialV2OfferError::Refused)?;
    let header = json::recognise(
        &protected,
        Limits {
            max_bytes: 1_024,
            max_depth: 1,
        },
    )
    .map_err(|_| CredentialV2OfferError::Refused)?;
    const HEADER_MEMBERS: [&str; 3] = ["alg", "kid", "typ"];
    if json::canonicalise(&header) != protected
        || header.member_names() != HEADER_MEMBERS
        || text(&header, "alg")? != "EdDSA"
        || text(&header, "kid")? != expected_kid
        || text(&header, "typ")? != FINAL_STATUS_TYPE
        || Sha256::digest(&core).as_slice() != expected_digest
        || core != final_status_core(profile, expected)?
    {
        return Err(CredentialV2OfferError::Refused);
    }
    let declared = profile
        .enrollment_keys
        .iter()
        .find(|candidate| candidate.kid == expected_kid)
        .ok_or(CredentialV2OfferError::Refused)?;
    VerifyingKey::from_bytes(&declared.jwk.public_key)
        .map_err(|_| CredentialV2OfferError::Refused)?
        .verify(
            format!("{encoded_header}.{encoded_payload}").as_bytes(),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| CredentialV2OfferError::Refused)
}

fn final_status_core(
    profile: &ApplicationProfile,
    input: &CredentialV2FinalStatusInput,
) -> Result<Vec<u8>, CredentialV2OfferError> {
    let application_id = ApplicationId::parse(&input.application_id)
        .map_err(|_| CredentialV2OfferError::Refused)?;
    if application_id.as_str() != input.application_id
        || profile.application_id.as_str() != input.application_id
        || input.application_id.len() > 2_048
        || input.device_did.len() != 56
        || didkey::decode(&input.device_did).is_err()
        || !valid_bound_did(&input.issuer_did)
        || input.finalized_at > MAX_JSON_SAFE_INTEGER
    {
        return Err(CredentialV2OfferError::Refused);
    }
    let core = json::canonicalise(&Json::obj([
        ("payloadVersion", Json::int(2)),
        ("role", Json::text("final-status")),
        ("applicationId", Json::text(&input.application_id)),
        (
            "carrierCeremonyId",
            Json::text(codec::b64url(&input.carrier_ceremony_id)),
        ),
        ("requestId", Json::text(codec::b64url(&input.request_id))),
        (
            "accountPrincipalDigest",
            Json::text(codec::b64url(&input.account_principal_digest)),
        ),
        (
            "accountScopeId",
            Json::text(codec::b64url(&input.account_scope_id)),
        ),
        ("deviceDid", Json::text(&input.device_did)),
        (
            "offerCoreDigest",
            Json::text(codec::b64url(&input.offer_core_digest)),
        ),
        (
            "payloadDigest",
            Json::text(codec::b64url(&input.payload_digest)),
        ),
        ("grantId", Json::text(codec::b64url(&input.grant_id))),
        ("issuerDid", Json::text(&input.issuer_did)),
        (
            "receiptRecoveryCommitment",
            Json::text(codec::b64url(&input.receipt_recovery_commitment)),
        ),
        ("status", Json::text("accepted")),
        (
            "finalizedAt",
            Json::int(
                i64::try_from(input.finalized_at)
                    .map_err(|_| CredentialV2OfferError::Refused)?,
            ),
        ),
    ]));
    if core.is_empty() || core.len() > MAX_FINAL_STATUS_CORE_BYTES {
        return Err(CredentialV2OfferError::Refused);
    }
    Ok(core)
}

fn decode_canonical_b64(value: &str) -> Result<Vec<u8>, CredentialV2OfferError> {
    let decoded = Base64UrlUnpadded::decode_vec(value)
        .map_err(|_| CredentialV2OfferError::Refused)?;
    if codec::b64url(&decoded) != value {
        return Err(CredentialV2OfferError::Refused);
    }
    Ok(decoded)
}

/// Build and sign one exact reciprocal-alias authority response.
pub fn build_authority_status_response(
    profile: &ApplicationProfile,
    carrier_ceremony_id: [u8; 32],
    offer_core_digest: [u8; 32],
    status: &CredentialV2AuthorityStatus,
    kid: &str,
    signing_key: &SigningKey,
) -> Result<BuiltCredentialV2AuthorityStatus, CredentialV2OfferError> {
    signing_key_declared(profile, kid, signing_key)?;
    let (status_text, bound_did) = match status {
        CredentialV2AuthorityStatus::NoBinding => ("no-binding", Value::Null),
        CredentialV2AuthorityStatus::Bound(did) if valid_bound_did(did) => {
            ("bound", Value::Text(did.clone()))
        }
        CredentialV2AuthorityStatus::Bound(_) => return Err(CredentialV2OfferError::Refused),
    };
    let unsigned = Value::Array(vec![
        Value::Text(AUTHORITY_STATUS_DOMAIN.into()),
        Value::Bytes(carrier_ceremony_id.to_vec()),
        Value::Bytes(offer_core_digest.to_vec()),
        Value::Text(status_text.into()),
        bound_did,
    ]);
    let unsigned_bytes =
        cbor2::to_canonical_vec(&unsigned).map_err(|_| CredentialV2OfferError::Refused)?;
    let signature = signing_key.sign(&labelled_hash(AUTHORITY_SIGNATURE_DOMAIN, &unsigned_bytes));
    let Value::Array(mut response_members) = unsigned else {
        unreachable!()
    };
    response_members.push(Value::Bytes(signature.to_bytes().to_vec()));
    let response = cbor2::to_canonical_vec(&Value::Array(response_members))
        .map_err(|_| CredentialV2OfferError::Refused)?;
    if response.is_empty() || response.len() > 768 {
        return Err(CredentialV2OfferError::Refused);
    }
    Ok(BuiltCredentialV2AuthorityStatus {
        digest: Sha256::digest(&response).into(),
        response,
        kid: kid.into(),
    })
}

/// Verify and recognise one exact authority response under the signed-offer key.
pub fn recognise_authority_status_response(
    profile: &ApplicationProfile,
    response: &[u8],
    kid: &str,
    expected_ceremony_id: [u8; 32],
    expected_offer_core_digest: [u8; 32],
) -> Result<CredentialV2AuthorityStatus, CredentialV2OfferError> {
    if response.is_empty() || response.len() > 768 {
        return Err(CredentialV2OfferError::Refused);
    }
    let mut cursor = std::io::Cursor::new(response);
    let value: Value =
        ciborium::de::from_reader(&mut cursor).map_err(|_| CredentialV2OfferError::Refused)?;
    if cursor.position() != response.len() as u64
        || cbor2::to_canonical_vec(&value).map_err(|_| CredentialV2OfferError::Refused)? != response
    {
        return Err(CredentialV2OfferError::Refused);
    }
    let members = value.as_array().ok_or(CredentialV2OfferError::Refused)?;
    let [domain, ceremony, offer_digest, status, did, signature] = members.as_slice() else {
        return Err(CredentialV2OfferError::Refused);
    };
    if domain.as_text() != Some(AUTHORITY_STATUS_DOMAIN)
        || ceremony.as_bytes().map(Vec::as_slice) != Some(expected_ceremony_id.as_slice())
        || offer_digest.as_bytes().map(Vec::as_slice) != Some(expected_offer_core_digest.as_slice())
    {
        return Err(CredentialV2OfferError::Refused);
    }
    let recognised = match (status.as_text(), did) {
        (Some("no-binding"), Value::Null) => CredentialV2AuthorityStatus::NoBinding,
        (Some("bound"), Value::Text(value)) if valid_bound_did(value) => {
            CredentialV2AuthorityStatus::Bound(value.clone())
        }
        _ => return Err(CredentialV2OfferError::Refused),
    };
    let signature: [u8; 64] = signature
        .as_bytes()
        .ok_or(CredentialV2OfferError::Refused)?
        .as_slice()
        .try_into()
        .map_err(|_| CredentialV2OfferError::Refused)?;
    let unsigned_bytes = cbor2::to_canonical_vec(&Value::Array(members[..5].to_vec()))
        .map_err(|_| CredentialV2OfferError::Refused)?;
    let declared = profile
        .enrollment_keys
        .iter()
        .find(|candidate| candidate.kid == kid)
        .ok_or(CredentialV2OfferError::Refused)?;
    VerifyingKey::from_bytes(&declared.jwk.public_key)
        .map_err(|_| CredentialV2OfferError::Refused)?
        .verify(
            &labelled_hash(AUTHORITY_SIGNATURE_DOMAIN, &unsigned_bytes),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| CredentialV2OfferError::Refused)?;
    Ok(recognised)
}

/// Re-recognise an unsigned core into the complete proof-free producer result.
///
/// This is the only bridge accepted by finalisation, so a caller cannot change
/// retained metadata while holding the signed bytes fixed.
pub fn recognise_prepared_offer(
    profile: &ApplicationProfile,
    offer_core: &[u8],
) -> Result<PreparedCredentialV2Offer, CredentialV2OfferError> {
    let recognised = recognise_offer_core(profile, offer_core)?;
    let transition = recognised
        .claims
        .transition()
        .as_path_a_to_b()
        .ok_or(CredentialV2OfferError::Refused)?;
    Ok(PreparedCredentialV2Offer {
        offer_core: offer_core.to_vec(),
        offer_core_digest: *recognised.claims.offer_core_digest(),
        intent_digest: credential_v2_intent_digest(*recognised.claims.offer_core_digest()),
        account_principal_digest: *recognised
            .claims
            .account_provenance()
            .account_principal_digest(),
        device_did: recognised.claims.device_binding().device_did().into(),
        device_key_digest: *recognised.claims.device_binding().device_key_digest(),
        legacy_key_digest: *transition.legacy_key_digest(),
        room_set_digest: *transition.room_set_digest(),
        migration_snapshot_digest: *transition.migration_snapshot_digest(),
    })
}

/// Recognise and verify one exact signed offer against the live profile.
pub fn recognise_signed_offer(
    profile: &ApplicationProfile,
    bytes: &[u8],
) -> Result<RecognisedCredentialV2Offer, CredentialV2OfferError> {
    if bytes.is_empty() || bytes.len() > MAX_SIGNED_OFFER_BYTES {
        return Err(CredentialV2OfferError::Refused);
    }
    let mut cursor = std::io::Cursor::new(bytes);
    let value: Value =
        ciborium::de::from_reader(&mut cursor).map_err(|_| CredentialV2OfferError::Refused)?;
    if cursor.position() != bytes.len() as u64
        || cbor2::to_canonical_vec(&value).map_err(|_| CredentialV2OfferError::Refused)? != bytes
    {
        return Err(CredentialV2OfferError::Refused);
    }
    let [domain, core, kid, signature] = value
        .as_array()
        .ok_or(CredentialV2OfferError::Refused)?
        .as_slice()
    else {
        return Err(CredentialV2OfferError::Refused);
    };
    if domain.as_text() != Some(SIGNED_OFFER_DOMAIN) {
        return Err(CredentialV2OfferError::Refused);
    }
    let offer_core = core.as_bytes().ok_or(CredentialV2OfferError::Refused)?;
    let kid = kid.as_text().ok_or(CredentialV2OfferError::Refused)?;
    let signature: [u8; 64] = signature
        .as_bytes()
        .ok_or(CredentialV2OfferError::Refused)?
        .as_slice()
        .try_into()
        .map_err(|_| CredentialV2OfferError::Refused)?;
    let key = profile
        .enrollment_keys
        .iter()
        .find(|candidate| candidate.kid == kid)
        .ok_or(CredentialV2OfferError::Refused)?;
    let digest: [u8; 32] = Sha256::digest(offer_core).into();
    VerifyingKey::from_bytes(&key.jwk.public_key)
        .map_err(|_| CredentialV2OfferError::Refused)?
        .verify(
            &[OFFER_SIGNATURE_DOMAIN, &digest].concat(),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| CredentialV2OfferError::Refused)?;
    recognise_offer_core_with_envelope(profile, bytes, offer_core, kid, digest)
}

/// Recognise one unsigned offer core under the independently authenticated profile.
pub fn recognise_offer_core(
    profile: &ApplicationProfile,
    offer_core: &[u8],
) -> Result<RecognisedCredentialV2Offer, CredentialV2OfferError> {
    let digest = Sha256::digest(offer_core).into();
    recognise_offer_core_with_envelope(profile, &[], offer_core, "", digest)
}

fn recognise_offer_core_with_envelope(
    profile: &ApplicationProfile,
    signed_offer: &[u8],
    offer_core: &[u8],
    kid: &str,
    digest: [u8; 32],
) -> Result<RecognisedCredentialV2Offer, CredentialV2OfferError> {
    let core = json::recognise(
        offer_core,
        Limits {
            max_bytes: MAX_OFFER_CORE_BYTES,
            max_depth: 4,
        },
    )
    .map_err(|_| CredentialV2OfferError::Refused)?;
    if json::canonicalise(&core).as_slice() != offer_core {
        return Err(CredentialV2OfferError::Refused);
    }
    parse_core(profile, signed_offer, offer_core, kid, digest, &core)
}

fn parse_core(
    profile: &ApplicationProfile,
    signed_offer: &[u8],
    offer_core: &[u8],
    kid: &str,
    digest: [u8; 32],
    core: &Json,
) -> Result<RecognisedCredentialV2Offer, CredentialV2OfferError> {
    const MEMBERS: [&str; 20] = [
        "accountPrincipalDigest",
        "accountScopeId",
        "accountTransition",
        "applicationId",
        "carrierCeremonyId",
        "carrierDigest",
        "descriptorDigest",
        "deviceDid",
        "deviceKeyJwk",
        "expiresAt",
        "intentNonce",
        "issuedAt",
        "payloadVersion",
        "profileDigest",
        "profileVersion",
        "relayOrigin",
        "requestId",
        "requestedPermissions",
        "role",
        "transcriptHash",
    ];
    if core.member_names() != MEMBERS
        || integer(core, "payloadVersion")? != 2
        || integer(core, "profileVersion")? != 2
        || text(core, "role")? != "offer"
        || text(core, "applicationId")? != profile.application_id.as_str()
        || fixed(core, "profileDigest")? != *profile.digest()
    {
        return Err(CredentialV2OfferError::Refused);
    }
    let relay_origin = text(core, "relayOrigin")?;
    let descriptor = profile
        .cbcl_pairing_relays
        .iter()
        .find(|candidate| candidate.relay_origin == relay_origin)
        .ok_or(CredentialV2OfferError::Refused)?;
    let descriptor_digest = fixed(core, "descriptorDigest")?;
    if descriptor_digest != descriptor.digest {
        return Err(CredentialV2OfferError::Refused);
    }
    let device_key = parse_device_jwk(
        core.get("deviceKeyJwk")
            .ok_or(CredentialV2OfferError::Refused)?,
    )?;
    let device_did = text(core, "deviceDid")?;
    didkey::matches_jwk(device_did, &device_key).map_err(|_| CredentialV2OfferError::Refused)?;
    let permissions = string_array(core, "requestedPermissions")?;
    recognise_permissions(profile, &permissions)?;
    let transition = parse_transition(
        core.get("accountTransition")
            .ok_or(CredentialV2OfferError::Refused)?,
    )?;
    let carrier_ceremony_id = fixed(core, "carrierCeremonyId")?;
    let account_scope_id = fixed(core, "accountScopeId")?;
    let account_principal_digest = fixed(core, "accountPrincipalDigest")?;
    let claims = CredentialV2IntentClaims::new(
        profile.application_id.as_str(),
        profile.application_id.origin(),
        relay_origin,
        carrier_ceremony_id,
        CredentialV2AccountProvenance::new(account_principal_digest, account_scope_id),
        permissions,
        CredentialV2DeviceBinding::new(
            device_did,
            Sha256::digest(json::canonicalise(
                core.get("deviceKeyJwk")
                    .ok_or(CredentialV2OfferError::Refused)?,
            ))
            .into(),
        )
        .map_err(|_| CredentialV2OfferError::Refused)?,
        transition,
        digest,
    )
    .map_err(|_| CredentialV2OfferError::Refused)?;
    let issued_at = integer(core, "issuedAt")?;
    let expires_at = integer(core, "expiresAt")?;
    if expires_at <= issued_at || !(300..=600).contains(&(expires_at - issued_at)) {
        return Err(CredentialV2OfferError::Refused);
    }
    Ok(RecognisedCredentialV2Offer {
        signed_offer: signed_offer.to_vec(),
        offer_core: offer_core.to_vec(),
        kid: kid.into(),
        claims,
        request_id: fixed(core, "requestId")?,
        profile_digest: fixed(core, "profileDigest")?,
        descriptor_digest,
        carrier_digest: fixed(core, "carrierDigest")?,
        intent_nonce: fixed(core, "intentNonce")?,
        transcript_hash: fixed(core, "transcriptHash")?,
        expires_at,
    })
}

fn selected_descriptor<'a>(
    profile: &'a ApplicationProfile,
    carrier: &CredentialV2Carrier,
) -> Result<&'a CbclRelayDescriptor, CredentialV2OfferError> {
    if profile.application_id.as_str() != carrier.application_context() {
        return Err(CredentialV2OfferError::Refused);
    }
    let mut matches = profile
        .cbcl_pairing_relays
        .iter()
        .filter(|candidate| candidate.relay_origin == carrier.relay_origin());
    let descriptor = matches.next().ok_or(CredentialV2OfferError::Refused)?;
    if matches.next().is_some() {
        return Err(CredentialV2OfferError::Refused);
    }
    Ok(descriptor)
}

fn recognise_permissions(
    profile: &ApplicationProfile,
    values: &[String],
) -> Result<(), CredentialV2OfferError> {
    if values.is_empty()
        || values.len() > 4
        || values.iter().any(|value| {
            value.is_empty() || value.len() > 128 || !profile.allowed_permissions.contains(value)
        })
        || values
            .windows(2)
            .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err(CredentialV2OfferError::Refused);
    }
    Ok(())
}

fn validate_snapshot(
    input: &CredentialV2OfferBuildInput,
) -> Result<Vec<String>, CredentialV2OfferError> {
    if input.legacy_handle.len() < 2
        || input.legacy_handle.len() > 33
        || !input.legacy_handle.starts_with('@')
        || !input.legacy_handle[1..].bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
        || input.snapshot_rows.len() > 256
    {
        return Err(CredentialV2OfferError::Refused);
    }
    let mut rooms = Vec::with_capacity(input.snapshot_rows.len());
    let mut prior_key: Option<&[u8]> = None;
    for row in &input.snapshot_rows {
        let mut expected_key = u32::try_from(row.room.len())
            .map_err(|_| CredentialV2OfferError::Refused)?
            .to_be_bytes()
            .to_vec();
        expected_key.extend_from_slice(row.room.as_bytes());
        expected_key.extend_from_slice(input.legacy_handle.as_bytes());
        if row.legacy_handle != input.legacy_handle
            || row.enrolled_key != input.enrolled_key
            || row.raw_primary_key != expected_key
            || prior_key.is_some_and(|prior| prior >= row.raw_primary_key.as_slice())
        {
            return Err(CredentialV2OfferError::Refused);
        }
        prior_key = Some(&row.raw_primary_key);
        rooms.push(row.room.clone());
    }
    if rooms
        .windows(2)
        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err(CredentialV2OfferError::Refused);
    }
    CredentialV2Transition::path_a_to_b(
        &input.legacy_handle,
        [0; 32],
        rooms.clone(),
        [0; 32],
        [0; 32],
        input.snapshot_nonce,
    )
    .map_err(|_| CredentialV2OfferError::Refused)?;
    Ok(rooms)
}

fn room_set_digest(rooms: &[String]) -> Result<[u8; 32], CredentialV2OfferError> {
    let value = Value::Array(
        rooms
            .iter()
            .map(|room| Value::Bytes(room.as_bytes().to_vec()))
            .collect(),
    );
    let bytes = cbor2::to_canonical_vec(&value).map_err(|_| CredentialV2OfferError::Refused)?;
    Ok(labelled_hash(ROOM_SET_DOMAIN, &bytes))
}

fn migration_snapshot_digest(
    input: &CredentialV2OfferBuildInput,
) -> Result<[u8; 32], CredentialV2OfferError> {
    let member = Value::Array(vec![
        Value::Text("cbcl-member".into()),
        Value::Bytes(input.legacy_handle.as_bytes().to_vec()),
        Value::Bytes(input.enrolled_key.to_vec()),
    ]);
    let rows = input
        .snapshot_rows
        .iter()
        .map(|row| {
            Value::Array(vec![
                Value::Text("cbcl-roommember".into()),
                Value::Bytes(row.raw_primary_key.clone()),
                Value::Bytes(row.room.as_bytes().to_vec()),
                Value::Bytes(row.legacy_handle.as_bytes().to_vec()),
                Value::Bytes(row.enrolled_key.to_vec()),
                Value::Integer(row.granted.into()),
                Value::Text(
                    match row.provenance {
                        CredentialV2RoomProvenance::Standing => "standing",
                        CredentialV2RoomProvenance::Invite => "invite",
                    }
                    .into(),
                ),
                row.since
                    .map_or(Value::Null, |value| Value::Integer(value.into())),
            ])
        })
        .collect();
    let bytes = cbor2::to_canonical_vec(&Value::Array(vec![member, Value::Array(rows)]))
        .map_err(|_| CredentialV2OfferError::Refused)?;
    Ok(labelled_hash(SNAPSHOT_DOMAIN, &bytes))
}

fn account_principal_digest(
    application_id: &str,
    application_account_id: [u8; 32],
) -> Result<[u8; 32], CredentialV2OfferError> {
    let bytes = cbor2::to_canonical_vec(&Value::Array(vec![
        Value::Text(ACCOUNT_PRINCIPAL_DOMAIN.into()),
        Value::Text(application_id.into()),
        Value::Bytes(application_account_id.to_vec()),
    ]))
    .map_err(|_| CredentialV2OfferError::Refused)?;
    Ok(Sha256::digest(bytes).into())
}

fn transition_json(
    legacy_handle: &str,
    legacy_key_digest: [u8; 32],
    rooms: &[String],
    room_set_digest: [u8; 32],
    migration_snapshot_digest: [u8; 32],
    snapshot_nonce: [u8; 32],
) -> Json {
    Json::obj([
        ("kind", Json::text("path-a-to-b")),
        ("legacyHandle", Json::text(legacy_handle)),
        (
            "legacyKeyDigest",
            Json::text(codec::b64url(&legacy_key_digest)),
        ),
        (
            "migrationRooms",
            Json::Array(rooms.iter().map(Json::text).collect()),
        ),
        (
            "migrationSnapshotDigest",
            Json::text(codec::b64url(&migration_snapshot_digest)),
        ),
        ("roomSetDigest", Json::text(codec::b64url(&room_set_digest))),
        ("snapshotNonce", Json::text(codec::b64url(&snapshot_nonce))),
    ])
}

fn parse_transition(value: &Json) -> Result<CredentialV2Transition, CredentialV2OfferError> {
    const MEMBERS: [&str; 7] = [
        "kind",
        "legacyHandle",
        "legacyKeyDigest",
        "migrationRooms",
        "migrationSnapshotDigest",
        "roomSetDigest",
        "snapshotNonce",
    ];
    if value.member_names() != MEMBERS || text(value, "kind")? != "path-a-to-b" {
        return Err(CredentialV2OfferError::Refused);
    }
    CredentialV2Transition::path_a_to_b(
        text(value, "legacyHandle")?,
        fixed(value, "legacyKeyDigest")?,
        string_array(value, "migrationRooms")?,
        fixed(value, "roomSetDigest")?,
        fixed(value, "migrationSnapshotDigest")?,
        fixed(value, "snapshotNonce")?,
    )
    .map_err(|_| CredentialV2OfferError::Refused)
}

fn device_jwk(key: [u8; 32]) -> Json {
    Json::obj([
        ("crv", Json::text("Ed25519")),
        ("kty", Json::text("OKP")),
        ("x", Json::text(codec::b64url(&key))),
    ])
}

fn parse_device_jwk(value: &Json) -> Result<[u8; 32], CredentialV2OfferError> {
    const MEMBERS: [&str; 3] = ["crv", "kty", "x"];
    if value.member_names() != MEMBERS
        || text(value, "crv")? != "Ed25519"
        || text(value, "kty")? != "OKP"
    {
        return Err(CredentialV2OfferError::Refused);
    }
    codec::decode_b64url_32(text(value, "x")?).map_err(|_| CredentialV2OfferError::Refused)
}

fn text<'a>(value: &'a Json, name: &str) -> Result<&'a str, CredentialV2OfferError> {
    value
        .get(name)
        .and_then(Json::as_str)
        .ok_or(CredentialV2OfferError::Refused)
}

fn integer(value: &Json, name: &str) -> Result<u64, CredentialV2OfferError> {
    value
        .get(name)
        .and_then(Json::as_i64)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(CredentialV2OfferError::Refused)
}

fn fixed<const N: usize>(value: &Json, name: &str) -> Result<[u8; N], CredentialV2OfferError> {
    codec::decode_b64url_exact(text(value, name)?, N)
        .map_err(|_| CredentialV2OfferError::Refused)?
        .try_into()
        .map_err(|_| CredentialV2OfferError::Refused)
}

fn string_array(value: &Json, name: &str) -> Result<Vec<String>, CredentialV2OfferError> {
    value
        .get(name)
        .and_then(Json::as_array)
        .ok_or(CredentialV2OfferError::Refused)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(CredentialV2OfferError::Refused)
        })
        .collect()
}

fn labelled_hash(label: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(label);
    hash.update(value);
    hash.finalize().into()
}

fn signing_key_declared(
    profile: &ApplicationProfile,
    kid: &str,
    signing_key: &SigningKey,
) -> Result<(), CredentialV2OfferError> {
    let declared = profile
        .enrollment_keys
        .iter()
        .find(|candidate| candidate.kid == kid)
        .ok_or(CredentialV2OfferError::Refused)?;
    if declared.jwk.public_key != signing_key.verifying_key().to_bytes() {
        return Err(CredentialV2OfferError::Refused);
    }
    Ok(())
}

fn valid_bound_did(value: &str) -> bool {
    value.len() > "did:crdt:".len()
        && value.len() <= 512
        && value.starts_with("did:crdt:")
        && !value.contains('#')
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

impl From<CredentialV2Error> for CredentialV2OfferError {
    fn from(_: CredentialV2Error) -> Self {
        Self::Refused
    }
}
