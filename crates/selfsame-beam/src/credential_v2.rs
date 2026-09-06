//! Closed Selfsame recognition for credential/v2 hub allocation inputs.
//!
//! The BEAM shell supplies the exact profile bytes already served by the hub,
//! the application and relay copied from a canonical `cbcl-pairing` carrier,
//! and the two bounded browser inputs. This module returns one typed projection
//! or one opaque refusal; no partially parsed profile, descriptor, permission,
//! or device key crosses the NIF boundary.

use rustler::types::atom;
use rustler::{Atom, Binary, Decoder, Encoder, Env, OwnedBinary, Resource, ResourceArc, Term};
use selfsame_app_identity::json::{Json, Limits};
use selfsame_app_identity::path_b::{replay_resolver_closure, InactiveStagedGrant};
use selfsame_app_identity::profile::{ApplicationProfile, CbclRelayDescriptor};
use selfsame_app_identity::{alias, codec, didkey, grant, json};
use selfsame_pairing::credential_v2::{
    build_authority_status_response, build_final_status, build_recovery_not_finalized,
    credential_v2_receipt_recovery_commitment, encode_receipt_recovery_response,
    finalize_verified_offer, migration_confirmation_digest, prepare_offer_core,
    recognise_browser_staging_receipt, recognise_prepared_offer,
    recognise_receipt_recovery_request, recognise_signed_offer, verify_prepared_offer_device_proof,
    CredentialV2AuthorityStatus, CredentialV2BrowserStagingInput, CredentialV2FinalStatusInput,
    CredentialV2OfferBuildInput, CredentialV2RecoveryNegativeInput, CredentialV2RecoveryResponse,
    CredentialV2RoomProvenance, CredentialV2RoomSnapshot,
};
use std::sync::Mutex;

const MAX_DEVICE_JWK_OCTETS: usize = 96;
const MAX_PERMISSION_OCTETS: usize = 128;
const MAX_REQUESTED_PERMISSIONS: usize = 4;
const REFUSED: &str = "rejected";

rustler::atoms! {
    rejected,
    verified,
    application_id,
    account_authority,
    profile_bytes,
    profile_digest,
    descriptor_bytes,
    descriptor_digest,
    relay_origin,
    requested_permissions,
    device_jwk,
    device_public_key,
    offer_core,
    offer_core_digest,
    intent_digest,
    signed_offer,
    kid,
    account_principal_digest,
    device_did,
    device_key_digest,
    legacy_key_digest,
    room_set_digest,
    migration_snapshot_digest,
    authority_status_response,
    authority_status_digest,
    request_id,
    carrier_ceremony_id,
    account_scope_id,
    account,
    payload_digest,
    grant_id,
    credential_id,
    issuer_did,
    receipt_recovery_commitment,
    raw_grant,
    migration_confirmation_digest_atom = "migration_confirmation_digest",
    final_status_jws,
    final_status_digest,
    finalized_at,
    valid_until,
    permissions,
    standing,
    invite,
    undefined,
}

/// Secret-free facts returned after a recovery request is recognised and its
/// token has been reduced to the public commitment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialV2RecoveryProjection {
    pub application_id: String,
    pub carrier_ceremony_id: [u8; 32],
    pub receipt_recovery_commitment: [u8; 32],
}

/// Recognise a deterministic-CBOR request and drop the raw token before return.
pub fn recognise_credential_v2_recovery_request(
    request: &[u8],
) -> Result<CredentialV2RecoveryProjection, String> {
    let recognised =
        recognise_receipt_recovery_request(request).map_err(|_| String::from(REFUSED))?;
    let receipt_recovery_commitment = credential_v2_receipt_recovery_commitment(
        recognised.receipt_recovery_token(),
        *recognised.carrier_ceremony_id(),
        recognised.application_id(),
    )
    .map_err(|_| String::from(REFUSED))?;
    Ok(CredentialV2RecoveryProjection {
        application_id: recognised.application_id().into(),
        carrier_ceremony_id: *recognised.carrier_ceremony_id(),
        receipt_recovery_commitment,
    })
}

/// Encode one byte-identical accepted response from the immutable final row.
pub fn credential_v2_recovery_accepted(
    final_status_jws: &str,
    final_status_digest: [u8; 32],
) -> Result<Vec<u8>, String> {
    encode_receipt_recovery_response(&CredentialV2RecoveryResponse::Accepted {
        final_status_jws: final_status_jws.into(),
        final_status_digest,
    })
    .map_err(|_| String::from(REFUSED))
}

/// Encode a bounded locked in-progress response.
pub fn credential_v2_recovery_in_progress(retry_after_seconds: u8) -> Result<Vec<u8>, String> {
    encode_receipt_recovery_response(&CredentialV2RecoveryResponse::InProgress {
        retry_after_seconds,
    })
    .map_err(|_| String::from(REFUSED))
}

/// Encode the one fixed-size unknown response.
pub fn credential_v2_recovery_unknown() -> Result<Vec<u8>, String> {
    encode_receipt_recovery_response(&CredentialV2RecoveryResponse::Unknown)
        .map_err(|_| String::from(REFUSED))
}

/// Sign and encode one locked terminal negative under the current profile.
pub fn prepare_credential_v2_recovery_negative(
    profile: &ApplicationProfile,
    input: &CredentialV2RecoveryNegativeInput,
    kid: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<Vec<u8>, String> {
    let built = build_recovery_not_finalized(profile, input, kid, signing_key)
        .map_err(|_| String::from(REFUSED))?;
    encode_receipt_recovery_response(&CredentialV2RecoveryResponse::NotFinalized {
        recovery_status_jws: built.jws,
        recovery_status_digest: built.digest,
    })
    .map_err(|_| String::from(REFUSED))
}

#[rustler::nif(
    name = "recognise_credential_v2_recovery_request",
    schedule = "DirtyCpu"
)]
pub fn recognise_credential_v2_recovery_request_nif<'a>(
    env: Env<'a>,
    request: Binary<'a>,
) -> Term<'a> {
    let result =
        std::panic::catch_unwind(|| recognise_credential_v2_recovery_request(request.as_slice()));
    match result {
        Ok(Ok(projection)) => {
            let mut map = rustler::types::map::map_new(env);
            let encoded = (|| {
                for (key, value) in [
                    (
                        application_id().encode(env),
                        binary(env, projection.application_id.as_bytes())?,
                    ),
                    (
                        carrier_ceremony_id().encode(env),
                        binary(env, &projection.carrier_ceremony_id)?,
                    ),
                    (
                        receipt_recovery_commitment().encode(env),
                        binary(env, &projection.receipt_recovery_commitment)?,
                    ),
                ] {
                    map = map.map_put(key, value).map_err(|_| String::from(REFUSED))?;
                }
                Ok::<Term<'a>, String>(map)
            })();
            match encoded {
                Ok(value) => (atom::ok(), value).encode(env),
                Err(_) => (atom::error(), rejected()).encode(env),
            }
        }
        Ok(Err(_)) | Err(_) => (atom::error(), rejected()).encode(env),
    }
}

#[rustler::nif(name = "credential_v2_recovery_accepted")]
pub fn credential_v2_recovery_accepted_nif<'a>(
    env: Env<'a>,
    final_status_jws: Binary<'a>,
    final_status_digest: Binary<'a>,
) -> Term<'a> {
    let result = std::panic::catch_unwind(|| {
        credential_v2_recovery_accepted(
            &utf8(final_status_jws.as_slice())?,
            exact(final_status_digest.as_slice())?,
        )
    });
    encode_binary_result(env, result)
}

#[rustler::nif(name = "credential_v2_recovery_in_progress")]
pub fn credential_v2_recovery_in_progress_nif<'a>(env: Env<'a>, retry: u8) -> Term<'a> {
    encode_binary_result(
        env,
        std::panic::catch_unwind(|| credential_v2_recovery_in_progress(retry)),
    )
}

#[rustler::nif(name = "credential_v2_recovery_unknown")]
pub fn credential_v2_recovery_unknown_nif<'a>(env: Env<'a>) -> Term<'a> {
    encode_binary_result(
        env,
        std::panic::catch_unwind(credential_v2_recovery_unknown),
    )
}

#[allow(clippy::too_many_arguments)]
#[rustler::nif(name = "credential_v2_recovery_not_finalized", schedule = "DirtyCpu")]
pub fn credential_v2_recovery_not_finalized_nif<'a>(
    env: Env<'a>,
    profile_bytes: Binary<'a>,
    application_id_value: Binary<'a>,
    carrier_ceremony_id_value: Binary<'a>,
    commitment_value: Binary<'a>,
    observed_at_value: u64,
    signing_kid: Binary<'a>,
    signing_seed: Binary<'a>,
) -> Term<'a> {
    let result = std::panic::catch_unwind(|| {
        let profile = ApplicationProfile::recognise(profile_bytes.as_slice())
            .map_err(|_| String::from(REFUSED))?;
        let input = CredentialV2RecoveryNegativeInput {
            application_id: utf8(application_id_value.as_slice())?,
            carrier_ceremony_id: exact(carrier_ceremony_id_value.as_slice())?,
            receipt_recovery_commitment: exact(commitment_value.as_slice())?,
            observed_at: observed_at_value,
        };
        let kid = utf8(signing_kid.as_slice())?;
        let seed = exact(signing_seed.as_slice())?;
        prepare_credential_v2_recovery_negative(
            &profile,
            &input,
            &kid,
            &ed25519_dalek::SigningKey::from_bytes(&seed),
        )
    });
    encode_binary_result(env, result)
}

/// `cbcl_selfsame_erl:build_credential_v2_authority_status/6`.
#[allow(clippy::too_many_arguments)]
#[rustler::nif(name = "build_credential_v2_authority_status", schedule = "DirtyCpu")]
pub fn build_credential_v2_authority_status_nif<'a>(
    env: Env<'a>,
    profile_bytes: Binary<'a>,
    carrier_ceremony_id: Binary<'a>,
    offer_core_digest_value: Binary<'a>,
    bound_did: Term<'a>,
    signing_kid: Binary<'a>,
    signing_seed: Binary<'a>,
) -> Term<'a> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let profile = ApplicationProfile::recognise(profile_bytes.as_slice())
            .map_err(|_| String::from(REFUSED))?;
        let status = if bound_did.decode::<Atom>().ok() == Some(undefined()) {
            CredentialV2AuthorityStatus::NoBinding
        } else {
            let did = Binary::decode(bound_did).map_err(|_| String::from(REFUSED))?;
            CredentialV2AuthorityStatus::Bound(utf8(did.as_slice())?)
        };
        let signing_kid = utf8(signing_kid.as_slice())?;
        let seed: [u8; 32] = exact(signing_seed.as_slice())?;
        let built = build_authority_status_response(
            &profile,
            exact(carrier_ceremony_id.as_slice())?,
            exact(offer_core_digest_value.as_slice())?,
            &status,
            &signing_kid,
            &ed25519_dalek::SigningKey::from_bytes(&seed),
        )
        .map_err(|_| String::from(REFUSED))?;
        let mut map = rustler::types::map::map_new(env);
        for (key, value) in [
            (
                authority_status_response().encode(env),
                binary(env, &built.response)?,
            ),
            (
                authority_status_digest().encode(env),
                binary(env, &built.digest)?,
            ),
            (kid().encode(env), binary(env, built.kid.as_bytes())?),
        ] {
            map = map.map_put(key, value).map_err(|_| String::from(REFUSED))?;
        }
        Ok::<Term<'a>, String>(map)
    }));
    match result {
        Ok(Ok(value)) => (atom::ok(), value).encode(env),
        Ok(Err(_)) | Err(_) => (atom::error(), rejected()).encode(env),
    }
}

/// `cbcl_selfsame_erl:verify_credential_v2_offer_proof/6`.
///
/// This is the recovery/retry verifier: it exposes no signing operation and
/// returns no offer metadata that the caller could confuse with authority.
#[allow(clippy::too_many_arguments)]
#[rustler::nif(name = "verify_credential_v2_offer_proof", schedule = "DirtyCpu")]
pub fn verify_credential_v2_offer_proof_nif<'a>(
    env: Env<'a>,
    profile_bytes: Binary<'a>,
    offer_core: Binary<'a>,
    socket_generation_digest: Binary<'a>,
    carrier_ceremony_id: Binary<'a>,
    device_public_key: Binary<'a>,
    device_possession_proof: Binary<'a>,
) -> Term<'a> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let profile = ApplicationProfile::recognise(profile_bytes.as_slice())
            .map_err(|_| String::from(REFUSED))?;
        let prepared = recognise_prepared_offer(&profile, offer_core.as_slice())
            .map_err(|_| String::from(REFUSED))?;
        verify_prepared_offer_device_proof(
            &profile,
            &prepared,
            exact(socket_generation_digest.as_slice())?,
            exact(carrier_ceremony_id.as_slice())?,
            exact(device_public_key.as_slice())?,
            exact(device_possession_proof.as_slice())?,
        )
        .map_err(|_| String::from(REFUSED))?;
        Ok::<Atom, String>(verified())
    }));
    match result {
        Ok(Ok(value)) => (atom::ok(), value).encode(env),
        Ok(Err(_)) | Err(_) => (atom::error(), rejected()).encode(env),
    }
}

/// Complete typed facts accepted for one credential/v2 pending allocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialV2ProfileProjection {
    /// Exact application identifier authenticated by the profile.
    pub application_id: String,
    /// Stable account authority authenticated by the profile.
    pub account_authority: String,
    /// Exact canonical profile bytes.
    pub profile_bytes: Vec<u8>,
    /// SHA-256 of the exact profile bytes.
    pub profile_digest: [u8; 32],
    /// Canonical bytes of the unique relay descriptor selected by origin.
    pub descriptor_bytes: Vec<u8>,
    /// SHA-256 of the complete selected descriptor.
    pub descriptor_digest: [u8; 32],
    /// Exact canonical relay origin from the selected descriptor.
    pub relay_origin: String,
    /// Sorted, unique, profile-declared permissions requested by the browser.
    pub requested_permissions: Vec<String>,
    /// Exact canonical closed device JWK bytes.
    pub device_jwk: Vec<u8>,
    /// Raw Ed25519 installation public key from that JWK.
    pub device_public_key: [u8; 32],
}

/// Verify the exact browser staging receipt under the held installation key.
pub fn verify_credential_v2_staging_receipt(
    expected: &CredentialV2BrowserStagingInput,
    device_public_key: [u8; 32],
    receipt: &[u8],
) -> Result<(), String> {
    recognise_browser_staging_receipt(receipt, expected, device_public_key)
        .map_err(|_| String::from(REFUSED))
}

/// `cbcl_selfsame_erl:verify_credential_v2_staging_receipt/13`.
#[allow(clippy::too_many_arguments)]
#[rustler::nif(name = "verify_credential_v2_staging_receipt", schedule = "DirtyCpu")]
pub fn verify_credential_v2_staging_receipt_nif<'a>(
    env: Env<'a>,
    application_id_value: Binary<'a>,
    carrier_ceremony_id: Binary<'a>,
    account_principal_digest_value: Binary<'a>,
    account_scope_id: Binary<'a>,
    device_did_value: Binary<'a>,
    offer_core_digest_value: Binary<'a>,
    payload_digest: Binary<'a>,
    grant_id: Binary<'a>,
    issuer_did: Binary<'a>,
    profile_digest_value: Binary<'a>,
    receipt_recovery_commitment: Binary<'a>,
    device_public_key_value: Binary<'a>,
    receipt: Binary<'a>,
) -> Term<'a> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let expected = CredentialV2BrowserStagingInput {
            application_id: utf8(application_id_value.as_slice())?,
            carrier_ceremony_id: exact(carrier_ceremony_id.as_slice())?,
            account_principal_digest: exact(account_principal_digest_value.as_slice())?,
            account_scope_id: exact(account_scope_id.as_slice())?,
            device_did: utf8(device_did_value.as_slice())?,
            offer_core_digest: exact(offer_core_digest_value.as_slice())?,
            payload_digest: exact(payload_digest.as_slice())?,
            grant_id: exact(grant_id.as_slice())?,
            issuer_did: utf8(issuer_did.as_slice())?,
            profile_digest: exact(profile_digest_value.as_slice())?,
            receipt_recovery_commitment: exact(receipt_recovery_commitment.as_slice())?,
        };
        verify_credential_v2_staging_receipt(
            &expected,
            exact(device_public_key_value.as_slice())?,
            receipt.as_slice(),
        )?;
        Ok::<Atom, String>(verified())
    }));
    match result {
        Ok(Ok(value)) => (atom::ok(), value).encode(env),
        Ok(Err(_)) | Err(_) => (atom::error(), rejected()).encode(env),
    }
}

/// Browser-authenticated finalization values not already held in the signed offer.
pub struct CredentialV2AcceptanceInput {
    pub raw_grant: Vec<u8>,
    pub payload_digest: [u8; 32],
    pub migration_confirmation_digest: [u8; 32],
    pub issuer_did: String,
    pub grant_id: [u8; 32],
    pub staging_receipt: Vec<u8>,
    pub receipt_recovery_commitment: [u8; 32],
    pub finalized_at: u64,
    pub signing_kid: String,
}

/// Exact facts projected only from a verified acceptance witness.
#[derive(Clone)]
pub struct CredentialV2AcceptanceProjection {
    pub application_id: String,
    pub profile_digest: [u8; 32],
    pub request_id: [u8; 32],
    pub carrier_ceremony_id: [u8; 32],
    pub account_principal_digest: [u8; 32],
    pub account_scope_id: [u8; 32],
    pub account: String,
    pub device_did: String,
    pub device_public_key: [u8; 32],
    pub offer_core_digest: [u8; 32],
    pub offer_kid: String,
    pub payload_digest: [u8; 32],
    pub migration_confirmation_digest: [u8; 32],
    pub grant_id: [u8; 32],
    pub credential_id: String,
    pub issuer_did: String,
    pub raw_grant: Vec<u8>,
    pub permissions: Vec<String>,
    pub valid_until: i64,
    pub receipt_recovery_commitment: [u8; 32],
    pub final_status_jws: String,
    pub final_status_digest: [u8; 32],
    pub finalized_at: u64,
}

/// Opaque verifier authority retained across retryable Mnesia transaction attempts.
pub struct CredentialV2AcceptanceWitness {
    projection: Mutex<CredentialV2AcceptanceProjection>,
}

impl Resource for CredentialV2AcceptanceWitness {}

/// Cross-check live grant verification, the signed offer, browser staging
/// receipt, migration digest, and immutable final status in one pure decision.
pub fn prepare_credential_v2_acceptance(
    profile: &ApplicationProfile,
    signed_offer: &[u8],
    staged: &InactiveStagedGrant,
    input: &CredentialV2AcceptanceInput,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<CredentialV2AcceptanceProjection, String> {
    let (projection, final_input) =
        validate_credential_v2_acceptance(profile, signed_offer, staged, input)?;
    sign_credential_v2_acceptance(
        profile,
        projection,
        &final_input,
        &input.signing_kid,
        signing_key,
    )
}

fn validate_credential_v2_acceptance(
    profile: &ApplicationProfile,
    signed_offer: &[u8],
    staged: &InactiveStagedGrant,
    input: &CredentialV2AcceptanceInput,
) -> Result<
    (
        CredentialV2AcceptanceProjection,
        CredentialV2FinalStatusInput,
    ),
    String,
> {
    let offer = recognise_signed_offer(profile, signed_offer).map_err(|_| String::from(REFUSED))?;
    let claims = &offer.claims;
    let device_public_key =
        didkey::decode(claims.device_binding().device_did()).map_err(|_| String::from(REFUSED))?;
    let account = alias::stable_acct_uri(&input.issuer_did, &profile.account_authority);
    let expected_grant_id = grant::identifiers(&input.issuer_did, &input.grant_id).0;
    if offer.kid != input.signing_kid
        || offer.profile_digest != *profile.digest()
        || staged.account_did != input.issuer_did
        || staged.account != account
        || staged.grant_id != expected_grant_id
        || staged.grant_token != input.grant_id
        || staged.device_did != claims.device_binding().device_did()
        || staged.device_public_key != device_public_key
        || staged.permissions != claims.permissions()
        || migration_confirmation_digest(&offer, &input.issuer_did)
            .map_err(|_| String::from(REFUSED))?
            != input.migration_confirmation_digest
    {
        return Err(String::from(REFUSED));
    }
    let staging = CredentialV2BrowserStagingInput {
        application_id: profile.application_id.as_str().into(),
        carrier_ceremony_id: *claims.carrier_ceremony_id(),
        account_principal_digest: *claims.account_provenance().account_principal_digest(),
        account_scope_id: *claims.account_provenance().account_scope_id(),
        device_did: claims.device_binding().device_did().into(),
        offer_core_digest: *claims.offer_core_digest(),
        payload_digest: input.payload_digest,
        grant_id: input.grant_id,
        issuer_did: input.issuer_did.clone(),
        profile_digest: *profile.digest(),
        receipt_recovery_commitment: input.receipt_recovery_commitment,
    };
    verify_credential_v2_staging_receipt(&staging, device_public_key, &input.staging_receipt)?;
    let final_input = CredentialV2FinalStatusInput {
        application_id: profile.application_id.as_str().into(),
        carrier_ceremony_id: *claims.carrier_ceremony_id(),
        request_id: offer.request_id,
        account_principal_digest: *claims.account_provenance().account_principal_digest(),
        account_scope_id: *claims.account_provenance().account_scope_id(),
        device_did: claims.device_binding().device_did().into(),
        offer_core_digest: *claims.offer_core_digest(),
        payload_digest: input.payload_digest,
        grant_id: input.grant_id,
        issuer_did: input.issuer_did.clone(),
        receipt_recovery_commitment: input.receipt_recovery_commitment,
        finalized_at: input.finalized_at,
    };
    Ok((
        CredentialV2AcceptanceProjection {
            application_id: profile.application_id.as_str().into(),
            profile_digest: *profile.digest(),
            request_id: offer.request_id,
            carrier_ceremony_id: *claims.carrier_ceremony_id(),
            account_principal_digest: *claims.account_provenance().account_principal_digest(),
            account_scope_id: *claims.account_provenance().account_scope_id(),
            account,
            device_did: claims.device_binding().device_did().into(),
            device_public_key,
            offer_core_digest: *claims.offer_core_digest(),
            offer_kid: offer.kid.clone(),
            payload_digest: input.payload_digest,
            migration_confirmation_digest: input.migration_confirmation_digest,
            grant_id: input.grant_id,
            credential_id: staged.grant_id.clone(),
            issuer_did: input.issuer_did.clone(),
            raw_grant: input.raw_grant.clone(),
            permissions: staged.permissions.clone(),
            valid_until: staged.valid_until,
            receipt_recovery_commitment: input.receipt_recovery_commitment,
            final_status_jws: String::new(),
            final_status_digest: [0_u8; 32],
            finalized_at: input.finalized_at,
        },
        final_input,
    ))
}

fn sign_credential_v2_acceptance(
    profile: &ApplicationProfile,
    mut projection: CredentialV2AcceptanceProjection,
    final_input: &CredentialV2FinalStatusInput,
    signing_kid: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<CredentialV2AcceptanceProjection, String> {
    let final_status = build_final_status(profile, final_input, signing_kid, signing_key)
        .map_err(|_| String::from(REFUSED))?;
    projection.final_status_jws = final_status.jws;
    projection.final_status_digest = final_status.digest;
    Ok(projection)
}

/// Verify one finalization command into an opaque authority resource. Resolver
/// evidence is supplied only by the hub sidecar; caller-carried closure bytes
/// are independently replayed but never promoted to resolver provenance.
#[allow(clippy::too_many_arguments)]
#[rustler::nif(name = "verify_credential_v2_acceptance", schedule = "DirtyCpu")]
pub fn verify_credential_v2_acceptance_nif<'a>(
    env: Env<'a>,
    profile_bytes: Binary<'a>,
    signed_offer: Binary<'a>,
    raw_grant_value: Binary<'a>,
    raw_resolver_closure: Binary<'a>,
    resolver_evidence: Term<'a>,
    payload_digest_value: Binary<'a>,
    migration_confirmation_digest_value: Binary<'a>,
    issuer_did_value: Binary<'a>,
    grant_id_value: Binary<'a>,
    staging_receipt: Binary<'a>,
    receipt_recovery_commitment_value: Binary<'a>,
    finalized_at: u64,
    signing_kid: Binary<'a>,
    signing_seed: Binary<'a>,
) -> Term<'a> {
    verify_credential_v2_acceptance_inner(
        env,
        profile_bytes,
        signed_offer,
        raw_grant_value,
        raw_resolver_closure,
        resolver_evidence,
        payload_digest_value,
        migration_confirmation_digest_value,
        issuer_did_value,
        grant_id_value,
        staging_receipt,
        receipt_recovery_commitment_value,
        finalized_at,
        finalized_at,
        signing_kid,
        signing_seed,
    )
}

/// Acceptance with distinct verifier and signed-finalization clocks.
///
/// Resolver evidence is obtained after the wire command is decoded, so its
/// verifier-owned fetch stamp can legitimately be newer than the immutable
/// finalization time retained for an accepted retry.  The former is used only
/// for freshness; the latter remains part of the signed final status.
#[allow(clippy::too_many_arguments)]
#[rustler::nif(name = "verify_credential_v2_acceptance_at", schedule = "DirtyCpu")]
pub fn verify_credential_v2_acceptance_at_nif<'a>(
    env: Env<'a>,
    profile_bytes: Binary<'a>,
    signed_offer: Binary<'a>,
    raw_grant_value: Binary<'a>,
    raw_resolver_closure: Binary<'a>,
    resolver_evidence: Term<'a>,
    payload_digest_value: Binary<'a>,
    migration_confirmation_digest_value: Binary<'a>,
    issuer_did_value: Binary<'a>,
    grant_id_value: Binary<'a>,
    staging_receipt: Binary<'a>,
    receipt_recovery_commitment_value: Binary<'a>,
    verification_now: u64,
    finalized_at: u64,
    signing_kid: Binary<'a>,
    signing_seed: Binary<'a>,
) -> Term<'a> {
    verify_credential_v2_acceptance_inner(
        env,
        profile_bytes,
        signed_offer,
        raw_grant_value,
        raw_resolver_closure,
        resolver_evidence,
        payload_digest_value,
        migration_confirmation_digest_value,
        issuer_did_value,
        grant_id_value,
        staging_receipt,
        receipt_recovery_commitment_value,
        verification_now,
        finalized_at,
        signing_kid,
        signing_seed,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_credential_v2_acceptance_inner<'a>(
    env: Env<'a>,
    profile_bytes: Binary<'a>,
    signed_offer: Binary<'a>,
    raw_grant_value: Binary<'a>,
    raw_resolver_closure: Binary<'a>,
    resolver_evidence: Term<'a>,
    payload_digest_value: Binary<'a>,
    migration_confirmation_digest_value: Binary<'a>,
    issuer_did_value: Binary<'a>,
    grant_id_value: Binary<'a>,
    staging_receipt: Binary<'a>,
    receipt_recovery_commitment_value: Binary<'a>,
    verification_now: u64,
    finalized_at: u64,
    signing_kid: Binary<'a>,
    signing_seed: Binary<'a>,
) -> Term<'a> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if finalized_at > verification_now {
            return Err(String::from(REFUSED));
        }
        if raw_grant_value.as_slice().is_empty()
            || raw_grant_value.as_slice().len() > 49_152
            || raw_resolver_closure.as_slice().is_empty()
            || raw_resolver_closure.as_slice().len() > 1_048_576
            || staging_receipt.as_slice().is_empty()
            || staging_receipt.as_slice().len() > 4_608
        {
            return Err(String::from(REFUSED));
        }
        let profile = ApplicationProfile::recognise(profile_bytes.as_slice())
            .map_err(|_| String::from(REFUSED))?;
        let issuer_did = utf8(issuer_did_value.as_slice())?;
        replay_carried_resolver_closure(
            &profile,
            &issuer_did,
            raw_resolver_closure.as_slice(),
            i64::try_from(verification_now).map_err(|_| String::from(REFUSED))?,
        )?;
        let offer = recognise_signed_offer(&profile, signed_offer.as_slice())
            .map_err(|_| String::from(REFUSED))?;
        let device_public_key = didkey::decode(offer.claims.device_binding().device_did())
            .map_err(|_| String::from(REFUSED))?;
        let account = alias::stable_acct_uri(&issuer_did, &profile.account_authority);
        let closures = crate::path_b::decode_closures(env, resolver_evidence)?;
        let staged = crate::path_b::verify_inactive_grant_pure(
            profile_bytes.as_slice(),
            &issuer_did,
            &account,
            &device_public_key,
            offer.claims.permissions(),
            i64::try_from(verification_now).map_err(|_| String::from(REFUSED))?,
            0,
            raw_grant_value.as_slice(),
            &closures,
        )?;
        let input = CredentialV2AcceptanceInput {
            raw_grant: raw_grant_value.as_slice().to_vec(),
            payload_digest: exact(payload_digest_value.as_slice())?,
            migration_confirmation_digest: exact(migration_confirmation_digest_value.as_slice())?,
            issuer_did,
            grant_id: exact(grant_id_value.as_slice())?,
            staging_receipt: staging_receipt.as_slice().to_vec(),
            receipt_recovery_commitment: exact(receipt_recovery_commitment_value.as_slice())?,
            finalized_at,
            signing_kid: utf8(signing_kid.as_slice())?,
        };
        let (projection, final_input) =
            validate_credential_v2_acceptance(&profile, signed_offer.as_slice(), &staged, &input)?;

        // The private seed is decoded only after grant, live resolver,
        // carried-closure, offer, migration, and staging-receipt verification.
        let seed: [u8; 32] = exact(signing_seed.as_slice())?;
        let projection = sign_credential_v2_acceptance(
            &profile,
            projection,
            &final_input,
            &input.signing_kid,
            &ed25519_dalek::SigningKey::from_bytes(&seed),
        )?;
        Ok::<ResourceArc<CredentialV2AcceptanceWitness>, String>(ResourceArc::new(
            CredentialV2AcceptanceWitness {
                projection: Mutex::new(projection),
            },
        ))
    }));
    match result {
        Ok(Ok(witness)) => (atom::ok(), witness).encode(env),
        Ok(Err(_)) | Err(_) => (atom::error(), rejected()).encode(env),
    }
}

/// Project one opaque witness inside each retryable transaction attempt. The
/// resource is immutable so an automatic Mnesia retry sees identical facts.
#[rustler::nif(name = "credential_v2_acceptance_facts")]
pub fn credential_v2_acceptance_facts_nif<'a>(
    env: Env<'a>,
    witness: ResourceArc<CredentialV2AcceptanceWitness>,
) -> Term<'a> {
    let result = witness
        .projection
        .lock()
        .map_err(|_| String::from(REFUSED))
        .and_then(|projection| encode_acceptance_projection(env, &projection));
    match result {
        Ok(value) => (atom::ok(), value).encode(env),
        Err(_) => (atom::error(), rejected()).encode(env),
    }
}

fn replay_carried_resolver_closure(
    profile: &ApplicationProfile,
    expected_did: &str,
    bytes: &[u8],
    now: i64,
) -> Result<(), String> {
    let bundle: did_crdt::core::recon::ClosureBundle =
        serde_json::from_slice(bytes).map_err(|_| String::from(REFUSED))?;
    if serde_json::to_vec(&bundle).ok().as_deref() != Some(bytes) {
        return Err(String::from(REFUSED));
    }
    let resolver_id = profile
        .state_resolvers
        .first()
        .ok_or_else(|| String::from(REFUSED))?
        .id
        .as_str();
    let observation = replay_resolver_closure(bundle, expected_did, resolver_id, now)
        .map_err(|_| String::from(REFUSED))?;
    if observation.did != expected_did {
        return Err(String::from(REFUSED));
    }
    Ok(())
}

fn encode_acceptance_projection<'a>(
    env: Env<'a>,
    projection: &CredentialV2AcceptanceProjection,
) -> Result<Term<'a>, String> {
    let permission_terms = projection
        .permissions
        .iter()
        .map(|value| binary(env, value.as_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut map = rustler::types::map::map_new(env);
    for (key, value) in [
        (
            application_id().encode(env),
            binary(env, projection.application_id.as_bytes())?,
        ),
        (
            profile_digest().encode(env),
            binary(env, &projection.profile_digest)?,
        ),
        (
            request_id().encode(env),
            binary(env, &projection.request_id)?,
        ),
        (
            carrier_ceremony_id().encode(env),
            binary(env, &projection.carrier_ceremony_id)?,
        ),
        (
            account_principal_digest().encode(env),
            binary(env, &projection.account_principal_digest)?,
        ),
        (
            account_scope_id().encode(env),
            binary(env, &projection.account_scope_id)?,
        ),
        (
            account().encode(env),
            binary(env, projection.account.as_bytes())?,
        ),
        (
            device_did().encode(env),
            binary(env, projection.device_did.as_bytes())?,
        ),
        (
            device_public_key().encode(env),
            binary(env, &projection.device_public_key)?,
        ),
        (
            offer_core_digest().encode(env),
            binary(env, &projection.offer_core_digest)?,
        ),
        (
            kid().encode(env),
            binary(env, projection.offer_kid.as_bytes())?,
        ),
        (
            payload_digest().encode(env),
            binary(env, &projection.payload_digest)?,
        ),
        (
            migration_confirmation_digest_atom().encode(env),
            binary(env, &projection.migration_confirmation_digest)?,
        ),
        (grant_id().encode(env), binary(env, &projection.grant_id)?),
        (
            credential_id().encode(env),
            binary(env, projection.credential_id.as_bytes())?,
        ),
        (
            issuer_did().encode(env),
            binary(env, projection.issuer_did.as_bytes())?,
        ),
        (raw_grant().encode(env), binary(env, &projection.raw_grant)?),
        (permissions().encode(env), permission_terms.encode(env)),
        (
            valid_until().encode(env),
            projection.valid_until.encode(env),
        ),
        (
            receipt_recovery_commitment().encode(env),
            binary(env, &projection.receipt_recovery_commitment)?,
        ),
        (
            final_status_jws().encode(env),
            binary(env, projection.final_status_jws.as_bytes())?,
        ),
        (
            final_status_digest().encode(env),
            binary(env, &projection.final_status_digest)?,
        ),
        (
            finalized_at().encode(env),
            projection.finalized_at.encode(env),
        ),
    ] {
        map = map.map_put(key, value).map_err(|_| String::from(REFUSED))?;
    }
    Ok(map)
}

/// Recognise and bind every profile-owned allocation field in one operation.
pub fn recognise_credential_v2_profile(
    profile_bytes: &[u8],
    application_context: &str,
    relay_origin: &str,
    requested_permissions: &[String],
    device_jwk: &[u8],
) -> Result<CredentialV2ProfileProjection, String> {
    let profile =
        ApplicationProfile::recognise(profile_bytes).map_err(|_| String::from(REFUSED))?;
    if profile.application_id.as_str() != application_context {
        return Err(String::from(REFUSED));
    }

    let mut matching = profile
        .cbcl_pairing_relays
        .iter()
        .filter(|descriptor| descriptor.relay_origin == relay_origin);
    let descriptor = matching.next().ok_or_else(|| String::from(REFUSED))?;
    if matching.next().is_some() {
        return Err(String::from(REFUSED));
    }

    recognise_permissions(&profile, requested_permissions)?;
    let device_public_key = recognise_device_jwk(device_jwk)?;
    let descriptor_bytes = canonical_descriptor(descriptor);

    Ok(CredentialV2ProfileProjection {
        application_id: profile.application_id.as_str().to_owned(),
        account_authority: profile.account_authority.clone(),
        profile_bytes: profile.canonical_bytes().to_vec(),
        profile_digest: *profile.digest(),
        descriptor_bytes,
        descriptor_digest: descriptor.digest,
        relay_origin: descriptor.relay_origin.clone(),
        requested_permissions: requested_permissions.to_vec(),
        device_jwk: device_jwk.to_vec(),
        device_public_key,
    })
}

fn recognise_permissions(profile: &ApplicationProfile, requested: &[String]) -> Result<(), String> {
    if requested.is_empty() || requested.len() > MAX_REQUESTED_PERMISSIONS {
        return Err(String::from(REFUSED));
    }
    let mut previous: Option<&[u8]> = None;
    for permission in requested {
        if permission.is_empty()
            || permission.len() > MAX_PERMISSION_OCTETS
            || !profile.allowed_permissions.contains(permission)
        {
            return Err(String::from(REFUSED));
        }
        if previous.is_some_and(|prior| prior >= permission.as_bytes()) {
            return Err(String::from(REFUSED));
        }
        previous = Some(permission.as_bytes());
    }
    Ok(())
}

fn recognise_device_jwk(octets: &[u8]) -> Result<[u8; 32], String> {
    let value = json::recognise(
        octets,
        Limits {
            max_bytes: MAX_DEVICE_JWK_OCTETS,
            max_depth: 1,
        },
    )
    .map_err(|_| String::from(REFUSED))?;
    if json::canonicalise(&value) != octets {
        return Err(String::from(REFUSED));
    }
    let Json::Object(members) = &value else {
        return Err(String::from(REFUSED));
    };
    if members.len() != 3
        || members
            .iter()
            .any(|(name, _)| !["crv", "kty", "x"].contains(&name.as_str()))
        || value.get("crv").and_then(Json::as_str) != Some("Ed25519")
        || value.get("kty").and_then(Json::as_str) != Some("OKP")
    {
        return Err(String::from(REFUSED));
    }
    codec::decode_b64url_32(
        value
            .get("x")
            .and_then(Json::as_str)
            .ok_or_else(|| String::from(REFUSED))?,
    )
    .map_err(|_| String::from(REFUSED))
}

fn canonical_descriptor(descriptor: &CbclRelayDescriptor) -> Vec<u8> {
    json::canonicalise(&Json::obj([
        (
            "conformanceEvidenceDigest",
            Json::text(codec::b64url(&descriptor.conformance_evidence_digest)),
        ),
        ("operatorId", Json::text(descriptor.operator_id.clone())),
        ("priority", Json::int(descriptor.priority)),
        (
            "privacyPolicyDigest",
            Json::text(codec::b64url(&descriptor.privacy_policy_digest)),
        ),
        ("relayOrigin", Json::text(descriptor.relay_origin.clone())),
        ("weight", Json::int(descriptor.weight)),
    ]))
}

/// `cbcl_selfsame_erl:prepare_credential_v2_offer/15`.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
#[rustler::nif(name = "prepare_credential_v2_offer", schedule = "DirtyCpu")]
pub fn prepare_credential_v2_offer_nif<'a>(
    env: Env<'a>,
    profile_bytes: Binary<'a>,
    carrier_bytes: Binary<'a>,
    request_id: Binary<'a>,
    transcript_hash: Binary<'a>,
    application_account_id: Binary<'a>,
    account_scope_id: Binary<'a>,
    device_public_key_value: Binary<'a>,
    permissions: Vec<Binary<'a>>,
    intent_nonce: Binary<'a>,
    issued_at: u64,
    expires_at: u64,
    legacy_handle: Binary<'a>,
    enrolled_key: Binary<'a>,
    snapshot_rows: Vec<(
        Binary<'a>,
        Binary<'a>,
        Binary<'a>,
        Binary<'a>,
        u64,
        Atom,
        Term<'a>,
    )>,
    snapshot_nonce: Binary<'a>,
) -> Term<'a> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let profile = ApplicationProfile::recognise(profile_bytes.as_slice())
            .map_err(|_| String::from(REFUSED))?;
        let carrier = cbcl_pairing::credential_v2::decode_carrier(carrier_bytes.as_slice())
            .map_err(|_| String::from(REFUSED))?;
        let permissions = permissions
            .iter()
            .map(|value| utf8(value.as_slice()))
            .collect::<Result<Vec<_>, _>>()?;
        let rows = snapshot_rows
            .into_iter()
            .map(|(primary, room, handle, key, granted, provenance, since)| {
                let provenance = if provenance == standing() {
                    CredentialV2RoomProvenance::Standing
                } else if provenance == invite() {
                    CredentialV2RoomProvenance::Invite
                } else {
                    return Err(String::from(REFUSED));
                };
                let since = if since.decode::<Atom>().ok() == Some(undefined()) {
                    None
                } else {
                    Some(u64::decode(since).map_err(|_| String::from(REFUSED))?)
                };
                Ok(CredentialV2RoomSnapshot {
                    raw_primary_key: primary.as_slice().to_vec(),
                    room: utf8(room.as_slice())?,
                    legacy_handle: utf8(handle.as_slice())?,
                    enrolled_key: exact(key.as_slice())?,
                    granted,
                    provenance,
                    since,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let input = CredentialV2OfferBuildInput {
            request_id: exact(request_id.as_slice())?,
            transcript_hash: exact(transcript_hash.as_slice())?,
            application_account_id: exact(application_account_id.as_slice())?,
            account_scope_id: exact(account_scope_id.as_slice())?,
            device_public_key: exact(device_public_key_value.as_slice())?,
            requested_permissions: permissions,
            intent_nonce: exact(intent_nonce.as_slice())?,
            issued_at,
            expires_at,
            legacy_handle: utf8(legacy_handle.as_slice())?,
            enrolled_key: exact(enrolled_key.as_slice())?,
            snapshot_rows: rows,
            snapshot_nonce: exact(snapshot_nonce.as_slice())?,
        };
        let prepared =
            prepare_offer_core(&profile, &carrier, &input).map_err(|_| String::from(REFUSED))?;
        encode_prepared_offer(env, &prepared)
    }));
    match result {
        Ok(Ok(value)) => (atom::ok(), value).encode(env),
        Ok(Err(_)) | Err(_) => (atom::error(), rejected()).encode(env),
    }
}

/// `cbcl_selfsame_erl:finalize_credential_v2_offer/8`.
///
/// The signing seed is not decoded until the exact installation-device proof
/// has been verified by the closed Rust recogniser.
#[allow(clippy::too_many_arguments)]
#[rustler::nif(name = "finalize_credential_v2_offer", schedule = "DirtyCpu")]
pub fn finalize_credential_v2_offer_nif<'a>(
    env: Env<'a>,
    profile_bytes: Binary<'a>,
    offer_core: Binary<'a>,
    socket_generation_digest: Binary<'a>,
    carrier_ceremony_id: Binary<'a>,
    device_public_key: Binary<'a>,
    device_possession_proof: Binary<'a>,
    signing_kid: Binary<'a>,
    signing_seed: Binary<'a>,
) -> Term<'a> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let profile = ApplicationProfile::recognise(profile_bytes.as_slice())
            .map_err(|_| String::from(REFUSED))?;
        let prepared = recognise_prepared_offer(&profile, offer_core.as_slice())
            .map_err(|_| String::from(REFUSED))?;
        let verified = verify_prepared_offer_device_proof(
            &profile,
            &prepared,
            exact(socket_generation_digest.as_slice())?,
            exact(carrier_ceremony_id.as_slice())?,
            exact(device_public_key.as_slice())?,
            exact(device_possession_proof.as_slice())?,
        )
        .map_err(|_| String::from(REFUSED))?;

        // Keep private-key decoding below the possession-proof hard stop.
        let signing_kid = utf8(signing_kid.as_slice())?;
        let seed: [u8; 32] = exact(signing_seed.as_slice())?;
        let built = finalize_verified_offer(
            &profile,
            &verified,
            &signing_kid,
            &ed25519_dalek::SigningKey::from_bytes(&seed),
        )
        .map_err(|_| String::from(REFUSED))?;
        encode_built_offer(env, &built)
    }));
    match result {
        Ok(Ok(value)) => (atom::ok(), value).encode(env),
        Ok(Err(_)) | Err(_) => (atom::error(), rejected()).encode(env),
    }
}

fn encode_prepared_offer<'a>(
    env: Env<'a>,
    prepared: &selfsame_pairing::credential_v2::PreparedCredentialV2Offer,
) -> Result<Term<'a>, String> {
    let mut map = rustler::types::map::map_new(env);
    for (key, value) in [
        (offer_core().encode(env), binary(env, &prepared.offer_core)?),
        (
            offer_core_digest().encode(env),
            binary(env, &prepared.offer_core_digest)?,
        ),
        (
            intent_digest().encode(env),
            binary(env, &prepared.intent_digest)?,
        ),
        (
            account_principal_digest().encode(env),
            binary(env, &prepared.account_principal_digest)?,
        ),
        (
            device_did().encode(env),
            binary(env, prepared.device_did.as_bytes())?,
        ),
        (
            device_key_digest().encode(env),
            binary(env, &prepared.device_key_digest)?,
        ),
        (
            legacy_key_digest().encode(env),
            binary(env, &prepared.legacy_key_digest)?,
        ),
        (
            room_set_digest().encode(env),
            binary(env, &prepared.room_set_digest)?,
        ),
        (
            migration_snapshot_digest().encode(env),
            binary(env, &prepared.migration_snapshot_digest)?,
        ),
    ] {
        map = map.map_put(key, value).map_err(|_| String::from(REFUSED))?;
    }
    Ok(map)
}

fn encode_built_offer<'a>(
    env: Env<'a>,
    built: &selfsame_pairing::credential_v2::BuiltCredentialV2Offer,
) -> Result<Term<'a>, String> {
    let mut map = rustler::types::map::map_new(env);
    for (key, value) in [
        (offer_core().encode(env), binary(env, &built.offer_core)?),
        (
            offer_core_digest().encode(env),
            binary(env, &built.offer_core_digest)?,
        ),
        (
            intent_digest().encode(env),
            binary(env, &built.intent_digest)?,
        ),
        (
            signed_offer().encode(env),
            binary(env, &built.signed_offer)?,
        ),
        (kid().encode(env), binary(env, built.kid.as_bytes())?),
        (
            account_principal_digest().encode(env),
            binary(env, &built.account_principal_digest)?,
        ),
        (
            device_did().encode(env),
            binary(env, built.device_did.as_bytes())?,
        ),
        (
            device_key_digest().encode(env),
            binary(env, &built.device_key_digest)?,
        ),
        (
            legacy_key_digest().encode(env),
            binary(env, &built.legacy_key_digest)?,
        ),
        (
            room_set_digest().encode(env),
            binary(env, &built.room_set_digest)?,
        ),
        (
            migration_snapshot_digest().encode(env),
            binary(env, &built.migration_snapshot_digest)?,
        ),
    ] {
        map = map.map_put(key, value).map_err(|_| String::from(REFUSED))?;
    }
    Ok(map)
}

fn utf8(input: &[u8]) -> Result<String, String> {
    std::str::from_utf8(input)
        .map(str::to_owned)
        .map_err(|_| String::from(REFUSED))
}

fn exact<const N: usize>(input: &[u8]) -> Result<[u8; N], String> {
    input.try_into().map_err(|_| String::from(REFUSED))
}

/// `cbcl_selfsame_erl:recognise_credential_v2_profile/5`.
#[rustler::nif(name = "recognise_credential_v2_profile", schedule = "DirtyCpu")]
pub fn recognise_credential_v2_profile_nif<'a>(
    env: Env<'a>,
    profile: Binary<'a>,
    application_context: Binary<'a>,
    relay: Binary<'a>,
    permissions: Vec<Binary<'a>>,
    jwk: Binary<'a>,
) -> Term<'a> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let application_context = std::str::from_utf8(application_context.as_slice())
            .map_err(|_| String::from(REFUSED))?;
        let relay = std::str::from_utf8(relay.as_slice()).map_err(|_| String::from(REFUSED))?;
        let permissions = permissions
            .into_iter()
            .map(|permission| {
                std::str::from_utf8(permission.as_slice())
                    .map(str::to_owned)
                    .map_err(|_| String::from(REFUSED))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let projection = recognise_credential_v2_profile(
            profile.as_slice(),
            application_context,
            relay,
            &permissions,
            jwk.as_slice(),
        )?;
        encode_projection(env, &projection)
    }));

    match result {
        Ok(Ok(projection)) => (atom::ok(), projection).encode(env),
        Ok(Err(_)) | Err(_) => (atom::error(), rejected()).encode(env),
    }
}

fn encode_projection<'a>(
    env: Env<'a>,
    projection: &CredentialV2ProfileProjection,
) -> Result<Term<'a>, String> {
    let permissions = projection
        .requested_permissions
        .iter()
        .map(|permission| binary(env, permission.as_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut map = rustler::types::map::map_new(env);
    for (key, value) in [
        (
            application_id().encode(env),
            binary(env, projection.application_id.as_bytes())?,
        ),
        (
            account_authority().encode(env),
            binary(env, projection.account_authority.as_bytes())?,
        ),
        (
            profile_bytes().encode(env),
            binary(env, &projection.profile_bytes)?,
        ),
        (
            profile_digest().encode(env),
            binary(env, &projection.profile_digest)?,
        ),
        (
            descriptor_bytes().encode(env),
            binary(env, &projection.descriptor_bytes)?,
        ),
        (
            descriptor_digest().encode(env),
            binary(env, &projection.descriptor_digest)?,
        ),
        (
            relay_origin().encode(env),
            binary(env, projection.relay_origin.as_bytes())?,
        ),
        (requested_permissions().encode(env), permissions.encode(env)),
        (
            device_jwk().encode(env),
            binary(env, &projection.device_jwk)?,
        ),
        (
            device_public_key().encode(env),
            binary(env, &projection.device_public_key)?,
        ),
    ] {
        map = map.map_put(key, value).map_err(|_| String::from(REFUSED))?;
    }
    Ok(map)
}

fn binary<'a>(env: Env<'a>, bytes: &[u8]) -> Result<Term<'a>, String> {
    let mut output = OwnedBinary::new(bytes.len()).ok_or_else(|| String::from(REFUSED))?;
    output.as_mut_slice().copy_from_slice(bytes);
    Ok(Binary::from_owned(output, env).encode(env))
}

fn encode_binary_result<'a>(
    env: Env<'a>,
    result: std::thread::Result<Result<Vec<u8>, String>>,
) -> Term<'a> {
    match result {
        Ok(Ok(bytes)) => match binary(env, &bytes) {
            Ok(value) => (atom::ok(), value).encode(env),
            Err(_) => (atom::error(), rejected()).encode(env),
        },
        Ok(Err(_)) | Err(_) => (atom::error(), rejected()).encode(env),
    }
}
