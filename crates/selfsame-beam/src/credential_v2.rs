//! Closed Selfsame recognition for credential/v2 hub allocation inputs.
//!
//! The BEAM shell supplies the exact profile bytes already served by the hub,
//! the application and relay copied from a canonical `cbcl-pairing` carrier,
//! and the two bounded browser inputs. This module returns one typed projection
//! or one opaque refusal; no partially parsed profile, descriptor, permission,
//! or device key crosses the NIF boundary.

use rustler::types::atom;
use rustler::{Atom, Binary, Decoder, Encoder, Env, OwnedBinary, Term};
use selfsame_app_identity::json::{Json, Limits};
use selfsame_app_identity::profile::{ApplicationProfile, CbclRelayDescriptor};
use selfsame_app_identity::{codec, json};
use selfsame_pairing::credential_v2::{
    finalize_verified_offer, prepare_offer_core, recognise_prepared_offer,
    verify_prepared_offer_device_proof, CredentialV2OfferBuildInput, CredentialV2RoomProvenance,
    CredentialV2RoomSnapshot,
};

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
    standing,
    invite,
    undefined,
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
