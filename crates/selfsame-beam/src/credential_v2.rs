//! Closed Selfsame recognition for credential/v2 hub allocation inputs.
//!
//! The BEAM shell supplies the exact profile bytes already served by the hub,
//! the application and relay copied from a canonical `cbcl-pairing` carrier,
//! and the two bounded browser inputs. This module returns one typed projection
//! or one opaque refusal; no partially parsed profile, descriptor, permission,
//! or device key crosses the NIF boundary.

use rustler::types::atom;
use rustler::{Binary, Encoder, Env, OwnedBinary, Term};
use selfsame_app_identity::json::{Json, Limits};
use selfsame_app_identity::profile::{ApplicationProfile, CbclRelayDescriptor};
use selfsame_app_identity::{codec, json};

const MAX_DEVICE_JWK_OCTETS: usize = 96;
const MAX_PERMISSION_OCTETS: usize = 128;
const MAX_REQUESTED_PERMISSIONS: usize = 4;
const REFUSED: &str = "rejected";

rustler::atoms! {
    rejected,
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
