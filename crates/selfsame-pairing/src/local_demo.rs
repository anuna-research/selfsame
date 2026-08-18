//! Compile-time-gated credential evidence for the local application/APK demo.
//!
//! This module is intentionally absent unless `local-pairing-demo` is enabled.
//! It constructs a real signed Selfsame grant and every input to the thirteen-
//! step verifier; it does not bypass or replace that verifier.

#[path = "../../selfsame-app-identity/tests/common/mod.rs"]
mod fixture;

use selfsame_app_identity::{accept::Freshness, ceremony, json::Json, profile::ApplicationProfile};

use crate::{CredentialTransfer, IntegrationError, SelfsameProof, SelfsameVerificationContext};

/// Approved local conformance digest carried by the development profile.
pub const LOCAL_CONFORMANCE_DIGEST: [u8; 32] = [19; 32];

/// Complete deterministic values independently built by both local endpoints.
pub struct LocalDemoCredential {
    /// Application payload transferred only after approval.
    pub transfer: CredentialTransfer,
    /// Local authoritative inputs to the complete Selfsame verifier.
    pub verification: SelfsameVerificationContext,
}

/// Build the local credential fixture for one exact loopback relay origin.
pub fn credential(relay_origin: &str) -> Result<LocalDemoCredential, IntegrationError> {
    credential_fixture(relay_origin, false)
}

/// Exact profile octets the fixture recognises, for shells that must present
/// the profile at a boundary (the browser allocator) rather than hold the
/// recognised value.
#[must_use]
pub fn profile_octets(relay_origin: &str) -> Vec<u8> {
    fixture::with_member(
        "cbclPairingRelays",
        Json::arr([fixture::cbcl_relay(
            "local-development",
            relay_origin,
            1,
            1,
            3,
        )]),
    )
}

/// Build a fixture whose transferred grant signature was mutated after issue.
///
/// Pairing remains valid, but the authoritative Selfsame verifier must refuse
/// the credential and no wallet credential/session may be created.
pub fn credential_with_mutated_signature(
    relay_origin: &str,
) -> Result<LocalDemoCredential, IntegrationError> {
    credential_fixture(relay_origin, true)
}

fn credential_fixture(
    relay_origin: &str,
    mutate_signature: bool,
) -> Result<LocalDemoCredential, IntegrationError> {
    let example = fixture::Ceremony::accepted();
    let profile = profile_octets(relay_origin);
    let profile = ApplicationProfile::recognise(&profile).map_err(|_| IntegrationError::Profile)?;
    let mut grant = example.grant_bytes.clone();
    if mutate_signature {
        let last = grant.last_mut().ok_or(IntegrationError::Recognition)?;
        *last = if *last == b'A' { b'B' } else { b'A' };
    }
    let bundle = ceremony::build_bundle(
        &selfsame_app_identity::codec::b64url(&[21; 32]),
        &selfsame_app_identity::codec::b64url(&[22; 32]),
        core::str::from_utf8(&grant).map_err(|_| IntegrationError::Recognition)?,
        None,
    )
    .map_err(|_| IntegrationError::Recognition)?;
    Ok(LocalDemoCredential {
        transfer: CredentialTransfer {
            application_id: fixture::APPLICATION_ID.into(),
            origin: "https://photos.example".into(),
            scope: fixture::PERMISSION.into(),
            recipient: example.device_did.clone(),
            bundle,
        },
        verification: SelfsameVerificationContext {
            profile,
            account: example.account,
            device_public_key: example.device_public_key,
            operation_permissions: vec![fixture::PERMISSION.into()],
            now: example.now,
            clock_skew_seconds: 0,
            freshness: Freshness::SessionEstablishment,
            issuer: Some(example.issuer),
            jrd: Some(example.jrd),
            projection: None,
            proof: Some(SelfsameProof {
                challenge: example.challenge,
                signature: example.signature,
                verifier_session: fixture::VERIFIER_SESSION.into(),
            }),
        },
    })
}
