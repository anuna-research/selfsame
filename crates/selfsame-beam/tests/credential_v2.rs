#[path = "../../selfsame-app-identity/tests/common/mod.rs"]
mod common;

use cbcl_selfsame_erl::credential_v2::{
    recognise_credential_v2_profile, verify_credential_v2_staging_receipt,
};
use ed25519_dalek::{Signer, SigningKey};
use selfsame_app_identity::{codec, didkey, json};
use selfsame_pairing::credential_v2::{
    browser_staging_signature_input, build_browser_staging_receipt,
    CredentialV2BrowserStagingInput,
};

fn device_jwk(key: [u8; 32]) -> Vec<u8> {
    json::canonicalise(&json::Json::obj([
        ("crv", json::Json::text("Ed25519")),
        ("kty", json::Json::text("OKP")),
        ("x", json::Json::text(codec::b64url(&key))),
    ]))
}

#[test]
fn test_117_profile_projection_binds_application_relay_permissions_and_device_key() {
    let profile = common::profile_octets();
    let jwk = device_jwk([0x77; 32]);
    let projection = recognise_credential_v2_profile(
        &profile,
        common::APPLICATION_ID,
        "https://cbcl-au.provider.example",
        &[common::PERMISSION.to_string()],
        &jwk,
    )
    .unwrap();

    assert_eq!(projection.application_id, common::APPLICATION_ID);
    assert_eq!(projection.account_authority, common::ACCOUNT_AUTHORITY);
    assert_eq!(projection.relay_origin, "https://cbcl-au.provider.example");
    assert_eq!(projection.requested_permissions, [common::PERMISSION]);
    assert_eq!(projection.device_public_key, [0x77; 32]);
    assert_eq!(projection.device_jwk, jwk);
    assert_eq!(projection.profile_bytes, profile);
    assert_eq!(projection.profile_digest.len(), 32);
    assert_eq!(projection.descriptor_digest.len(), 32);
    assert!(!projection.descriptor_bytes.is_empty());
}

#[test]
fn test_117_profile_projection_refuses_every_caller_selected_binding() {
    let profile = common::profile_octets();
    let jwk = device_jwk([0x77; 32]);
    let permission = vec![common::PERMISSION.to_string()];

    assert!(recognise_credential_v2_profile(
        &profile,
        common::OTHER_APPLICATION_ID,
        "https://cbcl-au.provider.example",
        &permission,
        &jwk,
    )
    .is_err());
    assert!(recognise_credential_v2_profile(
        &profile,
        common::APPLICATION_ID,
        "https://attacker.example",
        &permission,
        &jwk,
    )
    .is_err());
    assert!(recognise_credential_v2_profile(
        &profile,
        common::APPLICATION_ID,
        "https://cbcl-au.provider.example",
        &["https://photos.example/selfsame/application#admin".into()],
        &jwk,
    )
    .is_err());
    assert!(recognise_credential_v2_profile(
        &profile,
        common::APPLICATION_ID,
        "https://cbcl-au.provider.example",
        &[
            common::PERMISSION.to_string(),
            common::PERMISSION.to_string(),
        ],
        &jwk,
    )
    .is_err());

    let noncanonical = format!(
        "{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{}\"}}",
        codec::b64url(&[0x77; 32])
    );
    assert!(recognise_credential_v2_profile(
        &profile,
        common::APPLICATION_ID,
        "https://cbcl-au.provider.example",
        &permission,
        noncanonical.as_bytes(),
    )
    .is_err());
    assert!(recognise_credential_v2_profile(
        &profile,
        common::APPLICATION_ID,
        "https://cbcl-au.provider.example",
        &permission,
        br#"{"alg":"EdDSA","crv":"Ed25519","kty":"OKP","x":"d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3c"}"#,
    )
    .is_err());
}

#[test]
fn test_117_staging_receipt_boundary_verifies_signature_and_every_held_fact() {
    let key = SigningKey::from_bytes(&[0x88; 32]);
    let input = CredentialV2BrowserStagingInput {
        application_id: common::APPLICATION_ID.into(),
        carrier_ceremony_id: [0x11; 32],
        account_principal_digest: [0x22; 32],
        account_scope_id: [0x33; 32],
        device_did: didkey::encode(&key.verifying_key().to_bytes()),
        offer_core_digest: [0x44; 32],
        payload_digest: [0x55; 32],
        grant_id: [0x66; 32],
        issuer_did: "did:crdt:z6MkBeamStagingIssuer".into(),
        profile_digest: [0x77; 32],
        receipt_recovery_commitment: [0x99; 32],
    };
    let signature = key
        .sign(&browser_staging_signature_input(&input).unwrap())
        .to_bytes();
    let receipt = build_browser_staging_receipt(
        &input,
        key.verifying_key().to_bytes(),
        signature,
    )
    .unwrap();
    verify_credential_v2_staging_receipt(
        &input,
        key.verifying_key().to_bytes(),
        &receipt,
    )
    .unwrap();

    let mut changed = input.clone();
    changed.grant_id[0] ^= 1;
    assert!(verify_credential_v2_staging_receipt(
        &changed,
        key.verifying_key().to_bytes(),
        &receipt,
    )
    .is_err());
}
