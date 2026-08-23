#[path = "../../selfsame-app-identity/tests/common/mod.rs"]
mod common;

use cbcl_selfsame_erl::credential_v2::recognise_credential_v2_profile;
use selfsame_app_identity::{codec, json};

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
