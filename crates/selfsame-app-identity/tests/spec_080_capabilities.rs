//! cbcl-bus SPEC-080 CON-004 / SPEC-004 CON-201: the OPTIONAL closed
//! `capabilities` member of the application profile.

mod common;

use common::{profile_octets, with_member};
use selfsame_app_identity::{
    json::Json,
    profile::{ApplicationProfile, ProfileError, CAPABILITY_CREDENTIAL_V2_ACCOUNT_SELECT},
};

fn reject(octets: &[u8]) -> ProfileError {
    ApplicationProfile::recognise(octets).expect_err("profile must refuse")
}

#[test]
fn an_absent_member_advertises_nothing() {
    let profile = ApplicationProfile::recognise(&profile_octets()).unwrap();
    assert!(profile.capabilities.is_empty());
    assert!(!profile.advertises_credential_v2_account_select());
}

#[test]
fn the_account_select_capability_is_recognised_and_advertised() {
    let octets = with_member(
        "capabilities",
        Json::arr([Json::text(CAPABILITY_CREDENTIAL_V2_ACCOUNT_SELECT)]),
    );
    let profile = ApplicationProfile::recognise(&octets).unwrap();
    assert_eq!(
        profile.capabilities,
        vec![CAPABILITY_CREDENTIAL_V2_ACCOUNT_SELECT.to_string()]
    );
    assert!(profile.advertises_credential_v2_account_select());
    // An empty list is a valid encoding of "none".
    let none = ApplicationProfile::recognise(&with_member("capabilities", Json::arr([]))).unwrap();
    assert!(!none.advertises_credential_v2_account_select());
}

#[test]
fn every_shape_outside_the_closed_vocabulary_refuses() {
    let known = Json::text(CAPABILITY_CREDENTIAL_V2_ACCOUNT_SELECT);
    let cases: Vec<(&str, Json)> = vec![
        (
            "not an array",
            Json::text("credential-v2-account-select/v1"),
        ),
        (
            "unknown token",
            Json::arr([Json::text("credential-v2-account-select/v2")]),
        ),
        ("numeric entry", Json::arr([Json::int(1)])),
        ("duplicate", Json::arr([known.clone(), known.clone()])),
        (
            "nine entries",
            Json::arr([
                known.clone(),
                known.clone(),
                known.clone(),
                known.clone(),
                known.clone(),
                known.clone(),
                known.clone(),
                known.clone(),
                known.clone(),
            ]),
        ),
    ];
    for (name, value) in cases {
        assert!(
            matches!(
                reject(&with_member("capabilities", value)),
                ProfileError::BadValue { ref path, .. } if path == "capabilities"
            ),
            "{name}"
        );
    }
}
