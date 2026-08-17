mod common;

use common::{cbcl_relay, profile_value, with_member};
use selfsame_app_identity::{
    cbcl_relay::{self, RelayPolicy, RelaySelectionError},
    codec,
    json::Json,
    profile::{ApplicationProfile, ProfileError},
};

fn profile() -> ApplicationProfile {
    ApplicationProfile::recognise(&common::profile_octets()).unwrap()
}

#[test]
fn test_817_profile_rejects_closed_grammar_and_uniqueness_failures() {
    let unknown = cbcl_relay("one", "https://one.example", 1, 1, 1);
    let Json::Object(mut members) = unknown else {
        unreachable!()
    };
    members.push(("surprise".into(), Json::int(1)));
    let octets = with_member("cbclPairingRelays", Json::arr([Json::Object(members)]));
    assert!(matches!(
        ApplicationProfile::recognise(&octets),
        Err(ProfileError::UnknownMember(path)) if path == "cbclPairingRelays[].surprise"
    ));

    for descriptors in [
        Json::arr([
            cbcl_relay("same", "https://one.example", 1, 1, 1),
            cbcl_relay("same", "https://two.example", 1, 1, 2),
        ]),
        Json::arr([
            cbcl_relay("one", "https://same.example", 1, 1, 1),
            cbcl_relay("two", "https://same.example", 1, 1, 2),
        ]),
    ] {
        assert!(matches!(
            ApplicationProfile::recognise(&with_member("cbclPairingRelays", descriptors)),
            Err(ProfileError::BadValue { path, .. }) if path == "cbclPairingRelays"
        ));
    }

    let zero = Json::arr([cbcl_relay("one", "https://one.example", 1, 0, 1)]);
    assert!(matches!(
        ApplicationProfile::recognise(&with_member("cbclPairingRelays", zero)),
        Err(ProfileError::BadValue { path, .. }) if path == "cbclPairingRelays[].weight"
    ));

    let mut invalid_digest = profile_value();
    let Json::Object(root) = &mut invalid_digest else {
        unreachable!()
    };
    let relays = root
        .iter_mut()
        .find(|(name, _)| name == "cbclPairingRelays")
        .unwrap();
    let Json::Array(items) = &mut relays.1 else {
        unreachable!()
    };
    let Json::Object(first) = &mut items[0] else {
        unreachable!()
    };
    first
        .iter_mut()
        .find(|(name, _)| name == "conformanceEvidenceDigest")
        .unwrap()
        .1 = Json::text("not-a-digest");
    let octets = selfsame_app_identity::json::canonicalise(&invalid_digest);
    assert!(matches!(
        ApplicationProfile::recognise(&octets),
        Err(ProfileError::BadValue { path, .. })
            if path == "cbclPairingRelays[].conformanceEvidenceDigest"
    ));
}

#[test]
fn test_817_selection_requires_evidence_and_uses_lowest_priority_weights() {
    let profile = profile();
    let approved = [[17; 32], [18; 32]];
    let policy = RelayPolicy {
        forbidden_operator_ids: &[],
        approved_conformance: &approved,
        allow_loopback: false,
    };
    assert_eq!(
        cbcl_relay::select(&profile, &policy, 0)
            .unwrap()
            .operator_id,
        "au-primary"
    );
    assert_eq!(
        cbcl_relay::select(&profile, &policy, u64::MAX)
            .unwrap()
            .operator_id,
        "au-primary",
        "higher priorities are not a fallback within one attempt"
    );

    let missing = RelayPolicy {
        approved_conformance: &[],
        ..policy
    };
    assert_eq!(
        cbcl_relay::select(&profile, &missing, 0),
        Err(RelaySelectionError::NoEligibleRelay)
    );
    let forbidden = RelayPolicy {
        forbidden_operator_ids: &["au-primary"],
        ..policy
    };
    assert_eq!(
        cbcl_relay::select(&profile, &forbidden, 0)
            .unwrap()
            .operator_id,
        "global-secondary"
    );
}

#[test]
fn test_817_claimant_requires_the_exact_eligible_invitation_origin() {
    let profile = profile();
    let approved = [[17; 32], [18; 32]];
    let policy = RelayPolicy {
        forbidden_operator_ids: &[],
        approved_conformance: &approved,
        allow_loopback: false,
    };
    assert_eq!(
        cbcl_relay::verify_invitation_origin(&profile, &policy, "https://cbcl-au.provider.example"),
        Ok(())
    );
    assert_eq!(
        cbcl_relay::verify_invitation_origin(&profile, &policy, "https://attacker.example"),
        Err(RelaySelectionError::InvitationOrigin)
    );

    let loopback = with_member(
        "cbclPairingRelays",
        Json::arr([cbcl_relay("local", "https://localhost:8443", 1, 1, 3)]),
    );
    let loopback = ApplicationProfile::recognise(&loopback).unwrap();
    let approved = [[19; 32]];
    let production = RelayPolicy {
        forbidden_operator_ids: &[],
        approved_conformance: &approved,
        allow_loopback: false,
    };
    assert_eq!(
        cbcl_relay::select(&loopback, &production, 0),
        Err(RelaySelectionError::NoEligibleRelay)
    );
    assert!(cbcl_relay::select(
        &loopback,
        &RelayPolicy {
            allow_loopback: true,
            ..production
        },
        0
    )
    .is_ok());
}

#[test]
fn test_818_fixture_digests_are_exact_canonical_sha256_values() {
    let profile = profile();
    assert_eq!(
        codec::b64url(&profile.cbcl_pairing_relays[0].privacy_policy_digest),
        codec::b64url(&[1; 32])
    );
    assert_eq!(
        codec::b64url(&profile.cbcl_pairing_relays[0].conformance_evidence_digest),
        codec::b64url(&[17; 32])
    );
}
