#[path = "../../selfsame-app-identity/tests/common/mod.rs"]
mod common;

use cbcl_pairing::credential_v2::{CredentialV2Carrier, CredentialV2CarrierInput};
use cbcl_selfsame_erl::credential_v2::{
    credential_v2_recovery_accepted, credential_v2_recovery_in_progress,
    credential_v2_recovery_unknown, prepare_credential_v2_acceptance,
    prepare_credential_v2_recovery_negative, recognise_credential_v2_profile,
    recognise_credential_v2_recovery_request, verify_credential_v2_staging_receipt,
    CredentialV2AcceptanceInput,
};
use cbcl_selfsame_erl::path_b::{
    verify_inactive_grant_pure, ResolverAssertionMethod, ResolverClosure,
};
use ed25519_dalek::{Signer, SigningKey};
use selfsame_app_identity::profile::ApplicationProfile;
use selfsame_app_identity::{alias, codec, didkey, grant, json, path_b::InactiveStagedGrant};
use selfsame_pairing::credential_v2::{
    browser_staging_signature_input, build_browser_staging_receipt,
    decode_receipt_recovery_response, device_possession_proof_input,
    encode_receipt_recovery_request, finalize_verified_offer, migration_confirmation_digest,
    prepare_offer_core, verify_prepared_offer_device_proof, CredentialV2BrowserStagingInput,
    CredentialV2OfferBuildInput, CredentialV2RecoveryNegativeInput, CredentialV2RecoveryResponse,
};

fn device_jwk(key: [u8; 32]) -> Vec<u8> {
    json::canonicalise(&json::Json::obj([
        ("crv", json::Json::text("Ed25519")),
        ("kty", json::Json::text("OKP")),
        ("x", json::Json::text(codec::b64url(&key))),
    ]))
}

#[test]
fn test_119_recovery_boundary_never_projects_the_secret_token() {
    let application_key = SigningKey::from_bytes(&[0xa1; 32]);
    let profile = credential_profile(&application_key);
    let application_id = profile.application_id.as_str();
    let ceremony = [0xa2; 32];
    let token = [0xa3; 32];
    let request = encode_receipt_recovery_request(application_id, ceremony, &token).unwrap();
    let projection = recognise_credential_v2_recovery_request(&request).unwrap();
    assert_eq!(projection.application_id, application_id);
    assert_eq!(projection.carrier_ceremony_id, ceremony);
    assert_ne!(projection.receipt_recovery_commitment, token);

    let accepted = credential_v2_recovery_accepted("e30.e30.AA", [0xa4; 32]).unwrap();
    assert!(matches!(
        decode_receipt_recovery_response(&accepted).unwrap(),
        CredentialV2RecoveryResponse::Accepted { .. }
    ));
    let progress = credential_v2_recovery_in_progress(1).unwrap();
    assert_eq!(
        decode_receipt_recovery_response(&progress).unwrap(),
        CredentialV2RecoveryResponse::InProgress {
            retry_after_seconds: 1
        }
    );
    let unknown = credential_v2_recovery_unknown().unwrap();
    assert_eq!(
        decode_receipt_recovery_response(&unknown).unwrap(),
        CredentialV2RecoveryResponse::Unknown
    );

    let kid = "https://photos.example/selfsame/application#credential-v2-test";
    let negative = prepare_credential_v2_recovery_negative(
        &profile,
        &CredentialV2RecoveryNegativeInput {
            application_id: application_id.into(),
            carrier_ceremony_id: ceremony,
            receipt_recovery_commitment: projection.receipt_recovery_commitment,
            observed_at: 1_800_000_900,
        },
        kid,
        &application_key,
    )
    .unwrap();
    assert!(matches!(
        decode_receipt_recovery_response(&negative).unwrap(),
        CredentialV2RecoveryResponse::NotFinalized { .. }
    ));
}

fn credential_profile(signing_key: &SigningKey) -> ApplicationProfile {
    let json::Json::Object(mut members) = common::profile_value() else {
        unreachable!()
    };
    let mobile = members
        .iter()
        .find(|(name, _)| name == "enrollment")
        .and_then(|(_, value)| value.get("mobileBindings"))
        .cloned()
        .unwrap();
    members
        .iter_mut()
        .find(|(name, _)| name == "enrollment")
        .unwrap()
        .1 = json::Json::obj([
        (
            "requestSigningKeys",
            json::Json::arr([json::Json::obj([
                (
                    "kid",
                    json::Json::text(
                        "https://photos.example/selfsame/application#credential-v2-test",
                    ),
                ),
                (
                    "publicKeyJwk",
                    common::jwk(signing_key.verifying_key().to_bytes()),
                ),
            ])]),
        ),
        ("mobileBindings", mobile),
    ]);
    ApplicationProfile::recognise(&json::canonicalise(&json::Json::Object(members))).unwrap()
}

fn resolver_closure(ceremony: &common::Ceremony, fetched_at_seconds: i64) -> ResolverClosure {
    ResolverClosure {
        resolver_id: ceremony.profile.state_resolvers[0].id.clone(),
        did: ceremony.issuer.did.clone(),
        did_recomputed_ok: ceremony.issuer.did_recomputed_ok,
        deltas_verified: ceremony.issuer.deltas_verified,
        locally_closed: ceremony.issuer.locally_closed,
        deactivated: ceremony.issuer.deactivated,
        assertion_methods: ceremony
            .issuer
            .assertion_methods
            .iter()
            .map(|method| ResolverAssertionMethod {
                id: method.id.clone(),
                kind: method.kind.clone(),
                public_key: method.jwk.public_key,
                has_private_component: method.has_private_component,
            })
            .collect(),
        revoked_credential_ids: ceremony.issuer.revoked_credential_ids.clone(),
        also_known_as: ceremony.issuer.also_known_as.clone(),
        fetched_at_seconds,
    }
}

#[test]
fn test_117_resolver_verification_uses_the_post_fetch_clock_and_refuses_future_evidence() {
    let ceremony = common::Ceremony::accepted();
    let permissions = vec![common::PERMISSION.to_string()];
    let fetched_after_decode = common::NOW + 1;
    let closure = resolver_closure(&ceremony, fetched_after_decode);

    // The command's earlier decode clock makes the sidecar observation future.
    assert!(verify_inactive_grant_pure(
        &common::profile_octets(),
        &ceremony.home_did,
        ceremony.account.as_str(),
        &ceremony.device_public_key,
        &permissions,
        common::NOW,
        0,
        &ceremony.grant_bytes,
        std::slice::from_ref(&closure),
    )
    .is_err());

    // Sampling after the sidecar returns admits the same real grant and
    // resolver facts. A later accepted retry uses its own current verifier
    // clock, independent of the historical signed-finalization timestamp.
    verify_inactive_grant_pure(
        &common::profile_octets(),
        &ceremony.home_did,
        ceremony.account.as_str(),
        &ceremony.device_public_key,
        &permissions,
        fetched_after_decode + 1,
        0,
        &ceremony.grant_bytes,
        std::slice::from_ref(&closure),
    )
    .expect("a post-fetch verifier clock must accept fresh resolver evidence");

    let future = resolver_closure(&ceremony, fetched_after_decode + 2);
    assert!(verify_inactive_grant_pure(
        &common::profile_octets(),
        &ceremony.home_did,
        ceremony.account.as_str(),
        &ceremony.device_public_key,
        &permissions,
        fetched_after_decode + 1,
        0,
        &ceremony.grant_bytes,
        &[future],
    )
    .is_err());
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
    let receipt =
        build_browser_staging_receipt(&input, key.verifying_key().to_bytes(), signature).unwrap();
    verify_credential_v2_staging_receipt(&input, key.verifying_key().to_bytes(), &receipt).unwrap();

    let mut changed = input.clone();
    changed.grant_id[0] ^= 1;
    assert!(verify_credential_v2_staging_receipt(
        &changed,
        key.verifying_key().to_bytes(),
        &receipt,
    )
    .is_err());
}

#[test]
fn test_117_acceptance_projection_requires_offer_grant_receipt_and_migration_agreement() {
    let application_key = SigningKey::from_bytes(&[0x31; 32]);
    let device_key = SigningKey::from_bytes(&[0x32; 32]);
    let profile = credential_profile(&application_key);
    let carrier = CredentialV2Carrier::new(CredentialV2CarrierInput {
        application_context: profile.application_id.as_str().into(),
        relay_origin: "https://cbcl-au.provider.example".into(),
        mailbox_id: [0x33; 32],
        carrier_ceremony_id: [0x34; 32],
        carrier_nonce: [0x35; 32],
        claim_commitment: [0x36; 32],
        relay_expires_at: 1_800_000_900,
        expected_allocator_key: Some(device_key.verifying_key().to_bytes()),
    })
    .unwrap();
    let prepared = prepare_offer_core(
        &profile,
        &carrier,
        &CredentialV2OfferBuildInput {
            request_id: [0x37; 32],
            transcript_hash: [0x38; 64],
            application_account_id: [0x39; 32],
            account_scope_id: [0x3a; 32],
            device_public_key: device_key.verifying_key().to_bytes(),
            requested_permissions: vec![common::PERMISSION.into()],
            intent_nonce: [0x3b; 32],
            issued_at: 1_800_000_300,
            expires_at: 1_800_000_900,
            legacy_handle: "@alice".into(),
            enrolled_key: [0x3c; 32],
            snapshot_rows: Vec::new(),
            snapshot_nonce: [0x3d; 32],
        },
    )
    .unwrap();
    let proof_input = device_possession_proof_input(
        [0x3e; 32],
        *carrier.carrier_ceremony_id(),
        prepared.offer_core_digest,
    )
    .unwrap();
    let verified = verify_prepared_offer_device_proof(
        &profile,
        &prepared,
        [0x3e; 32],
        *carrier.carrier_ceremony_id(),
        device_key.verifying_key().to_bytes(),
        device_key.sign(&proof_input).to_bytes(),
    )
    .unwrap();
    let kid = "https://photos.example/selfsame/application#credential-v2-test";
    let offer = finalize_verified_offer(&profile, &verified, kid, &application_key).unwrap();
    let issuer_did = format!("did:crdt:{}", "a".repeat(64));
    let grant_id = [0x3f; 32];
    let account = alias::stable_acct_uri(&issuer_did, &profile.account_authority);
    let staged = InactiveStagedGrant {
        account_did: issuer_did.clone(),
        account: account.clone(),
        grant_id: grant::identifiers(&issuer_did, &grant_id).0,
        grant_token: grant_id,
        device_did: offer.device_did.clone(),
        device_public_key: device_key.verifying_key().to_bytes(),
        permissions: vec![common::PERMISSION.into()],
        valid_until: 1_800_086_400,
    };
    let recognised =
        selfsame_pairing::credential_v2::recognise_signed_offer(&profile, &offer.signed_offer)
            .unwrap();
    let payload_digest = [0x41; 32];
    let commitment = [0x42; 32];
    let staging_input = CredentialV2BrowserStagingInput {
        application_id: profile.application_id.as_str().into(),
        carrier_ceremony_id: *carrier.carrier_ceremony_id(),
        account_principal_digest: offer.account_principal_digest,
        account_scope_id: [0x3a; 32],
        device_did: offer.device_did.clone(),
        offer_core_digest: offer.offer_core_digest,
        payload_digest,
        grant_id,
        issuer_did: issuer_did.clone(),
        profile_digest: *profile.digest(),
        receipt_recovery_commitment: commitment,
    };
    let receipt_signature = device_key
        .sign(&browser_staging_signature_input(&staging_input).unwrap())
        .to_bytes();
    let receipt = build_browser_staging_receipt(
        &staging_input,
        device_key.verifying_key().to_bytes(),
        receipt_signature,
    )
    .unwrap();
    let input = CredentialV2AcceptanceInput {
        raw_grant: b"e30.e30.AA".to_vec(),
        payload_digest,
        migration_confirmation_digest: migration_confirmation_digest(&recognised, &issuer_did)
            .unwrap(),
        issuer_did: issuer_did.clone(),
        grant_id,
        staging_receipt: receipt,
        receipt_recovery_commitment: commitment,
        finalized_at: 1_800_000_700,
        signing_kid: kid.into(),
    };
    let accepted = prepare_credential_v2_acceptance(
        &profile,
        &offer.signed_offer,
        &staged,
        &input,
        &application_key,
    )
    .unwrap();
    assert_eq!(accepted.account, account);
    assert_eq!(accepted.request_id, [0x37; 32]);
    assert!(!accepted.final_status_jws.is_empty());

    let mut changed = input;
    changed.migration_confirmation_digest[0] ^= 1;
    assert!(prepare_credential_v2_acceptance(
        &profile,
        &offer.signed_offer,
        &staged,
        &changed,
        &application_key,
    )
    .is_err());
}
