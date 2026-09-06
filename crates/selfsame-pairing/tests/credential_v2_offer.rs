//! Cross-consumer signed OfferCoreV2 construction and recognition.

#[path = "../../selfsame-app-identity/tests/common/mod.rs"]
mod fixture;

use cbcl_pairing::credential_v2::{
    CredentialV2Advance, CredentialV2BodyVerifier, CredentialV2Carrier, CredentialV2CarrierInput,
    CredentialV2ClaimantOfferVerifier, CredentialV2Endpoint, CredentialV2Error, CredentialV2Kind,
    CredentialV2LogicalBody, CredentialV2Object, CredentialV2TofuState,
};
use cbcl_pairing::wire::Side;
use ed25519_dalek::SigningKey;
use selfsame_app_identity::{json, json::Json, profile::ApplicationProfile};
use selfsame_pairing::credential_v2::{
    build_authority_status_response, build_final_status, build_recovery_not_finalized,
    credential_v2_body_authority, credential_v2_body_authority_for_restore,
    credential_v2_receipt_recovery_commitment, decode_receipt_recovery_response,
    device_possession_proof_input, encode_receipt_recovery_request,
    encode_receipt_recovery_response, finalize_verified_offer, migration_confirmation_digest,
    prepare_offer_core, recognise_authority_status_response, recognise_final_status,
    recognise_final_status_with_embedded_time, recognise_prepared_offer, recognise_receipt,
    recognise_receipt_recovery_request, recognise_recovery_not_finalized,
    recognise_recovery_not_finalized_status, recognise_signed_offer, recovered_receipt_object,
    verify_prepared_offer_device_proof, CredentialV2AuthorityStatus, CredentialV2FinalDecision,
    CredentialV2FinalStatusInput, CredentialV2IntentDecision, CredentialV2OfferBuildInput,
    CredentialV2PayloadInput, CredentialV2ReceiptInput, CredentialV2RecoveryNegativeInput,
    CredentialV2RecoveryResponse, CredentialV2WalletOfferVerifier,
};
use sha2::{Digest, Sha256};

const RELAY: &str = "https://photos.example:9443";
const KID: &str = "https://photos.example/selfsame/application#credential-v2-test";
#[path = "../../../src-tauri/src/cbcl_v2_comparison_test_inputs.rs"]
mod comparison_inputs;

#[derive(Debug)]
struct AcceptBodies;

impl CredentialV2BodyVerifier for AcceptBodies {
    fn verify(&mut self, _: &CredentialV2LogicalBody<'_>) -> Result<(), CredentialV2Error> {
        Ok(())
    }
}

fn profile(signing_key: &SigningKey) -> ApplicationProfile {
    let Json::Object(mut members) = fixture::profile_value() else {
        unreachable!()
    };
    let mobile = members
        .iter()
        .find(|(name, _)| name == "enrollment")
        .and_then(|(_, value)| value.get("mobileBindings"))
        .cloned()
        .unwrap();
    let enrollment = Json::obj([
        (
            "requestSigningKeys",
            Json::arr([Json::obj([
                (
                    "kid",
                    Json::text("https://photos.example/selfsame/application#credential-v2-test"),
                ),
                (
                    "publicKeyJwk",
                    fixture::jwk(signing_key.verifying_key().to_bytes()),
                ),
            ])]),
        ),
        ("mobileBindings", mobile),
    ]);
    for (name, value) in [
        ("enrollment", enrollment),
        (
            "cbclPairingRelays",
            Json::arr([fixture::cbcl_relay("test-operator", RELAY, 1, 1, 9)]),
        ),
    ] {
        members
            .iter_mut()
            .find(|(candidate, _)| candidate == name)
            .unwrap()
            .1 = value;
    }
    ApplicationProfile::recognise(&json::canonicalise(&Json::Object(members))).unwrap()
}

#[test]
fn offer_is_one_canonical_signed_authority_for_hub_browser_and_wallet() {
    let offer_signing_key = SigningKey::from_bytes(&[0x21; 32]);
    let device_key = SigningKey::from_bytes(&[0x22; 32])
        .verifying_key()
        .to_bytes();
    let profile = profile(&offer_signing_key);
    let carrier = CredentialV2Carrier::new(CredentialV2CarrierInput {
        application_context: profile.application_id.as_str().into(),
        relay_origin: RELAY.into(),
        mailbox_id: [0x31; 32],
        carrier_ceremony_id: [0x32; 32],
        carrier_nonce: [0x33; 32],
        claim_commitment: [0x34; 32],
        relay_expires_at: 1_800_000_900,
        expected_allocator_key: Some(device_key),
    })
    .unwrap();
    let input = CredentialV2OfferBuildInput {
        request_id: [0x41; 32],
        transcript_hash: [0x42; 64],
        application_account_id: [0x43; 32],
        account_scope_id: [0x44; 32],
        device_public_key: device_key,
        requested_permissions: vec![fixture::PERMISSION.into()],
        intent_nonce: [0x45; 32],
        issued_at: 1_800_000_300,
        expires_at: 1_800_000_900,
        legacy_handle: "@alice".into(),
        enrolled_key: [0x46; 32],
        snapshot_rows: Vec::new(),
        snapshot_nonce: [0x47; 32],
    };
    let kid = "https://photos.example/selfsame/application#credential-v2-test";
    // Preparation has no signing-key argument and produces no signed bytes.
    let prepared = prepare_offer_core(&profile, &carrier, &input).unwrap();
    assert_eq!(
        recognise_prepared_offer(&profile, &prepared.offer_core).unwrap(),
        prepared
    );
    let socket_generation_digest = [0x48; 32];
    let device_signing_key = SigningKey::from_bytes(&[0x22; 32]);
    let proof_input = device_possession_proof_input(
        socket_generation_digest,
        *carrier.carrier_ceremony_id(),
        prepared.offer_core_digest,
    )
    .unwrap();
    use ed25519_dalek::Signer as _;
    let proof = device_signing_key.sign(&proof_input).to_bytes();
    let mut wrong_proof = proof;
    wrong_proof[0] ^= 1;
    assert!(verify_prepared_offer_device_proof(
        &profile,
        &prepared,
        socket_generation_digest,
        *carrier.carrier_ceremony_id(),
        device_key,
        wrong_proof,
    )
    .is_err());
    let verified = verify_prepared_offer_device_proof(
        &profile,
        &prepared,
        socket_generation_digest,
        *carrier.carrier_ceremony_id(),
        device_key,
        proof,
    )
    .unwrap();
    let wrong_signing_key = SigningKey::from_bytes(&[0x23; 32]);
    assert!(finalize_verified_offer(&profile, &verified, kid, &wrong_signing_key).is_err());

    let built = finalize_verified_offer(&profile, &verified, kid, &offer_signing_key).unwrap();
    let recognised = recognise_signed_offer(&profile, &built.signed_offer).unwrap();

    assert_eq!(recognised.offer_core, built.offer_core);
    assert_eq!(recognised.kid, kid);
    assert_eq!(
        recognised.claims.offer_core_digest(),
        &built.offer_core_digest
    );
    assert_eq!(
        recognised.claims.application_id(),
        profile.application_id.as_str()
    );
    assert_eq!(recognised.claims.relay_origin(), RELAY);
    assert_eq!(recognised.claims.carrier_ceremony_id(), &[0x32; 32]);
    assert_eq!(recognised.claims.permissions(), &[fixture::PERMISSION]);
    assert_eq!(
        recognised.claims.device_binding().device_did(),
        built.device_did
    );
    assert_eq!(recognised.request_id, input.request_id);
    assert_eq!(recognised.carrier_digest, carrier.digest());
    assert_eq!(recognised.intent_nonce, input.intent_nonce);
    assert_eq!(recognised.transcript_hash, input.transcript_hash);
    assert_eq!(recognised.expires_at, input.expires_at);

    // The wallet display is created only after the signed offer is verified
    // under the live profile and every local carrier/transcript value matches.
    let object = CredentialV2Object::new(
        CredentialV2Kind::Offer,
        built.intent_digest,
        built.signed_offer.clone(),
    )
    .unwrap();
    let mut endpoint =
        CredentialV2Endpoint::new(Side::Claimant, carrier.clone(), Box::new(AcceptBodies));
    let mut wallet_verifier = CredentialV2WalletOfferVerifier::new(
        profile.clone(),
        carrier.clone(),
        input.transcript_hash,
        CredentialV2TofuState::NewPair,
    )
    .unwrap();
    let CredentialV2Advance::DisplayIntent(display) = wallet_verifier
        .verify_offer(&mut endpoint, &object, input.expires_at - 1)
        .unwrap()
    else {
        panic!("a verified offer must produce the authenticated typed display")
    };
    assert_eq!(display.application_id(), profile.application_id.as_str());
    assert_eq!(display.relay_origin(), RELAY);
    assert_eq!(display.tofu_state(), CredentialV2TofuState::NewPair);

    for (transcript, now) in [
        ([0xff; 64], input.expires_at - 1),
        (input.transcript_hash, input.expires_at),
    ] {
        let mut endpoint =
            CredentialV2Endpoint::new(Side::Claimant, carrier.clone(), Box::new(AcceptBodies));
        let mut refused = CredentialV2WalletOfferVerifier::new(
            profile.clone(),
            carrier.clone(),
            transcript,
            CredentialV2TofuState::TrustedPair,
        )
        .unwrap();
        assert_eq!(
            refused.verify_offer(&mut endpoint, &object, now),
            Err(CredentialV2Error::Profile),
        );
    }

    let mut changed = built.signed_offer.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(recognise_signed_offer(&profile, &changed).is_err());

    let authority = build_authority_status_response(
        &profile,
        *carrier.carrier_ceremony_id(),
        built.offer_core_digest,
        &CredentialV2AuthorityStatus::NoBinding,
        kid,
        &offer_signing_key,
    )
    .unwrap();
    assert_eq!(
        authority.digest,
        <[u8; 32]>::from(Sha256::digest(&authority.response))
    );
    assert_eq!(
        recognise_authority_status_response(
            &profile,
            &authority.response,
            kid,
            *carrier.carrier_ceremony_id(),
            built.offer_core_digest,
        )
        .unwrap(),
        CredentialV2AuthorityStatus::NoBinding
    );
    assert!(recognise_authority_status_response(
        &profile,
        &authority.response,
        kid,
        [0x33; 32],
        built.offer_core_digest,
    )
    .is_err());
    assert!(recognise_authority_status_response(
        &profile,
        &authority.response,
        kid,
        *carrier.carrier_ceremony_id(),
        [0x44; 32],
    )
    .is_err());
    let mut changed_authority = authority.response.clone();
    *changed_authority.last_mut().unwrap() ^= 1;
    assert!(recognise_authority_status_response(
        &profile,
        &changed_authority,
        kid,
        *carrier.carrier_ceremony_id(),
        built.offer_core_digest,
    )
    .is_err());
    assert!(build_authority_status_response(
        &profile,
        *carrier.carrier_ceremony_id(),
        built.offer_core_digest,
        &CredentialV2AuthorityStatus::NoBinding,
        kid,
        &wrong_signing_key,
    )
    .is_err());
    assert!(build_authority_status_response(
        &profile,
        *carrier.carrier_ceremony_id(),
        built.offer_core_digest,
        &CredentialV2AuthorityStatus::Bound("did:crdt:bad DID".into()),
        kid,
        &offer_signing_key,
    )
    .is_err());

    let (checkpoint_authority, checkpoint_verifier) = credential_v2_body_authority();
    checkpoint_authority
        .bind_offer(profile.clone(), &recognised)
        .unwrap();
    let authority_checkpoint = checkpoint_verifier.checkpoint_state().unwrap();
    assert!(!authority_checkpoint.is_empty());
    let (restored_authority, mut restored_verifier) =
        credential_v2_body_authority_for_restore(profile.clone());
    restored_verifier
        .restore_checkpoint_state(&authority_checkpoint)
        .unwrap();
    assert!(restored_authority
        .intent_decision(&object, CredentialV2IntentDecision::Approve)
        .is_ok());
    let mut changed_checkpoint = authority_checkpoint;
    *changed_checkpoint.last_mut().unwrap() ^= 1;
    let (_, mut refused_verifier) = credential_v2_body_authority_for_restore(profile.clone());
    assert!(refused_verifier
        .restore_checkpoint_state(&changed_checkpoint)
        .is_err());

    let checkpoint_approve = checkpoint_authority
        .intent_decision(&object, CredentialV2IntentDecision::Approve)
        .unwrap();
    let checkpoint_preview = format!("did:crdt:{}", "c".repeat(64));
    let checkpoint_preparation = checkpoint_authority
        .preparation(&checkpoint_approve, &checkpoint_preview)
        .unwrap();
    let checkpoint_comparison = checkpoint_authority
        .comparison(&checkpoint_preparation, &authority.response)
        .unwrap();
    let checkpoint_final = checkpoint_authority
        .final_decision(&checkpoint_comparison, CredentialV2FinalDecision::Approve)
        .unwrap();
    let large_grant = format!("e30.{}.AA", "A".repeat(48_000));
    let checkpoint_payload = checkpoint_authority
        .payload(
            &checkpoint_final,
            CredentialV2PayloadInput {
                grant_id: [0x48; 32],
                grant: large_grant.clone(),
            },
        )
        .unwrap();
    let compact_authority_checkpoint = checkpoint_verifier.checkpoint_state().unwrap();
    assert!(
        compact_authority_checkpoint.len() < 4_096,
        "the endpoint owns the sole large payload copy"
    );
    let (payload_restored_authority, mut payload_restored_verifier) =
        credential_v2_body_authority_for_restore(profile.clone());
    payload_restored_verifier
        .restore_checkpoint_state(&compact_authority_checkpoint)
        .unwrap();
    payload_restored_authority
        .require_bound_offer(&profile, &recognised)
        .unwrap();
    assert!(payload_restored_authority.retained_payload().is_err());
    payload_restored_authority
        .restore_retained_received_object(&checkpoint_payload)
        .unwrap();
    assert_eq!(
        payload_restored_authority
            .retained_payload()
            .unwrap()
            .grant(),
        large_grant
    );

    let (browser_bodies, browser_body_verifier) = credential_v2_body_authority();
    let (wallet_bodies, wallet_body_verifier) = credential_v2_body_authority();
    browser_bodies
        .bind_offer(profile.clone(), &recognised)
        .unwrap();
    assert!(wallet_bodies
        .intent_decision(&object, CredentialV2IntentDecision::Approve)
        .is_err());
    let mut allocator = CredentialV2Endpoint::new(
        Side::Allocator,
        carrier.clone(),
        Box::new(browser_body_verifier),
    );
    let mut claimant = CredentialV2Endpoint::new(
        Side::Claimant,
        carrier.clone(),
        Box::new(wallet_body_verifier),
    );
    allocator.send(&object).unwrap();
    let mut offer_verifier = CredentialV2WalletOfferVerifier::new(
        profile.clone(),
        carrier.clone(),
        input.transcript_hash,
        CredentialV2TofuState::NewPair,
    )
    .unwrap()
    .with_body_authority(wallet_bodies.clone());
    offer_verifier
        .verify_offer(&mut claimant, &object, input.expires_at - 1)
        .unwrap();
    assert!(wallet_bodies
        .bind_offer(profile.clone(), &recognised)
        .is_err());

    let approve = wallet_bodies
        .intent_decision(&object, CredentialV2IntentDecision::Approve)
        .unwrap();
    exchange(&mut claimant, &mut allocator, &approve);
    let preview_did = format!("did:crdt:{}", "a".repeat(64));
    let preparation = wallet_bodies.preparation(&approve, &preview_did).unwrap();
    exchange(&mut claimant, &mut allocator, &preparation);
    let retained_preview = browser_bodies.retained_preview().unwrap();
    assert_eq!(retained_preview.did(), preview_did);
    assert_eq!(
        retained_preview.fingerprint_digest(),
        &<[u8; 32]>::from(Sha256::digest(preview_did.as_bytes()))
    );
    assert!(wallet_bodies
        .preparation(&approve, &format!("did:crdt:{}", "b".repeat(64)))
        .is_err());
    let comparison = browser_bodies
        .comparison(&preparation, &authority.response)
        .unwrap();
    assert_eq!(comparison.kind(), CredentialV2Kind::ComparisonConfirmed);
    exchange(&mut allocator, &mut claimant, &comparison);
    let final_approve = wallet_bodies
        .final_decision(&comparison, CredentialV2FinalDecision::Approve)
        .unwrap();
    exchange(&mut claimant, &mut allocator, &final_approve);
    let payload = wallet_bodies
        .payload(
            &final_approve,
            CredentialV2PayloadInput {
                grant_id: [0x49; 32],
                grant: "e30.e30.AA".into(),
            },
        )
        .unwrap();
    exchange(&mut claimant, &mut allocator, &payload);
    let retained_payload = browser_bodies.retained_payload().unwrap();
    assert_eq!(
        retained_payload.offer_core_digest(),
        &built.offer_core_digest
    );
    assert_eq!(retained_payload.preview_issuer_did(), preview_did);
    assert_eq!(
        retained_payload.preview_fingerprint_digest(),
        &<[u8; 32]>::from(Sha256::digest(preview_did.as_bytes()))
    );
    assert_eq!(
        retained_payload.account_principal_digest(),
        recognised
            .claims
            .account_provenance()
            .account_principal_digest()
    );
    assert_eq!(retained_payload.account_scope_id(), &[0x44; 32]);
    assert_eq!(
        retained_payload.device_did(),
        recognised.claims.device_binding().device_did()
    );
    assert_eq!(retained_payload.grant_id(), &[0x49; 32]);
    assert_eq!(retained_payload.grant(), "e30.e30.AA");
    assert_eq!(
        retained_payload.migration_confirmation_digest(),
        &migration_confirmation_digest(&recognised, &preview_did).unwrap(),
    );
    assert!(wallet_bodies
        .payload(
            &final_approve,
            CredentialV2PayloadInput {
                grant_id: [0x49; 32],
                grant: "not-a-jws".into(),
            },
        )
        .is_err());

    let final_status_jws = String::from("e30.e30.AA");
    let final_status_digest: [u8; 32] = Sha256::digest(b"{}").into();
    let receipt = browser_bodies
        .receipt(
            &payload,
            CredentialV2ReceiptInput {
                final_status_jws,
                final_status_digest,
            },
        )
        .unwrap();
    exchange(&mut allocator, &mut claimant, &receipt);
    assert_eq!(receipt.kind(), CredentialV2Kind::Receipt);
    let recognised_receipt = recognise_receipt(
        &receipt,
        *carrier.carrier_ceremony_id(),
        payload.content_hash(),
    )
    .unwrap();
    assert_eq!(recognised_receipt.final_status_digest, final_status_digest);
    assert_eq!(recognised_receipt.final_status_jws, "e30.e30.AA");

    let bound = CredentialV2AuthorityStatus::Bound(format!("did:crdt:{}", "a".repeat(64)));
    let bound_authority = build_authority_status_response(
        &profile,
        *carrier.carrier_ceremony_id(),
        built.offer_core_digest,
        &bound,
        kid,
        &offer_signing_key,
    )
    .unwrap();
    assert_eq!(
        recognise_authority_status_response(
            &profile,
            &bound_authority.response,
            kid,
            *carrier.carrier_ceremony_id(),
            built.offer_core_digest,
        )
        .unwrap(),
        bound
    );
}

#[test]
fn final_status_is_one_closed_jws_bound_to_every_accepted_fact() {
    let signing_key = SigningKey::from_bytes(&[0x71; 32]);
    let profile = profile(&signing_key);
    let kid = "https://photos.example/selfsame/application#credential-v2-test";
    let input = CredentialV2FinalStatusInput {
        application_id: profile.application_id.as_str().into(),
        carrier_ceremony_id: [0x72; 32],
        request_id: [0x73; 32],
        account_principal_digest: [0x74; 32],
        account_scope_id: [0x75; 32],
        device_did: selfsame_app_identity::didkey::encode(
            &SigningKey::from_bytes(&[0x76; 32])
                .verifying_key()
                .to_bytes(),
        ),
        offer_core_digest: [0x77; 32],
        payload_digest: [0x78; 32],
        grant_id: [0x79; 32],
        issuer_did: "did:crdt:z6MkFinalStatusIssuer".into(),
        receipt_recovery_commitment: [0x7a; 32],
        finalized_at: 1_800_000_700,
    };
    assert_eq!(input.device_did.len(), 56);
    let built = build_final_status(&profile, &input, kid, &signing_key).unwrap();
    assert_eq!(built.digest, <[u8; 32]>::from(Sha256::digest(&built.core)));
    assert!(built.core.len() <= 4_096);
    assert!(built.jws.len() <= 8_192);
    recognise_final_status(&profile, &built.jws, built.digest, &input, kid).unwrap();
    let recognised_time = recognise_final_status_with_embedded_time(
        &profile,
        &built.jws,
        built.digest,
        |finalized_at| CredentialV2FinalStatusInput {
            finalized_at,
            ..input.clone()
        },
        kid,
    )
    .unwrap();
    assert_eq!(recognised_time, input.finalized_at);

    let mut changed = input.clone();
    changed.payload_digest[0] ^= 1;
    assert!(recognise_final_status(&profile, &built.jws, built.digest, &changed, kid,).is_err());
    let mut wrong_digest = built.digest;
    wrong_digest[0] ^= 1;
    assert!(recognise_final_status(&profile, &built.jws, wrong_digest, &input, kid,).is_err());
}

#[test]
fn final_status_recovery_has_one_deterministic_cbor_and_signed_negative_grammar() {
    let signing_key = SigningKey::from_bytes(&[0x81; 32]);
    let profile = profile(&signing_key);
    let application_id = profile.application_id.as_str();
    let ceremony = [0x82; 32];
    let token = [0x83; 32];
    let request = encode_receipt_recovery_request(application_id, ceremony, &token).unwrap();
    assert!(request.len() <= 2_304);
    let recognised = recognise_receipt_recovery_request(&request).unwrap();
    assert_eq!(recognised.application_id(), application_id);
    assert_eq!(recognised.carrier_ceremony_id(), &ceremony);
    assert_eq!(recognised.receipt_recovery_token(), &token);
    assert_eq!(
        credential_v2_receipt_recovery_commitment(&token, ceremony, application_id).unwrap(),
        [
            0x82, 0x55, 0x0b, 0x2c, 0x7f, 0xe5, 0x09, 0x8c, 0x67, 0xac, 0x0b, 0xf9, 0x22, 0x2f,
            0x14, 0xd8, 0x0f, 0x3d, 0x4c, 0xe9, 0x5f, 0xd0, 0xd6, 0x26, 0x84, 0x7c, 0xa7, 0xbd,
            0x28, 0x6b, 0xff, 0x38,
        ]
    );

    let status_jws = "e30.e30.AA";
    let status_digest: [u8; 32] = Sha256::digest(b"{}").into();
    let accepted = CredentialV2RecoveryResponse::Accepted {
        final_status_jws: status_jws.into(),
        final_status_digest: status_digest,
    };
    let accepted_bytes = encode_receipt_recovery_response(&accepted).unwrap();
    assert_eq!(
        decode_receipt_recovery_response(&accepted_bytes).unwrap(),
        accepted
    );
    let receipt = recovered_receipt_object(
        [0x85; 32],
        ceremony,
        [0x86; 32],
        CredentialV2ReceiptInput {
            final_status_jws: status_jws.into(),
            final_status_digest: status_digest,
        },
    )
    .unwrap();
    let recognised_receipt = recognise_receipt(&receipt, ceremony, [0x86; 32]).unwrap();
    assert_eq!(recognised_receipt.final_status_jws, status_jws);
    assert_eq!(recognised_receipt.final_status_digest, status_digest);
    for response in [
        CredentialV2RecoveryResponse::InProgress {
            retry_after_seconds: 30,
        },
        CredentialV2RecoveryResponse::Unknown,
    ] {
        let bytes = encode_receipt_recovery_response(&response).unwrap();
        assert!(bytes.len() <= 9_216);
        assert_eq!(decode_receipt_recovery_response(&bytes).unwrap(), response);
    }

    let negative_input = CredentialV2RecoveryNegativeInput {
        application_id: application_id.into(),
        carrier_ceremony_id: ceremony,
        receipt_recovery_commitment: credential_v2_receipt_recovery_commitment(
            &token,
            ceremony,
            application_id,
        )
        .unwrap(),
        observed_at: 1_800_000_800,
    };
    let kid = "https://photos.example/selfsame/application#credential-v2-test";
    let negative =
        build_recovery_not_finalized(&profile, &negative_input, kid, &signing_key).unwrap();
    recognise_recovery_not_finalized(
        &profile,
        &negative.jws,
        negative.digest,
        &negative_input,
        kid,
    )
    .unwrap();
    let recognised_negative = recognise_recovery_not_finalized_status(
        &profile,
        &negative.jws,
        negative.digest,
        application_id,
        ceremony,
        negative_input.receipt_recovery_commitment,
    )
    .unwrap();
    assert_eq!(recognised_negative.kid, kid);
    assert_eq!(recognised_negative.observed_at, 1_800_000_800);
    let response = CredentialV2RecoveryResponse::NotFinalized {
        recovery_status_jws: negative.jws,
        recovery_status_digest: negative.digest,
    };
    let bytes = encode_receipt_recovery_response(&response).unwrap();
    assert_eq!(decode_receipt_recovery_response(&bytes).unwrap(), response);

    let mut noncanonical = request.clone();
    noncanonical.push(0);
    assert!(recognise_receipt_recovery_request(&noncanonical).is_err());
    let mut wrong = negative_input;
    wrong.receipt_recovery_commitment[0] ^= 1;
    assert!(recognise_recovery_not_finalized(
        &profile,
        match &response {
            CredentialV2RecoveryResponse::NotFinalized {
                recovery_status_jws,
                ..
            } => recovery_status_jws,
            _ => unreachable!(),
        },
        match response {
            CredentialV2RecoveryResponse::NotFinalized {
                recovery_status_digest,
                ..
            } => recovery_status_digest,
            _ => unreachable!(),
        },
        &wrong,
        kid,
    )
    .is_err());
}

fn exchange(
    sender: &mut CredentialV2Endpoint,
    receiver: &mut CredentialV2Endpoint,
    object: &CredentialV2Object,
) {
    assert_eq!(sender.send(object), Ok(CredentialV2Advance::Advanced));
    assert_eq!(receiver.receive(object), Ok(CredentialV2Advance::Advanced));
}

#[test]
fn spec079_valid_comparison_transition_guards() {
    let offer_signing_key = SigningKey::from_bytes(&[0x21; 32]);
    let device_key = SigningKey::from_bytes(&[0x22; 32])
        .verifying_key()
        .to_bytes();
    let profile = profile(&offer_signing_key);
    let carrier = CredentialV2Carrier::new(CredentialV2CarrierInput {
        application_context: profile.application_id.as_str().into(),
        relay_origin: RELAY.into(),
        mailbox_id: [0x31; 32],
        carrier_ceremony_id: [0x32; 32],
        carrier_nonce: [0x33; 32],
        claim_commitment: [0x34; 32],
        relay_expires_at: 1_800_000_900,
        expected_allocator_key: Some(device_key),
    })
    .unwrap();
    let input = CredentialV2OfferBuildInput {
        request_id: [0x41; 32],
        transcript_hash: [0x42; 64],
        application_account_id: [0x43; 32],
        account_scope_id: [0x44; 32],
        device_public_key: device_key,
        requested_permissions: vec![fixture::PERMISSION.into()],
        intent_nonce: [0x45; 32],
        issued_at: 1_800_000_300,
        expires_at: 1_800_000_900,
        legacy_handle: "@alice".into(),
        enrolled_key: [0x46; 32],
        snapshot_rows: Vec::new(),
        snapshot_nonce: [0x47; 32],
    };
    use ed25519_dalek::Signer as _;
    let prepared = prepare_offer_core(&profile, &carrier, &input).unwrap();
    let proof = SigningKey::from_bytes(&[0x22; 32])
        .sign(
            &device_possession_proof_input(
                [0x48; 32],
                *carrier.carrier_ceremony_id(),
                prepared.offer_core_digest,
            )
            .unwrap(),
        )
        .to_bytes();
    let verified = verify_prepared_offer_device_proof(
        &profile,
        &prepared,
        [0x48; 32],
        *carrier.carrier_ceremony_id(),
        device_key,
        proof,
    )
    .unwrap();
    let built = finalize_verified_offer(&profile, &verified, KID, &offer_signing_key).unwrap();
    let recognised = recognise_signed_offer(&profile, &built.signed_offer).unwrap();
    let object = CredentialV2Object::new(
        CredentialV2Kind::Offer,
        built.intent_digest,
        built.signed_offer.clone(),
    )
    .unwrap();
    let (bodies, _) = credential_v2_body_authority();
    bodies.bind_offer(profile.clone(), &recognised).unwrap();
    let approve = bodies
        .intent_decision(&object, CredentialV2IntentDecision::Approve)
        .unwrap();
    let preview_did = format!("did:crdt:{}", "a".repeat(64));
    let preparation = bodies.preparation(&approve, &preview_did).unwrap();
    let status = build_authority_status_response(
        &profile,
        *carrier.carrier_ceremony_id(),
        built.offer_core_digest,
        &CredentialV2AuthorityStatus::NoBinding,
        KID,
        &offer_signing_key,
    )
    .unwrap();
    let comparison = bodies.comparison(&preparation, &status.response).unwrap();
    // SPEC079 TEST005: this actual mode-free endpoint/body operation exposes
    // the earliest transition verdict, before later native/durable fences can
    // hide a removed guard. The native matrix uses the identical candidates.
    for field in [
        "positiveNoBinding",
        "boundSame",
        "earlyComparison",
        "carrierCeremonyId",
        "predecessorDigest",
        "intentDigest",
        "previewIssuerDid",
        "previewFingerprintDigest",
        "authorityStatusDigest",
        "authorityStatusResponse",
        "statusOffer",
        "statusSignature",
        "boundOther",
        "kind",
        "result",
    ] {
        let (bodies, verifier) = credential_v2_body_authority();
        let mut endpoint =
            CredentialV2Endpoint::new(Side::Claimant, carrier.clone(), Box::new(verifier));
        CredentialV2WalletOfferVerifier::new(
            profile.clone(),
            carrier.clone(),
            input.transcript_hash,
            CredentialV2TofuState::CeremonyGesture,
        )
        .unwrap()
        .with_body_authority(bodies.clone())
        .verify_offer(&mut endpoint, &object, input.expires_at - 1)
        .unwrap();
        endpoint.send(&approve).unwrap();
        let prepared = bodies.preparation(&approve, &preview_did).unwrap();
        assert_eq!(
            prepared, preparation,
            "same actual signed-context Preparation"
        );
        if field != "earlyComparison" {
            endpoint.send(&prepared).unwrap();
        }
        let selected = if field == "earlyComparison" {
            "predecessorDigest"
        } else {
            field
        };
        let candidate = if field == "positiveNoBinding" {
            comparison.clone()
        } else {
            comparison_inputs::alter(
                comparison.clone(),
                selected,
                &profile,
                &carrier,
                built.offer_core_digest,
                approve.content_hash(),
                &offer_signing_key,
            )
        };
        let verdict = endpoint.receive(&candidate);
        if matches!(field, "positiveNoBinding" | "boundSame") {
            assert_eq!(verdict.unwrap(), CredentialV2Advance::Advanced);
        } else if field == "earlyComparison" {
            assert_eq!(
                verdict.unwrap_err(),
                CredentialV2Error::Phase,
                "comparison requires actual Preparation progress"
            );
        } else {
            assert!(
                verdict.is_err(),
                "actual comparison transition accepted mismatched {field}"
            );
        }
    }
}
