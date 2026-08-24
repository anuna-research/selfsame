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
    build_authority_status_response, credential_v2_body_authority, device_possession_proof_input,
    finalize_verified_offer, prepare_offer_core, recognise_authority_status_response,
    recognise_prepared_offer, recognise_signed_offer, verify_prepared_offer_device_proof,
    CredentialV2AuthorityStatus, CredentialV2FinalDecision, CredentialV2IntentDecision,
    CredentialV2OfferBuildInput, CredentialV2PayloadInput, CredentialV2WalletOfferVerifier,
};
use sha2::{Digest, Sha256};

const RELAY: &str = "https://photos.example:9443";

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
    assert!(wallet_bodies
        .payload(
            &final_approve,
            CredentialV2PayloadInput {
                grant_id: [0x49; 32],
                grant: "not-a-jws".into(),
            },
        )
        .is_err());

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

fn exchange(
    sender: &mut CredentialV2Endpoint,
    receiver: &mut CredentialV2Endpoint,
    object: &CredentialV2Object,
) {
    assert_eq!(sender.send(object), Ok(CredentialV2Advance::Advanced));
    assert_eq!(receiver.receive(object), Ok(CredentialV2Advance::Advanced));
}
