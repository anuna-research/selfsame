//! Cross-consumer signed OfferCoreV2 construction and recognition.

#[path = "../../selfsame-app-identity/tests/common/mod.rs"]
mod fixture;

use cbcl_pairing::credential_v2::{CredentialV2Carrier, CredentialV2CarrierInput};
use ed25519_dalek::SigningKey;
use selfsame_app_identity::{json, json::Json, profile::ApplicationProfile};
use selfsame_pairing::credential_v2::{
    device_possession_proof_input, finalize_verified_offer, prepare_offer_core,
    recognise_prepared_offer, recognise_signed_offer, verify_prepared_offer_device_proof,
    CredentialV2OfferBuildInput,
};

const RELAY: &str = "https://photos.example:9443";

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
    assert_eq!(recognised.transcript_hash, input.transcript_hash);
    assert_eq!(recognised.expires_at, input.expires_at);

    let mut changed = built.signed_offer;
    *changed.last_mut().unwrap() ^= 1;
    assert!(recognise_signed_offer(&profile, &changed).is_err());
}
