//! SPEC-008 `CON-902` — the deferred, grant-bound `CON-207` proof.
//!
//! A production shell assembles its verification context before the ceremony,
//! so it cannot hold a device proof: the challenge binds the SHA-256 of the
//! exact grant octets, which do not exist yet. These tests drive the full
//! in-process ceremony with `proof: None` and prove: the adapter completes
//! and verifies a deferred proof signed by the device key (positive); an
//! absent signer refuses (fail-closed); a wrong-key signer refuses
//! (step 13 still binds).

#[path = "../../selfsame-app-identity/tests/common/mod.rs"]
mod fixture;

use cbcl_pairing::{
    profile::{
        CredentialGrant, CredentialIntentClaims, CREDENTIAL_ACTION, CREDENTIAL_APPLICATION,
        CREDENTIAL_PAYLOAD,
    },
    wire::{
        encode_invitation, ApplicationPayload, ChannelFrame, Decision, Invitation, Locator,
        PairingIntent, Side,
    },
};
use ed25519_dalek::Signer as _;
use selfsame_app_identity::{accept::Freshness, ceremony};
use selfsame_pairing::{
    DeferredProofSigner, SelfsameEndpoint, SelfsameEndpointBootstrap, SelfsameEndpointEffect,
    SelfsameVerificationContext,
};

const MAILBOX_ID: [u8; 32] = [0x32; 32];

fn invitation() -> Vec<u8> {
    encode_invitation(&Invitation {
        application: CREDENTIAL_APPLICATION.into(),
        relay_origin: "https://relay.example".into(),
        locator: Locator::Direct(MAILBOX_ID),
        secret: vec![0x22; 16],
        expected_allocator_key: None,
        expected_claimant_key: None,
    })
    .expect("invitation")
}

fn proofless_verification(example: &fixture::Ceremony) -> SelfsameVerificationContext {
    SelfsameVerificationContext {
        profile: example.profile.clone(),
        account: example.account.clone(),
        device_public_key: example.device_public_key,
        operation_permissions: vec![fixture::PERMISSION.into()],
        now: example.now,
        clock_skew_seconds: 0,
        freshness: Freshness::SessionEstablishment,
        issuer: Some(example.issuer.clone()),
        jrd: Some(example.jrd.clone()),
        projection: None,
        proof: None,
    }
}

/// Drive the ceremony to the delivered payload frame and return the claimant
/// endpoint plus that frame, with the claimant ready to receive it.
fn ceremony_to_payload(example: &fixture::Ceremony) -> (SelfsameEndpoint, ChannelFrame) {
    let invitation = invitation();
    let allocator_bootstrap = SelfsameEndpointBootstrap::start(
        Side::Allocator,
        &invitation,
        MAILBOX_ID,
        [0x43; 32],
        [0x53; 32],
    )
    .expect("allocator bootstrap");
    let claimant_bootstrap = SelfsameEndpointBootstrap::start(
        Side::Claimant,
        &invitation,
        MAILBOX_ID,
        [0x44; 32],
        [0x54; 32],
    )
    .expect("claimant bootstrap");
    let allocator_cpace = allocator_bootstrap.local_cpace_frame().clone();
    let claimant_cpace = claimant_bootstrap.local_cpace_frame().clone();
    let mut allocator = allocator_bootstrap
        .finish(&claimant_cpace)
        .expect("allocator endpoint");
    let mut claimant = claimant_bootstrap
        .finish(&allocator_cpace)
        .expect("claimant endpoint");

    let allocator_finished = allocator
        .local_finished_frame()
        .expect("allocator finished")
        .expect("allocator finished frame");
    let claimant_finished = claimant
        .local_finished_frame()
        .expect("claimant finished")
        .expect("claimant finished frame");
    claimant
        .receive_frame(&allocator_finished, None)
        .expect("claimant confirms allocator");
    let opener = allocator
        .receive_frame(&claimant_finished, None)
        .expect("allocator confirms claimant")
        .into_iter()
        .find_map(|effect| match effect {
            SelfsameEndpointEffect::SendFrame(frame) => Some(frame),
            _ => None,
        })
        .expect("role-cast opener");
    claimant
        .receive_frame(&opener, None)
        .expect("claimant receives role cast");

    let claims = CredentialIntentClaims {
        application_id: fixture::APPLICATION_ID.into(),
        origin: "https://photos.example".into(),
        scope: fixture::PERMISSION.into(),
        recipient: example.device_did.clone(),
    };
    let (allocator_claim, claimant_claim) = claims.encode().expect("claims");
    let intent_frame = allocator
        .send_intent(&PairingIntent {
            application: CREDENTIAL_APPLICATION.into(),
            action: CREDENTIAL_ACTION.into(),
            allocator_claim,
            claimant_claim,
            authority_summary: "Transfer one Selfsame device grant".into(),
            intent_nonce: [0x62; 32],
        })
        .expect("send intent");
    claimant
        .receive_frame(&intent_frame, None)
        .expect("receive intent");
    let approval = claimant
        .decide(Decision::Approve)
        .expect("approve")
        .into_iter()
        .find_map(|effect| match effect {
            cbcl_pairing::endpoint::EndpointEffect::SendFrame(frame) => Some(frame),
            _ => None,
        })
        .expect("approval frame");
    allocator
        .receive_frame(&approval, None)
        .expect("receive approval");

    let bundle = ceremony::build_bundle(
        &selfsame_app_identity::codec::b64url(&[21; 32]),
        &selfsame_app_identity::codec::b64url(&[22; 32]),
        core::str::from_utf8(&example.grant_bytes).expect("grant utf8"),
        None,
    )
    .expect("bundle");
    let grant = CredentialGrant {
        application_id: claims.application_id,
        origin: claims.origin,
        scope: claims.scope,
        recipient: claims.recipient,
        credential: bundle,
    }
    .encode()
    .expect("grant body");
    let payload_frame = allocator
        .send_payload(&ApplicationPayload {
            intent_digest: allocator.intent_digest().expect("intent digest"),
            payload_type: CREDENTIAL_PAYLOAD.into(),
            body: grant,
        })
        .expect("send payload");
    (claimant, payload_frame)
}

fn device_signer(example: &fixture::Ceremony) -> DeferredProofSigner {
    let key = example.device_key.clone();
    DeferredProofSigner {
        nonce: [0x77; 32],
        verifier_session: "wallet-ceremony-1".into(),
        signer: Box::new(move |input| key.sign(input).to_bytes()),
    }
}

// Positive: a proofless context plus a deferred device-key signer accepts —
// the adapter builds the grant-bound challenge and step 13 verifies it.
#[test]
fn deferred_proof_completes_and_accepts() {
    let example = fixture::Ceremony::accepted();
    let (mut claimant, payload_frame) = ceremony_to_payload(&example);
    let verification = proofless_verification(&example);
    let mut deferred = device_signer(&example);
    let delivered = claimant
        .receive_frame_with_proof(&payload_frame, Some(&verification), Some(&mut deferred))
        .expect("deferred proof accepts");
    assert!(delivered
        .iter()
        .any(|effect| matches!(effect, SelfsameEndpointEffect::Accepted(_))));
    assert_eq!(claimant.selfsame_verifier_calls(), 1);
}

// Fail-closed: no proof and no deferred signer refuses — step 13 receives
// nothing to verify and the credential is not accepted.
#[test]
fn proofless_context_without_signer_refuses() {
    let example = fixture::Ceremony::accepted();
    let (mut claimant, payload_frame) = ceremony_to_payload(&example);
    let verification = proofless_verification(&example);
    assert!(claimant
        .receive_frame_with_proof(&payload_frame, Some(&verification), None)
        .is_err());
}

// Step 13 still binds: a deferred signer holding a key other than the
// context's device key produces a proof the verifier refuses.
#[test]
fn wrong_key_deferred_signer_refuses() {
    let example = fixture::Ceremony::accepted();
    let (mut claimant, payload_frame) = ceremony_to_payload(&example);
    let verification = proofless_verification(&example);
    let stranger = ed25519_dalek::SigningKey::from_bytes(&[0x5A; 32]);
    let mut deferred = DeferredProofSigner {
        nonce: [0x77; 32],
        verifier_session: "wallet-ceremony-1".into(),
        signer: Box::new(move |input| stranger.sign(input).to_bytes()),
    };
    assert!(claimant
        .receive_frame_with_proof(&payload_frame, Some(&verification), Some(&mut deferred))
        .is_err());
}
