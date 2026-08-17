#[path = "../../selfsame-app-identity/tests/common/mod.rs"]
mod fixture;

use selfsame_app_identity::{accept::Freshness, ceremony};
use selfsame_pairing::{
    CeremonyEntropy, CeremonyOutcome, CredentialTransfer, IntegrationError, PendingTransfer,
    SelfsameProof, SelfsameVerificationContext, VerificationFailure,
};

fn verification(example: &fixture::Ceremony) -> SelfsameVerificationContext {
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
        proof: Some(SelfsameProof {
            challenge: example.challenge.clone(),
            signature: example.signature,
            verifier_session: fixture::VERIFIER_SESSION.into(),
        }),
    }
}

#[test]
fn test_703_and_705_approved_ceremony_reaches_selfsame_acceptance() {
    let (pending, carrier) = accepted_transfer();
    let mut ceremony = pending
        .begin(&carrier)
        .expect("the exact carrier establishes a session");

    let outcome = ceremony
        .approve()
        .expect("approval transfers and verifies one credential");
    let CeremonyOutcome::Accepted(accepted) = outcome else {
        panic!("approval must produce the accepted outcome")
    };
    assert_eq!(
        accepted.acceptance().grant.application,
        fixture::APPLICATION_ID
    );

    let snapshot = ceremony.snapshot();
    assert_eq!(snapshot.delivered_payloads, 1);
    assert_eq!(snapshot.pairing_verifier_calls, 1);
    assert_eq!(snapshot.selfsame_verifier_calls, 1);
    assert!(snapshot.allocator_secrets_erased);
    assert!(snapshot.claimant_secrets_erased);
    assert_eq!(snapshot.relay_frames, 8);
    assert!(snapshot.relay_bytes > 0);
    assert_eq!(snapshot.relay_mailboxes, 0);
}

#[test]
fn test_710_decline_releases_no_payload_and_calls_no_selfsame_verifier() {
    let (pending, carrier) = accepted_transfer();
    let mut ceremony = pending
        .begin(&carrier)
        .expect("the exact carrier establishes a session");

    assert!(matches!(
        ceremony.decline().unwrap(),
        CeremonyOutcome::Declined
    ));
    let snapshot = ceremony.snapshot();
    assert_eq!(snapshot.delivered_payloads, 0);
    assert_eq!(snapshot.pairing_verifier_calls, 0);
    assert_eq!(snapshot.selfsame_verifier_calls, 0);
    assert!(snapshot.allocator_secrets_erased);
    assert!(snapshot.claimant_secrets_erased);
    assert_eq!(snapshot.relay_frames, 7);
    assert_eq!(snapshot.relay_mailboxes, 0);
}

#[test]
fn test_706_invalid_grant_is_transported_but_never_authorized() {
    let (pending, carrier) = transfer_with_mutated_signature();
    let mut ceremony = pending.begin(&carrier).unwrap();

    assert!(matches!(
        ceremony.approve(),
        Err(IntegrationError::Selfsame(VerificationFailure::Selfsame(_)))
    ));
    let snapshot = ceremony.snapshot();
    assert_eq!(snapshot.delivered_payloads, 1);
    assert_eq!(snapshot.pairing_verifier_calls, 1);
    assert_eq!(snapshot.selfsame_verifier_calls, 1);
    assert!(snapshot.allocator_secrets_erased);
    assert!(snapshot.claimant_secrets_erased);
}

#[test]
fn test_711_wrong_carrier_is_refused_before_intent() {
    let (pending, mut carrier) = accepted_transfer();
    let last = carrier.last_mut().unwrap();
    *last ^= 1;
    assert!(matches!(
        pending.begin(&carrier),
        Err(IntegrationError::Recognition)
    ));
}

#[test]
fn test_707_and_708_relay_state_is_opaque_and_scope_bounded() {
    let (pending, carrier) = accepted_transfer();
    let ceremony = pending.begin(&carrier).unwrap();
    let debug = ceremony.relay_debug();
    assert!(!debug.contains(fixture::APPLICATION_ID));
    assert!(!debug.contains(fixture::PERMISSION));
    assert!(!debug.contains("photos.example"));
    assert!(!debug.contains("credential"));
    assert_eq!(ceremony.snapshot().relay_frames, 6);
    assert_eq!(ceremony.snapshot().relay_mailboxes, 1);
}

#[test]
fn test_718_cancel_and_expiry_erase_both_endpoints() {
    let (pending, carrier) = accepted_transfer();
    let mut cancelled = pending.begin(&carrier).unwrap();
    cancelled.cancel().unwrap();
    let snapshot = cancelled.snapshot();
    assert_eq!(snapshot.delivered_payloads, 0);
    assert_eq!(snapshot.selfsame_verifier_calls, 0);
    assert!(snapshot.allocator_secrets_erased && snapshot.claimant_secrets_erased);

    let (pending, carrier) = accepted_transfer();
    let mut expired = pending.begin(&carrier).unwrap();
    expired.expire().unwrap();
    let snapshot = expired.snapshot();
    assert_eq!(snapshot.delivered_payloads, 0);
    assert_eq!(snapshot.selfsame_verifier_calls, 0);
    assert!(snapshot.allocator_secrets_erased && snapshot.claimant_secrets_erased);
}

#[test]
fn test_718_decision_and_payload_replay_create_no_extra_effect() {
    let (pending, carrier) = accepted_transfer();
    let mut ceremony = pending.begin(&carrier).unwrap();
    assert!(matches!(
        ceremony.approve().unwrap(),
        CeremonyOutcome::Accepted(_)
    ));
    assert!(matches!(ceremony.approve(), Err(IntegrationError::State)));
    let snapshot = ceremony.snapshot();
    assert_eq!(snapshot.delivered_payloads, 1);
    assert_eq!(snapshot.selfsame_verifier_calls, 1);
}

#[test]
fn test_706_displayed_authority_must_match_the_transferred_grant() {
    let example = fixture::Ceremony::accepted();
    let bundle = ceremony::build_bundle(
        &selfsame_app_identity::codec::b64url(&[21; 32]),
        &selfsame_app_identity::codec::b64url(&[22; 32]),
        core::str::from_utf8(&example.grant_bytes).unwrap(),
        None,
    )
    .unwrap();
    let mismatched = CredentialTransfer {
        application_id: fixture::APPLICATION_ID.into(),
        origin: "https://photos.example".into(),
        scope: "https://photos.example/selfsame/application#other".into(),
        recipient: example.device_did.clone(),
        bundle,
    };
    assert!(matches!(
        PendingTransfer::new(mismatched, verification(&example), entropy()),
        Err(IntegrationError::Profile)
    ));
}

fn accepted_transfer() -> (PendingTransfer, Vec<u8>) {
    transfer(false)
}

fn transfer_with_mutated_signature() -> (PendingTransfer, Vec<u8>) {
    transfer(true)
}

fn transfer(mutate_signature: bool) -> (PendingTransfer, Vec<u8>) {
    let fixture = fixture::Ceremony::accepted();
    let mut grant = fixture.grant_bytes.clone();
    if mutate_signature {
        let last = grant.last_mut().unwrap();
        *last = if *last == b'A' { b'B' } else { b'A' };
    }
    let bundle = ceremony::build_bundle(
        &selfsame_app_identity::codec::b64url(&[21; 32]),
        &selfsame_app_identity::codec::b64url(&[22; 32]),
        core::str::from_utf8(&grant).unwrap(),
        None,
    )
    .unwrap();
    let transfer = CredentialTransfer {
        application_id: fixture::APPLICATION_ID.into(),
        origin: "https://photos.example".into(),
        scope: fixture::PERMISSION.into(),
        recipient: fixture.device_did.clone(),
        bundle,
    };
    let pending = PendingTransfer::new(transfer, verification(&fixture), entropy()).unwrap();
    let carrier = pending.carrier().to_vec();
    (pending, carrier)
}

fn entropy() -> CeremonyEntropy {
    CeremonyEntropy {
        mailbox_id: [31; 32],
        invitation_secret: [32; 16],
        allocator_cpace: [33; 32],
        claimant_cpace: [34; 32],
        allocator_signing: [35; 32],
        claimant_signing: [36; 32],
        relay_operator_key: [38; 32],
        allocator_membership: [39; 32],
        claimant_membership: [40; 32],
        intent_nonce: [37; 32],
    }
}
