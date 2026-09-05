//! SPEC078 TEST002/006: actual manual command recognition precedes reservation.
use super::*;
use crate::{cbcl_v2_completion as completion, custody::Custody, session::Session};
use base64ct::{Base64UrlUnpadded, Encoding};
use cbcl_pairing::credential_v2::*;
use serde_json::json;
use std::sync::Mutex;
use tauri::{
    test::{mock_builder, mock_context, noop_assets},
    Manager,
};

fn inputs(now: u64) -> (String, String) {
    let carrier = CredentialV2Carrier::new(CredentialV2CarrierInput {
        application_context: "https://photos.example/selfsame/application".into(),
        relay_origin: "https://photos.example:9443".into(),
        mailbox_id: [1; 32],
        carrier_ceremony_id: [2; 32],
        carrier_nonce: [3; 32],
        claim_commitment: cbcl_pairing::wire::claim_commitment(
            [1; 32],
            &cbcl_pairing::wire::ClaimToken::new([4; 16]),
        ),
        relay_expires_at: now + 300,
        expected_allocator_key: Some(
            ed25519_dalek::SigningKey::from_bytes(&[5; 32])
                .verifying_key()
                .to_bytes(),
        ),
    })
    .unwrap();
    (
        CredentialV2ManualBootstrap::new(carrier, [4; 16], now)
            .unwrap()
            .encode()
            .unwrap()
            .to_string(),
        CredentialV2ManualWords::from_csprng([6; 4])
            .encode()
            .to_string(),
    )
}

#[test]
fn manual_request_is_closed_and_never_coerces_input() {
    for value in [
        json!({}),
        json!({"bootstrap":"x"}),
        json!({"bootstrap":"x","words":3}),
        json!({"bootstrap":true,"words":"x"}),
        json!({"bootstrap":"x","words":"x","mode":"full"}),
        json!({"bootstrap":"x","words":"x","passcode":"private"}),
    ] {
        assert!(serde_json::from_value::<BeginManualRequest>(value).is_err());
    }
    assert!(
        serde_json::from_value::<BeginManualRequest>(json!({"bootstrap":"x","words":"x"})).is_ok()
    );
}

#[tokio::test]
#[ignore = "installs process-global memory custody; run alone"]
async fn manual_recognition_refuses_locally_and_preserves_typed_entry() {
    completion::shared_memkeyring::install();
    completion::shared_memkeyring::clear();
    Custody::restore("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "manual fixture passcode").unwrap();
    let app = mock_builder()
        .manage(AppSession(Mutex::new(Session::default())))
        .build(mock_context(noop_assets()))
        .unwrap();
    let now = crate::commands::now();
    let (bootstrap, words) = inputs(now);
    let writes = completion::shared_memkeyring::write_count();
    let policy = completion::shared_memkeyring::policy_operations();
    let identity = completion::identity_effect_count();
    let decisions = DECISIONS.load(std::sync::atomic::Ordering::SeqCst);
    let wrap = |bytes: &[u8]| format!("SSPAIR-M1:{}", Base64UrlUnpadded::encode_string(bytes));
    let decoded =
        Base64UrlUnpadded::decode_vec(bootstrap.strip_prefix("SSPAIR-M1:").unwrap()).unwrap();
    let mut invalid = Vec::new();
    for text in [
        String::new(),
        "SSPAIR1:x".into(),
        "SSPAIR-M2:x".into(),
        format!(" {bootstrap}"),
        format!("{bootstrap}="),
        "SSPAIR-M1:".to_owned() + &"A".repeat(3670),
        wrap(&[decoded.as_slice(), &[0]].concat()),
    ] {
        invalid.push((text, words.clone()));
    }
    for text in [
        String::new(),
        "abandon".into(),
        "abandon abandon".into(),
        "abandon abandon abandon".into(),
        format!("{words} abandon"),
        "unknown unknown unknown".into(),
        "aba aban aband".into(),
        words.replace(' ', ","),
        words.replace(' ', "\u{a0}"),
        "a".repeat(129),
        format!("{words}\u{200b}"),
    ] {
        invalid.push((bootstrap.clone(), text));
    }
    invalid.push((
        wrap(&[&[0x98, 0x03][..], &decoded[1..]].concat()),
        words.clone(),
    ));
    for kind in ["indefinite", "extra", "wrong-token", "nested", "domain"] {
        let mut bytes = decoded.clone();
        match kind {
            "indefinite" => {
                bytes[0] = 0x9f;
                bytes.push(0xff);
            }
            "extra" => {
                bytes[0] = 0x84;
                bytes.push(0);
            }
            "wrong-token" => *bytes.last_mut().unwrap() ^= 1,
            "nested" => {
                bytes.insert(0, 0x81);
            }
            _ => bytes[3] ^= 1,
        }
        invalid.push((wrap(&bytes), words.clone()));
    }
    let (expired, _) = inputs(now - 301);
    invalid.push((expired, words.clone()));
    for (bootstrap, words) in invalid {
        let error = cbcl_v2_begin_manual(BeginManualRequest { bootstrap, words }, app.state())
            .await
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "RecognitionFailed");
        let state = app.state::<AppSession>();
        let state = state.0.lock().unwrap();
        assert!(state.pending_cbcl_v2_entry.is_none());
        assert!(state.pending_cbcl_v2.is_none());
        assert!(state.pending_cbcl_v2_execution.is_none());
    }
    assert_eq!(completion::shared_memkeyring::write_count(), writes);
    assert_eq!(completion::shared_memkeyring::policy_operations(), policy);
    assert_eq!(completion::identity_effect_count(), identity);
    assert_eq!(
        DECISIONS.load(std::sync::atomic::Ordering::SeqCst),
        decisions
    );

    // Exercise every allowed ASCII separator/case normalization through the
    // actual command; the returned typed entry is exactly the recognised pair.
    for separator in [" ", "\t", "\r", "\n", " \t\r\n "] {
        let text = format!(" \t{}\r\n", words.to_uppercase().replace(' ', separator));
        let result = cbcl_v2_begin_manual(
            BeginManualRequest {
                bootstrap: bootstrap.clone(),
                words: text,
            },
            app.state(),
        )
        .await
        .unwrap();
        assert_eq!(result.phase, "reserved");
        assert_eq!(
            result.application_id,
            "https://photos.example/selfsame/application"
        );
        let response = serde_json::to_string(&result).unwrap();
        assert!(!response.contains(&bootstrap) && !response.contains(&words));
        assert_eq!(completion::shared_memkeyring::write_count(), writes);
        // A second entry cannot replace this reservation, even with a different
        // checksum-valid phrase. Invalid spelling never consumed this authority.
        let other = CredentialV2ManualWords::from_csprng([7; 4])
            .encode()
            .to_string();
        assert_eq!(
            cbcl_v2_begin_manual(
                BeginManualRequest {
                    bootstrap: bootstrap.clone(),
                    words: other
                },
                app.state()
            )
            .await
            .err()
            .unwrap()
            .to_string(),
            "PairingAlreadyActive"
        );
        cbcl_v2_cancel_link(
            TaggedRequest {
                attempt_tag: result.attempt_tag,
            },
            app.state(),
        )
        .await
        .unwrap();
    }
    let legacy_attempt = {
        let state = app.state::<AppSession>();
        let mut state = state.0.lock().unwrap();
        let operation = state.cbcl_v2_attempts.begin().unwrap();
        let attempt = operation.attempt.clone();
        operation.retain();
        attempt
    };
    assert_eq!(
        cbcl_v2_begin_manual(
            BeginManualRequest {
                bootstrap: bootstrap.clone(),
                words: words.clone()
            },
            app.state()
        )
        .await
        .err()
        .unwrap()
        .to_string(),
        "PairingWrongMode"
    );
    assert!(legacy_attempt.check().is_ok());
    cbcl_v2_cancel(app.state()).await.unwrap();
    for blocked in ["background", "root"] {
        let state = app.state::<AppSession>();
        let change = if blocked == "root" {
            Some(state.0.lock().unwrap().begin_cbcl_v2_root_change().unwrap())
        } else {
            state.0.lock().unwrap().cbcl_v2_attempts.foreground(false);
            None
        };
        assert_eq!(
            cbcl_v2_begin_manual(
                BeginManualRequest {
                    bootstrap: bootstrap.clone(),
                    words: words.clone()
                },
                app.state()
            )
            .await
            .err()
            .unwrap()
            .to_string(),
            if blocked == "root" {
                "PairingRootChanged"
            } else {
                "PairingCancelled"
            }
        );
        drop(change);
        state.0.lock().unwrap().cbcl_v2_attempts.foreground(true);
    }
    // Explicit Full and legacy inputs do not select the Manual recognizer.
    assert!(cbcl_v2_begin_handoff(
        BeginHandoffRequest {
            handoff: bootstrap.clone()
        },
        app.state()
    )
    .await
    .is_err());
    let (carrier, presence) =
        CredentialV2ManualBootstrap::recognise_pair(&bootstrap, &words, now).unwrap();
    let full = CredentialV2Handoff::new(carrier, presence)
        .unwrap()
        .encode()
        .unwrap();
    assert_eq!(
        cbcl_v2_begin_manual(
            BeginManualRequest {
                bootstrap: full.to_string(),
                words
            },
            app.state()
        )
        .await
        .err()
        .unwrap()
        .to_string(),
        "RecognitionFailed"
    );
    assert_eq!(completion::shared_memkeyring::policy_operations(), policy);
    assert_eq!(completion::identity_effect_count(), identity);
    completion::shared_memkeyring::clear();
}

#[tokio::test]
#[ignore = "installs process-global memory custody; run alone"]
async fn manual_checksum_valid_wrong_words_reach_one_share_but_no_finished_or_retry() {
    use cbcl_pairing::wire::{
        decode_client_message, encode_server_message, ClientMessage, ServerMessage, Side,
    };
    completion::shared_memkeyring::install();
    completion::shared_memkeyring::clear();
    Custody::restore("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "manual fixture passcode").unwrap();
    let app = mock_builder()
        .manage(AppSession(Mutex::new(Session::default())))
        .build(mock_context(noop_assets()))
        .unwrap();
    let now = crate::commands::now();
    let (bootstrap, _) = inputs(now);
    let carrier = CredentialV2ManualBootstrap::recognise(&bootstrap, now)
        .unwrap()
        .carrier()
        .clone();
    let (profile, octets) =
        super::tests::profile(&ed25519_dalek::SigningKey::from_bytes(&[0x21; 32]));
    let reserved = cbcl_v2_begin_manual(
        BeginManualRequest {
            bootstrap,
            words: CredentialV2ManualWords::from_csprng([7; 4])
                .encode()
                .to_string(),
        },
        app.state(),
    )
    .await
    .unwrap();
    let entry = app
        .state::<AppSession>()
        .0
        .lock()
        .unwrap()
        .pending_cbcl_v2_entry
        .take()
        .unwrap();
    let mut claimant = cbcl_v2_claimant::test_recognised_entry_claimant(
        entry,
        selfsame_app_identity_net::profile::FetchedProfile {
            profile: profile.clone(),
            octets,
            fetched_at: now as i64,
        },
        [9; 32],
    )
    .unwrap();
    let receive = |claimant: &mut cbcl_v2_claimant::PreparedClaimant, message: ServerMessage| {
        claimant
            .core_mut()
            .receive(&encode_server_message(&message).unwrap(), now)
    };
    assert!(claimant.core_mut().start().is_ok());
    receive(&mut claimant, ServerMessage::Welcome).unwrap();
    let effects = receive(
        &mut claimant,
        ServerMessage::ClaimedV2 {
            mailbox_id: *carrier.mailbox_id(),
            membership_token: [8; 32],
            expires_at: now + 300,
        },
    )
    .unwrap();
    let shares: Vec<_> = effects
        .iter()
        .filter_map(|effect| {
            if let CredentialV2ClaimantEffect::Send(bytes) = effect {
                if let ClientMessage::Put { seq: 0, body } = decode_client_message(bytes).unwrap() {
                    return Some(decode_frame(&body).unwrap());
                }
            }
            None
        })
        .collect();
    assert_eq!(shares.len(), 1);
    let correct = CredentialV2ManualWords::from_csprng([6; 4]);
    let mut allocator = CredentialV2AllocatorBootstrap::new(
        carrier.clone(),
        CredentialV2Presence::new(*correct.cpace_secret(), [4; 16]),
        *profile.digest(),
        CredentialV2RelayState::new([10; 32]),
        CredentialV2AllocatorMode::Manual,
    )
    .unwrap();
    allocator.claimant_admitted().unwrap();
    let response = allocator.start_cpace([11; 32]).unwrap();
    let finished = allocator.receive_cpace(&shares[0]).unwrap();
    receive(&mut claimant, ServerMessage::Acknowledged { seq: 0 }).unwrap();
    let reply = receive(
        &mut claimant,
        ServerMessage::Frame {
            peer_seq: 0,
            body: encode_frame(&response).unwrap(),
        },
    )
    .unwrap();
    assert!(!reply
        .iter()
        .any(|e| matches!(e, CredentialV2ClaimantEffect::Established { .. })));
    receive(&mut claimant, ServerMessage::Acknowledged { seq: 1 }).unwrap();
    assert!(receive(
        &mut claimant,
        ServerMessage::Frame {
            peer_seq: 1,
            body: encode_frame(&finished).unwrap()
        }
    )
    .is_err());
    assert!(claimant.core_mut().start().is_err());
    let context = CredentialV2Context::derive(&carrier, *profile.digest()).unwrap();
    let (_, correct_share) = context
        .start_cpace(
            Side::Claimant,
            &CredentialV2Presence::new(*correct.cpace_secret(), [4; 16]),
            [12; 32],
        )
        .unwrap();
    assert!(allocator
        .receive_cpace(&CredentialV2Frame::cpace(&correct_share).unwrap())
        .is_err());
    assert!(completion::pending_links().unwrap().is_empty());
    cbcl_v2_cancel_link(
        TaggedRequest {
            attempt_tag: reserved.attempt_tag,
        },
        app.state(),
    )
    .await
    .unwrap();
    completion::shared_memkeyring::clear();
}
