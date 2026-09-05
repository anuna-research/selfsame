//! SPEC079 TEST001..009: native commands, real signed offers and authenticated
//! CPace/Finished/object exchange over an explicitly local in-process peer.
use super::*;
use crate::{
    cbcl_v2_completion as completion, custody::Custody, fixture, session::Session,
};
use cbcl_pairing::{cpace, credential_v2::*, wire::*};
use ed25519_dalek::{Signer as _, SigningKey};
use selfsame_app_identity::{
    json::{self, Json},
    profile::ApplicationProfile,
};
use selfsame_pairing::credential_v2::*;
use std::{
    net::TcpListener,
    sync::{mpsc, Arc, Mutex},
};
use tauri::{
    test::{mock_builder, mock_context, noop_assets, MockRuntime},
    Manager,
};
const RELAY: &str = "https://photos.example:9443";
const KID: &str = "https://photos.example/selfsame/application#credential-v2-test";
const PASS: &str = "native fixture passcode";
const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

pub(super) fn profile(key: &SigningKey) -> (ApplicationProfile, Vec<u8>) {
    let Json::Object(mut members) = fixture::profile_value() else {
        unreachable!()
    };
    let mobile = members
        .iter()
        .find(|(k, _)| k == "enrollment")
        .unwrap()
        .1
        .get("mobileBindings")
        .unwrap()
        .clone();
    for (name, value) in [
        (
            "enrollment",
            Json::obj([
                (
                    "requestSigningKeys",
                    Json::arr([Json::obj([
                        ("kid", Json::text(KID)),
                        ("publicKeyJwk", fixture::jwk(key.verifying_key().to_bytes())),
                    ])]),
                ),
                ("mobileBindings", mobile),
            ]),
        ),
        (
            "cbclPairingRelays",
            Json::arr([fixture::cbcl_relay("test-operator", RELAY, 1, 1, 9)]),
        ),
    ] {
        members.iter_mut().find(|(k, _)| k == name).unwrap().1 = value;
    }
    let octets = json::canonicalise(&Json::Object(members));
    (ApplicationProfile::recognise(&octets).unwrap(), octets)
}
fn server(socket: &mut WebSocket<TcpStream>, value: ServerMessage) {
    socket
        .send(Message::Binary(
            encode_server_message(&value).unwrap().into(),
        ))
        .unwrap();
}
fn client(socket: &mut WebSocket<TcpStream>) -> ClientMessage {
    loop {
        if let Message::Binary(bytes) = socket.read().unwrap() {
            return decode_client_message(&bytes).unwrap();
        }
    }
}
fn put(socket: &mut WebSocket<TcpStream>) -> (u8, Vec<u8>) {
    loop {
        if let ClientMessage::Put { seq, body } = client(socket) {
            return (seq, body);
        }
    }
}

#[derive(Clone, Copy)]
enum ComparisonCase {
    Stop,
    Confirm,
    Decline,
    Mismatch,
    Alter(&'static str),
}
struct Peer {
    observed: Arc<Mutex<Vec<CredentialV2Kind>>>,
    release: mpsc::Sender<ComparisonCase>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.release.send(ComparisonCase::Stop);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
struct Rig {
    app: tauri::App<MockRuntime>,
    tag: String,
    attempt: CredentialV2Attempt,
    peer: Peer,
}
impl Drop for Rig {
    fn drop(&mut self) {
        self.app
            .state::<AppSession>()
            .0
            .lock()
            .unwrap()
            .revoke_cbcl_v2();
    }
}
impl Rig {
    fn request(&self) -> TaggedRequest {
        TaggedRequest {
            attempt_tag: self.tag.clone(),
        }
    }
    async fn unlock(&self) -> PreviewView {
        cbcl_v2_unlock_preview(
            UnlockPreviewRequest {
                attempt_tag: self.tag.clone(),
                passcode: PASS.into(),
            },
            self.app.state(),
        )
        .await
        .unwrap()
    }
    async fn review(&self) {
        self.unlock().await;
        cbcl_v2_preview_rendered(self.request(), self.app.state())
            .await
            .unwrap();
    }
    fn observations(&self) -> Vec<CredentialV2Kind> {
        self.peer.observed.lock().unwrap().clone()
    }
}

async fn rig(manual: bool) -> Rig {
    let words = CredentialV2ManualWords::from_csprng([0x35; 4]);
    let secret = if manual {
        *words.cpace_secret()
    } else {
        [0x35; 16]
    };
    let now = crate::commands::now();
    let signing = SigningKey::from_bytes(&[0x21; 32]);
    let device = SigningKey::from_bytes(&[0x22; 32]);
    let (profile, octets) = profile(&signing);
    let carrier = CredentialV2Carrier::new(CredentialV2CarrierInput {
        application_context: profile.application_id.as_str().into(),
        relay_origin: RELAY.into(),
        mailbox_id: [0x31; 32],
        carrier_ceremony_id: [0x32; 32],
        carrier_nonce: [0x33; 32],
        claim_commitment: claim_commitment([0x31; 32], &ClaimToken::new([0x34; 16])),
        relay_expires_at: now + 300,
        expected_allocator_key: Some(device.verifying_key().to_bytes()),
    })
    .unwrap();
    let handoff = CredentialV2Handoff::new(
        carrier.clone(),
        CredentialV2PresenceCode::new(secret, [0x34; 16]),
    )
    .unwrap()
    .encode()
    .unwrap();
    // The same exact candidate recognizer guards production contact before it
    // can create socket authority; these substitutions never reach the peer.
    for kind in ["missing", "duplicate", "relay", "application"] {
        let mut wrong = profile.clone();
        match kind {
            "missing" => wrong.cbcl_pairing_relays.clear(),
            "duplicate" => wrong
                .cbcl_pairing_relays
                .push(wrong.cbcl_pairing_relays[0].clone()),
            "relay" => {
                wrong.cbcl_pairing_relays[0].relay_origin = "https://other.example:9443".into()
            }
            _ => {
                wrong.application_id = selfsame_app_identity::profile::ApplicationId::parse(
                    "https://other.example/selfsame/v2",
                )
                .unwrap()
            }
        }
        assert!(
            cbcl_v2_claimant::test_ceremony_claimant(
                carrier.clone(),
                CredentialV2PresenceCode::new(secret, [0x34; 16]),
                selfsame_app_identity_net::profile::FetchedProfile {
                    profile: wrong,
                    octets: octets.clone(),
                    fetched_at: now as i64
                },
                [0x36; 32]
            )
            .is_err(),
            "{kind}"
        );
    }
    let app = mock_builder()
        .manage(AppSession(Mutex::new(Session::default())))
        .build(mock_context(noop_assets()))
        .unwrap();
    let reserved = if manual {
        cbcl_v2_begin_manual(
            BeginManualRequest {
                bootstrap: CredentialV2ManualBootstrap::new(carrier.clone(), [0x34; 16], now)
                    .unwrap()
                    .encode()
                    .unwrap()
                    .to_string(),
                words: words.encode().to_string(),
            },
            app.state(),
        )
        .await
        .unwrap()
    } else {
        cbcl_v2_begin_handoff(
            BeginHandoffRequest {
                handoff: handoff.to_string(),
            },
            app.state(),
        )
        .await
        .unwrap()
    };
    assert_eq!(reserved.phase, "reserved");
    let (entry, operation) = {
        let state = app.state::<AppSession>();
        let mut state = state.0.lock().unwrap();
        let entry = state.pending_cbcl_v2_entry.take().unwrap();
        (entry, state.cbcl_v2_attempts.start_work().unwrap())
    };
    let attempt = operation.attempt.clone();
    let claimant = cbcl_v2_claimant::test_recognised_entry_claimant(
        entry,
        selfsame_app_identity_net::profile::FetchedProfile {
            profile: profile.clone(),
            octets,
            fetched_at: now as i64,
        },
        [0x36; 32],
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let (peer_tcp, _) = listener.accept().unwrap();
    peer_tcp
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let observations = observed.clone();
    let (release, wait) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut socket =
            WebSocket::from_raw_socket(peer_tcp, tungstenite::protocol::Role::Server, None);
        assert!(matches!(client(&mut socket), ClientMessage::Bind));
        server(&mut socket, ServerMessage::Welcome);
        assert!(matches!(client(&mut socket), ClientMessage::ClaimV2 { .. }));
        server(
            &mut socket,
            ServerMessage::ClaimedV2 {
                mailbox_id: *carrier.mailbox_id(),
                membership_token: [0x37; 32],
                expires_at: now + 300,
            },
        );
        let (seq, claimant_share) = put(&mut socket);
        assert_eq!(seq, 0);
        let context = CredentialV2Context::derive(&carrier, *profile.digest()).unwrap();
        let (state, message) = context
            .start_cpace(
                Side::Allocator,
                &CredentialV2Presence::new(secret, [0x34; 16]),
                [0x38; 32],
            )
            .unwrap();
        let allocator_share = encode_frame(&CredentialV2Frame::cpace(&message).unwrap()).unwrap();
        server(&mut socket, ServerMessage::Acknowledged { seq: 0 });
        server(
            &mut socket,
            ServerMessage::Frame {
                peer_seq: 0,
                body: allocator_share.clone(),
            },
        );
        let (seq, claimant_finished) = put(&mut socket);
        assert_eq!(seq, 1);
        let isk = cpace::finish(
            state,
            decode_frame(&claimant_share)
                .unwrap()
                .cpace_message()
                .unwrap(),
        )
        .unwrap();
        let pending = PendingCredentialV2Channel::new(
            Side::Allocator,
            isk,
            context.public_context(),
            &allocator_share,
            &claimant_share,
        )
        .unwrap();
        let transcript = pending.transcript_hash();
        server(&mut socket, ServerMessage::Acknowledged { seq: 1 });
        server(
            &mut socket,
            ServerMessage::Frame {
                peer_seq: 1,
                body: encode_frame(&pending.local_finished_frame()).unwrap(),
            },
        );
        let mut channel = pending
            .confirm(&decode_frame(&claimant_finished).unwrap())
            .unwrap();
        let input = CredentialV2OfferBuildInput {
            request_id: [0x41; 32],
            transcript_hash: transcript,
            application_account_id: [0x43; 32],
            account_scope_id: [0x44; 32],
            device_public_key: device.verifying_key().to_bytes(),
            requested_permissions: vec![fixture::PERMISSION.into()],
            intent_nonce: [0x45; 32],
            issued_at: now - 60,
            expires_at: now + 240,
            legacy_handle: "@alice".into(),
            enrolled_key: [0x46; 32],
            snapshot_rows: Vec::new(),
            snapshot_nonce: [0x47; 32],
        };
        let prepared = prepare_offer_core(&profile, &carrier, &input).unwrap();
        let proof = device
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
            device.verifying_key().to_bytes(),
            proof,
        )
        .unwrap();
        let built = finalize_verified_offer(&profile, &verified, KID, &signing).unwrap();
        let recognised = recognise_signed_offer(&profile, &built.signed_offer).unwrap();
        let (authority, verifier) = credential_v2_body_authority();
        authority.bind_offer(profile.clone(), &recognised).unwrap();
        let offer = CredentialV2Object::new(
            CredentialV2Kind::Offer,
            built.intent_digest,
            built.signed_offer,
        )
        .unwrap();
        let mut endpoint =
            CredentialV2Endpoint::new(Side::Allocator, carrier.clone(), Box::new(verifier));
        endpoint.send(&offer).unwrap();
        server(
            &mut socket,
            ServerMessage::Frame {
                peer_seq: 2,
                body: encode_frame(&channel.seal(offer.as_bytes()).unwrap()).unwrap(),
            },
        );
        // Cancellation is expected; no partial application object is fabricated.
        let mut preparation = None;
        while let Ok(message) = socket.read() {
            let Message::Binary(bytes) = message else {
                continue;
            };
            let ClientMessage::Put { seq, body } = decode_client_message(&bytes).unwrap() else {
                continue;
            };
            let opened = channel.open(&decode_frame(&body).unwrap()).unwrap();
            let object = decode_object(&opened).unwrap();
            observations.lock().unwrap().push(object.kind());
            endpoint.receive(&object).unwrap();
            server(&mut socket, ServerMessage::Acknowledged { seq });
            if object.kind() == CredentialV2Kind::Preparation {
                preparation = Some(object);
                break;
            }
        }
        if let Some(preparation) = preparation {
            let case = wait
                .recv_timeout(Duration::from_secs(5))
                .unwrap_or(ComparisonCase::Stop);
            if !matches!(case, ComparisonCase::Stop) {
                let status = build_authority_status_response(
                    &profile,
                    *carrier.carrier_ceremony_id(),
                    built.offer_core_digest,
                    &CredentialV2AuthorityStatus::NoBinding,
                    KID,
                    &signing,
                )
                .unwrap();
                let mut compared = match case {
                    ComparisonCase::Decline => authority
                        .refusal(&preparation, CredentialV2RefusalReason::Cancelled)
                        .unwrap(),
                    ComparisonCase::Mismatch => authority
                        .refusal(&preparation, CredentialV2RefusalReason::BindingMismatch)
                        .unwrap(),
                    _ => authority
                        .comparison(&preparation, &status.response)
                        .unwrap(),
                };
                if let ComparisonCase::Alter(field) = case {
                    let mut body = compared.body().to_vec();
                    let at = body
                        .windows(field.len())
                        .position(|bytes| bytes == field.as_bytes())
                        .unwrap()
                        + field.len();
                    // Keep the field's canonical CBOR type/length and change one
                    // byte of its value. AEAD authenticates these altered bytes.
                    let header = body[at];
                    let offset = if header & 31 < 24 {
                        1
                    } else if header & 31 == 24 {
                        2
                    } else {
                        3
                    };
                    body[at + offset] ^= 1;
                    compared =
                        CredentialV2Object::new(compared.kind(), *compared.intent_digest(), body)
                            .unwrap();
                }
                let frame = channel.seal(compared.as_bytes()).unwrap();
                let _ = socket.send(Message::Binary(
                    encode_server_message(&ServerMessage::Frame {
                        peer_seq: 3,
                        body: encode_frame(&frame).unwrap(),
                    })
                    .unwrap()
                    .into(),
                ));
                while let Ok(Message::Binary(bytes)) = socket.read() {
                    if let ClientMessage::Put { seq, body } = decode_client_message(&bytes).unwrap()
                    {
                        let object =
                            decode_object(&channel.open(&decode_frame(&body).unwrap()).unwrap())
                                .unwrap();
                        observations.lock().unwrap().push(object.kind());
                        server(&mut socket, ServerMessage::Acknowledged { seq });
                    }
                }
            }
        }
    });
    let socket = WebSocket::from_raw_socket(
        MaybeTlsStream::Plain(tcp),
        tungstenite::protocol::Role::Client,
        None,
    );
    let a = attempt.clone();
    let (pending, view) = pairing_blocking(&operation, move || pump_to_offer(claimant, socket, a))
        .await
        .unwrap();
    assert_eq!(view.tofu_state, "ceremony-gesture");
    put_pending(&app.state::<AppSession>(), pending, operation).unwrap();
    Rig {
        app,
        tag: reserved.attempt_tag,
        attempt,
        peer: Peer {
            observed,
            release,
            worker: Some(worker),
        },
    }
}

#[test]
fn single_link_nested_requests_refuse_extras_coercions_and_invalid_tags() {
    use serde_json::json;
    for input in [
        json!({}),
        json!({"attemptTag":1}),
        json!({"attemptTag":"A".repeat(32)}),
        json!({"attemptTag":"0".repeat(31)}),
        json!({"attemptTag":"0".repeat(32),"approve":true}),
    ] {
        assert!(serde_json::from_value::<TaggedRequest>(input).is_err());
    }
    assert!(serde_json::from_value::<TaggedRequest>(json!({"attemptTag":"0".repeat(32)})).is_ok());
    assert!(serde_json::from_value::<UnlockPreviewRequest>(
        json!({"attemptTag":"0".repeat(32),"passcode":false})
    )
    .is_err());
    assert!(serde_json::from_value::<BeginHandoffRequest>(
        json!({"handoff":"SSPAIR1:x","profile":{}})
    )
    .is_err());
}

#[tokio::test]
async fn legacy_finish_missing_presence_keeps_the_attempt_retryable() {
    let app = mock_builder()
        .manage(AppSession(Mutex::new(Session::default())))
        .build(mock_context(noop_assets()))
        .unwrap();
    let attempt = {
        let session = app.state::<AppSession>();
        let mut session = session.0.lock().unwrap();
        let operation = session.cbcl_v2_attempts.begin().unwrap();
        let attempt = operation.attempt.clone();
        operation.retain();
        attempt
    };

    let missing = match cbcl_v2_finish(None, app.state()).await {
        Err(error) => error,
        Ok(_) => panic!("missing presence must be refused"),
    };
    assert_eq!(missing.to_string(), "PresenceRequired");
    assert!(
        attempt.check().is_ok(),
        "presence refusal cannot burn the attempt"
    );

    // A corrected value reaches the unchanged pending-phase check. Before the
    // fix, the missing value reached this check first and could take a real
    // PayloadSent pending session before reporting PresenceRequired.
    let retry = match cbcl_v2_finish(Some(PASS.into()), app.state()).await {
        Err(error) => error,
        Ok(_) => panic!("the fixture intentionally has no pending receipt"),
    };
    assert_eq!(retry.to_string(), "PairingNotStarted");
    assert!(attempt.check().is_ok());
}

#[tokio::test]
#[ignore = "installs process-global memory custody; run alone"]
async fn single_link_native_commands_render_mode_comparison_cancel_and_expiry() {
    native_consent_cases(false).await;
}

#[tokio::test]
#[ignore = "installs process-global memory custody; run alone"]
async fn manual_single_link_native_commands_render_mode_comparison_cancel_and_expiry() {
    native_consent_cases(true).await;
}

async fn native_consent_cases(manual: bool) {
    completion::shared_memkeyring::install();
    completion::shared_memkeyring::clear();
    Custody::restore(PHRASE, PASS).unwrap();
    {
        let mut session = Session::default();
        let change = session.begin_cbcl_v2_root_change().unwrap();
        let worker = change.clone();
        drop(change);
        assert_eq!(
            session
                .cbcl_v2_attempts
                .begin_single_link()
                .err()
                .unwrap()
                .to_string(),
            "PairingRootChanged"
        );
        assert_eq!(
            session.cbcl_v2_attempts.begin().err().unwrap().to_string(),
            "PairingRootChanged"
        );
        drop(worker);
        assert!(session.cbcl_v2_attempts.begin_single_link().is_ok());
    }
    let policy_operations = completion::shared_memkeyring::policy_operations();
    let identity_effects = completion::identity_effect_count();
    {
        let writes = completion::shared_memkeyring::write_count();
        let decisions = DECISIONS.load(std::sync::atomic::Ordering::SeqCst);
        let rig = rig(manual).await;
        assert_eq!(completion::shared_memkeyring::write_count(), writes);
        let stale = TaggedRequest {
            attempt_tag: "f".repeat(32),
        };
        assert_eq!(
            cbcl_v2_cancel_link(stale, rig.app.state())
                .await
                .err()
                .unwrap()
                .to_string(),
            "PairingStaleAttempt"
        );
        assert!(rig.attempt.check().is_ok());
        assert!(cbcl_v2_link(rig.request(), rig.app.state()).await.is_err());
        assert!(cbcl_v2_preview_rendered(rig.request(), rig.app.state())
            .await
            .is_err());
        assert!(cbcl_v2_continue_link(rig.request(), rig.app.state())
            .await
            .is_err());
        assert!(cbcl_v2_finish_link(rig.request(), rig.app.state())
            .await
            .is_err());
        for error in [
            cbcl_v2_relay_decide(true, rig.app.state())
                .await
                .err()
                .unwrap(),
            cbcl_v2_preliminary_decide(true, Some(PASS.into()), rig.app.state())
                .await
                .err()
                .unwrap(),
            cbcl_v2_compare(rig.app.state()).await.err().unwrap(),
            cbcl_v2_final_decide(true, Some(PASS.into()), rig.app.state())
                .await
                .err()
                .unwrap(),
            cbcl_v2_finish(None, rig.app.state()).await.err().unwrap(),
            cbcl_v2_cancel(rig.app.state()).await.err().unwrap(),
        ] {
            assert_eq!(error.to_string(), "PairingWrongMode");
        }
        assert!(rig.observations().is_empty());
        let preview = rig.unlock().await;
        assert!(preview.review.preview_issuer_did.starts_with("did:crdt:"));
        assert!(rig.attempt.test_has_custody());
        assert!(rig.observations().is_empty());
        assert!(completion::pending_links().unwrap().is_empty());
        assert!(cbcl_v2_link(rig.request(), rig.app.state()).await.is_err());
        cbcl_v2_preview_rendered(rig.request(), rig.app.state())
            .await
            .unwrap();
        assert!(rig.observations().is_empty());
        assert_eq!(completion::shared_memkeyring::write_count(), writes);
        assert_eq!(completion::identity_effect_count(), identity_effects);
        assert_eq!(
            DECISIONS.load(std::sync::atomic::Ordering::SeqCst),
            decisions
        );
        cbcl_v2_link(rig.request(), rig.app.state()).await.unwrap();
        assert!(cbcl_v2_link(rig.request(), rig.app.state()).await.is_err());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            rig.observations(),
            vec![
                CredentialV2Kind::IntentApprove,
                CredentialV2Kind::Preparation
            ]
        );
        assert!(completion::pending_links().unwrap().is_empty());
        let continue_future = cbcl_v2_continue_link(rig.request(), rig.app.state());
        let cancel = async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(
                cbcl_v2_continue_link(rig.request(), rig.app.state())
                    .await
                    .is_err(),
                "a pending continuation cannot be duplicated"
            );
            cbcl_v2_cancel_link(rig.request(), rig.app.state())
                .await
                .unwrap();
            assert!(!rig.attempt.test_has_custody());
            assert!(
                rig.app
                    .state::<AppSession>()
                    .0
                    .lock()
                    .unwrap()
                    .cbcl_v2_attempts
                    .begin_single_link()
                    .is_err(),
                "old worker retains its lease"
            );
        };
        let (result, ()) = tokio::join!(continue_future, cancel);
        assert_eq!(result.err().unwrap().to_string(), "PairingCancelled");
        assert!(completion::pending_links().unwrap().is_empty());
        assert!(!rig.observations().contains(&CredentialV2Kind::FinalApprove));
    }
    {
        let rig = rig(manual).await;
        rig.review().await;
        cbcl_v2_link(rig.request(), rig.app.state()).await.unwrap();
        rig.peer.release.send(ComparisonCase::Confirm).unwrap();
        struct Stop;
        impl PrePayloadFaultSink for Stop {
            fn before(&mut self, b: PrePayloadBoundary) -> Result<()> {
                assert_eq!(b, PrePayloadBoundary::FinalApprovalRelease);
                Err(UiError::from("InjectedPrePayloadFailure"))
            }
        }
        let error =
            continue_link_with_faults(rig.request(), &rig.app.state::<AppSession>(), &mut Stop)
                .await
                .err()
                .unwrap();
        assert_eq!(error.to_string(), "InjectedPrePayloadFailure");
        assert!(
            completion::pending_links().unwrap().is_empty(),
            "armed initial checkpoint was compensated"
        );
        assert!(!rig.attempt.test_has_custody());
        assert!(!rig.observations().contains(&CredentialV2Kind::FinalApprove));
    }
    {
        let rig = rig(manual).await;
        rig.review().await;
        cbcl_v2_link(rig.request(), rig.app.state()).await.unwrap();
        rig.peer.release.send(ComparisonCase::Confirm).unwrap();
        struct BeforeSignature;
        impl PrePayloadFaultSink for BeforeSignature {
            fn before(&mut self, b: PrePayloadBoundary) -> Result<()> {
                if b == PrePayloadBoundary::IssuerCustody {
                    return Err(UiError::from("InjectedPrePayloadFailure"));
                }
                Ok(())
            }
        }
        let error = continue_link_with_faults(
            rig.request(),
            &rig.app.state::<AppSession>(),
            &mut BeforeSignature,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(error.to_string(), "InjectedPrePayloadFailure");
        assert_eq!(
            rig.observations(),
            vec![
                CredentialV2Kind::IntentApprove,
                CredentialV2Kind::Preparation,
                CredentialV2Kind::FinalApprove
            ]
        );
        assert!(completion::pending_links().unwrap().is_empty());
        assert!(!rig.attempt.test_has_custody());
    }
    for case in [
        ComparisonCase::Decline,
        ComparisonCase::Mismatch,
        ComparisonCase::Alter("carrierCeremonyId"),
        ComparisonCase::Alter("predecessorDigest"),
        ComparisonCase::Alter("previewIssuerDid"),
        ComparisonCase::Alter("previewFingerprintDigest"),
        ComparisonCase::Alter("authorityStatusDigest"),
        ComparisonCase::Alter("authorityStatusResponse"),
        ComparisonCase::Alter("result"),
    ] {
        let rig = rig(manual).await;
        rig.review().await;
        cbcl_v2_link(rig.request(), rig.app.state()).await.unwrap();
        rig.peer.release.send(case).unwrap();
        assert!(cbcl_v2_continue_link(rig.request(), rig.app.state())
            .await
            .is_err());
        assert!(completion::pending_links().unwrap().is_empty());
        assert!(!rig.observations().contains(&CredentialV2Kind::FinalApprove));
        assert!(!rig.attempt.test_has_custody());
    }
    {
        let rig = rig(manual).await;
        rig.review().await;
        cbcl_v2_link(rig.request(), rig.app.state()).await.unwrap();
        // Only this private native test can replace the retained preview. A
        // renderer has no constructor, field, or request member that can do it.
        rig.app
            .state::<AppSession>()
            .0
            .lock()
            .unwrap()
            .pending_cbcl_v2_execution
            .as_mut()
            .unwrap()
            .pending
            .preview_did = Some(Zeroizing::new(format!("did:crdt:{}", "b".repeat(64))));
        rig.peer.release.send(ComparisonCase::Confirm).unwrap();
        struct MustNotEnter;
        impl PrePayloadFaultSink for MustNotEnter {
            fn before(&mut self, _: PrePayloadBoundary) -> Result<()> {
                Err(UiError::from("UnexpectedIdentityBoundary"))
            }
        }
        let error = continue_link_with_faults(
            rig.request(),
            &rig.app.state::<AppSession>(),
            &mut MustNotEnter,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(error.to_string(), "PairingPreviewChanged");
        assert!(completion::pending_links().unwrap().is_empty());
    }
    {
        let app = mock_builder()
            .manage(AppSession(Mutex::new(Session::default())))
            .build(mock_context(noop_assets()))
            .unwrap();
        let tag = {
            let session = app.state::<AppSession>();
            let mut s = session.0.lock().unwrap();
            let operation = s.cbcl_v2_attempts.begin().unwrap();
            let tag = operation.attempt.tag();
            operation.retain();
            tag
        };
        let request = || TaggedRequest {
            attempt_tag: tag.clone(),
        };
        for error in [
            cbcl_v2_contact(request(), app.state()).await.err().unwrap(),
            cbcl_v2_unlock_preview(
                UnlockPreviewRequest {
                    attempt_tag: tag.clone(),
                    passcode: PASS.into(),
                },
                app.state(),
            )
            .await
            .err()
            .unwrap(),
            cbcl_v2_preview_rendered(request(), app.state())
                .await
                .err()
                .unwrap(),
            cbcl_v2_link(request(), app.state()).await.err().unwrap(),
            cbcl_v2_continue_link(request(), app.state())
                .await
                .err()
                .unwrap(),
            cbcl_v2_finish_link(request(), app.state())
                .await
                .err()
                .unwrap(),
            cbcl_v2_cancel_link(request(), app.state())
                .await
                .err()
                .unwrap(),
        ] {
            assert_eq!(error.to_string(), "PairingWrongMode");
        }
        cbcl_v2_cancel(app.state()).await.unwrap();
    }
    for kind in ["continuous", "clock-failure", "root", "background"] {
        let rig = rig(manual).await;
        rig.review().await;
        match kind {
            "continuous" => {
                let mut now = crate::cbcl_v2_clock::snapshot().unwrap();
                now.continuous_ns += 121_000_000_000;
                now.utc -= 300;
                rig.attempt.test_clock(Some(now));
            }
            "clock-failure" => rig.attempt.test_clock(None),
            "root" => Custody::forget().unwrap(),
            _ => rig
                .app
                .state::<AppSession>()
                .0
                .lock()
                .unwrap()
                .cbcl_v2_attempts
                .foreground(false),
        }
        if kind == "continuous" {
            tokio::time::sleep(Duration::from_millis(120)).await;
            assert!(
                !rig.attempt.test_has_custody(),
                "watchdog clears idle custody without lifecycle or commands"
            );
        }
        assert!(
            cbcl_v2_link(rig.request(), rig.app.state()).await.is_err(),
            "{kind}"
        );
        assert!(!rig.attempt.test_has_custody(), "{kind}");
        assert!(rig.observations().is_empty(), "{kind}");
        if kind == "root" {
            Custody::restore(PHRASE, PASS).unwrap();
        }
    }
    for boundary in [
        PrePayloadBoundary::FinalApprovalRelease,
        PrePayloadBoundary::AcknowledgementRead,
        PrePayloadBoundary::AcknowledgementRecognition,
        PrePayloadBoundary::AcknowledgementCheckpointReplacement,
        PrePayloadBoundary::AcknowledgementCheckpointCommit,
        PrePayloadBoundary::PlanConstruction,
        PrePayloadBoundary::PlannedStageReplacement,
        PrePayloadBoundary::IssuerCustody,
        PrePayloadBoundary::IssuerStageReplacement,
        PrePayloadBoundary::IssuerPublication,
        PrePayloadBoundary::ResolverVerification,
        PrePayloadBoundary::GrantConstruction,
        PrePayloadBoundary::ProvisionedStageReplacement,
        PrePayloadBoundary::PayloadConstruction,
        PrePayloadBoundary::PayloadCheckpointPreparation,
    ] {
        let mut attempts = crate::session::CredentialV2Attempts::default();
        let operation = attempts.begin_single_link().unwrap();
        let now = crate::cbcl_v2_clock::snapshot().unwrap();
        operation
            .attempt
            .bind_deadline(now, now.utc + 240, now.utc + 300)
            .unwrap();
        struct PauseAndExpire(CredentialV2Attempt, crate::cbcl_v2_clock::Snapshot);
        impl PrePayloadFaultSink for PauseAndExpire {
            fn before(&mut self, _: PrePayloadBoundary) -> Result<()> {
                self.0.test_clock(Some(self.1));
                Ok(())
            }
        }
        let mut expired = now;
        expired.continuous_ns += 120_000_000_000;
        let mut pause = PauseAndExpire(operation.attempt.clone(), expired);
        let mut faults = CancellationFaults {
            attempt: &operation.attempt,
            inner: &mut pause,
            entry: None,
        };
        assert!(
            faults.before(boundary).is_err(),
            "{boundary:?} resumed at exclusive expiry"
        );
    }
    assert_eq!(completion::identity_effect_count(), identity_effects);
    assert_eq!(
        completion::shared_memkeyring::policy_operations(),
        policy_operations
    );
    completion::shared_memkeyring::clear();
}
