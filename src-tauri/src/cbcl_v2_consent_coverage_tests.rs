//! SPEC079 TEST005/006/007: actual command and executor coverage.
use super::*;
use crate::cbcl_v2_commands::CredentialV2Phase;
use base64ct::Encoding as _;

#[path = "cbcl_v2_consent_test_resolver.rs"]
mod resolver;

const BOUNDARIES: [PrePayloadBoundary; 15] = [
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
];

#[derive(Clone, Copy, Debug)]
enum Revoke {
    Expire,
    Cancel,
}

struct Pause<'a> {
    rig: &'a Rig,
    resolver: &'a resolver::Resolver,
    target: PrePayloadBoundary,
    reason: Revoke,
    visited: Vec<PrePayloadBoundary>,
    paused: Option<(usize, usize, usize, Vec<CredentialV2Kind>)>,
}
impl PrePayloadFaultSink for Pause<'_> {
    fn before(&mut self, boundary: PrePayloadBoundary) -> Result<()> {
        self.visited.push(boundary);
        if boundary == self.target {
            // A preceding send may already be in the peer's socket. Observe
            // that entered effect before taking the pause baseline.
            if boundary != PrePayloadBoundary::FinalApprovalRelease {
                let deadline = std::time::Instant::now() + Duration::from_secs(2);
                while !self
                    .rig
                    .observations()
                    .contains(&CredentialV2Kind::FinalApprove)
                {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "prior final approval arrived"
                    );
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
            // This callback is entered by the actual production executor,
            // after its first check and before its atomic effect entry.
            self.paused = Some((
                completion::shared_memkeyring::write_count(),
                completion::identity_effect_count(),
                self.resolver.requests(),
                self.rig.observations(),
            ));
            match self.reason {
                Revoke::Expire => {
                    let mut now = crate::cbcl_v2_clock::snapshot()?;
                    now.continuous_ns += 120_000_000_000;
                    now.utc -= 300; // rollback cannot extend the original bound
                    self.rig.attempt.test_clock(Some(now));
                }
                Revoke::Cancel => self
                    .rig
                    .app
                    .state::<AppSession>()
                    .0
                    .lock()
                    .unwrap()
                    .revoke_cbcl_v2(),
            }
        }
        Ok(())
    }
}

#[tokio::test]
#[ignore = "installs process-global memory custody and local test TLS; run alone"]
async fn single_link_actual_executor_expiry_and_revocation_at_every_boundary() {
    completion::shared_memkeyring::install();
    completion::shared_memkeyring::clear();
    Custody::restore(PHRASE, PASS).unwrap();
    let resolver = resolver::Resolver::install();
    let policy = completion::shared_memkeyring::policy_operations();
    for manual in [false, true] {
        for reason in [Revoke::Expire, Revoke::Cancel] {
            for (index, target) in BOUNDARIES.into_iter().enumerate() {
                resolver.reset();
                let rig = rig_with_resolver(manual, true).await;
                rig.review().await;
                cbcl_v2_link(rig.request(), rig.app.state()).await.unwrap();
                rig.peer.release.send(ComparisonCase::Confirm).unwrap();
                let mut pause = Pause {
                    rig: &rig,
                    resolver: &resolver,
                    target,
                    reason,
                    visited: Vec::new(),
                    paused: None,
                };
                let error = continue_link_with_faults(
                    rig.request(),
                    &rig.app.state::<AppSession>(),
                    &mut pause,
                )
                .await
                .err()
                .expect("the resumed executor must refuse");
                assert_eq!(
                    pause.visited,
                    BOUNDARIES[..=index],
                    "{manual}/{reason:?}/{target:?}"
                );
                assert_eq!(
                    error.to_string(),
                    match reason {
                        Revoke::Expire => "PairingExpired",
                        Revoke::Cancel => "PairingCancelled",
                    },
                    "{manual}/{reason:?}/{target:?}"
                );
                let (writes, identities, requests, objects) =
                    pause.paused.expect("actual target reached");
                assert_eq!(
                    completion::shared_memkeyring::write_count(),
                    writes + 2,
                    "only owned slot deletion and index compensation at {target:?}"
                );
                assert_eq!(
                    completion::identity_effect_count(),
                    identities,
                    "no next identity effect at {target:?}"
                );
                assert_eq!(
                    resolver.requests(),
                    requests,
                    "no next network effect at {target:?}"
                );
                assert_eq!(
                    rig.observations(),
                    objects,
                    "no next protocol object at {target:?}"
                );
                assert!(
                    completion::pending_links().unwrap().is_empty(),
                    "exact compensation at {target:?}"
                );
                assert!(completion::installed_links().unwrap().is_empty());
                assert!(!rig.attempt.test_has_custody());
                assert!(rig.attempt.check().is_err());
                assert_eq!(completion::shared_memkeyring::policy_operations(), policy);
                eprintln!("executor mode={} reason={reason:?} boundary={target:?} reached={} next_effects=0", if manual {"manual"} else {"full"}, index+1);
            }
        }
    }
    completion::shared_memkeyring::clear();
}

fn facts(
    pending: &PendingCredentialV2Pairing,
) -> (CredentialV2Carrier, Vec<u8>, RecognisedCredentialV2Offer) {
    let claimant = &pending.claimant;
    (
        claimant.carrier().clone(),
        claimant.profile_octets().to_vec(),
        recognise_signed_offer(
            claimant.profile(),
            claimant.authenticated_offer().unwrap().body(),
        )
        .unwrap(),
    )
}

#[tokio::test]
#[ignore = "installs process-global memory custody; run alone"]
async fn single_link_owned_binding_preservation_and_closed_substitutions() {
    completion::shared_memkeyring::install();
    completion::shared_memkeyring::clear();
    Custody::restore(PHRASE, PASS).unwrap();
    for manual in [false, true] {
        let rig = rig(manual).await;
        let original = {
            let session = rig.app.state::<AppSession>();
            let guard = session.0.lock().unwrap();
            facts(guard.pending_cbcl_v2.as_ref().unwrap())
        };
        assert_eq!(original.0.mailbox_id(), &[0x31; 32]);
        assert_eq!(original.0.carrier_ceremony_id(), &[0x32; 32]);
        assert_eq!(original.0.carrier_nonce(), &[0x33; 32]);
        assert_eq!(original.2.request_id, [0x41; 32]);
        assert_eq!(original.2.intent_nonce, [0x45; 32]);
        assert_eq!(
            *original.2.claims.account_provenance().account_scope_id(),
            [0x44; 32]
        );
        assert_eq!(
            original.2.claims.permissions(),
            &[fixture::PERMISSION.to_string()]
        );
        assert_eq!(
            original.2.profile_digest,
            *ApplicationProfile::recognise(&original.1).unwrap().digest()
        );
        rig.review().await;
        let policy = completion::shared_memkeyring::policy_operations();
        for linked in [false, true] {
            let before = (
                completion::shared_memkeyring::write_count(),
                completion::identity_effect_count(),
                rig.observations(),
            );
            // These names represent the complete CON003 input surface. They
            // are not additional native fields: Tauri's recognized DTO cannot
            // carry any of them, before or after ownership moves into Link.
            for name in [
                "attemptGeneration",
                "flow",
                "rootGeneration",
                "carrier",
                "carrierDigest",
                "applicationId",
                "profile",
                "profileDigest",
                "descriptor",
                "relayOrigin",
                "transcriptHash",
                "offer",
                "offerCore",
                "intent",
                "transition",
                "accountPrincipal",
                "accountScopeId",
                "installationDeviceKey",
                "permissions",
                "previewIssuerDid",
                "previewFingerprint",
                "predecessor",
                "deadline",
            ] {
                let mut request = serde_json::json!({"attemptTag": rig.tag});
                request[name] = serde_json::json!("caller-selected-replacement");
                assert!(
                    serde_json::from_value::<TaggedRequest>(request).is_err(),
                    "{linked}/{name}"
                );
            }
            let stale = TaggedRequest {
                attempt_tag: "f".repeat(32),
            };
            let error = if linked {
                cbcl_v2_continue_link(stale, rig.app.state())
                    .await
                    .err()
                    .unwrap()
            } else {
                cbcl_v2_link(stale, rig.app.state()).await.err().unwrap()
            };
            assert_eq!(error.to_string(), "PairingStaleAttempt");
            assert_eq!(
                (
                    completion::shared_memkeyring::write_count(),
                    completion::identity_effect_count(),
                    rig.observations()
                ),
                before
            );
            {
                let session = rig.app.state::<AppSession>();
                let guard = session.0.lock().unwrap();
                let pending = if linked {
                    &guard.pending_cbcl_v2_execution.as_ref().unwrap().pending
                } else {
                    guard.pending_cbcl_v2.as_ref().unwrap()
                };
                assert_eq!(facts(pending), original, "owned facts across preview/Link");
                guard
                    .cbcl_v2_attempts
                    .ensure_current(&pending.attempt)
                    .unwrap();
                assert_eq!(pending.attempt.tag(), rig.tag);
                assert_eq!(pending.claimant.flow(), CredentialV2Flow::SingleLink);
                assert_eq!(
                    pending.phase,
                    if linked {
                        CredentialV2Phase::Comparing
                    } else {
                        CredentialV2Phase::ReviewReady
                    }
                );
            }
            if !linked {
                cbcl_v2_link(rig.request(), rig.app.state()).await.unwrap();
            }
        }
        rig.peer.release.send(ComparisonCase::Confirm).unwrap();
        struct ObserveConsumer<'a> {
            original: &'a (CredentialV2Carrier, Vec<u8>, RecognisedCredentialV2Offer),
            reached: bool,
        }
        impl PrePayloadFaultSink for ObserveConsumer<'_> {
            fn before(&mut self, boundary: PrePayloadBoundary) -> Result<()> {
                if boundary != PrePayloadBoundary::IssuerCustody {
                    return Ok(());
                }
                let pending = completion::load_pending(self.original.0.application_context())?;
                let value = serde_json::to_value(pending).unwrap();
                let bytes = |name| {
                    base64ct::Base64UrlUnpadded::decode_vec(value[name].as_str().unwrap()).unwrap()
                };
                assert_eq!(bytes("offerProfile"), self.original.1);
                assert_eq!(bytes("carrier"), encode_carrier(&self.original.0).unwrap());
                let offer = decode_object(&bytes("offer")).unwrap();
                assert_eq!(offer.body(), self.original.2.signed_offer);
                let intent = decode_object(&bytes("intentApprove")).unwrap();
                let comparison = decode_object(&bytes("comparison")).unwrap();
                let final_approve = decode_object(&bytes("finalApprove")).unwrap();
                assert_eq!(intent.kind(), CredentialV2Kind::IntentApprove);
                assert_eq!(comparison.kind(), CredentialV2Kind::ComparisonConfirmed);
                assert_eq!(final_approve.kind(), CredentialV2Kind::FinalApprove);
                assert_eq!(offer.intent_digest(), intent.intent_digest());
                assert_eq!(offer.intent_digest(), comparison.intent_digest());
                assert_eq!(offer.intent_digest(), final_approve.intent_digest());
                self.reached = true;
                Err(UiError::from("ObservedExactConsumer"))
            }
        }
        let mut observer = ObserveConsumer {
            original: &original,
            reached: false,
        };
        let error =
            continue_link_with_faults(rig.request(), &rig.app.state::<AppSession>(), &mut observer)
                .await
                .err()
                .unwrap();
        assert_eq!(error.to_string(), "ObservedExactConsumer");
        assert!(observer.reached);
        assert!(completion::pending_links().unwrap().is_empty());
        assert_eq!(completion::shared_memkeyring::policy_operations(), policy);
    }
    completion::shared_memkeyring::clear();
}

#[tokio::test]
#[ignore = "installs process-global memory custody and local test TLS; run alone"]
async fn single_link_actual_held_publication_and_resolver_results_are_revoked() {
    completion::shared_memkeyring::install();
    completion::shared_memkeyring::clear();
    Custody::restore(PHRASE, PASS).unwrap();
    let resolver = resolver::Resolver::install();
    for manual in [false, true] {
        for reason in [Revoke::Expire, Revoke::Cancel] {
            for target in [resolver::Hold::Publication, resolver::Hold::Resolution] {
                resolver.reset();
                resolver.arm(target);
                let rig = rig_with_resolver(manual, true).await;
                rig.review().await;
                cbcl_v2_link(rig.request(), rig.app.state()).await.unwrap();
                rig.peer.release.send(ComparisonCase::Confirm).unwrap();
                let continuation = cbcl_v2_continue_link(rig.request(), rig.app.state());
                let cancel = async {
                    let deadline = std::time::Instant::now() + Duration::from_secs(5);
                    while !resolver.held() {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "real TLS response reached"
                        );
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                    let baseline = (
                        completion::shared_memkeyring::write_count(),
                        completion::identity_effect_count(),
                        resolver.requests(),
                        rig.observations(),
                    );
                    match reason {
                        Revoke::Expire => {
                            let mut now = crate::cbcl_v2_clock::snapshot().unwrap();
                            now.continuous_ns += 120_000_000_000;
                            rig.attempt.test_clock(Some(now));
                        }
                        Revoke::Cancel => cbcl_v2_cancel_link(rig.request(), rig.app.state())
                            .await
                            .unwrap(),
                    }
                    resolver.release();
                    baseline
                };
                let (result, baseline) = tokio::join!(continuation, cancel);
                assert_eq!(
                    result.err().unwrap().to_string(),
                    match reason {
                        Revoke::Expire => "PairingExpired",
                        Revoke::Cancel => "PairingCancelled",
                    }
                );
                assert_eq!(completion::shared_memkeyring::write_count(), baseline.0 + 2);
                assert_eq!(completion::identity_effect_count(), baseline.1);
                assert_eq!(resolver.requests(), baseline.2);
                assert_eq!(rig.observations(), baseline.3);
                assert!(completion::pending_links().unwrap().is_empty());
                assert!(completion::installed_links().unwrap().is_empty());
                assert!(!rig.attempt.test_has_custody());
                eprintln!(
                    "held-result mode={} reason={reason:?} result={target:?} next_effects=0",
                    if manual { "manual" } else { "full" }
                );
            }
        }
    }
    completion::shared_memkeyring::clear();
}

#[tokio::test]
#[ignore = "installs process-global memory custody; run alone"]
async fn single_link_ready_io_and_sync_results_cannot_cross_revocation() {
    completion::shared_memkeyring::install();
    completion::shared_memkeyring::clear();
    Custody::restore(PHRASE, PASS).unwrap();
    for asynchronous in [false, true] {
        for reason in [Revoke::Expire, Revoke::Cancel] {
            let mut attempts = crate::session::CredentialV2Attempts::default();
            let operation = attempts.begin_single_link().unwrap();
            let now = crate::cbcl_v2_clock::snapshot().unwrap();
            operation
                .attempt
                .bind_deadline(now, now.utc + 240, now.utc + 300)
                .unwrap();
            let mut action = || {
                match reason {
                    Revoke::Expire => {
                        operation
                            .attempt
                            .test_clock(Some(crate::cbcl_v2_clock::Snapshot {
                                continuous_ns: now.continuous_ns + 120_000_000_000,
                                ..now
                            }))
                    }
                    Revoke::Cancel => attempts.cancel(),
                }
                Ok(17_u8)
            };
            let result = if asynchronous {
                operation.attempt.io(async { action() }).await
            } else {
                operation.attempt.run(action)
            };
            assert!(
                result.is_err(),
                "a ready result cannot escape its original bound"
            );
            let mut later = false;
            assert!(operation
                .attempt
                .run(|| {
                    later = true;
                    Ok(())
                })
                .is_err());
            assert!(!later);
        }
    }
    // The production blocking reader has its own timeout/result fence. Hold
    // a real entered read, then deliver a well-formed public relay reply after
    // revocation. The body is never exposed to a successor reducer.
    for reason in [None, Some(Revoke::Expire), Some(Revoke::Cancel)] {
        let mut attempts = crate::session::CredentialV2Attempts::default();
        let operation = attempts.begin_single_link().unwrap();
        let now = crate::cbcl_v2_clock::snapshot().unwrap();
        operation
            .attempt
            .bind_deadline(now, now.utc + 240, now.utc + 300)
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        let mut peer = WebSocket::from_raw_socket(peer, tungstenite::protocol::Role::Server, None);
        let mut socket = WebSocket::from_raw_socket(
            MaybeTlsStream::Plain(client),
            tungstenite::protocol::Role::Client,
            None,
        );
        let attempt = operation.attempt.clone();
        let reader = std::thread::spawn(move || read_binary(&mut socket, &attempt));
        let waiting = std::time::Instant::now() + Duration::from_secs(2);
        while operation.attempt.test_entered_effects() == 0 {
            assert!(
                std::time::Instant::now() < waiting,
                "actual blocking read entered"
            );
            std::thread::yield_now();
        }
        match reason {
            Some(Revoke::Expire) => {
                operation
                    .attempt
                    .test_clock(Some(crate::cbcl_v2_clock::Snapshot {
                        continuous_ns: now.continuous_ns + 120_000_000_000,
                        ..now
                    }))
            }
            Some(Revoke::Cancel) => attempts.cancel(),
            None => (),
        }
        let reply = encode_server_message(&ServerMessage::Acknowledged { seq: 0 }).unwrap();
        let delivered = peer.send(Message::Binary(reply.clone().into())).is_ok();
        // A loaded host may resume after the read's 50 ms timeout. Revocation
        // can then close the socket before delivery; that is still refusal,
        // but is not reported as a delivered late reply in the evidence.
        if reason.is_none() {
            assert!(delivered, "positive public relay reply delivered");
        }
        eprintln!("blocking-read reason={reason:?} reply_delivered={delivered}");
        let result = reader.join().unwrap();
        if let Some(reason) = reason {
            assert_eq!(
                result.expect_err("late valid reply refused").to_string(),
                match reason {
                    Revoke::Expire => "PairingExpired",
                    Revoke::Cancel => "PairingCancelled",
                }
            );
        } else {
            assert_eq!(result.unwrap(), reply);
        }
        assert_eq!(operation.attempt.test_entered_effects(), 0);
    }
    completion::shared_memkeyring::clear();
}

#[tokio::test]
#[ignore = "installs process-global memory custody and local test TLS; run alone"]
async fn single_link_actual_commit_boundaries_compensate_or_preserve_payload() {
    completion::shared_memkeyring::install();
    completion::shared_memkeyring::clear();
    Custody::restore(PHRASE, PASS).unwrap();
    let resolver = resolver::Resolver::install();
    for manual in [false, true] {
        for reason in [Revoke::Expire, Revoke::Cancel] {
            for payload in [false, true] {
                resolver.reset();
                let rig = rig_with_resolver(manual, true).await;
                rig.review().await;
                cbcl_v2_link(rig.request(), rig.app.state()).await.unwrap();
                rig.peer.release.send(ComparisonCase::Confirm).unwrap();
                let observed = Arc::new(Mutex::new(None));
                let observed_commit = observed.clone();
                let attempt = rig.attempt.clone();
                let app = rig.app.handle().clone();
                completion::shared_memkeyring::on_next_matching_set(
                    move |_, bytes| {
                        let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
                            return false;
                        };
                        value["state"] == "pending"
                            && value["value"]["stage"]["phase"]
                                == if payload {
                                    "payload-prepared"
                                } else {
                                    "final-approval"
                                }
                    },
                    move || {
                        *observed_commit.lock().unwrap() = Some((
                            completion::shared_memkeyring::write_count(),
                            completion::identity_effect_count(),
                        ));
                        match reason {
                            Revoke::Expire => {
                                let mut now = crate::cbcl_v2_clock::snapshot().unwrap();
                                now.continuous_ns += 120_000_000_000;
                                attempt.test_clock(Some(now));
                            }
                            Revoke::Cancel => {
                                app.state::<AppSession>().0.lock().unwrap().revoke_cbcl_v2()
                            }
                        }
                    },
                );
                let error = cbcl_v2_continue_link(rig.request(), rig.app.state())
                    .await
                    .err()
                    .unwrap();
                assert_eq!(
                    error.to_string(),
                    match reason {
                        Revoke::Expire => "PairingExpired",
                        Revoke::Cancel => "PairingCancelled",
                    }
                );
                let (writes, identities) = observed
                    .lock()
                    .unwrap()
                    .expect("real storage commit reached");
                assert_eq!(completion::identity_effect_count(), identities);
                assert_eq!(
                    completion::shared_memkeyring::write_count(),
                    writes + if payload { 0 } else { 2 },
                    "only exact owned slot/index compensation is allowed"
                );
                assert!(
                    !rig.observations().contains(&CredentialV2Kind::Payload),
                    "no payload release after the storage-result fence"
                );
                assert!(completion::installed_links().unwrap().is_empty());
                assert!(!rig.attempt.test_has_custody());
                let remaining = completion::pending_links().unwrap();
                if payload {
                    assert_eq!(remaining.len(), 1);
                    assert_eq!(remaining[0].phase, "payload-prepared");
                    let record = completion::load_pending(&remaining[0].application_id).unwrap();
                    completion::remove_pending(&record).unwrap(); // explicit owned fixture cleanup
                } else {
                    assert!(remaining.is_empty());
                    assert!(!rig.observations().contains(&CredentialV2Kind::FinalApprove));
                }
                eprintln!(
                    "commit mode={} reason={reason:?} payload={payload} next_identity_effects=0",
                    if manual { "manual" } else { "full" }
                );
            }
        }
    }
    completion::shared_memkeyring::clear();
}

#[tokio::test]
#[ignore = "installs process-global memory custody and local test TLS; run alone"]
async fn single_link_actual_live_installation_responses_are_revoked() {
    completion::shared_memkeyring::install();
    completion::shared_memkeyring::clear();
    Custody::restore(PHRASE, PASS).unwrap();
    let resolver = resolver::Resolver::install();
    // Populate the resolver using the real native issuer publication, then
    // test the independent live-binding verifier with these real signed deltas.
    let rig = rig_with_resolver(false, true).await;
    let profile = rig
        .app
        .state::<AppSession>()
        .0
        .lock()
        .unwrap()
        .pending_cbcl_v2
        .as_ref()
        .unwrap()
        .claimant
        .profile()
        .clone();
    rig.review().await;
    cbcl_v2_link(rig.request(), rig.app.state()).await.unwrap();
    rig.peer.release.send(ComparisonCase::Confirm).unwrap();
    struct Stop;
    impl PrePayloadFaultSink for Stop {
        fn before(&mut self, boundary: PrePayloadBoundary) -> Result<()> {
            if boundary == PrePayloadBoundary::GrantConstruction {
                Err(UiError::from("PublishedFixture"))
            } else {
                Ok(())
            }
        }
    }
    let error = continue_link_with_faults(rig.request(), &rig.app.state::<AppSession>(), &mut Stop)
        .await
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "PublishedFixture");
    let (did, account_text) = resolver.binding();
    let account = selfsame_app_identity::alias::AcctUri::parse(&account_text).unwrap();
    for target in [
        None,
        Some(resolver::Hold::Resolution),
        Some(resolver::Hold::WebFinger),
    ] {
        for reason in [Revoke::Expire, Revoke::Cancel] {
            let mut attempts = crate::session::CredentialV2Attempts::default();
            let operation = attempts.begin_single_link().unwrap();
            let now = crate::cbcl_v2_clock::snapshot().unwrap();
            operation
                .attempt
                .bind_deadline(now, now.utc + 240, now.utc + 300)
                .unwrap();
            if let Some(target) = target {
                resolver.arm(target);
            }
            let verifier = verify_live_installation_guarded(
                profile.clone(),
                account.clone(),
                did.clone(),
                &operation.attempt,
            );
            if target.is_none() {
                let jrd = verifier.await.unwrap();
                selfsame_app_identity::alias::verify_reciprocal_binding(
                    &jrd,
                    &account,
                    &did,
                    std::slice::from_ref(&account_text),
                )
                .unwrap();
                continue;
            }
            let revoke = async {
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                while !resolver.held() {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "actual installation request reached"
                    );
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                let baseline = (
                    resolver.requests(),
                    completion::shared_memkeyring::write_count(),
                    completion::identity_effect_count(),
                );
                match reason {
                    Revoke::Expire => {
                        operation
                            .attempt
                            .test_clock(Some(crate::cbcl_v2_clock::Snapshot {
                                continuous_ns: now.continuous_ns + 120_000_000_000,
                                ..now
                            }))
                    }
                    Revoke::Cancel => attempts.cancel(),
                }
                resolver.release();
                baseline
            };
            let (result, baseline) = tokio::join!(verifier, revoke);
            assert_eq!(
                result.err().unwrap().to_string(),
                match reason {
                    Revoke::Expire => "PairingExpired",
                    Revoke::Cancel => "PairingCancelled",
                }
            );
            assert_eq!(
                (
                    resolver.requests(),
                    completion::shared_memkeyring::write_count(),
                    completion::identity_effect_count()
                ),
                baseline
            );
            assert!(completion::pending_links().unwrap().is_empty());
            assert!(completion::installed_links().unwrap().is_empty());
        }
    }
    completion::shared_memkeyring::clear();
}

#[tokio::test]
#[ignore = "installs process-global memory custody and local test TLS; run alone"]
async fn single_link_actual_install_operation_requires_live_authority() {
    completion::shared_memkeyring::install();
    completion::shared_memkeyring::clear();
    Custody::restore(PHRASE, PASS).unwrap();
    let resolver = resolver::Resolver::install();
    for manual in [false, true] {
        for reason in [None, Some(Revoke::Expire), Some(Revoke::Cancel)] {
            resolver.reset();
            let rig = rig_with_resolver(manual, true).await;
            rig.review().await;
            cbcl_v2_link(rig.request(), rig.app.state()).await.unwrap();
            rig.peer.release.send(ComparisonCase::Confirm).unwrap();
            assert_eq!(
                cbcl_v2_continue_link(rig.request(), rig.app.state())
                    .await
                    .unwrap()
                    .phase,
                "await-receipt"
            );
            let application = "https://photos.example/selfsame/application";
            let durable = completion::load_pending(application).unwrap();
            let profile_octets = durable.offer_profile_octets().unwrap();
            let profile = ApplicationProfile::recognise(&profile_octets).unwrap();
            let carrier = durable.carrier().unwrap();
            let offer_object = durable.offer_object().unwrap();
            let offer = recognise_signed_offer(&profile, offer_object.body()).unwrap();
            let payload_facts = durable.payload_facts().unwrap();
            let commitment = rig
                .app
                .state::<AppSession>()
                .0
                .lock()
                .unwrap()
                .pending_cbcl_v2
                .as_mut()
                .unwrap()
                .claimant
                .core_mut()
                .receipt_recovery_commitment()
                .unwrap();
            let input = CredentialV2FinalStatusInput {
                application_id: application.into(),
                carrier_ceremony_id: *carrier.carrier_ceremony_id(),
                request_id: offer.request_id,
                account_principal_digest: *offer
                    .claims
                    .account_provenance()
                    .account_principal_digest(),
                account_scope_id: *offer.claims.account_provenance().account_scope_id(),
                device_did: offer.claims.device_binding().device_did().into(),
                offer_core_digest: *offer.claims.offer_core_digest(),
                payload_digest: payload_facts.payload_content_hash,
                grant_id: payload_facts.grant_id,
                issuer_did: payload_facts.issuer_did.clone(),
                receipt_recovery_commitment: commitment,
                finalized_at: crate::commands::now(),
            };
            let status =
                build_final_status(&profile, &input, KID, &SigningKey::from_bytes(&[0x21; 32]))
                    .unwrap();
            let object = recovered_receipt_object(
                *offer_object.intent_digest(),
                *carrier.carrier_ceremony_id(),
                input.payload_digest,
                CredentialV2ReceiptInput {
                    final_status_jws: status.jws,
                    final_status_digest: status.digest,
                },
            )
            .unwrap();
            // The actual endpoint authenticates the retained predecessor, then
            // the production factory verifies the real signed final status
            // and issued grant. This is a recovery-object fixture, not a claim
            // of another complete network Receipt ceremony.
            let receipt = rig
                .app
                .state::<AppSession>()
                .0
                .lock()
                .unwrap()
                .pending_cbcl_v2
                .as_mut()
                .unwrap()
                .claimant
                .core_mut()
                .authenticate_recovered_receipt_object(object)
                .unwrap();
            let installed = completion::InstalledCredentialV2Link::from_authenticated_receipt(
                &durable,
                &profile_octets,
                receipt.object(),
                commitment,
            )
            .unwrap();
            let jrd = verify_live_installation_guarded(
                profile,
                installed.account().unwrap(),
                installed.issuer_did().into(),
                &rig.attempt,
            )
            .await
            .unwrap();
            let original_bytes = serde_json::to_vec(&durable).unwrap();
            let writes = completion::shared_memkeyring::write_count();
            match reason {
                Some(Revoke::Expire) => {
                    let mut now = crate::cbcl_v2_clock::snapshot().unwrap();
                    now.continuous_ns += 120_000_000_000;
                    rig.attempt.test_clock(Some(now));
                }
                Some(Revoke::Cancel) => cbcl_v2_cancel_link(rig.request(), rig.app.state())
                    .await
                    .unwrap(),
                None => (),
            }
            let result = install_guarded(&rig.attempt, &durable, &installed, &jrd);
            if reason.is_some() {
                assert!(
                    result.is_err(),
                    "revoked actual install operation must refuse"
                );
                assert_eq!(completion::shared_memkeyring::write_count(), writes);
                assert_eq!(
                    serde_json::to_vec(&completion::load_pending(application).unwrap()).unwrap(),
                    original_bytes
                );
                assert!(completion::installed_links().unwrap().is_empty());
                completion::remove_pending(&durable).unwrap();
            } else {
                result.unwrap();
                assert_eq!(completion::load_installed(application).unwrap(), installed);
                let selected = completion::load_local_link(application).unwrap();
                completion::unlink_local(&selected).unwrap();
            }
            eprintln!(
                "install-operation mode={} reason={reason:?} actual_signed_candidate=true",
                if manual { "manual" } else { "full" }
            );
        }
    }
    completion::shared_memkeyring::clear();
}

#[tokio::test]
#[ignore = "installs process-global memory custody; run alone"]
async fn single_link_valid_mutable_comparison_bindings_refuse_before_effects() {
    completion::shared_memkeyring::install();
    completion::shared_memkeyring::clear();
    Custody::restore(PHRASE, PASS).unwrap();
    for manual in [false, true] {
        for field in [
            "positiveNoBinding",
            "boundSame",
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
            let rig = rig(manual).await;
            rig.review().await;
            cbcl_v2_link(rig.request(), rig.app.state()).await.unwrap();
            let baseline = (
                completion::shared_memkeyring::write_count(),
                completion::identity_effect_count(),
            );
            rig.peer
                .release
                .send(if field == "positiveNoBinding" {
                    ComparisonCase::Confirm
                } else {
                    ComparisonCase::Alter(field)
                })
                .unwrap();
            struct Stop {
                reached: bool,
            }
            impl PrePayloadFaultSink for Stop {
                fn before(&mut self, boundary: PrePayloadBoundary) -> Result<()> {
                    assert_eq!(boundary, PrePayloadBoundary::FinalApprovalRelease);
                    self.reached = true;
                    Err(UiError::from("ObservedComparisonAccepted"))
                }
            }
            let mut stop = Stop { reached: false };
            let error =
                continue_link_with_faults(rig.request(), &rig.app.state::<AppSession>(), &mut stop)
                    .await
                    .err()
                    .unwrap();
            if matches!(field, "positiveNoBinding" | "boundSame") {
                assert!(stop.reached, "valid comparison reaches exact next boundary");
                assert_eq!(error.to_string(), "ObservedComparisonAccepted");
            } else {
                assert!(
                    !stop.reached,
                    "valid but mismatched comparison reached successor: {field}"
                );
                assert_eq!(
                    (
                        completion::shared_memkeyring::write_count(),
                        completion::identity_effect_count()
                    ),
                    baseline,
                    "comparison mismatch has no successor effect: {field}"
                );
            }
            assert!(completion::pending_links().unwrap().is_empty());
            assert!(completion::installed_links().unwrap().is_empty());
            assert!(!rig.observations().contains(&CredentialV2Kind::FinalApprove));
            assert!(!rig.attempt.test_has_custody());
            eprintln!(
                "comparison mode={} field={field} successor={}",
                if manual { "manual" } else { "full" },
                stop.reached
            );
        }
    }
    completion::shared_memkeyring::clear();
}
