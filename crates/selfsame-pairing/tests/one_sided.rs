#[path = "../../selfsame-app-identity/tests/common/mod.rs"]
mod fixture;

use base64ct::{Base64UrlUnpadded, Encoding as _};
use cbcl_pairing::{
    endpoint::EndpointEffect,
    limiter::{LimiterConfig, OperationPolicy},
    observability::CapacityCaps,
    profile::{
        CredentialGrant, CredentialIntentClaims, CREDENTIAL_ACTION, CREDENTIAL_APPLICATION,
        CREDENTIAL_PAYLOAD,
    },
    relay::{ConnectionId, RelayConfig, RelayRandomness, RelayService, RoutedMessage},
    wire::{
        decode_channel_frame, decode_client_message, decode_server_message, encode_channel_frame,
        encode_client_message, encode_invitation, encode_server_message, ApplicationPayload,
        ChannelFrame, ClientMessage, Decision, Invitation, Locator, PairingIntent, ServerMessage,
        Side,
    },
};
use selfsame_app_identity::{accept::Freshness, ceremony};
use selfsame_pairing::{
    SelfsameEndpointBootstrap, SelfsameEndpointEffect, SelfsameProof, SelfsameVerificationContext,
};
use std::io::{BufRead, BufReader, Write as _};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

const MAILBOX_ID: [u8; 32] = [0x31; 32];

#[test]
fn test_803_independent_endpoint_sessions_complete_the_cbcl_ceremony() {
    let invitation = invitation();
    let allocator_bootstrap = SelfsameEndpointBootstrap::start(
        Side::Allocator,
        &invitation,
        MAILBOX_ID,
        [0x41; 32],
        [0x51; 32],
    )
    .expect("allocator bootstrap");
    let claimant_bootstrap = SelfsameEndpointBootstrap::start(
        Side::Claimant,
        &invitation,
        MAILBOX_ID,
        [0x42; 32],
        [0x52; 32],
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
        .expect("allocator finished is valid");
    let claimant_finished = claimant
        .local_finished_frame()
        .expect("claimant finished")
        .expect("claimant finished is valid");
    assert!(claimant
        .receive_frame(&allocator_finished, None)
        .expect("claimant confirms allocator")
        .is_empty());
    let opener = sent_adapter_frame(
        allocator
            .receive_frame(&claimant_finished, None)
            .expect("allocator confirms claimant"),
    );
    assert!(claimant
        .receive_frame(&opener, None)
        .expect("claimant receives role cast")
        .is_empty());
    assert!(allocator.session_ready() && claimant.session_ready());

    let claims = claims();
    let (allocator_claim, claimant_claim) = claims.encode().expect("claims");
    let intent = PairingIntent {
        application: CREDENTIAL_APPLICATION.into(),
        action: CREDENTIAL_ACTION.into(),
        allocator_claim,
        claimant_claim,
        authority_summary: "Transfer one Selfsame device grant".into(),
        intent_nonce: [0x61; 32],
    };
    let intent_frame = allocator.send_intent(&intent).expect("send intent");
    let displayed = claimant
        .receive_frame(&intent_frame, None)
        .expect("receive intent");
    assert!(displayed
        .iter()
        .any(|effect| matches!(effect, SelfsameEndpointEffect::DisplayIntent(_))));

    let approval = sent_frame(claimant.decide(Decision::Approve).expect("approve"));
    assert!(allocator
        .receive_frame(&approval, None)
        .expect("receive approval")
        .is_empty());
    let example = fixture::Ceremony::accepted();
    let bundle = ceremony::build_bundle(
        &selfsame_app_identity::codec::b64url(&[21; 32]),
        &selfsame_app_identity::codec::b64url(&[22; 32]),
        core::str::from_utf8(&example.grant_bytes).unwrap(),
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
    .expect("grant");
    let payload = ApplicationPayload {
        intent_digest: allocator.intent_digest().expect("intent digest"),
        payload_type: CREDENTIAL_PAYLOAD.into(),
        body: grant,
    };
    let payload_frame = allocator.send_payload(&payload).expect("send payload");
    let verification = verification(&example);
    let delivered = claimant
        .receive_frame(&payload_frame, Some(&verification))
        .expect("receive payload");
    assert!(delivered
        .iter()
        .any(|effect| matches!(effect, SelfsameEndpointEffect::Accepted(_))));
    assert_eq!(claimant.delivered_payloads(), 1);
    assert_eq!(claimant.pairing_verifier_calls(), 1);
    assert_eq!(claimant.selfsame_verifier_calls(), 1);
    allocator
        .relay_closed(cbcl_pairing::wire::CloseReason::Closed)
        .expect("allocator close");
    claimant
        .relay_closed(cbcl_pairing::wire::CloseReason::Closed)
        .expect("claimant close");
    assert!(allocator.secrets_erased() && claimant.secrets_erased());
}

#[test]
fn test_803_separate_processes_complete_through_the_real_relay_wire() {
    let mut allocator = EndpointProcess::spawn("allocator");
    let mut claimant = EndpointProcess::spawn("claimant");
    let mut relay = ProcessRelay::new();

    let allocator_cpace = allocator.frame();
    let claimant_cpace = claimant.frame();
    claimant.send_frame(&relay.transmit(Side::Allocator, &allocator_cpace));
    allocator.send_frame(&relay.transmit(Side::Claimant, &claimant_cpace));

    let allocator_finished = allocator.frame();
    let claimant_finished = claimant.frame();
    claimant.send_frame(&relay.transmit(Side::Allocator, &allocator_finished));
    assert_eq!(claimant.message(), "FINISHED-RECEIVED");
    allocator.send_frame(&relay.transmit(Side::Claimant, &claimant_finished));

    let role_cast = allocator.frame();
    claimant.send_frame(&relay.transmit(Side::Allocator, &role_cast));
    assert_eq!(claimant.message(), "READY");
    allocator.send("START");

    let intent = allocator.frame();
    claimant.send_frame(&relay.transmit(Side::Allocator, &intent));
    let decision = claimant.frame();
    allocator.send_frame(&relay.transmit(Side::Claimant, &decision));
    let payload = allocator.frame();
    claimant.send_frame(&relay.transmit(Side::Allocator, &payload));
    assert_eq!(claimant.message(), "ACCEPTED 1 1 1");

    relay.close();
    allocator.send("CLOSE");
    claimant.send("CLOSE");
    assert_eq!(allocator.message(), "CLOSED ERASED");
    assert_eq!(claimant.message(), "CLOSED ERASED");
    allocator.finish();
    claimant.finish();
}

/// Child-side endpoint used only when the parent test starts this test binary
/// again with an exact ignored-test filter.
#[test]
#[ignore = "spawned by TEST-803 to prove process isolation"]
fn endpoint_process() {
    match std::env::var("SELFSAME_SPEC007_ENDPOINT").as_deref() {
        Ok("allocator") => allocator_process(),
        Ok("claimant") => claimant_process(),
        _ => panic!("endpoint helper requires an explicit role"),
    }
}

fn allocator_process() {
    let mut input = BufReader::new(std::io::stdin());
    let bootstrap = SelfsameEndpointBootstrap::start(
        Side::Allocator,
        &invitation(),
        MAILBOX_ID,
        [0x41; 32],
        [0x51; 32],
    )
    .unwrap();
    child_frame(bootstrap.local_cpace_frame());
    let mut endpoint = bootstrap.finish(&child_read_frame(&mut input)).unwrap();
    child_frame(&endpoint.local_finished_frame().unwrap().unwrap());
    let role_cast = sent_adapter_frame(
        endpoint
            .receive_frame(&child_read_frame(&mut input), None)
            .unwrap(),
    );
    child_frame(&role_cast);
    assert_eq!(child_read(&mut input), "START");

    let claims = claims();
    let (allocator_claim, claimant_claim) = claims.encode().unwrap();
    child_frame(
        &endpoint
            .send_intent(&PairingIntent {
                application: CREDENTIAL_APPLICATION.into(),
                action: CREDENTIAL_ACTION.into(),
                allocator_claim,
                claimant_claim,
                authority_summary: "Transfer one Selfsame device grant".into(),
                intent_nonce: [0x61; 32],
            })
            .unwrap(),
    );
    endpoint
        .receive_frame(&child_read_frame(&mut input), None)
        .unwrap();

    let example = fixture::Ceremony::accepted();
    let bundle = ceremony::build_bundle(
        &selfsame_app_identity::codec::b64url(&[21; 32]),
        &selfsame_app_identity::codec::b64url(&[22; 32]),
        core::str::from_utf8(&example.grant_bytes).unwrap(),
        None,
    )
    .unwrap();
    let grant = CredentialGrant {
        application_id: claims.application_id,
        origin: claims.origin,
        scope: claims.scope,
        recipient: claims.recipient,
        credential: bundle,
    }
    .encode()
    .unwrap();
    child_frame(
        &endpoint
            .send_payload(&ApplicationPayload {
                intent_digest: endpoint.intent_digest().unwrap(),
                payload_type: CREDENTIAL_PAYLOAD.into(),
                body: grant,
            })
            .unwrap(),
    );
    assert_eq!(child_read(&mut input), "CLOSE");
    endpoint
        .relay_closed(cbcl_pairing::wire::CloseReason::Closed)
        .unwrap();
    child_message(if endpoint.secrets_erased() {
        "CLOSED ERASED"
    } else {
        "CLOSED RETAINED"
    });
}

fn claimant_process() {
    let mut input = BufReader::new(std::io::stdin());
    let bootstrap = SelfsameEndpointBootstrap::start(
        Side::Claimant,
        &invitation(),
        MAILBOX_ID,
        [0x42; 32],
        [0x52; 32],
    )
    .unwrap();
    child_frame(bootstrap.local_cpace_frame());
    let mut endpoint = bootstrap.finish(&child_read_frame(&mut input)).unwrap();
    child_frame(&endpoint.local_finished_frame().unwrap().unwrap());
    assert!(endpoint
        .receive_frame(&child_read_frame(&mut input), None)
        .unwrap()
        .is_empty());
    child_message("FINISHED-RECEIVED");
    assert!(endpoint
        .receive_frame(&child_read_frame(&mut input), None)
        .unwrap()
        .is_empty());
    assert!(endpoint.session_ready());
    child_message("READY");

    let effects = endpoint
        .receive_frame(&child_read_frame(&mut input), None)
        .unwrap();
    assert!(effects
        .iter()
        .any(|effect| matches!(effect, SelfsameEndpointEffect::DisplayIntent(_))));
    child_frame(&sent_frame(endpoint.decide(Decision::Approve).unwrap()));

    let example = fixture::Ceremony::accepted();
    let effects = endpoint
        .receive_frame(&child_read_frame(&mut input), Some(&verification(&example)))
        .unwrap();
    assert!(effects
        .iter()
        .any(|effect| matches!(effect, SelfsameEndpointEffect::Accepted(_))));
    child_message(&format!(
        "ACCEPTED {} {} {}",
        endpoint.delivered_payloads(),
        endpoint.pairing_verifier_calls(),
        endpoint.selfsame_verifier_calls()
    ));
    assert_eq!(child_read(&mut input), "CLOSE");
    endpoint
        .relay_closed(cbcl_pairing::wire::CloseReason::Closed)
        .unwrap();
    child_message(if endpoint.secrets_erased() {
        "CLOSED ERASED"
    } else {
        "CLOSED RETAINED"
    });
}

fn child_read(input: &mut impl BufRead) -> String {
    let mut line = String::new();
    input.read_line(&mut line).expect("parent command");
    line.trim().to_owned()
}

fn child_read_frame(input: &mut impl BufRead) -> ChannelFrame {
    let line = child_read(input);
    let encoded = line.strip_prefix("FRAME ").expect("frame command");
    let bytes = Base64UrlUnpadded::decode_vec(encoded).expect("frame base64url");
    decode_channel_frame(&bytes).expect("canonical channel frame")
}

fn child_frame(frame: &ChannelFrame) {
    let bytes = encode_channel_frame(frame).expect("canonical channel frame");
    child_message(&format!(
        "FRAME {}",
        Base64UrlUnpadded::encode_string(&bytes)
    ));
}

fn child_message(message: &str) {
    println!("SPEC007 {message}");
    std::io::stdout().flush().expect("flush child output");
}

struct EndpointProcess {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl EndpointProcess {
    fn spawn(role: &str) -> Self {
        let mut child = Command::new(std::env::current_exe().expect("test executable"))
            .args(["--ignored", "--exact", "endpoint_process", "--nocapture"])
            .env("SELFSAME_SPEC007_ENDPOINT", role)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn endpoint process");
        let input = child.stdin.take().expect("child stdin");
        let output = BufReader::new(child.stdout.take().expect("child stdout"));
        Self {
            child,
            input,
            output,
        }
    }

    fn send(&mut self, message: &str) {
        writeln!(self.input, "{message}").expect("write endpoint command");
        self.input.flush().expect("flush endpoint command");
    }

    fn send_frame(&mut self, frame: &ChannelFrame) {
        let bytes = encode_channel_frame(frame).expect("canonical channel frame");
        self.send(&format!(
            "FRAME {}",
            Base64UrlUnpadded::encode_string(&bytes)
        ));
    }

    fn message(&mut self) -> String {
        loop {
            let mut line = String::new();
            let read = self.output.read_line(&mut line).expect("endpoint output");
            assert_ne!(
                read, 0,
                "endpoint exited before returning a protocol message"
            );
            if let Some(message) = line.trim().strip_prefix("SPEC007 ") {
                return message.to_owned();
            }
        }
    }

    fn frame(&mut self) -> ChannelFrame {
        let message = self.message();
        let encoded = message.strip_prefix("FRAME ").expect("endpoint frame");
        let bytes = Base64UrlUnpadded::decode_vec(encoded).expect("frame base64url");
        decode_channel_frame(&bytes).expect("canonical channel frame")
    }

    fn finish(mut self) {
        drop(self.input);
        assert!(self.child.wait().expect("endpoint exit").success());
    }
}

struct ProcessRelay {
    service: RelayService,
    sequence: [u8; 2],
    now: u64,
}

impl ProcessRelay {
    fn new() -> Self {
        let mut relay = Self {
            service: RelayService::new(RelayConfig {
                operator_key: [0x81; 32],
                limiter: LimiterConfig::new(
                    OperationPolicy {
                        limit: 100,
                        window_seconds: 60,
                    },
                    32,
                    30,
                ),
                capacity: CapacityCaps {
                    open_mailboxes: 4,
                    queue_bytes: 4 * 69_632,
                    limiter_entries: 32,
                },
                allocation_enabled: true,
            })
            .unwrap(),
            sequence: [0, 0],
            now: 1_000,
        };
        relay.expect(ConnectionId(1), ClientMessage::Bind, [0; 32]);
        relay.expect(
            ConnectionId(1),
            ClientMessage::Allocate {
                locator_mode: 0,
                ttl_seconds: Some(600),
            },
            [0x91; 32],
        );
        relay.expect(ConnectionId(2), ClientMessage::Bind, [0; 32]);
        relay.expect(
            ConnectionId(2),
            ClientMessage::Claim(Locator::Direct(MAILBOX_ID)),
            [0x92; 32],
        );
        relay
    }

    fn transmit(&mut self, side: Side, frame: &ChannelFrame) -> ChannelFrame {
        let body = encode_channel_frame(frame).unwrap();
        let (source, destination, index) = match side {
            Side::Allocator => (ConnectionId(1), ConnectionId(2), 0),
            Side::Claimant => (ConnectionId(2), ConnectionId(1), 1),
        };
        let seq = self.sequence[index];
        self.sequence[index] += 1;
        let routed = self.handle(source, ClientMessage::Put { seq, body });
        let (peer_seq, body) = routed
            .into_iter()
            .find_map(|item| match item {
                RoutedMessage {
                    connection,
                    message: ServerMessage::Frame { peer_seq, body },
                } if connection == destination => Some((peer_seq, body)),
                _ => None,
            })
            .expect("relay delivers one peer frame");
        self.handle(destination, ClientMessage::Ack { peer_seq });
        decode_channel_frame(&body).unwrap()
    }

    fn close(&mut self) {
        self.handle(ConnectionId(1), ClientMessage::Close);
        self.service.sweep(2_000).unwrap();
    }

    fn expect(&mut self, connection: ConnectionId, message: ClientMessage, membership: [u8; 32]) {
        assert_eq!(
            self.handle_with_membership(connection, message, membership)
                .len(),
            1
        );
    }

    fn handle(&mut self, connection: ConnectionId, message: ClientMessage) -> Vec<RoutedMessage> {
        self.handle_with_membership(connection, message, [0; 32])
    }

    fn handle_with_membership(
        &mut self,
        connection: ConnectionId,
        message: ClientMessage,
        membership_token: [u8; 32],
    ) -> Vec<RoutedMessage> {
        let encoded = encode_client_message(&message).unwrap();
        let message = decode_client_message(&encoded).unwrap();
        let randomness = RelayRandomness {
            mailbox_id: MAILBOX_ID,
            membership_token,
            nameplate: 0,
        };
        let routed = self
            .service
            .handle(connection, b"127.0.0.1", self.now, randomness, message)
            .unwrap();
        self.now += 1;
        routed
            .into_iter()
            .map(|item| RoutedMessage {
                connection: item.connection,
                message: decode_server_message(&encode_server_message(&item.message).unwrap())
                    .unwrap(),
            })
            .collect()
    }
}

#[test]
fn test_813_decline_and_replay_are_terminal_without_payload_effects() {
    let invitation = invitation();
    let allocator_bootstrap = SelfsameEndpointBootstrap::start(
        Side::Allocator,
        &invitation,
        MAILBOX_ID,
        [0x71; 32],
        [0x72; 32],
    )
    .unwrap();
    let claimant_bootstrap = SelfsameEndpointBootstrap::start(
        Side::Claimant,
        &invitation,
        MAILBOX_ID,
        [0x73; 32],
        [0x74; 32],
    )
    .unwrap();
    let allocator_cpace = allocator_bootstrap.local_cpace_frame().clone();
    let claimant_cpace = claimant_bootstrap.local_cpace_frame().clone();
    let mut allocator = allocator_bootstrap.finish(&claimant_cpace).unwrap();
    let mut claimant = claimant_bootstrap.finish(&allocator_cpace).unwrap();
    let allocator_finished = allocator.local_finished_frame().unwrap().unwrap();
    let claimant_finished = claimant.local_finished_frame().unwrap().unwrap();
    claimant.receive_frame(&allocator_finished, None).unwrap();
    let opener = sent_adapter_frame(allocator.receive_frame(&claimant_finished, None).unwrap());
    claimant.receive_frame(&opener, None).unwrap();

    let claims = claims();
    let (allocator_claim, claimant_claim) = claims.encode().unwrap();
    let intent = allocator
        .send_intent(&PairingIntent {
            application: CREDENTIAL_APPLICATION.into(),
            action: CREDENTIAL_ACTION.into(),
            allocator_claim,
            claimant_claim,
            authority_summary: "Transfer one Selfsame device grant".into(),
            intent_nonce: [0x75; 32],
        })
        .unwrap();
    claimant.receive_frame(&intent, None).unwrap();
    let decline = sent_frame(claimant.decide(Decision::Decline).unwrap());
    allocator.receive_frame(&decline, None).unwrap();

    assert_eq!(claimant.delivered_payloads(), 0);
    assert_eq!(claimant.pairing_verifier_calls(), 0);
    assert!(allocator.secrets_erased() && claimant.secrets_erased());
    assert!(allocator.receive_frame(&decline, None).is_ok());
    assert!(claimant.decide(Decision::Decline).is_ok());
    assert_eq!(claimant.delivered_payloads(), 0);
}

fn invitation() -> Vec<u8> {
    encode_invitation(&Invitation {
        application: CREDENTIAL_APPLICATION.into(),
        relay_origin: "https://relay.example".into(),
        locator: Locator::Direct(MAILBOX_ID),
        secret: vec![0x21; 16],
        expected_allocator_key: None,
        expected_claimant_key: None,
    })
    .expect("invitation")
}

fn claims() -> CredentialIntentClaims {
    let example = fixture::Ceremony::accepted();
    CredentialIntentClaims {
        application_id: fixture::APPLICATION_ID.into(),
        origin: "https://photos.example".into(),
        scope: fixture::PERMISSION.into(),
        recipient: example.device_did,
    }
}

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

fn sent_frame(effects: Vec<EndpointEffect>) -> ChannelFrame {
    effects
        .into_iter()
        .find_map(|effect| match effect {
            EndpointEffect::SendFrame(frame) => Some(frame),
            _ => None,
        })
        .expect("one send-frame effect")
}

fn sent_adapter_frame(effects: Vec<SelfsameEndpointEffect>) -> ChannelFrame {
    effects
        .into_iter()
        .find_map(|effect| match effect {
            SelfsameEndpointEffect::SendFrame(frame) => Some(frame),
            _ => None,
        })
        .expect("one send-frame effect")
}
