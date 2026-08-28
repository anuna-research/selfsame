//! The browser allocator surface completes a ceremony over the real relay.
//!
//! This drives `CbclAllocatorSession` — the exact wasm-bound value, natively —
//! against the real `RelayService` and the native `ClaimantRelaySession`, both
//! fed by the deterministic local demo credential. The browser's contribution
//! is reduced to what a page actually does: pass binary messages through, act
//! on the JSON effect list, and paint the invitation QR.

use cbcl_pairing::{
    limiter::{LimiterConfig, OperationPolicy},
    observability::CapacityCaps,
    relay::{ConnectionId, RelayConfig, RelayRandomness, RelayService, RoutedMessage},
    wire::{decode_client_message, encode_server_message, Decision},
};
use selfsame_pairing::{
    live::{ClaimantRelaySession, LiveEffect, LiveOutcome},
    local_demo,
};
use selfsame_web_device::{cbcl_invitation_qr_modules_json, CbclAllocatorSession};
use std::collections::VecDeque;

const ALLOCATOR: ConnectionId = ConnectionId(1);
const CLAIMANT: ConnectionId = ConnectionId(2);
const RELAY_ORIGIN: &str = "https://localhost:7443";

fn b64url_decode(text: &str) -> Vec<u8> {
    let padded = match text.len() % 4 {
        2 => format!("{text}=="),
        3 => format!("{text}="),
        _ => text.to_string(),
    };
    let table: Vec<u8> = (b'A'..=b'Z')
        .chain(b'a'..=b'z')
        .chain(b'0'..=b'9')
        .chain(*b"-_")
        .collect();
    let mut bits = 0u32;
    let mut have = 0u8;
    let mut out = Vec::new();
    for byte in padded.bytes() {
        if byte == b'=' {
            break;
        }
        let value = table
            .iter()
            .position(|&candidate| candidate == byte)
            .expect("base64url alphabet") as u32;
        bits = (bits << 6) | value;
        have += 6;
        if have >= 8 {
            have -= 8;
            out.push((bits >> have) as u8);
        }
    }
    out
}

fn allocator_session() -> CbclAllocatorSession {
    let fixture = local_demo::credential(RELAY_ORIGIN).expect("local demo credential");
    let transfer_json = serde_json::json!({
        "applicationId": fixture.transfer.application_id,
        "origin": fixture.transfer.origin,
        "scope": fixture.transfer.scope,
        "recipient": fixture.transfer.recipient,
    })
    .to_string();
    CbclAllocatorSession::new(
        RELAY_ORIGIN.into(),
        &transfer_json,
        &fixture.transfer.bundle,
        &local_demo::profile_octets(RELAY_ORIGIN),
        fixture.verification.account.as_str(),
        &fixture.verification.device_public_key,
        &[0x11; 16],
        &[0x21; 32],
        &[0x31; 32],
        &[0x41; 32],
    )
    .expect("allocator session")
}

#[test]
fn browser_allocator_surface_completes_a_ceremony_over_the_relay_wire() {
    let mut allocator = allocator_session();
    let mut claimant: Option<ClaimantRelaySession> = None;
    let mut relay = relay();
    let mut queue = VecDeque::new();
    let mut tick = 1_u8;
    submit(
        &mut relay,
        &mut queue,
        &mut tick,
        ALLOCATOR,
        allocator.start().expect("bind"),
    );

    let mut invitation_seen = false;
    let mut awaiting_seen = false;
    let mut payload_sent = false;
    let mut allocator_outcome = None;
    let mut claimant_accepted = false;
    let mut claimant_outcome = None;

    while let Some(routed) = queue.pop_front() {
        let wire = encode_server_message(&routed.message).expect("server message");
        if routed.connection == ALLOCATOR {
            let effects: Vec<serde_json::Value> =
                serde_json::from_str(&allocator.receive(&wire).expect("allocator receive"))
                    .expect("effect list");
            for effect in effects {
                match effect["type"].as_str().expect("effect type") {
                    "send" => submit(
                        &mut relay,
                        &mut queue,
                        &mut tick,
                        ALLOCATOR,
                        b64url_decode(effect["bodyB64u"].as_str().expect("send body")),
                    ),
                    "invitation" => {
                        invitation_seen = true;
                        let carrier =
                            b64url_decode(effect["carrierB64u"].as_str().expect("carrier"));
                        // The QR encoder must accept every carrier it is shown.
                        let qr: serde_json::Value = serde_json::from_str(
                            &cbcl_invitation_qr_modules_json(&carrier).expect("qr modules"),
                        )
                        .expect("qr json");
                        let size = qr["size"].as_u64().expect("qr size");
                        assert!(size >= 21);
                        assert_eq!(
                            qr["dark"].as_array().expect("qr dark").len() as u64,
                            size * size
                        );
                        let fixture =
                            local_demo::credential(RELAY_ORIGIN).expect("claimant credential");
                        let session = ClaimantRelaySession::new(
                            &carrier,
                            [0x22; 32],
                            [0x32; 32],
                            fixture.verification,
                        )
                        .expect("claimant session");
                        let start = session.start().expect("claimant bind");
                        claimant = Some(session);
                        submit(&mut relay, &mut queue, &mut tick, CLAIMANT, start);
                    }
                    "awaiting-decision" => awaiting_seen = true,
                    "payload-sent" => payload_sent = true,
                    "terminal" => {
                        allocator_outcome =
                            Some(effect["outcome"].as_str().expect("outcome").to_string());
                    }
                    other => panic!("unexpected allocator effect {other}"),
                }
            }
        } else {
            let effects = claimant
                .as_mut()
                .expect("invitation precedes claimant messages")
                .receive(&wire)
                .expect("claimant receive");
            for effect in effects {
                match effect {
                    LiveEffect::Send(bytes) => {
                        submit(&mut relay, &mut queue, &mut tick, CLAIMANT, bytes)
                    }
                    LiveEffect::DisplayIntent(intent) => {
                        assert_eq!(intent.application(), "anuna.io/credential/v1");
                        let decision = claimant
                            .as_mut()
                            .expect("claimant deciding")
                            .decide(Decision::Approve)
                            .expect("decision effects");
                        for effect in decision {
                            let LiveEffect::Send(bytes) = effect else {
                                panic!("approval emits only its protected decision")
                            };
                            submit(&mut relay, &mut queue, &mut tick, CLAIMANT, bytes);
                        }
                    }
                    LiveEffect::Accepted => claimant_accepted = true,
                    LiveEffect::Terminal(outcome) => claimant_outcome = Some(outcome),
                    LiveEffect::AwaitingDecision
                    | LiveEffect::PayloadSent
                    | LiveEffect::Invitation(_) => {
                        panic!("claimant released an allocator-only effect")
                    }
                }
            }
        }
    }

    assert!(invitation_seen);
    assert!(awaiting_seen);
    assert!(payload_sent);
    assert!(claimant_accepted);
    assert_eq!(allocator_outcome.as_deref(), Some("delivered"));
    assert_eq!(claimant_outcome, Some(LiveOutcome::Accepted));
    relay.sweep(10_000).expect("sweep");
    assert_eq!(relay.mailbox_count(), 0);
}

#[test]
fn cancelled_session_burns_the_attempt() {
    // Refusal after cancel raises a JsError, which only a wasm runtime can
    // construct; natively this test can assert the closing effects and that a
    // second cancel finds nothing left to close.
    let mut allocator = allocator_session();
    let effects = allocator.cancel().expect("cancel effects");
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&effects).expect("effect list");
    assert!(parsed
        .iter()
        .any(|effect| effect["type"] == "terminal" && effect["outcome"] == "cancelled"));
    assert_eq!(allocator.cancel().expect("second cancel"), "[]");
}

fn relay() -> RelayService {
    RelayService::new(RelayConfig {
        operator_key: [0x91; 32],
        limiter: LimiterConfig::new(
            OperationPolicy {
                limit: 240,
                window_seconds: 60,
            },
            128,
            30,
        ),
        capacity: CapacityCaps {
            open_mailboxes: 16,
            queue_bytes: 1_000_000,
            limiter_entries: 128,
        },
        allocation_enabled: true,
    })
    .expect("relay service")
}

fn submit(
    relay: &mut RelayService,
    queue: &mut VecDeque<RoutedMessage>,
    tick: &mut u8,
    connection: ConnectionId,
    bytes: Vec<u8>,
) {
    let message = decode_client_message(&bytes).expect("client message");
    let random = RelayRandomness {
        mailbox_id: [tick.wrapping_add(10); 32],
        membership_token: [tick.wrapping_add(40); 32],
        nameplate: u32::from(*tick) + 100,
    };
    *tick = tick.wrapping_add(1);
    let peer = if connection == ALLOCATOR {
        b"allocator".as_slice()
    } else {
        b"claimant".as_slice()
    };
    queue.extend(
        relay
            .handle(connection, peer, u64::from(*tick), random, message)
            .expect("relay handle"),
    );
}
