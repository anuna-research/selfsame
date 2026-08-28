#![cfg(feature = "local-pairing-demo")]

use cbcl_pairing::{
    limiter::{LimiterConfig, OperationPolicy},
    observability::CapacityCaps,
    relay::{ConnectionId, RelayConfig, RelayRandomness, RelayService, RoutedMessage},
    wire::{decode_client_message, encode_server_message, Decision},
};
use selfsame_pairing::{
    live::{
        AllocatorEntropy, AllocatorRelaySession, ClaimantRelaySession, LiveEffect, LiveOutcome,
    },
    local_demo,
};
use std::collections::VecDeque;

const ALLOCATOR: ConnectionId = ConnectionId(1);
const CLAIMANT: ConnectionId = ConnectionId(2);

#[test]
fn test_803_through_805_live_sessions_complete_over_the_relay_wire() {
    let result = drive(Decision::Approve, false);
    assert!(result.displayed);
    assert!(result.accepted);
    assert_eq!(result.payloads, 1);
    assert_eq!(result.allocator_outcome, Some(LiveOutcome::Delivered));
    assert_eq!(result.claimant_outcome, Some(LiveOutcome::Accepted));
}

#[test]
fn test_804_decline_releases_no_payload_and_calls_no_selfsame_verifier() {
    let result = drive(Decision::Decline, false);
    assert!(result.displayed);
    assert!(!result.accepted);
    assert_eq!(result.payloads, 0);
    assert_eq!(result.allocator_outcome, Some(LiveOutcome::Declined));
    assert_eq!(result.claimant_outcome, Some(LiveOutcome::Declined));
}

#[test]
fn test_806_mutated_grant_is_refused_after_valid_pairing() {
    let result = drive(Decision::Approve, true);
    assert!(result.displayed);
    assert!(!result.accepted);
    assert_eq!(result.payloads, 1);
    assert_eq!(result.allocator_outcome, Some(LiveOutcome::Delivered));
    assert_eq!(result.claimant_outcome, Some(LiveOutcome::Refused));
}

#[derive(Default)]
struct RunResult {
    displayed: bool,
    accepted: bool,
    payloads: usize,
    allocator_outcome: Option<LiveOutcome>,
    claimant_outcome: Option<LiveOutcome>,
}

fn drive(decision: Decision, mutate_signature: bool) -> RunResult {
    let relay_origin = "https://localhost:7443";
    let fixture = if mutate_signature {
        local_demo::credential_with_mutated_signature(relay_origin).unwrap()
    } else {
        local_demo::credential(relay_origin).unwrap()
    };
    let mut allocator = AllocatorRelaySession::new(
        relay_origin.into(),
        fixture.transfer,
        &fixture.verification,
        AllocatorEntropy {
            invitation_secret: [0x11; 16],
            cpace_scalar: [0x21; 32],
            signing_seed: [0x31; 32],
            intent_nonce: [0x41; 32],
        },
    )
    .unwrap();
    let mut claimant: Option<ClaimantRelaySession> = None;
    let mut relay = relay();
    let mut queue = VecDeque::new();
    let mut tick = 1_u8;
    submit(
        &mut relay,
        &mut queue,
        &mut tick,
        ALLOCATOR,
        allocator.start().unwrap(),
    );

    let mut result = RunResult::default();
    while let Some(routed) = queue.pop_front() {
        let wire = encode_server_message(&routed.message).unwrap();
        let effects = if routed.connection == ALLOCATOR {
            allocator.receive(&wire).unwrap()
        } else {
            claimant
                .as_mut()
                .expect("invitation precedes claimant messages")
                .receive(&wire)
                .unwrap()
        };
        for effect in effects {
            match effect {
                LiveEffect::Send(bytes) => {
                    submit(&mut relay, &mut queue, &mut tick, routed.connection, bytes)
                }
                LiveEffect::Invitation(carrier) => {
                    let fixture = local_demo::credential(relay_origin).unwrap();
                    let session = ClaimantRelaySession::new(
                        &carrier,
                        [0x22; 32],
                        [0x32; 32],
                        fixture.verification,
                    )
                    .unwrap();
                    let start = session.start().unwrap();
                    claimant = Some(session);
                    submit(&mut relay, &mut queue, &mut tick, CLAIMANT, start);
                }
                LiveEffect::DisplayIntent(intent) => {
                    assert_eq!(intent.application(), "anuna.io/credential/v1");
                    result.displayed = true;
                    let decision = claimant.as_mut().unwrap().decide(decision).unwrap();
                    for effect in decision {
                        let LiveEffect::Send(bytes) = effect else {
                            panic!("approval emits only its protected decision")
                        };
                        submit(&mut relay, &mut queue, &mut tick, CLAIMANT, bytes);
                    }
                }
                LiveEffect::Accepted => result.accepted = true,
                LiveEffect::Terminal(outcome) if routed.connection == ALLOCATOR => {
                    result.allocator_outcome = Some(outcome)
                }
                LiveEffect::Terminal(outcome) => result.claimant_outcome = Some(outcome),
                LiveEffect::PayloadSent => result.payloads += 1,
                LiveEffect::AwaitingDecision => {}
            }
        }
    }

    relay.sweep(10_000).unwrap();
    assert_eq!(relay.mailbox_count(), 0);
    result
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
    .unwrap()
}

fn submit(
    relay: &mut RelayService,
    queue: &mut VecDeque<RoutedMessage>,
    tick: &mut u8,
    connection: ConnectionId,
    bytes: Vec<u8>,
) {
    let message = decode_client_message(&bytes).unwrap();
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
            .unwrap(),
    );
}
