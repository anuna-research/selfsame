use cbcl_pairing::{
    limiter::{LimiterConfig, OperationPolicy},
    observability::CapacityCaps,
    relay::{ConnectionId, RelayConfig, RelayRandomness, RelayService, RoutedMessage},
    wire::{
        decode_client_message, encode_client_message, ClientMessage, CloseReason, Locator,
        ServerMessage,
    },
};

#[test]
fn test_717_relay_wire_requires_one_complete_canonical_value() {
    let canonical = encode_client_message(&ClientMessage::Bind).unwrap();
    assert_eq!(
        decode_client_message(&canonical).unwrap(),
        ClientMessage::Bind
    );

    let mut trailing = canonical.clone();
    trailing.push(0);
    assert!(decode_client_message(&trailing).is_err());
    assert!(decode_client_message(&[0xff]).is_err());
    assert!(decode_client_message(&[]).is_err());
}

#[test]
fn test_702_adapter_source_has_no_legacy_pairing_import() {
    let source = include_str!("../src/lib.rs");
    for forbidden in [
        "selfsame_core::spake2",
        "PairingSession",
        "PairingCarrier",
        "pairing_net",
    ] {
        assert!(
            !source.contains(forbidden),
            "adapter imports forbidden legacy symbol {forbidden}"
        );
    }
}

#[test]
fn test_718_third_claim_closes_every_membership_without_payload_effect() {
    let mut relay = RelayService::new(RelayConfig {
        operator_key: [1; 32],
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
    .unwrap();
    let mailbox = [2; 32];

    for (connection, now) in [(1, 1_000), (2, 1_002), (3, 1_004)] {
        assert_eq!(
            relay
                .handle(
                    ConnectionId(connection),
                    b"127.0.0.1",
                    now,
                    relay_randomness(0, 0),
                    ClientMessage::Bind,
                )
                .unwrap(),
            vec![RoutedMessage {
                connection: ConnectionId(connection),
                message: ServerMessage::Welcome,
            }]
        );
    }
    relay
        .handle(
            ConnectionId(1),
            b"127.0.0.1",
            1_001,
            relay_randomness(2, 3),
            ClientMessage::Allocate {
                locator_mode: 0,
                ttl_seconds: Some(60),
            },
        )
        .unwrap();
    relay
        .handle(
            ConnectionId(2),
            b"127.0.0.1",
            1_003,
            relay_randomness(0, 4),
            ClientMessage::Claim(Locator::Direct(mailbox)),
        )
        .unwrap();

    let crowded = relay
        .handle(
            ConnectionId(3),
            b"127.0.0.1",
            1_005,
            relay_randomness(0, 5),
            ClientMessage::Claim(Locator::Direct(mailbox)),
        )
        .unwrap();
    for connection in [1, 2, 3] {
        assert!(crowded.contains(&RoutedMessage {
            connection: ConnectionId(connection),
            message: ServerMessage::Closed(CloseReason::Crowded),
        }));
    }
    assert_eq!(crowded.len(), 3);
}

fn relay_randomness(mailbox: u8, membership: u8) -> RelayRandomness {
    RelayRandomness {
        mailbox_id: [mailbox; 32],
        membership_token: [membership; 32],
        nameplate: 0,
    }
}
