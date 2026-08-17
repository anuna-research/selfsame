use cbcl_pairing::{
    limiter::{LimiterConfig, OperationPolicy},
    observability::CapacityCaps,
    profile::CredentialGrant,
    relay::{ConnectionId, RelayConfig, RelayRandomness, RelayService, RoutedMessage},
    wire::{
        decode_client_message, encode_client_message, ClientMessage, CloseReason, Locator,
        ServerMessage,
    },
};
use selfsame_pairing::MAX_CREDENTIAL_PAYLOAD_OCTETS;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn test_818_credential_profile_enforces_the_exact_payload_bound() {
    let grant = |length| CredentialGrant {
        application_id: "https://photos.example/selfsame/application".into(),
        origin: "https://photos.example".into(),
        scope: "https://photos.example/selfsame/application#photos.read".into(),
        recipient: "did:example:device".into(),
        credential: vec![0x5a; length],
    };
    assert!(grant(MAX_CREDENTIAL_PAYLOAD_OCTETS).encode().is_ok());
    assert!(grant(MAX_CREDENTIAL_PAYLOAD_OCTETS + 1).encode().is_err());
}

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
fn test_802_production_sources_have_no_legacy_pairing_path() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let mut sources = Vec::new();
    for root in [
        repository.join("crates"),
        repository.join("src-tauri/src"),
        repository.join("src"),
    ] {
        collect_production_sources(&root, &mut sources);
    }

    for forbidden in [
        "selfsame_core::spake2",
        "pub struct PairingSession",
        "PairingCarrier",
        "mod pairing_net",
        "mod pairing;",
        "pairingRecordRelays",
        "selfsame-pairing-v1",
        "selfsame-rendezvous-v1",
        "PROTO-002",
        "PROTO-003",
        "PROTO-004",
        "/pair/v1",
        "/proto002/rendezvous",
        "/pairing/records",
    ] {
        for source in &sources {
            let contents = fs::read_to_string(source).expect("UTF-8 production source");
            assert!(
                !contents.contains(forbidden),
                "{} retains forbidden legacy pairing source `{forbidden}`",
                source.display()
            );
        }
    }
}

#[test]
fn test_802_dependency_graph_selects_only_cbcl_pairing() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let output = Command::new(env!("CARGO"))
        .current_dir(repository)
        .args([
            "tree", "-p", "selfsame", "--edges", "normal", "--prefix", "none",
        ])
        .output()
        .expect("cargo tree runs");
    assert!(output.status.success(), "cargo tree failed");
    let tree = String::from_utf8(output.stdout).expect("cargo tree is UTF-8");
    assert!(tree
        .lines()
        .any(|line| line.starts_with("selfsame-pairing ")));
    assert!(tree.lines().any(|line| line.starts_with("cbcl-pairing ")));
    assert!(!tree.lines().any(|line| line.starts_with("spake2 ")));
}

#[test]
fn test_812_legacy_executables_are_deleted_but_authority_is_retained() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    for removed in [
        "crates/selfsame-core/src/spake2.rs",
        "crates/selfsame-core/src/envelope.rs",
        "crates/selfsame-app-identity/src/pairing.rs",
        "crates/selfsame-app-identity/src/pairing_code.rs",
        "crates/selfsame-app-identity/src/selection.rs",
        "crates/selfsame-app-identity-net/src/probe.rs",
        "crates/selfsame-web-device/src/carrier.rs",
        "crates/selfsame-rendezvous/src/pairing.rs",
        "src-tauri/src/pairing.rs",
        "src-tauri/src/pairing_net.rs",
        "src-tauri/tests/a_live_pairing.rs",
    ] {
        assert!(
            !repository.join(removed).exists(),
            "legacy executable remains: {removed}"
        );
    }

    for authority in [
        "specs/PROTO-002-selfsame-rendezvous-v1.md",
        "specs/PROTO-003-selfsame-pairing-v1.md",
        "specs/PROTO-004-selfsame-ceremony-envelope-v1.md",
    ] {
        let text = fs::read_to_string(repository.join(authority)).expect("retained authority");
        assert!(
            text.contains("SPEC-007"),
            "{authority} has no versioned cutover disposition"
        );
        assert!(text.contains("Production approval: not granted."));
    }
}

fn collect_production_sources(root: &Path, sources: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries {
        let path = entry.expect("source directory entry").path();
        if path.is_dir() {
            collect_production_sources(&path, sources);
        } else if matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("rs" | "js" | "html")
        ) && !path.ends_with("selfsame-pairing/src/legacy.rs")
            && !path.components().any(|part| part.as_os_str() == "tests")
            && !path.components().any(|part| part.as_os_str() == "examples")
        {
            sources.push(path);
        }
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
