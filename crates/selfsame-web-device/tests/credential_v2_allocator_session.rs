//! Browser/WASM boundary for the distinct credential/v2 allocator.

use cbcl_pairing::{
    cpace,
    credential_v2::{
        decode_carrier, decode_frame, encode_frame, CredentialV2Context, CredentialV2Frame,
        CredentialV2Presence, PendingCredentialV2Channel,
    },
    wire::{decode_client_message, encode_server_message, ClientMessage, ServerMessage, Side},
};
use selfsame_app_identity::profile::ApplicationProfile;
use selfsame_pairing::local_demo;
use selfsame_web_device::CredentialV2BrowserAllocatorSession;

const RELAY: &str = "https://localhost:7443";

fn effects(value: String) -> Vec<serde_json::Value> {
    serde_json::from_str(&value).expect("closed effect JSON")
}

fn body(effect: &serde_json::Value) -> Vec<u8> {
    decode_b64u(effect["bodyB64u"].as_str().unwrap())
}

fn decode_b64u(text: &str) -> Vec<u8> {
    let alphabet: Vec<u8> = (b'A'..=b'Z')
        .chain(b'a'..=b'z')
        .chain(b'0'..=b'9')
        .chain(*b"-_")
        .collect();
    let mut bits = 0_u32;
    let mut count = 0_u8;
    let mut output = Vec::new();
    for byte in text.bytes() {
        bits = (bits << 6)
            | u32::try_from(
                alphabet
                    .iter()
                    .position(|candidate| *candidate == byte)
                    .unwrap(),
            )
            .unwrap();
        count += 6;
        if count >= 8 {
            count -= 8;
            output.push((bits >> count) as u8);
        }
    }
    output
}

fn checkpoint(
    allocator: &mut CredentialV2BrowserAllocatorSession,
    input: ServerMessage,
    nonce: u8,
    generation: u64,
) -> Vec<serde_json::Value> {
    let encoded = encode_server_message(&input).unwrap();
    let checkpoint_effects = effects(
        allocator
            .receive(&encoded, 1_800_000_000, &[nonce; 12])
            .unwrap(),
    );
    assert_eq!(checkpoint_effects.len(), 1);
    assert_eq!(checkpoint_effects[0]["type"], "checkpoint");
    assert_eq!(checkpoint_effects[0]["generation"], generation);
    effects(allocator.checkpoint_persisted(generation).unwrap())
}

#[test]
fn wasm_surface_carries_recovery_bindings_and_hub_correlators_only_after_checkpoint() {
    let profile = local_demo::profile_octets(RELAY);
    let mut allocator = CredentialV2BrowserAllocatorSession::new(
        &profile,
        RELAY.into(),
        &[0x11; 32],
        &[0x12; 32],
        &[0x13; 32],
        &[0x14; 16],
        &[0x15; 16],
        &[0x16; 32],
        &[0x17; 32],
        &[0x18; 32],
        &[0x19; 32],
        &[0x1a; 32],
    )
    .unwrap();

    let start = effects(allocator.start().unwrap());
    assert_eq!(
        decode_client_message(&body(&start[0])).unwrap(),
        ClientMessage::Bind,
    );

    let welcome = encode_server_message(&ServerMessage::Welcome).unwrap();
    let allocate = effects(
        allocator
            .receive(&welcome, 1_800_000_000, &[0x21; 12])
            .unwrap(),
    );
    assert!(matches!(
        decode_client_message(&body(&allocate[0])).unwrap(),
        ClientMessage::AllocateV2 {
            ttl_seconds: Some(900),
            ..
        }
    ));

    let allocated = encode_server_message(&ServerMessage::AllocatedV2 {
        mailbox_id: [0x11; 32],
        membership_token: [0x22; 32],
        expires_at: 1_800_000_900,
    })
    .unwrap();
    let checkpoint = effects(
        allocator
            .receive(&allocated, 1_800_000_000, &[0x23; 12])
            .unwrap(),
    );
    assert_eq!(checkpoint.len(), 1);
    assert_eq!(checkpoint[0]["type"], "checkpoint");
    assert_eq!(checkpoint[0]["generation"], 1);
    assert!(checkpoint[0]["checkpointB64u"].as_str().unwrap().len() > 100);
    assert!(checkpoint[0]["rawCarrierB64u"].as_str().unwrap().len() > 100);
    assert_eq!(
        checkpoint[0]["carrierCeremonyIdB64u"]
            .as_str()
            .unwrap()
            .len(),
        43
    );

    let pending = effects(allocator.checkpoint_persisted(1).unwrap());
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["type"], "pending-allocation");
    assert_eq!(pending[0]["requestIdB64u"].as_str().unwrap().len(), 43);
    assert_eq!(pending[0]["intentNonceB64u"].as_str().unwrap().len(), 43);
    assert_eq!(
        pending[0]["carrierCeremonyIdB64u"],
        checkpoint[0]["carrierCeremonyIdB64u"],
    );
    assert_eq!(
        pending[0]["rawCarrierB64u"],
        checkpoint[0]["rawCarrierB64u"]
    );
}

#[test]
fn wasm_surface_completes_cpace_only_through_persisted_relay_transitions() {
    let profile_octets = local_demo::profile_octets(RELAY);
    let profile = ApplicationProfile::recognise(&profile_octets).unwrap();
    let mut allocator = CredentialV2BrowserAllocatorSession::new(
        &profile_octets,
        RELAY.into(),
        &[0x31; 32],
        &[0x32; 32],
        &[0x33; 32],
        &[0x34; 16],
        &[0x35; 16],
        &[0x36; 32],
        &[0x37; 32],
        &[0x38; 32],
        &[0x39; 32],
        &[0x3a; 32],
    )
    .unwrap();

    assert_eq!(
        decode_client_message(&body(&effects(allocator.start().unwrap())[0])).unwrap(),
        ClientMessage::Bind,
    );
    let welcome = encode_server_message(&ServerMessage::Welcome).unwrap();
    let allocate = effects(
        allocator
            .receive(&welcome, 1_800_000_000, &[0x41; 12])
            .unwrap(),
    );
    assert!(matches!(
        decode_client_message(&body(&allocate[0])).unwrap(),
        ClientMessage::AllocateV2 {
            ttl_seconds: Some(900),
            ..
        }
    ));

    let pending = checkpoint(
        &mut allocator,
        ServerMessage::AllocatedV2 {
            mailbox_id: [0x31; 32],
            membership_token: [0x42; 32],
            expires_at: 1_800_000_900,
        },
        0x43,
        1,
    );
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["type"], "pending-allocation");
    let carrier =
        decode_carrier(&decode_b64u(pending[0]["rawCarrierB64u"].as_str().unwrap())).unwrap();
    let context = CredentialV2Context::derive(&carrier, *profile.digest()).unwrap();
    let claimant_presence = CredentialV2Presence::new([0x34; 16], [0x35; 16]);
    let (claimant_state, claimant_share) = context
        .start_cpace(Side::Claimant, &claimant_presence, [0x44; 32])
        .unwrap();
    let claimant_share = CredentialV2Frame::cpace(&claimant_share).unwrap();

    let allocator_share_effects = checkpoint(
        &mut allocator,
        ServerMessage::Frame {
            peer_seq: 0,
            body: encode_frame(&claimant_share).unwrap(),
        },
        0x45,
        2,
    );
    assert_eq!(allocator_share_effects.len(), 2);
    assert!(matches!(
        decode_client_message(&body(&allocator_share_effects[0])).unwrap(),
        ClientMessage::Ack { peer_seq: 0 }
    ));
    let ClientMessage::Put {
        seq: 0,
        body: allocator_share,
    } = decode_client_message(&body(&allocator_share_effects[1])).unwrap()
    else {
        panic!("allocator share must be relay sequence zero")
    };
    let allocator_share = decode_frame(&allocator_share).unwrap();

    let allocator_finished_effects = checkpoint(
        &mut allocator,
        ServerMessage::Acknowledged { seq: 0 },
        0x46,
        3,
    );
    assert_eq!(allocator_finished_effects.len(), 1);
    let ClientMessage::Put {
        seq: 1,
        body: allocator_finished,
    } = decode_client_message(&body(&allocator_finished_effects[0])).unwrap()
    else {
        panic!("allocator Finished must be relay sequence one")
    };
    let allocator_finished = decode_frame(&allocator_finished).unwrap();

    let claimant_isk = cpace::finish(
        claimant_state,
        allocator_share.cpace_message().expect("allocator CPace"),
    )
    .unwrap();
    let claimant_pending = PendingCredentialV2Channel::new(
        Side::Claimant,
        claimant_isk,
        context.public_context(),
        &encode_frame(&allocator_share).unwrap(),
        &encode_frame(&claimant_share).unwrap(),
    )
    .unwrap();
    let claimant_finished = claimant_pending.local_finished_frame();
    claimant_pending.confirm(&allocator_finished).unwrap();

    assert!(checkpoint(
        &mut allocator,
        ServerMessage::Acknowledged { seq: 1 },
        0x47,
        4,
    )
    .is_empty());
    let established = checkpoint(
        &mut allocator,
        ServerMessage::Frame {
            peer_seq: 1,
            body: encode_frame(&claimant_finished).unwrap(),
        },
        0x48,
        5,
    );
    assert_eq!(established.len(), 2);
    assert!(matches!(
        decode_client_message(&body(&established[0])).unwrap(),
        ClientMessage::Ack { peer_seq: 1 }
    ));
    assert_eq!(established[1]["type"], "established");
    assert_eq!(
        decode_b64u(established[1]["transcriptHashB64u"].as_str().unwrap()).len(),
        64,
    );
}
