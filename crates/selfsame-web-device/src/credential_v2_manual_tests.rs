//! Adapter cases for SPEC-078 TEST-001/002/003/006/007. Refusal tests call the
//! exact pure implementation under the exports: native JsError aborts are not tests.
use super::*;
use base64ct::{Base64UrlUnpadded, Encoding};
use cbcl_pairing::{
    cpace,
    credential_v2::{
        decode_carrier, decode_frame, encode_frame, CredentialV2AllocatorMode as Mode,
        CredentialV2Carrier, CredentialV2Context, CredentialV2Frame, CredentialV2Handoff,
        CredentialV2ManualBootstrap, CredentialV2Presence, PendingCredentialV2Channel,
    },
    wire::{
        decode_client_message, encode_server_message, ClientMessage, CloseReason, ServerMessage,
        Side,
    },
};
use selfsame_pairing::local_demo;
use serde_json::Value;

type Session = CredentialV2BrowserAllocatorSession;
const NOW: u64 = 1_800_000_000;
const RELAY: &str = "https://localhost:7443";
const T: [u8; 16] = [0x15; 16];
// Independent fixture C for entropy 0x12345678. The adapter must invoke the
// shared mapping; the test never computes its expected secret with that codec.
const C: [u8; 16] = *b"SSPAIR-M1\0\0\0\x12\x34\x56\x78";

fn vectors() -> Value {
    serde_json::from_str(include_str!("../tests/fixtures/spec078-wasm-manual.json")).unwrap()
}
fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn unb64(text: &str) -> Vec<u8> {
    Base64UrlUnpadded::decode_vec(text).unwrap()
}
fn json(text: String) -> Vec<Value> {
    serde_json::from_str(&text).unwrap()
}
fn sent(effects: &[Value]) -> Vec<ClientMessage> {
    effects
        .iter()
        .map(|effect| {
            assert_eq!(effect["type"], "send");
            decode_client_message(&unb64(effect["bodyB64u"].as_str().unwrap())).unwrap()
        })
        .collect()
}
fn receive(s: &mut Session, m: ServerMessage, nonce: u8) -> Result<Vec<Value>, String> {
    s.receive_inner(&encode_server_message(&m).unwrap(), NOW, &[nonce; 12])
        .map(json)
}
fn new(mode: Mode, presence: &[u8]) -> Session {
    // Success paths call the actual exported constructors, so wrapper mode or
    // argument swaps are observable here (not just a test of the shared core).
    let constructor = match mode {
        Mode::Full => Session::new,
        Mode::Manual => Session::new_manual,
    };
    constructor(
        &local_demo::profile_octets(RELAY),
        RELAY.into(),
        &[0x11; 32],
        &[0x12; 32],
        &[0x13; 32],
        presence,
        &T,
        &[0x18; 32],
        &[0x21; 32],
        &[0x22; 32],
        &[0x19; 32],
        &[0x16; 32],
    )
    .unwrap()
}
fn checkpoint(effects: &[Value], generation: u64) -> (Vec<u8>, Vec<u8>) {
    assert_eq!(
        effects.len(),
        1,
        "no Ack/Put before checkpoint acknowledgement"
    );
    assert_eq!(effects[0]["type"], "checkpoint");
    assert_eq!(effects[0]["generation"], generation);
    (
        unb64(effects[0]["checkpointB64u"].as_str().unwrap()),
        unb64(effects[0]["rawCarrierB64u"].as_str().unwrap()),
    )
}
fn allocate(s: &mut Session) -> (Vec<u8>, Vec<u8>, Vec<Value>) {
    assert_eq!(s.bootstrap_mode(), None);
    assert_eq!(s.handoff_text().unwrap(), None);
    assert_eq!(s.manual_transfer_text().unwrap(), None);
    let mut public = json(s.start().unwrap());
    assert_eq!(sent(&public), vec![ClientMessage::Bind]);
    let allocate = receive(s, ServerMessage::Welcome, 1).unwrap();
    assert!(matches!(
        sent(&allocate).as_slice(),
        [ClientMessage::AllocateV2 {
            ttl_seconds: Some(900),
            ..
        }]
    ));
    public.extend(allocate);
    let durable = receive(
        s,
        ServerMessage::AllocatedV2 {
            mailbox_id: [0x11; 32],
            membership_token: [0x20; 32],
            expires_at: NOW + 900,
        },
        2,
    )
    .unwrap();
    let (sealed, carrier) = checkpoint(&durable, 1);
    public.extend(durable);
    let pending = json(s.checkpoint_persisted(1).unwrap());
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["type"], "pending-allocation");
    public.extend(pending);
    (sealed, carrier, public)
}
fn restore(
    sealed: &[u8],
    carrier: &[u8],
    generation: u64,
    mode: &str,
    scalar: &[u8],
) -> Result<Session, String> {
    Session::restore_inner(
        &local_demo::profile_octets(RELAY),
        carrier,
        sealed,
        generation,
        &[0x21; 32],
        &[0x22; 32],
        &[0x19; 32],
        &[0x16; 32],
        NOW,
        mode.into(),
        scalar,
    )
}
fn context(carrier: &[u8]) -> CredentialV2Context {
    let profile = ApplicationProfile::recognise(&local_demo::profile_octets(RELAY)).unwrap();
    CredentialV2Context::derive(&decode_carrier(carrier).unwrap(), *profile.digest()).unwrap()
}
fn share(carrier: &[u8], c: [u8; 16], scalar: u8) -> CredentialV2Frame {
    let (_, message) = context(carrier)
        .start_cpace(
            Side::Claimant,
            &CredentialV2Presence::new(c, T),
            [scalar; 32],
        )
        .unwrap();
    CredentialV2Frame::cpace(&message).unwrap()
}
fn frame(peer: &CredentialV2Frame) -> ServerMessage {
    ServerMessage::Frame {
        peer_seq: 0,
        body: encode_frame(peer).unwrap(),
    }
}
fn put(effects: &[Value]) -> Vec<u8> {
    let messages = sent(effects);
    let ClientMessage::Put { seq: 0, body } = messages.last().unwrap() else {
        panic!("expected CPace response")
    };
    body.clone()
}
fn no_exports(s: &Session) {
    if s.bootstrap_mode().as_deref() == Some("full") {
        assert!(s.manual_transfer_text_inner().is_err());
    } else {
        assert!(s.manual_transfer_text().unwrap().is_none());
    }
    if s.bootstrap_mode().as_deref() == Some("manual") {
        assert!(s.handoff_text_inner().is_err());
    } else {
        assert!(s.handoff_text().unwrap().is_none());
    }
    assert!(s.restored_presence_code().is_none());
}
fn no_leak(public: &[Value], bootstrap: &str, words: &str, c: &[u8]) {
    // Inspect all JSON values, including decoded carrier/relay wire bytes;
    // encrypted checkpoint bytes are allowed, but never plaintext C/T/text.
    let output = serde_json::to_string(public).unwrap();
    for secret in [
        bootstrap.to_string(),
        words.to_string(),
        Base64UrlUnpadded::encode_string(c),
        Base64UrlUnpadded::encode_string(&T),
    ] {
        assert!(!output.contains(&secret));
    }
    for effect in public {
        for field in ["bodyB64u", "rawCarrierB64u", "checkpointB64u"] {
            if let Some(encoded) = effect[field].as_str() {
                let bytes = unb64(encoded);
                for secret in [c, T.as_slice(), bootstrap.as_bytes(), words.as_bytes()] {
                    assert!(!bytes.windows(secret.len()).any(|w| w == secret));
                }
            }
        }
        assert!(effect.get("bootstrap").is_none());
        assert!(effect.get("words").is_none());
        if effect["type"] == "pending-allocation" {
            assert!(effect["presenceCode"].is_null());
        }
    }
}

#[test]
fn actual_manual_constructor_matches_independent_words_and_bootstrap() {
    let v = vectors();
    assert_eq!(cbcl_allocator_api_version(), 2);
    for row in v["words"].as_array().unwrap() {
        let n = row["n"].as_u64().unwrap() as u32;
        // Both high random bits must be masked by the shared codec, in BE order.
        for high in [0, 0x40000000, 0x80000000, 0xc0000000] {
            let mut s = new(Mode::Manual, &(n | high).to_be_bytes());
            let (_, carrier, public) = allocate(&mut s);
            assert_eq!(s.bootstrap_mode().as_deref(), Some("manual"));
            let text = s.manual_transfer_text().unwrap().unwrap();
            let fields: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(fields.as_object().unwrap().len(), 2);
            assert_eq!(fields["words"], row["words"]);
            assert_eq!(fields["bootstrap"], v["allocated"]["bootstrap"]);
            assert_eq!(
                carrier,
                hex(v["allocated"]["carrier_hex"].as_str().unwrap())
            );
            let bootstrap = fields["bootstrap"].as_str().unwrap();
            let words = fields["words"].as_str().unwrap();
            let (recognized, presence) =
                CredentialV2ManualBootstrap::recognise_pair(bootstrap, words, NOW).unwrap();
            assert_eq!(recognized, decode_carrier(&carrier).unwrap());
            assert_eq!(
                presence.into_presence().cpace_secret().as_slice(),
                hex(row["c_hex"].as_str().unwrap())
            );
            no_leak(
                &public,
                bootstrap,
                words,
                &hex(row["c_hex"].as_str().unwrap()),
            );
            assert_eq!(
                s.handoff_text_inner().unwrap_err(),
                "the pairing invitation was refused"
            );
            assert!(s.restored_presence_code().is_none());
            // Mutating a caller-owned copy cannot affect the next fresh export.
            let mut caller_copy = text.clone();
            caller_copy.clear();
            assert_eq!(s.manual_transfer_text().unwrap(), Some(text));
        }
    }
}

#[test]
fn full_default_keeps_independent_c16_t16_even_with_manual_prefix() {
    for c in [[0x14; 16], C, *b"SSPAIR-M1\0\0\0\xff\xff\xff\xff"] {
        let mut s = new(Mode::Full, &c);
        let (sealed, carrier, _) = allocate(&mut s);
        assert_eq!(s.bootstrap_mode().as_deref(), Some("full"));
        assert!(s.manual_transfer_text_inner().is_err());
        let handoff: CredentialV2Handoff = s.handoff_text().unwrap().unwrap().parse().unwrap();
        let (_, presence) = handoff.into_parts();
        let presence = presence.into_presence();
        assert_eq!(presence.cpace_secret(), &c);
        // Legacy text independently encodes the precise C/T pair.
        assert_eq!(
            s.restored_presence_code(),
            Some(cbcl_pairing::credential_v2::CredentialV2PresenceCode::new(c, T).to_string())
        );
        assert_ne!(c, T);
        assert!(restore(&sealed, &carrier, 1, "manual", &[0x61; 32]).is_err());
        let restored = restore(&sealed, &carrier, 1, "full", &[0x61; 32]).unwrap();
        assert_eq!(restored.handoff_text().unwrap(), s.handoff_text().unwrap());
    }
}

#[test]
fn constructor_and_restore_lengths_and_mode_are_strict_and_redacted() {
    let p = local_demo::profile_octets(RELAY);
    for mode in [Mode::Full, Mode::Manual] {
        let sizes = [
            32,
            32,
            32,
            if mode == Mode::Full { 16 } else { 4 },
            16,
            32,
            32,
            32,
            32,
            32,
        ];
        let valid: Vec<Vec<u8>> = sizes.iter().map(|size| vec![0x41; *size]).collect();
        for field in 0..sizes.len() {
            for bad in [0, sizes[field] - 1, sizes[field] + 1, 64] {
                let mut a = valid.clone();
                a[field] = vec![0x41; bad];
                let result = Session::new_inner(
                    &p,
                    RELAY.into(),
                    &a[0],
                    &a[1],
                    &a[2],
                    &a[3],
                    &a[4],
                    &a[5],
                    &a[6],
                    &a[7],
                    &a[8],
                    &a[9],
                    mode,
                );
                let error = result
                    .err()
                    .expect("wrong constructor byte length must refuse");
                assert!(error.contains("exactly"));
                assert!(!error.contains("AAAA"));
            }
        }
        let mut s = new(
            mode,
            if mode == Mode::Manual {
                &[0x12, 0x34, 0x56, 0x78]
            } else {
                &C
            },
        );
        let (sealed, carrier, _) = allocate(&mut s);
        for text in [
            "",
            "FULL",
            "Full",
            "Manual",
            "manual ",
            " full",
            "scan",
            "SSPAIR-M1:",
            "full\0",
        ] {
            assert_eq!(
                restore(&sealed, &carrier, 1, text, &[0x61; 32])
                    .err()
                    .unwrap(),
                "the credential/v2 allocator mode was refused"
            );
        }
        let mode_text = if mode == Mode::Manual {
            "manual"
        } else {
            "full"
        };
        for bad in [0, 1, 31, 33, 64] {
            assert_eq!(
                restore(&sealed, &carrier, 1, mode_text, &vec![0x61; bad])
                    .err()
                    .unwrap(),
                "the credential/v2 fresh CPace scalar is exactly 32 octets"
            );
        }
        for field in 0..4 {
            for bad in [0, 31, 33] {
                let mut a = [
                    vec![0x21; 32],
                    vec![0x22; 32],
                    vec![0x19; 32],
                    vec![0x16; 32],
                ];
                a[field] = vec![0x41; bad];
                assert!(Session::restore_inner(
                    &p,
                    &carrier,
                    &sealed,
                    1,
                    &a[0],
                    &a[1],
                    &a[2],
                    &a[3],
                    NOW,
                    mode_text.into(),
                    &[0x61; 32]
                )
                .is_err());
            }
        }
        for generation in [0, 2, u64::MAX] {
            assert!(restore(&sealed, &carrier, generation, mode_text, &[0x61; 32]).is_err());
        }
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(restore(&tampered, &carrier, 1, mode_text, &[0x61; 32]).is_err());
        assert!(restore(&[], &carrier, 1, mode_text, &[0x61; 32]).is_err());
        assert!(restore(&sealed, &[], 1, mode_text, &[0x61; 32]).is_err());
        assert!(Session::restore_inner(
            &p,
            &carrier,
            &sealed,
            1,
            &[0x21; 32],
            &[0x22; 32],
            &[0x19; 32],
            &[0x16; 32],
            NOW + 900,
            mode_text.into(),
            &[0x61; 32]
        )
        .is_err());
    }
}

#[test]
fn actual_restore_uses_fresh_scalar_before_peer_in_both_modes() {
    for (mode, name) in [(Mode::Full, "full"), (Mode::Manual, "manual")] {
        let mut s = new(
            mode,
            if mode == Mode::Manual {
                &[0x12, 0x34, 0x56, 0x78]
            } else {
                &C
            },
        );
        let (sealed, carrier, _) = allocate(&mut s);
        let peer = share(&carrier, C, 0x31);
        let mut outputs = Vec::new();
        for scalar in [[0x42; 32], [0x53; 32], [0x64; 32]] {
            let mut r = Session::restore(
                &local_demo::profile_octets(RELAY),
                &carrier,
                &sealed,
                1,
                &[0x21; 32],
                &[0x22; 32],
                &[0x19; 32],
                &[0x16; 32],
                NOW,
                name.into(),
                &scalar,
            )
            .unwrap();
            assert_eq!(r.bootstrap_mode().as_deref(), Some(name));
            assert_eq!(sent(&json(r.start().unwrap())), vec![ClientMessage::Bind]);
            let reopen = receive(&mut r, ServerMessage::Welcome, 3).unwrap();
            assert!(matches!(
                sent(&reopen).as_slice(),
                [ClientMessage::Open { .. }]
            ));
            checkpoint(&receive(&mut r, frame(&peer), 4).unwrap(), 2);
            assert!(r.checkpoint_persisted_inner(1).is_err());
            assert!(receive(&mut r, frame(&peer), 5).is_err());
            no_exports(&r);
            let output = put(&json(r.checkpoint_persisted(2).unwrap()));
            let (_, expected) = context(&carrier)
                .start_cpace(Side::Allocator, &CredentialV2Presence::new(C, T), scalar)
                .unwrap();
            assert_eq!(
                decode_frame(&output).unwrap(),
                CredentialV2Frame::cpace(&expected).unwrap()
            );
            outputs.push(output);
        }
        assert_ne!(outputs[0], outputs[1]);
        assert_ne!(outputs[1], outputs[2]);
    }
}

#[test]
fn manual_bound_restore_preserves_exact_reply_and_one_peer_attempt() {
    let mut s = new(Mode::Manual, &[0x12, 0x34, 0x56, 0x78]);
    let (before, carrier, mut public) = allocate(&mut s);
    assert!(restore(&before, &carrier, 1, "full", &[0x71; 32]).is_err());
    let transfer: Value =
        serde_json::from_str(&s.manual_transfer_text().unwrap().unwrap()).unwrap();
    let wrong_c = *b"SSPAIR-M1\0\0\0\0\0\0\0"; // checksum-valid "abandon abandon absent"
    let wrong = share(&carrier, wrong_c, 0x33);
    let correct = share(&carrier, C, 0x44);
    let same_phrase_different_share = share(&carrier, wrong_c, 0x55);
    let effects = receive(&mut s, frame(&wrong), 3).unwrap();
    let (bound, _) = checkpoint(&effects, 2);
    public.extend(effects);
    no_exports(&s);
    // A crash before persistence released no response. Old durable state may
    // bind a peer anew, but still releases nothing before the next commit.
    let mut pre = restore(&before, &carrier, 1, "manual", &[0x71; 32]).unwrap();
    checkpoint(&receive(&mut pre, frame(&correct), 4).unwrap(), 2);
    drop(pre);
    let exact = json(s.checkpoint_persisted(2).unwrap());
    public.extend(exact.clone());
    assert!(matches!(
        sent(&exact).as_slice(),
        [
            ClientMessage::Ack { peer_seq: 0 },
            ClientMessage::Put { seq: 0, .. }
        ]
    ));
    // One snapshot covers after persist, before/after Ack and before/after Put.
    for scalar in [[0x71; 32], [0x82; 32]] {
        let mut r = restore(&bound, &carrier, 2, "manual", &scalar).unwrap();
        no_exports(&r);
        let reopen = sent(&receive(&mut r, ServerMessage::Welcome, 5).unwrap());
        assert!(matches!(reopen[0], ClientMessage::Open { .. }));
        assert_eq!(reopen[1], sent(&exact)[1]);
        for nonce in [6, 7] {
            assert_eq!(receive(&mut r, frame(&wrong), nonce).unwrap(), exact);
        }
        for other in [&correct, &same_phrase_different_share] {
            let mut r = restore(&bound, &carrier, 2, "manual", &scalar).unwrap();
            assert_eq!(
                receive(&mut r, frame(other), 8).unwrap_err(),
                "the credential/v2 relay message was refused"
            );
            assert!(r.bootstrap_mode().is_none());
            no_exports(&r);
            assert!(receive(&mut r, frame(&wrong), 9).is_err());
            assert!(r.transcript_hash.is_none());
        }
    }
    // The acknowledged allocator share advances to a durable cached Finished.
    // Fresh caller scalar bytes cannot change either recovered response.
    let mut finished_outputs = Vec::new();
    for scalar in [[0x71; 32], [0x82; 32]] {
        let mut r = restore(&bound, &carrier, 2, "manual", &scalar).unwrap();
        let effects = receive(&mut r, ServerMessage::Acknowledged { seq: 0 }, 10).unwrap();
        let (sealed_finished, _) = checkpoint(&effects, 3);
        let exact_finished = sent(&json(r.checkpoint_persisted(3).unwrap()));
        let mut r = restore(&sealed_finished, &carrier, 3, "manual", &[0x93; 32]).unwrap();
        let reopened = sent(&receive(&mut r, ServerMessage::Welcome, 11).unwrap());
        assert_eq!(&reopened[1..], exact_finished);
        no_exports(&r);
        assert!(receive(&mut r, frame(&correct), 12).is_err());
        finished_outputs.push(exact_finished);
    }
    assert_eq!(finished_outputs[0], finished_outputs[1]);
    no_leak(
        &public,
        transfer["bootstrap"].as_str().unwrap(),
        transfer["words"].as_str().unwrap(),
        &C,
    );
}

#[test]
fn terminal_cancel_failure_and_exclusive_expiry_clear_private_core_values() {
    for case in 0..4 {
        let mut s = new(Mode::Manual, &[0x12, 0x34, 0x56, 0x78]);
        let (_, carrier, _) = allocate(&mut s);
        match case {
            0 => {
                assert_eq!(json(s.cancel())[0]["type"], "terminal");
            }
            1 => {
                assert_eq!(
                    receive(&mut s, ServerMessage::Closed(CloseReason::Closed), 3).unwrap()[0]
                        ["type"],
                    "terminal"
                );
            }
            2 => {
                assert_eq!(
                    s.receive_inner(&[0], NOW, &[3; 12]).unwrap_err(),
                    "the credential/v2 relay message was refused"
                );
            }
            _ => {
                let peer = share(&carrier, C, 0x31);
                assert!(s
                    .receive_inner(
                        &encode_server_message(&frame(&peer)).unwrap(),
                        NOW + 900,
                        &[3; 12]
                    )
                    .is_err());
            }
        }
        no_exports(&s);
        assert!(s.bootstrap_mode().is_none());
        assert!(s.transcript_hash.is_none());
    }
}

#[test]
fn manual_finished_and_established_restore_grant_no_bootstrap_capability() {
    for correct in [true, false] {
        let mut s = new(Mode::Manual, &[0x12, 0x34, 0x56, 0x78]);
        let (_, carrier, _) = allocate(&mut s);
        let context = context(&carrier);
        let c = if correct {
            C
        } else {
            *b"SSPAIR-M1\0\0\0\0\0\0\0"
        };
        let (state, message) = context
            .start_cpace(Side::Claimant, &CredentialV2Presence::new(c, T), [0x31; 32])
            .unwrap();
        let peer = CredentialV2Frame::cpace(&message).unwrap();
        checkpoint(&receive(&mut s, frame(&peer), 3).unwrap(), 2);
        let local_bytes = put(&json(s.checkpoint_persisted(2).unwrap()));
        no_exports(&s);
        let local = decode_frame(&local_bytes).unwrap();
        let isk = cpace::finish(state, local.cpace_message().unwrap()).unwrap();
        let claimant = PendingCredentialV2Channel::new(
            Side::Claimant,
            isk,
            context.public_context(),
            &local_bytes,
            &encode_frame(&peer).unwrap(),
        )
        .unwrap();
        let peer_finished = claimant.local_finished_frame();
        checkpoint(
            &receive(&mut s, ServerMessage::Acknowledged { seq: 0 }, 4).unwrap(),
            3,
        );
        let effects = json(s.checkpoint_persisted(3).unwrap());
        let messages = sent(&effects);
        let [ClientMessage::Put {
            seq: 1,
            body: finished,
        }] = messages.as_slice()
        else {
            panic!("Finished follows checkpoint")
        };
        assert_eq!(
            claimant.confirm(&decode_frame(finished).unwrap()).is_ok(),
            correct
        );
        checkpoint(
            &receive(&mut s, ServerMessage::Acknowledged { seq: 1 }, 5).unwrap(),
            4,
        );
        assert!(json(s.checkpoint_persisted(4).unwrap()).is_empty());
        let result = receive(
            &mut s,
            ServerMessage::Frame {
                peer_seq: 1,
                body: encode_frame(&peer_finished).unwrap(),
            },
            6,
        );
        if !correct {
            assert_eq!(
                result.unwrap_err(),
                "the credential/v2 relay message was refused"
            );
            assert!(s.transcript_hash.is_none());
            assert!(s.bootstrap_mode().is_none());
            no_exports(&s);
            continue;
        }
        let (established, _) = checkpoint(&result.unwrap(), 5);
        // Establishment removes mode before acknowledgement releases the effect.
        assert!(s.bootstrap_mode().is_none());
        no_exports(&s);
        let effects = json(s.checkpoint_persisted(5).unwrap());
        assert_eq!(effects.len(), 2);
        assert!(matches!(
            sent(&effects[..1]).as_slice(),
            [ClientMessage::Ack { peer_seq: 1 }]
        ));
        assert_eq!(effects[1]["type"], "established");
        let commitment = s.receipt_recovery_commitment().unwrap();
        assert_eq!(commitment.len(), 32);
        for mode in ["full", "manual"] {
            let r = Session::restore(
                &local_demo::profile_octets(RELAY),
                &carrier,
                &established,
                5,
                &[0x21; 32],
                &[0x22; 32],
                &[0x19; 32],
                &[0x16; 32],
                NOW,
                mode.into(),
                &[0x83; 32],
            )
            .unwrap();
            assert_eq!(r.restored_phase(), "begin");
            assert!(r.bootstrap_mode().is_none());
            no_exports(&r);
            assert_eq!(r.receipt_recovery_commitment().unwrap(), commitment);
            assert!(restore(&established, &carrier, 5, mode, &[]).is_err());
        }
        assert!(restore(&established, &carrier, 5, "", &[0x83; 32]).is_err());
    }
}

#[test]
fn mode_changes_no_public_context_or_carrier_bytes() {
    let mut full = new(Mode::Full, &C);
    let mut manual = new(Mode::Manual, &[0x12, 0x34, 0x56, 0x78]);
    let (_, a, _) = allocate(&mut full);
    let (_, b, _) = allocate(&mut manual);
    assert_eq!(a, b);
    assert_eq!(context(&a).public_context(), context(&b).public_context());
    assert_eq!(share(&a, C, 0x31), share(&b, C, 0x31));
}

#[test]
fn manual_qr_encodes_exact_complete_input_at_q_level_and_refuses_capacity() {
    let v = vectors();
    for (text, now) in [
        (v["bootstraps"][0]["bootstrap"].as_str().unwrap(), 0),
        (v["allocated"]["bootstrap"].as_str().unwrap(), NOW),
    ] {
        // Actual exported successful QR path, exact module equality to existing Q encoder.
        let value: Value =
            serde_json::from_str(&cbcl_manual_bootstrap_qr_modules_json(text, now).unwrap())
                .unwrap();
        assert_eq!(value.as_object().unwrap().len(), 2);
        let expected =
            qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::Q)
                .unwrap();
        let size = expected.width();
        assert_eq!(value["size"], size);
        let dark = value["dark"].as_array().unwrap();
        assert_eq!(dark.len(), size * size);
        for y in 0..size {
            for x in 0..size {
                assert_eq!(
                    dark[y * size + x],
                    u8::from(expected[(x, y)] == qrcode::Color::Dark)
                );
            }
        }
    }
    let maximum = v["bootstraps"][1]["bootstrap"].as_str().unwrap();
    assert_eq!(maximum.len(), 3669);
    // Recognized maximum with exact original u64 deadline. Capacity is an
    // explicit, distinct fallback; it never strips fields or encodes a prefix.
    CredentialV2ManualBootstrap::recognise(maximum, u64::MAX - 1).unwrap();
    assert_eq!(
        manual_bootstrap_qr_modules_json(maximum, u64::MAX - 1).unwrap_err(),
        "the pairing invitation does not fit a QR symbol"
    );
    assert_eq!(maximum, v["bootstraps"][1]["bootstrap"].as_str().unwrap());
    assert_eq!(
        manual_bootstrap_qr_modules_json(maximum, u64::MAX).unwrap_err(),
        "the pairing invitation was refused"
    );
}

#[test]
fn manual_qr_shared_recognizer_runs_before_rendering_or_capacity() {
    let v = vectors();
    let valid = v["allocated"]["bootstrap"].as_str().unwrap();
    let raw = unb64(valid.strip_prefix("SSPAIR-M1:").unwrap());
    let mut wrong_token = raw.clone();
    *wrong_token.last_mut().unwrap() ^= 1;
    let mut wrong_domain = raw.clone();
    wrong_domain[3] ^= 1;
    let mut trailing = raw.clone();
    trailing.push(0);
    let mut extra = raw.clone();
    extra[0] = 0x84;
    extra.push(0);
    let mut nested = raw.clone();
    nested[0] = 0x81;
    nested.insert(1, 0x83);
    let encode = |bytes: &[u8]| format!("SSPAIR-M1:{}", Base64UrlUnpadded::encode_string(bytes));
    let mut invalid = vec![
        String::new(),
        "SSPAIR-M2:AAAA".into(),
        "SSPAIR-M1:A".into(),
        "SSPAIR-M1:AB".into(),
        "SSPAIR-M1:!!!!".into(),
        format!("{valid}="),
        format!(" {valid}"),
        format!("{valid}\n"),
        format!("{valid}é"),
        format!("{valid}x"),
        encode(&wrong_token),
        encode(&wrong_domain),
        encode(&trailing),
        encode(&extra),
        encode(&nested),
        "https://example.org/".into(),
        "abandon abandon absent".into(),
        "SSPAIR-M1:".to_owned() + &"A".repeat(3661),
    ];
    let mut full = new(Mode::Full, &C);
    allocate(&mut full);
    invalid.push(full.handoff_text().unwrap().unwrap());
    invalid.push(full.restored_presence_code().unwrap());
    let carrier = decode_carrier(&hex(v["allocated"]["carrier_hex"].as_str().unwrap())).unwrap();
    // A valid public carrier with no allocator key must refuse before QR.
    let no_key = CredentialV2Carrier::new(cbcl_pairing::credential_v2::CredentialV2CarrierInput {
        application_context: carrier.application_context().into(),
        relay_origin: carrier.relay_origin().into(),
        mailbox_id: *carrier.mailbox_id(),
        carrier_ceremony_id: *carrier.carrier_ceremony_id(),
        carrier_nonce: *carrier.carrier_nonce(),
        claim_commitment: *carrier.claim_commitment(),
        relay_expires_at: carrier.relay_expires_at(),
        expected_allocator_key: None,
    })
    .unwrap();
    // Reuse the canonical wrapper prefix and literal token around the encoded carrier.
    // Carrier length stays >255 so its canonical bstr header is 0x59 + u16BE.
    let carrier = cbcl_pairing::credential_v2::encode_carrier(&no_key).unwrap();
    let mut no_key_wrapper = raw[..29].to_vec();
    no_key_wrapper.push(0x59);
    no_key_wrapper.extend((carrier.len() as u16).to_be_bytes());
    no_key_wrapper.extend(carrier);
    no_key_wrapper.push(0x50);
    no_key_wrapper.extend(T);
    assert_eq!(
        CredentialV2ManualBootstrap::recognise(&encode(&no_key_wrapper), NOW).unwrap_err(),
        cbcl_pairing::credential_v2::CredentialV2ManualError::AllocatorKeyRequired
    );
    invalid.push(encode(&no_key_wrapper));
    for text in invalid {
        assert_eq!(
            manual_bootstrap_qr_modules_json(&text, NOW).unwrap_err(),
            "the pairing invitation was refused"
        );
    }
    assert!(manual_bootstrap_qr_modules_json(valid, NOW + 899).is_ok());
    for now in [NOW + 900, NOW + 901] {
        assert_eq!(
            manual_bootstrap_qr_modules_json(valid, now).unwrap_err(),
            "the pairing invitation was refused"
        );
    }
    assert_eq!(
        handoff_qr_modules_json(valid).unwrap_err(),
        "the pairing invitation was refused"
    );
    assert!(valid
        .parse::<cbcl_pairing::credential_v2::CredentialV2PresenceCode>()
        .is_err());
}

#[test]
fn independently_sealed_old_inner_v2_restores_as_full_only() {
    let v = vectors();
    let old = &v["old_full_checkpoint"];
    let profile = old["profile"].as_str().unwrap().as_bytes();
    let carrier = hex(old["carrier_hex"].as_str().unwrap());
    let sealed = hex(old["checkpoint_hex"].as_str().unwrap());
    let r = Session::restore(
        profile,
        &carrier,
        &sealed,
        1,
        &[0x21; 32],
        &[0x22; 32],
        &[0x19; 32],
        &[0x16; 32],
        NOW,
        "full".into(),
        &[0x71; 32],
    )
    .unwrap();
    assert_eq!(r.bootstrap_mode().as_deref(), Some("full"));
    assert_eq!(r.restored_phase(), "allocated");
    assert!(r.manual_transfer_text_inner().is_err());
    let handoff: CredentialV2Handoff = r.handoff_text().unwrap().unwrap().parse().unwrap();
    let mut presence = handoff.into_parts().1.into_presence();
    assert_eq!(presence.cpace_secret(), &C);
    assert_eq!(presence.take_claim_token().unwrap().as_bytes(), &T);
    assert!(r.restored_presence_code().is_some());
    assert!(Session::restore_inner(
        profile,
        &carrier,
        &sealed,
        1,
        &[0x21; 32],
        &[0x22; 32],
        &[0x19; 32],
        &[0x16; 32],
        NOW,
        "manual".into(),
        &[0x71; 32]
    )
    .is_err());
}
