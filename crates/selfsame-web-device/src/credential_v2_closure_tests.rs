//! Actual exported adapter implementation with real signed bodies and sealed
//! shared-core checkpoints. These fixtures grant no application capability.
use super::*;
use base64ct::{Base64UrlUnpadded, Encoding};
use cbcl_pairing::{cpace, credential_v2::*, wire::Side};
use ed25519_dalek::Signer;
use selfsame_pairing::credential_v2::*;

type View = CredentialV2BrowserAllocatorClosureInspection;
type Session = CredentialV2BrowserAllocatorSession;
const NOW: u64 = 1_760_000_300;
const EXPIRY: u64 = 1_760_000_900;
const RELAY: &str = "https://photos.example:9443";
const SEED: [u8; 32] = [0x16; 32];
const REQUEST: [u8; 32] = [0x21; 32];
const INTENT: [u8; 32] = [0x22; 32];
const KID: &str = "https://photos.example/selfsame/application#closure-test";

fn profile(key: &SigningKey) -> ApplicationProfile {
    let mut raw: serde_json::Value =
        serde_json::from_slice(&selfsame_pairing::local_demo::profile_octets(RELAY)).unwrap();
    raw["enrollment"]["requestSigningKeys"] = serde_json::json!([{
        "kid": KID,
        "publicKeyJwk": {"kty":"OKP", "crv":"Ed25519",
            "x": Base64UrlUnpadded::encode_string(&key.verifying_key().to_bytes())}
    }]);
    ApplicationProfile::recognise(&serde_json::to_vec(&raw).unwrap()).unwrap()
}

fn wrapping(carrier: &CredentialV2Carrier) -> [u8; 32] {
    let mut key = [0; 32];
    hkdf::Hkdf::<sha2::Sha512>::new(Some(carrier.carrier_ceremony_id()), &SEED)
        .expand(V2_ALLOCATOR_CHECKPOINT_INFO, &mut key)
        .unwrap();
    key
}

fn bootstrap(
    mode: CredentialV2AllocatorMode,
) -> (ApplicationProfile, CredentialV2Carrier, Vec<u8>) {
    let profile = profile(&SigningKey::from_bytes(&[0x31; 32]));
    let device = SigningKey::from_bytes(&SEED).verifying_key().to_bytes();
    let carrier = CredentialV2Carrier::new(CredentialV2CarrierInput {
        application_context: profile.application_id.as_str().into(),
        relay_origin: RELAY.into(),
        mailbox_id: [1; 32],
        carrier_ceremony_id: [2; 32],
        carrier_nonce: [3; 32],
        claim_commitment: cbcl_pairing::wire::claim_commitment(
            [1; 32],
            &cbcl_pairing::wire::ClaimToken::new([5; 16]),
        ),
        relay_expires_at: EXPIRY,
        expected_allocator_key: Some(device),
    })
    .unwrap();
    let secret = match mode {
        CredentialV2AllocatorMode::Full => [4; 16],
        CredentialV2AllocatorMode::Manual => {
            *CredentialV2ManualWords::from_csprng([4; 4]).cpace_secret()
        }
    };
    let mut state = CredentialV2AllocatorBootstrap::new(
        carrier.clone(),
        CredentialV2Presence::new(secret, [5; 16]),
        *profile.digest(),
        CredentialV2RelayState::new([6; 32]),
        mode,
    )
    .unwrap();
    let saved = state
        .seal_checkpoint(
            &wrapping(&carrier),
            1,
            CredentialV2CheckpointNonce::from_csprng([7; 12]),
            NOW,
        )
        .unwrap();
    (profile, carrier, saved.as_bytes().to_vec())
}

fn inspect(
    profile: &ApplicationProfile,
    carrier: &CredentialV2Carrier,
    sealed: &[u8],
    generation: u64,
    now: u64,
    mode: &str,
) -> Result<View, String> {
    View::restore_inner(
        profile.canonical_bytes(),
        &encode_carrier(carrier).unwrap(),
        sealed,
        generation,
        &REQUEST,
        &INTENT,
        carrier.expected_allocator_key().unwrap(),
        &SEED,
        now,
        mode.into(),
    )
}

#[test]
fn closure_expiry_is_separate_from_live_restore_in_full_and_manual() {
    for (mode, name) in [
        (CredentialV2AllocatorMode::Full, "full"),
        (CredentialV2AllocatorMode::Manual, "manual"),
    ] {
        let (p, c, saved) = bootstrap(mode);
        for now in [EXPIRY - 1, EXPIRY, EXPIRY + 1] {
            // Success calls the export, including its exact argument order.
            let mut view = Session::restore_for_closure(
                p.canonical_bytes(),
                &encode_carrier(&c).unwrap(),
                &saved,
                1,
                &REQUEST,
                &INTENT,
                c.expected_allocator_key().unwrap(),
                &SEED,
                now,
                name.into(),
            )
            .unwrap();
            assert_eq!(view.restored_phase(), "allocated");
            assert_eq!(view.restored_mode().as_deref(), Some(name));
            assert!(view
                .verify_final_status_inner(b"e30.e30.AA", &[0; 32], now)
                .is_err());
            assert_eq!(view.cancel(), "[]");
            assert_eq!(view.restored_phase(), "cancelled");
            assert!(view.restored_mode().is_none());
            let live = Session::restore_inner(
                p.canonical_bytes(),
                &encode_carrier(&c).unwrap(),
                &saved,
                1,
                &REQUEST,
                &INTENT,
                c.expected_allocator_key().unwrap(),
                &SEED,
                now,
                name.into(),
                &[9; 32],
            );
            assert_eq!(live.is_ok(), now < EXPIRY);
        }
    }
}

#[test]
fn closure_bootstrap_bindings_and_old_full_are_authenticated() {
    let (p, c, saved) = bootstrap(CredentialV2AllocatorMode::Manual);
    assert!(inspect(&p, &c, &saved, 1, EXPIRY, "full").is_err());
    assert!(inspect(&p, &c, &saved, 1, EXPIRY, "Manual").is_err());
    assert!(inspect(&p, &c, &saved, 0, EXPIRY, "manual").is_err());
    assert!(inspect(&p, &c, &saved, 2, EXPIRY, "manual").is_err());
    let mut corrupt = saved.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(inspect(&p, &c, &corrupt, 1, EXPIRY, "manual").is_err());
    let other_profile = profile(&SigningKey::from_bytes(&[0x32; 32]));
    assert!(inspect(&other_profile, &c, &saved, 1, EXPIRY, "manual").is_err());
    let raw_carrier = encode_carrier(&c).unwrap();
    for (key, seed) in [
        ([0; 32], SEED),
        (*c.expected_allocator_key().unwrap(), [0; 32]),
    ] {
        assert!(View::restore_inner(
            p.canonical_bytes(),
            &raw_carrier,
            &saved,
            1,
            &REQUEST,
            &INTENT,
            &key,
            &seed,
            EXPIRY,
            "manual".into()
        )
        .is_err());
    }
    let changed = changed_carrier(&c);
    assert!(inspect(&p, &changed, &saved, 1, EXPIRY, "manual").is_err());
    assert!(View::restore_inner(
        p.canonical_bytes(),
        &raw_carrier,
        &saved,
        1,
        &[],
        &INTENT,
        c.expected_allocator_key().unwrap(),
        &SEED,
        EXPIRY,
        "manual".into()
    )
    .is_err());
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../tests/fixtures/spec078-wasm-manual.json")).unwrap();
    let old = &vectors["old_full_checkpoint"];
    let hex = |s: &str| {
        s.as_bytes()
            .chunks_exact(2)
            .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).unwrap())
            .collect::<Vec<_>>()
    };
    let old_carrier = decode_carrier(&hex(old["carrier_hex"].as_str().unwrap())).unwrap();
    for mode in ["full", "manual"] {
        let result = View::restore_inner(
            old["profile"].as_str().unwrap().as_bytes(),
            &hex(old["carrier_hex"].as_str().unwrap()),
            &hex(old["checkpoint_hex"].as_str().unwrap()),
            1,
            &REQUEST,
            &INTENT,
            &[0x19; 32],
            &SEED,
            old_carrier.relay_expires_at() + 1,
            mode.into(),
        );
        assert_eq!(result.is_ok(), mode == "full");
    }
}

#[test]
fn closure_peer_bound_bootstrap_preserves_authenticated_mode_after_expiry() {
    for (mode, name) in [
        (CredentialV2AllocatorMode::Full, "full"),
        (CredentialV2AllocatorMode::Manual, "manual"),
    ] {
        let (p, c, saved) = bootstrap(mode);
        let secret = match mode {
            CredentialV2AllocatorMode::Full => [4; 16],
            CredentialV2AllocatorMode::Manual => {
                *CredentialV2ManualWords::from_csprng([4; 4]).cpace_secret()
            }
        };
        let mut state = CredentialV2AllocatorBootstrap::restore_checkpoint(
            &saved,
            &wrapping(&c),
            &c,
            1,
            NOW,
            mode,
        )
        .unwrap();
        state.claimant_admitted().unwrap();
        state.start_cpace([8; 32]).unwrap();
        let context = CredentialV2Context::derive(&c, *p.digest()).unwrap();
        let (_, message) = context
            .start_cpace(
                Side::Claimant,
                &CredentialV2Presence::new(secret, [5; 16]),
                [9; 32],
            )
            .unwrap();
        state
            .receive_cpace(&CredentialV2Frame::cpace(&message).unwrap())
            .unwrap();
        let saved = state
            .seal_checkpoint(
                &wrapping(&c),
                2,
                CredentialV2CheckpointNonce::from_csprng([11; 12]),
                NOW,
            )
            .unwrap();
        for now in [EXPIRY - 1, EXPIRY, EXPIRY + 1] {
            let view = inspect(&p, &c, saved.as_bytes(), 2, now, name).unwrap();
            assert_eq!(view.restored_phase(), "finished-sent");
            assert_eq!(view.restored_mode().as_deref(), Some(name));
            assert!(view
                .verify_final_status_inner(b"e30.e30.AA", &[0; 32], now)
                .is_err());
        }
    }
}

fn changed_carrier(c: &CredentialV2Carrier) -> CredentialV2Carrier {
    CredentialV2Carrier::new(CredentialV2CarrierInput {
        application_context: c.application_context().into(),
        relay_origin: c.relay_origin().into(),
        mailbox_id: [0xee; 32],
        carrier_ceremony_id: *c.carrier_ceremony_id(),
        carrier_nonce: *c.carrier_nonce(),
        claim_commitment: *c.claim_commitment(),
        relay_expires_at: c.relay_expires_at(),
        expected_allocator_key: c.expected_allocator_key().copied(),
    })
    .unwrap()
}

struct Saved {
    profile: ApplicationProfile,
    carrier: CredentialV2Carrier,
    endpoint: CredentialV2Endpoint,
    channel: SecureCredentialV2Channel,
    authority: CredentialV2BodyAuthority,
    offer: BuiltCredentialV2Offer,
    status: BuiltCredentialV2FinalStatus,
    status_input: CredentialV2FinalStatusInput,
    authority_response: Vec<u8>,
    authority_digest: [u8; 32],
    payload: CredentialV2Object,
    key: SigningKey,
}

impl Saved {
    fn payload() -> Self {
        let key = SigningKey::from_bytes(&[0x31; 32]);
        let (p, c, _) = bootstrap(CredentialV2AllocatorMode::Full);
        let context = CredentialV2Context::derive(&c, *p.digest()).unwrap();
        let presence = CredentialV2Presence::new([4; 16], [5; 16]);
        let (a, am) = context
            .start_cpace(Side::Allocator, &presence, [8; 32])
            .unwrap();
        let (b, bm) = context
            .start_cpace(Side::Claimant, &presence, [9; 32])
            .unwrap();
        let aw = encode_frame(&CredentialV2Frame::cpace(&am).unwrap()).unwrap();
        let bw = encode_frame(&CredentialV2Frame::cpace(&bm).unwrap()).unwrap();
        let pa = PendingCredentialV2Channel::new(
            Side::Allocator,
            cpace::finish(a, &bm).unwrap(),
            context.public_context(),
            &aw,
            &bw,
        )
        .unwrap();
        let pb = PendingCredentialV2Channel::new(
            Side::Claimant,
            cpace::finish(b, &am).unwrap(),
            context.public_context(),
            &aw,
            &bw,
        )
        .unwrap();
        let finished = pb.local_finished_frame();
        let channel = pa.confirm(&finished).unwrap();
        let device = SigningKey::from_bytes(&SEED);
        let prepared = prepare_offer_core(
            &p,
            &c,
            &CredentialV2OfferBuildInput {
                request_id: REQUEST,
                transcript_hash: channel.transcript_hash(),
                application_account_id: [0x43; 32],
                account_scope_id: [0x44; 32],
                device_public_key: device.verifying_key().to_bytes(),
                requested_permissions: vec![
                    "https://photos.example/selfsame/application#device".into()
                ],
                intent_nonce: INTENT,
                issued_at: NOW,
                expires_at: EXPIRY - 100,
                legacy_handle: "@alice".into(),
                enrolled_key: [0x46; 32],
                snapshot_rows: Vec::new(),
                snapshot_nonce: [0x47; 32],
            },
        )
        .unwrap();
        let proof = device_possession_proof_input(
            [0x48; 32],
            *c.carrier_ceremony_id(),
            prepared.offer_core_digest,
        )
        .unwrap();
        let verified = verify_prepared_offer_device_proof(
            &p,
            &prepared,
            [0x48; 32],
            *c.carrier_ceremony_id(),
            device.verifying_key().to_bytes(),
            device.sign(&proof).to_bytes(),
        )
        .unwrap();
        let offer = finalize_verified_offer(&p, &verified, KID, &key).unwrap();
        let recognised = recognise_signed_offer(&p, &offer.signed_offer).unwrap();
        let authority_response = build_authority_status_response(
            &p,
            *c.carrier_ceremony_id(),
            offer.offer_core_digest,
            &CredentialV2AuthorityStatus::NoBinding,
            KID,
            &key,
        )
        .unwrap();
        let (authority, verifier) = credential_v2_body_authority();
        authority.bind_offer(p.clone(), &recognised).unwrap();
        let mut endpoint =
            CredentialV2Endpoint::new(Side::Allocator, c.clone(), Box::new(verifier));
        let object = CredentialV2Object::new(
            CredentialV2Kind::Offer,
            credential_v2_intent_digest(offer.offer_core_digest),
            offer.signed_offer.clone(),
        )
        .unwrap();
        endpoint.send(&object).unwrap();
        let approve = authority
            .intent_decision(&object, CredentialV2IntentDecision::Approve)
            .unwrap();
        endpoint.receive(&approve).unwrap();
        let preview = format!("did:crdt:{}", "a".repeat(64));
        let preparation = authority.preparation(&approve, &preview).unwrap();
        endpoint.receive(&preparation).unwrap();
        let comparison = authority
            .comparison(&preparation, &authority_response.response)
            .unwrap();
        endpoint.send(&comparison).unwrap();
        let final_approve = authority
            .final_decision(&comparison, CredentialV2FinalDecision::Approve)
            .unwrap();
        endpoint.receive(&final_approve).unwrap();
        let payload = authority
            .payload(
                &final_approve,
                CredentialV2PayloadInput {
                    grant_id: [0x49; 32],
                    grant: "e30.e30.AA".into(),
                },
            )
            .unwrap();
        endpoint.receive(&payload).unwrap();
        let retained = authority.retained_payload().unwrap();
        let (_, initial_verifier) = credential_v2_body_authority();
        let mut initial =
            CredentialV2Endpoint::new(Side::Allocator, c.clone(), Box::new(initial_verifier));
        let checkpoint = initial
            .seal_checkpoint(
                &channel,
                &CredentialV2RelayState::new([6; 32]),
                &wrapping(&c),
                1,
                Some(EXPIRY),
                CredentialV2CheckpointNonce::from_csprng([10; 12]),
                NOW,
            )
            .unwrap();
        let (_, restore_verifier) = credential_v2_body_authority_for_restore(p.clone());
        let commitment = Inspection::inspect(
            checkpoint.as_bytes(),
            &wrapping(&c),
            &c,
            1,
            *p.digest(),
            NOW,
            CredentialV2AllocatorMode::Full,
            Box::new(restore_verifier),
        )
        .unwrap()
        .receipt_recovery_commitment()
        .unwrap();
        let status_input = CredentialV2FinalStatusInput {
            application_id: p.application_id.as_str().into(),
            carrier_ceremony_id: *c.carrier_ceremony_id(),
            request_id: REQUEST,
            account_principal_digest: *retained.account_principal_digest(),
            account_scope_id: *retained.account_scope_id(),
            device_did: retained.device_did().into(),
            offer_core_digest: offer.offer_core_digest,
            payload_digest: payload.content_hash(),
            grant_id: *retained.grant_id(),
            issuer_did: retained.preview_issuer_did().into(),
            receipt_recovery_commitment: commitment,
            finalized_at: NOW + 100,
        };
        let status = build_final_status(&p, &status_input, KID, &key).unwrap();
        Self {
            profile: p,
            carrier: c,
            endpoint,
            channel,
            authority,
            offer,
            status,
            status_input,
            authority_response: authority_response.response,
            authority_digest: authority_response.digest,
            payload,
            key,
        }
    }

    fn seal(&mut self, generation: u64) -> Vec<u8> {
        self.endpoint
            .seal_checkpoint(
                &self.channel,
                &CredentialV2RelayState::new([6; 32]),
                &wrapping(&self.carrier),
                generation,
                Some(EXPIRY),
                CredentialV2CheckpointNonce::from_csprng([generation as u8; 12]),
                NOW,
            )
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    fn terminal(&mut self, status: &BuiltCredentialV2FinalStatus) {
        let receipt = self
            .authority
            .receipt(
                &self.payload,
                CredentialV2ReceiptInput {
                    final_status_jws: status.jws.clone(),
                    final_status_digest: status.digest,
                },
            )
            .unwrap();
        self.endpoint.send(&receipt).unwrap();
    }

    fn context(&self, view: &mut View) -> Result<(), &'static str> {
        view.restore_offer_context_inner(
            &encode_carrier(&self.carrier).unwrap(),
            &self.offer.offer_core,
            &self.offer.offer_core_digest,
            EXPIRY - 100,
            &self.offer.signed_offer,
            &self.authority_response,
            &self.authority_digest,
            EXPIRY + 1,
        )
    }

    fn view(&mut self, terminal: bool) -> View {
        if terminal {
            self.terminal(&self.status.clone());
        }
        let sealed = self.seal(1);
        let mut view =
            inspect(&self.profile, &self.carrier, &sealed, 1, EXPIRY + 1, "full").unwrap();
        self.context(&mut view).unwrap();
        view
    }
}

// Optional export of the exact real-builder bytes for generated-WASM browser
// verification. Every key in this test is a fixed, disposable public fixture.
fn export_browser_fixtures_if_requested() {
    let Some(path) = std::env::var_os("SPEC078_CLOSURE_FIXTURES_OUT") else {
        return;
    };
    let b64 = |bytes: &[u8]| Base64UrlUnpadded::encode_string(bytes);
    let mut cases = Vec::new();
    for (name, terminal, valid) in [
        ("payload-sent", false, true),
        ("terminal-receipt", true, true),
        ("terminal-receipt-invalid-signature", true, false),
    ] {
        let mut saved = Saved::payload();
        let status = if valid {
            saved.status.clone()
        } else {
            corrupt_signature(&saved.status)
        };
        if terminal {
            saved.terminal(&status);
        }
        let checkpoint = saved.seal(1);
        let mut view = inspect(
            &saved.profile,
            &saved.carrier,
            &checkpoint,
            1,
            EXPIRY + 1,
            "full",
        )
        .unwrap();
        saved.context(&mut view).unwrap();
        assert_eq!(
            view.verify_final_status_inner(
                status.jws.as_bytes(),
                &status.digest,
                saved.status_input.finalized_at
            )
            .is_ok(),
            valid
        );
        let carrier = encode_carrier(&saved.carrier).unwrap();
        cases.push(serde_json::json!({
            "name": name,
            "restore": {
                "profileB64u": b64(saved.profile.canonical_bytes()),
                "carrierB64u": b64(&carrier),
                "checkpointB64u": b64(&checkpoint),
                "generation": 1,
                "requestIdB64u": b64(&REQUEST),
                "intentNonceB64u": b64(&INTENT),
                "expectedAllocatorKeyB64u": b64(saved.carrier.expected_allocator_key().unwrap()),
                "installationSeedB64u": b64(&SEED),
                "mode": "full",
                "relayExpiresAt": EXPIRY
            },
            "offerContext": {
                "carrierB64u": b64(&carrier),
                "offerCoreB64u": b64(&saved.offer.offer_core),
                "offerCoreDigestB64u": b64(&saved.offer.offer_core_digest),
                "pendingExpiresAt": EXPIRY - 100,
                "signedOfferB64u": b64(&saved.offer.signed_offer),
                "authorityResponseB64u": b64(&saved.authority_response),
                "authorityDigestB64u": b64(&saved.authority_digest)
            },
            "finalStatus": {
                "jws": status.jws,
                "digestB64u": b64(&status.digest),
                "finalizedAt": saved.status_input.finalized_at,
                "expectedVerified": valid
            },
            "expectedPhase": if terminal { "terminal" } else { "payload-sent" },
            "expectedMode": serde_json::Value::Null
        }));
    }
    let fixture = serde_json::json!({
        "schema": "spec078-wasm-closure-fixtures/v1",
        "disposablePublicTestKeys": true,
        "cases": cases
    });
    std::fs::write(path, serde_json::to_vec_pretty(&fixture).unwrap()).unwrap();
}

#[test]
fn closure_real_payload_and_terminal_receipt_verify_after_expiry() {
    export_browser_fixtures_if_requested();
    for terminal in [false, true] {
        let mut saved = Saved::payload();
        let view = saved.view(terminal);
        assert_eq!(
            view.restored_phase(),
            if terminal { "terminal" } else { "payload-sent" }
        );
        assert!(view.restored_mode().is_none());
        assert_eq!(view.body_authority.retained_payload().is_ok(), !terminal);
        view.verify_final_status(
            saved.status.jws.as_bytes(),
            &saved.status.digest,
            saved.status_input.finalized_at,
        )
        .unwrap();
    }
}

#[test]
fn closure_final_status_mutations_refuse_in_both_retained_phases() {
    for terminal in [false, true] {
        let mut saved = Saved::payload();
        let view = saved.view(terminal);
        let mut inputs = Vec::new();
        for field in 0..10 {
            let mut input = saved.status_input.clone();
            match field {
                0 => input.carrier_ceremony_id[0] ^= 1,
                1 => input.request_id[0] ^= 1,
                2 => input.offer_core_digest[0] ^= 1,
                3 => input.payload_digest[0] ^= 1,
                4 => input.receipt_recovery_commitment[0] ^= 1,
                5 => input.account_principal_digest[0] ^= 1,
                6 => input.account_scope_id[0] ^= 1,
                7 => input.grant_id[0] ^= 1,
                8 => input.issuer_did = format!("did:crdt:{}", "b".repeat(64)),
                _ => input.finalized_at += 1,
            }
            inputs.push(build_final_status(&saved.profile, &input, KID, &saved.key).unwrap());
        }
        for status in inputs {
            assert!(view
                .verify_final_status_inner(
                    status.jws.as_bytes(),
                    &status.digest,
                    saved.status_input.finalized_at
                )
                .is_err());
        }
        let mut wrong_digest = saved.status.digest;
        wrong_digest[0] ^= 1;
        assert!(view
            .verify_final_status_inner(
                saved.status.jws.as_bytes(),
                &wrong_digest,
                saved.status_input.finalized_at
            )
            .is_err());
        assert!(view
            .verify_final_status_inner(
                saved.status.jws.as_bytes(),
                &saved.status.digest,
                saved.status_input.finalized_at + 1
            )
            .is_err());
        let changed = corrupt_signature(&saved.status);
        assert!(view
            .verify_final_status_inner(
                changed.jws.as_bytes(),
                &changed.digest,
                saved.status_input.finalized_at
            )
            .is_err());
    }
}

fn corrupt_signature(status: &BuiltCredentialV2FinalStatus) -> BuiltCredentialV2FinalStatus {
    let mut status = status.clone();
    let mut parts: Vec<_> = status.jws.split('.').map(str::to_owned).collect();
    let mut signature = Base64UrlUnpadded::decode_vec(&parts[2]).unwrap();
    signature[0] ^= 1;
    parts[2] = Base64UrlUnpadded::encode_string(&signature);
    status.jws = parts.join(".");
    status
}

#[test]
fn closure_terminal_sealed_hash_does_not_replace_signature_verification() {
    let mut saved = Saved::payload();
    let changed = corrupt_signature(&saved.status);
    // The body/endpoint grammar accepts this canonical receipt; its exact hash
    // is sealed. The consumer must still run the real final-status verifier.
    saved.terminal(&changed);
    let sealed = saved.seal(1);
    let mut view = inspect(
        &saved.profile,
        &saved.carrier,
        &sealed,
        1,
        EXPIRY + 1,
        "full",
    )
    .unwrap();
    saved.context(&mut view).unwrap();
    assert!(view
        .verify_final_status_inner(
            changed.jws.as_bytes(),
            &changed.digest,
            saved.status_input.finalized_at
        )
        .is_err());
}

#[test]
fn closure_terminal_exact_hash_and_signature_still_require_closed_canonical_core() {
    for extra_field in [false, true] {
        let mut saved = Saved::payload();
        let mut status = saved.status.clone();
        let mut core: serde_json::Value = serde_json::from_slice(&status.core).unwrap();
        if extra_field {
            core["extra"] = true.into();
            status.core = serde_json::to_vec(&core).unwrap();
        } else {
            status.core = serde_json::to_vec_pretty(&core).unwrap();
        }
        status.digest = Sha256::digest(&status.core).into();
        let header = status.jws.split('.').next().unwrap();
        let signing_input = format!(
            "{header}.{}",
            Base64UrlUnpadded::encode_string(&status.core)
        );
        status.jws = format!(
            "{signing_input}.{}",
            Base64UrlUnpadded::encode_string(&saved.key.sign(signing_input.as_bytes()).to_bytes())
        );
        // This exact Receipt hash and the actual Ed25519 signature both match.
        // An extra core member or noncanonical octets must still be refused.
        saved.terminal(&status);
        let sealed = saved.seal(1);
        let mut view = inspect(
            &saved.profile,
            &saved.carrier,
            &sealed,
            1,
            EXPIRY + 1,
            "full",
        )
        .unwrap();
        saved.context(&mut view).unwrap();
        assert!(view
            .verify_final_status_inner(
                status.jws.as_bytes(),
                &status.digest,
                saved.status_input.finalized_at
            )
            .is_err());
    }
}

#[test]
fn closure_terminal_candidate_hash_binds_otherwise_valid_status() {
    let mut saved = Saved::payload();
    let view = saved.view(true);
    let mut changed = saved.status_input.clone();
    changed.grant_id[0] ^= 1;
    let status = build_final_status(&saved.profile, &changed, KID, &saved.key).unwrap();
    assert!(view
        .verify_final_status_inner(status.jws.as_bytes(), &status.digest, changed.finalized_at)
        .is_err());
}

#[test]
fn closure_offer_context_checks_exact_carrier_and_authenticated_metadata() {
    let mut saved = Saved::payload();
    let sealed = saved.seal(1);
    let mut view = inspect(&saved.profile, &saved.carrier, &sealed, 1, EXPIRY, "full").unwrap();
    assert!(view
        .verify_final_status_inner(
            saved.status.jws.as_bytes(),
            &saved.status.digest,
            saved.status_input.finalized_at
        )
        .is_err());
    let changed_carrier = encode_carrier(&changed_carrier(&saved.carrier)).unwrap();
    assert!(view
        .restore_offer_context_inner(
            &changed_carrier,
            &saved.offer.offer_core,
            &saved.offer.offer_core_digest,
            EXPIRY - 100,
            &saved.offer.signed_offer,
            &saved.authority_response,
            &saved.authority_digest,
            EXPIRY
        )
        .is_err());
    for change_request in [true, false] {
        let mut changed =
            inspect(&saved.profile, &saved.carrier, &sealed, 1, EXPIRY, "full").unwrap();
        if change_request {
            changed.request_id[0] ^= 1;
        } else {
            changed.intent_nonce[0] ^= 1;
        }
        assert!(saved.context(&mut changed).is_err());
    }
    saved.context(&mut view).unwrap();
    assert!(view
        .restore_offer_context_inner(
            &encode_carrier(&saved.carrier).unwrap(),
            &saved.offer.offer_core,
            &saved.offer.offer_core_digest,
            EXPIRY - 99,
            &saved.offer.signed_offer,
            &saved.authority_response,
            &saved.authority_digest,
            EXPIRY
        )
        .is_err());
    assert!(
        view.offer.is_none(),
        "refused context cannot preserve a prior verifier context"
    );

    for mutate_signature in [true, false] {
        let mut signed_offer = saved.offer.signed_offer.clone();
        let mut authority = saved.authority_response.clone();
        if mutate_signature {
            *signed_offer.last_mut().unwrap() ^= 1;
        } else {
            *authority.last_mut().unwrap() ^= 1;
        }
        let digest: [u8; 32] = Sha256::digest(&authority).into();
        assert!(view
            .restore_offer_context_inner(
                &encode_carrier(&saved.carrier).unwrap(),
                &saved.offer.offer_core,
                &saved.offer.offer_core_digest,
                EXPIRY - 100,
                &signed_offer,
                &authority,
                &digest,
                EXPIRY
            )
            .is_err());
    }
}

#[test]
fn closure_offer_expiry_does_not_relax_ordinary_live_context() {
    let mut saved = Saved::payload();
    let sealed = saved.seal(1);
    let carrier = encode_carrier(&saved.carrier).unwrap();
    let mut live = Session::restore_inner(
        saved.profile.canonical_bytes(),
        &carrier,
        &sealed,
        1,
        &REQUEST,
        &INTENT,
        saved.carrier.expected_allocator_key().unwrap(),
        &SEED,
        NOW,
        "full".into(),
        &[9; 32],
    )
    .unwrap();
    for now in [EXPIRY - 101, EXPIRY - 100, EXPIRY + 1] {
        assert_eq!(
            live.restore_offer_context_inner(
                &carrier,
                &saved.offer.offer_core,
                &saved.offer.offer_core_digest,
                EXPIRY - 100,
                &saved.offer.signed_offer,
                &saved.authority_response,
                &saved.authority_digest,
                now
            )
            .is_ok(),
            now < EXPIRY - 100
        );
        let mut view = inspect(&saved.profile, &saved.carrier, &sealed, 1, now, "full").unwrap();
        view.restore_offer_context_inner(
            &carrier,
            &saved.offer.offer_core,
            &saved.offer.offer_core_digest,
            EXPIRY - 100,
            &saved.offer.signed_offer,
            &saved.authority_response,
            &saved.authority_digest,
            now,
        )
        .unwrap();
    }
}

#[test]
fn closure_cannot_replace_retained_offer_with_another_valid_signed_offer() {
    let mut saved = Saved::payload();
    let sealed = saved.seal(1);
    let mut view = inspect(&saved.profile, &saved.carrier, &sealed, 1, EXPIRY, "full").unwrap();
    let mut core: serde_json::Value = serde_json::from_slice(&saved.offer.offer_core).unwrap();
    core["accountScopeId"] = Base64UrlUnpadded::encode_string(&[0xfe; 32]).into();
    let core = selfsame_app_identity::json::recognise(
        &serde_json::to_vec(&core).unwrap(),
        selfsame_app_identity::json::Limits {
            max_bytes: 16_384,
            max_depth: 8,
        },
    )
    .unwrap();
    let prepared = recognise_prepared_offer(
        &saved.profile,
        &selfsame_app_identity::json::canonicalise(&core),
    )
    .unwrap();
    let device = SigningKey::from_bytes(&SEED);
    let proof = device_possession_proof_input(
        [0x48; 32],
        *saved.carrier.carrier_ceremony_id(),
        prepared.offer_core_digest,
    )
    .unwrap();
    let verified = verify_prepared_offer_device_proof(
        &saved.profile,
        &prepared,
        [0x48; 32],
        *saved.carrier.carrier_ceremony_id(),
        device.verifying_key().to_bytes(),
        device.sign(&proof).to_bytes(),
    )
    .unwrap();
    let offer = finalize_verified_offer(&saved.profile, &verified, KID, &saved.key).unwrap();
    let authority = build_authority_status_response(
        &saved.profile,
        *saved.carrier.carrier_ceremony_id(),
        offer.offer_core_digest,
        &CredentialV2AuthorityStatus::NoBinding,
        KID,
        &saved.key,
    )
    .unwrap();
    assert!(view
        .restore_offer_context_inner(
            &encode_carrier(&saved.carrier).unwrap(),
            &offer.offer_core,
            &offer.offer_core_digest,
            EXPIRY - 100,
            &offer.signed_offer,
            &authority.response,
            &authority.digest,
            EXPIRY
        )
        .is_err());
}

#[test]
fn closure_bootstrap_and_begin_cannot_create_finality_from_offer_metadata() {
    let mut saved = Saved::payload();
    let (p, c, bootstrap) = bootstrap(CredentialV2AllocatorMode::Full);
    let mut view = inspect(&p, &c, &bootstrap, 1, EXPIRY, "full").unwrap();
    saved.context(&mut view).unwrap();
    assert!(view
        .verify_final_status_inner(
            saved.status.jws.as_bytes(),
            &saved.status.digest,
            saved.status_input.finalized_at
        )
        .is_err());
    let (_, verifier) = credential_v2_body_authority();
    saved.endpoint =
        CredentialV2Endpoint::new(Side::Allocator, saved.carrier.clone(), Box::new(verifier));
    let sealed = saved.seal(1);
    let mut view = inspect(&saved.profile, &saved.carrier, &sealed, 1, EXPIRY, "manual").unwrap();
    saved.context(&mut view).unwrap();
    assert!(view.restored_mode().is_none());
    assert!(view
        .verify_final_status_inner(
            saved.status.jws.as_bytes(),
            &saved.status.digest,
            saved.status_input.finalized_at
        )
        .is_err());
}
