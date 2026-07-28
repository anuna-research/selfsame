//! A fully hostile rendezvous — SPEC-001 NFR-003, TEST-029, TEST-030, T1–T3.
//!
//! > **NFR-003 — Blind rendezvous.** Compromise of the rendezvous — full read,
//! > write, replay, and withholding — SHALL NOT enable an attacker to link a
//! > device to a DID its root key did not authorise, nor to learn `s`, a private
//! > key, or the offer contents. The achievable effects SHALL be denial of
//! > service and traffic observation of `H(s)` values.
//!
//! This file gives the operator every power NFR-003 concedes and then asserts
//! the two things that must still hold. It is written as an adversary, not as a
//! happy path with a negative assertion bolted on: [`Rendezvous`] below *is* the
//! attacker, and the tests are its attempts.
//!
//! v0.1.0 of the specification failed this file. The nonce **was** the mailbox
//! path, so the operator knew it; and an attacker can mint a DID naming any
//! public key, so "the document lists our key" passed. Substitution succeeded
//! against every clause. The transcript binding of REQ-006 is what changed.

use std::collections::HashMap;

use selfsame_core::{
    accept, identity, record::{Application, Grant, Offer}, seal, AcceptedIdentity, LinkContext,
    RejectReason,
};
use did_crdt::core::delta::SignedDelta;
use ed25519_dalek::SigningKey;

const NOW: u64 = 1_790_000_000;
const DEADLINE: u64 = NOW + 300;

/// A rendezvous operated by the adversary.
///
/// It records everything it ever sees, exactly as a compromised server would,
/// so the tests can assert over the operator's *whole* view rather than over
/// what a well-behaved implementation would have chosen to log.
#[derive(Default)]
struct Rendezvous {
    slots: HashMap<String, Vec<u8>>,
    observed: Vec<String>,
}

impl Rendezvous {
    fn put(&mut self, slot: &str, ciphertext: &[u8]) {
        self.observed.push(slot.to_owned());
        self.slots.insert(slot.to_owned(), ciphertext.to_vec());
    }

    fn get(&mut self, slot: &str) -> Option<Vec<u8>> {
        self.observed.push(slot.to_owned());
        self.slots.get(slot).cloned()
    }

    /// Everything the operator holds, as one blob — for the TEST-030 scan.
    fn everything_it_knows(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for slot in &self.observed {
            out.extend_from_slice(slot.as_bytes());
        }
        for (slot, ciphertext) in &self.slots {
            out.extend_from_slice(slot.as_bytes());
            out.extend_from_slice(ciphertext);
        }
        out
    }
}

fn device() -> SigningKey {
    SigningKey::from_bytes(&[0x22; 32])
}

fn honest_root() -> SigningKey {
    SigningKey::from_bytes(&[0x11; 32])
}

fn attacker_root() -> SigningKey {
    SigningKey::from_bytes(&[0x66; 32])
}

/// The phone's half: authorise `offer.device_key` under `root` and seal the
/// grant to `offer`'s transcript.
fn phone_replies(offer: &Offer, root: &SigningKey, secret: &[u8; 16]) -> Vec<u8> {
    let (mut doc, genesis) = identity::sign_genesis(root).unwrap();
    let add = identity::add_device(&doc, root, &offer.device_key, "dev-1", NOW * 1_000).unwrap();
    doc.merge_verified_delta(add.clone()).unwrap();
    let deltas: Vec<Vec<u8>> =
        [genesis, add].iter().map(|d| serde_json::to_vec(d).unwrap()).collect();
    let grant = Grant::new(doc.did.to_string(), deltas);
    seal::seal_bundle(&seal::derive_key(secret), &grant.to_bytes(), &offer.transcript())
}

/// The client's half, start to finish, against a given rendezvous.
fn client_links(
    rv: &mut Rendezvous,
    secret: [u8; 16],
    root: &SigningKey,
    tamper: impl FnOnce(&mut Rendezvous, &str, &Offer),
) -> Result<AcceptedIdentity, RejectReason> {
    let offer = Offer::sign(Application::CbclChat, &device(), "Chrome on macOS", DEADLINE);
    rv.put(&seal::slot(seal::Role::Offer, &secret), &seal::seal_offer(&seal::derive_key(&secret), &offer.to_bytes()));

    // The phone reads the offer slot and replies honestly.
    let bundle_slot = seal::slot(seal::Role::Bundle, &secret);
    rv.put(&bundle_slot, &phone_replies(&offer, root, &secret));

    // …and then the operator does whatever it likes.
    tamper(rv, &bundle_slot, &offer);

    let sealed = rv.get(&bundle_slot).ok_or(RejectReason::TranscriptMismatch)?;
    accept(&sealed, &LinkContext { secret, offer }, NOW)
}

// ── the baseline ────────────────────────────────────────────────────────────

#[test]
fn an_honest_rendezvous_links() {
    let mut rv = Rendezvous::default();
    let accepted = client_links(&mut rv, [1u8; 16], &honest_root(), |_, _, _| {}).unwrap();
    let expected = identity::derive_did(&honest_root().verifying_key().to_bytes()).unwrap();
    assert_eq!(accepted.did, expected.to_string());
}

// ── TEST-029: the operator's four powers ────────────────────────────────────

/// **Substitute** — the attack v0.1.0 lost to. The operator mints its own DID,
/// authorises the victim's device key inside it (which it may freely do — a DID
/// controller can add any public key to their own document), and swaps it in.
#[test]
fn substitution_with_an_attacker_rooted_did_is_refused() {
    let mut rv = Rendezvous::default();
    let secret = [2u8; 16];
    let result = client_links(&mut rv, secret, &honest_root(), |rv, slot, offer| {
        // The operator does not hold `s`, so it cannot derive `K` and cannot
        // produce a tag. Give it the strongest thing it *can* build: a
        // perfectly valid bundle sealed under a key it chose.
        let forged = phone_replies(offer, &attacker_root(), &[0xaa; 16]);
        rv.slots.insert(slot.to_owned(), forged);
    });
    assert_eq!(result, Err(RejectReason::TranscriptMismatch));
}

/// The same attack, conceding the operator has somehow learned `s` — the
/// strongest form of T1. The transcript binding still refuses it, because the
/// operator does not hold the *offer bytes* the client wrote… and when it does,
/// the DID it produces is provably not the victim's, which is what the
/// fingerprint comparison (assumption A6) exists to catch.
#[test]
fn substitution_even_with_the_secret_cannot_produce_the_victims_did() {
    let mut rv = Rendezvous::default();
    let secret = [3u8; 16];
    let result = client_links(&mut rv, secret, &honest_root(), |rv, slot, _offer| {
        // Operator holds `s` but binds to an offer of its own choosing.
        let its_own_offer =
            Offer::sign(Application::CbclChat, &device(), "attacker copy", DEADLINE);
        let forged = phone_replies(&its_own_offer, &attacker_root(), &secret);
        rv.slots.insert(slot.to_owned(), forged);
    });
    assert_eq!(result, Err(RejectReason::TranscriptMismatch));

    // Now hand it the offer bytes too. It gets a bundle that opens — and it is
    // unmistakably a different identity.
    let mut rv = Rendezvous::default();
    let accepted = client_links(&mut rv, secret, &honest_root(), |rv, slot, offer| {
        let forged = phone_replies(offer, &attacker_root(), &secret);
        rv.slots.insert(slot.to_owned(), forged);
    })
    .unwrap();
    let victim = identity::derive_did(&honest_root().verifying_key().to_bytes()).unwrap();
    assert_ne!(accepted.did, victim.to_string(), "NFR-003: a foreign DID was accepted as ours");
    assert_ne!(
        accepted.fingerprint,
        selfsame_core::fingerprint_did(victim.as_str()),
        "the fingerprints must differ, or A6's backstop is not there"
    );
}

/// **Replay** — an old bundle from a previous, completed link.
#[test]
fn replay_of_a_previous_bundle_is_refused() {
    let mut first = Rendezvous::default();
    let old_secret = [4u8; 16];
    let old_offer = Offer::sign(Application::CbclChat, &device(), "Chrome on macOS", DEADLINE);
    let old_bundle = phone_replies(&old_offer, &honest_root(), &old_secret);
    first.put(&seal::slot(seal::Role::Bundle, &old_secret), &old_bundle);

    // A fresh attempt with a fresh `s` (REQ-005), into which the operator
    // replays the old bundle.
    let mut rv = Rendezvous::default();
    let result = client_links(&mut rv, [5u8; 16], &honest_root(), |rv, slot, _| {
        rv.slots.insert(slot.to_owned(), old_bundle.clone());
    });
    assert_eq!(result, Err(RejectReason::TranscriptMismatch));
}

/// **Forge** — bit-flips anywhere in the ciphertext.
#[test]
fn forgery_by_mutation_is_refused_at_every_byte() {
    let secret = [6u8; 16];
    let offer = Offer::sign(Application::CbclChat, &device(), "Chrome on macOS", DEADLINE);
    let sealed = phone_replies(&offer, &honest_root(), &secret);
    let ctx = LinkContext { secret, offer };

    for i in 0..sealed.len() {
        let mut mutated = sealed.clone();
        mutated[i] ^= 0x80;
        assert_eq!(
            accept(&mutated, &ctx, NOW),
            Err(RejectReason::TranscriptMismatch),
            "a mutation at byte {i} was not caught"
        );
    }
}

/// **Reorder / cross-wire** — serve the offer slot's contents as the bundle.
#[test]
fn crossing_the_two_slots_is_refused() {
    let mut rv = Rendezvous::default();
    let secret = [7u8; 16];
    let result = client_links(&mut rv, secret, &honest_root(), |rv, slot, _| {
        let offer_slot = seal::slot(seal::Role::Offer, &secret);
        let offer_ciphertext = rv.slots.get(&offer_slot).cloned().unwrap();
        rv.slots.insert(slot.to_owned(), offer_ciphertext);
    });
    assert_eq!(result, Err(RejectReason::TranscriptMismatch));
}

/// **Withhold** — the one effect NFR-003 concedes. It is a denial of service
/// and nothing more: no identity is joined, and no state changes.
#[test]
fn withholding_denies_service_and_achieves_nothing_else() {
    let mut rv = Rendezvous::default();
    let result = client_links(&mut rv, [8u8; 16], &honest_root(), |rv, slot, _| {
        rv.slots.remove(slot);
    });
    assert!(result.is_err());
}

/// **Deny by size** — an oversized body is refused before any parsing.
#[test]
fn an_oversized_body_is_refused() {
    let secret = [9u8; 16];
    let offer = Offer::sign(Application::CbclChat, &device(), "Chrome on macOS", DEADLINE);
    let ctx = LinkContext { secret, offer };
    assert_eq!(
        accept(&vec![0u8; selfsame_core::MAX_SEALED_BYTES + 1], &ctx, NOW),
        Err(RejectReason::Unrecognised)
    );
}

// ── TEST-030: what the operator ends up holding ─────────────────────────────

#[test]
fn the_operator_holds_only_slot_addresses_and_ciphertext() {
    let mut rv = Rendezvous::default();
    let secret = [0x5au8; 16];
    let root = honest_root();
    let accepted = client_links(&mut rv, secret, &root, |_, _, _| {}).unwrap();

    let view = rv.everything_it_knows();
    let contains = |needle: &[u8]| view.windows(needle.len()).any(|w| w == needle);

    // `s` itself, in the two spellings it could plausibly leak in.
    assert!(!contains(&secret), "the link secret is recoverable from server state");
    let secret_hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
    assert!(!contains(secret_hex.as_bytes()), "the link secret leaked as hex");

    // The derived channel key.
    assert!(!contains(&seal::derive_key(&secret)), "the channel key leaked");

    // Either private key.
    assert!(!contains(&device().to_bytes()), "the device private key leaked");
    assert!(!contains(&root.to_bytes()), "the root private key leaked");

    // The offer plaintext: the device description is the most recognisable
    // fragment of it.
    assert!(!contains(b"Chrome on macOS"), "the offer plaintext leaked");
    assert!(!contains(b"(offer"), "the offer plaintext leaked");

    // The DID, which would let the operator correlate a link with an identity.
    assert!(!contains(accepted.did.as_bytes()), "the DID leaked to the rendezvous");

    // What it *is* allowed to hold: the two slot addresses, and nothing else
    // that identifies anyone.
    let mut expected: Vec<String> =
        vec![seal::slot(seal::Role::Offer, &secret), seal::slot(seal::Role::Bundle, &secret)];
    expected.sort();
    let mut seen: Vec<String> = rv.slots.keys().cloned().collect();
    seen.sort();
    assert_eq!(seen, expected);
}

// ── T3 / REQ-005: what nonce reuse would cost ───────────────────────────────

/// Fixed nonces are safe **only** because `K` is single-use. This test makes
/// the cost of breaking REQ-005 concrete rather than leaving it as a comment:
/// reusing `s` across two links produces two ciphertexts under one key and one
/// nonce, and XORing them cancels the keystream, exposing the XOR of the two
/// plaintexts to anyone holding both — which the rendezvous operator does.
#[test]
fn reusing_the_secret_would_expose_the_plaintexts_to_the_operator() {
    let secret = [0x11u8; 16];
    let key = seal::derive_key(&secret);

    let a = b"(grant :v 1 :did \"did:crdt:aaaa\" :deltas ())".to_vec();
    let b = b"(grant :v 1 :did \"did:crdt:bbbb\" :deltas ())".to_vec();
    let t = seal::transcript(b"same offer");

    let ca = seal::seal_bundle(&key, &a, &t);
    let cb = seal::seal_bundle(&key, &b, &t);

    // Strip the 16-byte Poly1305 tag; the remainder is the ChaCha20 keystream
    // XORed with the plaintext.
    let xor: Vec<u8> =
        ca[..a.len()].iter().zip(&cb[..b.len()]).map(|(x, y)| x ^ y).collect();
    let plaintext_xor: Vec<u8> = a.iter().zip(&b).map(|(x, y)| x ^ y).collect();
    assert_eq!(
        xor, plaintext_xor,
        "this equality is exactly the harm REQ-005 exists to prevent"
    );

    // And with a fresh secret, it does not hold.
    let mut other = secret;
    other[0] ^= 1;
    let cb2 = seal::seal_bundle(&seal::derive_key(&other), &b, &t);
    let xor2: Vec<u8> =
        ca[..a.len()].iter().zip(&cb2[..b.len()]).map(|(x, y)| x ^ y).collect();
    assert_ne!(xor2, plaintext_xor);
}

// ── T4: forging a genesis for an existing DID ───────────────────────────────

#[test]
fn a_genesis_cannot_be_forged_for_someone_elses_did() {
    // The DID commits to the genesis, so producing a different genesis with the
    // same DID requires a BLAKE3 preimage. What is testable here is the
    // consequence: every distinct root gives a distinct DID, and swapping the
    // genesis inside a bundle changes the DID the verifier recomputes.
    let victim = identity::derive_did(&honest_root().verifying_key().to_bytes()).unwrap();
    let attacker = identity::derive_did(&attacker_root().verifying_key().to_bytes()).unwrap();
    assert_ne!(victim, attacker);

    let secret = [0x77u8; 16];
    let offer = Offer::sign(Application::CbclChat, &device(), "Chrome on macOS", DEADLINE);
    let honest = phone_replies(&offer, &honest_root(), &secret);
    let key = seal::derive_key(&secret);
    let grant = Grant::parse(&seal::open_bundle(&key, &honest, &offer.transcript()).unwrap()).unwrap();

    // Splice the attacker's genesis into the victim's bundle, keeping the
    // victim's asserted DID.
    let (_, attacker_genesis) = identity::sign_genesis(&attacker_root()).unwrap();
    let mut deltas = grant.deltas.clone();
    deltas[0] = serde_json::to_vec(&attacker_genesis).unwrap();
    let spliced = Grant::new(grant.did.clone(), deltas);
    let resealed = seal::seal_bundle(&key, &spliced.to_bytes(), &offer.transcript());

    let ctx = LinkContext { secret, offer };
    assert_eq!(accept(&resealed, &ctx, NOW), Err(RejectReason::DidMismatch));
}

// ── T5 / REQ-008: a linked device promoting itself ──────────────────────────

#[test]
fn a_bundle_containing_a_device_signed_delta_is_discarded_whole() {
    use did_crdt::core::delta::{DeltaOp, SigningKey as DidSigningKey, SuiteType};
    use did_crdt::core::hlc::HlcTimestamp;
    use did_crdt::core::validate::node_id_from_pubkey;

    let root = honest_root();
    let (mut doc, genesis) = identity::sign_genesis(&root).unwrap();
    let dev_pk = device().verifying_key().to_bytes();
    let add = identity::add_device(&doc, &root, &dev_pk, "dev-1", NOW * 1_000).unwrap();
    doc.merge_verified_delta(add.clone()).unwrap();
    let method_id = format!("{}#dev-1", doc.did);

    // The device now signs an `AddVerificationMethod` for a second key of its
    // own — upstream would admit this; the profile must not.
    let intruder = SigningKey::from_bytes(&[0x99; 32]);
    let escalation = SignedDelta::new_with_parents(
        doc.did.clone(),
        DeltaOp::AddVerificationMethod {
            id: format!("{}#dev-2", doc.did),
            public_key_multibase: identity::key_multibase(&intruder.verifying_key().to_bytes()),
            suite_type: SuiteType::Ed25519Signature2020,
            relationships: did_crdt::core::delta::default_relationships(),
        },
        HlcTimestamp { wall_ms: NOW * 1_000 + 5, logical: 0, node_id: node_id_from_pubkey(&dev_pk) },
        doc.frontier(),
        method_id,
        &DidSigningKey::Ed25519(device()),
    )
    .unwrap();

    let deltas: Vec<Vec<u8>> =
        [genesis, add, escalation].iter().map(|d| serde_json::to_vec(d).unwrap()).collect();
    let grant = Grant::new(doc.did.to_string(), deltas);

    let secret = [0x88u8; 16];
    let offer = Offer::sign(Application::CbclChat, &device(), "Chrome on macOS", DEADLINE);
    let sealed =
        seal::seal_bundle(&seal::derive_key(&secret), &grant.to_bytes(), &offer.transcript());

    let ctx = LinkContext { secret, offer };
    assert_eq!(accept(&sealed, &ctx, NOW), Err(RejectReason::ForeignSigner));
}
