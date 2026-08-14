//! One ceremony, both halves, no sockets — `PROTO-003` and `PROTO-004` end to
//! end between the browser's surface and the wallet's primitives.
//!
//! # What this is evidence of, and what it is not
//!
//! The browser side is the real thing: `PairingCarrier` and `PairingSession` are
//! the exact values `wasm-bindgen` exports, called through their native twins.
//!
//! The wallet side is **its cryptography, not its command**. `pairing_answer`
//! lives in `src-tauri`, which this crate cannot depend on, so role B here is
//! played by `selfsame_core::{spake2, envelope, seal}` — the same primitives that
//! command calls, in the same order. What that proves is agreement on the wire
//! values: the same `C` and `binding_hash` produce the same mailbox secret, the
//! same slots, and records each side can open. What it does not prove is that the
//! wallet's transport, state machine, or ordering are right; those are its own.
//!
//! # Why it exists
//!
//! Because for a while they did not agree, and nothing would have said so.
//!
//! `seal_offer_bytes` and `open_bundle_bytes` are SPEC-001's envelope — HKDF over
//! the secret alone, bound to a BLAKE3 transcript of the offer. The wallet opens
//! `PROTO-004`'s — two role-separated keys salted by `binding_hash`, a constant
//! nonce, a fixed 69,632-octet record. Both are reachable from JavaScript as
//! functions taking a secret and some bytes, both were written against a real
//! contract, and neither knew about the other. A pairing built from the pair
//! would have completed its PAKE, agreed its slots, written an offer, and then
//! failed to open it — three round trips and a signature after the mistake.
//!
//! So this test seals with one half and opens with the other, in both
//! directions.

use selfsame_core::envelope::EnvelopeKeys;
use selfsame_core::seal;
use selfsame_core::spake2::{Pairing as Spake2, Party};
use selfsame_web_device::{
    open_bundle_envelope_for, seal_offer_envelope_for, PairingCarrier, PairingSession,
};

/// `CON-403`'s binding, as both endpoints must hold it before either processes a
/// peer frame. Constructed once here and shared, which is what "both parties MUST
/// hold every member" means in a test that has no two parties to disagree.
const BINDING_HASH: [u8; 32] = [0x11; 32];

const CODE: [u8; 16] = [
    0x9f, 0x3a, 0x11, 0xc2, 0xe7, 0x0b, 0x4d, 0x8a, 0x5c, 0x6f, 0x90, 0x12, 0xab, 0x34, 0xcd, 0x56,
];

/// Run the four frames and return the mailbox secret each side derived.
///
/// The order is `CON-407`'s: `pA`, then `pB`, then `cA` verified by B, then `cB`
/// verified by A. A test that exchanged them in any other order would agree with
/// itself and with no conforming implementation.
fn ceremony(code: [u8; 16], b_code: [u8; 16]) -> (Result<[u8; 16], ()>, Result<[u8; 16], ()>) {
    let carrier = PairingCarrier::from_entropy(code);

    // Role A: the browser, through the surface a page actually calls.
    let mut a: PairingSession = carrier.begin_pairing(&BINDING_HASH, &[0x22; 64]).unwrap();
    let p_a = a.message();

    // Role B: the wallet's primitives, in the order `pairing_answer` calls them.
    let b = Spake2::begin(Party::Wallet, &b_code, &BINDING_HASH, &[0x33; 64]).unwrap();
    let p_b = b.message();

    // B consumes `pA` and reaches its confirmation stage; A consumes `pB`.
    let Ok(b) = b.confirm(&p_a.clone().try_into().unwrap()) else {
        return (Err(()), Err(()));
    };
    let Ok(c_a) = a.confirm_for(&p_b) else { return (Err(()), Err(())) };
    let c_b = b.confirmation();

    // B verifies `cA` before storing `cB` — the one authorization-critical
    // online password guess.
    let b_secret = b.verify_peer(&c_a).map(|m| m.mailbox_secret()).map_err(|_| ());
    // A verifies `cB` before treating the PAKE as complete.
    let a_secret = a.finish_for(&c_b).map_err(|_| ());
    (a_secret, b_secret)
}

/// The honest path: one code, one binding, one secret on both sides.
#[test]
fn both_halves_derive_the_same_mailbox_secret() {
    let (a, b) = ceremony(CODE, CODE);
    let (a, b) = (a.expect("role A confirmed"), b.expect("role B confirmed"));
    assert_eq!(a, b, "CON-408 must produce one secret from one exchange");
    assert_ne!(a, [0u8; 16]);
    // And it is not the code. `CON-226`'s downgrade is "deriving an AEAD or
    // mailbox secret directly from `C`", and a 128-bit code used as a key is one
    // an eavesdropper grinds offline.
    assert_ne!(a, CODE);
}

/// A wrong word fails at the confirmation MAC, which is where `REQ-406` puts it.
#[test]
fn a_different_code_fails_at_confirmation_and_yields_nothing() {
    let mut wrong = CODE;
    wrong[15] ^= 1;
    let (a, b) = ceremony(CODE, wrong);
    assert!(a.is_err() && b.is_err(), "a wrong code must not produce a mailbox secret");
}

/// The offer the browser seals is the offer the wallet opens.
///
/// This is the assertion that was false. Sealed through the wasm surface and
/// opened through the core's `EnvelopeKeys`, which is what `pairing_answer` uses.
#[test]
fn the_offer_the_browser_seals_is_the_one_the_wallet_opens() {
    let (a, b) = ceremony(CODE, CODE);
    let (a_secret, b_secret) = (a.unwrap(), b.unwrap());

    let payload = br#"{"payloadVersion":1,"role":"offer"}"#;
    let sealed = seal_offer_envelope_for(&a_secret, &BINDING_HASH, payload).unwrap();
    assert_eq!(sealed.len(), selfsame_core::envelope::SEALED_OCTETS);

    let opened = EnvelopeKeys::derive(&b_secret, &BINDING_HASH)
        .unwrap()
        .offer
        .open(&sealed)
        .expect("the wallet must open what the browser sealed");
    assert_eq!(opened, payload);
}

/// And the bundle back the other way.
#[test]
fn the_bundle_the_wallet_seals_is_the_one_the_browser_opens() {
    let (a, b) = ceremony(CODE, CODE);
    let (a_secret, b_secret) = (a.unwrap(), b.unwrap());

    let payload = br#"{"payloadVersion":1,"role":"bundle"}"#;
    let sealed = EnvelopeKeys::derive(&b_secret, &BINDING_HASH)
        .unwrap()
        .bundle
        .seal(payload)
        .unwrap();

    let opened = open_bundle_envelope_for(&a_secret, &BINDING_HASH, &sealed)
        .expect("the browser must open what the wallet sealed");
    assert_eq!(opened, payload);
}

/// The two slots agree, so each side writes where the other reads.
///
/// `CON-302`'s derivation is `selfsame_core::seal::slot` on both sides — the same
/// function, which is the point: PROTO-002's normative vectors are SPEC-001's,
/// and a second implementation of a slot name is a mailbox nobody reads.
#[test]
fn both_halves_address_the_same_two_slots() {
    let (a, b) = ceremony(CODE, CODE);
    let (a_secret, b_secret) = (a.unwrap(), b.unwrap());
    assert_eq!(
        seal::slot(seal::Role::Offer, &a_secret),
        seal::slot(seal::Role::Offer, &b_secret),
    );
    assert_eq!(
        seal::slot(seal::Role::Bundle, &a_secret),
        seal::slot(seal::Role::Bundle, &b_secret),
    );
    assert_ne!(
        seal::slot(seal::Role::Offer, &a_secret),
        seal::slot(seal::Role::Bundle, &a_secret),
    );
}

/// SPEC-001's envelope and PROTO-004's are not interchangeable, and this is what
/// that costs if the wrong one is reached for.
///
/// Kept as a test rather than a comment because the two are one autocomplete
/// apart in JavaScript, and the failure it produces — a ceremony that completes
/// its PAKE and then cannot read its own mailbox — is expensive to diagnose from
/// the far end.
#[test]
fn the_spec_001_envelope_does_not_open_a_proto_004_record() {
    let (a, _) = ceremony(CODE, CODE);
    let secret = a.unwrap();
    let payload = br#"{"payloadVersion":1,"role":"offer"}"#;

    let proto_004 = seal_offer_envelope_for(&secret, &BINDING_HASH, payload).unwrap();
    assert!(
        seal::open_offer(&seal::derive_key(&secret), &proto_004).is_err(),
        "SPEC-001's opener must not accept a PROTO-004 record",
    );

    let spec_001 = seal::seal_offer(&seal::derive_key(&secret), payload);
    assert!(
        EnvelopeKeys::derive(&secret, &BINDING_HASH).unwrap().offer.open(&spec_001).is_err(),
        "PROTO-004's opener must not accept a SPEC-001 record",
    );
    // They are not even the same size, which is the first thing that gives it
    // away: PROTO-004 pads to one length so a mailbox operator learns nothing
    // from a record's size, and SPEC-001 does not pad at all.
    assert_ne!(proto_004.len(), spec_001.len());
}

/// A record from a different ceremony does not open, even under the right secret.
///
/// `CON-501` salts both keys with `binding_hash`, so this is refused by the key
/// schedule before the tag is reached — which is the property that lets one
/// mailbox operator serve many ceremonies without any of them being splice-able
/// into another.
#[test]
fn a_record_from_another_binding_does_not_open() {
    let (a, _) = ceremony(CODE, CODE);
    let secret = a.unwrap();
    let mut other_binding = BINDING_HASH;
    other_binding[0] ^= 0xff;

    let elsewhere = seal_offer_envelope_for(&secret, &other_binding, b"{}").unwrap();
    assert!(open_bundle_envelope_for(&secret, &BINDING_HASH, &elsewhere).is_err());
    assert!(EnvelopeKeys::derive(&secret, &BINDING_HASH)
        .unwrap()
        .offer
        .open(&elsewhere)
        .is_err());
}
