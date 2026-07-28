//! Property-based tests — SPEC-001 TEST-035, TEST-036, TEST-037, TEST-005.
//!
//! The pure core is the ideal property-testing target (PROTO-001's
//! "complex business logic in pure core" row): total functions, well-defined
//! input domains, and roundtrips the system both reads and writes. LangSec's
//! verification obligation is explicit — *property-based roundtrip tests*
//! `parse(serialise(x)) == x` *are REQUIRED for any format the system both
//! reads and writes*.
//!
//! Each property below states the requirement it discharges rather than merely
//! exercising code, so a shrunk counterexample lands on one obligation.

use selfsame_core::{code, mb, record, seal, MAX_DEVICE_DESCRIPTION_CHARS};
use ed25519_dalek::SigningKey;
use proptest::prelude::*;

// ── REQ-027 — one canonical binary spelling ─────────────────────────────────

proptest! {
    /// TEST-037 positive: every byte string has exactly one spelling, and it
    /// round-trips.
    #[test]
    fn multibase_round_trips(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let encoded = mb::encode(&bytes);
        prop_assert!(encoded.starts_with('u'));
        prop_assert_eq!(mb::decode(&encoded).unwrap(), bytes);
    }

    /// TEST-037 negative-output: the decoder is injective on its accepted
    /// language — no two accepted strings decode to the same bytes.
    #[test]
    fn multibase_decoding_is_injective(a in "[A-Za-z0-9_-]{0,24}", b in "[A-Za-z0-9_-]{0,24}") {
        let (sa, sb) = (format!("u{a}"), format!("u{b}"));
        if let (Ok(da), Ok(db)) = (mb::decode(&sa), mb::decode(&sb)) {
            prop_assert_eq!(da == db, a == b, "{} vs {}", sa, sb);
        }
    }

    /// The decoder never panics, whatever it is fed.
    #[test]
    fn multibase_decoding_is_total(s in ".{0,256}") {
        let _ = mb::decode(&s);
    }
}

// ── CON-001 — the link code ─────────────────────────────────────────────────

proptest! {
    /// TEST-011 positive: `parse(render(x)) == x` for every secret.
    #[test]
    fn link_code_round_trips(secret in any::<[u8; 16]>()) {
        let link = code::LinkCode {
            application: record::Application::CbclChat,
            secret: code::LinkSecret::from_bytes(secret),
        };
        let rendered = link.render();
        prop_assert_eq!(rendered.chars().count(), code::CODE_CHARS);
        prop_assert_eq!(code::LinkCode::parse(&rendered).unwrap(), link);
    }

    /// TEST-011 negative-output: a corrupted code is never accepted as a
    /// *different valid* secret. This is the property REQ-011's checksum
    /// exists for — silent acceptance of a typo is worse than rejection.
    #[test]
    fn a_corrupted_code_never_decodes_to_a_different_secret(
        secret in any::<[u8; 16]>(),
        position in 6usize..41,
        replacement in 0usize..32,
    ) {
        const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        let link = code::LinkCode {
            application: record::Application::CbclChat,
            secret: code::LinkSecret::from_bytes(secret),
        };
        let mut bytes = link.render().into_bytes();
        if bytes[position] == CHARSET[replacement] {
            return Ok(());
        }
        bytes[position] = CHARSET[replacement];
        let corrupted = String::from_utf8(bytes).unwrap();
        prop_assert!(code::LinkCode::parse(&corrupted).is_err());
    }

    /// The recogniser never panics on hostile input.
    #[test]
    fn link_code_parsing_is_total(s in ".{0,128}") {
        let _ = code::LinkCode::parse(&s);
    }
}

// ── CON-001 / CON-002 — the two records ─────────────────────────────────────

fn signing_key() -> impl Strategy<Value = SigningKey> {
    any::<[u8; 32]>().prop_map(|seed| SigningKey::from_bytes(&seed))
}

proptest! {
    /// TEST-035 positive: `parse(render(x)) == x` for every offer, and the
    /// signature verifies over the canonical encoding.
    #[test]
    fn offer_round_trips(
        sk in signing_key(),
        desc in ".{0,64}",
        expiry in 0u64..i64::MAX as u64,
    ) {
        let offer = record::Offer::sign(record::Application::CbclChat, &sk, &desc, expiry);
        let wire = offer.to_bytes();
        prop_assume!(wire.len() <= record::MAX_RECORD_BYTES);
        prop_assert_eq!(record::Offer::parse(&wire).unwrap(), offer);
    }

    /// TEST-035 negative-output: two implementations producing different
    /// canonical bytes for one offer would break cross-runtime signatures. The
    /// in-process form of that property is that the transcript is a function of
    /// the offer's *value*, not of how it was obtained.
    #[test]
    fn the_transcript_depends_only_on_the_offer_value(
        sk in signing_key(),
        desc in ".{0,64}",
        expiry in 0u64..i64::MAX as u64,
    ) {
        let offer = record::Offer::sign(record::Application::CbclChat, &sk, &desc, expiry);
        let wire = offer.to_bytes();
        prop_assume!(wire.len() <= record::MAX_RECORD_BYTES);
        let reparsed = record::Offer::parse(&wire).unwrap();
        prop_assert_eq!(reparsed.transcript(), offer.transcript());
        prop_assert_eq!(reparsed.signing_bytes(), offer.signing_bytes());
    }

    /// REQ-019: the description cap holds however strange the description is.
    #[test]
    fn a_signed_offer_never_exceeds_the_description_cap(sk in signing_key(), desc in ".{0,4096}") {
        let offer = record::Offer::sign(record::Application::CbclChat, &sk, &desc, 1);
        prop_assert!(offer.device_description.chars().count() <= MAX_DEVICE_DESCRIPTION_CHARS);
    }

    /// TEST-036 negative-output: deltas survive the envelope **byte-identical**,
    /// because REQ-003's derivation hashes those exact bytes.
    #[test]
    fn grant_round_trips_preserving_delta_bytes(
        deltas in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..256), 2..=3),
        hex in "[0-9a-f]{64}",
    ) {
        let grant = record::Grant::new(format!("did:crdt:{hex}"), deltas.clone());
        let wire = grant.to_bytes();
        prop_assume!(wire.len() <= record::MAX_RECORD_BYTES);
        let parsed = record::Grant::parse(&wire).unwrap();
        prop_assert_eq!(&parsed.deltas, &deltas);
        prop_assert_eq!(parsed, grant);
    }

    /// TEST-035 / TEST-036 negative-input: hostile bytes never panic and never
    /// yield a record outside the dialect.
    #[test]
    fn record_recognisers_are_total(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
        let _ = record::Offer::parse(&bytes);
        let _ = record::Grant::parse(&bytes);
    }

    #[test]
    fn record_recognisers_are_total_on_plausible_text(s in r"\(offer( :[a-z]{1,6} [^()]{0,16}){0,10}\)") {
        let _ = record::Offer::parse(s.as_bytes());
    }
}

// ── CON-002 — the sealed envelope ───────────────────────────────────────────

proptest! {
    /// TEST-006 positive: a bundle sealed against a transcript opens under that
    /// transcript and no other.
    #[test]
    fn sealing_round_trips_and_binds_to_the_transcript(
        secret in any::<[u8; 16]>(),
        plaintext in prop::collection::vec(any::<u8>(), 0..1024),
        offer_a in prop::collection::vec(any::<u8>(), 0..64),
        offer_b in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let key = seal::derive_key(&secret);
        let ta = seal::transcript(&offer_a);
        let tb = seal::transcript(&offer_b);
        let sealed = seal::seal_bundle(&key, &plaintext, &ta);
        prop_assert_eq!(seal::open_bundle(&key, &sealed, &ta).unwrap(), plaintext);
        if offer_a != offer_b {
            prop_assert!(seal::open_bundle(&key, &sealed, &tb).is_err());
        }
    }

    /// TEST-005 negative-output: distinct secrets give distinct slots and
    /// distinct channel keys, so a reused `s` is the *only* way two link
    /// attempts can collide — which is exactly what REQ-005 forbids.
    #[test]
    fn distinct_secrets_never_share_a_slot_or_a_key(a in any::<[u8; 16]>(), b in any::<[u8; 16]>()) {
        prop_assume!(a != b);
        prop_assert_ne!(seal::derive_key(&a), seal::derive_key(&b));
        prop_assert_ne!(seal::slot(seal::Role::Offer, &a), seal::slot(seal::Role::Offer, &b));
        prop_assert_ne!(seal::slot(seal::Role::Bundle, &a), seal::slot(seal::Role::Bundle, &b));
        // Direction separation holds for every secret, not just for the ones
        // in the unit tests.
        prop_assert_ne!(seal::slot(seal::Role::Offer, &a), seal::slot(seal::Role::Bundle, &a));
    }

    /// Opening never panics on arbitrary ciphertext.
    #[test]
    fn opening_is_total(
        secret in any::<[u8; 16]>(),
        sealed in prop::collection::vec(any::<u8>(), 0..256),
        t in any::<[u8; 32]>(),
    ) {
        let key = seal::derive_key(&secret);
        let _ = seal::open_bundle(&key, &sealed, &t);
        let _ = seal::open_offer(&key, &sealed);
    }
}
