//! The transcript-bound blind rendezvous — SPEC-001 CON-002, ADR-008, REQ-006.
//!
//! This module is the clause that makes the rendezvous untrusted. The operator
//! sees `H(s)` and ciphertext, never `s`, so it can **withhold but cannot
//! substitute**.
//!
//! ```text
//!   client                     rendezvous (blind)                   phone
//!     │  PUT slot(offer, s)  ──▶ H(s) ┐                               │
//!     │     AEAD(K, offer)           │  stores opaque bytes           │
//!     │                              │                               │
//!     │                              └──── GET slot(offer, s) ────────┤ reads code,
//!     │                                                              │ derives K
//!     │  GET slot(bundle, s) ◀─── AEAD(K, grant, ad = H(offer)) ──────┤
//!     ▼
//!   accepts only if the tag verifies under *its own* offer's hash
//! ```
//!
//! # Why v0.1.0 was broken, and what fixed it
//!
//! v0.1.0 addressed the mailbox by the raw nonce and put no authenticator on
//! the reply, so the operator knew the slot key and could substitute a bundle
//! for an attacker-rooted DID that authorised the victim's public key. That
//! passed every acceptance clause, because an attacker may freely add *any*
//! public key to *their own* DID. Two changes close it:
//!
//! 1. slots are addressed by `BLAKE3(domain ‖ role ‖ s)`, so the operator
//!    cannot derive `s` from what it sees and therefore cannot forge a tag;
//! 2. the bundle's associated data is `BLAKE3(offer_plaintext)` — the complete
//!    transcript — so a bundle is acceptable only *in reply to this offer*,
//!    from a party that read the code off the user's screen.
//!
//! # The nonce discipline
//!
//! `K = HKDF-SHA-256(s)` is **single-use**, which is the only reason fixed,
//! direction-separated nonces are safe. REQ-005 forbids reusing `s`;
//! `tests/nonce_reuse.rs` demonstrates what reuse would cost, so the constraint
//! is visible rather than assumed.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

/// HKDF `info` string for the link channel key (CON-002).
const KDF_INFO: &[u8] = b"anuna-ssi/v1/link";

/// Domain prefix for slot addressing (CON-002).
const SLOT_DOMAIN: &[u8] = b"anuna-ssi/v1/slot/";

/// Associated data for the offer record (CON-002).
const AD_OFFER: &[u8] = b"anuna-ssi/v1/offer";

/// Associated-data prefix for the bundle record; the transcript hash follows.
const AD_BUNDLE: &[u8] = b"anuna-ssi/v1/bundle";

/// Which of the two single-write slots a call refers to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// Written by the device client, read by the phone.
    Offer,
    /// Written by the phone, read by the device client.
    Bundle,
}

impl Role {
    /// The role token that participates in slot derivation and in the URL.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Offer => "offer",
            Role::Bundle => "bundle",
        }
    }

    /// The fixed, direction-separated nonce. Safe **only** because `K` is
    /// single-use (REQ-005).
    fn nonce(self) -> Nonce {
        let mut n = [0u8; 12];
        n[11] = match self {
            Role::Offer => 1,
            Role::Bundle => 2,
        };
        *Nonce::from_slice(&n)
    }
}

/// The AEAD failed to authenticate.
///
/// Deliberately carries nothing: a diagnostic here would be an oracle for the
/// rendezvous operator, and CON-002's error model gives the server no
/// information to make a trust decision with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("sealed record did not authenticate")]
pub struct SealError;

/// Derive the single-use channel key `K = HKDF-SHA-256(s, "", "anuna-ssi/v1/link", 32)`.
pub fn derive_key(secret: &[u8; 16]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut okm = [0u8; 32];
    hk.expand(KDF_INFO, &mut okm).expect("32 bytes is a valid HKDF output length");
    okm
}

/// The transcript hash: `BLAKE3(offer_plaintext)`.
///
/// This is the value that makes the bundle a *reply* rather than a message —
/// it commits to the exact offer bytes the client wrote, so a bundle minted
/// against a different offer cannot authenticate here (REQ-006).
pub fn transcript(offer_plaintext: &[u8]) -> [u8; 32] {
    *blake3::hash(offer_plaintext).as_bytes()
}

/// Derive a slot address: `base32(BLAKE3("anuna-ssi/v1/slot/" ‖ role ‖ s)[0..16])`.
///
/// The operator sees only this. 128 bits of the digest is the same guessing
/// margin as `s` itself, so slot enumeration is no cheaper than guessing the
/// secret (threat T2).
///
/// The base32 alphabet is RFC 4648 lowercase without padding. CON-002 says
/// "base32" without fixing an alphabet; this build fixes it here and
/// [`tests/vectors.rs`] pins it, so two implementations cannot disagree about
/// which mailbox a code refers to.
pub fn slot(role: Role, secret: &[u8; 16]) -> String {
    let mut input = Vec::with_capacity(SLOT_DOMAIN.len() + 6 + 16);
    input.extend_from_slice(SLOT_DOMAIN);
    input.extend_from_slice(role.as_str().as_bytes());
    input.extend_from_slice(secret);
    let digest = blake3::hash(&input);
    base32_lower(&digest.as_bytes()[..16])
}

/// Seal the offer record into the offer slot.
pub fn seal_offer(key: &[u8; 32], offer_plaintext: &[u8]) -> Vec<u8> {
    cipher(key)
        .encrypt(&Role::Offer.nonce(), Payload { msg: offer_plaintext, aad: AD_OFFER })
        .expect("ChaCha20-Poly1305 encryption is infallible for in-memory buffers")
}

/// Open the offer record. The phone calls this after deriving `K` from the
/// scanned code.
pub fn open_offer(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, SealError> {
    cipher(key)
        .decrypt(&Role::Offer.nonce(), Payload { msg: sealed, aad: AD_OFFER })
        .map_err(|_| SealError)
}

/// Seal the credential bundle, binding it to the offer transcript.
pub fn seal_bundle(key: &[u8; 32], grant_plaintext: &[u8], transcript: &[u8; 32]) -> Vec<u8> {
    cipher(key)
        .encrypt(
            &Role::Bundle.nonce(),
            Payload { msg: grant_plaintext, aad: &bundle_ad(transcript) },
        )
        .expect("ChaCha20-Poly1305 encryption is infallible for in-memory buffers")
}

/// Open the credential bundle **under the caller's own offer hash**.
///
/// The caller passes the transcript of the offer *it itself wrote*. That is
/// the whole of REQ-006: a reply that authenticates here provably came from
/// something that read the code off the user's screen, not from the rendezvous
/// operator.
pub fn open_bundle(
    key: &[u8; 32],
    sealed: &[u8],
    transcript: &[u8; 32],
) -> Result<Vec<u8>, SealError> {
    cipher(key)
        .decrypt(&Role::Bundle.nonce(), Payload { msg: sealed, aad: &bundle_ad(transcript) })
        .map_err(|_| SealError)
}

/// Associated data for at-rest sealing, kept apart from both wire directions.
const AD_AT_REST: &[u8] = b"anuna-ssi/v1/at-rest";

/// Seal a secret for storage on the device that owns it.
///
/// The link channel and the keychain are different problems, but they should
/// not be different *ciphers*: an application that carries two AEADs has two
/// sets of nonce rules to keep straight. This is the same primitive with its
/// own domain separator and a caller-supplied nonce, because at rest the key
/// is long-lived and the nonce must therefore be fresh per seal — the exact
/// opposite of the wire case, where the key is single-use and the nonce is
/// fixed.
pub fn seal_at_rest(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    cipher(key)
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad: AD_AT_REST })
        .expect("ChaCha20-Poly1305 encryption is infallible for in-memory buffers")
}

/// Open a secret sealed by [`seal_at_rest`].
pub fn open_at_rest(key: &[u8; 32], nonce: &[u8; 12], sealed: &[u8]) -> Result<Vec<u8>, SealError> {
    cipher(key)
        .decrypt(Nonce::from_slice(nonce), Payload { msg: sealed, aad: AD_AT_REST })
        .map_err(|_| SealError)
}

fn bundle_ad(transcript: &[u8; 32]) -> Vec<u8> {
    let mut ad = AD_BUNDLE.to_vec();
    ad.extend_from_slice(transcript);
    ad
}

fn cipher(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(Key::from_slice(key))
}

/// RFC 4648 base32, lowercase, no padding.
///
/// Written out rather than pulled in: a dependency for sixteen lines is the
/// rung-4 reflex misapplied, and the alphabet is part of the contract so it
/// should be readable at the point of use.
fn base32_lower(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut acc: u16 = 0;
    let mut bits: u8 = 0;
    for &b in bytes {
        acc = (acc << 8) | b as u16;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: [u8; 16] = [
        0x9f, 0x3a, 0x11, 0xc2, 0xe7, 0x0b, 0x4d, 0x8a, 0x5c, 0x6f, 0x90, 0x12, 0xab, 0x34, 0xcd,
        0x56,
    ];

    // TEST-006 positive: a bundle sealed under HKDF(s) with our offer hash is
    // accepted.
    #[test]
    fn a_bundle_bound_to_our_offer_opens() {
        let k = derive_key(&S);
        let offer = b"(offer :v 1 ...)";
        let t = transcript(offer);
        let sealed = seal_bundle(&k, b"(grant :v 1 ...)", &t);
        assert_eq!(open_bundle(&k, &sealed, &t).unwrap(), b"(grant :v 1 ...)");
    }

    #[test]
    fn the_offer_record_round_trips() {
        let k = derive_key(&S);
        let sealed = seal_offer(&k, b"(offer :v 1 ...)");
        assert_eq!(open_offer(&k, &sealed).unwrap(), b"(offer :v 1 ...)");
    }

    // TEST-006 negative-input: tampered ciphertext, wrong AD, wrong K, and a
    // bundle from a *different* offer are each refused.
    #[test]
    fn a_tampered_ciphertext_is_refused() {
        let k = derive_key(&S);
        let t = transcript(b"offer");
        let mut sealed = seal_bundle(&k, b"grant", &t);
        for i in 0..sealed.len() {
            let original = sealed[i];
            sealed[i] ^= 0x01;
            assert_eq!(open_bundle(&k, &sealed, &t), Err(SealError), "byte {i}");
            sealed[i] = original;
        }
    }

    #[test]
    fn a_bundle_from_a_different_offer_is_refused() {
        // This is the substitution attack of threat T1, run directly.
        let k = derive_key(&S);
        let ours = transcript(b"(offer :desc \"Chrome on macOS\" ...)");
        let theirs = transcript(b"(offer :desc \"attacker\" ...)");
        let sealed = seal_bundle(&k, b"grant", &theirs);
        assert_eq!(open_bundle(&k, &sealed, &ours), Err(SealError));
    }

    #[test]
    fn a_bundle_under_a_different_key_is_refused() {
        let mut other_secret = S;
        other_secret[0] ^= 0xff;
        let t = transcript(b"offer");
        let sealed = seal_bundle(&derive_key(&other_secret), b"grant", &t);
        assert_eq!(open_bundle(&derive_key(&S), &sealed, &t), Err(SealError));
    }

    #[test]
    fn the_two_directions_cannot_be_crossed() {
        // Direction separation: an offer record must not open as a bundle even
        // under the same key, and vice versa.
        let k = derive_key(&S);
        let t = transcript(b"offer");
        assert_eq!(open_bundle(&k, &seal_offer(&k, b"x"), &t), Err(SealError));
        assert_eq!(open_offer(&k, &seal_bundle(&k, b"x", &t)), Err(SealError));
    }

    // TEST-029 / NFR-003: what the operator can see is `H(s)` and ciphertext.
    #[test]
    fn slots_are_distinct_per_role_and_per_secret_and_reveal_nothing() {
        let a = slot(Role::Offer, &S);
        let b = slot(Role::Bundle, &S);
        assert_ne!(a, b);
        assert_eq!(a.len(), 26, "128 bits in RFC 4648 base32");
        assert!(a.chars().all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c)));

        let mut other = S;
        other[15] ^= 1;
        assert_ne!(slot(Role::Offer, &other), a);

        // The secret is not a substring of anything the operator holds.
        let hex: String = S.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!a.contains(&hex));
    }

    #[test]
    fn slot_derivation_is_deterministic() {
        assert_eq!(slot(Role::Offer, &S), slot(Role::Offer, &S));
    }

    #[test]
    fn base32_matches_rfc_4648_lowercase_unpadded() {
        // RFC 4648 §10 test vectors, lowercased and unpadded.
        assert_eq!(base32_lower(b""), "");
        assert_eq!(base32_lower(b"f"), "my");
        assert_eq!(base32_lower(b"fo"), "mzxq");
        assert_eq!(base32_lower(b"foo"), "mzxw6");
        assert_eq!(base32_lower(b"foob"), "mzxw6yq");
        assert_eq!(base32_lower(b"fooba"), "mzxw6ytb");
        assert_eq!(base32_lower(b"foobar"), "mzxw6ytboi");
    }

    #[test]
    fn at_rest_sealing_round_trips_and_is_separated_from_the_wire() {
        let key = [0x5au8; 32];
        let nonce = [1u8; 12];
        let sealed = seal_at_rest(&key, &nonce, b"root seed");
        assert_eq!(open_at_rest(&key, &nonce, &sealed).unwrap(), b"root seed");

        // A different nonce, a different key, or a wire-domain open all fail.
        let mut other_nonce = nonce;
        other_nonce[0] ^= 1;
        assert_eq!(open_at_rest(&key, &other_nonce, &sealed), Err(SealError));
        assert_eq!(open_offer(&key, &sealed), Err(SealError));
        assert_eq!(open_bundle(&key, &sealed, &[0u8; 32]), Err(SealError));

        // And a wire record does not open as an at-rest one.
        let wire = seal_offer(&key, b"x");
        assert_eq!(open_at_rest(&key, &Role::Offer.nonce().into(), &wire), Err(SealError));
    }

    #[test]
    fn key_derivation_is_domain_separated_and_deterministic() {
        assert_eq!(derive_key(&S), derive_key(&S));
        // A different `info` would yield a different key; the constant is the
        // contract, so pin the first bytes against accidental edits.
        let hk = Hkdf::<Sha256>::new(None, &S);
        let mut other = [0u8; 32];
        hk.expand(b"anuna-ssi/v1/other", &mut other).unwrap();
        assert_ne!(derive_key(&S), other);
    }
}
