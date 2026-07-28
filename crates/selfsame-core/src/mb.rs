//! One canonical binary spelling — SPEC-001 REQ-027.
//!
//! CBCL atoms are `Symbol | Str | Num | Bool | Keyword` with **no byte-string
//! type** (SPEC-001 ADR-013), so public keys, signatures, and `did:crdt`
//! deltas all travel as text. That makes the binary encoding a
//! signing-correctness concern rather than a formatting choice: a decoder that
//! accepts two spellings of the same bytes reintroduces malleability
//! *underneath* a canonical envelope, which is worse than having no canonical
//! form at all, because the canonicality is then believed.
//!
//! The encoding is multibase `u` — base64url, no padding — which is the
//! encoding `did:crdt` already requires (`validate.rs:224`), so the system
//! carries one binary spelling rather than two.
//!
//! # What a conforming decoder rejects
//!
//! | Input | Why it is rejected |
//! |---|---|
//! | `AQAB` | no `u` multibase prefix |
//! | `uAQA=` | padding character |
//! | `uA+/B` | standard-alphabet `+` / `/` |
//! | `uAQAC` (non-zero unused bits) | two spellings of one byte string |
//! | `uAQAB` followed by whitespace | not in the alphabet |
//!
//! The trailing-bits rule is the one that actually closes malleability: in a
//! final quantum of 2 characters the low 4 bits of the second character are
//! unused, and in a quantum of 3 the low 2 bits of the third are. Any encoder
//! sets them to zero; a lenient decoder that ignores them accepts up to 16
//! distinct strings for one byte string.

/// The multibase prefix character for base64url-no-pad (multibase table `u`).
pub const MB_PREFIX: char = 'u';

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Why a multibase string was refused.
///
/// The variants are distinct so a test can assert *which* rule fired; the
/// user-facing surface never shows them (SPEC-001 CON-001 error model).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MultibaseError {
    /// The string did not begin with the `u` multibase prefix.
    #[error("missing multibase 'u' prefix")]
    MissingPrefix,
    /// A character outside the base64url alphabet appeared (including `=`,
    /// `+`, `/`, and whitespace).
    #[error("character outside the base64url alphabet at byte {0}")]
    BadAlphabet(usize),
    /// The length is not reachable by any base64 encoding (a final quantum of
    /// exactly one character encodes no whole byte).
    #[error("truncated final quantum")]
    BadLength,
    /// The final quantum carried non-zero unused bits — a second spelling of
    /// the same bytes.
    #[error("non-zero unused bits in the final quantum")]
    NonCanonicalTail,
    /// The decoded value was not the length the caller required.
    #[error("expected {expected} bytes, decoded {actual}")]
    WrongLength {
        /// Bytes the caller required.
        expected: usize,
        /// Bytes actually decoded.
        actual: usize,
    },
}

/// Encode bytes as multibase `u` base64url without padding.
///
/// This is a total function: every byte string has exactly one spelling.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(1 + bytes.len().div_ceil(3) * 4);
    out.push(MB_PREFIX);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        let emit = chunk.len() + 1; // 1 byte → 2 chars, 2 → 3, 3 → 4
        for i in 0..emit {
            let sextet = (n >> (18 - 6 * i)) & 0x3f;
            out.push(ALPHABET[sextet as usize] as char);
        }
    }
    out
}

/// Decode a multibase `u` base64url-no-pad string, rejecting every
/// non-canonical spelling (SPEC-001 REQ-027).
///
/// The decoder is written out rather than delegated because the obligation is
/// *rejection*, not decoding: a general-purpose base64 decoder that silently
/// tolerates padding or non-zero tail bits would satisfy the happy path and
/// fail the requirement. The loop below is ~20 lines and every rejection rule
/// is visible in it.
pub fn decode(s: &str) -> Result<Vec<u8>, MultibaseError> {
    let body = s.strip_prefix(MB_PREFIX).ok_or(MultibaseError::MissingPrefix)?;
    let bytes = body.as_bytes();

    // Alphabet first, then length. Checking in this order means a `=`, a `+`,
    // or a space is always reported as what it is, rather than as whichever
    // rule happened to fire first for that particular length — the rejection
    // reasons stay independent of each other, which is what makes them
    // individually testable.
    if let Some(i) = bytes.iter().position(|&c| sextet(c).is_none()) {
        return Err(MultibaseError::BadAlphabet(i));
    }

    // A final quantum of exactly one character encodes no whole byte, so no
    // encoder can produce `len % 4 == 1`.
    if bytes.len() % 4 == 1 {
        return Err(MultibaseError::BadLength);
    }

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut acc: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            acc |= (sextet(c).expect("alphabet was validated above") as u32) << (18 - 6 * i);
        }
        // A short final chunk carries `chunk.len() - 1` whole bytes; the bits
        // below them are unused and MUST be zero, or the same bytes have a
        // second spelling.
        let whole = chunk.len() - 1;
        if chunk.len() < 4 && (acc & (0x00ff_ffff >> (whole * 8))) != 0 {
            return Err(MultibaseError::NonCanonicalTail);
        }
        for i in 0..whole {
            out.push(((acc >> (16 - 8 * i)) & 0xff) as u8);
        }
    }
    Ok(out)
}

/// Decode and require an exact byte length — the common case for a 32-byte
/// public key or a 64-byte signature.
pub fn decode_exact<const N: usize>(s: &str) -> Result<[u8; N], MultibaseError> {
    let v = decode(s)?;
    v.as_slice()
        .try_into()
        .map_err(|_| MultibaseError::WrongLength { expected: N, actual: v.len() })
}

fn sextet(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TEST-037 positive: canonical `u` base64url round-trips for keys,
    // signatures, and deltas.
    #[test]
    fn roundtrips_every_length_up_to_a_signature() {
        for len in 0..=64usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37)).collect();
            let encoded = encode(&bytes);
            assert!(encoded.starts_with('u'));
            assert_eq!(decode(&encoded).unwrap(), bytes, "length {len}");
        }
    }

    #[test]
    fn agrees_with_did_crdt_on_a_public_key() {
        // did:crdt encodes verification-method keys with base64ct's
        // Base64UrlUnpadded and a `u` prefix (validate.rs:224). One binary
        // spelling means our encoder must agree with theirs byte for byte.
        use base64ct::{Base64UrlUnpadded, Encoding as _};
        let key = [0x42u8; 32];
        let theirs = format!("u{}", Base64UrlUnpadded::encode_string(&key));
        assert_eq!(encode(&key), theirs);
    }

    // TEST-037 negative-input: every non-canonical spelling is refused.
    #[test]
    fn rejects_missing_prefix() {
        assert_eq!(decode("QUJD"), Err(MultibaseError::MissingPrefix));
    }

    #[test]
    fn rejects_padding() {
        assert_eq!(decode("uQQ=="), Err(MultibaseError::BadAlphabet(2)));
        assert_eq!(decode("uQUJD="), Err(MultibaseError::BadAlphabet(4)));
    }

    #[test]
    fn rejects_standard_alphabet() {
        assert_eq!(decode("uA+AB"), Err(MultibaseError::BadAlphabet(1)));
        assert_eq!(decode("uA/AB"), Err(MultibaseError::BadAlphabet(1)));
    }

    #[test]
    fn rejects_whitespace_and_control_characters() {
        assert_eq!(decode("uQU JD"), Err(MultibaseError::BadAlphabet(2)));
        assert_eq!(decode("uQUJD\n"), Err(MultibaseError::BadAlphabet(4)));
        assert_eq!(decode("uQU\u{0}D"), Err(MultibaseError::BadAlphabet(2)));
    }

    #[test]
    fn rejects_truncated_final_quantum() {
        assert_eq!(decode("uQUJDQ"), Err(MultibaseError::BadLength));
    }

    // TEST-037 negative-output — the requirement's whole point: **two distinct
    // encodings decoding to the same bytes must not both be accepted.**
    //
    // In a two-character quantum the second character's low 4 bits are unused,
    // so each byte value has exactly one canonical tail and fifteen
    // near-misses. The test enumerates all 64 tails and asserts that the
    // accepted ones are (a) exactly four and (b) pairwise distinct in what they
    // decode to — i.e. the decode map restricted to accepted inputs is
    // injective.
    #[test]
    fn two_spellings_of_one_byte_string_cannot_both_be_accepted() {
        use std::collections::HashMap;
        let mut accepted: HashMap<Vec<u8>, String> = HashMap::new();
        for tail in ALPHABET.iter().map(|&c| c as char) {
            let candidate = format!("uA{tail}");
            match decode(&candidate) {
                Ok(bytes) => {
                    if let Some(previous) = accepted.insert(bytes.clone(), candidate.clone()) {
                        panic!("{previous} and {candidate} both decode to {bytes:?}");
                    }
                }
                Err(e) => assert_eq!(e, MultibaseError::NonCanonicalTail, "{candidate}"),
            }
        }
        // Sextets 0, 16, 32, 48 are the four with zero unused bits.
        assert_eq!(accepted.len(), 4);
        assert_eq!(decode("uAA").unwrap(), vec![0x00]);
        assert_eq!(decode("uAQ").unwrap(), vec![0x01]);
        assert_eq!(decode("uAg").unwrap(), vec![0x02]);
        assert_eq!(decode("uAw").unwrap(), vec![0x03]);
    }

    #[test]
    fn rejects_non_zero_tail_in_a_three_character_quantum() {
        // In a three-character quantum the last character's low 2 bits are
        // unused. `B` (sextet 1) sets one of them; `E` (sextet 4) does not.
        assert_eq!(decode("uAAB"), Err(MultibaseError::NonCanonicalTail));
        assert_eq!(decode("uAAC"), Err(MultibaseError::NonCanonicalTail));
        assert_eq!(decode("uAAD"), Err(MultibaseError::NonCanonicalTail));
        assert_eq!(decode("uAAA").unwrap(), vec![0x00, 0x00]);
        assert_eq!(decode("uAAE").unwrap(), vec![0x00, 0x01]);
    }

    #[test]
    fn decode_exact_enforces_the_caller_s_length() {
        let key = [7u8; 32];
        assert_eq!(decode_exact::<32>(&encode(&key)).unwrap(), key);
        assert_eq!(
            decode_exact::<64>(&encode(&key)),
            Err(MultibaseError::WrongLength { expected: 64, actual: 32 })
        );
    }
}
