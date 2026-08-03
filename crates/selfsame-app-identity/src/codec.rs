//! Canonical binary-to-text codecs — `CON-203` and `CON-211`.
//!
//! Two alphabets appear in SPEC-004, and both are required to be *canonical*
//! rather than merely decodable:
//!
//! - **base64url without padding** carries every 32-octet value in the profile:
//!   the account scope (`CON-211`), the grant token (`CON-205`), the request and
//!   ceremony identifiers (`CON-214`), every SHA-256 digest, and the `x` member
//!   of an Ed25519 JWK.
//! - **base32, lower-case, unpadded** carries exactly one value: the `ss-`
//!   localpart of the stable account alias (`CON-203`).
//!
//! # Why decoding is not enough
//!
//! `CON-211` spells its rule out in four steps, the last of which is *"re-encode
//! those bytes without padding and require byte-for-byte equality with the
//! input"*. That step is not redundant. Base64 has spare bits in its final
//! character: a 32-octet value occupies 43 characters of which the last carries
//! only 2 significant bits, so `…A`, `…B`, `…C` and `…D` all decode to the same
//! 32 octets. Without the re-encode check, one account scope would have four
//! spellings, and a system that compares scopes as strings anywhere — a database
//! key, a cache entry, a log line — would treat one account as four.
//!
//! `CON-211`'s ABNF closes the same hole from the other side by restricting the
//! final character to the sixteen values whose pad bits are zero. Both are
//! implemented, because the ABNF is the declared grammar and the re-encode is
//! the declared check, and an implementation that dropped either would be
//! conforming to half a contract.

/// Why a canonical encoding was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    /// The text is not the length the contract fixes for this value.
    #[error("encoded value has the wrong length")]
    WrongLength,
    /// The text contains a character outside the alphabet, padding, or
    /// whitespace.
    #[error("encoded value contains a character outside the alphabet")]
    BadAlphabet,
    /// The text decodes, but to the wrong number of octets.
    #[error("encoded value decodes to the wrong number of octets")]
    WrongDecodedLength,
    /// The text decodes but re-encodes differently: its pad bits are non-zero.
    #[error("encoded value is not canonical")]
    NotCanonical,
}

/// Encode octets as base64url with no padding.
pub fn b64url(bytes: &[u8]) -> String {
    use base64ct::Encoding as _;
    base64ct::Base64UrlUnpadded::encode_string(bytes)
}

/// Number of unpadded base64url characters that encode `n` octets.
pub const fn b64url_len(n: usize) -> usize {
    n.div_ceil(3) * 4 - (3 - n % 3) % 3
}

/// Recognise a canonical unpadded base64url value of an exact octet length.
///
/// Applies `CON-211`'s four steps in order: length and alphabet, decode, decoded
/// length, and re-encode equality.
pub fn decode_b64url_exact(text: &str, expected_octets: usize) -> Result<Vec<u8>, CodecError> {
    if text.len() != b64url_len(expected_octets) {
        return Err(CodecError::WrongLength);
    }
    if !text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        // Catches `=`, whitespace, and every non-ASCII octet in one predicate,
        // because none of them is in the URL- and filename-safe alphabet.
        return Err(CodecError::BadAlphabet);
    }
    use base64ct::Encoding as _;
    let decoded =
        base64ct::Base64UrlUnpadded::decode_vec(text).map_err(|_| CodecError::NotCanonical)?;
    if decoded.len() != expected_octets {
        return Err(CodecError::WrongDecodedLength);
    }
    if b64url(&decoded) != text {
        return Err(CodecError::NotCanonical);
    }
    Ok(decoded)
}

/// Recognise a canonical unpadded base64url encoding of exactly 32 octets.
///
/// The shape of every random identifier and every SHA-256 digest in SPEC-004.
pub fn decode_b64url_32(text: &str) -> Result<[u8; 32], CodecError> {
    let v = decode_b64url_exact(text, 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

/// The `CON-203` base32 alphabet: RFC 4648 base32, lower-cased.
const BASE32_LOWER: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Encode octets as RFC 4648 base32 with a lower-case alphabet and no padding.
///
/// A SHA-256 digest produces 52 characters, so a complete `CON-203` localpart is
/// `"ss-"` plus 52, or 55 ASCII characters.
pub fn base32_lower_nopad(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut accumulator: u16 = 0;
    let mut bits: u8 = 0;
    for &byte in bytes {
        accumulator = (accumulator << 8) | u16::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((accumulator >> bits) & 0x1F) as usize;
            out.push(BASE32_LOWER[index] as char);
        }
    }
    if bits > 0 {
        // The remaining bits are left-aligned and zero-padded on the right,
        // which is what "no padding" means for the character, not for the file.
        let index = ((accumulator << (5 - bits)) & 0x1F) as usize;
        out.push(BASE32_LOWER[index] as char);
    }
    out
}

/// The Bitcoin base58 alphabet, as `did:key` uses it via multibase `z`.
const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode octets as base58btc.
///
/// Used by exactly one value in SPEC-004: the `did:key` device identifier of
/// `CON-205`'s `credentialSubject.id`. The alphabet omits `0`, `O`, `I`, and
/// `l` so that a person transcribing one cannot produce a second spelling.
pub fn base58btc(bytes: &[u8]) -> String {
    // Leading zero octets carry no magnitude, so they are encoded positionally
    // as `1` rather than being absorbed by the base conversion.
    let leading_zeros = bytes.iter().take_while(|b| **b == 0).count();
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 138 / 100 + 1);
    for &byte in bytes {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut() {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(leading_zeros + digits.len());
    out.extend(core::iter::repeat_n('1', leading_zeros));
    out.extend(digits.iter().rev().map(|d| BASE58[*d as usize] as char));
    out
}

/// Decode a base58btc string.
pub fn decode_base58btc(text: &str) -> Result<Vec<u8>, CodecError> {
    if text.is_empty() {
        return Err(CodecError::WrongLength);
    }
    let leading_ones = text.bytes().take_while(|b| *b == b'1').count();
    let mut bytes: Vec<u8> = Vec::with_capacity(text.len());
    for c in text.bytes() {
        let value = BASE58.iter().position(|a| *a == c).ok_or(CodecError::BadAlphabet)? as u32;
        let mut carry = value;
        for byte in bytes.iter_mut() {
            carry += u32::from(*byte) * 58;
            *byte = (carry & 0xFF) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xFF) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; leading_ones];
    out.extend(bytes.iter().rev());
    // Base58 has no padding and no length field, so canonicality is decided by
    // re-encoding — the same discipline CON-211 applies to base64url.
    if base58btc(&out) != text {
        return Err(CodecError::NotCanonical);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn base58_matches_the_published_vectors() {
        // The vectors every base58btc implementation is checked against.
        for (input, expected) in [
            (vec![], ""),
            (vec![0x00], "1"),
            (vec![0x00, 0x00], "11"),
            (b"hello world".to_vec(), "StV1DL6CwTryKyV"),
            (vec![0x61], "2g"),
            (vec![0x62, 0x62, 0x62], "a3gV"),
            (vec![0x63, 0x63, 0x63], "aPEr"),
        ] {
            assert_eq!(base58btc(&input), expected, "{input:?}");
        }
    }

    #[test]
    fn base58_round_trips_and_preserves_leading_zeros() {
        // The empty string is deliberately not in this list: `base58btc(&[])`
        // is `""`, and an empty `did:key` suffix is a malformed identifier
        // rather than a zero-length key, so the decoder refuses it outright.
        for bytes in [vec![0u8; 5], vec![0, 0, 1, 2, 3], (0u8..64).collect::<Vec<_>>()] {
            assert_eq!(decode_base58btc(&base58btc(&bytes)).unwrap(), bytes, "{bytes:?}");
        }
    }

    #[test]
    fn base58_rejects_the_omitted_characters_and_non_canonical_input() {
        for c in ['0', 'O', 'I', 'l'] {
            assert_eq!(decode_base58btc(&format!("2g{c}")), Err(CodecError::BadAlphabet), "{c}");
        }
        assert_eq!(decode_base58btc(""), Err(CodecError::WrongLength));
    }

    #[test]
    fn base32_matches_the_rfc_4648_vectors_lower_cased() {
        // RFC 4648 §10, with the alphabet lower-cased and the padding removed.
        for (input, expected) in [
            ("", ""),
            ("f", "my"),
            ("fo", "mzxq"),
            ("foo", "mzxw6"),
            ("foob", "mzxw6yq"),
            ("fooba", "mzxw6ytb"),
            ("foobar", "mzxw6ytboi"),
        ] {
            assert_eq!(base32_lower_nopad(input.as_bytes()), expected, "{input:?}");
        }
    }

    #[test]
    fn a_sha256_digest_base32s_to_the_fifty_two_characters_con_203_expects() {
        assert_eq!(base32_lower_nopad(&[0u8; 32]).len(), 52);
        assert_eq!(base32_lower_nopad(&[0xFFu8; 32]).len(), 52);
    }

    #[test]
    fn b64url_len_matches_the_encoder() {
        for n in 0..=64usize {
            let bytes = vec![0xA5u8; n];
            assert_eq!(b64url(&bytes).len(), b64url_len(n), "n = {n}");
        }
        // The two lengths CON-205 and CON-211 both name.
        assert_eq!(b64url_len(32), 43);
        assert_eq!(b64url_len(16), 22);
    }

    #[test]
    fn accepts_a_canonical_thirty_two_octet_value() {
        let bytes = [7u8; 32];
        let text = b64url(&bytes);
        assert_eq!(decode_b64url_32(&text).unwrap(), bytes);
    }

    #[test]
    fn rejects_padding_whitespace_and_non_ascii() {
        let base = b64url(&[7u8; 32]);
        let mut padded = base.clone();
        padded.push('=');
        assert_eq!(decode_b64url_32(&padded), Err(CodecError::WrongLength));

        let spaced = format!("{} ", &base[..42]);
        assert_eq!(decode_b64url_32(&spaced), Err(CodecError::BadAlphabet));

        let unicode = format!("{}é", &base[..42]);
        assert_eq!(decode_b64url_32(&unicode), Err(CodecError::WrongLength));
    }

    #[test]
    fn rejects_every_length_other_than_the_declared_one() {
        let base = b64url(&[7u8; 32]);
        assert_eq!(decode_b64url_32(&base[..42]), Err(CodecError::WrongLength));
        assert_eq!(decode_b64url_32(&format!("{base}A")), Err(CodecError::WrongLength));
        assert_eq!(decode_b64url_32(""), Err(CodecError::WrongLength));
    }

    #[test]
    fn rejects_the_standard_base64_alphabet() {
        // `+` and `/` decode under the standard alphabet and would silently
        // admit a second spelling of the same octets.
        let mut text: Vec<char> = b64url(&[0xFBu8; 32]).chars().collect();
        text[0] = '+';
        assert_eq!(
            decode_b64url_32(&text.iter().collect::<String>()),
            Err(CodecError::BadAlphabet)
        );
    }

    #[test]
    fn rejects_non_canonical_pad_bits() {
        // The CON-211 hazard, made concrete: a 32-octet value's final character
        // carries two significant bits, so four characters decode alike. Only
        // the one the encoder produces is the account scope.
        let bytes = [0u8; 32];
        let canonical = b64url(&bytes);
        assert!(canonical.ends_with('A'), "expected the zero value to end in `A`");
        for variant in ['B', 'C', 'D'] {
            let mutated = format!("{}{variant}", &canonical[..42]);
            assert_eq!(
                decode_b64url_32(&mutated),
                Err(CodecError::NotCanonical),
                "`{mutated}` decodes to the same octets and must not be accepted"
            );
        }
    }

    #[test]
    fn round_trips_every_octet_length_a_contract_names() {
        for n in [16usize, 32, 64] {
            let bytes: Vec<u8> = (0..n).map(|i| (i * 7) as u8).collect();
            assert_eq!(decode_b64url_exact(&b64url(&bytes), n).unwrap(), bytes);
        }
    }
}
