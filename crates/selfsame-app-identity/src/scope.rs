//! The opaque account scope — `CON-211`, `REQ-216`, `REQ-217`.
//!
//! An `accountScopeId` selects one account child below an application node. It
//! is the second of the two KDF context values in `CON-202`, and it is the only
//! thing that distinguishes two accounts a person holds in the same application.
//!
//! # What it is not
//!
//! `REQ-217` spends most of its length on prohibitions, and they are the point:
//!
//! - it is **not entropy.** It is "sensitive correlation metadata but is not a
//!   password or source of cryptographic entropy". An implementation that
//!   treated it as a secret would be relying on the application to keep it, and
//!   the application is exactly who supplies it.
//! - it is **not PII, and not derived from any.** Not an email, user name,
//!   display name, phone number, or sequential database identifier. A scope
//!   derived from an email would make the home DID a deterministic function of
//!   that email, and `NFR-201` unlinkability would be gone for anyone who could
//!   guess it.
//! - it is **never public.** It appears in no DID, DID Document, `acct:` URI,
//!   VC, JWS header, WebFinger response, provider hint, status entry, log, or
//!   analytics event. It reaches this crate through an in-process boundary and
//!   leaves it only as a KDF input.
//! - it is **never guessed.** When neither the authenticated account record nor
//!   a protected backup can restore it, the answer is
//!   [`ScopeError::Unavailable`] and not a fresh identity. Silently allocating a
//!   replacement would hand the person a new account wearing the old one's name.
//!
//! # The grammar, and why the re-encode check is separate from it
//!
//! `CON-211` declares the canonical form twice over, from both ends:
//!
//! ```abnf
//! b64url-char  = ALPHA / DIGIT / "-" / "_"
//! b64url-final = %x41 / %x45 / %x49 / %x4D / %x51 / %x55 / %x59
//!              / %x63 / %x67 / %x6B / %x6F / %x73 / %x77
//!              / %x30 / %x34 / %x38
//! account-scope-id = 42b64url-char b64url-final
//! ```
//!
//! and then as four parser steps ending in *"re-encode those bytes without
//! padding and require byte-for-byte equality with the input"*.
//!
//! These are the same constraint approached differently, and both are
//! implemented because both are declared. 43 base64url characters carry 258
//! bits while 32 octets need 256, so the final character has two spare bits: the
//! sixteen `b64url-final` values are exactly those whose index is divisible by
//! four, and the re-encode check is what catches the other forty-eight. Without
//! either, one account would have four spellings, and anything that compares
//! scopes as text — a database key, a cache entry — would see four accounts.

use crate::codec::{self, CodecError};

/// Octets of CSPRNG output an application allocates per account (`CON-211`).
pub const SCOPE_OCTETS: usize = 32;

/// Length of the canonical textual form.
pub const SCOPE_CHARS: usize = 43;

/// The sixteen final characters whose base64 index is divisible by four, so
/// that the two pad bits of a 32-octet value are zero (`CON-211` `b64url-final`).
const FINAL_CHARS: &[u8; 16] = b"AEIMQUYcgkosw048";

/// Why an account scope was refused.
///
/// The variants track `CON-211`'s parser steps one for one so that the
/// `CON-226` corpus can name which check fired.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ScopeError {
    /// Step 1: the text is not exactly 43 characters.
    #[error("account scope is not 43 characters")]
    WrongLength,
    /// Step 1: the text contains `=`, whitespace, non-ASCII, or a character
    /// outside the URL- and filename-safe alphabet.
    #[error("account scope contains a character outside the alphabet")]
    BadAlphabet,
    /// The final character's pad bits are non-zero, so this is a second
    /// spelling of some other scope's octets.
    #[error("account scope is not canonical")]
    NotCanonical,
    /// Steps 2–3: the text does not decode to exactly 32 octets.
    #[error("account scope does not decode to 32 octets")]
    WrongDecodedLength,
    /// `REQ-217`: neither the authenticated account record nor a protected
    /// backup could restore the exact scope.
    ///
    /// This is a terminal outcome, not a prompt. The SDK does not guess a
    /// scope, ask the person to enter one, or create a replacement identity.
    #[error("account scope unavailable")]
    Unavailable,
}

/// A recognised, canonical account scope.
///
/// Constructing one is the only way to reach [`crate::hierarchy::account_node`],
/// so `CON-202`'s precondition — *"after validating
/// `canonical_account_scope_id` with `CON-211`"* — is carried by the type rather
/// than by a comment (LangSec Principle 7).
#[derive(Clone, PartialEq, Eq)]
pub struct AccountScopeId {
    text: String,
    octets: [u8; SCOPE_OCTETS],
}

impl AccountScopeId {
    /// Recognise the canonical textual form.
    pub fn parse(text: &str) -> Result<Self, ScopeError> {
        if text.len() != SCOPE_CHARS {
            return Err(ScopeError::WrongLength);
        }
        let bytes = text.as_bytes();
        if !bytes.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_') {
            return Err(ScopeError::BadAlphabet);
        }
        // The ABNF's restricted final character. Checked before decoding so the
        // grammar is enforced as a grammar, not inferred from the codec.
        if !FINAL_CHARS.contains(&bytes[SCOPE_CHARS - 1]) {
            return Err(ScopeError::NotCanonical);
        }
        let octets = codec::decode_b64url_32(text).map_err(|e| match e {
            CodecError::WrongLength => ScopeError::WrongLength,
            CodecError::BadAlphabet => ScopeError::BadAlphabet,
            CodecError::WrongDecodedLength => ScopeError::WrongDecodedLength,
            CodecError::NotCanonical => ScopeError::NotCanonical,
        })?;
        Ok(Self { text: text.to_string(), octets })
    }

    /// Encode 32 octets an application drew from its CSPRNG.
    ///
    /// The core owns no RNG: the application allocates the value and commits it
    /// to the account record *before* requesting derivation, so that concurrent
    /// first-use requests resolve atomically to one committed scope.
    pub fn from_octets(octets: [u8; SCOPE_OCTETS]) -> Self {
        Self { text: codec::b64url(&octets), octets }
    }

    /// The canonical textual form, for storage in the account record.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The decoded octets.
    pub fn octets(&self) -> &[u8; SCOPE_OCTETS] {
        &self.octets
    }
}

/// Deliberately opaque, so a scope cannot reach a log line through `{:?}`.
///
/// `REQ-217` forbids the raw or encoded scope appearing in "a log, analytics
/// event, or other public protocol artifact". A derived `Debug` would make the
/// most casual possible mistake — adding `?` to a tracing macro — sufficient to
/// breach that, so the impl is written rather than derived.
impl core::fmt::Debug for AccountScopeId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AccountScopeId(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical() -> String {
        codec::b64url(&[0x11u8; SCOPE_OCTETS])
    }

    // TEST-223 positive.
    #[test]
    fn accepts_a_canonical_forty_three_character_encoding_of_thirty_two_octets() {
        let text = canonical();
        assert_eq!(text.len(), SCOPE_CHARS);
        let scope = AccountScopeId::parse(&text).unwrap();
        assert_eq!(scope.as_str(), text);
        assert_eq!(scope.octets(), &[0x11u8; SCOPE_OCTETS]);
    }

    #[test]
    fn from_octets_and_parse_agree() {
        let octets = [0x5Au8; SCOPE_OCTETS];
        let built = AccountScopeId::from_octets(octets);
        assert_eq!(AccountScopeId::parse(built.as_str()).unwrap(), built);
    }

    // TEST-223 negative-input: wrong length, padding, whitespace, non-ASCII,
    // invalid alphabet, non-canonical pad bits, decode/re-encode mismatch.
    #[test]
    fn rejects_wrong_lengths() {
        let text = canonical();
        assert_eq!(AccountScopeId::parse(&text[..42]), Err(ScopeError::WrongLength));
        assert_eq!(AccountScopeId::parse(&format!("{text}A")), Err(ScopeError::WrongLength));
        assert_eq!(AccountScopeId::parse(""), Err(ScopeError::WrongLength));
    }

    #[test]
    fn rejects_padding_and_whitespace() {
        let text = canonical();
        // A padded 44-character form fails on length before the alphabet.
        assert_eq!(AccountScopeId::parse(&format!("{text}=")), Err(ScopeError::WrongLength));
        assert_eq!(
            AccountScopeId::parse(&format!("{} ", &text[..42])),
            Err(ScopeError::BadAlphabet)
        );
        assert_eq!(
            AccountScopeId::parse(&format!("{}\n", &text[..42])),
            Err(ScopeError::BadAlphabet)
        );
    }

    #[test]
    fn rejects_non_ascii_and_the_standard_base64_alphabet() {
        let text = canonical();
        // `é` is two octets, so the byte length lands elsewhere; either
        // rejection is correct, and neither yields a scope.
        assert!(AccountScopeId::parse(&format!("{}é", &text[..42])).is_err());
        assert_eq!(
            AccountScopeId::parse(&format!("+{}", &text[1..])),
            Err(ScopeError::BadAlphabet)
        );
        assert_eq!(
            AccountScopeId::parse(&format!("/{}", &text[1..])),
            Err(ScopeError::BadAlphabet)
        );
    }

    #[test]
    fn rejects_every_final_character_whose_pad_bits_are_not_zero() {
        // The concrete hazard: 48 of the 64 alphabet characters decode to the
        // same 32 octets as one of the 16 canonical finals. Each is a second
        // spelling of a scope that already exists.
        let text = canonical();
        let head = &text[..42];
        let mut rejected = 0;
        for c in
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".chars()
        {
            let candidate = format!("{head}{c}");
            if FINAL_CHARS.contains(&(c as u8)) {
                assert!(AccountScopeId::parse(&candidate).is_ok(), "`{c}` is a canonical final");
            } else {
                assert_eq!(
                    AccountScopeId::parse(&candidate),
                    Err(ScopeError::NotCanonical),
                    "`{c}` has non-zero pad bits and must not be accepted"
                );
                rejected += 1;
            }
        }
        assert_eq!(rejected, 64 - FINAL_CHARS.len());
    }

    #[test]
    fn the_abnf_final_set_is_exactly_the_indices_divisible_by_four() {
        // Cross-checks the constant against the reason it holds, so that a typo
        // in the transcription from CON-211 fails here rather than silently
        // narrowing or widening the language.
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let expected: Vec<u8> =
            ALPHABET.iter().enumerate().filter(|(i, _)| i % 4 == 0).map(|(_, c)| *c).collect();
        assert_eq!(expected, FINAL_CHARS.to_vec());
    }

    // REQ-217 prohibited-action: the scope must not reach a log through Debug.
    #[test]
    fn debug_does_not_disclose_the_scope() {
        let scope = AccountScopeId::from_octets([0x11u8; SCOPE_OCTETS]);
        let rendered = format!("{scope:?}");
        assert!(!rendered.contains(scope.as_str()), "Debug leaked the scope: {rendered}");
        assert!(rendered.contains("redacted"));
    }
}
