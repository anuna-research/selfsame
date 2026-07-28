//! Root-key derivation — SPEC-001 CON-007, REQ-001, REQ-002.
//!
//! ```text
//! ed25519_seed(i) = HKDF-SHA-512( ikm  = BIP39_seed(mnemonic, ""),
//!                                 salt = "",
//!                                 info = "anuna-ssi/v1/root-key/" ‖ u32be(i),
//!                                 L    = 32 )
//! ```
//!
//! `i` is the **persona index**, a `u32` encoded big-endian — raw bytes, not
//! decimal text, so there is no `"01"` vs `"1"` ambiguity to parse. This
//! version defines and uses `i = 0` only; the index exists so that ADR-012's
//! deferred HD personas do not require a derivation change *after* test
//! vectors ship. Gate condition B freezes this mapping the moment vectors are
//! published, and changing it afterwards re-derives every existing identity —
//! which is precisely why the index is here now, costing nothing, rather than
//! later, costing every user their DID.
//!
//! # The one deliberate exception to NFR-002
//!
//! The mnemonic is displayed for the user to transcribe. That is the recovery
//! mechanism and is exempt by construction. It is the *only* exemption: the
//! mnemonic is never written to device storage, a screenshot-enabled surface,
//! or a clipboard, and the derived seed never leaves the platform keychain.

use bip39::Language;
use zeroize::Zeroizing;

/// The BIP-39 mnemonic type, re-exported so a consumer does not need its own
/// pinned `bip39` dependency. Two versions of a wordlist in one process is two
/// answers to "is this phrase valid", which is the parser-differential shape
/// LangSec Principle 5 rules out.
pub use bip39::Mnemonic;

/// HKDF `info` prefix for the root key (CON-007).
const ROOT_INFO_PREFIX: &[u8] = b"anuna-ssi/v1/root-key/";

/// The persona index this version defines and uses (ADR-012).
pub const PERSONA_ZERO: u32 = 0;

/// Number of words in a generated recovery phrase (REQ-001).
pub const MNEMONIC_WORDS: usize = 12;

/// Number of words the user must re-enter before linking is unlocked (REQ-002).
pub const CONFIRMATION_WORDS: usize = 3;

/// Why a mnemonic or a confirmation was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeriveError {
    /// The phrase failed the BIP-39 checksum, used an unknown word, or was not
    /// twelve words. Rejected **before any derivation** (CON-007 error model).
    #[error("not a valid BIP-39 recovery phrase")]
    InvalidMnemonic,
    /// A confirmation answer named a word position outside the phrase.
    #[error("confirmation index out of range")]
    IndexOutOfRange,
}

/// A 32-byte Ed25519 seed, zeroised on drop.
pub type RootSeed = Zeroizing<[u8; 32]>;

/// Build a 12-word English recovery phrase from 128 bits of CSPRNG entropy.
///
/// The core owns no RNG; the shell draws the entropy and passes it in, which
/// is also what makes the mapping testable against published vectors.
pub fn mnemonic_from_entropy(entropy: &[u8; 16]) -> Mnemonic {
    Mnemonic::from_entropy_in(Language::English, entropy)
        .expect("128 bits is a valid BIP-39 entropy length")
}

/// Recognise a recovery phrase typed by a user restoring an identity.
///
/// Whitespace is normalised and case is folded because those are properties of
/// *transcription*, not of the phrase — but nothing else is repaired: a word
/// outside the wordlist or a failing checksum is refused outright.
pub fn parse_mnemonic(phrase: &str) -> Result<Mnemonic, DeriveError> {
    let normalised = phrase.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
    if normalised.split(' ').count() != MNEMONIC_WORDS {
        return Err(DeriveError::InvalidMnemonic);
    }
    Mnemonic::parse_in_normalized(Language::English, &normalised)
        .map_err(|_| DeriveError::InvalidMnemonic)
}

/// Derive the persona-indexed Ed25519 seed (CON-007).
///
/// No user-supplied passphrase is defined in this version, so the BIP-39
/// passphrase is the empty string. Adding one later would change every derived
/// identity, so it is a versioned change to this function and not a parameter.
pub fn root_seed(mnemonic: &Mnemonic, persona: u32) -> RootSeed {
    let bip39_seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
    let mut info = ROOT_INFO_PREFIX.to_vec();
    info.extend_from_slice(&persona.to_be_bytes());

    let hk = hkdf::Hkdf::<sha2::Sha512>::new(None, bip39_seed.as_ref());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(&info, okm.as_mut()).expect("32 bytes is a valid HKDF output length");
    okm
}

/// The Ed25519 signing key for a persona — the [`Root Key`].
///
/// [`Root Key`]: ../../../../anuna-ssi/specs/concepts/Root-Key.md
pub fn root_signing_key(mnemonic: &Mnemonic, persona: u32) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&root_seed(mnemonic, persona))
}

/// Check the REQ-002 backup confirmation.
///
/// The caller chose the positions at random and collected the user's answers;
/// this function decides whether the confirmation passes. Linking and revoking
/// stay locked until it does — an identity that cannot be recovered cannot be
/// revoked from, which makes HP-5 impossible.
///
/// Comparison is over the whole answer set: a caller cannot learn *which* word
/// was wrong, so the screen cannot degrade into a per-word oracle.
pub fn confirm_backup(mnemonic: &Mnemonic, answers: &[(usize, String)]) -> Result<bool, DeriveError> {
    if answers.len() != CONFIRMATION_WORDS {
        return Ok(false);
    }
    let words: Vec<&'static str> = mnemonic.words().collect();
    let mut all_correct = true;
    for (index, answer) in answers {
        let expected = words.get(*index).ok_or(DeriveError::IndexOutOfRange)?;
        // Non-short-circuiting so the number of comparisons does not depend on
        // where the first wrong word sits.
        all_correct &= answer.trim().eq_ignore_ascii_case(expected);
    }
    Ok(all_correct)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn phrase() -> Mnemonic {
        mnemonic_from_entropy(&[0u8; 16])
    }

    // TEST-001 positive: the same mnemonic and index yield the same seed.
    #[test]
    fn derivation_is_deterministic() {
        let m = phrase();
        assert_eq!(*root_seed(&m, 0), *root_seed(&m, 0));
    }

    // TEST-001 negative-output: two distinct indices MUST NOT yield the same
    // seed, and the big-endian encoding MUST NOT let `"01"` collide with `"1"`.
    #[test]
    fn distinct_personas_yield_independent_seeds() {
        let m = phrase();
        let mut seen = std::collections::HashSet::new();
        for i in 0..64u32 {
            assert!(seen.insert(*root_seed(&m, i)), "persona {i} collided");
        }
        // The decimal-text hazard the big-endian encoding closes: were `info`
        // built from decimal text, persona 1 and persona 01 would be one key.
        // With `u32be` there is no second spelling of an index at all.
        assert_eq!(1u32.to_be_bytes(), [0, 0, 0, 1]);
    }

    #[test]
    fn distinct_mnemonics_yield_distinct_seeds() {
        let a = mnemonic_from_entropy(&[0u8; 16]);
        let mut e = [0u8; 16];
        e[15] = 1;
        let b = mnemonic_from_entropy(&e);
        assert_ne!(*root_seed(&a, 0), *root_seed(&b, 0));
    }

    #[test]
    fn a_generated_phrase_has_twelve_words_and_round_trips() {
        let m = phrase();
        assert_eq!(m.words().count(), MNEMONIC_WORDS);
        let parsed = parse_mnemonic(&m.to_string()).unwrap();
        assert_eq!(*root_seed(&parsed, 0), *root_seed(&m, 0));
    }

    // TEST-001 negative-input: 11-word and bad-checksum mnemonics are rejected
    // before any derivation.
    #[test]
    fn short_and_bad_checksum_phrases_are_rejected() {
        let m = phrase();
        let words: Vec<&str> = m.words().collect();

        let eleven = words[..11].join(" ");
        assert_eq!(parse_mnemonic(&eleven), Err(DeriveError::InvalidMnemonic));

        let thirteen = format!("{} {}", m, words[0]);
        assert_eq!(parse_mnemonic(&thirteen), Err(DeriveError::InvalidMnemonic));

        // Swap the last word for another valid word: checksum fails.
        let mut bad = words.clone();
        bad[11] = if words[11] == "about" { "zoo" } else { "about" };
        assert_eq!(parse_mnemonic(&bad.join(" ")), Err(DeriveError::InvalidMnemonic));

        // A word outside the wordlist.
        let mut alien = words.clone();
        alien[3] = "verbena";
        assert_eq!(parse_mnemonic(&alien.join(" ")), Err(DeriveError::InvalidMnemonic));
    }

    #[test]
    fn transcription_variance_is_normalised_but_content_is_not_repaired() {
        let m = phrase();
        let messy = format!("  {}  ", m.to_string().to_uppercase().replace(' ', "   "));
        assert_eq!(*root_seed(&parse_mnemonic(&messy).unwrap(), 0), *root_seed(&m, 0));
    }

    // TEST-002 positive / negative-output.
    #[test]
    fn confirmation_passes_only_with_every_word_right() {
        let m = phrase();
        let words: Vec<&str> = m.words().collect();

        let right: Vec<(usize, String)> =
            vec![(3, words[3].into()), (6, words[6].into()), (10, words[10].into())];
        assert!(confirm_backup(&m, &right).unwrap());

        // Case and surrounding whitespace are transcription, not content.
        let sloppy: Vec<(usize, String)> = vec![
            (3, format!(" {} ", words[3].to_uppercase())),
            (6, words[6].into()),
            (10, words[10].into()),
        ];
        assert!(confirm_backup(&m, &sloppy).unwrap());

        let one_wrong: Vec<(usize, String)> =
            vec![(3, words[3].into()), (6, "wrong".into()), (10, words[10].into())];
        assert!(!confirm_backup(&m, &one_wrong).unwrap());

        let too_few: Vec<(usize, String)> = vec![(3, words[3].into())];
        assert!(!confirm_backup(&m, &too_few).unwrap());

        let out_of_range: Vec<(usize, String)> =
            vec![(3, words[3].into()), (6, words[6].into()), (99, words[0].into())];
        assert_eq!(confirm_backup(&m, &out_of_range), Err(DeriveError::IndexOutOfRange));
    }

    #[test]
    fn the_seed_is_domain_separated_from_a_bare_bip39_seed() {
        let m = phrase();
        let bip39 = m.to_seed_normalized("");
        assert_ne!(&bip39[..32], root_seed(&m, 0).as_ref());
    }
}
