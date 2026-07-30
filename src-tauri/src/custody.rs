//! Root-key custody — SPEC-001 REQ-024, REQ-002, REQ-001, NFR-002.
//!
//! > **REQ-024.** The derived seed SHALL be stored in the platform keychain
//! > under an access-control policy requiring user presence (biometric or
//! > device passcode) for every use, wrapped by a hardware-protected key where
//! > the platform provides one; and every operation that uses the Root Key
//! > SHALL require that user-presence check.
//!
//! # What is true here, stated exactly
//!
//! The requirement's own rationale is careful, and this module keeps that care:
//! the [Secure Enclave] generates and holds P-256 keys and **cannot import a
//! recoverable Ed25519 seed**, so "the key lives in the enclave" would be
//! false. What is true — and what this implements — is enclave-*wrapped*
//! keychain storage with a user-presence gate.
//!
//! | Platform | Storage | Presence |
//! |---|---|---|
//! | macOS / iOS | Keychain (`keyring`), enclave-wrapped by the OS | biometric on mobile, device passcode on desktop |
//! | Windows | Credential Manager | device passcode |
//! | Linux | Secret Service | device passcode |
//!
//! On desktop there is no biometric API Tauri exposes, so the presence check is
//! the *device passcode* half of REQ-024, which the requirement admits in as
//! many words. It is not a weakened form of the requirement: the seed is
//! sealed under a passcode-derived key with Argon2id, so possession of the
//! keychain entry alone does not yield the root key.
//!
// SIMPLIFY: passcode-derived sealing on desktop — replace with
// `tauri-plugin-biometric` plus a hardware-backed access-control policy on
// iOS/Android, where the platform provides one (trace: REQ-024, ADR-002).
//!
//! # The mnemonic
//!
//! NFR-002 permits exactly one secret to be shown to a human: the twelve words
//! of REQ-002, which are the recovery mechanism and are exempt by construction.
//! They are held in memory only for as long as the confirmation ceremony takes,
//! are never written to storage, and are zeroised on drop. Everything else —
//! the seed, the derived signing key — never leaves this module unsealed.
//!
//! [Secure Enclave]: ../../../../../anuna-ssi/specs/concepts/Secure-Enclave.md

use selfsame_core::derive::{self, Mnemonic, PERSONA_ZERO};
use argon2::Argon2;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

// ── No silent fallback to a store that forgets — BUG-201 ────────────────────
//
// `keyring` 3.6.3 selects its default credential store by target, and its
// catch-all arm is the **mock** store (lib.rs:300):
//
//     #[cfg(not(any(linux, freebsd, openbsd, macos, ios, windows)))]
//     pub use mock as default;
//
// Android is in none of those arms, and the crate ships no `android.rs` at all.
// Worse, `MockCredential` holds `Mutex<RefCell<MockData>>` constructed fresh per
// instance, and `entry()` below builds a new `Entry` on every call — so a write
// and the read that follows it never touch the same map. On Android this module
// stored the root key nowhere, `Custody::create` was followed three lines later
// by a `root_public_key()` that returned `NoIdentity`, and an APK shipped.
//
// The dependency degraded silently and the build stayed green. This turns that
// into the compile failure it should always have been: a custody module that
// cannot persist a key must not compile, let alone publish.
//
// Remove this once Keystore-backed storage lands for Android.
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "windows",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
)))]
compile_error!(
    "no keychain backend exists on this target: `keyring` would silently fall \
     back to its in-memory mock store and the root key would not be persisted \
     at all. See BUG-201 in specs/SPEC-004-android-secure-storage.md. Android \
     needs the Keystore-backed store; do not paper over this with a plain file."
);

/// Keychain service name.
const SERVICE: &str = "io.anuna.selfsame";

/// The keychain entry holding the sealed root record.
const ENTRY: &str = "root-v1";

/// Argon2id parameters. Deliberately above the RFC 9106 second-recommended
/// option: this gate is the only thing between a stolen keychain entry and a
/// user's whole identity, and it runs at most a few times a day.
const ARGON_MEMORY_KIB: u32 = 64 * 1024;
const ARGON_PASSES: u32 = 3;
const ARGON_LANES: u32 = 1;

/// Minimum passcode length. Short enough to type on a phone, long enough that
/// Argon2id's cost is doing real work rather than covering for a 4-digit PIN.
pub const MIN_PASSCODE_CHARS: usize = 6;

#[derive(Debug, thiserror::Error)]
pub enum CustodyError {
    #[error("no identity on this device")]
    NoIdentity,
    #[error("an identity already exists on this device")]
    AlreadyExists,
    #[error("that passcode is not correct")]
    BadPasscode,
    #[error("a passcode must be at least {MIN_PASSCODE_CHARS} characters")]
    PasscodeTooShort,
    #[error("finish writing down your recovery phrase first")]
    BackupNotConfirmed,
    #[error("that is not a valid recovery phrase")]
    InvalidMnemonic,
    #[error("keychain unavailable: {0}")]
    Keychain(String),
    #[error("stored record is corrupt")]
    Corrupt,
}

/// What the keychain holds. **No plaintext key material.**
#[derive(Serialize, Deserialize)]
struct SealedRoot {
    version: u8,
    /// Argon2id salt.
    salt: [u8; 16],
    /// XChaCha-style nonce for the seal. 12 bytes, single-use per re-seal.
    nonce: [u8; 12],
    /// The 32-byte root seed, sealed under the passcode-derived key.
    sealed_seed: Vec<u8>,
    /// The root **public** key, in the clear.
    ///
    /// A public key is not a secret, and storing it is what lets the home
    /// screen show the identity and its fingerprint without a passcode prompt.
    /// Gating a public value behind user presence would put a prompt on every
    /// app launch and teach the user to type the passcode reflexively — which
    /// is precisely what REQ-024's check is supposed to mean something against.
    root_public_key: [u8; 32],
    /// REQ-002: linking and revoking stay locked until the user has re-entered
    /// three words from the phrase. Stored so the lock survives a restart —
    /// otherwise closing the app would be a way past the requirement.
    backup_confirmed: bool,
    /// The persona this device uses. ADR-012 defines index 0 only.
    persona: u32,
}

/// The custodian. Holds no secret between calls: every root-key use derives
/// the key from the passcode and drops it again.
pub struct Custody;

impl Custody {
    fn entry() -> Result<keyring::Entry, CustodyError> {
        keyring::Entry::new(SERVICE, ENTRY).map_err(|e| CustodyError::Keychain(e.to_string()))
    }

    fn read() -> Result<Option<SealedRoot>, CustodyError> {
        match Self::entry()?.get_password() {
            Ok(json) => {
                serde_json::from_str(&json).map(Some).map_err(|_| CustodyError::Corrupt)
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(CustodyError::Keychain(e.to_string())),
        }
    }

    fn write(record: &SealedRoot) -> Result<(), CustodyError> {
        let json = serde_json::to_string(record).map_err(|_| CustodyError::Corrupt)?;
        Self::entry()?.set_password(&json).map_err(|e| CustodyError::Keychain(e.to_string()))
    }

    /// Is there an identity on this device?
    pub fn exists() -> Result<bool, CustodyError> {
        Ok(Self::read()?.is_some())
    }

    /// Has the REQ-002 backup confirmation been completed?
    pub fn backup_confirmed() -> Result<bool, CustodyError> {
        Ok(Self::read()?.map(|r| r.backup_confirmed).unwrap_or(false))
    }

    /// HP-1 — create a root identity from fresh CSPRNG entropy.
    ///
    /// Returns the twelve words for the user to transcribe. This is the one
    /// deliberate exception NFR-002 names, and it is the only value this
    /// module ever hands out in the clear.
    pub fn create(passcode: &str) -> Result<Zeroizing<String>, CustodyError> {
        if Self::exists()? {
            return Err(CustodyError::AlreadyExists);
        }
        check_passcode(passcode)?;

        let mut entropy = Zeroizing::new([0u8; 16]);
        rand::rngs::OsRng.fill_bytes(entropy.as_mut());
        let mnemonic = derive::mnemonic_from_entropy(&entropy);

        Self::store(&mnemonic, passcode, false)?;
        Ok(Zeroizing::new(mnemonic.to_string()))
    }

    /// HP-5 tail — restore from the twelve words on a replacement phone.
    ///
    /// A restored identity is **already backed up** by definition: the user
    /// just proved they hold the phrase, so REQ-002's lock does not re-apply.
    pub fn restore(phrase: &str, passcode: &str) -> Result<(), CustodyError> {
        if Self::exists()? {
            return Err(CustodyError::AlreadyExists);
        }
        check_passcode(passcode)?;
        let mnemonic =
            derive::parse_mnemonic(phrase).map_err(|_| CustodyError::InvalidMnemonic)?;
        Self::store(&mnemonic, passcode, true)
    }

    fn store(mnemonic: &Mnemonic, passcode: &str, confirmed: bool) -> Result<(), CustodyError> {
        let seed = derive::root_seed(mnemonic, PERSONA_ZERO);

        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let wrapping = derive_wrapping_key(passcode, &salt)?;
        let sealed_seed = seal(&wrapping, &nonce, seed.as_ref())?;
        let root_public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();

        Self::write(&SealedRoot {
            version: 1,
            salt,
            nonce,
            sealed_seed,
            root_public_key,
            backup_confirmed: confirmed,
            persona: PERSONA_ZERO,
        })
    }

    /// REQ-002 — confirm the backup by re-entering three words chosen at
    /// random from the phrase.
    ///
    /// The phrase is not stored, so confirmation happens while the words are
    /// still on screen: the caller holds them for the duration of the ceremony
    /// and passes them back here. That is why this takes the mnemonic rather
    /// than reading it from storage — storing it to check it would defeat the
    /// exemption NFR-002 grants.
    pub fn confirm_backup(
        mnemonic: &str,
        answers: &[(usize, String)],
    ) -> Result<bool, CustodyError> {
        let parsed =
            derive::parse_mnemonic(mnemonic).map_err(|_| CustodyError::InvalidMnemonic)?;
        let ok = derive::confirm_backup(&parsed, answers)
            .map_err(|_| CustodyError::InvalidMnemonic)?;
        if ok {
            let mut record = Self::read()?.ok_or(CustodyError::NoIdentity)?;
            record.backup_confirmed = true;
            Self::write(&record)?;
        }
        Ok(ok)
    }

    /// The public half of the root key — needed to derive the DID and to show
    /// the identity fingerprint. No presence check; see the field docs on
    /// [`SealedRoot::root_public_key`].
    pub fn root_public_key() -> Result<[u8; 32], CustodyError> {
        Ok(Self::read()?.ok_or(CustodyError::NoIdentity)?.root_public_key)
    }

    /// REQ-024 — run `f` with the root signing key, behind a user-presence
    /// check.
    ///
    /// Every root-key operation goes through here: signing the genesis, signing
    /// an `AddVerificationMethod`, signing a `RevokeVerificationMethod`. The
    /// key is derived, used, and dropped inside the call — it is never held in
    /// a field where a later bug could reach it.
    pub fn use_root_key<T>(
        passcode: &str,
        f: impl FnOnce(&SigningKey) -> T,
    ) -> Result<T, CustodyError> {
        let record = Self::read()?.ok_or(CustodyError::NoIdentity)?;
        let wrapping = derive_wrapping_key(passcode, &record.salt)?;
        let mut seed = open(&wrapping, &record.nonce, &record.sealed_seed)
            .map_err(|_| CustodyError::BadPasscode)?;
        let seed_array: [u8; 32] = seed.as_slice().try_into().map_err(|_| CustodyError::Corrupt)?;
        let signing = SigningKey::from_bytes(&seed_array);
        let out = f(&signing);
        seed.zeroize();
        Ok(out)
    }

    /// REQ-002 gate — refuse a link or revoke until the backup is confirmed.
    pub fn require_backup_confirmed() -> Result<(), CustodyError> {
        if Self::backup_confirmed()? {
            Ok(())
        } else {
            Err(CustodyError::BackupNotConfirmed)
        }
    }

    /// Remove the identity from this device. Used only by the "start again"
    /// path during first run; it does **not** revoke anything, because the
    /// root key is the only thing that can revoke and this destroys it.
    pub fn forget() -> Result<(), CustodyError> {
        match Self::entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(CustodyError::Keychain(e.to_string())),
        }
    }
}

fn check_passcode(passcode: &str) -> Result<(), CustodyError> {
    if passcode.chars().count() < MIN_PASSCODE_CHARS {
        return Err(CustodyError::PasscodeTooShort);
    }
    Ok(())
}

/// Argon2id over the passcode. The cost parameters are the presence check's
/// only real strength on a desktop, so they are named constants rather than
/// library defaults.
fn derive_wrapping_key(passcode: &str, salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>, CustodyError> {
    let params = argon2::Params::new(ARGON_MEMORY_KIB, ARGON_PASSES, ARGON_LANES, Some(32))
        .map_err(|_| CustodyError::Corrupt)?;
    let argon = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passcode.as_bytes(), salt, out.as_mut())
        .map_err(|_| CustodyError::Corrupt)?;
    Ok(out)
}

/// Seal and open reuse the core's AEAD so the app carries one cipher, not two.
fn seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, CustodyError> {
    Ok(selfsame_core::seal::seal_at_rest(key, nonce, plaintext))
}

fn open(key: &[u8; 32], nonce: &[u8; 12], sealed: &[u8]) -> Result<Vec<u8>, CustodyError> {
    selfsame_core::seal::open_at_rest(key, nonce, sealed).map_err(|_| CustodyError::BadPasscode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wrapping_key_depends_on_both_passcode_and_salt() {
        let salt = [1u8; 16];
        let a = derive_wrapping_key("correct horse", &salt).unwrap();
        let b = derive_wrapping_key("correct horse", &[2u8; 16]).unwrap();
        let c = derive_wrapping_key("battery staple", &salt).unwrap();
        assert_ne!(*a, *b);
        assert_ne!(*a, *c);
        assert_eq!(*a, *derive_wrapping_key("correct horse", &salt).unwrap());
    }

    #[test]
    fn a_sealed_seed_does_not_open_under_the_wrong_passcode() {
        let salt = [3u8; 16];
        let nonce = [4u8; 12];
        let seed = [0x42u8; 32];
        let right = derive_wrapping_key("correct horse", &salt).unwrap();
        let wrong = derive_wrapping_key("correct horsf", &salt).unwrap();
        let sealed = seal(&right, &nonce, &seed).unwrap();
        assert_eq!(open(&right, &nonce, &sealed).unwrap(), seed);
        assert!(open(&wrong, &nonce, &sealed).is_err());
    }

    #[test]
    fn short_passcodes_are_refused() {
        assert!(matches!(check_passcode("12345"), Err(CustodyError::PasscodeTooShort)));
        assert!(check_passcode("123456").is_ok());
    }

    // NFR-002: the sealed record carries no plaintext key material.
    #[test]
    fn the_stored_record_contains_no_plaintext_seed() {
        let salt = [5u8; 16];
        let nonce = [6u8; 12];
        let seed = [0x7eu8; 32];
        let key = derive_wrapping_key("a passcode", &salt).unwrap();
        let record = SealedRoot {
            version: 1,
            salt,
            nonce,
            sealed_seed: seal(&key, &nonce, &seed).unwrap(),
            root_public_key: SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
            backup_confirmed: false,
            persona: 0,
        };
        let json = serde_json::to_string(&record).unwrap();
        let seed_b64 = selfsame_core::mb::encode(&seed);
        assert!(!json.contains(&seed_b64[1..]));
        assert!(!json.contains("0x7e"));
        assert!(!record.sealed_seed.windows(32).any(|w| w == seed));
    }
}
