//! The application and account key hierarchy — `CON-202`, `REQ-201`,
//! `REQ-213`, `REQ-216`.
//!
//! One recovery secret, a different home key for every application account:
//!
//! ```text
//! UTF8(s)  = UTF-8 encoding of Unicode string s
//! U32BE(n) = four-octet unsigned big-endian encoding of n
//! LP(s)    = U32BE(len(UTF8(s))) || UTF8(s)
//! SALT     = SHA-512(UTF8("selfsame/application-account-key-hierarchy/v1"))
//!
//! KDF(ikm, label, context, length) =
//!   HKDF-SHA-512(IKM = ikm, salt = SALT,
//!                info = LP(label) || LP(context), L = length)
//!
//! recovery_seed     = BIP-39 seed, 64 octets
//! application_node  = KDF(recovery_seed,    "application",      applicationId,   64)
//! account_node      = KDF(application_node, "account",          accountScopeId,  64)
//! home_signing_seed = KDF(account_node,     "home-signing-key", "",              32)
//! ```
//!
//! # Why `LP`, and why it is the load-bearing part
//!
//! `info` is the concatenation of two length-prefixed strings, not two strings
//! with a separator. That is what makes the mapping from `(label, context)` to
//! `info` injective.
//!
//! Consider the alternative. With plain concatenation, the label `"account"`
//! with context `"xy"` and the label `"accountx"` with context `"y"` produce the
//! same `info`, so they produce the same key. With a separator, the same
//! collision returns whenever a context can contain the separator. `LP` closes
//! it for every input: the first four octets fix how many follow, so no two
//! distinct pairs can encode alike. The `U32BE` choice does the same job for the
//! length itself that `selfsame-core`'s persona index does — raw octets, so
//! there is no `"01"` versus `"1"` second spelling to argue about.
//!
//! # What the hierarchy deliberately does not depend on
//!
//! `REQ-213`: derivation depends **only** on the recovery input, the KDF
//! version, the canonical `applicationId`, and the canonical `accountScopeId`.
//! Not the account authority, rendezvous, state, or projection provider; not an
//! endpoint URL, region, projection index, device key, or health response.
//!
//! The consequence is the one a person notices: changing providers does not
//! rotate the home DID or the `acct:` localpart. Restoring an identity needs the
//! words and the scope, and nothing that an operator could take away.
//!
//! # The types carry the preconditions
//!
//! `CON-202` says the hierarchy applies *"after validating
//! `canonical_account_scope_id` with `CON-211`"*. That precondition is carried
//! by [`ApplicationId`] and [`AccountScopeId`] rather than by a comment: there
//! is no way to reach these functions with an unrecognised identifier, so the
//! ordering cannot be got wrong at a call site (LangSec Principle 7).

use zeroize::{Zeroize, Zeroizing};

use crate::profile::ApplicationId;
use crate::scope::AccountScopeId;

/// The domain-separation string hashed into the HKDF salt.
const SALT_LABEL: &[u8] = b"selfsame/application-account-key-hierarchy/v1";

/// `CON-202` label for the application node.
const LABEL_APPLICATION: &str = "application";
/// `CON-202` label for the account node.
const LABEL_ACCOUNT: &str = "account";
/// `CON-202` label for the home signing seed.
const LABEL_HOME_SIGNING_KEY: &str = "home-signing-key";

/// The BIP-39 mnemonic type, re-exported so a consumer needs no second pinned
/// `bip39` dependency.
///
/// Two wordlists in one process is two answers to "is this phrase valid", which
/// is the parser-differential shape LangSec Principle 5 rules out.
pub use bip39::Mnemonic;

/// The 64-octet BIP-39 seed, zeroised on drop.
///
/// A newtype rather than an alias for [`Zeroizing<[u8; 64]>`](Zeroizing), and
/// the reason is the same one [`ApplicationNode`] and [`AccountNode`] are: an
/// alias inherits the inner type's derived [`Debug`](core::fmt::Debug), so
/// `{:?}` on the *root* of the whole hierarchy would print all sixty-four
/// octets into whatever log or error report the caller was assembling. This is
/// the one secret in `CON-202` from which every other one below it can be
/// re-derived, so it is the one that least belongs in a log line.
///
/// It carries no accessor for the same reason the nodes do not: it exists only
/// to be the IKM of [`application_node`], and nothing else in this profile has
/// a use for the octets.
pub struct RecoverySeed(Zeroizing<[u8; 64]>);

impl RecoverySeed {
    /// The raw seed, for the first KDF step only.
    fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// A private application node — 64 octets of KDF material.
///
/// `CON-202`: not a DID, a signing key, a wire identifier, a log field, or an
/// application-visible secret. It exists only to be the IKM of the next step.
pub struct ApplicationNode(Zeroizing<[u8; 64]>);

/// A private account node — 64 octets of KDF material, one per
/// `(applicationId, accountScopeId)` pair.
pub struct AccountNode(Zeroizing<[u8; 64]>);

/// The application-account home signing key.
///
/// `CON-202` confines it: it signs the home DID's assertion and control
/// operations and nothing else. It is never a device key, encryption key, route
/// key, account token, or status-provider credential.
pub struct HomeKey {
    seed: Zeroizing<[u8; 32]>,
    signing: ed25519_dalek::SigningKey,
}

impl ApplicationNode {
    /// The raw node material, for the next KDF step only.
    fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl AccountNode {
    fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl HomeKey {
    /// The RFC 8032 private seed.
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// The Ed25519 signing key.
    pub fn signing_key(&self) -> &ed25519_dalek::SigningKey {
        &self.signing
    }

    /// The raw 32-octet Ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// The `did:crdt` identifier of this account's home identity.
    ///
    /// Exact DID construction stays owned by the pinned `did:crdt` method, so
    /// this defers to `selfsame-core`, which already pins it and has a test that
    /// fails if the derivation drifts.
    pub fn home_did(&self) -> Result<String, HierarchyError> {
        let did = selfsame_core::identity::derive_did(&self.public_key())
            .map_err(|_| HierarchyError::DidDerivation)?;
        Ok(did.to_string())
    }
}

/// Deliberately opaque: a home seed must not reach a log through `{:?}`.
impl core::fmt::Debug for HomeKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HomeKey(<redacted>)")
    }
}

impl core::fmt::Debug for RecoverySeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoverySeed(<redacted>)")
    }
}

impl core::fmt::Debug for ApplicationNode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ApplicationNode(<redacted>)")
    }
}

impl core::fmt::Debug for AccountNode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AccountNode(<redacted>)")
    }
}

/// Why a derivation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HierarchyError {
    /// The pinned `did:crdt` method refused to derive an identifier from the
    /// home public key.
    #[error("did:crdt derivation failed")]
    DidDerivation,
}

/// The 64-octet BIP-39 seed (`CON-202`).
///
/// Version 1 uses the empty BIP-39 passphrase. That is a versioned property of
/// the derivation, not a parameter: admitting a passphrase later would re-derive
/// every existing identity, so it becomes a new hierarchy version rather than an
/// argument a caller can vary.
pub fn recovery_seed(mnemonic: &Mnemonic) -> RecoverySeed {
    RecoverySeed(Zeroizing::new(mnemonic.to_seed_normalized("")))
}

/// The private application node for one canonical `applicationId`.
pub fn application_node(recovery: &RecoverySeed, application: &ApplicationId) -> ApplicationNode {
    ApplicationNode(kdf64(recovery.as_bytes(), LABEL_APPLICATION, application.as_str()))
}

/// The private account node for one `(applicationId, accountScopeId)` pair.
pub fn account_node(application: &ApplicationNode, scope: &AccountScopeId) -> AccountNode {
    AccountNode(kdf64(application.as_bytes(), LABEL_ACCOUNT, scope.as_str()))
}

/// The home signing key for one application account.
pub fn home_key(account: &AccountNode) -> HomeKey {
    let mut seed = Zeroizing::new([0u8; 32]);
    expand(account.as_bytes(), LABEL_HOME_SIGNING_KEY, "", seed.as_mut());
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    HomeKey { seed, signing }
}

/// The whole hierarchy in one call, the shape every caller actually wants.
pub fn derive(
    mnemonic: &Mnemonic,
    application: &ApplicationId,
    scope: &AccountScopeId,
) -> HomeKey {
    let recovery = recovery_seed(mnemonic);
    let app = application_node(&recovery, application);
    let account = account_node(&app, scope);
    home_key(&account)
}

// ── the KDF ─────────────────────────────────────────────────────────────────

/// `SALT = SHA-512(UTF8("selfsame/application-account-key-hierarchy/v1"))`.
fn salt() -> [u8; 64] {
    use sha2::Digest as _;
    sha2::Sha512::digest(SALT_LABEL).into()
}

/// `LP(s) = U32BE(len(UTF8(s))) || UTF8(s)`.
fn length_prefixed(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn expand(ikm: &[u8], label: &str, context: &str, okm: &mut [u8]) {
    let mut info = Vec::with_capacity(8 + label.len() + context.len());
    length_prefixed(&mut info, label);
    length_prefixed(&mut info, context);
    let salt = salt();
    let hk = hkdf::Hkdf::<sha2::Sha512>::new(Some(&salt), ikm);
    hk.expand(&info, okm).expect("output length is within HKDF-SHA-512's bound");
    info.zeroize();
}

fn kdf64(ikm: &[u8], label: &str, context: &str) -> Zeroizing<[u8; 64]> {
    let mut out = Zeroizing::new([0u8; 64]);
    expand(ikm, label, context, out.as_mut());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mnemonic(entropy: u8) -> Mnemonic {
        Mnemonic::from_entropy_in(bip39::Language::English, &[entropy; 16])
            .expect("128 bits is a valid BIP-39 entropy length")
    }

    fn app(id: &str) -> ApplicationId {
        ApplicationId::parse(id).expect("test identifier is canonical")
    }

    fn scope(byte: u8) -> AccountScopeId {
        AccountScopeId::from_octets([byte; 32])
    }

    fn home(m: &Mnemonic, id: &str, s: u8) -> [u8; 32] {
        *derive(m, &app(id), &scope(s)).seed()
    }

    const A: &str = "https://photos.example/selfsame/application";
    const B: &str = "https://pictura.example/selfsame/application";

    // TEST-202 positive: determinism.
    #[test]
    fn the_same_inputs_reproduce_the_same_home_seed() {
        let m = mnemonic(0);
        assert_eq!(home(&m, A, 1), home(&m, A, 1));
    }

    // TEST-201: two application IDs under one mnemonic and one scope.
    #[test]
    fn two_applications_yield_different_home_keys_under_one_scope() {
        let m = mnemonic(0);
        assert_ne!(home(&m, A, 1), home(&m, B, 1));
    }

    // TEST-222: two scopes below one application.
    #[test]
    fn two_account_scopes_yield_different_home_keys_below_one_application() {
        let m = mnemonic(0);
        assert_ne!(home(&m, A, 1), home(&m, A, 2));
    }

    #[test]
    fn the_same_scope_octets_below_two_applications_stay_independent() {
        let m = mnemonic(0);
        assert_ne!(home(&m, A, 7), home(&m, B, 7));
    }

    #[test]
    fn two_mnemonics_yield_different_home_keys_for_one_application_and_scope() {
        assert_ne!(home(&mnemonic(0), A, 1), home(&mnemonic(1), A, 1));
    }

    #[test]
    fn a_one_octet_application_id_change_changes_the_home_key() {
        let m = mnemonic(0);
        assert_ne!(
            home(&m, "https://photos.example/selfsame/application", 1),
            home(&m, "https://photos.example/selfsame/applicatioo", 1)
        );
    }

    #[test]
    fn a_one_octet_account_scope_change_changes_the_home_key() {
        let m = mnemonic(0);
        let mut octets = [0u8; 32];
        let one = AccountScopeId::from_octets(octets);
        octets[31] = 1;
        let two = AccountScopeId::from_octets(octets);
        assert_ne!(
            *derive(&m, &app(A), &one).seed(),
            *derive(&m, &app(A), &two).seed()
        );
    }

    // TEST-201 at scale: 10,000 distinct application IDs, no collision.
    #[test]
    fn ten_thousand_applications_produce_ten_thousand_distinct_home_keys() {
        let m = mnemonic(0);
        let recovery = recovery_seed(&m);
        let s = scope(3);
        let mut seen = std::collections::HashSet::with_capacity(10_000);
        for i in 0..10_000u32 {
            let id = app(&format!("https://a{i}.example/selfsame/application"));
            let key = home_key(&account_node(&application_node(&recovery, &id), &s));
            assert!(seen.insert(*key.seed()), "application {i} collided");
        }
    }

    // TEST-222 at scale: 10,000 distinct scopes below one application.
    #[test]
    fn ten_thousand_account_scopes_produce_ten_thousand_distinct_home_keys() {
        let m = mnemonic(0);
        let recovery = recovery_seed(&m);
        let node = application_node(&recovery, &app(A));
        let mut seen = std::collections::HashSet::with_capacity(10_000);
        for i in 0..10_000u32 {
            let mut octets = [0u8; 32];
            octets[..4].copy_from_slice(&i.to_be_bytes());
            let key = home_key(&account_node(&node, &AccountScopeId::from_octets(octets)));
            assert!(seen.insert(*key.seed()), "scope {i} collided");
        }
    }

    // REQ-201 negative-output: no application receives a sibling's material.
    #[test]
    fn the_home_seed_is_domain_separated_from_every_node_above_it() {
        let m = mnemonic(0);
        let recovery = recovery_seed(&m);
        let a = application_node(&recovery, &app(A));
        let account = account_node(&a, &scope(1));
        let key = home_key(&account);
        assert_ne!(&recovery.as_bytes()[..32], key.seed().as_slice());
        assert_ne!(&a.as_bytes()[..32], key.seed().as_slice());
        assert_ne!(&account.as_bytes()[..32], key.seed().as_slice());
    }

    /// The collision the length prefix exists to prevent.
    ///
    /// Without `LP`, `("account", "xy")` and `("accountx", "y")` would build the
    /// same `info` and therefore the same key. The labels are fixed constants in
    /// this profile, so the hazard is not reachable through the public API — the
    /// test drives the KDF directly, because a property that only holds by
    /// accident of the current constants is one a later revision would break
    /// silently.
    #[test]
    fn length_prefixing_makes_the_label_and_context_pair_injective() {
        let ikm = [9u8; 32];
        let mut left = [0u8; 32];
        let mut right = [0u8; 32];
        expand(&ikm, "account", "xy", &mut left);
        expand(&ikm, "accountx", "y", &mut right);
        assert_ne!(left, right, "LP() failed to separate a shifted label boundary");

        let mut prefix = Vec::new();
        length_prefixed(&mut prefix, "ab");
        assert_eq!(prefix, vec![0, 0, 0, 2, b'a', b'b']);
    }

    #[test]
    fn the_salt_is_the_sha512_of_the_declared_domain_string() {
        use sha2::Digest as _;
        let expected: [u8; 64] =
            sha2::Sha512::digest(b"selfsame/application-account-key-hierarchy/v1").into();
        assert_eq!(salt(), expected);
        // A bare unsalted HKDF must not produce the same material.
        let hk = hkdf::Hkdf::<sha2::Sha512>::new(None, &[0u8; 64]);
        let mut unsalted = [0u8; 32];
        hk.expand(b"", &mut unsalted).unwrap();
        let mut salted = [0u8; 32];
        expand(&[0u8; 64], "", "", &mut salted);
        assert_ne!(unsalted, salted);
    }

    // REQ-213: derivation depends on no provider value.
    #[test]
    fn derivation_reads_nothing_but_the_recovery_seed_application_id_and_scope() {
        // Stated structurally rather than by assertion: the signatures of
        // `application_node`, `account_node`, and `home_key` admit no profile,
        // descriptor, endpoint, region, or device key, so there is no value a
        // provider controls that could reach the KDF. This test pins the
        // consequence a person notices — the same three inputs give the same
        // home DID no matter what else changed.
        let m = mnemonic(0);
        let first = derive(&m, &app(A), &scope(1));
        let second = derive(&m, &app(A), &scope(1));
        assert_eq!(first.public_key(), second.public_key());
        assert_eq!(first.home_did().unwrap(), second.home_did().unwrap());
    }

    #[test]
    fn distinct_home_keys_yield_distinct_dids() {
        let m = mnemonic(0);
        let one = derive(&m, &app(A), &scope(1)).home_did().unwrap();
        let two = derive(&m, &app(B), &scope(1)).home_did().unwrap();
        assert_ne!(one, two);
        assert!(one.starts_with("did:crdt:"), "{one}");
    }

    // REQ-217 / REQ-201 prohibited-action: no node reaches a log via Debug.
    #[test]
    fn debug_discloses_no_key_material() {
        let m = mnemonic(0);
        let recovery = recovery_seed(&m);
        let a = application_node(&recovery, &app(A));
        let account = account_node(&a, &scope(1));
        let key = home_key(&account);
        for rendered in
            [format!("{recovery:?}"), format!("{a:?}"), format!("{account:?}"), format!("{key:?}")]
        {
            assert!(rendered.contains("redacted"), "{rendered}");
            assert!(!rendered.contains("0x"), "{rendered}");
        }
    }

    /// The recovery seed was a `Zeroizing<[u8; 64]>` alias, which inherits the
    /// array's derived `Debug` — so `{:?}` printed all sixty-four octets of the
    /// root secret, while every type below it in the hierarchy was redacted.
    #[test]
    fn the_recovery_seed_does_not_print_its_octets() {
        let recovery = recovery_seed(&mnemonic(0));
        let rendered = format!("{recovery:?}");
        // The first octet of this seed, in the two spellings a derived `Debug`
        // for `[u8; 64]` would produce.
        let first = recovery.as_bytes()[0];
        assert!(!rendered.contains(&format!("{first}")), "{rendered}");
        assert!(!rendered.contains(&format!("{first:02x}")), "{rendered}");
        assert_eq!(rendered, "RecoverySeed(<redacted>)");
    }
}
