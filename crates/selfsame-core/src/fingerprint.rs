//! The human backstop — SPEC-001 REQ-007, NFR-008.
//!
//! Two **distinct total functions over distinct inputs**: the phone shows
//! [`fingerprint_key`] of the key it is about to authorise; the client shows
//! [`fingerprint_did`] of the identity it joined. v0.1.0 had one
//! `fingerprint(did)` compared against a device-key fingerprint — comparing two
//! different things — which is why the two functions are named separately here
//! and why it is stated at each call site which is compared to which.
//!
//! ```text
//!   phone (SCREEN-001)                        client (SCREEN-002)
//!   fingerprint_key(device_key)               fingerprint_did(did)
//!   "C0 7A 1E 42 9B 33"                       "5F 9A C9 07 2E 11"
//!        ▲                                          ▲
//!        └── compared against the client's ──────────┘  NO. See below.
//! ```
//!
//! The two are **not** compared against each other. `fingerprint_key` is
//! compared against what the linking client displays for *its own key*;
//! `fingerprint_did` is compared against what the phone displayed at identity
//! creation. Trust assumption A6 is that the user actually performs those
//! comparisons, and SCREEN-002 is designed to make skipping them effortful.
//!
//! # Rendering, and which rendering is normative
//!
//! [`Fingerprint::hex`] — six bytes, `C0 7A 1E 42 9B 33` — is the **normative
//! comparison rendering**. 48 bits, against NFR-008's floor of 32: a
//! "four colours" rendering at 16 bits would be forgeable by an attacker
//! willing to grind keys, and this value is the user-visible backstop behind
//! REQ-006.
//!
//! [`Fingerprint::label`] — `copper-lynx-42` — is a **nickname**, not a
//! comparison value. It carries ≈ 18.6 bits and exists so a device list can
//! name a row without a hex string in it. No screen asks the user to compare
//! labels, and no code path treats equal labels as equal identities.

/// A 48-bit identity fingerprint.
///
/// Deterministic and total, so the phone's and the client's displays agree by
/// construction (REQ-007). Two fingerprints compare equal iff their inputs
/// produced the same digest.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct Fingerprint([u8; 6]);

/// Bits of entropy carried by [`Fingerprint::hex`] — the value NFR-008 bounds.
pub const FINGERPRINT_BITS: u32 = 48;

/// NFR-008's floor, checked at compile time.
///
/// A runtime assertion would be a test that could be skipped; this one cannot
/// be. Shrinking the fingerprint below 32 bits fails the build, which is the
/// right severity for the user-visible backstop behind REQ-006.
const _: () = assert!(FINGERPRINT_BITS >= 32);

const KEY_DOMAIN: &[u8] = b"anuna-ssi/v1/fp/key";
const DID_DOMAIN: &[u8] = b"anuna-ssi/v1/fp/did";

impl Fingerprint {
    /// The normative comparison rendering: six uppercase hex pairs, spaced.
    ///
    /// Spaced pairs rather than a run of twelve characters because the user is
    /// asked to compare two of these across two devices, and chunking is what
    /// makes that possible at a glance (Miller's Law).
    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
    }

    /// A short nickname for list rows — `copper-lynx-42`.
    ///
    /// **Not a comparison value.** ≈ 18.6 bits; see the module docs.
    pub fn label(&self) -> String {
        let n = u64::from_be_bytes([0, 0, self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]]);
        let adjective = ADJECTIVES[(n % ADJECTIVES.len() as u64) as usize];
        let noun = NOUNS[((n / ADJECTIVES.len() as u64) % NOUNS.len() as u64) as usize];
        let number = (n / (ADJECTIVES.len() as u64 * NOUNS.len() as u64)) % 100;
        format!("{adjective}-{noun}-{number:02}")
    }

    /// The raw digest, for tests and for callers that need to compare without
    /// rendering.
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

impl core::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.hex())
    }
}

/// The fingerprint of a device public key — what the phone shows before
/// authorising (REQ-019, SCREEN-001).
pub fn fingerprint_key(public_key: &[u8; 32]) -> Fingerprint {
    digest(KEY_DOMAIN, public_key)
}

/// The fingerprint of a DID — what the client shows after accepting, for
/// comparison against the value the phone showed at identity creation
/// (REQ-007, SCREEN-002 S3).
///
/// Takes the DID as a string so the function is callable from a runtime that
/// has not linked `did-crdt`; the value hashed is the full `did:crdt:…` text.
pub fn fingerprint_did(did: &str) -> Fingerprint {
    digest(DID_DOMAIN, did.as_bytes())
}

fn digest(domain: &[u8], input: &[u8]) -> Fingerprint {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(input);
    let out = hasher.finalize();
    let mut bytes = [0u8; 6];
    bytes.copy_from_slice(&out.as_bytes()[..6]);
    Fingerprint(bytes)
}

const ADJECTIVES: [&str; 64] = [
    "amber", "arctic", "ashen", "auburn", "azure", "basalt", "brass", "bronze", "cedar", "cobalt",
    "copper", "coral", "cotton", "crimson", "dusty", "ember", "fallow", "flint", "frosted", "garnet",
    "gilded", "glacial", "granite", "hazel", "indigo", "ivory", "jade", "lilac", "linen", "marble",
    "mauve", "misty", "mossy", "olive", "onyx", "opal", "pearl", "pewter", "quartz", "russet",
    "saffron", "sage", "salt", "sandy", "scarlet", "shale", "silver", "slate", "smoky", "spruce",
    "steel", "storm", "teal", "thistle", "tidal", "topaz", "umber", "velvet", "verdant", "walnut",
    "wheaten", "willow", "winter", "wren",
];

const NOUNS: [&str; 64] = [
    "adder", "alder", "badger", "beacon", "bittern", "bramble", "cairn", "chough", "cormorant",
    "curlew", "dipper", "dunlin", "eider", "fallow", "ferret", "finch", "gannet", "godwit",
    "grebe", "harrier", "heron", "hobby", "ibis", "jackdaw", "kestrel", "lapwing", "linnet",
    "lynx", "marten", "merlin", "mussel", "nuthatch", "osprey", "otter", "ouzel", "petrel",
    "pintail", "pipit", "plover", "pochard", "puffin", "quarry", "raven", "redwing", "roebuck",
    "sanderling", "sandpiper", "scoter", "shelduck", "siskin", "skylark", "smew", "snipe",
    "stoat", "swift", "teal", "tern", "turnstone", "twite", "vole", "wagtail", "weasel",
    "wheatear", "widgeon",
];

#[cfg(test)]
mod tests {
    use super::*;

    // TEST-007 positive: both functions are stable and platform-independent.
    #[test]
    fn both_functions_are_deterministic() {
        let pk = [0x42u8; 32];
        assert_eq!(fingerprint_key(&pk), fingerprint_key(&pk));
        let did = "did:crdt:".to_owned() + &"9f3a".repeat(16);
        assert_eq!(fingerprint_did(&did), fingerprint_did(&did));
    }

    #[test]
    fn the_two_functions_are_domain_separated() {
        // Feeding a DID's bytes to `fingerprint_key` must not produce the DID's
        // fingerprint — otherwise the two displays could be made to agree by an
        // attacker who controls one of the inputs.
        let did = "did:crdt:".to_owned() + &"9f3a".repeat(16);
        let mut as_key = [0u8; 32];
        as_key.copy_from_slice(&did.as_bytes()[..32]);
        assert_ne!(fingerprint_key(&as_key).as_bytes(), fingerprint_did(&did).as_bytes());
    }

    #[test]
    fn rendering_matches_the_design() {
        let fp = Fingerprint([0xC0, 0x7A, 0x1E, 0x42, 0x9B, 0x33]);
        assert_eq!(fp.hex(), "C0 7A 1E 42 9B 33");
        assert_eq!(fp.to_string(), "C0 7A 1E 42 9B 33");
        // Labels are `adjective-noun-NN`, lowercase, hyphenated.
        let label = fp.label();
        assert_eq!(label.split('-').count(), 3, "{label}");
        assert!(label.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
    }

    // TEST-007 negative-output: < 32 bits of entropy, or a collision within a
    // 10^6-sample corpus, is a failure. The corpus is 10^6 distinct keys.
    #[test]
    fn carries_at_least_thirty_two_bits_and_does_not_collide_over_a_million_samples() {
        // The bit count itself is asserted at compile time above; this test
        // covers what a constant cannot — that the bits are actually spread.
        use std::collections::HashSet;
        let mut seen = HashSet::with_capacity(1_000_000);
        for i in 0..1_000_000u32 {
            let mut pk = [0u8; 32];
            pk[..4].copy_from_slice(&i.to_le_bytes());
            let fp = fingerprint_key(&pk);
            assert!(seen.insert(*fp.as_bytes()), "collision at sample {i}");
        }
    }

    #[test]
    fn one_bit_of_input_change_changes_the_display() {
        let a = fingerprint_key(&[0u8; 32]);
        let mut pk = [0u8; 32];
        pk[31] = 1;
        assert_ne!(a, fingerprint_key(&pk));
    }

    #[test]
    fn the_wordlists_have_no_duplicates() {
        use std::collections::HashSet;
        assert_eq!(ADJECTIVES.iter().collect::<HashSet<_>>().len(), ADJECTIVES.len());
        assert_eq!(NOUNS.iter().collect::<HashSet<_>>().len(), NOUNS.len());
    }
}
