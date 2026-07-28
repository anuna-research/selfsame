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
//!
//! [`Fingerprint::lifehash`] — a 32×32 picture — is a **recognition aid**
//! (SPEC-002 REQ-101, ADR-102). Unlike the label it is computed from the whole
//! digest, so its preimage carries all 48 bits; unlike the hex, nobody is asked
//! to compare it. Think of the three together as a passport: the photograph is
//! what you glance at to see whether this is the same person, the number is
//! what you read when it has to be right, and the name is what you call the
//! row in a list.
//!
//! It replaced three colour bars that lived in `app.js`. Those bars consumed
//! bytes 0, 2 and 4 and threw the other half of the digest away; worse, because
//! they lived in the front end, the CLI never had them and no test here could
//! see them. This one is computed once, in the core, for every shell.

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

    /// The picture — LifeHash v2 of this fingerprint (SPEC-002 CON-101).
    ///
    /// Derived from the *fingerprint*, not from the key it came from, so that
    /// the picture and the hex are two renderings of one value: equal hex
    /// implies an equal picture, necessarily (SPEC-002 ADR-102). Deriving it
    /// from the key instead would make "the numbers match but the pictures
    /// don't" a reachable state, and there is nothing a user could do with
    /// that.
    ///
    /// Domain separation comes free: [`fingerprint_key`] and
    /// [`fingerprint_did`] already commit to different BLAKE3 domains, so their
    /// pictures differ for exactly the reason their hexes do.
    pub fn lifehash(&self) -> LifeHash {
        // `make_from_data` hashes its argument, so the six bytes reach the
        // algorithm whole — all 48 bits, which is the point of NFR-101.
        let image = bc_lifehash::make_from_data(&self.0, bc_lifehash::Version::Version2, 1, false);
        LifeHash(image.colors.try_into().expect(
            "LifeHash v2 at module size 1 without alpha is 32×32 RGB by construction; \
             the version is pinned exactly in Cargo.toml so this cannot drift silently",
        ))
    }
}

/// The side of a LifeHash v2 image, in pixels.
///
/// The Game of Life runs on a 16×16 grid; the symmetry pattern applied
/// afterwards doubles it, which is why the picture is 32 and not 16.
pub const LIFEHASH_SIDE: usize = 32;

/// Bytes in a LifeHash v2 image — 32 × 32 × RGB.
pub const LIFEHASH_RGB_LEN: usize = LIFEHASH_SIDE * LIFEHASH_SIDE * 3;

/// A 32×32 RGB picture of a [`Fingerprint`] — SPEC-002 CON-101.
///
/// Total and deterministic: every shell painting the same fingerprint paints
/// the same pixels. It decides nothing — SPEC-002 REQ-103 keeps
/// [`Fingerprint::hex`] the value the user is asked to compare — which is why
/// a defect in the picture cannot become a wrong authorisation.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct LifeHash([u8; LIFEHASH_RGB_LEN]);

impl LifeHash {
    /// The side of the image, in pixels.
    pub const SIDE: usize = LIFEHASH_SIDE;
    /// The length of [`LifeHash::rgb`].
    pub const RGB_LEN: usize = LIFEHASH_RGB_LEN;

    /// The pixels, row-major, three bytes each.
    pub fn rgb(&self) -> &[u8; LIFEHASH_RGB_LEN] {
        &self.0
    }

    /// One pixel. Panics outside `0..SIDE`, which is a caller bug rather than
    /// an input error — every caller here iterates a fixed range.
    pub fn pixel(&self, x: usize, y: usize) -> (u8, u8, u8) {
        assert!(x < Self::SIDE && y < Self::SIDE, "pixel ({x}, {y}) is outside a {}² image", Self::SIDE);
        let i = (y * Self::SIDE + x) * 3;
        (self.0[i], self.0[i + 1], self.0[i + 2])
    }

    /// The pixels as Base64 — the transport encoding across the Tauri boundary
    /// (SPEC-002 CON-102).
    ///
    /// It lives here beside [`Fingerprint::hex`] and [`Fingerprint::label`]
    /// because this module owns the question "what may a fingerprint be
    /// displayed as?", and because putting it here keeps the shells free of a
    /// Base64 dependency they would otherwise each need.
    ///
    /// 3072 is divisible by 3, so the output is exactly 4096 characters and
    /// never actually carries padding — but the padded alphabet is what CON-102
    /// declares, so that is what is emitted.
    pub fn base64(&self) -> String {
        use base64ct::{Base64, Encoding as _};
        Base64::encode_string(&self.0)
    }
}

impl core::fmt::Debug for LifeHash {
    /// Deliberately not the pixels. A derived `Debug` on 3072 bytes turns any
    /// assertion failure that mentions a `LifeHash` into a wall of numbers
    /// nobody reads; the digest of the image is what actually identifies it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let digest = blake3::hash(&self.0);
        write!(f, "LifeHash({}²  {})", Self::SIDE, &digest.to_hex()[..12])
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

    // ── SPEC-002: the picture ───────────────────────────────────────────────

    // TEST-102 positive: deterministic, and the right shape.
    #[test]
    fn the_picture_is_deterministic_and_thirty_two_squared() {
        let fp = fingerprint_key(&[0x42u8; 32]);
        let a = fp.lifehash();
        let b = fp.lifehash();
        assert_eq!(a, b, "the same fingerprint must paint the same pixels");
        assert_eq!(a.rgb().len(), LIFEHASH_RGB_LEN);
        assert_eq!(LIFEHASH_RGB_LEN, 32 * 32 * 3);
        assert_eq!(LifeHash::SIDE, 32);
    }

    // TEST-102 positive (NFR-101): the whole 48-bit digest reaches the
    // algorithm. The bars this replaced consumed bytes 0, 2 and 4 and dropped
    // the rest, so "all six bytes are the preimage" is the property worth
    // pinning, not an implementation detail.
    #[test]
    fn the_picture_is_lifehash_v2_of_the_whole_fingerprint() {
        let fp = fingerprint_key(&[0x42u8; 32]);
        let direct =
            bc_lifehash::make_from_data(fp.as_bytes(), bc_lifehash::Version::Version2, 1, false);
        assert_eq!(fp.lifehash().rgb().as_slice(), direct.colors.as_slice());

        // Every byte is load-bearing: flipping any one of the six changes it.
        for i in 0..6 {
            let mut bytes = *fp.as_bytes();
            bytes[i] ^= 0x01;
            assert_ne!(
                Fingerprint(bytes).lifehash(),
                fp.lifehash(),
                "byte {i} of the digest does not reach the picture"
            );
        }
    }

    // TEST-102 negative-output: one bit of *input* change changes the picture.
    #[test]
    fn one_bit_of_input_change_changes_the_picture() {
        let mut pk = [0u8; 32];
        let a = fingerprint_key(&pk).lifehash();
        pk[31] = 1;
        assert_ne!(a, fingerprint_key(&pk).lifehash());
    }

    // TEST-104 negative-output: the domain separation survives the rendering.
    // If it did not, an attacker controlling one input could make the phone's
    // picture and the client's picture agree while the identities differ.
    #[test]
    fn the_two_domains_produce_different_pictures() {
        let did = "did:crdt:".to_owned() + &"9f3a".repeat(16);
        let mut as_key = [0u8; 32];
        as_key.copy_from_slice(&did.as_bytes()[..32]);
        assert_ne!(fingerprint_key(&as_key).lifehash(), fingerprint_did(&did).lifehash());
    }

    // CON-101: the transport encoding is exactly 4096 characters and decodes
    // back to the pixels — the roundtrip CON-102's grammar depends on.
    #[test]
    fn base64_is_four_thousand_and_ninety_six_characters_and_roundtrips() {
        use base64ct::{Base64, Encoding as _};
        let lh = fingerprint_key(&[7u8; 32]).lifehash();
        let encoded = lh.base64();
        assert_eq!(encoded.len(), 4096, "CON-102's grammar fixes the length");
        let decoded = Base64::decode_vec(&encoded).expect("our own encoder round-trips");
        assert_eq!(decoded.as_slice(), lh.rgb().as_slice());
    }

    #[test]
    fn pixel_agrees_with_the_raw_buffer() {
        let lh = fingerprint_key(&[9u8; 32]).lifehash();
        for (x, y) in [(0, 0), (31, 31), (5, 17), (31, 0)] {
            let i = (y * LifeHash::SIDE + x) * 3;
            let rgb = lh.rgb();
            assert_eq!(lh.pixel(x, y), (rgb[i], rgb[i + 1], rgb[i + 2]));
        }
    }

    // TEST-106 negative-output (NFR-102): two *different* fingerprints sharing
    // a picture is a failure.
    //
    // This bounds entropy collapse in the rendering, not injectivity over the
    // whole 2^48 space: a 10^5 corpus would surface roughly five collisions if
    // the picture retained only ~34 bits, and near-certainly catch anything
    // worse, but it says nothing at the 2^48 birthday bound. The weaker claim
    // is the one made in NFR-102 because it is the one tested.
    //
    // SIMPLIFY: 10^5 samples, ~7 s across eight cores. Raise it — or run the
    // `#[ignore]`d million below — if the rendering is ever proposed as a
    // comparison value, which is the ceiling this corpus stops being adequate
    // at (trace: SPEC-002 ADR-107, NFR-102).
    #[test]
    fn distinct_fingerprints_produce_distinct_pictures() {
        assert_no_picture_collision(100_000);
    }

    // The deeper run, for a rendering or dependency change. ~10 minutes.
    #[test]
    #[ignore = "10^6 samples; run explicitly when the picture or its crate changes"]
    fn distinct_fingerprints_produce_distinct_pictures_over_a_million_samples() {
        assert_no_picture_collision(1_000_000);
    }

    fn assert_no_picture_collision(samples: u32) {
        use std::collections::HashMap;

        let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        let chunk = samples.div_ceil(threads as u32);

        // Each worker returns (picture digest, fingerprint) for its slice; the
        // parent merges. Digesting the image keeps the merged map to 38 bytes
        // an entry instead of 3078.
        let pairs: Vec<([u8; 32], [u8; 6])> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..threads)
                .map(|t| {
                    let lo = chunk * t as u32;
                    let hi = (lo + chunk).min(samples);
                    scope.spawn(move || {
                        (lo..hi)
                            .map(|i| {
                                let mut pk = [0u8; 32];
                                pk[..4].copy_from_slice(&i.to_le_bytes());
                                let fp = fingerprint_key(&pk);
                                (*blake3::hash(fp.lifehash().rgb()).as_bytes(), *fp.as_bytes())
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            handles.into_iter().flat_map(|h| h.join().expect("worker did not panic")).collect()
        });

        assert_eq!(pairs.len(), samples as usize, "every sample was rendered");

        let mut seen: HashMap<[u8; 32], [u8; 6]> = HashMap::with_capacity(pairs.len());
        for (picture, fp) in pairs {
            if let Some(previous) = seen.insert(picture, fp) {
                // Equal fingerprints legitimately share a picture; that would be
                // a fingerprint collision, which the hex test above covers.
                assert_eq!(
                    previous, fp,
                    "two distinct fingerprints ({previous:02X?} and {fp:02X?}) paint the same \
                     picture — the rendering is losing entropy the hex still has"
                );
            }
        }
    }

    #[test]
    fn the_wordlists_have_no_duplicates() {
        use std::collections::HashSet;
        assert_eq!(ADJECTIVES.iter().collect::<HashSet<_>>().len(), ADJECTIVES.len());
        assert_eq!(NOUNS.iter().collect::<HashSet<_>>().len(), NOUNS.len());
    }
}
