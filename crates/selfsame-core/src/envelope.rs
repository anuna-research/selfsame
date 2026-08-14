//! `PROTO-004` `CON-501`/`CON-502`/`CON-504` — the ceremony envelope.
//!
//! What travels between the browser and the wallet after `PROTO-003` confirms:
//! one AEAD, two role-separated single-use keys, a constant nonce, and a record
//! that is **always exactly 69,632 octets**.
//!
//! # Why every record is the same length
//!
//! `REQ-505` forbids cleartext ceremony metadata, and a length is metadata. A
//! bundle that inlines a `did:crdt` closure is larger than one that does not, and
//! closure size tracks a DID's delta history — so a variable-length record would
//! hand the mailbox operator a per-account fingerprint it never has to ask for.
//! `ADR-504` chose one length over a ladder of buckets because a bucket boundary
//! is still a disclosure, just a coarser one.
//!
//! The padding therefore lives **inside** the sealed plaintext, behind a
//! `U32BE` length prefix:
//!
//! ```text
//!   plaintext = U32BE(len(json)) ‖ json ‖ 0x00 × (69,607 − len(json))
//!             = exactly 69,611 octets, for every record, always
//!   sealed    = "SSE1" ‖ role ‖ ChaCha20-Poly1305(plaintext)
//!             = exactly 69,632 octets
//! ```
//!
//! The prefix is never visible to an operator, so it is not the
//! "length-revealing padding marker" `REQ-505` rules out. It exists because
//! `CON-503` step 6 requires the payload to re-serialize byte-for-byte with no
//! trailing content, and bare trailing padding would break that.
//!
//! **Verifying the padding is required, not advisory.** Unverified padding is a
//! covert channel between two endpoints that have already authenticated each
//! other, and a source of the implementation divergence the byte-identity of
//! `TEST-506` would then fail on.
//!
//! # Why the nonce is twelve zero octets
//!
//! Because each key seals exactly one plaintext. `REQ-502` is what makes a
//! constant nonce safe, so [`EnvelopeKey::seal`] **consumes the key** — the same
//! idiom [`crate::spake2::Confirmed::verify_peer`] uses, and for the same reason:
//! a rule the type system keeps cannot be forgotten under a retry path. A caller
//! that must retry a transport write retries it with the octets it already
//! holds, which are byte-identical because the construction is deterministic.
//!
//! # What is here and what is next door
//!
//! This module recognises the *envelope*. `CON-503` recognises the *payload*,
//! against a member set the enclosing profile owns — `SPEC-004`'s, in
//! `selfsame_app_identity::ceremony`. The split is `ADR-502`'s: one envelope
//! serves every ceremony record precisely because it does not know what is in
//! them.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// `MAGIC`, whose fourth octet carries the version. There is no separate version
/// field to parse: a record not beginning `SSE1` is rejected.
const MAGIC: &[u8; 4] = b"SSE1";

/// The largest RFC 8785 JSON payload a record can carry (`CON-502`).
///
/// It agrees with `selfsame_app_identity::ceremony::MAX_PAYLOAD_OCTETS`, which is
/// the same bound stated by the enclosing profile. Stated again here rather than
/// imported because this crate is below that one and the envelope's frame
/// arithmetic is fixed by `PROTO-004` alone.
pub const MAX_PAYLOAD_OCTETS: usize = 69_607;

/// The framed plaintext: `U32BE` prefix plus the padded payload region.
pub const FRAME_OCTETS: usize = 4 + MAX_PAYLOAD_OCTETS;

/// The one valid sealed-record length: header, ciphertext, Poly1305 tag.
pub const SEALED_OCTETS: usize = 5 + FRAME_OCTETS + 16;

const OFFER_INFO: &[u8] = b"selfsame-envelope-v1/offer";
const BUNDLE_INFO: &[u8] = b"selfsame-envelope-v1/bundle";

/// Which record a key seals, and the octet that says so on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Sealed by the application, opened by the wallet. Role octet `0x01`.
    Offer,
    /// Sealed by the wallet, opened by the application. Role octet `0x02`.
    Bundle,
}

impl Role {
    fn octet(self) -> u8 {
        match self {
            Role::Offer => 0x01,
            Role::Bundle => 0x02,
        }
    }

    fn info(self) -> &'static [u8] {
        match self {
            Role::Offer => OFFER_INFO,
            Role::Bundle => BUNDLE_INFO,
        }
    }
}

/// Why an envelope operation was refused (`CON-504`).
///
/// Three variants, not six. The other two in `CON-504`'s table —
/// `EnvelopeKeyUnavailable` and `EnvelopeReseal` — are statements about ceremony
/// *state*, which this module deliberately does not hold: the first is
/// unreachable because a key cannot be constructed without a
/// [`crate::spake2::Mutual`]'s mailbox secret, and the second is unreachable
/// because [`EnvelopeKey::seal`] consumes the key. `PayloadMalformed` belongs to
/// `CON-503`, which is the enclosing profile's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    /// The header, role octet, or record length fails the `CON-502` grammar, or
    /// the opened frame has an out-of-range length prefix or non-zero padding.
    #[error("the record is not a PROTO-004 envelope")]
    Malformed,
    /// The AEAD tag did not verify — for any reason, and the reason is not
    /// reported. A wrong key, a wrong `binding_hash`, a wrong role, a truncated
    /// record and a mutated ciphertext are one outcome here on purpose.
    #[error("the record did not authenticate")]
    AuthFailed,
    /// The JSON offered for sealing exceeds `CON-502`'s bound.
    #[error("the payload exceeds the envelope's bound")]
    PayloadTooLarge,
}

/// The two keys `CON-501` derives, once per ceremony, by both endpoints.
pub struct EnvelopeKeys {
    /// Seals the offer; the wallet opens with it and never seals with it.
    pub offer: EnvelopeKey,
    /// Seals the bundle; the application opens with it and never seals with it.
    pub bundle: EnvelopeKey,
}

impl EnvelopeKeys {
    /// Derive both keys from `CON-408`'s mailbox secret and `CON-403`'s binding.
    ///
    /// These are the only two admissible inputs. `CON-501` names what an endpoint
    /// SHALL NOT derive an envelope key from — a pairing word, `wib`, the human
    /// code, a nameplate, a role token, a `PROTO-002` slot name, or the
    /// *unconfirmed* SPAKE2 key `K` — and the type system carries the last of
    /// those: `mailbox_secret_16` is reachable only from
    /// [`crate::spake2::Mutual`], which is reachable only through
    /// [`crate::spake2::Confirmed::verify_peer`].
    ///
    /// Returns [`EnvelopeError::Malformed`] if the two keys come out equal.
    /// `CON-501` requires an implementation that finds them equal to abort, and
    /// the honest way to hold a requirement you believe is unreachable is to let
    /// it fail rather than to comment that it cannot.
    pub fn derive(
        mailbox_secret_16: &[u8; 16],
        binding_hash: &[u8; 32],
    ) -> Result<Self, EnvelopeError> {
        let offer = EnvelopeKey::derive(Role::Offer, mailbox_secret_16, binding_hash);
        let bundle = EnvelopeKey::derive(Role::Bundle, mailbox_secret_16, binding_hash);
        if offer.key == bundle.key {
            return Err(EnvelopeError::Malformed);
        }
        Ok(Self { offer, bundle })
    }
}

/// One role's key, good for exactly one seal.
pub struct EnvelopeKey {
    key: [u8; 32],
    role: Role,
    binding_hash: [u8; 32],
}

impl EnvelopeKey {
    fn derive(role: Role, mailbox_secret_16: &[u8; 16], binding_hash: &[u8; 32]) -> Self {
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(binding_hash), mailbox_secret_16)
            .expand(role.info(), &mut key)
            .expect("32 octets is a valid HKDF output length");
        Self { key, role, binding_hash: *binding_hash }
    }

    /// Which record this key is for. Structural, so an endpoint cannot reach for
    /// "the other role's key on failure", which `CON-502` forbids.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Frame, pad, and seal one payload — consuming the key (`REQ-502`).
    pub fn seal(self, payload_octets: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        if payload_octets.is_empty() || payload_octets.len() > MAX_PAYLOAD_OCTETS {
            return Err(EnvelopeError::PayloadTooLarge);
        }

        let mut plaintext = Vec::with_capacity(FRAME_OCTETS);
        plaintext.extend_from_slice(&(payload_octets.len() as u32).to_be_bytes());
        plaintext.extend_from_slice(payload_octets);
        plaintext.resize(FRAME_OCTETS, 0x00);

        let header = self.header();
        let sealed = cipher(&self.key)
            .encrypt(
                &nonce(),
                Payload { msg: &plaintext, aad: &aad(&header, &self.binding_hash) },
            )
            .expect("ChaCha20-Poly1305 encryption is infallible for in-memory buffers");
        plaintext.zeroize();

        let mut record = Vec::with_capacity(SEALED_OCTETS);
        record.extend_from_slice(&header);
        record.extend_from_slice(&sealed);
        debug_assert_eq!(record.len(), SEALED_OCTETS);
        Ok(record)
    }

    /// Open a record of *this* key's role, returning the payload octets alone.
    ///
    /// The length prefix and the padding are removed here and the padding is
    /// verified here, so what `CON-503` receives is the JSON and nothing else.
    pub fn open(&self, sealed_record: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        // Length before anything else: "a record shorter or longer than 69,632
        // octets is rejected before any AEAD operation."
        if sealed_record.len() != SEALED_OCTETS {
            return Err(EnvelopeError::Malformed);
        }
        if &sealed_record[..4] != MAGIC {
            return Err(EnvelopeError::Malformed);
        }
        let role_octet = sealed_record[4];
        if role_octet != 0x01 && role_octet != 0x02 {
            return Err(EnvelopeError::Malformed);
        }
        // A grammatically valid record for the OTHER direction. Refused without
        // attempting the AEAD, because `CON-502` says an endpoint "SHALL NOT
        // attempt the opposite role's key on failure" — and reported as an
        // authentication failure, which is the outcome the tag would have given
        // anyway since the role octet is inside the associated data.
        if role_octet != self.role.octet() {
            return Err(EnvelopeError::AuthFailed);
        }

        let header = self.header();
        let plaintext = cipher(&self.key)
            .decrypt(
                &nonce(),
                Payload {
                    msg: &sealed_record[5..],
                    aad: &aad(&header, &self.binding_hash),
                },
            )
            .map_err(|_| EnvelopeError::AuthFailed)?;
        if plaintext.len() != FRAME_OCTETS {
            return Err(EnvelopeError::Malformed);
        }

        let n = u32::from_be_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]])
            as usize;
        if n == 0 || n > MAX_PAYLOAD_OCTETS {
            return Err(EnvelopeError::Malformed);
        }
        // REQUIRED, not advisory. The frame is authenticated by the tag at this
        // point, so refusing it here discloses nothing to an attacker who did not
        // already hold the key.
        if plaintext[4 + n..].iter().any(|&b| b != 0x00) {
            return Err(EnvelopeError::Malformed);
        }
        Ok(plaintext[4..4 + n].to_vec())
    }

    fn header(&self) -> [u8; 5] {
        let mut header = [0u8; 5];
        header[..4].copy_from_slice(MAGIC);
        header[4] = self.role.octet();
        header
    }
}

/// `CON-501`: zeroized at the earlier of ceremony completion and abandonment.
/// Dropping the key is both of those.
impl Drop for EnvelopeKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Twelve `0x00` octets — safe only because each key seals once.
fn nonce() -> Nonce {
    *Nonce::from_slice(&[0u8; 12])
}

/// `aad = header ‖ binding_hash`, exactly 37 octets.
fn aad(header: &[u8; 5], binding_hash: &[u8; 32]) -> [u8; 37] {
    let mut aad = [0u8; 37];
    aad[..5].copy_from_slice(header);
    aad[5..].copy_from_slice(binding_hash);
    aad
}

fn cipher(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(Key::from_slice(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 16] = [
        0x9f, 0x3a, 0x11, 0xc2, 0xe7, 0x0b, 0x4d, 0x8a, 0x5c, 0x6f, 0x90, 0x12, 0xab, 0x34, 0xcd,
        0x56,
    ];
    const BINDING: [u8; 32] = [0x5a; 32];

    fn keys() -> EnvelopeKeys {
        EnvelopeKeys::derive(&SECRET, &BINDING).unwrap()
    }

    /// TEST-502 positive: what the wallet seals, the application opens.
    #[test]
    fn a_record_round_trips_under_its_own_role() {
        let payload = br#"{"role":"bundle"}"#;
        let sealed = keys().bundle.seal(payload).unwrap();
        assert_eq!(keys().bundle.open(&sealed).unwrap(), payload);
    }

    /// `CON-502`: "**Every sealed record is exactly 69,632 octets**".
    #[test]
    fn every_record_is_the_same_length_whatever_it_carries() {
        let one = keys().offer.seal(b"{}").unwrap();
        let big = keys().offer.seal(&vec![b'x'; MAX_PAYLOAD_OCTETS]).unwrap();
        assert_eq!(one.len(), SEALED_OCTETS);
        assert_eq!(big.len(), SEALED_OCTETS);
        assert_eq!(one.len(), big.len(), "length would otherwise be metadata");
        assert_eq!(&one[..5], b"SSE1\x01");
    }

    /// TEST-505: the operator sees a header and 69,627 octets of noise.
    #[test]
    fn nothing_of_the_payload_survives_into_the_clear() {
        let sealed = keys().offer.seal(br#"{"applicationId":"https://chat.example"}"#).unwrap();
        assert!(!sealed.windows(4).any(|w| w == b"chat"));
    }

    /// TEST-503 / REQ-502: the same input yields the same octets, which is what
    /// makes a transport retry a retry rather than a second plaintext.
    #[test]
    fn sealing_is_deterministic() {
        assert_eq!(keys().offer.seal(b"{}").unwrap(), keys().offer.seal(b"{}").unwrap());
    }

    /// TEST-502 negative-input: every single-bit mutation is refused.
    #[test]
    fn a_mutated_record_never_opens() {
        let sealed = keys().offer.seal(b"{}").unwrap();
        for i in [0, 3, 4, 5, 100, SEALED_OCTETS - 1] {
            let mut broken = sealed.clone();
            broken[i] ^= 0x01;
            assert!(keys().offer.open(&broken).is_err(), "octet {i} was not load-bearing");
        }
    }

    /// `CON-502`: rejected "before any AEAD operation".
    #[test]
    fn a_record_of_any_other_length_is_malformed() {
        let sealed = keys().offer.seal(b"{}").unwrap();
        for len in [0, 5, SEALED_OCTETS - 1] {
            assert_eq!(keys().offer.open(&sealed[..len]), Err(EnvelopeError::Malformed));
        }
        let mut long = sealed.clone();
        long.push(0);
        assert_eq!(keys().offer.open(&long), Err(EnvelopeError::Malformed));
    }

    /// The two directions cannot be crossed, and the opposite key is not tried.
    ///
    /// This one passes on `CON-501`'s key separation alone — deleting the role
    /// octet from the associated data leaves it green, which is why it is not the
    /// only test of the role binding. See
    /// [`the_role_octet_is_inside_the_associated_data`].
    #[test]
    fn an_offer_record_does_not_open_as_a_bundle() {
        let offer = keys().offer.seal(b"{}").unwrap();
        assert_eq!(keys().bundle.open(&offer), Err(EnvelopeError::AuthFailed));
        let bundle = keys().bundle.seal(b"{}").unwrap();
        assert_eq!(keys().offer.open(&bundle), Err(EnvelopeError::AuthFailed));
    }

    /// `CON-502`: `aad = header ‖ binding_hash`, and the header carries the role.
    ///
    /// Isolated from key separation by holding the key material *identical* and
    /// varying only the role. Without that the clause is untestable in practice:
    /// `K_offer` and `K_bundle` already differ, so every natural cross-role case
    /// is refused before the associated data is ever consulted, and an
    /// implementation that dropped the role octet would look correct while
    /// producing tags no other implementation reproduces (`TEST-506`).
    #[test]
    fn the_role_octet_is_inside_the_associated_data() {
        let as_offer = EnvelopeKey { key: [7u8; 32], role: Role::Offer, binding_hash: BINDING };
        let as_bundle = EnvelopeKey { key: [7u8; 32], role: Role::Bundle, binding_hash: BINDING };
        let one = as_offer.seal(b"{}").unwrap();
        let other = as_bundle.seal(b"{}").unwrap();
        assert_ne!(one[5..], other[5..], "the role octet is not authenticated");

        // And the binding hash likewise, holding both key and role fixed.
        let mut elsewhere = BINDING;
        elsewhere[0] ^= 0xff;
        let same_key_other_ceremony =
            EnvelopeKey { key: [7u8; 32], role: Role::Offer, binding_hash: elsewhere };
        assert_ne!(
            EnvelopeKey { key: [7u8; 32], role: Role::Offer, binding_hash: BINDING }
                .seal(b"{}")
                .unwrap()[5..],
            same_key_other_ceremony.seal(b"{}").unwrap()[5..],
            "the binding hash is not authenticated",
        );
    }

    /// `CON-502`'s grammar is `role = %x01 / %x02`, so a third value is not a
    /// wrong-direction record — it is not a record.
    #[test]
    fn an_unknown_role_octet_is_malformed_rather_than_unauthenticated() {
        let mut sealed = keys().offer.seal(b"{}").unwrap();
        sealed[4] = 0x03;
        assert_eq!(keys().offer.open(&sealed), Err(EnvelopeError::Malformed));
        sealed[4] = 0x02;
        assert_eq!(keys().offer.open(&sealed), Err(EnvelopeError::AuthFailed));
    }

    /// The construction, pinned end to end.
    ///
    /// Every previous test would survive a change to the HKDF labels, the
    /// constant nonce, the magic, or the frame layout, because each of those
    /// changes both sides at once. This one does not, which is the only way a
    /// second implementation can be held to the same octets.
    ///
    /// **Provisional.** `PROTO-004` `TEST-501` and `TEST-506` require vectors
    /// published with the specification and reproduced by an independent stack;
    /// none exist yet, so this pins *this* build against silent drift and is not
    /// evidence of interoperability. Replacing it with the published vectors is
    /// the `Tier-1` gate's, not this test's.
    #[test]
    fn the_construction_is_pinned() {
        let k = keys();
        assert_eq!(
            hex(&k.offer.key),
            "e6885be7dc2babda5fd37326f6189623befe0e958e2ddcd4e969117c0da52165",
        );
        assert_eq!(
            hex(&k.bundle.key),
            "19dc329b31facd2960b1e841805147a8b9adda25452c0a6369662f4eae7ca7fa",
        );
        let sealed = k.offer.seal(b"{}").unwrap();
        assert_eq!(hex(&sealed[..5]), "5353453101");
        assert_eq!(hex(&sealed[5..21]), "3fb261cb825f96b7150872f8f52f89ed");
        assert_eq!(hex(&sealed[sealed.len() - 16..]), "9cad48a39f0ea862b9c3be2275b65520");
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// TEST-504: a record from another ceremony authenticates nowhere.
    #[test]
    fn a_record_from_another_binding_is_refused() {
        let mut other_binding = BINDING;
        other_binding[0] ^= 0xff;
        let theirs = EnvelopeKeys::derive(&SECRET, &other_binding).unwrap();
        let sealed = theirs.offer.seal(b"{}").unwrap();
        assert_eq!(keys().offer.open(&sealed), Err(EnvelopeError::AuthFailed));

        let mut other_secret = SECRET;
        other_secret[0] ^= 0xff;
        let elsewhere = EnvelopeKeys::derive(&other_secret, &BINDING).unwrap();
        assert_eq!(keys().offer.open(&elsewhere.offer.seal(b"{}").unwrap()), Err(EnvelopeError::AuthFailed));
    }

    /// `CON-502`: the padding check is REQUIRED, not advisory.
    ///
    /// This is the test the covert channel lives or dies by, so it is built the
    /// only way that proves anything: seal a frame whose padding is *not* zero,
    /// under a real key, so the tag verifies and the refusal can come from
    /// nowhere but the padding check itself.
    #[test]
    fn non_zero_padding_is_refused_even_when_the_tag_verifies() {
        let key = EnvelopeKey::derive(Role::Offer, &SECRET, &BINDING);
        let mut plaintext = vec![0u8; FRAME_OCTETS];
        plaintext[..4].copy_from_slice(&2u32.to_be_bytes());
        plaintext[4] = b'{';
        plaintext[5] = b'}';
        // One octet of smuggled data, well past the payload.
        plaintext[9_000] = 0x01;

        let sealed = seal_frame_verbatim(&key, &plaintext);
        assert_eq!(key.open(&sealed), Err(EnvelopeError::Malformed));

        // And with that octet cleared, the very same construction opens — so the
        // refusal above is the padding and not some other property of the frame.
        plaintext[9_000] = 0x00;
        assert_eq!(key.open(&seal_frame_verbatim(&key, &plaintext)).unwrap(), b"{}");
    }

    /// `CON-502`: `require 1 <= n <= 69,607`.
    #[test]
    fn an_out_of_range_length_prefix_is_refused() {
        let key = EnvelopeKey::derive(Role::Bundle, &SECRET, &BINDING);
        for n in [0u32, (MAX_PAYLOAD_OCTETS + 1) as u32, u32::MAX] {
            let mut plaintext = vec![0u8; FRAME_OCTETS];
            plaintext[..4].copy_from_slice(&n.to_be_bytes());
            assert_eq!(
                key.open(&seal_frame_verbatim(&key, &plaintext)),
                Err(EnvelopeError::Malformed),
                "length prefix {n}",
            );
        }
    }

    /// A payload of zero octets, or one past the bound, is refused at sealing.
    #[test]
    fn the_payload_bound_is_enforced_at_the_sealing_end_too() {
        assert_eq!(keys().offer.seal(b""), Err(EnvelopeError::PayloadTooLarge));
        assert_eq!(
            keys().offer.seal(&vec![b'x'; MAX_PAYLOAD_OCTETS + 1]),
            Err(EnvelopeError::PayloadTooLarge),
        );
    }

    /// `CON-501`: the two keys are distinct, and neither is the mailbox secret
    /// nor the `PROTO-002` slot input.
    #[test]
    fn the_two_keys_are_distinct_and_domain_separated() {
        let k = keys();
        assert_ne!(k.offer.key, k.bundle.key);
        assert_ne!(&k.offer.key[..16], &SECRET[..]);
        // Changing only the salt changes both.
        let mut other_binding = BINDING;
        other_binding[31] ^= 1;
        let elsewhere = EnvelopeKeys::derive(&SECRET, &other_binding).unwrap();
        assert_ne!(k.offer.key, elsewhere.offer.key);
        assert_ne!(k.bundle.key, elsewhere.bundle.key);
    }

    /// Seal a frame exactly as given, bypassing [`EnvelopeKey::seal`]'s framing.
    ///
    /// Test-only, and the reason the padding and length-prefix tests are worth
    /// anything: a hostile *peer* can construct these frames, because it holds
    /// the key. Building them by mutating a well-formed record would only ever
    /// produce an `AuthFailed`, which would leave both checks untested while
    /// looking tested.
    fn seal_frame_verbatim(key: &EnvelopeKey, plaintext: &[u8]) -> Vec<u8> {
        let header = key.header();
        let sealed = cipher(&key.key)
            .encrypt(&nonce(), Payload { msg: plaintext, aad: &aad(&header, &key.binding_hash) })
            .unwrap();
        let mut record = header.to_vec();
        record.extend_from_slice(&sealed);
        record
    }
}

