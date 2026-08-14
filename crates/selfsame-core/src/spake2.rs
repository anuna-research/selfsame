//! `PROTO-003` `CON-404` — the SPAKE2 ristretto255 ciphersuite, and `CON-408`.
//!
//! # This is a port, not a design
//!
//! `CON-404` says so itself:
//!
//! > This construction deliberately uses the same M/N derivation and word-index
//! > packing implemented by the existing Hark/cbcl-bus primitive, with distinct
//! > Selfsame KDF and confirmation labels plus the binding identities in
//! > `CON-403`.
//!
//! The primitive it names is real and vetted: `cbcl-crypto-spake2` (the hub
//! responder, over libsodium ristretto255) and `hark/src/pairing/spake2.rs` (the
//! agent initiator, over curve25519-dalek), pinned against each other by
//! cross-stack known-answer vectors. The group, the M/N derivation, the `w`
//! schedule, the `LV` transcript framing, the HKDF and the HMACs here are all
//! that construction. What differs is the domain labels — every one carries
//! `v2` — and the identities, which come from `CON-403`'s binding object.
//!
//! Writing it a third time was the alternative and would have been worse: three
//! implementations of one ciphersuite is two chances to disagree.
//!
//! # It is stricter than the primitive it ports
//!
//! `CON-404` requires two checks the SPEC-016 implementation does not make, and
//! they are not optional here:
//!
//! * **the identity element is rejected**, for a received peer value and for a
//!   derived `Z`. A peer that sends `w*M` (or `w*N`) drives `Z` to the identity
//!   for a `w` it can compute offline, which turns the shared secret into a
//!   constant the attacker also knows.
//! * **a zero scalar is refused rather than used.** The contract says each role
//!   draws 64 fresh octets and redraws if the reduction is zero; a zero `x`
//!   makes `pA = w*M`, which is the same attack committed by accident.
//!
//! # `K` cannot be reached before mutual confirmation
//!
//! `CON-404` ends: *"`K` is internal key material and is released to `CON-408`
//! only after the state machine's mutual confirmation rule."* That is enforced
//! by the types rather than by a comment — [`Confirmed`] can produce this
//! endpoint's MAC and check the peer's, and only [`Mutual`], which
//! [`Confirmed::verify_peer`] alone returns, can derive the mailbox secret.
//! There is no accessor for `K` at any stage.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::IsIdentity,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// The password input: `CON-403`'s `wib = C`, exactly 16 octets.
pub const WIB_OCTETS: usize = 16;

/// The mailbox secret `CON-408` composes, 128 bits.
pub const MAILBOX_SECRET_OCTETS: usize = 16;

// ── the labels, every one of which is `v2` ──────────────────────────────────
//
// `ADR-406` changed `wib` from three octets to sixteen, and every label carries
// `v2` so that a version-1 and a version-2 implementation cannot derive a common
// `w`, `K`, or confirmation MAC from the same input. A downgrade attempt fails
// as a mismatch rather than succeeding weakly.
const ID_A_PREFIX: &[u8] = b"selfsame-pairing-v2/application/";
const ID_B_PREFIX: &[u8] = b"selfsame-pairing-v2/wallet/";
const MAILBOX_INFO: &[u8] = b"selfsame-rendezvous-secret-v1";

/// The four domain labels, gathered so the CONSTRUCTION can be exercised apart
/// from them.
///
/// `PROTO_003` is the only suite this module exposes and the only one any caller
/// can reach. The reason the labels are a value rather than four constants is the
/// test at the bottom of this file: `CON-404` claims this is the same
/// construction as the existing Hark/cbcl-bus primitive with different labels,
/// and the honest way to check a claim of that shape is to run it under the OTHER
/// labels and reproduce that primitive's published vectors. A comment asserting
/// the constructions match would be the same claim with no evidence.
struct Suite {
    w_salt: &'static [u8],
    w_info: &'static [u8],
    sk_info: &'static [u8],
    confirm_a: &'static [u8],
    confirm_b: &'static [u8],
}

impl Suite {
    const PROTO_003: Self = Self {
        w_salt: b"selfsame-pairing-v2",
        w_info: b"selfsame-pairing-password-v2",
        sk_info: b"selfsame-pairing-session-key-v2",
        confirm_a: b"selfsame-pairing-application-confirm-v2",
        confirm_b: b"selfsame-pairing-wallet-confirm-v2",
    };

    /// SPEC-016's pairing labels — the ones `cbcl-chat-pairing` and
    /// `hark/src/pairing/spake2.rs` use. Test-only, and MUST stay that way: a
    /// Selfsame ceremony run under them would be `CON-404`'s downgrade.
    #[cfg(test)]
    const SPEC_016: Self = Self {
        w_salt: b"cbcl-chat-pair-v1",
        w_info: b"cbcl-chat-pair-password-v1",
        sk_info: b"cbcl-chat-pair-session-key-v1",
        confirm_a: b"cbcl-chat-pair-agent-confirm",
        confirm_b: b"cbcl-chat-pair-hub-confirm",
    };

    fn confirm_label(&self, party: Party) -> &'static [u8] {
        match party {
            Party::Application => self.confirm_a,
            Party::Wallet => self.confirm_b,
        }
    }
}

// The CFRG reference strings, hashed to the group. Nothing up either sleeve.
const M_SEED: &[u8] = b"SPAKE2 M Ristretto Curve25519 SHA-512 Hash v1";
const N_SEED: &[u8] = b"SPAKE2 N Ristretto Curve25519 SHA-512 Hash v1";

/// Which party this endpoint is.
///
/// `CON-403`: *"The identity labels name the **party**, not who started the
/// ceremony."* Either may initiate, so this is not "initiator" and "responder" —
/// the application is always A and the wallet is always B, whoever moves first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Party {
    /// The adopting application's client — the browser, here.
    Application,
    /// The wallet holding the account's recovery secret — the phone.
    Wallet,
}

impl Party {
    fn peer(self) -> Self {
        match self {
            Party::Application => Party::Wallet,
            Party::Wallet => Party::Application,
        }
    }

    /// The mask this party adds to its own message: `M` for A, `N` for B.
    fn mask(self) -> RistrettoPoint {
        match self {
            Party::Application => from_seed(M_SEED),
            Party::Wallet => from_seed(N_SEED),
        }
    }
}

/// Why a pairing step was refused.
///
/// Deliberately coarse about *which* element failed: a peer learning whether its
/// point was non-canonical, the identity, or simply wrong is a distinction it can
/// use, and none of them is recoverable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Spake2Error {
    /// The peer's 32 octets are not a canonical, non-identity ristretto255
    /// element — or the shared point they produce is the identity.
    #[error("the peer value is not an admissible ristretto255 element")]
    InvalidPeerElement,
    /// The supplied ephemeral octets reduce to the zero scalar. `CON-404` says
    /// to redraw; the caller owns the CSPRNG, so the caller redraws.
    #[error("the ephemeral scalar is zero — draw 64 fresh octets and retry")]
    ZeroEphemeral,
    /// The peer's confirmation MAC did not verify.
    #[error("the peer confirmation did not verify")]
    ConfirmationMismatch,
}

fn from_seed(seed: &[u8]) -> RistrettoPoint {
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&Sha512::digest(seed));
    RistrettoPoint::from_uniform_bytes(&wide)
}

fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out)
        .expect("an output length under 255 * 32 octets");
}

/// `LV(x) = U64LE(len(x)) || x`, the transcript framing `CON-404` fixes.
fn lv(out: &mut Vec<u8>, x: &[u8]) {
    out.extend_from_slice(&(x.len() as u64).to_le_bytes());
    out.extend_from_slice(x);
}

fn mac(key: &[u8; 32], label: &[u8], transcript: &[u8; 32]) -> [u8; 32] {
    let mut hmac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    hmac.update(label);
    hmac.update(transcript);
    hmac.finalize().into_bytes().into()
}

/// `CON-403`'s two identities, derived from the binding hash.
fn identities(binding_hash: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let mut a = ID_A_PREFIX.to_vec();
    a.extend_from_slice(binding_hash);
    let mut b = ID_B_PREFIX.to_vec();
    b.extend_from_slice(binding_hash);
    (a, b)
}

/// One endpoint, between drawing its ephemeral and receiving the peer's value.
pub struct Pairing {
    suite: &'static Suite,
    party: Party,
    id_a: Vec<u8>,
    id_b: Vec<u8>,
    binding_hash: [u8; 32],
    w: Scalar,
    w_bytes: [u8; 64],
    secret: Scalar,
    ours: [u8; 32],
}

impl Pairing {
    /// Begin, from the password and 64 fresh CSPRNG octets.
    ///
    /// `binding_hash` is `CON-403`'s — `SHA256(RFC8785(binding_object))` — and is
    /// taken rather than computed here because the object it hashes is a
    /// `SPEC-004` value and this crate is the ciphersuite. Both parties must
    /// already hold every member of it: *"Both parties MUST hold every member
    /// below before either processes a peer frame."*
    pub fn begin(
        party: Party,
        wib: &[u8; WIB_OCTETS],
        binding_hash: &[u8; 32],
        ephemeral: &[u8; 64],
    ) -> Result<Self, Spake2Error> {
        let (id_a, id_b) = identities(binding_hash);
        Self::begin_with(&Suite::PROTO_003, party, wib, id_a, id_b, *binding_hash, ephemeral)
    }

    /// The construction, apart from the labels and identities. See [`Suite`].
    fn begin_with(
        suite: &'static Suite,
        party: Party,
        wib: &[u8],
        id_a: Vec<u8>,
        id_b: Vec<u8>,
        binding_hash: [u8; 32],
        ephemeral: &[u8; 64],
    ) -> Result<Self, Spake2Error> {
        let mut w_bytes = [0u8; 64];
        hkdf_sha256(wib, suite.w_salt, suite.w_info, &mut w_bytes);
        let w = Scalar::from_bytes_mod_order_wide(&w_bytes);

        let secret = Scalar::from_bytes_mod_order_wide(ephemeral);
        // Refused, not silently used. See the module header.
        if secret == Scalar::ZERO {
            w_bytes.zeroize();
            return Err(Spake2Error::ZeroEphemeral);
        }

        // pA = x*B + w*M   (application)      pB = y*B + w*N   (wallet)
        let ours = (RISTRETTO_BASEPOINT_TABLE * &secret + w * party.mask())
            .compress()
            .to_bytes();

        Ok(Self {
            suite,
            party,
            id_a,
            id_b,
            binding_hash,
            w,
            w_bytes,
            secret,
            ours,
        })
    }

    /// This endpoint's wire value — `pA` or `pB`, always exactly 32 octets.
    pub fn message(&self) -> [u8; 32] {
        self.ours
    }

    /// Consume the peer's value and reach the confirmation stage.
    ///
    /// The peer's mask is the OTHER party's: A subtracts `w*N` from what the
    /// wallet sent, B subtracts `w*M`. Using one's own mask here would make both
    /// endpoints compute different `Z` from an honest exchange, which presents as
    /// an unfailing confirmation mismatch.
    pub fn confirm(mut self, peer_message: &[u8; 32]) -> Result<Confirmed, Spake2Error> {
        let peer = CompressedRistretto(*peer_message)
            .decompress()
            .ok_or(Spake2Error::InvalidPeerElement)?;
        if peer.is_identity() {
            return Err(Spake2Error::InvalidPeerElement);
        }

        let shared = self.secret * (peer - self.w * self.party.peer().mask());
        if shared.is_identity() {
            return Err(Spake2Error::InvalidPeerElement);
        }
        let z = shared.compress().to_bytes();

        // The transcript is ordered by PARTY, never by who sent first: idA, idB,
        // pA, pB. An endpoint that framed it in arrival order would agree with
        // itself and with nobody else.
        let (p_a, p_b) = match self.party {
            Party::Application => (self.ours, *peer_message),
            Party::Wallet => (*peer_message, self.ours),
        };
        let mut transcript = Vec::new();
        lv(&mut transcript, &self.id_a);
        lv(&mut transcript, &self.id_b);
        lv(&mut transcript, &p_a);
        lv(&mut transcript, &p_b);
        lv(&mut transcript, &z);
        lv(&mut transcript, &self.w_bytes);
        let tt_hash: [u8; 32] = Sha256::digest(&transcript).into();

        let mut k = [0u8; 32];
        hkdf_sha256(&tt_hash, b"", self.suite.sk_info, &mut k);

        self.w_bytes.zeroize();
        Ok(Confirmed {
            suite: self.suite,
            party: self.party,
            binding_hash: self.binding_hash,
            k,
            tt_hash,
        })
    }
}

/// Both messages exchanged; neither confirmation checked yet.
pub struct Confirmed {
    suite: &'static Suite,
    party: Party,
    binding_hash: [u8; 32],
    k: [u8; 32],
    tt_hash: [u8; 32],
}

impl Confirmed {
    /// The confirmation this endpoint sends — `cA` for the application, `cB` for
    /// the wallet.
    pub fn confirmation(&self) -> [u8; 32] {
        mac(&self.k, self.suite.confirm_label(self.party), &self.tt_hash)
    }

    /// Check the peer's confirmation, in constant time.
    ///
    /// Consuming `self` is the point: there is no way to hold a `Confirmed` that
    /// has *also* verified its peer, so nothing downstream can reach `CON-408`
    /// with only one side confirmed.
    pub fn verify_peer(self, peer_confirmation: &[u8; 32]) -> Result<Mutual, Spake2Error> {
        let expected = mac(&self.k, self.suite.confirm_label(self.party.peer()), &self.tt_hash);
        if expected.ct_eq(peer_confirmation).into() {
            Ok(Mutual {
                binding_hash: self.binding_hash,
                k: self.k,
            })
        } else {
            Err(Spake2Error::ConfirmationMismatch)
        }
    }
}

/// Mutual confirmation reached — the only state from which `K` composes.
pub struct Mutual {
    binding_hash: [u8; 32],
    k: [u8; 32],
}

impl Mutual {
    /// `CON-408` — the 128-bit `PROTO-002` mailbox secret.
    ///
    /// ```text
    /// mailbox_secret_16 = HKDF-SHA256(
    ///   ikm = K, salt = binding_hash,
    ///   info = "selfsame-rendezvous-secret-v1", L = 16)
    /// ```
    ///
    /// This is the whole reason the pairing is not an optional transport choice:
    /// the mailbox key is DOWNSTREAM of the PAKE, so the slot a relay sees is
    /// bound to a code only the two people held. Substituting a CSPRNG value
    /// would remove that binding while leaving the mailbox working.
    pub fn mailbox_secret(&self) -> [u8; MAILBOX_SECRET_OCTETS] {
        let mut secret = [0u8; MAILBOX_SECRET_OCTETS];
        hkdf_sha256(&self.k, &self.binding_hash, MAILBOX_INFO, &mut secret);
        secret
    }
}

impl Drop for Mutual {
    fn drop(&mut self) {
        self.k.zeroize();
    }
}

impl Drop for Confirmed {
    fn drop(&mut self) {
        self.k.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIB: [u8; 16] = [7u8; 16];
    const BINDING: [u8; 32] = [9u8; 32];

    fn ephemeral(seed: u8) -> [u8; 64] {
        // Distinct, deterministic, and non-zero after reduction.
        let mut e = [seed; 64];
        e[0] = seed.wrapping_add(1);
        e
    }

    fn run(wib_a: &[u8; 16], wib_b: &[u8; 16], bind_a: &[u8; 32], bind_b: &[u8; 32])
        -> Result<([u8; 16], [u8; 16]), Spake2Error>
    {
        let a = Pairing::begin(Party::Application, wib_a, bind_a, &ephemeral(1))?;
        let b = Pairing::begin(Party::Wallet, wib_b, bind_b, &ephemeral(2))?;
        let (pa, pb) = (a.message(), b.message());
        let a = a.confirm(&pb)?;
        let b = b.confirm(&pa)?;
        let (ca, cb) = (a.confirmation(), b.confirmation());
        Ok((a.verify_peer(&cb)?.mailbox_secret(), b.verify_peer(&ca)?.mailbox_secret()))
    }

    /// The property the whole ceremony exists for: two endpoints that held the
    /// same code reach the same mailbox, and nobody else does.
    #[test]
    fn two_endpoints_with_the_same_code_agree_on_a_mailbox_secret() {
        let (a, b) = run(&WIB, &WIB, &BINDING, &BINDING).expect("an honest exchange");
        assert_eq!(a, b);
        assert_ne!(a, [0u8; 16], "a mailbox secret is not the zero value");
    }

    /// A wrong code fails at CONFIRMATION, not at the mailbox.
    ///
    /// This is what makes the code low-entropy and still safe: the exchange
    /// completes, both sides derive different keys, and the MAC catches it — one
    /// online guess, which the relay's single-claim rule then burns.
    #[test]
    fn a_different_code_fails_at_confirmation() {
        let wrong = [8u8; 16];
        assert_eq!(run(&WIB, &wrong, &BINDING, &BINDING), Err(Spake2Error::ConfirmationMismatch));
    }

    /// A different binding object is a different ceremony, even with the code.
    ///
    /// `CON-403`: two applications may share a route, provider, number and code;
    /// their different applicationIds still produce different transcripts, keys
    /// and MACs. This is that sentence as a test.
    #[test]
    fn the_same_code_under_a_different_binding_does_not_agree() {
        let other = [10u8; 32];
        assert_eq!(run(&WIB, &WIB, &BINDING, &other), Err(Spake2Error::ConfirmationMismatch));
    }

    /// The identity element is refused from a peer.
    ///
    /// The attack it stops: a peer sending its mask alone drives `Z` to the
    /// identity for a value it can compute offline, so the "shared" secret is a
    /// constant the attacker knows too.
    #[test]
    fn the_identity_element_is_refused() {
        let a = Pairing::begin(Party::Application, &WIB, &BINDING, &ephemeral(1)).unwrap();
        let identity = RistrettoPoint::default().compress().to_bytes();
        // `Confirmed` deliberately has no `Debug` — it holds key material — so the
        // outcome is matched rather than compared.
        assert!(matches!(a.confirm(&identity), Err(Spake2Error::InvalidPeerElement)));
    }

    /// A non-canonical 32 octets is refused rather than clamped.
    #[test]
    fn a_non_canonical_element_is_refused() {
        let a = Pairing::begin(Party::Application, &WIB, &BINDING, &ephemeral(1)).unwrap();
        assert!(matches!(a.confirm(&[0xffu8; 32]), Err(Spake2Error::InvalidPeerElement)));
    }

    /// A zero ephemeral is refused, so the caller redraws.
    #[test]
    fn a_zero_ephemeral_is_refused() {
        assert_eq!(
            Pairing::begin(Party::Application, &WIB, &BINDING, &[0u8; 64]).err(),
            Some(Spake2Error::ZeroEphemeral)
        );
    }

    /// The two parties send different values and expect different confirmations.
    ///
    /// A symmetric implementation that used one mask for both would let an
    /// endpoint complete a ceremony with ITSELF, which is the reflection attack
    /// the M/N split exists to prevent.
    #[test]
    fn the_two_parties_are_not_interchangeable() {
        let a = Pairing::begin(Party::Application, &WIB, &BINDING, &ephemeral(1)).unwrap();
        let b = Pairing::begin(Party::Wallet, &WIB, &BINDING, &ephemeral(1)).unwrap();
        assert_ne!(a.message(), b.message(), "same ephemeral, different mask");

        // Two applications cannot confirm each other.
        let a2 = Pairing::begin(Party::Application, &WIB, &BINDING, &ephemeral(3)).unwrap();
        let m2 = a2.message();
        let a = a.confirm(&m2).unwrap();
        let a2 = a2.confirm(&a.confirmation()[..32].try_into().unwrap());
        // The second confirm consumed a MAC as if it were a point; whether it
        // decodes or not, the ceremony cannot reach mutual confirmation.
        assert!(a2.is_err() || a2.unwrap().verify_peer(&a.confirmation()).is_err());
    }

    /// `CON-408` is a function of both `K` and the binding hash.
    #[test]
    fn the_mailbox_secret_is_bound_to_the_ceremony() {
        let (one, _) = run(&WIB, &WIB, &BINDING, &BINDING).unwrap();
        let other_binding = [11u8; 32];
        let (two, _) = run(&WIB, &WIB, &other_binding, &other_binding).unwrap();
        assert_ne!(one, two, "a different ceremony reaches a different mailbox");
    }

    /// Both wire values are exactly 32 octets, as `CON-404` requires.
    #[test]
    fn every_wire_value_is_thirty_two_octets() {
        let a = Pairing::begin(Party::Application, &WIB, &BINDING, &ephemeral(1)).unwrap();
        let b = Pairing::begin(Party::Wallet, &WIB, &BINDING, &ephemeral(2)).unwrap();
        assert_eq!(a.message().len(), 32);
        assert_eq!(b.message().len(), 32);
        let pb = b.message();
        assert_eq!(a.confirm(&pb).unwrap().confirmation().len(), 32);
    }

    // ── the cross-check that decides whether this is really a port ───────────

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// This construction reproduces the EXISTING primitive's published vectors.
    ///
    /// `CON-404` claims this ciphersuite is *"the same M/N derivation and
    /// word-index packing implemented by the existing Hark/cbcl-bus primitive,
    /// with distinct Selfsame KDF and confirmation labels"*. That is a claim
    /// about two implementations, and the only honest way to check it is to run
    /// THIS code under THOSE labels and see whether it lands on the values that
    /// primitive publishes.
    ///
    /// The vectors are `SPEC-016 REQ-007`'s, carried verbatim from
    /// `cbcl-bus/apps/cbcl_chat/test/fixtures/pairing-vectors.json`, and they
    /// already pin two independent implementations against each other: the LFE
    /// hub responder over libsodium and hark's Rust initiator over
    /// curve25519-dalek. Reproducing them makes this the third.
    ///
    /// If this fails, the Selfsame labels are not the only thing that differs and
    /// the module header's first sentence is false.
    #[test]
    fn the_construction_reproduces_the_existing_primitives_vectors() {
        let vectors: serde_json::Value =
            serde_json::from_slice(include_bytes!("../tests/spec-016-pairing-vectors.json"))
                .expect("the checked-in vectors are JSON");
        let input = &vectors["inputs"];
        let expect = &vectors["outputs"];

        let wib = hex(input["wib_hex"].as_str().unwrap());
        // SPEC-016's identities: idA is the pairing_id's ASCII CHARACTERS — not
        // its decoded octets — and idB is a prefix followed by the hub id.
        // Decoding the hex here reproduced `msg_a` and `msg_b` and then missed
        // `mac_a`, which is exactly the shape of a transcript disagreement:
        // the messages do not depend on the identities and the MACs do.
        let id_a = input["pairing_id"].as_str().unwrap().as_bytes().to_vec();
        let mut id_b = b"cbcl-chat-pair:".to_vec();
        id_b.extend_from_slice(input["hub_id"].as_str().unwrap().as_bytes());

        let agent: [u8; 64] = hex(input["agent_ephemeral_hex"].as_str().unwrap()).try_into().unwrap();
        let hub: [u8; 64] = hex(input["hub_ephemeral_hex"].as_str().unwrap()).try_into().unwrap();

        // The agent is role A and the hub is role B, which is exactly the
        // application/wallet split under different names.
        let a = Pairing::begin_with(&Suite::SPEC_016, Party::Application, &wib,
                                    id_a.clone(), id_b.clone(), [0u8; 32], &agent).unwrap();
        let b = Pairing::begin_with(&Suite::SPEC_016, Party::Wallet, &wib,
                                    id_a, id_b, [0u8; 32], &hub).unwrap();

        assert_eq!(a.message().to_vec(), hex(expect["msg_a_hex"].as_str().unwrap()), "msg_a");
        assert_eq!(b.message().to_vec(), hex(expect["msg_b_hex"].as_str().unwrap()), "msg_b");

        let (pa, pb) = (a.message(), b.message());
        let a = a.confirm(&pb).unwrap();
        let b = b.confirm(&pa).unwrap();

        assert_eq!(a.confirmation().to_vec(), hex(expect["mac_a_hex"].as_str().unwrap()), "mac_a");
        assert_eq!(b.confirmation().to_vec(), hex(expect["mac_b_hex"].as_str().unwrap()), "mac_b");
        // The session key is not exposed — deliberately — so it is checked
        // through the MACs, which are a function of it and of the transcript.
        // Two HMACs agreeing under different labels is what pins K.
    }

    /// The Selfsame labels do NOT reproduce those vectors.
    ///
    /// The other half of the claim: if `PROTO_003` and `SPEC_016` produced the
    /// same values, the `v2` domain separation `ADR-406` requires would not exist
    /// and a downgrade would succeed weakly rather than fail as a mismatch.
    #[test]
    fn the_selfsame_labels_are_domain_separated_from_the_existing_ones() {
        let vectors: serde_json::Value =
            serde_json::from_slice(include_bytes!("../tests/spec-016-pairing-vectors.json")).unwrap();
        let input = &vectors["inputs"];
        let wib = hex(input["wib_hex"].as_str().unwrap());
        let id_a = input["pairing_id"].as_str().unwrap().as_bytes().to_vec();
        let mut id_b = b"cbcl-chat-pair:".to_vec();
        id_b.extend_from_slice(input["hub_id"].as_str().unwrap().as_bytes());
        let agent: [u8; 64] = hex(input["agent_ephemeral_hex"].as_str().unwrap()).try_into().unwrap();

        let under_selfsame = Pairing::begin_with(&Suite::PROTO_003, Party::Application, &wib,
                                                 id_a, id_b, [0u8; 32], &agent).unwrap();
        assert_ne!(
            under_selfsame.message().to_vec(),
            hex(vectors["outputs"]["msg_a_hex"].as_str().unwrap()),
            "the v2 password labels must change w, and therefore pA",
        );
    }

}
