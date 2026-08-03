//! Device proof of possession — `CON-207`, `REQ-206`.
//!
//! A valid credential proves the issuer said something. It does not prove the
//! party presenting it is the device the issuer was talking about. `REQ-206`
//! closes that with one sentence — *"Possession of the VC without the
//! corresponding device private key SHALL confer no access"* — and this contract
//! is how.
//!
//! ```text
//! grant_hash  = SHA-256(grant_bytes)
//!
//! proof_input = UTF8("selfsame/device-possession/v1")
//!            || 0x00
//!            || LP(canonical_application_id)
//!            || LP(canonical_acct_uri)
//!            || nonce_32
//!            || grant_hash
//! ```
//!
//! The device signs `proof_input` with the `cnf.jwk` private key and the
//! verifier checks it with the public half.
//!
//! # What each field is doing
//!
//! Every element is there to stop one specific replay, and the set is worth
//! reading as a list of attacks rather than as a struct:
//!
//! | Element | Without it |
//! |---|---|
//! | domain string + `0x00` | a signature made for another Selfsame protocol could be replayed as a device proof |
//! | `LP(application_id)` | a proof made to application A would authorise the device at application B |
//! | `LP(acct_uri)` | a proof for account A1 would authorise A2 — `REQ-216` forbids exactly this |
//! | `nonce_32` | any past proof would work forever |
//! | `grant_hash` | a proof for one grant would carry over to a differently-scoped grant issued to the same device |
//!
//! `LP` is `CON-202`'s length prefix, and it is here for the same reason it is
//! there: without it, an application ID ending in some string and an account URI
//! beginning with the rest would produce the same octets as a different pair.
//! A separator would not do, because both fields can contain most characters.
//!
//! # The nonce is consumed either way
//!
//! `CON-207`: "The verifier SHALL atomically mark the nonce used **whether
//! verification succeeds or fails**." Marking it only on success turns a failed
//! attempt into a free retry, which is what makes an online guessing attack
//! cheap. [`NonceLedger`] is a small pure model of that rule; the durable store
//! is the shell's, and this is the predicate it has to implement.

use crate::UnixSeconds;

/// The domain-separation string, followed by a zero octet.
const DOMAIN: &[u8] = b"selfsame/device-possession/v1";

/// `CON-207`: a nonce expires after at most 120 seconds.
pub const MAX_NONCE_AGE_SECONDS: i64 = 120;

/// Octets of verifier-chosen randomness in a challenge.
pub const NONCE_OCTETS: usize = 32;

/// Why a proof was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProofError {
    /// The signature does not verify under the `cnf.jwk` key.
    #[error("device proof signature does not verify")]
    BadSignature,
    /// The nonce was issued more than 120 seconds ago.
    #[error("device proof nonce has expired")]
    NonceExpired,
    /// The nonce has already been presented, successfully or otherwise.
    #[error("device proof nonce has already been used")]
    NonceReplayed,
    /// The nonce was issued for a different application, account, grant, or
    /// session.
    #[error("device proof nonce was issued for a different binding")]
    NonceMismatch,
    /// The nonce is not known to this verifier at all.
    #[error("device proof nonce is unknown")]
    NonceUnknown,
}

/// What a nonce was issued for.
///
/// `CON-207`: the verifier "SHALL reject a nonce issued for another application,
/// account, grant, verifier session, or time window". Recording the binding at
/// issuance is what makes that decidable later — all five of them.
///
/// # Why the session is a field and not part of `proof_input`
///
/// `CON-207` fixes `proof_input` exactly, and the session is not in it. That is
/// consistent: the session is the *verifier's* own notion, the device has no way
/// to know it, and putting it in the signed octets would require telling the
/// device a value that means nothing to it.
///
/// So the session is enforced where the other stateful rules are — at the
/// ledger, on the recorded challenge. Without it, a verifier running concurrent
/// sessions against one durable nonce store has four of the contract's five
/// bindings: a challenge issued in session A, for the same application, account
/// and grant, is indistinguishable from one issued in session B and is accepted
/// there. The nonce is single-use, so this is not unlimited, but it is a
/// challenge crossing exactly the boundary the contract names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    /// The verifier's 32 random octets.
    pub nonce: [u8; NONCE_OCTETS],
    /// The canonical application identifier this challenge is bound to.
    pub application_id: String,
    /// The canonical account URI this challenge is bound to.
    pub account: String,
    /// `SHA-256` of the exact grant octets.
    pub grant_hash: [u8; 32],
    /// The verifier session this challenge was issued in.
    ///
    /// Opaque to this crate and to the device: whatever a verifier uses to tell
    /// its own concurrent sessions apart. A verifier that genuinely has one
    /// session passes one constant and loses nothing.
    pub session: String,
    /// When the verifier issued it.
    pub issued_at: UnixSeconds,
}

/// Build `proof_input` (`CON-207`).
///
/// Both the device and the verifier call this, so there is one definition of the
/// signed octets rather than a signer's and a checker's — the parser-differential
/// hazard applied to a signing input.
pub fn proof_input(challenge: &Challenge) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        DOMAIN.len() + 1 + 8 + challenge.application_id.len() + challenge.account.len() + 64,
    );
    out.extend_from_slice(DOMAIN);
    out.push(0x00);
    length_prefixed(&mut out, &challenge.application_id);
    length_prefixed(&mut out, &challenge.account);
    out.extend_from_slice(&challenge.nonce);
    out.extend_from_slice(&challenge.grant_hash);
    out
}

fn length_prefixed(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// `SHA-256(grant_bytes)` over the exact compact JWS octets.
pub fn grant_hash(grant_bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(grant_bytes).into()
}

/// The device's half: sign `proof_input` with the `cnf` private key.
pub fn sign(challenge: &Challenge, device_key: &ed25519_dalek::SigningKey) -> [u8; 64] {
    use ed25519_dalek::Signer as _;
    device_key.sign(&proof_input(challenge)).to_bytes()
}

/// The verifier's half: check the signature against `cnf.jwk`.
///
/// Freshness and single use are [`NonceLedger`]'s, because they are state and
/// this is not.
///
/// # Why the strict equation
///
/// `REQ-206` is a statement about *possession*: "Possession of the VC without
/// the corresponding device private key SHALL confer no access." The permissive
/// (cofactored) Ed25519 check cannot carry that sentence. A grant whose device
/// DID encodes a low-order point — the identity, say — has `[k]A = identity`
/// for every challenge, so the fixed pair `R = identity, S = 0` satisfies the
/// equation over any `proof_input`, and the presenter needs no private key at
/// all. The nonce, the bindings, and the domain separation above would all hold
/// while the one thing this contract exists to establish did not.
///
/// [`crate::didkey::decode`] refuses such a point before it can become a device
/// DID; this is the same refusal at the step that would otherwise be fooled, so
/// a key reaching here by any other route is refused too.
pub fn verify(
    challenge: &Challenge,
    signature: &[u8; 64],
    device_public_key: &[u8; 32],
) -> Result<(), ProofError> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(device_public_key)
        .map_err(|_| ProofError::BadSignature)?;
    key.verify_strict(&proof_input(challenge), &ed25519_dalek::Signature::from_bytes(signature))
        .map_err(|_| ProofError::BadSignature)
}

/// A pure model of the verifier's nonce store.
///
/// The durable implementation is the shell's — a database row, a cache entry —
/// but the *rule* is here so both are the same rule, and so it can be tested
/// without one. Ordering is the load-bearing part: [`consume`](Self::consume)
/// marks the nonce used **before** the caller learns whether the signature was
/// good, so a failed attempt cannot become a free retry.
#[derive(Debug, Default)]
pub struct NonceLedger {
    outstanding: Vec<Challenge>,
    used: Vec<[u8; NONCE_OCTETS]>,
}

impl NonceLedger {
    /// An empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a challenge as issued and outstanding.
    pub fn issue(&mut self, challenge: Challenge) {
        self.outstanding.push(challenge);
    }

    /// Consume a nonce, returning the challenge it was issued for.
    ///
    /// Consumes it whatever happens next. Every rejection below also removes it
    /// from the outstanding set, so a caller cannot retry a nonce by failing
    /// with it first.
    pub fn consume(
        &mut self,
        nonce: &[u8; NONCE_OCTETS],
        now: UnixSeconds,
    ) -> Result<Challenge, ProofError> {
        if self.used.contains(nonce) {
            return Err(ProofError::NonceReplayed);
        }
        let position = match self.outstanding.iter().position(|c| &c.nonce == nonce) {
            Some(p) => p,
            None => return Err(ProofError::NonceUnknown),
        };
        let challenge = self.outstanding.remove(position);
        self.used.push(*nonce);
        // A nonce cannot be presented before it was issued. Without this line
        // the subtraction below goes negative and passes: a clock that moves
        // backwards — or a challenge stamped ahead of the verifier's own time —
        // yields a nonce that stays usable until 120 seconds past a timestamp
        // in the future. The window is checked from both ends, or it is not a
        // window.
        if now < challenge.issued_at {
            return Err(ProofError::NonceExpired);
        }
        if now - challenge.issued_at > MAX_NONCE_AGE_SECONDS {
            return Err(ProofError::NonceExpired);
        }
        Ok(challenge)
    }

    /// Whether a nonce has been consumed.
    pub fn is_used(&self, nonce: &[u8; NONCE_OCTETS]) -> bool {
        self.used.contains(nonce)
    }
}

/// Check that a consumed challenge was issued for the binding now being claimed.
///
/// All four of `CON-207`'s non-temporal bindings — application, account, grant,
/// and verifier session. `session` is the caller's current session; a verifier
/// with one session passes the same constant it issued with.
pub fn matches_binding(
    challenge: &Challenge,
    application_id: &str,
    account: &str,
    grant_hash: &[u8; 32],
    session: &str,
) -> Result<(), ProofError> {
    if challenge.application_id != application_id
        || challenge.account != account
        || &challenge.grant_hash != grant_hash
        || challenge.session != session
    {
        return Err(ProofError::NonceMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = "https://photos.example/selfsame/application";
    const OTHER_APP: &str = "https://pictura.example/selfsame/application";
    const A1: &str = "acct:ss-aaaa@accounts.photos.example";
    const A2: &str = "acct:ss-bbbb@accounts.photos.example";

    fn device(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    const S1: &str = "session-a";
    const S2: &str = "session-b";

    fn challenge() -> Challenge {
        Challenge {
            nonce: [5u8; NONCE_OCTETS],
            application_id: APP.into(),
            account: A1.into(),
            grant_hash: grant_hash(b"a grant"),
            session: S1.into(),
            issued_at: 1_000,
        }
    }

    // TEST-209 positive.
    #[test]
    fn accepts_a_valid_signature_from_the_cnf_key() {
        let key = device(3);
        let c = challenge();
        let sig = sign(&c, &key);
        assert!(verify(&c, &sig, &key.verifying_key().to_bytes()).is_ok());
    }

    // TEST-209 negative: issuer, another device, another application's device,
    // another account's device, a key whose bytes differ from the subject DID.
    #[test]
    fn rejects_a_signature_by_any_other_key() {
        let c = challenge();
        let sig = sign(&c, &device(3));
        for other in [1u8, 2, 4, 200] {
            assert_eq!(
                verify(&c, &sig, &device(other).verifying_key().to_bytes()),
                Err(ProofError::BadSignature),
                "key seed {other}"
            );
        }
    }

    // REQ-206: possession, or nothing.
    #[test]
    fn a_low_order_device_key_proves_possession_of_nothing() {
        // `A` is the identity point, so `[k]A` is the identity for every
        // challenge and the fixed pair `R = identity, S = 0` satisfies the
        // permissive equation over any `proof_input`. A presenter holding a
        // grant whose device DID encodes such a point would pass this check
        // without ever having had the device private key — which is exactly
        // what REQ-206 says must not confer access.
        let mut weak = [0u8; 32];
        weak[0] = 1;
        let mut forged = [0u8; 64];
        forged[0] = 1;

        let c = challenge();
        {
            use ed25519_dalek::Verifier as _;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&weak).expect("a valid point");
            assert!(
                key.verify(&proof_input(&c), &ed25519_dalek::Signature::from_bytes(&forged))
                    .is_ok(),
                "the permissive equation no longer accepts the low-order forgery"
            );
        }
        assert_eq!(verify(&c, &forged, &weak), Err(ProofError::BadSignature));

        // …and the same forgery against a second, unrelated challenge, because
        // the point of it is that the signed octets never mattered.
        let elsewhere = Challenge { application_id: OTHER_APP.into(), ..challenge() };
        assert_eq!(verify(&elsewhere, &forged, &weak), Err(ProofError::BadSignature));
    }

    #[test]
    fn a_proof_for_one_application_does_not_verify_for_another() {
        let key = device(3);
        let sig = sign(&challenge(), &key);
        let elsewhere = Challenge { application_id: OTHER_APP.into(), ..challenge() };
        assert_eq!(
            verify(&elsewhere, &sig, &key.verifying_key().to_bytes()),
            Err(ProofError::BadSignature)
        );
    }

    #[test]
    fn a_proof_for_one_account_does_not_verify_for_a_sibling() {
        // REQ-216: a proof belonging to A1 "SHALL confer no authority in A2,
        // even though both accounts share an applicationId".
        let key = device(3);
        let sig = sign(&challenge(), &key);
        let sibling = Challenge { account: A2.into(), ..challenge() };
        assert_eq!(
            verify(&sibling, &sig, &key.verifying_key().to_bytes()),
            Err(ProofError::BadSignature)
        );
    }

    #[test]
    fn a_proof_for_one_grant_does_not_verify_for_another() {
        let key = device(3);
        let sig = sign(&challenge(), &key);
        let other_grant = Challenge { grant_hash: grant_hash(b"another grant"), ..challenge() };
        assert_eq!(
            verify(&other_grant, &sig, &key.verifying_key().to_bytes()),
            Err(ProofError::BadSignature)
        );
    }

    #[test]
    fn a_proof_for_one_nonce_does_not_verify_for_another() {
        let key = device(3);
        let sig = sign(&challenge(), &key);
        let other_nonce = Challenge { nonce: [6u8; NONCE_OCTETS], ..challenge() };
        assert_eq!(
            verify(&other_nonce, &sig, &key.verifying_key().to_bytes()),
            Err(ProofError::BadSignature)
        );
    }

    #[test]
    fn the_length_prefix_separates_a_shifted_field_boundary() {
        // Without LP, an application ID ending in `x` and an account beginning
        // with the rest would build the same octets as a different pair, and one
        // proof would verify for both.
        let left = proof_input(&Challenge {
            application_id: "https://a.example/appx".into(),
            account: "acct:b@c".into(),
            ..challenge()
        });
        let right = proof_input(&Challenge {
            application_id: "https://a.example/app".into(),
            account: "xacct:b@c".into(),
            ..challenge()
        });
        assert_ne!(left, right);
    }

    #[test]
    fn the_domain_string_and_separator_lead_the_input() {
        let input = proof_input(&challenge());
        assert!(input.starts_with(DOMAIN));
        assert_eq!(input[DOMAIN.len()], 0x00);
    }

    // TEST-210: challenge replay.
    #[test]
    fn a_nonce_is_consumed_after_a_successful_proof() {
        let mut ledger = NonceLedger::new();
        let c = challenge();
        ledger.issue(c.clone());
        assert!(ledger.consume(&c.nonce, 1_010).is_ok());
        assert_eq!(ledger.consume(&c.nonce, 1_020), Err(ProofError::NonceReplayed));
    }

    #[test]
    fn a_nonce_is_consumed_after_a_failed_proof_as_well() {
        // CON-207: consumed "whether verification succeeds or fails". Marking
        // only on success would make a failed attempt a free retry, which is
        // what makes an online guessing attack cheap.
        let mut ledger = NonceLedger::new();
        let c = challenge();
        ledger.issue(c.clone());

        let consumed = ledger.consume(&c.nonce, 1_010).expect("first use");
        let bad_signature = [0u8; 64];
        assert_eq!(
            verify(&consumed, &bad_signature, &device(3).verifying_key().to_bytes()),
            Err(ProofError::BadSignature)
        );
        // The failure did not give the nonce back.
        assert!(ledger.is_used(&c.nonce));
        assert_eq!(ledger.consume(&c.nonce, 1_011), Err(ProofError::NonceReplayed));
    }

    #[test]
    fn a_nonce_expires_after_one_hundred_and_twenty_seconds() {
        let mut ledger = NonceLedger::new();
        let c = challenge();
        ledger.issue(c.clone());
        assert_eq!(ledger.consume(&c.nonce, 1_000 + 121), Err(ProofError::NonceExpired));

        let mut ledger = NonceLedger::new();
        ledger.issue(c.clone());
        assert!(ledger.consume(&c.nonce, 1_000 + 120).is_ok(), "the boundary is inclusive");
    }

    #[test]
    fn a_nonce_presented_before_it_was_issued_is_refused() {
        // The other end of the window. Subtracting a later `issued_at` from an
        // earlier `now` goes negative, which is under the maximum by
        // arithmetic — so a backwards clock, or a challenge stamped ahead of
        // this verifier, produced a nonce good until 120 seconds past a future
        // instant.
        let mut ledger = NonceLedger::new();
        let c = challenge();
        ledger.issue(c.clone());
        assert_eq!(ledger.consume(&c.nonce, 999), Err(ProofError::NonceExpired));
        // …and consumed anyway, like every other refusal here.
        assert!(ledger.is_used(&c.nonce));

        let mut ledger = NonceLedger::new();
        ledger.issue(c.clone());
        assert!(ledger.consume(&c.nonce, 1_000).is_ok(), "the issuing instant itself is usable");
    }

    #[test]
    fn an_expired_nonce_is_still_consumed() {
        let mut ledger = NonceLedger::new();
        let c = challenge();
        ledger.issue(c.clone());
        assert_eq!(ledger.consume(&c.nonce, 2_000), Err(ProofError::NonceExpired));
        assert_eq!(ledger.consume(&c.nonce, 1_010), Err(ProofError::NonceReplayed));
    }

    #[test]
    fn an_unknown_nonce_is_refused_without_being_recorded_as_used() {
        let mut ledger = NonceLedger::new();
        assert_eq!(ledger.consume(&[9u8; NONCE_OCTETS], 1_000), Err(ProofError::NonceUnknown));
        assert!(!ledger.is_used(&[9u8; NONCE_OCTETS]));
    }

    #[test]
    fn a_nonce_issued_for_another_binding_is_refused() {
        let c = challenge();
        assert!(matches_binding(&c, APP, A1, &grant_hash(b"a grant"), S1).is_ok());
        assert_eq!(
            matches_binding(&c, OTHER_APP, A1, &grant_hash(b"a grant"), S1),
            Err(ProofError::NonceMismatch)
        );
        assert_eq!(
            matches_binding(&c, APP, A2, &grant_hash(b"a grant"), S1),
            Err(ProofError::NonceMismatch)
        );
        assert_eq!(
            matches_binding(&c, APP, A1, &grant_hash(b"other"), S1),
            Err(ProofError::NonceMismatch)
        );
    }

    #[test]
    fn a_nonce_issued_in_another_verifier_session_is_refused() {
        // CON-207 names the verifier session alongside application, account and
        // grant. It is the one a verifier with a durable nonce ledger shared
        // across concurrent sessions would otherwise never check: same
        // application, same account, same grant, different session — and every
        // other binding agrees.
        let c = challenge();
        assert!(matches_binding(&c, APP, A1, &grant_hash(b"a grant"), S1).is_ok());
        assert_eq!(
            matches_binding(&c, APP, A1, &grant_hash(b"a grant"), S2),
            Err(ProofError::NonceMismatch),
            "a challenge issued in one session was accepted in another"
        );
    }

    #[test]
    fn the_session_is_not_part_of_the_signed_octets() {
        // CON-207 fixes `proof_input` exactly and the session is not in it. The
        // device could not supply it if it were — the value is the verifier's
        // own. This pins that adding the binding did not change what is signed,
        // so a device built against the contract still interoperates.
        let mut a = challenge();
        let mut b = challenge();
        a.session = S1.into();
        b.session = S2.into();
        assert_eq!(proof_input(&a), proof_input(&b));
    }
}
