//! The two wire records — SPEC-001 CON-001, CON-002, ADR-013.
//!
//! The offer and the grant are [CBCL] messages under a dedicated
//! `anuna-ssi-v1` dialect. Signing and transcript-binding are over
//! `cbcl_core::canonical_encode`, which implements RFC 9804 §6.2: length-
//! prefixed atoms, no whitespace, and an explicitly **injective** atom→octet
//! mapping. One logical offer therefore yields one byte string on every
//! implementation, which is what makes the offer signature (REQ-018) and the
//! transcript hash (REQ-006) well-defined rather than serialiser-dependent.
//!
//! ```text
//! (offer :v 1 :app "cbcl-chat" :purpose "chat-device"
//!        :key "u<32-byte Ed25519 public key>"
//!        :desc "Chrome on macOS"          ← attacker-controlled, untrusted
//!        :exp 1790000000
//!        :sig "u<64-byte Ed25519 signature>")
//!
//! (grant :v 1 :did "did:crdt:9f3a…"
//!        :deltas ("u<delta JSON>" "u<delta JSON>" "u<delta JSON>"))
//! ```
//!
//! # Why the deltas stay JSON
//!
//! REQ-003 derives the DID by hashing `did:crdt`'s exact `serde_json` bytes
//! (`document.rs:219`). Re-encoding a delta as CBCL would make the identifier
//! un-recomputable, so deltas travel as **opaque** multibase atoms: CBCL is the
//! envelope, JSON is the payload. This is the only correct split and it is not
//! a compromise (ADR-013).
//!
//! # Field order is part of the grammar
//!
//! `canonical_encode` is order-sensitive by construction — that is what makes
//! it injective. A recogniser that accepted the fields in any order would admit
//! several byte strings for one logical offer, and the signature would cover
//! only the one the sender happened to emit. The recogniser therefore requires
//! the exact declared order and rejects every permutation.
//!
//! [CBCL]: ../../../../anuna-ssi/specs/concepts/CBCL.md

use cbcl_core::canonical::canonical_encode;
use cbcl_core::sexpr::{Atom, SExpr};
use cbcl_parser::{parse, parse_shape};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::{mb, MAX_DEVICE_DESCRIPTION_CHARS, UnixSeconds, WIRE_VERSION};

// ── application registry (REQ-026) ───────────────────────────────────────────

/// The applications this build knows how to link into.
///
/// REQ-026: the rendezvous and resolver hosts are resolved from this table and
/// **never** from the link code or the offer. A URL in a scanned code is a
/// phishing primitive; the code carries a secret and an identifier, and the
/// identifier indexes a table compiled into the reader.
///
/// The table is `#[non_exhaustive]` in spirit but a closed enum in fact: a new
/// application is a code change and a new compiled build, which is the point.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Application {
    /// `cbcl-chat` — the application SPEC-001 is written for.
    CbclChat,
}

impl Application {
    /// The byte carried in the link code's data part.
    pub fn id_byte(self) -> u8 {
        match self {
            Application::CbclChat => 1,
        }
    }

    /// Recognise an application byte, or refuse it.
    pub fn from_id_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Application::CbclChat),
            _ => None,
        }
    }

    /// The `:app` slug carried in the offer.
    pub fn slug(self) -> &'static str {
        match self {
            Application::CbclChat => "cbcl-chat",
        }
    }

    /// Recognise an `:app` slug against the compiled table.
    pub fn from_slug(s: &str) -> Option<Self> {
        match s {
            "cbcl-chat" => Some(Application::CbclChat),
            _ => None,
        }
    }

    /// The single purpose this version defines for the application.
    ///
    /// SPEC-001 §2.2 puts capability delegation out of scope: the purpose names
    /// *what kind of device* is joining, never what it may do.
    pub fn purpose(self) -> &'static str {
        match self {
            Application::CbclChat => "chat-device",
        }
    }
}

// ── the dialect (CON-001) ────────────────────────────────────────────────────

/// The `anuna-ssi-v1` dialect, as declared by SPEC-001 CON-001.
///
/// Held as source text rather than as a Rust structure so the grammar in the
/// specification and the grammar in the code are the same artefact. A test
/// parses it, so a divergence is a build failure and not a comment that rots.
pub const DIALECT_SOURCE: &str = r#"(define anuna-ssi-v1 (cbcl) @anuna
  (:resource-requirements
    ((max-depth 6) (max-expansion-size 256) (verification-time 10)))

  (extend link-offer (v app purpose key desc exp sig)
    (tell @selfsame
      (offer :v v :app app :purpose purpose
             :key key :desc desc :exp exp :sig sig)
      :domain selfsame))

  (extend link-grant (v did deltas)
    (tell @selfsame
      (grant :v v :did did :deltas deltas)
      :domain selfsame)))"#;

/// R5 `(shape …)` clause for the offer performative.
///
/// Arity and atom types are declared here and checked by `cbcl-core`'s shape
/// checker in linear time, so the recogniser below never has to re-state them
/// (ADR-013, "shape enforcement for free").
pub const OFFER_SHAPE: &str = "(shape offer \
     (require :v number) (require :app string) (require :purpose string) \
     (require :key string) (require :desc string) (require :exp number) \
     (require :sig string) (max-depth 2))";

/// R5 `(shape …)` clause for the grant performative.
pub const GRANT_SHAPE: &str = "(shape grant \
     (require :v number) (require :did string) (require :deltas list) \
     (max-depth 3))";

/// Domain separator for the offer signature (REQ-018, CON-001).
pub const OFFER_DOMAIN: &[u8] = b"anuna-ssi/v1/offer";

/// Maximum accepted size of a record plaintext, in bytes.
///
/// Matches CON-002's 4 KiB ciphertext bound: a plaintext larger than the
/// envelope that carries it is not a record this system can have produced.
pub const MAX_RECORD_BYTES: usize = 4096;

/// Maximum accepted nesting depth, from CON-001's `:resource-requirements`.
pub const MAX_RECORD_DEPTH: usize = 6;

/// Reject over-deep input **before** handing it to the recursive-descent
/// recogniser.
///
/// `cbcl_parser::parse` is fuel-bounded but not *depth*-bounded: its fuel
/// counts steps, and `"("` repeated a few thousand times buys enough fuel to
/// recurse until the stack is gone. That is a denial of service at a trust
/// boundary (threat T9), tracked as
/// [`BUG-002`](../../../../anuna-ssi/bugs/BUG-002-cbcl-parser-unbounded-recursion.md)
/// against `cbcl-rs`.
///
/// The guard is deliberately a *regular* property — count unescaped parens
/// outside string literals — computed iteratively in one pass. LangSec
/// Principle 6: use the weakest grammar class that expresses the constraint,
/// and put it in front of the stronger recogniser rather than inside it.
///
// SIMPLIFY: local depth pre-filter — remove once `cbcl-parser` bounds its own
// recursion depth and the fix is in the pinned revision (trace: ADR-013,
// BUG-002).
fn within_resource_bounds(input: &str) -> bool {
    if input.len() > MAX_RECORD_BYTES {
        return false;
    }
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for b in input.bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'(' => {
                depth += 1;
                if depth > MAX_RECORD_DEPTH {
                    return false;
                }
            }
            b')' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    true
}

/// `did:crdt` identifier shape, as CON-004 states it.
fn is_well_formed_did(s: &str) -> bool {
    match s.strip_prefix("did:crdt:") {
        Some(hex) => hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        None => false,
    }
}

// ── errors ───────────────────────────────────────────────────────────────────

/// Why a record was refused.
///
/// The user sees "that code isn't valid" and never a parse detail (CON-001
/// error model). These variants exist so a test can attribute a rejection to a
/// single rule, and so [`crate::accept`] can name the failing conjunct.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// The bytes are not well-formed CBCL, or not valid UTF-8.
    #[error("not a well-formed CBCL message")]
    Unrecognised,
    /// The message is CBCL but not a record of the expected performative,
    /// or its fields are absent, mistyped, or out of the declared order.
    #[error("not a well-formed {0} record")]
    WrongShape(&'static str),
    /// The `:v` field names a version this build does not speak.
    #[error("unsupported record version")]
    UnsupportedVersion,
    /// The `:app` slug is not in the compiled table (REQ-026).
    #[error("unknown application")]
    UnknownApplication,
    /// The `:purpose` is not the one this application defines.
    #[error("unknown purpose")]
    UnknownPurpose,
    /// A multibase field was not canonically spelled (REQ-027).
    #[error("non-canonical binary encoding: {0}")]
    Multibase(#[from] mb::MultibaseError),
    /// The `:did` is not a well-formed `did:crdt` identifier.
    #[error("malformed did")]
    MalformedDid,
    /// The `:desc` exceeded the cap of [`MAX_DEVICE_DESCRIPTION_CHARS`].
    #[error("device description too long")]
    DescriptionTooLong,
    /// The `:deltas` list was outside the 2–3 entries CON-002 admits.
    #[error("delta list outside the admitted arity")]
    DeltaArity,
    /// The offer's signature is absent or does not verify under `:key`
    /// (REQ-018). **This is checked before any field is displayed.**
    #[error("offer signature does not verify under the contained key")]
    BadSignature,
}

// ── the offer (CON-001) ──────────────────────────────────────────────────────

/// A recognised, signature-verified link offer.
///
/// A value of this type is only ever produced by [`Offer::parse`], which
/// verifies the signature before returning — so holding one *is* the evidence
/// that REQ-018 was satisfied. There is no constructor that skips the check.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Offer {
    /// Which application asked (from the compiled table, never from the wire).
    pub application: Application,
    /// What the key is for. Never a capability (REQ-013).
    pub purpose: &'static str,
    /// The device public key the offer proves possession of.
    pub device_key: [u8; 32],
    /// **Untrusted.** The device's own words about itself. REQ-019 requires
    /// this be rendered as untrusted text: length-capped at recognition, no
    /// formatting interpreted, visually distinguished from application chrome.
    pub device_description: String,
    /// Absolute expiry, seconds since the Unix epoch.
    pub expiry: UnixSeconds,
    /// The Ed25519 signature over [`Offer::signing_bytes`].
    pub signature: [u8; 64],
}

impl Offer {
    /// Build and sign an offer with the device's own key.
    ///
    /// The signature is what makes the offer a *proof of possession*: without
    /// it the phone would root-sign whatever key a QR contained, so any QR a
    /// user could be induced to scan would add an attacker's key to their
    /// identity (REQ-018, threat T6).
    ///
    /// `device_description` is truncated to [`MAX_DEVICE_DESCRIPTION_CHARS`]
    /// on the way out, so a conforming client cannot mint an offer the
    /// recogniser would refuse.
    pub fn sign(
        application: Application,
        signing_key: &SigningKey,
        device_description: &str,
        expiry: UnixSeconds,
    ) -> Self {
        let mut offer = Self {
            application,
            purpose: application.purpose(),
            device_key: signing_key.verifying_key().to_bytes(),
            device_description: device_description
                .chars()
                .take(MAX_DEVICE_DESCRIPTION_CHARS)
                .collect(),
            expiry,
            signature: [0u8; 64],
        };
        let sig: Signature = signing_key.sign(&offer.signing_bytes());
        offer.signature = sig.to_bytes();
        offer
    }

    /// The exact bytes the signature covers: the domain separator followed by
    /// `canonical_encode` of the offer form **with `:sig` and its value
    /// removed** — a structure cannot sign itself (CON-001).
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = OFFER_DOMAIN.to_vec();
        out.extend_from_slice(&canonical_encode(&self.to_sexpr_unsigned()));
        out
    }

    /// The unsigned form: everything the signature covers.
    fn to_sexpr_unsigned(&self) -> SExpr {
        SExpr::List(vec![
            SExpr::Atom(Atom::Symbol("offer".into())),
            SExpr::Atom(Atom::Keyword("v".into())),
            SExpr::Atom(Atom::Num(WIRE_VERSION)),
            SExpr::Atom(Atom::Keyword("app".into())),
            SExpr::Atom(Atom::Str(self.application.slug().into())),
            SExpr::Atom(Atom::Keyword("purpose".into())),
            SExpr::Atom(Atom::Str(self.purpose.into())),
            SExpr::Atom(Atom::Keyword("key".into())),
            SExpr::Atom(Atom::Str(mb::encode(&self.device_key))),
            SExpr::Atom(Atom::Keyword("desc".into())),
            SExpr::Atom(Atom::Str(self.device_description.clone())),
            SExpr::Atom(Atom::Keyword("exp".into())),
            SExpr::Atom(Atom::Num(self.expiry as i64)),
        ])
    }

    /// The full signed form, as written to the rendezvous.
    pub fn to_sexpr(&self) -> SExpr {
        let mut items = match self.to_sexpr_unsigned() {
            SExpr::List(items) => items,
            _ => unreachable!("to_sexpr_unsigned always builds a list"),
        };
        items.push(SExpr::Atom(Atom::Keyword("sig".into())));
        items.push(SExpr::Atom(Atom::Str(mb::encode(&self.signature))));
        SExpr::List(items)
    }

    /// The wire bytes of the signed offer — the plaintext sealed into the offer
    /// slot.
    ///
    /// This is the *textual* CBCL form, because the phone has to recognise it
    /// with `cbcl-parser` and `cbcl-core` publishes no canonical decoder. The
    /// canonical encoding is used where canonicality is what matters — the
    /// signature ([`Offer::signing_bytes`]) and the transcript
    /// ([`Offer::transcript`]) — which is exactly what CON-001 and ADR-013 ask
    /// for: *"signing and transcript-binding are over
    /// `cbcl_core::canonical_encode`"*, not "the wire is canonical_encode".
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_sexpr().to_string().into_bytes()
    }

    /// The transcript this offer binds its reply to (CON-002, REQ-006).
    ///
    /// `BLAKE3` over the **canonical** encoding rather than over the wire
    /// bytes, so the binding is immune to whitespace variation between what the
    /// client wrote and what the phone re-serialised. Both sides recompute it
    /// from the typed offer, so they agree by construction rather than by
    /// byte-for-byte luck.
    pub fn transcript(&self) -> [u8; 32] {
        crate::seal::transcript(&canonical_encode(&self.to_sexpr()))
    }

    /// Recognise an offer, **verifying the signature before returning**.
    ///
    /// Full recognition precedes any semantic action (CON-001 post-conditions):
    /// the whole message is parsed, shape-checked, typed, and only then is the
    /// signature verified — and no field is available to a caller until it has.
    /// SCREEN-001's "Never reached" rows are this function returning `Err`.
    pub fn parse(bytes: &[u8]) -> Result<Self, RecordError> {
        let text = core::str::from_utf8(bytes).map_err(|_| RecordError::Unrecognised)?;
        if !within_resource_bounds(text) {
            return Err(RecordError::Unrecognised);
        }
        let sexpr = parse(text).map_err(|_| RecordError::Unrecognised)?;
        check_shape(OFFER_SHAPE, &sexpr).map_err(|_| RecordError::WrongShape("offer"))?;

        let fields = keyword_fields(&sexpr, "offer", &["v", "app", "purpose", "key", "desc", "exp", "sig"])
            .ok_or(RecordError::WrongShape("offer"))?;

        if num(&fields[0]).ok_or(RecordError::WrongShape("offer"))? != WIRE_VERSION {
            return Err(RecordError::UnsupportedVersion);
        }
        let application = Application::from_slug(text_of(&fields[1]).ok_or(RecordError::WrongShape("offer"))?)
            .ok_or(RecordError::UnknownApplication)?;
        let purpose = text_of(&fields[2]).ok_or(RecordError::WrongShape("offer"))?;
        if purpose != application.purpose() {
            return Err(RecordError::UnknownPurpose);
        }
        let device_key: [u8; 32] =
            mb::decode_exact(text_of(&fields[3]).ok_or(RecordError::WrongShape("offer"))?)?;
        let device_description = text_of(&fields[4]).ok_or(RecordError::WrongShape("offer"))?;
        if device_description.chars().count() > MAX_DEVICE_DESCRIPTION_CHARS {
            return Err(RecordError::DescriptionTooLong);
        }
        let expiry_raw = num(&fields[5]).ok_or(RecordError::WrongShape("offer"))?;
        let expiry: UnixSeconds =
            expiry_raw.try_into().map_err(|_| RecordError::WrongShape("offer"))?;
        let signature: [u8; 64] =
            mb::decode_exact(text_of(&fields[6]).ok_or(RecordError::WrongShape("offer"))?)?;

        let offer = Self {
            application,
            purpose: application.purpose(),
            device_key,
            device_description: device_description.to_owned(),
            expiry,
            signature,
        };

        // REQ-018: the offer must be signed by the key it names. Parsing the
        // offer is not authorising it.
        let vk = VerifyingKey::from_bytes(&offer.device_key).map_err(|_| RecordError::BadSignature)?;
        vk.verify(&offer.signing_bytes(), &Signature::from_bytes(&offer.signature))
            .map_err(|_| RecordError::BadSignature)?;

        Ok(offer)
    }
}

// ── the grant (CON-002) ──────────────────────────────────────────────────────

/// The credential bundle the phone seals back into the bundle slot.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Grant {
    /// The identity the device is being joined to.
    pub did: String,
    /// 2–3 `did:crdt` signed deltas in their upstream `serde_json` form,
    /// carried as opaque bytes: genesis, `AddVerificationMethod`, and the
    /// optional device label of REQ-021.
    pub deltas: Vec<Vec<u8>>,
}

impl Grant {
    /// Build a grant. The deltas are passed through untouched — a byte-level
    /// round trip is required for the DID derivation to remain recomputable
    /// (TEST-036 negative-output).
    pub fn new(did: String, deltas: Vec<Vec<u8>>) -> Self {
        Self { did, deltas }
    }

    /// The CBCL form.
    pub fn to_sexpr(&self) -> SExpr {
        SExpr::List(vec![
            SExpr::Atom(Atom::Symbol("grant".into())),
            SExpr::Atom(Atom::Keyword("v".into())),
            SExpr::Atom(Atom::Num(WIRE_VERSION)),
            SExpr::Atom(Atom::Keyword("did".into())),
            SExpr::Atom(Atom::Str(self.did.clone())),
            SExpr::Atom(Atom::Keyword("deltas".into())),
            SExpr::List(self.deltas.iter().map(|d| SExpr::Atom(Atom::Str(mb::encode(d)))).collect()),
        ])
    }

    /// The wire bytes, sealed into the bundle slot.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_sexpr().to_string().into_bytes()
    }

    /// Recognise a grant.
    ///
    /// The arity bound of 2–3 is a grammar rule, not a sanity check: a longer
    /// list is not a richer credential, it is an unrecognised input (CON-002).
    pub fn parse(bytes: &[u8]) -> Result<Self, RecordError> {
        let text = core::str::from_utf8(bytes).map_err(|_| RecordError::Unrecognised)?;
        if !within_resource_bounds(text) {
            return Err(RecordError::Unrecognised);
        }
        let sexpr = parse(text).map_err(|_| RecordError::Unrecognised)?;
        check_shape(GRANT_SHAPE, &sexpr).map_err(|_| RecordError::WrongShape("grant"))?;

        let fields = keyword_fields(&sexpr, "grant", &["v", "did", "deltas"])
            .ok_or(RecordError::WrongShape("grant"))?;

        if num(&fields[0]).ok_or(RecordError::WrongShape("grant"))? != WIRE_VERSION {
            return Err(RecordError::UnsupportedVersion);
        }
        let did = text_of(&fields[1]).ok_or(RecordError::WrongShape("grant"))?;
        if !is_well_formed_did(did) {
            return Err(RecordError::MalformedDid);
        }
        let items = match &fields[2] {
            SExpr::List(items) => items,
            _ => return Err(RecordError::WrongShape("grant")),
        };
        if !(2..=3).contains(&items.len()) {
            return Err(RecordError::DeltaArity);
        }
        let mut deltas = Vec::with_capacity(items.len());
        for item in items {
            let s = text_of(item).ok_or(RecordError::WrongShape("grant"))?;
            deltas.push(mb::decode(s)?);
        }
        Ok(Self { did: did.to_owned(), deltas })
    }
}

// ── recognition helpers ──────────────────────────────────────────────────────

/// Run a declared R5 `(shape …)` clause over a message.
fn check_shape(shape_src: &str, sexpr: &SExpr) -> Result<(), ()> {
    let clause = parse(shape_src).map_err(|_| ())?;
    let constraint = parse_shape(&clause).map_err(|_| ())?;
    constraint.check(sexpr).map_err(|_| ())
}

/// Extract the values of `keywords`, in exactly that order, from
/// `(head :k1 v1 :k2 v2 …)`.
///
/// Returns `None` on any deviation — a missing keyword, an extra one, a
/// permutation, or a trailing atom. There is no repair and no normalisation
/// (CON-001 error model).
fn keyword_fields(sexpr: &SExpr, head: &str, keywords: &[&str]) -> Option<Vec<SExpr>> {
    let items = match sexpr {
        SExpr::List(items) => items,
        _ => return None,
    };
    if items.len() != 1 + keywords.len() * 2 || !items[0].is_symbol(head) {
        return None;
    }
    let mut out = Vec::with_capacity(keywords.len());
    for (i, expected) in keywords.iter().enumerate() {
        match &items[1 + i * 2] {
            SExpr::Atom(Atom::Keyword(k)) if k == expected => {}
            _ => return None,
        }
        out.push(items[2 + i * 2].clone());
    }
    Some(out)
}

fn text_of(sexpr: &SExpr) -> Option<&str> {
    match sexpr {
        SExpr::Atom(Atom::Str(s)) => Some(s),
        _ => None,
    }
}

fn num(sexpr: &SExpr) -> Option<i64> {
    match sexpr {
        SExpr::Atom(Atom::Num(n)) => Some(*n),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn offer() -> Offer {
        Offer::sign(Application::CbclChat, &key(1), "Chrome on macOS", 1_790_000_000)
    }

    // The declared grammar in the spec and the grammar in the code are one
    // artefact: if the dialect source stops being well-formed CBCL, the build
    // fails rather than the comment rotting.
    #[test]
    fn the_declared_dialect_and_shapes_are_well_formed_cbcl() {
        assert!(parse(DIALECT_SOURCE).is_ok(), "dialect source must parse");
        for src in [OFFER_SHAPE, GRANT_SHAPE] {
            let clause = parse(src).expect("shape clause must parse");
            parse_shape(&clause).expect("shape clause must be a valid R5 shape");
        }
    }

    // TEST-035 positive: parse(render(x)) == x.
    #[test]
    fn offer_round_trips_through_its_own_recogniser() {
        let o = offer();
        assert_eq!(Offer::parse(&o.to_bytes()).unwrap(), o);
    }

    #[test]
    fn grant_round_trips_and_preserves_delta_bytes_exactly() {
        // TEST-036 negative-output: a delta altered by the envelope round trip
        // would break the DID derivation, so byte identity is the assertion.
        let deltas = vec![b"{\"a\":1}".to_vec(), (0u8..=255).collect::<Vec<u8>>()];
        let g = Grant::new("did:crdt:".to_owned() + &"9f3a".repeat(16), deltas.clone());
        let parsed = Grant::parse(&g.to_bytes()).unwrap();
        assert_eq!(parsed.deltas, deltas);
        assert_eq!(parsed, g);
    }

    // TEST-018 positive.
    #[test]
    fn an_offer_signed_by_the_contained_key_verifies() {
        assert!(Offer::parse(&offer().to_bytes()).is_ok());
    }

    // TEST-018 negative-input: absent, wrong-key, and wrong-domain signatures
    // are all refused *before display*.
    #[test]
    fn an_offer_with_no_signature_is_refused() {
        let mut o = offer();
        o.signature = [0u8; 64];
        assert_eq!(Offer::parse(&o.to_bytes()), Err(RecordError::BadSignature));
    }

    #[test]
    fn an_offer_signed_by_a_different_key_is_refused() {
        // The attacker holds key(2) and wants the victim's key(1) authorised.
        let mut o = offer();
        let sig: Signature = key(2).sign(&o.signing_bytes());
        o.signature = sig.to_bytes();
        assert_eq!(Offer::parse(&o.to_bytes()), Err(RecordError::BadSignature));
    }

    #[test]
    fn an_offer_signed_over_the_wrong_domain_is_refused() {
        let o = offer();
        let sk = key(1);
        let mut without_domain = canonical_encode(&o.to_sexpr_unsigned());
        let sig: Signature = sk.sign(&without_domain);
        without_domain.clear();
        let mut forged = o.clone();
        forged.signature = sig.to_bytes();
        assert_eq!(Offer::parse(&forged.to_bytes()), Err(RecordError::BadSignature));
    }

    #[test]
    fn tampering_with_any_signed_field_invalidates_the_signature() {
        let base = offer();
        let mut with_other_desc = base.clone();
        with_other_desc.device_description = "Safari on iOS".into();
        assert_eq!(Offer::parse(&with_other_desc.to_bytes()), Err(RecordError::BadSignature));

        let mut with_other_expiry = base.clone();
        with_other_expiry.expiry += 1;
        assert_eq!(Offer::parse(&with_other_expiry.to_bytes()), Err(RecordError::BadSignature));
    }

    // TEST-019 negative-input: a 10 KiB description, markup, and control
    // characters. The cap fires at recognition, so an oversized description is
    // never a value the UI has to carry.
    #[test]
    fn an_oversized_device_description_is_refused_at_recognition() {
        let sk = key(1);
        // Over the character cap, but within `MAX_RECORD_BYTES` — so the
        // description rule fires and not the record-size rule. The 10 KiB case
        // is covered by `an_oversized_record_is_refused_before_parsing`.
        let long: String = "A".repeat(MAX_DEVICE_DESCRIPTION_CHARS + 1);
        // Build the record by hand: `Offer::sign` truncates, so the only way to
        // present an oversized description is to forge the wire form.
        let mut o = Offer::sign(Application::CbclChat, &sk, "x", 1_790_000_000);
        o.device_description = long;
        let sig: Signature = sk.sign(&o.signing_bytes());
        o.signature = sig.to_bytes();
        assert_eq!(Offer::parse(&o.to_bytes()), Err(RecordError::DescriptionTooLong));
    }

    #[test]
    fn markup_and_control_characters_survive_as_inert_text_within_the_cap() {
        let o = Offer::sign(
            Application::CbclChat,
            &key(1),
            "<b>Verified by Anuna</b>\u{0007}",
            1_790_000_000,
        );
        let parsed = Offer::parse(&o.to_bytes()).unwrap();
        // Recognised, carried, and never interpreted — the display obligation
        // is SCREEN-001's; the recogniser's job is to refuse to normalise it.
        assert_eq!(parsed.device_description, o.device_description);
    }

    #[test]
    fn a_permuted_field_order_is_refused() {
        // canonical_encode is order-sensitive by construction; accepting a
        // permutation would admit several byte strings for one logical offer.
        let text = "(offer :app \"cbcl-chat\" :v 1 :purpose \"chat-device\" \
                    :key \"uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\" :desc \"x\" \
                    :exp 1 :sig \"uAA\")";
        assert!(matches!(Offer::parse(text.as_bytes()), Err(RecordError::WrongShape("offer"))));
    }

    #[test]
    fn an_extra_field_is_refused() {
        let mut items = match offer().to_sexpr() {
            SExpr::List(items) => items,
            _ => unreachable!(),
        };
        items.push(SExpr::Atom(Atom::Keyword("extra".into())));
        items.push(SExpr::Atom(Atom::Str("x".into())));
        let bytes = canonical_encode(&SExpr::List(items));
        assert!(matches!(Offer::parse(&bytes), Err(RecordError::WrongShape("offer"))));
    }

    #[test]
    fn an_unknown_application_or_purpose_is_refused() {
        let text = "(offer :v 1 :app \"evil-app\" :purpose \"chat-device\" \
                    :key \"uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\" :desc \"x\" \
                    :exp 1 :sig \"uAA\")";
        assert_eq!(Offer::parse(text.as_bytes()), Err(RecordError::UnknownApplication));

        let text = "(offer :v 1 :app \"cbcl-chat\" :purpose \"admin\" \
                    :key \"uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\" :desc \"x\" \
                    :exp 1 :sig \"uAA\")";
        assert_eq!(Offer::parse(text.as_bytes()), Err(RecordError::UnknownPurpose));
    }

    #[test]
    fn a_non_canonical_multibase_field_is_refused() {
        // REQ-027 reaches into the record grammar: `=` padding in `:key`.
        let text = "(offer :v 1 :app \"cbcl-chat\" :purpose \"chat-device\" \
                    :key \"uAAA=\" :desc \"x\" :exp 1 :sig \"uAA\")";
        assert!(matches!(Offer::parse(text.as_bytes()), Err(RecordError::Multibase(_))));
    }

    // TEST-036 negative-input: a `:deltas` list of 1 or 4 is refused.
    #[test]
    fn a_delta_list_outside_two_to_three_is_refused() {
        let did = "did:crdt:".to_owned() + &"9f3a".repeat(16);
        for n in [0usize, 1, 4, 5] {
            let g = Grant::new(did.clone(), vec![b"{}".to_vec(); n]);
            assert_eq!(Grant::parse(&g.to_bytes()), Err(RecordError::DeltaArity), "n = {n}");
        }
        for n in [2usize, 3] {
            let g = Grant::new(did.clone(), vec![b"{}".to_vec(); n]);
            assert!(Grant::parse(&g.to_bytes()).is_ok(), "n = {n}");
        }
    }

    #[test]
    fn a_malformed_did_is_refused() {
        let g = Grant::new("did:web:example.com".into(), vec![b"{}".to_vec(); 2]);
        assert_eq!(Grant::parse(&g.to_bytes()), Err(RecordError::MalformedDid));

        let g = Grant::new("did:crdt:".to_owned() + &"9F3A".repeat(16), vec![b"{}".to_vec(); 2]);
        assert_eq!(Grant::parse(&g.to_bytes()), Err(RecordError::MalformedDid));
    }

    // TEST-035 negative-input: nothing outside the dialect is accepted, and
    // nothing panics.
    #[test]
    fn hostile_bytes_are_refused_without_panicking() {
        let cases: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"(".to_vec(),
            b")".to_vec(),
            b"(offer".to_vec(),
            b"(grant :v 1)".to_vec(),
            b"(tell @x (offer))".to_vec(),
            vec![0xff, 0xfe, 0xfd],
            b"(".repeat(4096),
            format!("(offer :v 1 :app \"{}\" )", "x".repeat(4096)).into_bytes(),
        ];
        for c in cases {
            assert!(Offer::parse(&c).is_err());
            assert!(Grant::parse(&c).is_err());
        }
    }

    // BUG-002 regression: deep nesting must be refused by the resource guard
    // rather than reaching the recursive-descent parser, which would exhaust
    // the stack. Sizes span both sides of the length cap so neither bound can
    // silently take over for the other.
    #[test]
    fn deep_nesting_is_refused_without_recursing() {
        for n in [MAX_RECORD_DEPTH + 1, 64, 512, MAX_RECORD_BYTES - 1] {
            let deep = "(".repeat(n);
            assert!(!within_resource_bounds(&deep), "depth {n} passed the guard");
            assert_eq!(Offer::parse(deep.as_bytes()), Err(RecordError::Unrecognised));
            assert_eq!(Grant::parse(deep.as_bytes()), Err(RecordError::Unrecognised));
        }
    }

    #[test]
    fn the_resource_guard_does_not_count_parentheses_inside_strings() {
        // A device description is attacker-controlled text; parentheses in it
        // are characters, not structure, and must not trip the depth guard.
        let o = Offer::sign(Application::CbclChat, &key(1), "Chrome ((((( macOS", 1_790_000_000);
        assert!(within_resource_bounds(core::str::from_utf8(&o.to_bytes()).unwrap()));
        assert!(Offer::parse(&o.to_bytes()).is_ok());

        // …including one that tries to escape the string it lives in.
        let o = Offer::sign(Application::CbclChat, &key(1), "a\\\" ((((((( b", 1_790_000_000);
        assert!(Offer::parse(&o.to_bytes()).is_ok());
    }

    #[test]
    fn an_oversized_record_is_refused_before_parsing() {
        let big = format!("(offer :desc \"{}\")", "x".repeat(MAX_RECORD_BYTES));
        assert!(!within_resource_bounds(&big));
        assert_eq!(Offer::parse(big.as_bytes()), Err(RecordError::Unrecognised));
    }
}
