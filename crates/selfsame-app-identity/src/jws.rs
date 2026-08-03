//! Compact JWS — the wire form shared by `CON-205`, `CON-214`, and `CON-225`.
//!
//! Three contracts secure a JSON object with an RFC 7515 compact JWS, and all
//! three fix the same shape: a **closed** protected header, `alg` exactly
//! `EdDSA`, no unprotected header, and no key-discovery parameter. Only the
//! `typ` value and the payload grammar differ:
//!
//! | Contract | `typ` | Payload |
//! |---|---|---|
//! | `CON-205` | `vc+jwt` | the unsecured VC document |
//! | `CON-214` | `selfsame-enrollment+jws` | the enrollment statement |
//! | `CON-225` | `selfsame-succession+jws` / `…-countersign+jws` | the succession statement |
//!
//! One recogniser serves all three (LangSec Principle 5). What differs is
//! policy, and policy is a parameter.
//!
//! # The bytes that are verified are the bytes that arrived
//!
//! [`CompactJws::signing_input`] is the exact ASCII of
//! `protected_b64 || "." || payload_b64` **as received**, not a re-serialisation
//! of the recognised header and payload. `CON-206` step 7 says so — *"Verify the
//! JWS over the original compact protected-header and payload bytes"* — and the
//! reason is that a signature is over octets. Re-canonicalising before verifying
//! would mean checking a signature over bytes the issuer never signed, which
//! turns any difference between two serialisers into a forgery oracle.
//!
//! The recognised [`Json`] values exist to be *inspected*. They are never fed
//! back into the signature check.
//!
//! # What the header may not carry
//!
//! `CON-205`: "The header SHALL contain no `jku`, `x5u`, `x5c`, embedded `jwk`,
//! or unprotected algorithm/key-discovery parameter." Each of those is a way for
//! the input to nominate the key that will verify it, which makes the signature
//! a statement about itself. The closed member set refuses them by construction,
//! and [`JwsPolicy`] names the only members a contract may add.
//!
//! `alg` is checked against an allowlist of exactly one value. `NFR-208` confines
//! version 1 to Ed25519/EdDSA, so `none` and every other algorithm are rejected
//! — not ignored, and not defaulted.

use crate::codec;
use crate::json::{self, Json, JsonError, Limits};

/// The one algorithm version 1 admits (`NFR-208`).
pub const ALG: &str = "EdDSA";

/// Header members no contract may include, at any value.
///
/// Each nominates a key or a location from which to fetch one, so accepting any
/// of them would let the input choose what verifies it.
const FORBIDDEN_HEADER_MEMBERS: &[&str] = &["jku", "x5u", "x5c", "x5t", "x5t#S256", "jwk", "epk"];

/// What shape of `kid` a contract requires.
///
/// The two differ because the two key sources differ, and neither would be safe
/// under the other's rule. A grant's key is resolved from a `did:crdt` closure,
/// so its `kid` is an absolute DID URL. An enrollment statement's key is
/// resolved from the origin-authenticated profile, so its `kid` is an HTTPS URI
/// on the `applicationId` origin with a fragment. Accepting an HTTPS `kid` on a
/// grant would reintroduce exactly the remote key URL `CON-206` step 3 forbids.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KidRule {
    /// An absolute DID URL with a fragment (`CON-205`, `CON-225` per-account).
    DidUrl,
    /// An absolute HTTPS URI with a non-empty fragment (`CON-214`, `CON-225`
    /// developer pointer).
    HttpsFragment,
}

/// What one contract requires of a compact JWS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JwsPolicy {
    /// The exact `typ` value.
    pub typ: &'static str,
    /// What shape of `kid` this contract requires.
    pub kid: KidRule,
    /// The exact `cty` value, when the contract fixes one.
    pub cty: Option<&'static str>,
    /// Octet bound on the whole compact serialisation.
    pub max_octets: usize,
    /// Nesting bound applied to the payload.
    pub max_payload_depth: usize,
    /// Whether the payload octets must be the RFC 8785 serialisation of the
    /// payload, exactly.
    ///
    /// Three of the four contracts say so in as many words — `CON-214`'s
    /// evidence is "a compact JWS over the exact UTF-8 RFC 8785 serialization",
    /// and `CON-225`'s pointer and statement are the same — so a payload with
    /// added whitespace or reordered members is not the document the contract
    /// defines, whoever signed it. `CON-205` fixes no such serialisation for a
    /// grant, and the difference is deliberate rather than an oversight: a
    /// verifier checks the bytes it received, and requiring canonical form of a
    /// W3C VC that some other issuer serialised would refuse conforming grants.
    ///
    /// The check never feeds a re-serialisation back into the signature. It
    /// compares the received octets with the canonical form of what was
    /// recognised *from those same octets*, and refuses on a difference — which
    /// is the profile recogniser's step 5 (`CON-201`) applied to a payload.
    pub canonical_payload: bool,
}

/// Why a compact JWS was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum JwsError {
    /// The serialisation exceeds the contract's octet bound.
    #[error("JWS exceeds the declared octet bound")]
    TooLarge,
    /// Not three `.`-separated segments.
    #[error("JWS is not three dot-separated segments")]
    BadSegmentCount,
    /// A segment is not canonical unpadded base64url.
    #[error("JWS segment is not canonical base64url")]
    BadBase64,
    /// The protected header is not a recognised JSON object.
    #[error("JWS protected header is not recognised: {0}")]
    BadHeader(JsonError),
    /// The payload is not a recognised JSON object.
    #[error("JWS payload is not recognised: {0}")]
    BadPayload(JsonError),
    /// `alg` is absent, or is anything other than `EdDSA`.
    #[error("JWS `alg` is not exactly EdDSA")]
    BadAlgorithm,
    /// `typ` or `cty` is absent or does not match the contract.
    #[error("JWS `typ` or `cty` does not match the contract")]
    BadType,
    /// `kid` is absent or is not an absolute DID URL.
    #[error("JWS `kid` is absent or is not an absolute DID URL")]
    BadKid,
    /// The header carries a key-discovery parameter, or a member the contract
    /// does not define.
    #[error("JWS protected header carries a forbidden or unknown member")]
    ForbiddenHeaderMember,
    /// The signature is not 64 octets.
    #[error("JWS signature is not 64 octets")]
    BadSignatureLength,
    /// The signature does not verify under the supplied key.
    #[error("JWS signature does not verify")]
    BadSignature,
    /// The payload is not the RFC 8785 serialisation its contract requires.
    #[error("JWS payload is not the canonical RFC 8785 serialisation")]
    PayloadNotCanonical,
    /// The payload carries a legacy JWT `vc` wrapper claim.
    ///
    /// `REQ-205`: "The grant SHALL NOT be wrapped in a legacy JWT `vc` claim.
    /// The unsecured VC document itself SHALL be the JWS payload."
    #[error("payload is a legacy JWT `vc` wrapper rather than the credential itself")]
    LegacyVcWrapper,
}

/// A recognised compact JWS, still holding the octets it arrived as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactJws {
    /// The recognised protected header.
    pub protected: Json,
    /// The recognised payload.
    pub payload: Json,
    /// `kid`, an absolute DID URL naming the verification method.
    pub kid: String,
    signing_input: Vec<u8>,
    signature: [u8; 64],
    payload_octets: Vec<u8>,
}

impl CompactJws {
    /// The exact octets the signature covers, as received.
    pub fn signing_input(&self) -> &[u8] {
        &self.signing_input
    }

    /// The payload octets as received, before any re-serialisation.
    pub fn payload_octets(&self) -> &[u8] {
        &self.payload_octets
    }

    /// The raw 64-octet signature.
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Verify the signature under an Ed25519 public key.
    ///
    /// The caller resolves the key from `kid` **against an authenticated
    /// source** — a `did:crdt` closure for `CON-205`, the recognised profile for
    /// `CON-214` — and never from the JWS itself.
    ///
    /// # Why the strict equation
    ///
    /// `verify_strict` rather than `verify`, and the difference is an
    /// authentication bypass rather than a preference. RFC 8032's permissive
    /// (cofactored) check accepts a signature whose `R` and public key `A` are
    /// both low-order points: with `A` the identity, `[k]A` is the identity for
    /// every challenge `k`, so `R = identity, S = 0` satisfies the equation
    /// **for any message at all**. Nothing about that forgery needs a private
    /// key.
    ///
    /// The keys that reach here are not all ones this implementation generated:
    /// a `CON-205` grant's key comes out of a `did:crdt` closure and a `CON-214`
    /// key out of a fetched profile, and neither recogniser has any reason to
    /// know that one of the eight small-order encodings is special. So the
    /// refusal belongs at the verification step, where the point is already in
    /// hand — [`ed25519_dalek::VerifyingKey::verify_strict`] rejects a
    /// small-order `A` or `R` outright.
    pub fn verify(&self, public_key: &[u8; 32]) -> Result<(), JwsError> {
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(public_key)
            .map_err(|_| JwsError::BadSignature)?;
        verifying
            .verify_strict(
                &self.signing_input,
                &ed25519_dalek::Signature::from_bytes(&self.signature),
            )
            .map_err(|_| JwsError::BadSignature)
    }
}

/// Recognise a compact JWS under one contract's policy.
///
/// Performs every check that does not need a key: shape, canonical base64url,
/// the closed header, the algorithm allowlist, and the payload grammar. The
/// signature check is separate and explicit, so a caller cannot accidentally
/// treat "well-formed" as "verified".
pub fn recognise(
    text: &str,
    policy: JwsPolicy,
    extra_header_members: &[&str],
) -> Result<CompactJws, JwsError> {
    if text.len() > policy.max_octets {
        return Err(JwsError::TooLarge);
    }
    let segments: Vec<&str> = text.split('.').collect();
    if segments.len() != 3 {
        return Err(JwsError::BadSegmentCount);
    }
    let header_octets = decode_segment(segments[0])?;
    let payload_octets = decode_segment(segments[1])?;
    let signature_octets = decode_segment(segments[2])?;

    if signature_octets.len() != 64 {
        return Err(JwsError::BadSignatureLength);
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&signature_octets);

    let header_limits = Limits { max_bytes: 4_096, max_depth: 4 };
    let protected =
        json::recognise(&header_octets, header_limits).map_err(JwsError::BadHeader)?;
    let payload_limits =
        Limits { max_bytes: policy.max_octets, max_depth: policy.max_payload_depth };
    let payload = json::recognise(&payload_octets, payload_limits).map_err(JwsError::BadPayload)?;
    // Where the contract fixes the serialisation, a second spelling of the same
    // object is a different document — checked before any member is read, so
    // nothing downstream compares against octets that were never canonical.
    if policy.canonical_payload && json::canonicalise(&payload) != payload_octets {
        return Err(JwsError::PayloadNotCanonical);
    }

    recognise_header(&protected, policy, extra_header_members)?;

    // `REQ-205`: the unsecured document is the payload, never a JWT claim set
    // wrapping it. A `vc` member at the top level is the legacy shape.
    if payload.get("vc").is_some() {
        return Err(JwsError::LegacyVcWrapper);
    }

    let kid = protected.get("kid").and_then(Json::as_str).ok_or(JwsError::BadKid)?.to_string();

    let mut signing_input = Vec::with_capacity(segments[0].len() + 1 + segments[1].len());
    signing_input.extend_from_slice(segments[0].as_bytes());
    signing_input.push(b'.');
    signing_input.extend_from_slice(segments[1].as_bytes());

    Ok(CompactJws { protected, payload, kid, signing_input, signature, payload_octets })
}

fn recognise_header(
    protected: &Json,
    policy: JwsPolicy,
    extra: &[&str],
) -> Result<(), JwsError> {
    let members = protected.as_object().ok_or(JwsError::ForbiddenHeaderMember)?;

    let mut allowed: Vec<&str> = vec!["alg", "typ", "kid"];
    if policy.cty.is_some() {
        allowed.push("cty");
    }
    allowed.extend_from_slice(extra);

    for (name, _) in members {
        if FORBIDDEN_HEADER_MEMBERS.contains(&name.as_str())
            || !allowed.contains(&name.as_str())
        {
            return Err(JwsError::ForbiddenHeaderMember);
        }
    }

    // An allowlist of exactly one algorithm. `none` is not special-cased: it is
    // simply not `EdDSA`, and neither is anything else.
    if protected.get("alg").and_then(Json::as_str) != Some(ALG) {
        return Err(JwsError::BadAlgorithm);
    }
    if protected.get("typ").and_then(Json::as_str) != Some(policy.typ) {
        return Err(JwsError::BadType);
    }
    if let Some(expected) = policy.cty {
        if protected.get("cty").and_then(Json::as_str) != Some(expected) {
            return Err(JwsError::BadType);
        }
    }

    let kid = protected.get("kid").and_then(Json::as_str).ok_or(JwsError::BadKid)?;
    match policy.kid {
        // `CON-206` step 3: "an absolute DID URL `kid`; reject remote key URLs".
        // A relative fragment would be resolved against something, and whatever
        // it was resolved against would be choosing the key.
        KidRule::DidUrl => {
            if !kid.starts_with("did:") || !kid.contains('#') {
                return Err(JwsError::BadKid);
            }
        }
        // `CON-201`: each `kid` "MUST be an absolute HTTPS URI on the
        // `applicationId` origin with a non-empty fragment". The origin check
        // belongs to the profile recogniser, which has the origin; here the
        // shape is checked so a `did:` or relative value cannot slip through.
        KidRule::HttpsFragment => {
            if crate::uri::recognise(kid, crate::uri::UriPolicy::FRAGMENT_ID).is_err() {
                return Err(JwsError::BadKid);
            }
        }
    }
    Ok(())
}

fn decode_segment(segment: &str) -> Result<Vec<u8>, JwsError> {
    use base64ct::Encoding as _;
    if segment.is_empty()
        || !segment.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(JwsError::BadBase64);
    }
    let decoded =
        base64ct::Base64UrlUnpadded::decode_vec(segment).map_err(|_| JwsError::BadBase64)?;
    // TEST-208 requires non-canonical base64url to be rejected. Trailing bits
    // that re-encode differently are a second spelling of the same octets, and
    // a second spelling of a *signing input* is a second signature over one
    // message.
    if codec::b64url(&decoded) != segment {
        return Err(JwsError::BadBase64);
    }
    Ok(decoded)
}

/// Produce a compact JWS over the canonical serialisation of `payload`.
///
/// The issuer's side. Emitting RFC 8785 canonical octets is not required by
/// `CON-205` — a verifier checks the bytes it received — but it is what makes a
/// published vector reproducible by a second implementation, which `NFR-202`
/// does require.
pub fn sign(header: &Json, payload: &Json, key: &ed25519_dalek::SigningKey) -> String {
    use ed25519_dalek::Signer as _;
    let header_b64 = codec::b64url(&json::canonicalise(header));
    let payload_b64 = codec::b64url(&json::canonicalise(payload));
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", codec::b64url(&signature.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: JwsPolicy = JwsPolicy {
        typ: "vc+jwt",
        kid: KidRule::DidUrl,
        cty: Some("vc"),
        max_octets: 65_536,
        max_payload_depth: 8,
        canonical_payload: false,
    };

    fn key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    fn header() -> Json {
        Json::obj([
            ("alg", Json::text("EdDSA")),
            ("kid", Json::text("did:crdt:abc#jwk-0")),
            ("typ", Json::text("vc+jwt")),
            ("cty", Json::text("vc")),
        ])
    }

    fn payload() -> Json {
        Json::obj([("id", Json::text("did:crdt:abc#grant-x")), ("n", Json::int(1))])
    }

    fn signed() -> String {
        sign(&header(), &payload(), &key())
    }

    /// Sign over payload octets exactly as given, canonical or not.
    ///
    /// [`sign`] canonicalises, which is right for an issuer and useless for
    /// testing what a verifier does with a payload some other issuer spelled
    /// differently.
    fn sign_raw(header: &Json, payload_octets: &[u8], key: &ed25519_dalek::SigningKey) -> String {
        use ed25519_dalek::Signer as _;
        let signing_input = format!(
            "{}.{}",
            codec::b64url(&json::canonicalise(header)),
            codec::b64url(payload_octets)
        );
        let signature = key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", codec::b64url(&signature.to_bytes()))
    }

    // TEST-207 positive.
    #[test]
    fn recognises_and_verifies_a_well_formed_grant_jws() {
        let text = signed();
        let jws = recognise(&text, POLICY, &[]).unwrap();
        assert_eq!(jws.kid, "did:crdt:abc#jwk-0");
        assert_eq!(jws.payload, payload());
        assert!(jws.verify(&key().verifying_key().to_bytes()).is_ok());
    }

    #[test]
    fn the_signing_input_is_the_received_octets_not_a_re_serialisation() {
        let text = signed();
        let jws = recognise(&text, POLICY, &[]).unwrap();
        let expected = text.rsplit_once('.').unwrap().0;
        assert_eq!(jws.signing_input(), expected.as_bytes());
    }

    // TEST-208, item by item.
    #[test]
    fn rejects_alg_none_and_every_algorithm_substitution() {
        for alg in ["none", "None", "HS256", "RS256", "ES256", "EdDSA "] {
            let mut h = header();
            let Json::Object(members) = &mut h else { unreachable!() };
            members.iter_mut().find(|(k, _)| k == "alg").unwrap().1 = Json::text(alg);
            let text = sign(&h, &payload(), &key());
            assert_eq!(recognise(&text, POLICY, &[]), Err(JwsError::BadAlgorithm), "{alg}");
        }
    }

    #[test]
    fn rejects_a_missing_relative_or_wrong_kid() {
        for kid in ["#jwk-0", "jwk-0", "https://photos.example/key#k", "did:crdt:abc"] {
            let mut h = header();
            let Json::Object(members) = &mut h else { unreachable!() };
            members.iter_mut().find(|(k, _)| k == "kid").unwrap().1 = Json::text(kid);
            let text = sign(&h, &payload(), &key());
            assert_eq!(recognise(&text, POLICY, &[]), Err(JwsError::BadKid), "{kid}");
        }
        // Absent entirely.
        let h = Json::obj([
            ("alg", Json::text("EdDSA")),
            ("typ", Json::text("vc+jwt")),
            ("cty", Json::text("vc")),
        ]);
        let text = sign(&h, &payload(), &key());
        assert_eq!(recognise(&text, POLICY, &[]), Err(JwsError::BadKid));
    }

    #[test]
    fn the_two_kid_rules_do_not_admit_each_others_shapes() {
        // A grant's key comes from a did:crdt closure and an enrollment
        // statement's from the authenticated profile. Accepting an HTTPS `kid`
        // on a grant would reintroduce the remote key URL CON-206 step 3
        // forbids; accepting a DID URL on an enrollment statement would name a
        // key the profile cannot resolve.
        const HTTPS_POLICY: JwsPolicy = JwsPolicy {
            typ: "selfsame-enrollment+jws",
            kid: KidRule::HttpsFragment,
            cty: None,
            max_octets: 8_192,
            max_payload_depth: 4,
            canonical_payload: true,
        };
        let https_kid = "https://photos.example/selfsame/application#enrollment-2026-01";

        let h = Json::obj([
            ("alg", Json::text("EdDSA")),
            ("typ", Json::text("selfsame-enrollment+jws")),
            ("kid", Json::text(https_kid)),
        ]);
        let text = sign(&h, &payload(), &key());
        assert!(recognise(&text, HTTPS_POLICY, &[]).is_ok(), "an HTTPS kid is the enrollment shape");

        let h = Json::obj([
            ("alg", Json::text("EdDSA")),
            ("typ", Json::text("selfsame-enrollment+jws")),
            ("kid", Json::text("did:crdt:abc#jwk-0")),
        ]);
        let text = sign(&h, &payload(), &key());
        assert_eq!(recognise(&text, HTTPS_POLICY, &[]), Err(JwsError::BadKid));

        // …and an HTTPS kid on a grant.
        let text = sign(&header(), &payload(), &key());
        let _ = text;
        let h = Json::obj([
            ("alg", Json::text("EdDSA")),
            ("kid", Json::text(https_kid)),
            ("typ", Json::text("vc+jwt")),
            ("cty", Json::text("vc")),
        ]);
        let text = sign(&h, &payload(), &key());
        assert_eq!(recognise(&text, POLICY, &[]), Err(JwsError::BadKid));
    }

    #[test]
    fn a_non_canonical_payload_is_refused_only_where_the_contract_fixes_it() {
        // `CON-214`'s evidence and both `CON-225` forms are defined as a JWS
        // over the *exact* RFC 8785 serialisation, so a signer that adds a
        // space or reorders two members has not produced that document — even
        // though the signature over those octets is perfectly good and the
        // recognised value is identical. `CON-205` fixes no serialisation for a
        // grant, and the same octets must therefore still be accepted there.
        const CANONICAL: JwsPolicy = JwsPolicy {
            typ: "selfsame-enrollment+jws",
            kid: KidRule::HttpsFragment,
            cty: None,
            max_octets: 8_192,
            max_payload_depth: 4,
            canonical_payload: true,
        };
        let canonical_header = Json::obj([
            ("alg", Json::text("EdDSA")),
            ("typ", Json::text("selfsame-enrollment+jws")),
            ("kid", Json::text("https://photos.example/selfsame/application#enrollment-1")),
        ]);

        for spelling in [
            // A space after a colon.
            br#"{"id":"did:crdt:abc#grant-x", "n":1}"#.to_vec(),
            // The same members in another order.
            br#"{"n":1,"id":"did:crdt:abc#grant-x"}"#.to_vec(),
        ] {
            let text = sign_raw(&canonical_header, &spelling, &key());
            assert_eq!(
                recognise(&text, CANONICAL, &[]),
                Err(JwsError::PayloadNotCanonical),
                "{}",
                String::from_utf8_lossy(&spelling)
            );

            // The same octets under a grant's policy: recognised, and the
            // signature over them verifies.
            let text = sign_raw(&header(), &spelling, &key());
            let jws = recognise(&text, POLICY, &[]).expect("CON-205 fixes no serialisation");
            assert!(jws.verify(&key().verifying_key().to_bytes()).is_ok());
        }

        // The canonical spelling of the same object passes both.
        let canonical = json::canonicalise(&payload());
        let text = sign_raw(&canonical_header, &canonical, &key());
        let jws = recognise(&text, CANONICAL, &[]).expect("the exact RFC 8785 octets");
        assert_eq!(jws.payload, payload());
    }

    #[test]
    fn rejects_every_key_discovery_parameter() {
        // Each of these lets the input nominate what verifies it.
        for member in ["jku", "x5u", "x5c", "jwk", "epk"] {
            let Json::Object(mut members) = header() else { unreachable!() };
            members.push((member.to_string(), Json::text("x")));
            let text = sign(&Json::Object(members), &payload(), &key());
            assert_eq!(
                recognise(&text, POLICY, &[]),
                Err(JwsError::ForbiddenHeaderMember),
                "{member}"
            );
        }
    }

    #[test]
    fn rejects_an_unknown_header_member() {
        let Json::Object(mut members) = header() else { unreachable!() };
        members.push(("crit".to_string(), Json::arr([Json::text("x")])));
        let text = sign(&Json::Object(members), &payload(), &key());
        assert_eq!(recognise(&text, POLICY, &[]), Err(JwsError::ForbiddenHeaderMember));
    }

    #[test]
    fn rejects_a_wrong_typ_or_cty() {
        for (member, value) in [("typ", "JWT"), ("cty", "json")] {
            let mut h = header();
            let Json::Object(members) = &mut h else { unreachable!() };
            members.iter_mut().find(|(k, _)| k == member).unwrap().1 = Json::text(value);
            let text = sign(&h, &payload(), &key());
            assert_eq!(recognise(&text, POLICY, &[]), Err(JwsError::BadType), "{member}={value}");
        }
    }

    #[test]
    fn rejects_a_legacy_vc_wrapper_claim() {
        let wrapped = Json::obj([("iss", Json::text("did:crdt:abc")), ("vc", payload())]);
        let text = sign(&header(), &wrapped, &key());
        assert_eq!(recognise(&text, POLICY, &[]), Err(JwsError::LegacyVcWrapper));
    }

    #[test]
    fn rejects_duplicate_json_member_names_in_the_header_or_payload() {
        let text = signed();
        let (header_b64, rest) = text.split_once('.').unwrap();
        let doubled_header = codec::b64url(
            br#"{"alg":"EdDSA","alg":"none","cty":"vc","kid":"did:crdt:abc#jwk-0","typ":"vc+jwt"}"#,
        );
        let mutated = format!("{doubled_header}.{rest}");
        assert!(matches!(recognise(&mutated, POLICY, &[]), Err(JwsError::BadHeader(_))));
        let _ = header_b64;
    }

    #[test]
    fn rejects_malformed_compact_serialisation() {
        let text = signed();
        for mutated in [
            text.replace('.', ""),
            format!("{text}.extra"),
            text.split_once('.').unwrap().1.to_string(),
            format!(".{text}"),
        ] {
            assert!(
                matches!(
                    recognise(&mutated, POLICY, &[]),
                    Err(JwsError::BadSegmentCount | JwsError::BadBase64)
                ),
                "{mutated:.40}"
            );
        }
    }

    #[test]
    fn rejects_non_canonical_base64url() {
        let text = signed();
        let (head, tail) = text.split_once('.').unwrap();
        // Append padding, which is never canonical for unpadded base64url.
        assert_eq!(recognise(&format!("{head}=.{tail}"), POLICY, &[]), Err(JwsError::BadBase64));
    }

    // TEST-208: an altered payload no longer verifies.
    #[test]
    fn an_altered_payload_recognises_but_does_not_verify() {
        let text = signed();
        let mutated_payload = codec::b64url(&json::canonicalise(&Json::obj([
            ("id", Json::text("did:crdt:abc#grant-y")),
            ("n", Json::int(1)),
        ])));
        let mut parts: Vec<&str> = text.split('.').collect();
        parts[1] = &mutated_payload;
        let mutated = parts.join(".");
        let jws = recognise(&mutated, POLICY, &[]).expect("still well-formed");
        assert_eq!(
            jws.verify(&key().verifying_key().to_bytes()),
            Err(JwsError::BadSignature),
            "recognition is not verification, and the test says so"
        );
    }

    #[test]
    fn a_signature_by_another_key_does_not_verify() {
        let text = signed();
        let jws = recognise(&text, POLICY, &[]).unwrap();
        let other = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        assert_eq!(jws.verify(&other.verifying_key().to_bytes()), Err(JwsError::BadSignature));
    }

    #[test]
    fn a_low_order_key_cannot_forge_a_signature_over_arbitrary_input() {
        // The bypass `verify_strict` exists to close. `A` is the identity
        // point, so `[k]A` is the identity whatever the challenge scalar is,
        // and the fixed pair `R = identity, S = 0` therefore satisfies the
        // permissive equation over *every* signing input. A profile or a
        // closure that names such a key would let any party produce enrollment
        // evidence or a succession statement under it.
        let mut weak = [0u8; 32];
        weak[0] = 1;
        let mut forged = [0u8; 64];
        forged[0] = 1; // R = the identity encoding; S stays zero.

        let text = signed();
        let (head, _) = text.rsplit_once('.').unwrap();
        let mutated = format!("{head}.{}", codec::b64url(&forged));
        let jws = recognise(&mutated, POLICY, &[]).expect("the shape is untouched");

        // First: the forgery is real. If a future `ed25519-dalek` stops
        // accepting it under the permissive check, this assertion fails and
        // says so, rather than leaving the one below asserting nothing.
        {
            use ed25519_dalek::Verifier as _;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&weak).expect("a valid point");
            assert!(
                key.verify(
                    jws.signing_input(),
                    &ed25519_dalek::Signature::from_bytes(&forged)
                )
                .is_ok(),
                "the permissive equation no longer accepts the low-order forgery"
            );
        }
        // Second: this crate does not.
        assert_eq!(jws.verify(&weak), Err(JwsError::BadSignature));
    }

    #[test]
    fn rejects_a_signature_of_the_wrong_length() {
        let text = signed();
        let (head, _) = text.rsplit_once('.').unwrap();
        let short = format!("{head}.{}", codec::b64url(&[0u8; 32]));
        assert_eq!(recognise(&short, POLICY, &[]), Err(JwsError::BadSignatureLength));
    }

    #[test]
    fn rejects_input_over_the_declared_octet_bound() {
        let small = JwsPolicy { max_octets: 16, ..POLICY };
        assert_eq!(recognise(&signed(), small, &[]), Err(JwsError::TooLarge));
    }
}
