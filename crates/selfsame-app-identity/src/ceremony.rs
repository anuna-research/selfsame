//! Ceremony payloads and the same-device handoff — `CON-219`, `CON-215`,
//! `REQ-211`, `REQ-220` to `REQ-225`.
//!
//! `REQ-221` is why there is one payload module rather than two. The same-device
//! path "SHALL use the same fresh offer, application evidence, provider
//! selection, SPAKE2 roles and confirmation, derived rendezvous slots, encrypted
//! grant bundle, acceptance predicate, device proof, and state-publication path
//! as the cross-device ceremony; only delivery of the logical pairing bootstrap
//! to Selfsame and an optional non-authoritative UI return differ." So
//! [`Handoff`] and [`HandoffReturn`] are the *only* same-device types in this
//! crate — everything else on that path is the cross-device type, which is what
//! stops a platform adapter becoming "a second grant protocol with a different
//! security state machine".
//!
//! PROTO-004 seals and recognises the envelope; this contract declares the two
//! payload member sets that PROTO-004 leaves to the enclosing profile, and the
//! digest rule that lets a developer backend commit to an offer it does not yet
//! hold.
//!
//! # `offer_core` and the digest that has no fixed point
//!
//! ```text
//! offer_core  = the offer payload without "enrollmentEvidence" and "providerHint"
//! offerDigest = BASE64URL-NOPAD(SHA-256(RFC8785(offer_core)))
//! ```
//!
//! The two excluded members are **exactly the two that carry `offerDigest`
//! themselves**. Excluding them is what makes the digest well-defined: a digest
//! computed over an object containing itself has no fixed point, and version 1
//! does not attempt one. `CON-214` puts the consequence bluntly — an
//! implementation that computes the digest over the complete offer payload "MUST
//! be rejected as non-conforming rather than accommodated."
//!
//! The construction order follows mechanically, and is fixed:
//!
//! ```text
//! 1. assemble offer_core
//! 2. compute offerDigest
//! 3. the backend signs the CON-214 statement carrying that digest
//! 4. build the CON-209 hint carrying the same digest
//! 5. assemble the complete offer payload and seal it
//! ```
//!
//! Excluding them does not leave them unauthenticated: the PROTO-004 tag covers
//! the complete payload, and the `CON-214` signature independently covers every
//! security-relevant `offer_core` value. `offerDigest` exists only so a backend
//! that never sees the sealed record can bind its signature to the exact request
//! that will be sealed.
//!
//! # The grant travels verbatim
//!
//! `REQ-211`: the ceremony carries the compact JWS bytes and the exact media
//! type, and the outer transport "SHALL NOT translate the VC properties,
//! reserialize its JWS components, replace its signature, or call an outer
//! signature 'VC conformance.'"
//!
//! So `grant` is the ASCII string it already is, not re-encoded. `CON-219` gives
//! the arithmetic reason as well as the principle: a compact JWS is three
//! base64url segments separated by `.`, so every character is already
//! JSON-string-safe, and base64url-encoding it a second time would expand 65,536
//! octets to 87,382 — 17,771 over the payload bound.
//!
//! # Bundle length is not observable
//!
//! PROTO-004 pads every sealed record to a fixed size, so whether a bundle
//! inlines a closure, and how large that closure is, is invisible to the
//! rendezvous operator. That matters because closure size tracks a DID's delta
//! history and would otherwise be a per-account fingerprint.

use crate::codec;
use crate::json::{self, Json, JsonError, Limits};
use crate::time::{self, TimeError};
use crate::UnixSeconds;

/// `CON-219`: the declared payload bound in octets.
pub const MAX_PAYLOAD_OCTETS: usize = 69_607;

/// `CON-219`: the declared nesting bound.
pub const MAX_PAYLOAD_DEPTH: usize = 8;

/// `CON-219`: the ceiling on the verbatim compact JWS.
pub const MAX_GRANT_CHARS: usize = 65_536;

/// The exact media type the bundle carries beside the grant.
pub const GRANT_MEDIA_TYPE: &str = "application/vc+jwt";

/// `CON-219`: the offer and enrollment window, in seconds.
pub const MAX_OFFER_WINDOW_SECONDS: i64 = 120;

/// Octets of the PROTO-003 human code `C`.
pub const CODE_OCTETS: usize = 16;

/// The thirteen `offer_core` members, in the order `CON-219` prints them.
pub const OFFER_CORE_MEMBERS: &[&str] = &[
    "payloadVersion",
    "role",
    "ceremonyId",
    "requestId",
    "applicationId",
    "profileVersion",
    "profileDigest",
    "accountScopeId",
    "deviceDid",
    "deviceKeyJwk",
    "requestedPermissions",
    "issuedAt",
    "expiresAt",
];

/// The two members excluded from `offer_core`, because they carry the digest.
pub const OFFER_EXCLUDED_MEMBERS: &[&str] = &["enrollmentEvidence", "providerHint"];

/// The seven bundle members, of which `issuerClosure` is the only optional one.
pub const BUNDLE_MEMBERS: &[&str] = &[
    "payloadVersion",
    "role",
    "ceremonyId",
    "requestId",
    "grantMediaType",
    "grant",
    "issuerClosure",
];

/// Why a ceremony payload was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CeremonyError {
    /// The payload is not recognised JSON within the declared bounds.
    #[error("ceremony payload is not recognised: {0}")]
    Json(#[from] JsonError),
    /// A member the payload requires is absent or the wrong type.
    #[error("ceremony payload member `{0}` is absent or malformed")]
    BadMember(String),
    /// The payload carries a member the contract does not define.
    #[error("ceremony payload carries the unknown member `{0}`")]
    UnknownMember(String),
    /// A value is present but outside its grammar.
    #[error("ceremony payload member `{path}` is invalid: {reason}")]
    BadValue {
        /// The member.
        path: String,
        /// What rule it broke.
        reason: &'static str,
    },
    /// `CON-219`: the sealed record would exceed the declared payload bound.
    ///
    /// One of the closed error tokens `CON-226` requires a corpus case for. It
    /// is never a silent truncation: an implementation whose closure does not
    /// fit omits it and lets the verifier resolve one.
    #[error("payload too large")]
    PayloadTooLarge,
    /// The recomputed `offerDigest` does not equal the one a bound value carries.
    ///
    /// One of `CON-214`'s closed error tokens.
    #[error("offer mismatch")]
    OfferMismatch,
}

fn bad(path: impl Into<String>, reason: &'static str) -> CeremonyError {
    CeremonyError::BadValue { path: path.into(), reason }
}

/// The thirteen semantic members of an offer, before it is sealed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferCore {
    /// The ceremony identifier, 32 random octets base64url.
    pub ceremony_id: String,
    /// The one-time request identifier, 32 random octets base64url.
    pub request_id: String,
    /// The canonical application identifier.
    pub application_id: String,
    /// The profile version.
    pub profile_version: i64,
    /// `SHA-256(RFC8785(profile))`, base64url.
    pub profile_digest: String,
    /// The private account scope. Never leaves the sealed offer.
    pub account_scope_id: String,
    /// The device DID the grant will name as subject.
    pub device_did: String,
    /// The device public key, which `CON-205` requires in `cnf.jwk`.
    pub device_public_key: [u8; 32],
    /// The requested permissions, sorted and an exact subset of the profile's.
    pub requested_permissions: Vec<String>,
    /// When the offer was issued.
    pub issued_at: UnixSeconds,
    /// When it expires, at most 120 seconds later.
    pub expires_at: UnixSeconds,
}

impl OfferCore {
    /// Serialise the thirteen members, in `CON-219`'s printed order.
    ///
    /// Order in the value is irrelevant to the digest — RFC 8785 sorts — but it
    /// is kept because a reader comparing this to the contract should see the
    /// same sequence.
    pub fn to_json(&self) -> Json {
        Json::obj([
            ("payloadVersion", Json::int(1)),
            ("role", Json::text("offer")),
            ("ceremonyId", Json::text(self.ceremony_id.clone())),
            ("requestId", Json::text(self.request_id.clone())),
            ("applicationId", Json::text(self.application_id.clone())),
            ("profileVersion", Json::int(self.profile_version)),
            ("profileDigest", Json::text(self.profile_digest.clone())),
            ("accountScopeId", Json::text(self.account_scope_id.clone())),
            ("deviceDid", Json::text(self.device_did.clone())),
            (
                "deviceKeyJwk",
                Json::obj([
                    ("kty", Json::text("OKP")),
                    ("crv", Json::text("Ed25519")),
                    ("alg", Json::text("EdDSA")),
                    ("x", Json::text(codec::b64url(&self.device_public_key))),
                ]),
            ),
            (
                "requestedPermissions",
                Json::Array(
                    self.requested_permissions.iter().map(|p| Json::text(p.clone())).collect(),
                ),
            ),
            ("issuedAt", Json::text(time::format_date_time_stamp(self.issued_at))),
            ("expiresAt", Json::text(time::format_date_time_stamp(self.expires_at))),
        ])
    }

    /// `offerDigest = BASE64URL-NOPAD(SHA-256(RFC8785(offer_core)))`.
    pub fn digest(&self) -> String {
        offer_digest(&self.to_json())
    }
}

/// Compute `offerDigest` over an already-assembled `offer_core` value.
pub fn offer_digest(offer_core: &Json) -> String {
    use sha2::Digest as _;
    let digest: [u8; 32] = sha2::Sha256::digest(json::canonicalise(offer_core)).into();
    codec::b64url(&digest)
}

/// Extract `offer_core` from a complete offer payload and digest it.
///
/// What the wallet does on receipt: recompute from "the `offer_core` members of
/// the payload it actually opened", then require equality with the digest inside
/// the verified enrollment evidence **and** the one inside the provider hint.
pub fn digest_of_received_offer(payload: &Json) -> Result<String, CeremonyError> {
    let members = payload
        .as_object()
        .ok_or_else(|| CeremonyError::BadMember("<root>".into()))?;
    let core: Vec<(String, Json)> = members
        .iter()
        .filter(|(name, _)| !OFFER_EXCLUDED_MEMBERS.contains(&name.as_str()))
        .cloned()
        .collect();
    if core.len() != OFFER_CORE_MEMBERS.len() {
        return Err(bad("<root>", "offer_core does not hold exactly thirteen members"));
    }
    Ok(offer_digest(&Json::Object(core)))
}

/// A recognised offer payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferPayload {
    /// The thirteen semantic members.
    pub core: OfferCore,
    /// The `CON-214` compact JWS.
    pub enrollment_evidence: String,
    /// The `CON-209` hint, still as a value for [`crate::selection::ProviderHint`].
    pub provider_hint: Json,
    /// The digest recomputed from the members actually opened.
    pub offer_digest: String,
}

/// Recognise an offer payload as a closed language.
pub fn recognise_offer(octets: &[u8]) -> Result<OfferPayload, CeremonyError> {
    let limits = Limits { max_bytes: MAX_PAYLOAD_OCTETS, max_depth: MAX_PAYLOAD_DEPTH };
    if octets.len() > MAX_PAYLOAD_OCTETS {
        return Err(CeremonyError::PayloadTooLarge);
    }
    let payload = json::recognise(octets, limits)?;
    let members = payload.as_object().ok_or_else(|| CeremonyError::BadMember("<root>".into()))?;

    // The member set is exactly those fifteen names.
    for (name, _) in members {
        if !OFFER_CORE_MEMBERS.contains(&name.as_str())
            && !OFFER_EXCLUDED_MEMBERS.contains(&name.as_str())
        {
            return Err(CeremonyError::UnknownMember(name.clone()));
        }
    }
    for name in OFFER_CORE_MEMBERS.iter().chain(OFFER_EXCLUDED_MEMBERS) {
        if payload.get(name).is_none() {
            return Err(CeremonyError::BadMember((*name).to_string()));
        }
    }

    if payload.get("payloadVersion").and_then(Json::as_i64) != Some(1) {
        return Err(bad("payloadVersion", "must be exactly 1"));
    }
    if payload.get("role").and_then(Json::as_str) != Some("offer") {
        return Err(bad("role", "must be exactly `offer`"));
    }

    let text = |name: &str| -> Result<String, CeremonyError> {
        payload
            .get(name)
            .and_then(Json::as_str)
            .map(str::to_string)
            .ok_or_else(|| CeremonyError::BadMember(name.to_string()))
    };

    let ceremony_id = random_id(&text("ceremonyId")?, "ceremonyId")?;
    let request_id = random_id(&text("requestId")?, "requestId")?;
    let profile_digest = random_id(&text("profileDigest")?, "profileDigest")?;
    let account_scope_id = text("accountScopeId")?;
    crate::scope::AccountScopeId::parse(&account_scope_id)
        .map_err(|_| bad("accountScopeId", "is not a canonical account scope"))?;

    let device_did = text("deviceDid")?;
    let jwk = payload
        .get("deviceKeyJwk")
        .ok_or_else(|| CeremonyError::BadMember("deviceKeyJwk".into()))?;
    for (name, _) in jwk.as_object().ok_or_else(|| bad("deviceKeyJwk", "is not an object"))? {
        if !["kty", "crv", "alg", "x"].contains(&name.as_str()) {
            return Err(CeremonyError::UnknownMember(format!("deviceKeyJwk.{name}")));
        }
    }
    if jwk.get("kty").and_then(Json::as_str) != Some("OKP")
        || jwk.get("crv").and_then(Json::as_str) != Some("Ed25519")
    {
        return Err(bad("deviceKeyJwk", "is not an OKP/Ed25519 key"));
    }
    let device_public_key = codec::decode_b64url_32(
        jwk.get("x").and_then(Json::as_str).ok_or_else(|| bad("deviceKeyJwk.x", "is absent"))?,
    )
    .map_err(|_| bad("deviceKeyJwk.x", "is not a canonical 32-octet base64url value"))?;
    // `deviceDid` encodes the same key. Two members naming one key is two places
    // a substitution could hide, so they are compared here rather than later.
    crate::didkey::matches_jwk(&device_did, &device_public_key)
        .map_err(|_| bad("deviceDid", "does not encode deviceKeyJwk"))?;

    let permission_items = payload
        .get("requestedPermissions")
        .and_then(Json::as_array)
        .ok_or_else(|| CeremonyError::BadMember("requestedPermissions".into()))?;
    if permission_items.is_empty() {
        return Err(bad("requestedPermissions", "must be a non-empty set"));
    }
    let mut requested_permissions = Vec::with_capacity(permission_items.len());
    for item in permission_items {
        requested_permissions.push(
            item.as_str().ok_or_else(|| bad("requestedPermissions", "entry is not a string"))?
                .to_string(),
        );
    }
    if requested_permissions.windows(2).any(|w| w[0] >= w[1]) {
        return Err(bad("requestedPermissions", "is unsorted or contains a duplicate"));
    }

    let issued_at = stamp(&text("issuedAt")?, "issuedAt")?;
    let expires_at = stamp(&text("expiresAt")?, "expiresAt")?;
    if expires_at <= issued_at || expires_at - issued_at > MAX_OFFER_WINDOW_SECONDS {
        return Err(bad("expiresAt", "is not later than issuedAt by at most 120 seconds"));
    }

    let core = OfferCore {
        ceremony_id,
        request_id,
        application_id: text("applicationId")?,
        profile_version: payload
            .get("profileVersion")
            .and_then(Json::as_i64)
            .ok_or_else(|| CeremonyError::BadMember("profileVersion".into()))?,
        profile_digest,
        account_scope_id,
        device_did,
        device_public_key,
        requested_permissions,
        issued_at,
        expires_at,
    };

    let offer_digest = digest_of_received_offer(&payload)?;
    Ok(OfferPayload {
        core,
        enrollment_evidence: text("enrollmentEvidence")?,
        provider_hint: payload.get("providerHint").cloned().unwrap_or(Json::Null),
        offer_digest,
    })
}

/// A recognised grant bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundlePayload {
    /// The exact `ceremonyId` from the offer.
    pub ceremony_id: String,
    /// The exact `requestId` from the offer.
    pub request_id: String,
    /// The compact JWS, verbatim.
    pub grant: String,
    /// An optional `did:crdt` closure the verifier may consume without a
    /// round trip.
    pub issuer_closure: Option<Vec<u8>>,
}

/// Assemble a bundle payload, refusing rather than truncating (`CON-219`).
pub fn build_bundle(
    ceremony_id: &str,
    request_id: &str,
    grant: &str,
    issuer_closure: Option<&[u8]>,
) -> Result<Vec<u8>, CeremonyError> {
    if grant.len() > MAX_GRANT_CHARS {
        return Err(CeremonyError::PayloadTooLarge);
    }
    let mut members = vec![
        ("payloadVersion", Json::int(1)),
        ("role", Json::text("bundle")),
        ("ceremonyId", Json::text(ceremony_id)),
        ("requestId", Json::text(request_id)),
        ("grantMediaType", Json::text(GRANT_MEDIA_TYPE)),
        ("grant", Json::text(grant)),
    ];
    if let Some(closure) = issuer_closure {
        members.push(("issuerClosure", Json::text(codec::b64url(closure))));
    }
    let value =
        Json::Object(members.into_iter().map(|(k, v)| (k.to_string(), v)).collect());
    let octets = json::canonicalise(&value);
    // "A payload exceeding the bound is a `PayloadTooLarge` failure, never a
    // silent truncation." An implementation whose closure does not fit omits it
    // and lets the verifier resolve one.
    if octets.len() > MAX_PAYLOAD_OCTETS {
        return Err(CeremonyError::PayloadTooLarge);
    }
    Ok(octets)
}

/// Recognise a grant bundle as a closed language.
pub fn recognise_bundle(octets: &[u8]) -> Result<BundlePayload, CeremonyError> {
    if octets.len() > MAX_PAYLOAD_OCTETS {
        return Err(CeremonyError::PayloadTooLarge);
    }
    let limits = Limits { max_bytes: MAX_PAYLOAD_OCTETS, max_depth: MAX_PAYLOAD_DEPTH };
    let payload = json::recognise(octets, limits)?;
    let members = payload.as_object().ok_or_else(|| CeremonyError::BadMember("<root>".into()))?;

    for (name, _) in members {
        if !BUNDLE_MEMBERS.contains(&name.as_str()) {
            return Err(CeremonyError::UnknownMember(name.clone()));
        }
    }
    for name in &BUNDLE_MEMBERS[..6] {
        if payload.get(name).is_none() {
            return Err(CeremonyError::BadMember((*name).to_string()));
        }
    }
    if payload.get("payloadVersion").and_then(Json::as_i64) != Some(1) {
        return Err(bad("payloadVersion", "must be exactly 1"));
    }
    if payload.get("role").and_then(Json::as_str) != Some("bundle") {
        return Err(bad("role", "must be exactly `bundle`"));
    }
    if payload.get("grantMediaType").and_then(Json::as_str) != Some(GRANT_MEDIA_TYPE) {
        return Err(bad("grantMediaType", "must be exactly application/vc+jwt"));
    }

    let grant = payload
        .get("grant")
        .and_then(Json::as_str)
        .ok_or_else(|| CeremonyError::BadMember("grant".into()))?;
    if grant.len() > MAX_GRANT_CHARS {
        return Err(CeremonyError::PayloadTooLarge);
    }

    let issuer_closure = match payload.get("issuerClosure") {
        None => None,
        Some(v) => {
            let text = v.as_str().ok_or_else(|| bad("issuerClosure", "is not a string"))?;
            use base64ct::Encoding as _;
            Some(
                base64ct::Base64UrlUnpadded::decode_vec(text)
                    .map_err(|_| bad("issuerClosure", "is not canonical base64url"))?,
            )
        }
    };

    Ok(BundlePayload {
        ceremony_id: random_id(
            payload
                .get("ceremonyId")
                .and_then(Json::as_str)
                .ok_or_else(|| CeremonyError::BadMember("ceremonyId".into()))?,
            "ceremonyId",
        )?,
        request_id: random_id(
            payload
                .get("requestId")
                .and_then(Json::as_str)
                .ok_or_else(|| CeremonyError::BadMember("requestId".into()))?,
            "requestId",
        )?,
        grant: grant.to_string(),
        issuer_closure,
    })
}

/// `CON-219`: a bundle whose identifiers are not the ones this application
/// sealed into its offer "is a rejection, not a new ceremony".
pub fn bundle_matches_offer(
    bundle: &BundlePayload,
    offer: &OfferCore,
) -> Result<(), CeremonyError> {
    if bundle.ceremony_id != offer.ceremony_id || bundle.request_id != offer.request_id {
        return Err(CeremonyError::OfferMismatch);
    }
    Ok(())
}

fn random_id(text: &str, path: &'static str) -> Result<String, CeremonyError> {
    codec::decode_b64url_32(text)
        .map_err(|_| bad(path, "is not a canonical 32-octet base64url value"))?;
    Ok(text.to_string())
}

fn stamp(text: &str, path: &'static str) -> Result<UnixSeconds, CeremonyError> {
    time::parse_date_time_stamp(text).map_err(|e| match e {
        TimeError::Malformed => bad(path, "is not a UTC XML Schema dateTimeStamp"),
        TimeError::OutOfRange => bad(path, "names a date or time that does not exist"),
    })
}

// ── CON-215: the same-device handoff ───────────────────────────────────────

/// What a platform adapter returned (`CON-215`).
///
/// `REQ-225`: every result except [`Dispatched`](DispatchResult::Dispatched),
/// "and every ambiguous post-dispatch condition, abandons the ceremony". The
/// install or help action offered afterwards is a separate action containing no
/// ceremony value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchResult {
    /// Delivered to the verified installed wallet.
    Dispatched,
    /// No conforming wallet is installed.
    WalletUnavailable,
    /// A candidate exists but its signing identity did not verify.
    UnverifiedWalletTarget,
    /// The handoff value did not recognise.
    HandoffMalformed,
    /// The platform could not prove delivery to the intended target.
    HandoffAmbiguous,
    /// The wallet reported a caller-binding mismatch.
    PlatformBindingMismatch,
    /// The person declined.
    UserDenied,
}

impl DispatchResult {
    /// Whether this outcome burns the ceremony (`REQ-225`).
    pub fn burns_ceremony(self) -> bool {
        self != DispatchResult::Dispatched
    }
}

/// The closed same-device handoff (`CON-215`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handoff {
    /// The 32-octet ceremony identifier, the same one `CON-214` carries.
    pub ceremony_id: String,
    /// The same digest `CON-214` carries.
    pub offer_digest: String,
    /// The sixteen octets of the PROTO-003 code `C`, never its word rendering.
    pub code: [u8; CODE_OCTETS],
    /// The optional return URI, declared by the authenticated platform binding.
    pub return_uri: Option<String>,
}

const HANDOFF_MEMBERS: &[&str] =
    &["handoffVersion", "mode", "ceremonyId", "offerDigest", "pairingBootstrap", "returnUri"];

impl Handoff {
    /// Serialise for delivery through the platform adapter.
    pub fn to_json(&self) -> Json {
        let mut members = vec![
            ("handoffVersion".to_string(), Json::int(1)),
            ("mode".to_string(), Json::text("same-device")),
            ("ceremonyId".to_string(), Json::text(self.ceremony_id.clone())),
            ("offerDigest".to_string(), Json::text(self.offer_digest.clone())),
            (
                "pairingBootstrap".to_string(),
                Json::obj([
                    ("version", Json::int(2)),
                    ("c", Json::text(codec::b64url(&self.code))),
                ]),
            ),
        ];
        if let Some(uri) = &self.return_uri {
            members.push(("returnUri".to_string(), Json::text(uri.clone())));
        }
        Json::Object(members)
    }

    /// Recognise a delivered handoff.
    ///
    /// `CON-215`: the recogniser "does not extract fields with regular
    /// expressions or act on a partial parse". Application identity and provider
    /// selection are deliberately **not** carried here — they are resolved from
    /// the PROTO-003 record like every other carrier, so the handoff cannot
    /// become a second routing path.
    pub fn recognise(octets: &[u8]) -> Result<Self, CeremonyError> {
        let limits = Limits { max_bytes: 4_096, max_depth: 4 };
        let value = json::recognise(octets, limits)?;
        let members =
            value.as_object().ok_or_else(|| CeremonyError::BadMember("<root>".into()))?;
        for (name, _) in members {
            if !HANDOFF_MEMBERS.contains(&name.as_str()) {
                return Err(CeremonyError::UnknownMember(name.clone()));
            }
        }
        if value.get("handoffVersion").and_then(Json::as_i64) != Some(1) {
            return Err(bad("handoffVersion", "must be exactly 1"));
        }
        if value.get("mode").and_then(Json::as_str) != Some("same-device") {
            return Err(bad("mode", "must be exactly `same-device`"));
        }
        let ceremony_id = random_id(
            value
                .get("ceremonyId")
                .and_then(Json::as_str)
                .ok_or_else(|| CeremonyError::BadMember("ceremonyId".into()))?,
            "ceremonyId",
        )?;
        let offer_digest = random_id(
            value
                .get("offerDigest")
                .and_then(Json::as_str)
                .ok_or_else(|| CeremonyError::BadMember("offerDigest".into()))?,
            "offerDigest",
        )?;

        let bootstrap = value
            .get("pairingBootstrap")
            .ok_or_else(|| CeremonyError::BadMember("pairingBootstrap".into()))?;
        for (name, _) in bootstrap
            .as_object()
            .ok_or_else(|| bad("pairingBootstrap", "is not an object"))?
        {
            if !["version", "c"].contains(&name.as_str()) {
                return Err(CeremonyError::UnknownMember(format!("pairingBootstrap.{name}")));
            }
        }
        if bootstrap.get("version").and_then(Json::as_i64) != Some(2) {
            return Err(bad("pairingBootstrap.version", "must be exactly 2"));
        }
        let code_text = bootstrap
            .get("c")
            .and_then(Json::as_str)
            .ok_or_else(|| CeremonyError::BadMember("pairingBootstrap.c".into()))?;
        let decoded = codec::decode_b64url_exact(code_text, CODE_OCTETS)
            .map_err(|_| bad("pairingBootstrap.c", "is not sixteen canonical base64url octets"))?;
        let mut code = [0u8; CODE_OCTETS];
        code.copy_from_slice(&decoded);

        Ok(Self {
            ceremony_id,
            offer_digest,
            code,
            return_uri: value.get("returnUri").and_then(Json::as_str).map(str::to_string),
        })
    }
}

/// The three outcomes an optional platform return may carry (`CON-215`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The ceremony completed.
    Completed,
    /// The person cancelled.
    Cancelled,
    /// It failed.
    Failed,
}

/// The optional, non-authoritative platform return (`CON-215`, `REQ-224`).
///
/// `REQ-224`: the target application "SHALL determine authorization success only
/// from the ordinary, transcript-authenticated grant bundle and `CON-206`
/// acceptance predicate, never from an OS callback".
///
/// So this object has exactly three members and carries no pairing code, word,
/// token, PAKE or mailbox key, provider, profile digest, offer digest, account
/// scope, DID, alias, key, credential, ciphertext, permission, or error detail.
/// Interception, replay, mutation, or loss of it "cannot disclose a credential
/// or turn rejection into acceptance" — and the closed member set is what makes
/// that a property of the format rather than a promise about the code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandoffReturn {
    /// The ceremony this return refers to.
    pub ceremony_id: String,
    /// What happened.
    pub outcome: Outcome,
}

const RETURN_MEMBERS: &[&str] = &["handoffVersion", "ceremonyId", "outcome"];

impl HandoffReturn {
    /// Serialise the three members.
    pub fn to_json(&self) -> Json {
        Json::obj([
            ("handoffVersion", Json::int(1)),
            ("ceremonyId", Json::text(self.ceremony_id.clone())),
            (
                "outcome",
                Json::text(match self.outcome {
                    Outcome::Completed => "completed",
                    Outcome::Cancelled => "cancelled",
                    Outcome::Failed => "failed",
                }),
            ),
        ])
    }

    /// Recognise a platform return.
    pub fn recognise(octets: &[u8]) -> Result<Self, CeremonyError> {
        let limits = Limits { max_bytes: 1_024, max_depth: 2 };
        let value = json::recognise(octets, limits)?;
        let members =
            value.as_object().ok_or_else(|| CeremonyError::BadMember("<root>".into()))?;
        if members.len() != RETURN_MEMBERS.len() {
            return Err(bad("<root>", "the return carries exactly three members"));
        }
        for (name, _) in members {
            if !RETURN_MEMBERS.contains(&name.as_str()) {
                return Err(CeremonyError::UnknownMember(name.clone()));
            }
        }
        if value.get("handoffVersion").and_then(Json::as_i64) != Some(1) {
            return Err(bad("handoffVersion", "must be exactly 1"));
        }
        let outcome = match value.get("outcome").and_then(Json::as_str) {
            Some("completed") => Outcome::Completed,
            Some("cancelled") => Outcome::Cancelled,
            Some("failed") => Outcome::Failed,
            _ => return Err(bad("outcome", "is not one of completed, cancelled, failed")),
        };
        Ok(Self {
            ceremony_id: random_id(
                value
                    .get("ceremonyId")
                    .and_then(Json::as_str)
                    .ok_or_else(|| CeremonyError::BadMember("ceremonyId".into()))?,
                "ceremonyId",
            )?,
            outcome,
        })
    }

    /// Whether this return may foreground a locally pending session.
    ///
    /// The **only** thing a return is allowed to do. It does not stop polling,
    /// supply grant data, or alter the acceptance result.
    pub fn may_foreground(&self, pending_ceremony_id: Option<&str>) -> bool {
        pending_ceremony_id.is_some_and(|id| id == self.ceremony_id)
    }
}
