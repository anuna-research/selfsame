//! Application enrollment evidence — `CON-214`, `REQ-222`, `REQ-223`.
//!
//! `REQ-222` is the strongest prohibition in the specification, and it is worth
//! reading in full because everything here serves it:
//!
//! > Selfsame SHALL NOT disclose whether an application branch exists, derive or
//! > select an existing application-account home, sign or publish an
//! > authorization delta, issue a device grant, or write a grant bundle unless
//! > the enrollment evidence in `CON-214` authenticates the application origin
//! > and binds the exact profile, account scope, device key, requested
//! > permissions, offer digest, time window, and one-time request ID observed in
//! > the current ceremony.
//!
//! > A public application profile, display name, icon, bundle/package name, deep
//! > link, callback URI, or TLS connection is **insufficient by itself**.
//!
//! Note the first clause: not even *branch existence* may be disclosed. A wallet
//! that answered "no such account" faster than "wrong evidence" would leak which
//! applications a person uses, so every failure below returns a closed token and
//! leaves state untouched.
//!
//! # Why a backend signature and not a platform check
//!
//! The private enrollment key is a developer **backend** credential and
//! `CON-201` forbids embedding it in a native application. That single placement
//! decision is what a hostile sibling app cannot copy. It may copy the public
//! profile, the display name, the icon, the package name, the deep link, and the
//! callback URI — `TEST-229` requires exactly that experiment — and it still
//! cannot produce this signature.
//!
//! # `requestId` is consumed before the first side effect
//!
//! Step 5: the wallet "atomically records `requestId` as consumed **before** any
//! home-key signature, delta publication, or grant-bundle write, whether the
//! request is approved or rejected."
//!
//! Both halves matter. *Before* means a crash between consumption and issuance
//! loses the ceremony rather than allowing a second one. *Whether approved or
//! rejected* means a denial cannot be retried into an approval. `CON-214` then
//! closes the loop: "The consumed-ID record is the sole permitted mutation after
//! syntactically valid evidence reaches step 5" — so [`RequestLedger`] is the
//! only state this module writes.

use crate::ceremony::OfferCore;
use crate::codec;
use crate::json::{Json, Limits};
use crate::jws::{self, CompactJws, JwsPolicy};
use crate::profile::{ApplicationId, ApplicationProfile};
use crate::time::{self, TimeError};
use crate::uri::{self, UriPolicy};
use crate::UnixSeconds;

/// The JWS policy `CON-214` fixes for an enrollment statement.
pub const ENROLLMENT_JWS: JwsPolicy = JwsPolicy {
    typ: "selfsame-enrollment+jws",
    kid: crate::jws::KidRule::HttpsFragment,
    cty: None,
    max_octets: 8_192,
    max_payload_depth: 4,
    // "The physical evidence is a compact JWS over the exact UTF-8 RFC 8785
    // serialization of that object." Exact, so whitespace or a reordered member
    // is a different document and not this one.
    canonical_payload: true,
};

/// `CON-214`: `expiresAt` is later than `issuedAt` by at most 120 seconds.
pub const MAX_EVIDENCE_WINDOW_SECONDS: i64 = 120;

/// A pre-allocation bound for an enrollment `kid`.
///
/// The protected-header limit is stricter after JSON escaping and fixed-member
/// overhead are included. This raw-octet ceiling exists so an oversized `kid`
/// is refused before it is cloned into a JSON value or expanded by the RFC 8785
/// writer.
pub const MAX_ENROLLMENT_KID_OCTETS: usize = jws::HEADER_LIMITS.max_bytes;

/// The closed member set of an enrollment statement.
pub const STATEMENT_MEMBERS: &[&str] = &[
    "evidenceVersion",
    "requestId",
    "ceremonyId",
    "applicationId",
    "profileVersion",
    "profileDigest",
    "accountScopeId",
    "deviceKeyDigest",
    "requestedPermissions",
    "providerId",
    "descriptorDigest",
    "offerDigest",
    "platformBindingId",
    "returnUri",
    "issuedAt",
    "expiresAt",
];

/// The closed error set `CON-214` defines.
///
/// `CON-226`'s completeness rule requires a corpus case for every one of these,
/// which is why they are an enum with no catch-all variant: a thirteenth failure
/// mode would have to be added here, and would then be visibly missing from the
/// corpus.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EnrollmentError {
    /// The application could not be authenticated at all.
    #[error("UnverifiedApplication")]
    UnverifiedApplication,
    /// The statement is not a document in the closed language.
    #[error("EnrollmentMalformed")]
    EnrollmentMalformed,
    /// The signature does not verify under a key in the authenticated profile.
    #[error("EnrollmentBadSignature")]
    EnrollmentBadSignature,
    /// The 120-second window has passed, or has not opened.
    #[error("EnrollmentExpired")]
    EnrollmentExpired,
    /// This `requestId` has already been consumed.
    #[error("EnrollmentReplay")]
    EnrollmentReplay,
    /// The statement names a different profile or profile digest.
    #[error("ProfileMismatch")]
    ProfileMismatch,
    /// The account scope does not match the offer's.
    #[error("AccountBindingMismatch")]
    AccountBindingMismatch,
    /// The device key digest does not match the offer's device key.
    #[error("DeviceBindingMismatch")]
    DeviceBindingMismatch,
    /// The requested permissions are not an exact subset of the profile's.
    #[error("PermissionMismatch")]
    PermissionMismatch,
    /// The provider or descriptor does not match the selected one.
    #[error("ProviderMismatch")]
    ProviderMismatch,
    /// The offer digest does not match the offer being processed.
    #[error("OfferMismatch")]
    OfferMismatch,
    /// The platform binding does not match what the OS reported.
    #[error("PlatformBindingMismatch")]
    PlatformBindingMismatch,
}

/// Every closed token, for the `CON-226` completeness check.
pub const ERROR_TOKENS: &[&str] = &[
    "UnverifiedApplication",
    "EnrollmentMalformed",
    "EnrollmentBadSignature",
    "EnrollmentExpired",
    "EnrollmentReplay",
    "ProfileMismatch",
    "AccountBindingMismatch",
    "DeviceBindingMismatch",
    "PermissionMismatch",
    "ProviderMismatch",
    "OfferMismatch",
    "PlatformBindingMismatch",
];

/// A recognised enrollment statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollmentStatement {
    /// The one-time request identifier.
    pub request_id: String,
    /// The ceremony identifier.
    pub ceremony_id: String,
    /// The canonical application identifier.
    pub application_id: String,
    /// The profile version.
    pub profile_version: i64,
    /// `SHA-256(RFC8785(profile))`, base64url.
    pub profile_digest: String,
    /// The private account scope.
    pub account_scope_id: String,
    /// `SHA-256` of the canonical `deviceKeyJwk`, base64url.
    pub device_key_digest: String,
    /// The requested permissions, sorted.
    pub requested_permissions: Vec<String>,
    /// The selected provider.
    pub provider_id: String,
    /// `SHA-256` of the canonical descriptor, base64url.
    pub descriptor_digest: String,
    /// The `CON-219` offer digest, computed over `offer_core` only.
    pub offer_digest: String,
    /// The platform binding the OS is expected to corroborate.
    pub platform_binding_id: String,
    /// The declared return URI.
    pub return_uri: String,
    /// When the backend signed it.
    pub issued_at: UnixSeconds,
    /// When it stops being usable.
    pub expires_at: UnixSeconds,
}

/// What the OS and the ceremony reported, against which the statement is checked.
#[derive(Clone, Copy, Debug)]
pub struct Observed<'a> {
    /// The authenticated profile, obtained through `CON-220`.
    pub profile: &'a ApplicationProfile,
    /// The `offer_core` this ceremony is actually processing.
    pub offer: &'a OfferCore,
    /// The provider the initiator selected.
    pub provider_id: &'a str,
    /// `SHA-256` of the canonical descriptor, base64url.
    pub descriptor_digest: &'a str,
    /// The platform binding the adapter observed, when the platform provides
    /// one.
    ///
    /// `None` on Apple, where `CON-223` records plainly that the platform gives
    /// no general caller attribution for a Universal Link open. The residual gap
    /// is closed by this signature and by `CON-221` confirmation, not by the
    /// platform — so `None` means "the OS said nothing", never "any binding
    /// will do".
    pub platform_binding_id: Option<&'a str>,
    /// The wallet's local clock.
    pub now: UnixSeconds,
}

/// The consumed-`requestId` record.
///
/// The sole permitted mutation once syntactically valid evidence reaches step 5.
#[derive(Debug, Default)]
pub struct RequestLedger {
    consumed: Vec<String>,
}

impl RequestLedger {
    /// An empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Consume a request identifier, or report a replay.
    ///
    /// Consumes it whether the request is later approved or rejected, so a
    /// denial cannot be retried into an approval and a crash after consumption
    /// loses the ceremony rather than permitting a second one.
    pub fn consume(&mut self, request_id: &str) -> Result<(), EnrollmentError> {
        if self.consumed.iter().any(|id| id == request_id) {
            return Err(EnrollmentError::EnrollmentReplay);
        }
        self.consumed.push(request_id.to_string());
        Ok(())
    }

    /// Whether an identifier has been consumed.
    pub fn is_consumed(&self, request_id: &str) -> bool {
        self.consumed.iter().any(|id| id == request_id)
    }

    /// How many identifiers this ledger holds.
    ///
    /// `TEST-228`'s scope-invariant assertion "permits only one consumed-ID
    /// record and leaves every other application and account unchanged".
    pub fn len(&self) -> usize {
        self.consumed.len()
    }

    /// Whether the ledger is empty.
    pub fn is_empty(&self) -> bool {
        self.consumed.is_empty()
    }
}

/// `SHA-256` of the canonical `deviceKeyJwk`, base64url (`CON-214`).
pub fn device_key_digest(offer: &OfferCore) -> String {
    use sha2::Digest as _;
    let jwk = offer
        .to_json()
        .get("deviceKeyJwk")
        .cloned()
        .expect("OfferCore always serialises a deviceKeyJwk");
    let digest: [u8; 32] = sha2::Sha256::digest(crate::json::canonicalise(&jwk)).into();
    codec::b64url(&digest)
}

/// Recognise an enrollment statement as a closed language, without verifying it.
pub fn recognise(compact: &str) -> Result<(EnrollmentStatement, CompactJws), EnrollmentError> {
    let signed = jws::recognise(compact, ENROLLMENT_JWS, &[])
        .map_err(|_| EnrollmentError::EnrollmentMalformed)?;
    let statement = recognise_payload(&signed.payload)?;
    recognise_kid_for_application(&signed.kid, &statement.application_id)?;
    Ok((statement, signed))
}

/// Recognise a canonical unsigned enrollment statement and its proposed `kid`.
///
/// This is the producer-side counterpart to [`recognise`]. It applies the same
/// closed payload grammar and the same protected-header policy before a backend
/// lets its private key touch the statement. The returned value is suitable for
/// [`sign`]; malformed or non-canonical input yields no partial statement.
pub fn recognise_unsigned(
    statement_octets: &[u8],
    kid: &str,
) -> Result<EnrollmentStatement, EnrollmentError> {
    // This check must precede every parse, clone, JSON construction, and
    // canonicalisation. C0 bytes can expand sixfold when the protected header
    // is written, and callers of this pure helper are not necessarily behind
    // the BEAM boundary's matching guard.
    if kid.len() > MAX_ENROLLMENT_KID_OCTETS {
        return Err(EnrollmentError::EnrollmentMalformed);
    }

    let payload = crate::json::recognise(statement_octets, STATEMENT_LIMITS)
        .map_err(|_| EnrollmentError::EnrollmentMalformed)?;
    if crate::json::canonicalise(&payload) != statement_octets {
        return Err(EnrollmentError::EnrollmentMalformed);
    }
    let protected = header(kid);
    let protected_octets = crate::json::canonicalise(&protected);
    if protected_octets.len() > jws::HEADER_LIMITS.max_bytes {
        return Err(EnrollmentError::EnrollmentMalformed);
    }
    jws::recognise_header(&protected, ENROLLMENT_JWS, &[])
        .map_err(|_| EnrollmentError::EnrollmentMalformed)?;
    let statement = recognise_payload(&payload)?;
    recognise_kid_for_application(kid, &statement.application_id)?;
    if crate::json::canonicalise(&build(&statement)) != statement_octets {
        return Err(EnrollmentError::EnrollmentMalformed);
    }

    // The policy bounds the complete compact JWS, not merely its decoded
    // payload. Account for the exact protected header and fixed-size Ed25519
    // signature before a private key is constructed.
    let compact_octets = codec::b64url(&protected_octets)
        .len()
        .saturating_add(codec::b64url(statement_octets).len())
        .saturating_add(codec::b64url(&[0u8; 64]).len())
        .saturating_add(2);
    if compact_octets > ENROLLMENT_JWS.max_octets {
        return Err(EnrollmentError::EnrollmentMalformed);
    }

    Ok(statement)
}

/// Recognise canonical unsigned statement OCTETS, with no protected header.
///
/// `recognise_unsigned` needs a `kid` because it also recognises the header a
/// signature will carry. A CONSTRUCTOR has no `kid` yet and still must not emit
/// a statement its own grammar rejects — `build` is an infallible serialiser, so
/// without this a browser facade could return canonical-looking bytes for
/// `"bad"` identifiers, an empty permission list, or `expiresAt` before
/// `issuedAt`, and the disagreement between builder and recogniser would surface
/// only as a wallet refusing every request.
pub fn recognise_unsigned_payload(
    statement_octets: &[u8],
) -> Result<EnrollmentStatement, EnrollmentError> {
    let payload = crate::json::recognise(statement_octets, STATEMENT_LIMITS)
        .map_err(|_| EnrollmentError::EnrollmentMalformed)?;
    if crate::json::canonicalise(&payload) != statement_octets {
        return Err(EnrollmentError::EnrollmentMalformed);
    }
    let statement = recognise_payload(&payload)?;
    if crate::json::canonicalise(&build(&statement)) != statement_octets {
        return Err(EnrollmentError::EnrollmentMalformed);
    }
    Ok(statement)
}

fn recognise_payload(payload: &Json) -> Result<EnrollmentStatement, EnrollmentError> {
    let members =
        payload.as_object().ok_or(EnrollmentError::EnrollmentMalformed)?;
    for (name, _) in members {
        if !STATEMENT_MEMBERS.contains(&name.as_str()) {
            return Err(EnrollmentError::EnrollmentMalformed);
        }
    }
    for name in STATEMENT_MEMBERS {
        if payload.get(name).is_none() {
            return Err(EnrollmentError::EnrollmentMalformed);
        }
    }
    if payload.get("evidenceVersion").and_then(Json::as_i64) != Some(1) {
        return Err(EnrollmentError::EnrollmentMalformed);
    }

    let text = |name: &str| -> Result<String, EnrollmentError> {
        payload
            .get(name)
            .and_then(Json::as_str)
            .map(str::to_string)
            .ok_or(EnrollmentError::EnrollmentMalformed)
    };
    let b64_32 = |name: &str| -> Result<String, EnrollmentError> {
        let value = text(name)?;
        codec::decode_b64url_32(&value).map_err(|_| EnrollmentError::EnrollmentMalformed)?;
        Ok(value)
    };

    let application_id = text("applicationId")?;
    let application_id_parts = ApplicationId::parse(&application_id)
        .map_err(|_| EnrollmentError::EnrollmentMalformed)?;

    if payload.get("profileVersion").and_then(Json::as_i64) != Some(crate::PROFILE_VERSION) {
        return Err(EnrollmentError::EnrollmentMalformed);
    }

    let permission_items = payload
        .get("requestedPermissions")
        .and_then(Json::as_array)
        .ok_or(EnrollmentError::EnrollmentMalformed)?;
    if permission_items.is_empty() || permission_items.len() > crate::profile::MAX_PERMISSIONS {
        return Err(EnrollmentError::EnrollmentMalformed);
    }
    let mut requested_permissions = Vec::with_capacity(permission_items.len());
    for item in permission_items {
        let permission = item.as_str().ok_or(EnrollmentError::EnrollmentMalformed)?;
        let parts = uri::recognise(permission, UriPolicy::FRAGMENT_ID)
            .map_err(|_| EnrollmentError::EnrollmentMalformed)?;
        if parts.origin != application_id_parts.origin() {
            return Err(EnrollmentError::EnrollmentMalformed);
        }
        requested_permissions.push(permission.to_string());
    }
    if requested_permissions
        .windows(2)
        .any(|window| matches!(window, [left, right] if left >= right))
    {
        return Err(EnrollmentError::EnrollmentMalformed);
    }

    let stamp = |name: &str| -> Result<UnixSeconds, EnrollmentError> {
        time::parse_date_time_stamp(&text(name)?).map_err(|e| match e {
            TimeError::Malformed | TimeError::OutOfRange => EnrollmentError::EnrollmentMalformed,
        })
    };
    let issued_at = stamp("issuedAt")?;
    let expires_at = stamp("expiresAt")?;
    if expires_at <= issued_at || expires_at - issued_at > MAX_EVIDENCE_WINDOW_SECONDS {
        return Err(EnrollmentError::EnrollmentMalformed);
    }

    let provider_id = text("providerId")?;
    if !crate::profile::is_provider_id(&provider_id) {
        return Err(EnrollmentError::EnrollmentMalformed);
    }

    let return_uri = text("returnUri")?;
    let return_uri_parts = uri::recognise(&return_uri, UriPolicy::PROVIDER_URL)
        .map_err(|_| EnrollmentError::EnrollmentMalformed)?;
    if return_uri_parts.origin != application_id_parts.origin() {
        return Err(EnrollmentError::EnrollmentMalformed);
    }

    let platform_binding_id = text("platformBindingId")?;
    recognise_platform_binding(&platform_binding_id, return_uri_parts.origin)?;

    let statement = EnrollmentStatement {
        request_id: b64_32("requestId")?,
        ceremony_id: b64_32("ceremonyId")?,
        application_id,
        profile_version: crate::PROFILE_VERSION,
        profile_digest: b64_32("profileDigest")?,
        account_scope_id: b64_32("accountScopeId")?,
        device_key_digest: b64_32("deviceKeyDigest")?,
        requested_permissions,
        provider_id,
        descriptor_digest: b64_32("descriptorDigest")?,
        offer_digest: b64_32("offerDigest")?,
        platform_binding_id,
        return_uri,
        issued_at,
        expires_at,
    };
    Ok(statement)
}

fn recognise_kid_for_application(kid: &str, application_id: &str) -> Result<(), EnrollmentError> {
    let application = ApplicationId::parse(application_id)
        .map_err(|_| EnrollmentError::EnrollmentMalformed)?;
    let kid = uri::recognise(kid, UriPolicy::FRAGMENT_ID)
        .map_err(|_| EnrollmentError::EnrollmentMalformed)?;
    if kid.origin != application.origin() {
        return Err(EnrollmentError::EnrollmentMalformed);
    }
    Ok(())
}

fn recognise_platform_binding(id: &str, return_origin: &str) -> Result<(), EnrollmentError> {
    if let Some(android) = id.strip_prefix("android:") {
        let (package_name, certificate) = android
            .rsplit_once(':')
            .ok_or(EnrollmentError::EnrollmentMalformed)?;
        if package_name.is_empty() {
            return Err(EnrollmentError::EnrollmentMalformed);
        }
        codec::decode_b64url_32(certificate)
            .map_err(|_| EnrollmentError::EnrollmentMalformed)?;
        return Ok(());
    }

    if let Some(web) = id.strip_prefix("web:") {
        // CON-227: `web:` followed by exactly the `applicationId` origin —
        // which the statement's `returnUri` is already anchored to above, so
        // the return origin is the value to equal.
        if web != return_origin {
            return Err(EnrollmentError::EnrollmentMalformed);
        }
        uri::recognise(web, UriPolicy::ORIGIN)
            .map_err(|_| EnrollmentError::EnrollmentMalformed)?;
        return Ok(());
    }

    if let Some(apple) = id.strip_prefix("apple:") {
        let (team_id, rest) = apple
            .split_once(':')
            .ok_or(EnrollmentError::EnrollmentMalformed)?;
        let (bundle_id, origin) = rest
            .split_once(':')
            .ok_or(EnrollmentError::EnrollmentMalformed)?;
        if team_id.is_empty() || bundle_id.is_empty() || origin != return_origin {
            return Err(EnrollmentError::EnrollmentMalformed);
        }
        uri::recognise(origin, UriPolicy::ORIGIN)
            .map_err(|_| EnrollmentError::EnrollmentMalformed)?;
        return Ok(());
    }

    Err(EnrollmentError::EnrollmentMalformed)
}

/// `CON-214` steps 1 to 4 and 6: verify the evidence and every binding.
///
/// Step 5 — consuming `requestId` — is [`RequestLedger::consume`], and is the
/// caller's to perform **before** any home-key signature. It is deliberately not
/// folded in here: a function that both verified and consumed would make the
/// ordering an implementation detail rather than a call the caller has to make.
pub fn verify(
    compact: &str,
    observed: &Observed<'_>,
) -> Result<EnrollmentStatement, EnrollmentError> {
    let (statement, signed) = recognise(compact)?;

    // Step 2: resolve `kid` **only** from the authenticated profile. This is
    // the line that makes a copied public profile useless to a hostile app: the
    // key comes from the origin-authenticated document, and the private half is
    // a backend credential the app cannot hold.
    let key = observed
        .profile
        .enrollment_keys
        .iter()
        .find(|k| k.kid == signed.kid)
        .ok_or(EnrollmentError::UnverifiedApplication)?;
    signed
        .verify(&key.jwk.public_key)
        .map_err(|_| EnrollmentError::EnrollmentBadSignature)?;

    // Step 3, in the order the contract prints the fields. Each comparison is
    // against something the wallet observed itself, never against another field
    // of the same statement.
    if statement.application_id != observed.profile.application_id.as_str()
        || statement.profile_version != crate::PROFILE_VERSION
        || statement.profile_digest != codec::b64url(observed.profile.digest())
    {
        return Err(EnrollmentError::ProfileMismatch);
    }
    if statement.account_scope_id != observed.offer.account_scope_id {
        return Err(EnrollmentError::AccountBindingMismatch);
    }
    if statement.device_key_digest != device_key_digest(observed.offer) {
        return Err(EnrollmentError::DeviceBindingMismatch);
    }
    if statement.requested_permissions != observed.offer.requested_permissions {
        return Err(EnrollmentError::PermissionMismatch);
    }
    // An exact subset of the profile's `allowedPermissions`.
    for permission in &statement.requested_permissions {
        if !observed.profile.allowed_permissions.iter().any(|p| p == permission) {
            return Err(EnrollmentError::PermissionMismatch);
        }
    }
    if statement.provider_id != observed.provider_id
        || statement.descriptor_digest != observed.descriptor_digest
    {
        return Err(EnrollmentError::ProviderMismatch);
    }

    // `CON-214`: every member that also appears in `offer_core` "SHALL be
    // exact-string equal to its counterpart there".
    //
    // *Every* one. `applicationId`, `profileVersion`, and `profileDigest` are
    // shared members too, and checking them against the profile above is a
    // different check: the profile is what the wallet fetched, the offer is what
    // this ceremony carried. A backend that signs a statement whose profile
    // fields match the fetched profile while the *offer* carries different ones
    // satisfies the first check and contradicts the offer it claims to be
    // enrolling — which is exactly the substitution exact-string equality across
    // both is there to catch.
    if statement.request_id != observed.offer.request_id
        || statement.ceremony_id != observed.offer.ceremony_id
        || statement.application_id != observed.offer.application_id
        || statement.profile_version != observed.offer.profile_version
        || statement.profile_digest != observed.offer.profile_digest
    {
        return Err(EnrollmentError::OfferMismatch);
    }
    if statement.offer_digest != observed.offer.digest() {
        return Err(EnrollmentError::OfferMismatch);
    }
    if statement.issued_at != observed.offer.issued_at
        || statement.expires_at != observed.offer.expires_at
    {
        return Err(EnrollmentError::OfferMismatch);
    }

    // Step 4: the 120-second window against the wallet's *local* clock.
    if observed.now < statement.issued_at || observed.now >= statement.expires_at {
        return Err(EnrollmentError::EnrollmentExpired);
    }

    // The platform binding must exist in the authenticated profile, and must
    // match what the OS reported wherever the OS reports anything.
    let binding = observed
        .profile
        .mobile_bindings
        .iter()
        .find(|b| b.id() == statement.platform_binding_id)
        .ok_or(EnrollmentError::PlatformBindingMismatch)?;
    // Absent attribution is permitted on exactly one platform, and this is the
    // same rule [`crate::platform::caller_matches_binding`] applies — stated
    // twice because the adapter reaches this function without going through
    // that one, and a check that only one of two entry points performs is a
    // check an attacker chooses whether to face.
    //
    // `CON-223` records that Apple gives the wallet no general caller
    // attribution for a Universal Link open, so `None` there is the conforming
    // case. `CON-222` states the Android comparison as an obligation with a
    // named failure, so `None` there means the mandatory comparison did not
    // happen — and "I could not check" is not a pass. Treating it as optional
    // turns the Apple carve-out into a universal bypass reachable by any
    // Android caller whose adapter simply reports nothing.
    match (observed.platform_binding_id, binding) {
        (Some(observed_id), _) if observed_id != binding.id() => {
            return Err(EnrollmentError::PlatformBindingMismatch);
        }
        (None, crate::profile::MobileBinding::Android { .. }) => {
            return Err(EnrollmentError::PlatformBindingMismatch);
        }
        // CON-227: a web binding admits exactly the unattributed manual path.
        // An OS handoff that attributed anything while the statement names the
        // manual binding is a contradiction, refused even when the attributed
        // id equals the binding id the arm above would have matched.
        (Some(_), crate::profile::MobileBinding::Web { .. }) => {
            return Err(EnrollmentError::PlatformBindingMismatch);
        }
        _ => {}
    }
    // The return URI is the one the authenticated binding declares, not one the
    // caller supplied.
    if let crate::profile::MobileBinding::Apple { return_uri, .. } = binding {
        if &statement.return_uri != return_uri {
            return Err(EnrollmentError::PlatformBindingMismatch);
        }
    }

    Ok(statement)
}

/// Build a statement payload, for an issuer and for the corpus.
pub fn build(statement: &EnrollmentStatement) -> Json {
    Json::obj([
        ("evidenceVersion", Json::int(1)),
        ("requestId", Json::text(statement.request_id.clone())),
        ("ceremonyId", Json::text(statement.ceremony_id.clone())),
        ("applicationId", Json::text(statement.application_id.clone())),
        ("profileVersion", Json::int(statement.profile_version)),
        ("profileDigest", Json::text(statement.profile_digest.clone())),
        ("accountScopeId", Json::text(statement.account_scope_id.clone())),
        ("deviceKeyDigest", Json::text(statement.device_key_digest.clone())),
        (
            "requestedPermissions",
            Json::Array(
                statement.requested_permissions.iter().map(|p| Json::text(p.clone())).collect(),
            ),
        ),
        ("providerId", Json::text(statement.provider_id.clone())),
        ("descriptorDigest", Json::text(statement.descriptor_digest.clone())),
        ("offerDigest", Json::text(statement.offer_digest.clone())),
        ("platformBindingId", Json::text(statement.platform_binding_id.clone())),
        ("returnUri", Json::text(statement.return_uri.clone())),
        ("issuedAt", Json::text(time::format_date_time_stamp(statement.issued_at))),
        ("expiresAt", Json::text(time::format_date_time_stamp(statement.expires_at))),
    ])
}

/// The protected header `CON-214` fixes.
pub fn header(kid: &str) -> Json {
    Json::obj([
        ("alg", Json::text(jws::ALG)),
        ("typ", Json::text(ENROLLMENT_JWS.typ)),
        ("kid", Json::text(kid)),
    ])
}

/// Sign a statement with the developer backend key.
pub fn sign(
    statement: &EnrollmentStatement,
    kid: &str,
    backend_key: &ed25519_dalek::SigningKey,
) -> String {
    jws::sign(&header(kid), &build(statement), backend_key)
}

/// The `Limits` a statement payload is recognised under.
pub const STATEMENT_LIMITS: Limits =
    Limits { max_bytes: ENROLLMENT_JWS.max_octets, max_depth: ENROLLMENT_JWS.max_payload_depth };
