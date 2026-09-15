//! The application profile — `CON-201`, `REQ-202`, `REQ-209`, `REQ-210`,
//! `REQ-214`.
//!
//! The profile is the boundary the whole specification turns on. It fixes one
//! developer's immutable identifier, its account authority, the permissions it
//! may ask for, the keys that may sign an enrollment, and the providers it will
//! talk to. Everything downstream — the KDF context, the acceptance predicate's
//! expectations, the provider election, the enrollment signature — reads from a
//! recognised profile and from nothing else.
//!
//! # A closed language, not a schema
//!
//! `CON-201` states five recognition steps and one sentence that governs the
//! rest: **"An unknown member at any depth is a rejection, not an extension
//! point."** There is no forward-compatibility affordance inside a profile; a
//! new field is a new `profileVersion`.
//!
//! That is stricter than it first looks, and the reason is the digest.
//! `CON-214` signs `SHA-256(RFC8785(profile))`, `CON-220` step 6 requires a
//! resolving party to recompute it, and the pairing intent binds it to the channel
//! transcript. If two conforming recognisers disagreed about which documents are
//! valid, they could still agree on a digest while disagreeing about what they
//! had agreed to. Steps 1–5 close that: the octets are bounded, the JSON is
//! recognised as a closed language, every value satisfies its grammar, and
//! re-serialising reproduces the input byte for byte.
//!
//! # The five steps, in order
//!
//! 1. valid UTF-8, no byte-order mark, at most 65,536 octets;
//! 2. parses as JSON with no duplicate member names, no trailing content, and
//!    nesting depth at most 8;
//! 3. the top-level member set is exact and closed;
//! 4. every member value satisfies its grammar; and
//! 5. re-serialising with RFC 8785 reproduces the input byte for byte.
//!
//! [`ApplicationProfile::recognise`] performs all five before any semantic
//! action, and returns the canonical octets and their digest alongside the
//! parsed values, so no caller has to re-derive either.
//!
//! # What a profile may not contain
//!
//! An `accountScopeId`. `CON-201` says so explicitly, and the reason is worth
//! keeping in view: the profile is embedded in every release of the
//! application, so a scope inside it would give **every account the same
//! branch** and would publish private correlation metadata in release
//! configuration. The closed member set enforces this at every depth without
//! needing a special case.

use crate::codec;
use crate::json::{self, Json, JsonError, Limits};
use crate::uri::{self, UriError, UriPolicy};

/// `CON-201` step 1: the octet bound on a profile document.
pub const MAX_PROFILE_OCTETS: usize = 65_536;

/// `CON-201` step 2: the nesting bound.
pub const MAX_PROFILE_DEPTH: usize = 8;

/// The profile version this build speaks.
pub const PROFILE_VERSION: i64 = 1;

/// `CON-201`: ceiling on `revocation.maxGrantLifetimeSeconds` — thirty days.
pub const MAX_GRANT_LIFETIME_CEILING: i64 = 2_592_000;

/// `CON-201`: ceiling on `revocation.maxClosureAgeSeconds` — one hour.
pub const MAX_CLOSURE_AGE_CEILING: i64 = 3_600;

/// `CON-201`: ceiling on `revocation.propagationSlaSeconds` — five minutes.
pub const MAX_PROPAGATION_SLA_CEILING: i64 = 300;

/// `CON-201`: ceiling on `revocation.projection.maxAgeSeconds` — one hour.
pub const MAX_PROJECTION_AGE_CEILING: i64 = 3_600;

/// The shared `CON-201` ceiling for permission sets carried by profiles and
/// enrollment statements.
pub(crate) const MAX_PERMISSIONS: usize = 64;
const MAX_PROVIDERS: usize = 64;
const MAX_RELAYS: usize = 16;

const TOP_LEVEL_REQUIRED: &[&str] = &[
    "profileVersion",
    "applicationId",
    "accountAuthority",
    "verifierAudience",
    "allowedPermissions",
    "enrollment",
    "cbclPairingRelays",
    "stateResolvers",
    "revocation",
];
const TOP_LEVEL_OPTIONAL: &[&str] = &["capabilities"];

/// The application advertises cbcl-bus SPEC-080 account selection: a wallet
/// pairing a further device SHALL send its existing account scope for this
/// application before the offer, and the allocator waits for it.
pub const CAPABILITY_CREDENTIAL_V2_ACCOUNT_SELECT: &str = "credential-v2-account-select/v1";
/// The closed capability vocabulary (`CON-201`). Anything else refuses.
const CAPABILITIES: &[&str] = &[CAPABILITY_CREDENTIAL_V2_ACCOUNT_SELECT];
const MAX_CAPABILITIES: usize = 8;

/// Why a profile was refused.
///
/// `path` names the member so that a `CON-226` corpus case can state *which*
/// check fired. Two stacks that reject one profile for different reasons have
/// not implemented the same recogniser.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// Steps 1–2: the octets are not a document in the closed JSON language.
    #[error("profile is not recognised JSON: {0}")]
    Json(#[from] JsonError),
    /// Step 5: re-serialising does not reproduce the input.
    #[error("profile is not in RFC 8785 canonical form")]
    NotCanonical,
    /// Step 3 or 4: a member the language does not define.
    #[error("profile contains the unknown member `{0}`")]
    UnknownMember(String),
    /// Step 3 or 4: a required member is absent.
    #[error("profile is missing the member `{0}`")]
    MissingMember(String),
    /// Step 4: a member is present with a value outside its grammar.
    #[error("profile member `{path}` is invalid: {reason}")]
    BadValue {
        /// Dotted path to the member, e.g. `revocation.maxClosureAgeSeconds`.
        path: String,
        /// What rule the value broke.
        reason: &'static str,
    },
}

fn bad(path: impl Into<String>, reason: &'static str) -> ProfileError {
    ProfileError::BadValue {
        path: path.into(),
        reason,
    }
}

/// A canonical, immutable application identifier (`CON-201`, `REQ-202`).
///
/// The identifier "SHALL identify the authorization and correlation boundary,
/// not a particular build, endpoint, deployment region, or provider", and
/// changing it creates a new application identity — silent migration is
/// prohibited, and the one audited exception is `CON-225`.
///
/// Holding it as a validated newtype is what lets `CON-202` state its
/// precondition in the type system: [`crate::hierarchy::application_node`]
/// cannot be reached with an unrecognised identifier.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct ApplicationId {
    text: String,
    origin: String,
}

impl ApplicationId {
    /// Recognise the canonical form. Non-canonical input is refused, never
    /// repaired.
    pub fn parse(text: &str) -> Result<Self, UriError> {
        let parts = uri::recognise(text, UriPolicy::APPLICATION_ID)?;
        Ok(Self {
            text: text.to_string(),
            origin: parts.origin.to_string(),
        })
    }

    /// The exact ASCII serialisation. Compared as exact ASCII by every verifier.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// `https://host[:port]` — the origin permissions and enrollment keys must
    /// share.
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

impl core::fmt::Display for ApplicationId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text)
    }
}

/// An Ed25519 public key in the one JWK shape SPEC-004 admits.
///
/// `NFR-208` confines version 1 to Ed25519/EdDSA, so there is no algorithm
/// member for untrusted input to select. `CON-201` fixes the member set to
/// exactly `kty`, `crv`, and `x` for an enrollment key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed25519Jwk {
    /// The raw 32-octet public key.
    pub public_key: [u8; 32],
    /// The canonical unpadded base64url spelling of `public_key`.
    pub x: String,
}

/// One enrollment-signing key from the profile (`CON-201`, `CON-214`).
///
/// The private half is a developer **backend** credential and "MUST NOT be
/// embedded in a native application" — which is the whole reason a copied
/// public profile does not let a hostile local app impersonate the developer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollmentKey {
    /// An absolute HTTPS URI on the `applicationId` origin with a non-empty
    /// fragment.
    pub kid: String,
    /// The Ed25519 public key.
    pub jwk: Ed25519Jwk,
}

/// A platform binding the wallet may authenticate against (`CON-201`,
/// `CON-222`, `CON-223`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MobileBinding {
    /// `android:<package>:<cert-sha256>`.
    Android {
        /// The binding identifier, unique within the profile.
        id: String,
        /// The exact Android package name.
        package_name: String,
        /// The declared signing-certificate rotation set, as SHA-256 digests.
        signing_certificate_sha256: Vec<String>,
    },
    /// `apple:<TeamID>:<bundleId>:<origin>`.
    Apple {
        /// The binding identifier, unique within the profile.
        id: String,
        /// The Apple Team ID.
        team_id: String,
        /// The bundle identifier.
        bundle_id: String,
        /// A claimed HTTPS return URI on the `applicationId` origin.
        return_uri: String,
    },
    /// `web:<applicationId origin>` — the manual cross-device path
    /// (`CON-227`): the profile's authenticated admission that no platform
    /// will attribute a caller.
    Web {
        /// The binding identifier, unique within the profile.
        id: String,
        /// Exactly the `applicationId` origin.
        origin: String,
    },
}

impl MobileBinding {
    /// The binding identifier, whatever the platform.
    pub fn id(&self) -> &str {
        match self {
            MobileBinding::Android { id, .. }
            | MobileBinding::Apple { id, .. }
            | MobileBinding::Web { id, .. } => id,
        }
    }
}

/// One authenticated cbcl-pairing relay descriptor (`SPEC-007 CON-806`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CbclRelayDescriptor {
    /// Operator identifier, unique within the profile.
    pub operator_id: String,
    /// Canonical HTTPS relay origin.
    pub relay_origin: String,
    /// Selection group, ascending.
    pub priority: i64,
    /// Positive selection weight within the priority group.
    pub weight: i64,
    /// SHA-256 of the approved privacy policy.
    pub privacy_policy_digest: [u8; 32],
    /// SHA-256 of the relay conformance evidence.
    pub conformance_evidence_digest: [u8; 32],
    /// SHA-256 of this complete canonical descriptor.
    pub digest: [u8; 32],
}

/// One `did:crdt` state resolver (`CON-201`).
///
/// An adopting application MAY list its own origin here, and doing so is
/// RECOMMENDED: `CON-210` delivers the revocation delta directly to the party
/// that enforces it, which is the strongest available answer to a third party
/// withholding state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateResolver {
    /// Resolver identifier, unique within this role.
    pub id: String,
    /// HTTPS URL of a node conforming to the method's `CON-003`/`CON-004`.
    pub url: String,
    /// Exactly `did-crdt-service-v1` in profile version 1.
    pub protocol: String,
}

/// The optional W3C Bitstring Status List projection (`CON-201`, `CON-210`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionPolicy {
    /// Exactly `BitstringStatusList`.
    pub kind: String,
    /// Where an issuer obtains a free `(credential, index)` allocation.
    pub allocation_url: String,
    /// Base URL under which status list credentials are published.
    pub credential_base_url: String,
    /// Cache bound, at most one hour. Also bounds the published credential's
    /// own `validUntil - validFrom`.
    pub max_age_seconds: i64,
}

/// Revocation and freshness policy (`CON-201`, `CON-206`, `CON-210`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationPolicy {
    /// Exactly `did-crdt-revocations-v1` in profile version 1.
    pub method: String,
    /// Outer bound on `validUntil - validFrom`, at most thirty days.
    pub max_grant_lifetime_seconds: i64,
    /// Continuation freshness bound, at most one hour.
    pub max_closure_age_seconds: i64,
    /// Revocation propagation bound, at most five minutes.
    pub propagation_sla_seconds: i64,
    /// The optional projection. Its absence disables projection without
    /// disabling issuance or revocation.
    pub projection: Option<ProjectionPolicy>,
}

impl RevocationPolicy {
    /// The `CON-206` step 10 bound for **establishing** a session:
    /// `min(maxClosureAgeSeconds, propagationSlaSeconds)`.
    ///
    /// Both are members `CON-201` already defines, which is why the two-tier
    /// rule needed no new profile member and invalidated no published vector.
    pub fn session_establishment_bound(&self) -> i64 {
        self.max_closure_age_seconds
            .min(self.propagation_sla_seconds)
    }
}

/// A recognised application profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationProfile {
    canonical: Vec<u8>,
    digest: [u8; 32],
    /// The immutable application identifier.
    pub application_id: ApplicationId,
    /// The RFC 7565 authority that hosts account records.
    pub account_authority: String,
    /// Permission URIs this application may request, sorted by code point.
    pub allowed_permissions: Vec<String>,
    /// Keys competent to sign a `CON-214` enrollment statement.
    pub enrollment_keys: Vec<EnrollmentKey>,
    /// Platform bindings for the same-device path.
    pub mobile_bindings: Vec<MobileBinding>,
    /// Authenticated relay descriptors for cbcl credential pairing.
    pub cbcl_pairing_relays: Vec<CbclRelayDescriptor>,
    /// `did:crdt` state resolvers.
    pub state_resolvers: Vec<StateResolver>,
    /// Revocation and freshness policy.
    pub revocation: RevocationPolicy,
    /// Protocol capabilities the application advertises, from the closed
    /// `CON-201` vocabulary, strictly ascending. Absent means none.
    pub capabilities: Vec<String>,
}

impl ApplicationProfile {
    /// Whether a wallet pairing another device sends its account selection
    /// before the offer (cbcl-bus SPEC-080 CON-004).
    #[must_use]
    pub fn advertises_credential_v2_account_select(&self) -> bool {
        self.capabilities
            .iter()
            .any(|capability| capability == CAPABILITY_CREDENTIAL_V2_ACCOUNT_SELECT)
    }

    /// Run `CON-201`'s five recognition steps over the profile octets.
    ///
    /// No semantic action is taken on failure: the error carries no profile, so
    /// there is nothing for a caller to act on partially.
    pub fn recognise(octets: &[u8]) -> Result<Self, ProfileError> {
        let limits = Limits {
            max_bytes: MAX_PROFILE_OCTETS,
            max_depth: MAX_PROFILE_DEPTH,
        };
        // Steps 1 and 2.
        let value = json::recognise(octets, limits)?;
        // Step 5, run before the field grammars so that a non-canonical profile
        // never reaches a comparison that assumes canonical bytes.
        let canonical = json::canonicalise(&value);
        if canonical != octets {
            return Err(ProfileError::NotCanonical);
        }
        // Steps 3 and 4.
        let profile = Self::from_value(&value, canonical)?;
        Ok(profile)
    }

    /// The RFC 8785 octets. Byte-identical to the recognised input.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// `SHA-256(RFC8785(profile))` — the `profileDigest` of `CON-214`,
    /// `CON-220` step 6, and the authenticated pairing intent.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    fn from_value(value: &Json, canonical: Vec<u8>) -> Result<Self, ProfileError> {
        closed_members(value, "", TOP_LEVEL_REQUIRED, TOP_LEVEL_OPTIONAL)?;

        let version = integer(value, "profileVersion")?;
        if version != PROFILE_VERSION {
            return Err(bad(
                "profileVersion",
                "must be exactly 1 in this profile version",
            ));
        }

        let application_id =
            ApplicationId::parse(string(value, "applicationId")?).map_err(|_| {
                bad(
                    "applicationId",
                    "is not a canonical HTTPS application identifier",
                )
            })?;

        // `CON-201`: "applicationId and verifierAudience MUST be identical in
        // version 1." Compared as exact ASCII, after both have been recognised.
        if string(value, "verifierAudience")? != application_id.as_str() {
            return Err(bad(
                "verifierAudience",
                "must be identical to applicationId",
            ));
        }

        let account_authority = string(value, "accountAuthority")?.to_string();
        uri::recognise_dns_name(&account_authority).map_err(|_| {
            bad(
                "accountAuthority",
                "is not a lower-case ASCII A-label DNS name",
            )
        })?;

        let allowed_permissions = permissions(value, &application_id)?;
        let (enrollment_keys, mobile_bindings) = enrollment(value, &application_id)?;
        let cbcl_pairing_relays = cbcl_pairing_relays(value)?;
        let state_resolvers = state_resolvers(value)?;
        let revocation = revocation(value)?;
        let capabilities = capabilities(value)?;

        let digest = sha256(&canonical);
        Ok(Self {
            canonical,
            digest,
            application_id,
            account_authority,
            allowed_permissions,
            enrollment_keys,
            mobile_bindings,
            cbcl_pairing_relays,
            state_resolvers,
            revocation,
            capabilities,
        })
    }
}

// ── member helpers ──────────────────────────────────────────────────────────

fn join(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}.{name}")
    }
}

/// Enforce `CON-201`'s "unknown member at any depth is a rejection" for one
/// object, in both directions: nothing unknown, nothing required missing.
fn closed_members(
    value: &Json,
    path: &str,
    required: &[&str],
    optional: &[&str],
) -> Result<(), ProfileError> {
    let members = value.as_object().ok_or_else(|| {
        bad(
            if path.is_empty() { "<root>" } else { path },
            "is not an object",
        )
    })?;
    for (name, _) in members {
        if !required.contains(&name.as_str()) && !optional.contains(&name.as_str()) {
            return Err(ProfileError::UnknownMember(join(path, name)));
        }
    }
    for name in required {
        if value.get(name).is_none() {
            return Err(ProfileError::MissingMember(join(path, name)));
        }
    }
    Ok(())
}

fn member<'a>(value: &'a Json, name: &str) -> Result<&'a Json, ProfileError> {
    value
        .get(name)
        .ok_or_else(|| ProfileError::MissingMember(name.to_string()))
}

fn string<'a>(value: &'a Json, name: &str) -> Result<&'a str, ProfileError> {
    member(value, name)?
        .as_str()
        .ok_or_else(|| bad(name, "is not a string"))
}

fn integer(value: &Json, name: &str) -> Result<i64, ProfileError> {
    member(value, name)?
        .as_i64()
        .ok_or_else(|| bad(name, "is not an integer"))
}

fn array<'a>(value: &'a Json, name: &str) -> Result<&'a [Json], ProfileError> {
    member(value, name)?
        .as_array()
        .ok_or_else(|| bad(name, "is not an array"))
}

fn bounded_positive(
    value: &Json,
    path: &str,
    name: &str,
    ceiling: i64,
    reason: &'static str,
) -> Result<i64, ProfileError> {
    let n = member(value, name)?
        .as_i64()
        .ok_or_else(|| bad(join(path, name), "is not an integer"))?;
    if n <= 0 || n > ceiling {
        return Err(bad(join(path, name), reason));
    }
    Ok(n)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes).into()
}

// ── member grammars ─────────────────────────────────────────────────────────

/// `allowedPermissions`: non-empty, at most 64, absolute HTTPS URIs on the
/// `applicationId` origin with a non-empty fragment, sorted by Unicode code
/// point, without duplicates.
///
/// The sort and duplicate rules are not cosmetic. `CON-206` step 12 and
/// `CON-214` both compare a requested set against this array, so an unsorted or
/// duplicated array would make "is this an exact subset" depend on how the
/// comparison happened to be written.
fn permissions(value: &Json, application_id: &ApplicationId) -> Result<Vec<String>, ProfileError> {
    let items = array(value, "allowedPermissions")?;
    if items.is_empty() || items.len() > MAX_PERMISSIONS {
        return Err(bad(
            "allowedPermissions",
            "must hold between 1 and 64 entries",
        ));
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let text = item
            .as_str()
            .ok_or_else(|| bad("allowedPermissions", "entry is not a string"))?;
        let parts = uri::recognise(text, UriPolicy::FRAGMENT_ID).map_err(|_| {
            bad(
                "allowedPermissions",
                "entry is not a canonical HTTPS URI with a fragment",
            )
        })?;
        if parts.origin != application_id.origin() {
            return Err(bad(
                "allowedPermissions",
                "entry is not on the applicationId origin",
            ));
        }
        out.push(text.to_string());
    }
    // `CON-201` says "sorted by Unicode code point", which for Rust's `str`
    // ordering is byte order over UTF-8 — the same relation. This is
    // deliberately *not* the UTF-16 order RFC 8785 uses for member names.
    if out.windows(2).any(|w| w[0] >= w[1]) {
        return Err(bad(
            "allowedPermissions",
            "is unsorted or contains a duplicate",
        ));
    }
    Ok(out)
}

fn enrollment(
    value: &Json,
    application_id: &ApplicationId,
) -> Result<(Vec<EnrollmentKey>, Vec<MobileBinding>), ProfileError> {
    let enrollment = member(value, "enrollment")?;
    closed_members(
        enrollment,
        "enrollment",
        &["requestSigningKeys"],
        &["mobileBindings"],
    )?;

    let key_items = array(enrollment, "requestSigningKeys")?;
    if key_items.is_empty() || key_items.len() > MAX_PROVIDERS {
        return Err(bad(
            "enrollment.requestSigningKeys",
            "must hold at least one entry",
        ));
    }
    let mut keys = Vec::with_capacity(key_items.len());
    for item in key_items {
        closed_members(
            item,
            "enrollment.requestSigningKeys[]",
            &["kid", "publicKeyJwk"],
            &[],
        )?;
        let kid = string(item, "kid")?.to_string();
        let parts = uri::recognise(&kid, UriPolicy::FRAGMENT_ID).map_err(|_| {
            bad(
                "enrollment.requestSigningKeys[].kid",
                "is not a canonical HTTPS URI with a fragment",
            )
        })?;
        if parts.origin != application_id.origin() {
            return Err(bad(
                "enrollment.requestSigningKeys[].kid",
                "is not on the applicationId origin",
            ));
        }
        let jwk = ed25519_jwk(
            member(item, "publicKeyJwk")?,
            "enrollment.requestSigningKeys[].publicKeyJwk",
        )?;
        keys.push(EnrollmentKey { kid, jwk });
    }
    if first_duplicate(keys.iter().map(|k| k.kid.as_str())).is_some() {
        return Err(bad(
            "enrollment.requestSigningKeys",
            "contains a duplicate kid",
        ));
    }
    // `CON-201`: "MUST contain at least one unique key". Two entries with
    // different `kid` values but the same public key would let one compromised
    // key masquerade as rotation having happened.
    if first_duplicate(keys.iter().map(|k| k.jwk.x.as_str())).is_some() {
        return Err(bad(
            "enrollment.requestSigningKeys",
            "contains a duplicate public key",
        ));
    }

    let bindings = match enrollment.get("mobileBindings") {
        None => Vec::new(),
        Some(value) => {
            let items = value
                .as_array()
                .ok_or_else(|| bad("enrollment.mobileBindings", "is not an array"))?;
            if items.len() > MAX_PROVIDERS {
                return Err(bad(
                    "enrollment.mobileBindings",
                    "holds more than 64 entries",
                ));
            }
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(mobile_binding(item, application_id)?);
            }
            if first_duplicate(out.iter().map(MobileBinding::id)).is_some() {
                return Err(bad("enrollment.mobileBindings", "contains a duplicate id"));
            }
            out
        }
    };

    Ok((keys, bindings))
}

fn ed25519_jwk(value: &Json, path: &'static str) -> Result<Ed25519Jwk, ProfileError> {
    closed_members(value, path, &["kty", "crv", "x"], &[])?;
    if string(value, "kty")? != "OKP" {
        return Err(bad(path, "kty must be exactly OKP"));
    }
    if string(value, "crv")? != "Ed25519" {
        return Err(bad(path, "crv must be exactly Ed25519"));
    }
    let x = string(value, "x")?.to_string();
    let public_key = crate::codec::decode_b64url_32(&x)
        .map_err(|_| bad(path, "x is not a canonical 32-octet base64url value"))?;
    Ok(Ed25519Jwk { public_key, x })
}

fn mobile_binding(
    value: &Json,
    application_id: &ApplicationId,
) -> Result<MobileBinding, ProfileError> {
    let platform = string(value, "platform")?;
    match platform {
        "android" => {
            closed_members(
                value,
                "enrollment.mobileBindings[]",
                &["id", "platform", "packageName", "signingCertificateSha256"],
                &[],
            )?;
            let package_name = string(value, "packageName")?.to_string();
            let digests = array(value, "signingCertificateSha256")?;
            if digests.is_empty() {
                return Err(bad(
                    "enrollment.mobileBindings[].signingCertificateSha256",
                    "must declare at least one certificate digest",
                ));
            }
            let mut certs = Vec::with_capacity(digests.len());
            for d in digests {
                let text = d.as_str().ok_or_else(|| {
                    bad(
                        "enrollment.mobileBindings[].signingCertificateSha256",
                        "entry is not a string",
                    )
                })?;
                crate::codec::decode_b64url_32(text).map_err(|_| {
                    bad(
                        "enrollment.mobileBindings[].signingCertificateSha256",
                        "entry is not a canonical 32-octet base64url digest",
                    )
                })?;
                certs.push(text.to_string());
            }
            let id = string(value, "id")?.to_string();
            // `CON-214`: "Android uses `android:` followed by the exact package
            // name and a SHA-256 signing-certificate digest."
            let expected_prefix = format!("android:{package_name}:");
            if !id.starts_with(&expected_prefix) {
                return Err(bad(
                    "enrollment.mobileBindings[].id",
                    "does not spell `android:<packageName>:<cert-sha256>`",
                ));
            }
            if !certs.iter().any(|c| id == format!("{expected_prefix}{c}")) {
                return Err(bad(
                    "enrollment.mobileBindings[].id",
                    "names a certificate digest outside its own rotation set",
                ));
            }
            Ok(MobileBinding::Android {
                id,
                package_name,
                signing_certificate_sha256: certs,
            })
        }
        "apple" => {
            closed_members(
                value,
                "enrollment.mobileBindings[]",
                &["id", "platform", "teamId", "bundleId", "returnUri"],
                &[],
            )?;
            let team_id = string(value, "teamId")?.to_string();
            let bundle_id = string(value, "bundleId")?.to_string();
            let return_uri = string(value, "returnUri")?.to_string();
            let parts = uri::recognise(&return_uri, UriPolicy::PROVIDER_URL).map_err(|_| {
                bad(
                    "enrollment.mobileBindings[].returnUri",
                    "is not a canonical HTTPS URI",
                )
            })?;
            // `CON-201`: "Apple entries bind an exact Team ID and bundle ID to a
            // claimed HTTPS return URI on the `applicationId` origin."
            if parts.origin != application_id.origin() {
                return Err(bad(
                    "enrollment.mobileBindings[].returnUri",
                    "is not on the applicationId origin",
                ));
            }
            let id = string(value, "id")?.to_string();
            if id != format!("apple:{team_id}:{bundle_id}:{}", parts.origin) {
                return Err(bad(
                    "enrollment.mobileBindings[].id",
                    "does not spell `apple:<teamId>:<bundleId>:<returnUri origin>`",
                ));
            }
            Ok(MobileBinding::Apple {
                id,
                team_id,
                bundle_id,
                return_uri,
            })
        }
        "web" => {
            closed_members(
                value,
                "enrollment.mobileBindings[]",
                &["id", "platform", "origin"],
                &[],
            )?;
            let origin = string(value, "origin")?.to_string();
            // `CON-227`: "`origin` MUST equal the profile's `applicationId`
            // origin byte for byte" — a web binding whose origin names
            // anything else refuses the whole profile.
            if origin != application_id.origin() {
                return Err(bad(
                    "enrollment.mobileBindings[].origin",
                    "is not the applicationId origin",
                ));
            }
            let id = string(value, "id")?.to_string();
            if id != format!("web:{origin}") {
                return Err(bad(
                    "enrollment.mobileBindings[].id",
                    "does not spell `web:<applicationId origin>`",
                ));
            }
            Ok(MobileBinding::Web { id, origin })
        }
        _ => Err(bad(
            "enrollment.mobileBindings[].platform",
            "is neither `android`, `apple`, nor `web`",
        )),
    }
}

/// Whether `text` belongs to `CON-201`'s provider-ID language.
pub(crate) fn is_provider_id(text: &str) -> bool {
    let bytes = text.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

fn provider_id(text: &str, path: &'static str) -> Result<(), ProfileError> {
    if is_provider_id(text) {
        Ok(())
    } else {
        Err(bad(path, "does not match [a-z0-9][a-z0-9-]{0,62}"))
    }
}

/// The OPTIONAL `capabilities` member: at most eight strings from the closed
/// vocabulary, strictly ascending by code point, so one set has one encoding.
fn capabilities(value: &Json) -> Result<Vec<String>, ProfileError> {
    let Some(member) = optional_member(value, "capabilities") else {
        return Ok(Vec::new());
    };
    let items = member
        .as_array()
        .ok_or_else(|| bad("capabilities", "is not an array"))?;
    if items.len() > MAX_CAPABILITIES {
        return Err(bad("capabilities", "must hold at most 8 entries"));
    }
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        let capability = item
            .as_str()
            .ok_or_else(|| bad("capabilities", "entries must be strings"))?;
        if !CAPABILITIES.contains(&capability) {
            return Err(bad("capabilities", "is not a known capability"));
        }
        if out.last().is_some_and(|previous| previous.as_str() >= capability) {
            return Err(bad(
                "capabilities",
                "must be strictly ascending without duplicates",
            ));
        }
        out.push(capability.to_string());
    }
    Ok(out)
}

fn optional_member<'a>(value: &'a Json, name: &str) -> Option<&'a Json> {
    match value {
        Json::Object(members) => members
            .iter()
            .find_map(|(candidate, member)| (candidate == name).then_some(member)),
        _ => None,
    }
}

fn cbcl_pairing_relays(value: &Json) -> Result<Vec<CbclRelayDescriptor>, ProfileError> {
    let items = array(value, "cbclPairingRelays")?;
    if items.is_empty() || items.len() > MAX_RELAYS {
        return Err(bad(
            "cbclPairingRelays",
            "must hold between 1 and 16 entries",
        ));
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        closed_members(
            item,
            "cbclPairingRelays[]",
            &[
                "operatorId",
                "relayOrigin",
                "priority",
                "weight",
                "privacyPolicyDigest",
                "conformanceEvidenceDigest",
            ],
            &[],
        )?;
        let operator_id = string(item, "operatorId")?.to_string();
        provider_id(&operator_id, "cbclPairingRelays[].operatorId")?;
        let relay_origin = string(item, "relayOrigin")?.to_string();
        uri::recognise(&relay_origin, UriPolicy::ORIGIN).map_err(|_| {
            bad(
                "cbclPairingRelays[].relayOrigin",
                "is not a canonical HTTPS origin",
            )
        })?;
        let priority = bounded_range(item, "cbclPairingRelays[]", "priority")?;
        let weight = bounded_range(item, "cbclPairingRelays[]", "weight")?;
        if weight == 0 {
            return Err(bad("cbclPairingRelays[].weight", "must be positive"));
        }
        let privacy_policy_digest = codec::decode_b64url_32(string(item, "privacyPolicyDigest")?)
            .map_err(|_| {
            bad(
                "cbclPairingRelays[].privacyPolicyDigest",
                "is not a canonical SHA-256 digest",
            )
        })?;
        let conformance_evidence_digest =
            codec::decode_b64url_32(string(item, "conformanceEvidenceDigest")?).map_err(|_| {
                bad(
                    "cbclPairingRelays[].conformanceEvidenceDigest",
                    "is not a canonical SHA-256 digest",
                )
            })?;
        out.push(CbclRelayDescriptor {
            operator_id,
            relay_origin,
            priority,
            weight,
            privacy_policy_digest,
            conformance_evidence_digest,
            digest: sha256(&json::canonicalise(item)),
        });
    }
    if first_duplicate(out.iter().map(|d| d.operator_id.as_str())).is_some() {
        return Err(bad("cbclPairingRelays", "contains a duplicate operator id"));
    }
    if first_duplicate(out.iter().map(|d| d.relay_origin.as_str())).is_some() {
        return Err(bad(
            "cbclPairingRelays",
            "contains a duplicate relay origin",
        ));
    }
    Ok(out)
}

fn bounded_range(item: &Json, path: &str, name: &str) -> Result<i64, ProfileError> {
    let n = member(item, name)?
        .as_i64()
        .ok_or_else(|| bad(join(path, name), "is not an integer"))?;
    if !(0..=65_535).contains(&n) {
        return Err(bad(join(path, name), "is outside [0, 65535]"));
    }
    Ok(n)
}

fn state_resolvers(value: &Json) -> Result<Vec<StateResolver>, ProfileError> {
    let items = array(value, "stateResolvers")?;
    if items.is_empty() || items.len() > MAX_PROVIDERS {
        return Err(bad("stateResolvers", "must hold between 1 and 64 entries"));
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        closed_members(item, "stateResolvers[]", &["id", "url", "protocol"], &[])?;
        let id = string(item, "id")?.to_string();
        provider_id(&id, "stateResolvers[].id")?;
        if string(item, "protocol")? != "did-crdt-service-v1" {
            return Err(bad(
                "stateResolvers[].protocol",
                "must be exactly did-crdt-service-v1",
            ));
        }
        let url = string(item, "url")?.to_string();
        uri::recognise(&url, UriPolicy::PROVIDER_URL)
            .map_err(|_| bad("stateResolvers[].url", "is not a canonical HTTPS URL"))?;
        out.push(StateResolver {
            id,
            url,
            protocol: "did-crdt-service-v1".to_string(),
        });
    }
    if first_duplicate(out.iter().map(|r| r.id.as_str())).is_some() {
        return Err(bad("stateResolvers", "contains a duplicate resolver id"));
    }
    Ok(out)
}

fn revocation(value: &Json) -> Result<RevocationPolicy, ProfileError> {
    let node = member(value, "revocation")?;
    closed_members(
        node,
        "revocation",
        &[
            "method",
            "maxGrantLifetimeSeconds",
            "maxClosureAgeSeconds",
            "propagationSlaSeconds",
        ],
        &["projection"],
    )?;
    if string(node, "method")? != "did-crdt-revocations-v1" {
        return Err(bad(
            "revocation.method",
            "must be exactly did-crdt-revocations-v1",
        ));
    }
    let max_grant_lifetime_seconds = bounded_positive(
        node,
        "revocation",
        "maxGrantLifetimeSeconds",
        MAX_GRANT_LIFETIME_CEILING,
        "must be a positive integer of at most 2592000",
    )?;
    let max_closure_age_seconds = bounded_positive(
        node,
        "revocation",
        "maxClosureAgeSeconds",
        MAX_CLOSURE_AGE_CEILING,
        "must be a positive integer of at most 3600",
    )?;
    let propagation_sla_seconds = bounded_positive(
        node,
        "revocation",
        "propagationSlaSeconds",
        MAX_PROPAGATION_SLA_CEILING,
        "must be a positive integer of at most 300",
    )?;

    let projection = match node.get("projection") {
        None => None,
        Some(p) => {
            closed_members(
                p,
                "revocation.projection",
                &[
                    "type",
                    "allocationUrl",
                    "credentialBaseUrl",
                    "maxAgeSeconds",
                ],
                &[],
            )?;
            if string(p, "type")? != "BitstringStatusList" {
                return Err(bad(
                    "revocation.projection.type",
                    "must be exactly BitstringStatusList",
                ));
            }
            let allocation_url = string(p, "allocationUrl")?.to_string();
            uri::recognise(&allocation_url, UriPolicy::PROVIDER_URL).map_err(|_| {
                bad(
                    "revocation.projection.allocationUrl",
                    "is not a canonical HTTPS URL",
                )
            })?;
            let credential_base_url = string(p, "credentialBaseUrl")?.to_string();
            uri::recognise(&credential_base_url, UriPolicy::PROVIDER_URL).map_err(|_| {
                bad(
                    "revocation.projection.credentialBaseUrl",
                    "is not a canonical HTTPS URL",
                )
            })?;
            let max_age_seconds = bounded_positive(
                p,
                "revocation.projection",
                "maxAgeSeconds",
                MAX_PROJECTION_AGE_CEILING,
                "must be a positive integer of at most 3600",
            )?;
            Some(ProjectionPolicy {
                kind: "BitstringStatusList".to_string(),
                allocation_url,
                credential_base_url,
                max_age_seconds,
            })
        }
    };

    Ok(RevocationPolicy {
        method: "did-crdt-revocations-v1".to_string(),
        max_grant_lifetime_seconds,
        max_closure_age_seconds,
        propagation_sla_seconds,
        projection,
    })
}

fn first_duplicate<'a>(items: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    let mut seen: Vec<&str> = Vec::new();
    for item in items {
        if seen.contains(&item) {
            return Some(item);
        }
        seen.push(item);
    }
    None
}
