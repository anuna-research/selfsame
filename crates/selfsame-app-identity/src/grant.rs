//! The Selfsame Device Grant Credential — `CON-205`, `REQ-205`, `REQ-206`,
//! `REQ-208`.
//!
//! A grant is a W3C Verifiable Credential 2.0 secured as a compact JWS with
//! media type `application/vc+jwt`, issued by an application-account home DID to
//! one device.
//!
//! ```text
//! issuer   did:crdt:<home>                      ← the account, not the person
//! subject  did:key:<device>                     ← one device installation
//! account  acct:ss-…@accounts.photos.example    ← the stable alias, never a username
//! aud      https://photos.example/…/application ← the application, exactly
//! cnf.jwk  the same key the subject DID encodes ← what the device must prove
//! ```
//!
//! # Three identifiers from one token
//!
//! ```text
//! grant_token = BASE64URL-NOPAD(32 CSPRNG octets)     // 43 characters
//! grant_id    = home_did || "#grant-"  || grant_token
//! status_id   = home_did || "#status-" || grant_token
//! ```
//!
//! `CON-205` requires the token to be "independent for every grant and never
//! derived from a device key, account scope, timestamp, provider allocation, or
//! recovery material". Each of those would make one grant's identifier
//! predictable from another's, and `grant_id` is what a revocation names — a
//! predictable identifier is one an attacker can watch for, or pre-compute a
//! revocation set against.
//!
//! Deriving all three from a single token is what keeps `credentialStatus.id`,
//! `credentialStatus.credentialId`, and `id` provably consistent: `CON-205`
//! requires "matching `status_id`, `credentialId`, issuer DID, and grant token",
//! and they match by construction rather than by three separate checks.
//!
//! # The credential is not a JWT
//!
//! `REQ-205`: "The grant SHALL NOT be wrapped in a legacy JWT `vc` claim. The
//! unsecured VC document itself SHALL be the JWS payload." The [`crate::jws`]
//! recogniser enforces this; it is stated here because it is the single most
//! common way an implementation drifts, every JWT library making the wrapper the
//! path of least resistance.

use crate::alias::AcctUri;
use crate::codec;
use crate::context::{self, ContextError};
use crate::didkey;
use crate::json::{Json, JsonError};
use crate::jws::{self, JwsPolicy};
use crate::profile::ApplicationId;
use crate::time::{self, TimeError};
use crate::UnixSeconds;

/// `CON-206` step 1: the octet bound on a grant.
pub const MAX_GRANT_OCTETS: usize = 65_536;

/// The JWS policy `CON-205` fixes for a grant.
pub const GRANT_JWS: JwsPolicy = JwsPolicy {
    typ: "vc+jwt",
    kid: crate::jws::KidRule::DidUrl,
    cty: Some("vc"),
    max_octets: MAX_GRANT_OCTETS,
    max_payload_depth: 8,
};

/// The media type the ceremony carries alongside the compact JWS.
pub const GRANT_MEDIA_TYPE: &str = "application/vc+jwt";

/// The verification-method fragment the home DID exposes.
pub const HOME_METHOD_FRAGMENT: &str = "#jwk-0";

/// The two `type` values every grant carries, in order.
pub const GRANT_TYPES: [&str; 2] = ["VerifiableCredential", "SelfsameDeviceGrantCredential"];

/// The one status entry type this profile defines.
pub const STATUS_ENTRY_TYPE: &str = "SelfsameDidCrdtStatusEntry";

/// The optional W3C projection entry type.
pub const BITSTRING_ENTRY_TYPE: &str = "BitstringStatusListEntry";

/// Why a grant was refused, before any authorization decision.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    /// A member the credential requires is absent or the wrong JSON type.
    #[error("grant member `{0}` is absent or malformed")]
    BadMember(&'static str),
    /// A member is present but outside its grammar.
    #[error("grant member `{path}` is invalid: {reason}")]
    BadValue {
        /// The member.
        path: &'static str,
        /// What rule it broke.
        reason: &'static str,
    },
    /// The credential carries a member this profile does not define.
    #[error("grant contains the unknown member `{0}`")]
    UnknownMember(String),
    /// The `@context` array is wrong.
    #[error("grant context is invalid: {0}")]
    Context(#[from] ContextError),
    /// A timestamp is not a UTC `dateTimeStamp`.
    #[error("grant timestamp is invalid")]
    BadTimestamp,
    /// The payload is not recognised JSON.
    #[error("grant payload is not recognised: {0}")]
    Json(#[from] JsonError),
}

fn bad(path: &'static str, reason: &'static str) -> GrantError {
    GrantError::BadValue { path, reason }
}

/// A recognised device grant, with every cross-field equality already checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceGrant {
    /// `did:crdt:<home>#grant-<token>`.
    pub id: String,
    /// The application-account home DID.
    pub issuer: String,
    /// The 43-character random token all three identifiers share.
    pub token: String,
    /// The device DID, which is the credential subject.
    pub device_did: String,
    /// The Ed25519 public key from `cnf.jwk`, equal to the key `device_did`
    /// encodes.
    pub device_public_key: [u8; 32],
    /// The canonical application identifier, equal to `aud`.
    pub application: String,
    /// The stable opaque account alias, never a username.
    pub account: AcctUri,
    /// The requested permission URIs, sorted and without duplicates.
    pub permissions: Vec<String>,
    /// Start of the validity window.
    pub valid_from: UnixSeconds,
    /// End of the validity window.
    pub valid_until: UnixSeconds,
    /// The `did:crdt` status entry.
    pub status_id: String,
    /// The optional Bitstring projection entry accompanying it.
    ///
    /// Kept whole rather than as a flag: `CON-210` has a verifier read a bit
    /// from a signed status list, and reading it needs the credential URL and
    /// the index. A boolean records that a projection *exists* and throws away
    /// everything needed to consult it, which makes any later observation
    /// unattributable to this grant.
    pub projection_entry: Option<BitstringStatusEntry>,
}

/// A conforming W3C `BitstringStatusListEntry` (`CON-205`, `CON-210`).
///
/// All five members are required by W3C Bitstring Status List 1.0. Recognising
/// only `type` and `statusListIndex` would admit an entry that names no list to
/// read, or names one for a different purpose, and would silently accept a
/// second status object that is not a projection at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitstringStatusEntry {
    /// The entry's own identifier.
    pub id: String,
    /// The purpose this bit expresses. `revocation` for a Selfsame grant.
    pub status_purpose: String,
    /// The index of this grant's bit, a canonical base-10 integer.
    pub status_list_index: String,
    /// The absolute URL of the signed status list credential.
    pub status_list_credential: String,
}

impl DeviceGrant {
    /// The lifetime `REQ-208` bounds, independent of the current instant.
    pub fn lifetime_seconds(&self) -> i64 {
        self.valid_until - self.valid_from
    }
}

/// Build the three identifiers a grant carries from one random token.
///
/// The 32 octets come from the caller's CSPRNG — the core owns no randomness,
/// which is also what makes a published vector reproducible.
pub fn identifiers(home_did: &str, token_octets: &[u8; 32]) -> (String, String, String) {
    let token = codec::b64url(token_octets);
    let grant_id = format!("{home_did}#grant-{token}");
    let status_id = format!("{home_did}#status-{token}");
    (grant_id, status_id, token)
}

/// The unsecured credential document (`CON-205`).
///
/// Assembled here and signed by [`crate::jws::sign`], so that the payload a
/// verifier recognises and the payload an issuer produces are the same shape by
/// construction rather than by two parallel definitions.
#[allow(clippy::too_many_arguments)]
pub fn build(
    home_did: &str,
    token_octets: &[u8; 32],
    device_did: &str,
    device_public_key: &[u8; 32],
    application: &ApplicationId,
    account: &AcctUri,
    permissions: &[String],
    valid_from: UnixSeconds,
    valid_until: UnixSeconds,
) -> Json {
    let (grant_id, status_id, _) = identifiers(home_did, token_octets);
    Json::obj([
        (
            "@context",
            Json::arr([
                Json::text(context::W3C_VC_CONTEXT),
                Json::text(context::CONTEXT_IRI),
            ]),
        ),
        ("type", Json::arr([Json::text(GRANT_TYPES[0]), Json::text(GRANT_TYPES[1])])),
        ("id", Json::text(grant_id.clone())),
        ("issuer", Json::text(home_did)),
        ("validFrom", Json::text(time::format_date_time_stamp(valid_from))),
        ("validUntil", Json::text(time::format_date_time_stamp(valid_until))),
        (
            "credentialSubject",
            Json::obj([
                ("id", Json::text(device_did)),
                ("application", Json::text(application.as_str())),
                ("account", Json::text(account.as_str())),
                (
                    "permissions",
                    Json::Array(permissions.iter().map(|p| Json::text(p.clone())).collect()),
                ),
            ]),
        ),
        (
            "credentialStatus",
            Json::obj([
                ("id", Json::text(status_id)),
                ("type", Json::text(STATUS_ENTRY_TYPE)),
                ("statusPurpose", Json::text("revocation")),
                ("credentialId", Json::text(grant_id)),
            ]),
        ),
        ("aud", Json::text(application.as_str())),
        (
            "cnf",
            Json::obj([(
                "jwk",
                Json::obj([
                    ("kty", Json::text("OKP")),
                    ("crv", Json::text("Ed25519")),
                    ("alg", Json::text("EdDSA")),
                    ("x", Json::text(codec::b64url(device_public_key))),
                ]),
            )]),
        ),
    ])
}

/// The protected header `CON-205` fixes.
pub fn header(home_did: &str) -> Json {
    Json::obj([
        ("alg", Json::text(jws::ALG)),
        ("kid", Json::text(format!("{home_did}{HOME_METHOD_FRAGMENT}"))),
        ("typ", Json::text(GRANT_JWS.typ)),
        ("cty", Json::text(GRANT_JWS.cty.expect("the grant policy fixes a cty"))),
    ])
}

/// Issue a grant: build the document, sign it, return the compact JWS.
#[allow(clippy::too_many_arguments)]
pub fn issue(
    home_key: &ed25519_dalek::SigningKey,
    home_did: &str,
    token_octets: &[u8; 32],
    device_did: &str,
    device_public_key: &[u8; 32],
    application: &ApplicationId,
    account: &AcctUri,
    permissions: &[String],
    valid_from: UnixSeconds,
    valid_until: UnixSeconds,
) -> String {
    let payload = build(
        home_did,
        token_octets,
        device_did,
        device_public_key,
        application,
        account,
        permissions,
        valid_from,
        valid_until,
    );
    jws::sign(&header(home_did), &payload, home_key)
}

const CREDENTIAL_MEMBERS: &[&str] = &[
    "@context",
    "type",
    "id",
    "issuer",
    "validFrom",
    "validUntil",
    "credentialSubject",
    "credentialStatus",
    "aud",
    "cnf",
];

const SUBJECT_MEMBERS: &[&str] = &["id", "application", "account", "permissions"];

const STATUS_MEMBERS: &[&str] = &["id", "type", "statusPurpose", "credentialId"];

/// The five members W3C Bitstring Status List 1.0 fixes for an entry.
const BITSTRING_MEMBERS: &[&str] =
    &["id", "type", "statusPurpose", "statusListIndex", "statusListCredential"];

/// Recognise a credential payload and check every cross-field equality
/// `CON-205` states.
///
/// This is `CON-206` step 8 minus the expected-account comparison, which needs
/// the verifier's context and is applied by [`crate::accept`].
pub fn recognise(payload: &Json) -> Result<DeviceGrant, GrantError> {
    let members = payload.as_object().ok_or(GrantError::BadMember("<root>"))?;
    for (name, _) in members {
        if !CREDENTIAL_MEMBERS.contains(&name.as_str()) {
            return Err(GrantError::UnknownMember(name.clone()));
        }
    }
    for name in CREDENTIAL_MEMBERS {
        if payload.get(name).is_none() {
            return Err(GrantError::BadMember(match *name {
                "@context" => "@context",
                "type" => "type",
                "id" => "id",
                "issuer" => "issuer",
                "validFrom" => "validFrom",
                "validUntil" => "validUntil",
                "credentialSubject" => "credentialSubject",
                "credentialStatus" => "credentialStatus",
                "aud" => "aud",
                _ => "cnf",
            }));
        }
    }

    context::recognise_context_array(payload.get("@context").expect("checked above"))?;

    let types = payload.get("type").and_then(Json::as_array).ok_or(GrantError::BadMember("type"))?;
    if types.len() != 2
        || types[0].as_str() != Some(GRANT_TYPES[0])
        || types[1].as_str() != Some(GRANT_TYPES[1])
    {
        return Err(bad("type", "must be exactly the two declared types in order"));
    }

    let issuer = text(payload, "issuer")?.to_string();
    if !issuer.starts_with("did:crdt:") || issuer.contains('#') {
        return Err(bad("issuer", "is not a bare did:crdt identifier"));
    }

    let id = text(payload, "id")?.to_string();
    let token = id
        .strip_prefix(&format!("{issuer}#grant-"))
        .ok_or(bad("id", "is not the issuer DID with a #grant- fragment"))?
        .to_string();
    // The token is the same 43-character canonical base64url shape CON-211
    // requires of an account scope, and for the same reason: a second spelling
    // of one identifier is a second identity for anything that compares it as
    // text — including the revocation G-Set.
    codec::decode_b64url_32(&token)
        .map_err(|_| bad("id", "grant token is not a canonical 32-octet base64url value"))?;

    let valid_from = stamp(payload, "validFrom")?;
    let valid_until = stamp(payload, "validUntil")?;
    if valid_until <= valid_from {
        return Err(bad("validUntil", "is not later than validFrom"));
    }

    // ── credentialSubject ──────────────────────────────────────────────────
    let subject = payload.get("credentialSubject").expect("checked above");
    closed(subject, SUBJECT_MEMBERS, "credentialSubject")?;
    let device_did = text(subject, "id")?.to_string();
    let application = text(subject, "application")?.to_string();
    let account_text = text(subject, "account")?;
    let account =
        AcctUri::parse(account_text).map_err(|_| bad("credentialSubject.account", "is not an acct: URI"))?;
    // REQ-218: the human-readable alias never appears in a VC `account` claim.
    if !account.is_stable() {
        return Err(bad(
            "credentialSubject.account",
            "is a human-readable alias, and only the stable opaque alias may appear here",
        ));
    }

    let permission_items = subject
        .get("permissions")
        .and_then(Json::as_array)
        .ok_or(GrantError::BadMember("credentialSubject.permissions"))?;
    if permission_items.is_empty() {
        return Err(bad("credentialSubject.permissions", "must be a non-empty set"));
    }
    let mut permissions = Vec::with_capacity(permission_items.len());
    for item in permission_items {
        permissions.push(
            item.as_str()
                .ok_or(bad("credentialSubject.permissions", "entry is not a string"))?
                .to_string(),
        );
    }
    if permissions.windows(2).any(|w| w[0] >= w[1]) {
        return Err(bad("credentialSubject.permissions", "is unsorted or contains a duplicate"));
    }

    // ── aud ────────────────────────────────────────────────────────────────
    if text(payload, "aud")? != application {
        return Err(bad("aud", "does not equal credentialSubject.application"));
    }

    // ── credentialStatus ───────────────────────────────────────────────────
    let (status_id, projection_entry) = recognise_status(payload, &issuer, &token, &id)?;

    // ── cnf ────────────────────────────────────────────────────────────────
    let cnf = payload.get("cnf").expect("checked above");
    closed(cnf, &["jwk"], "cnf")?;
    let jwk = cnf.get("jwk").ok_or(GrantError::BadMember("cnf.jwk"))?;
    closed(jwk, &["kty", "crv", "alg", "x"], "cnf.jwk")?;
    if text(jwk, "kty")? != "OKP" || text(jwk, "crv")? != "Ed25519" {
        return Err(bad("cnf.jwk", "is not an OKP/Ed25519 key"));
    }
    if text(jwk, "alg")? != jws::ALG {
        return Err(bad("cnf.jwk", "alg is not EdDSA"));
    }
    // `CON-206` step 6 forbids a private `d` on the *issuer* key; a private
    // component anywhere in a credential is a defect whoever put it there.
    if jwk.get("d").is_some() {
        return Err(bad("cnf.jwk", "carries a private key component"));
    }
    let device_public_key = codec::decode_b64url_32(text(jwk, "x")?)
        .map_err(|_| bad("cnf.jwk", "x is not a canonical 32-octet base64url value"))?;

    // The cross-field equality REQ-206 turns on: possession of the VC without
    // the corresponding device private key confers no access, and that is only
    // meaningful if the subject and the confirmation key are the same key.
    didkey::matches_jwk(&device_did, &device_public_key)
        .map_err(|_| bad("credentialSubject.id", "does not encode the cnf.jwk key"))?;

    Ok(DeviceGrant {
        id,
        issuer,
        token,
        device_did,
        device_public_key,
        application,
        account,
        permissions,
        valid_from,
        valid_until,
        status_id,
        projection_entry,
    })
}

/// `CON-205`: exactly one `SelfsameDidCrdtStatusEntry`, optionally followed by
/// one `BitstringStatusListEntry` when the profile enables the projection.
fn recognise_status(
    payload: &Json,
    issuer: &str,
    token: &str,
    grant_id: &str,
) -> Result<(String, Option<BitstringStatusEntry>), GrantError> {
    let node = payload.get("credentialStatus").expect("checked above");
    let (selfsame, projection) = match node {
        Json::Array(items) => match items.len() {
            2 => (&items[0], Some(&items[1])),
            _ => return Err(bad("credentialStatus", "an array must hold exactly two entries")),
        },
        _ => (node, None),
    };

    closed(selfsame, STATUS_MEMBERS, "credentialStatus")?;
    if text(selfsame, "type")? != STATUS_ENTRY_TYPE {
        return Err(bad("credentialStatus.type", "is not SelfsameDidCrdtStatusEntry"));
    }
    if text(selfsame, "statusPurpose")? != "revocation" {
        return Err(bad("credentialStatus.statusPurpose", "is not `revocation`"));
    }
    // The three-way agreement CON-205 requires: matching status_id,
    // credentialId, issuer DID, and grant token.
    let expected_status_id = format!("{issuer}#status-{token}");
    if text(selfsame, "id")? != expected_status_id {
        return Err(bad("credentialStatus.id", "does not match the issuer DID and grant token"));
    }
    if text(selfsame, "credentialId")? != grant_id {
        return Err(bad("credentialStatus.credentialId", "does not equal the grant id"));
    }

    let projection_entry = match projection {
        None => None,
        Some(entry) => {
            // A *conforming* BitstringStatusListEntry, not merely one carrying
            // the two members this used to look at.
            closed(entry, BITSTRING_MEMBERS, "credentialStatus")?;
            if entry.get("type").and_then(Json::as_str) != Some(BITSTRING_ENTRY_TYPE) {
                return Err(bad(
                    "credentialStatus",
                    "the second entry is not a BitstringStatusListEntry",
                ));
            }
            let member = |name: &'static str| -> Result<String, GrantError> {
                entry
                    .get(name)
                    .and_then(Json::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .ok_or(bad("credentialStatus", "the projection entry is incomplete"))
            };
            let id = member("id")?;
            let status_purpose = member("statusPurpose")?;
            let status_list_index = member("statusListIndex")?;
            let status_list_credential = member("statusListCredential")?;

            // The projection expresses the same thing the CRDT entry does, so a
            // second purpose here would be a bit about something else.
            if status_purpose != "revocation" {
                return Err(bad(
                    "credentialStatus.statusPurpose",
                    "the projection entry is not for revocation",
                ));
            }
            // `CON-210`: "canonical base-10 integer with no leading zeroes".
            if status_list_index.bytes().any(|b| !b.is_ascii_digit())
                || (status_list_index.len() > 1 && status_list_index.starts_with('0'))
            {
                return Err(bad("credentialStatus", "statusListIndex is not a canonical integer"));
            }
            // W3C requires an absolute URL, and CON-210's publication host is
            // HTTPS. A relative value would be resolved against something, and
            // what it was resolved against would decide which list was read.
            if !status_list_credential.starts_with("https://") {
                return Err(bad(
                    "credentialStatus.statusListCredential",
                    "is not an absolute HTTPS URL",
                ));
            }
            Some(BitstringStatusEntry {
                id,
                status_purpose,
                status_list_index,
                status_list_credential,
            })
        }
    };
    Ok((expected_status_id, projection_entry))
}

fn closed(value: &Json, allowed: &[&str], path: &'static str) -> Result<(), GrantError> {
    let members = value.as_object().ok_or(GrantError::BadMember(path))?;
    for (name, _) in members {
        if !allowed.contains(&name.as_str()) {
            return Err(GrantError::UnknownMember(format!("{path}.{name}")));
        }
    }
    Ok(())
}

fn text<'a>(value: &'a Json, name: &'static str) -> Result<&'a str, GrantError> {
    value.get(name).and_then(Json::as_str).ok_or(GrantError::BadMember(name))
}

fn stamp(value: &Json, name: &'static str) -> Result<UnixSeconds, GrantError> {
    let text = text(value, name)?;
    time::parse_date_time_stamp(text).map_err(|e| match e {
        TimeError::Malformed | TimeError::OutOfRange => GrantError::BadTimestamp,
    })
}
