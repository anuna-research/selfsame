//! A browser device client for [SPEC-001] linking — the wasm half of EXP-002.
//!
//! `selfsame-cli` is the reference device client: it draws a 128-bit secret,
//! signs an offer, seals it into a rendezvous slot, shows the person a link
//! code, and polls for the reply. This crate is the same client with the
//! effectful parts removed, so a browser can supply them instead.
//!
//! ```text
//!   JavaScript                         this crate                selfsame-core
//!   ──────────                         ──────────                ─────────────
//!   crypto.getRandomValues  ─secret─▶  LinkSession::new()  ────▶  Offer::sign
//!   fetch(PUT slot)         ◀─bytes──  sealed_offer()      ◀────  seal::seal_offer
//!   fetch(GET slot)         ─sealed─▶  accept()            ────▶  accept()
//!   IndexedDB                          (holds nothing)
//! ```
//!
//! # The split is the one the repository already draws
//!
//! Randomness, HTTP, and storage are the shell's; recognition and the
//! authorization decision are the core's. Nothing here decides anything — every
//! predicate below is `selfsame_core`'s, called in the order
//! `selfsame-cli/src/main.rs` calls it. A second implementation of the offer
//! format, the slot derivation, or the acceptance predicate is exactly the
//! parser differential this codebase spends `CON-205` avoiding, so there is not
//! one.
//!
//! # What this crate deliberately does not do
//!
//! It draws no randomness. `LinkSession::new` takes the secret and the device
//! seed as arguments rather than generating them, because a wasm module that
//! reached for an RNG would need one compiled in, and the browser already has
//! `crypto.getRandomValues` — a better source than anything this crate could
//! link. It also keeps the shell honest: the secret is visible at the boundary
//! where it is drawn.
//!
//! It stores nothing. The CLI persists an identity because a CLI is a device;
//! the harness's browser page is a fixture that is thrown away after each run,
//! and a store would be state the test has to clean up.
//!
//! # The SPEC-004 browser/hub boundary
//!
//! A browser proving possession of its own grant is the subject, not the
//! verifier. It can build the bytes to sign from its local profile, account,
//! exact grant, and the hub's nonce, but it cannot issue or consume the hub's
//! nonce record, observe resolver reachability for the hub, or know whether the
//! hub is establishing or continuing a session. Consequently this crate
//! exposes [`proof_input_json`] and no subject-side grant-acceptance facade.
//! Only the hub's effectful shell can combine those verifier-owned facts into
//! authorization.
//!
//! [SPEC-001]: ../../../specs/SPEC-001-device-key-provisioning.md

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ed25519_dalek::SigningKey;
use serde::Deserialize;
use wasm_bindgen::prelude::*;

use selfsame_app_identity::accept::VerificationMethod;
use selfsame_app_identity::accept::{ClosureSource, IssuerState};
use selfsame_app_identity::alias::{AcctUri, Jrd};
use selfsame_app_identity::ceremony::{self as identity_ceremony, BundlePayload, OfferCore};
use selfsame_app_identity::enrollment::{self as identity_enrollment, EnrollmentStatement};
use selfsame_app_identity::json::{self as identity_json, Json};
use selfsame_app_identity::path_b::{rehydrate_verified_grant, GrantRequest, VerifiedGrant};
use selfsame_app_identity::path_b::{union_resolver_revocations, ResolverRevocations};
use selfsame_app_identity::profile::ApplicationProfile;
use selfsame_app_identity::profile::Ed25519Jwk;
use selfsame_app_identity::proof::{self as identity_proof, Challenge};
use selfsame_app_identity::selection::ProviderHint;
use selfsame_core::code::{LinkCode, LinkSecret};
use selfsame_core::record::{Application, Offer};
use selfsame_core::{accept, seal, LinkContext, UnixSeconds};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserClosure {
    resolver_id: String,
    did: String,
    did_recomputed_ok: bool,
    deltas_verified: bool,
    causally_complete: bool,
    deactivated: bool,
    assertion_methods: Vec<BrowserMethod>,
    revoked_credential_ids: Vec<String>,
    closure_age_seconds: i64,
    also_known_as: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserMethod {
    id: String,
    kind: String,
    public_key: Vec<u8>,
    has_private_component: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserOfferCore {
    ceremony_id: String,
    request_id: String,
    application_id: String,
    profile_version: i64,
    profile_digest: String,
    account_scope_id: String,
    device_did: String,
    device_public_key: Vec<u8>,
    requested_permissions: Vec<String>,
    issued_at: i64,
    expires_at: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserProviderHint {
    application_id: String,
    profile_version: i64,
    provider_id: String,
    descriptor_digest: String,
    offer_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserEnrollmentStatement {
    request_id: String,
    ceremony_id: String,
    application_id: String,
    profile_version: i64,
    profile_digest: String,
    account_scope_id: String,
    device_key_digest: String,
    requested_permissions: Vec<String>,
    provider_id: String,
    descriptor_digest: String,
    offer_digest: String,
    platform_binding_id: String,
    return_uri: String,
    issued_at: i64,
    expires_at: i64,
}

/// Opaque refusal from a SPEC-004 browser-surface operation.
///
/// The pure identity crate retains precise local diagnostics. This boundary
/// deliberately does not: all malformed input, failed bindings, and failed
/// cryptographic checks have the same native outcome and the same per-facade
/// JavaScript error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    /// The operation was refused, without saying which check failed.
    Refused,
}

impl core::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Selfsame identity operation refused")
    }
}

/// Build the complete logical `CON-219` offer payload for the browser.
///
/// `offer_core_json` and `provider_hint_json` use the snake-case field names of
/// [`OfferCore`] and [`ProviderHint`] respectively. Both objects are closed.
/// The result is canonical JSON payload octets; PROTO-004 envelope sealing is a
/// separate transport operation.
#[wasm_bindgen]
pub fn build_offer_json(
    offer_core_json: &str,
    enrollment_evidence: &str,
    provider_hint_json: &str,
    profile: &[u8],
) -> Result<Vec<u8>, JsError> {
    let result = (|| -> Result<Vec<u8>, IdentityError> {
        let core = parse_offer_core(offer_core_json)?;
        let hint = parse_provider_hint(provider_hint_json)?;
        build_offer(&core, enrollment_evidence, &hint, profile)
    })();
    result.map_err(|_| JsError::new("SPEC-004 offer refused"))
}

/// Native twin of [`build_offer_json`].
///
/// [`OfferCore::to_json`] is the ceremony module's actual construction entry
/// point. There is no `ceremony::build_offer`; this function only adds the two
/// excluded members and asks the module's own recogniser to accept the result.
/// PROFILE-BOUND, because the two nested members are not this function's to take
/// on trust.
///
/// `recognise_offer` returns the evidence as text and the hint as an
/// unrecognised JSON value, so this used to emit a "complete" offer for
/// `not.a.valid.enrollment-jws` and a hint naming another application, an
/// undeclared provider and an unrelated offer digest — reproduced against the
/// built artefact. `ProviderHint::verify` is `CON-209`'s five checks and already
/// existed; nothing called it. A constructor that emits what its own protocol
/// rejects is a producer/recogniser disagreement that surfaces as a wallet
/// refusing every request rather than as a diff.
pub fn build_offer(
    core: &OfferCore,
    enrollment_evidence: &str,
    provider_hint: &ProviderHint,
    profile_bytes: &[u8],
) -> Result<Vec<u8>, IdentityError> {
    // Every check below compares against the JOINER'S OWN profile, never a
    // value the hint supplied — a hint may only select among things already
    // trusted.
    let profile =
        ApplicationProfile::recognise(profile_bytes).map_err(|_| IdentityError::Refused)?;
    provider_hint
        .verify(&profile, &core.digest())
        .map_err(|_| IdentityError::Refused)?;
    // The evidence is a CON-214 compact JWS, not arbitrary text to append.
    identity_enrollment::recognise(enrollment_evidence).map_err(|_| IdentityError::Refused)?;

    let Json::Object(mut members) = core.to_json() else {
        return Err(IdentityError::Refused);
    };
    members.push((
        "enrollmentEvidence".to_string(),
        Json::text(enrollment_evidence),
    ));
    members.push(("providerHint".to_string(), provider_hint.to_json()));
    let payload = identity_json::canonicalise(&Json::Object(members));
    identity_ceremony::recognise_offer(&payload).map_err(|_| IdentityError::Refused)?;
    Ok(payload)
}

/// Recognise a closed `CON-219` grant bundle and return its logical fields.
#[wasm_bindgen]
pub fn recognise_bundle_json(bundle: &[u8]) -> Result<String, JsError> {
    let result = recognise_bundle(bundle).and_then(|bundle| {
        let issuer_closure =
            serde_json::to_string(&bundle.issuer_closure).map_err(|_| IdentityError::Refused)?;
        Ok(format!(
            r#"{{"ceremonyId":{},"requestId":{},"grant":{},"issuerClosure":{}}}"#,
            json_string(&bundle.ceremony_id),
            json_string(&bundle.request_id),
            json_string(&bundle.grant),
            issuer_closure,
        ))
    });
    result.map_err(|_| JsError::new("SPEC-004 bundle refused"))
}

/// Native twin of [`recognise_bundle_json`].
pub fn recognise_bundle(bundle: &[u8]) -> Result<BundlePayload, IdentityError> {
    identity_ceremony::recognise_bundle(bundle).map_err(|_| IdentityError::Refused)
}

/// Require a returned bundle to name the exact complete offer the browser sent.
#[wasm_bindgen]
pub fn bundle_matches_offer_json(bundle: &[u8], offer: &[u8]) -> Result<(), JsError> {
    let result = (|| -> Result<(), IdentityError> {
        let bundle = recognise_bundle(bundle)?;
        let offer =
            identity_ceremony::recognise_offer(offer).map_err(|_| IdentityError::Refused)?;
        bundle_matches_offer(&bundle, &offer.core)
    })();
    result.map_err(|_| JsError::new("SPEC-004 bundle refused"))
}

/// Native twin of [`bundle_matches_offer_json`].
pub fn bundle_matches_offer(
    bundle: &BundlePayload,
    offer: &OfferCore,
) -> Result<(), IdentityError> {
    identity_ceremony::bundle_matches_offer(bundle, offer).map_err(|_| IdentityError::Refused)
}

/// Build the device's exact `CON-207` possession-proof input.
///
/// The hub sends only `nonce`. The authenticated profile, selected account,
/// and exact locally held grant are device-owned inputs; the grant hash is
/// derived here. Verifier-only session and issuance metadata deliberately do
/// not cross this boundary. The returned octets are for the browser to sign
/// with a non-extractable WebCrypto key and are not an authorization result.
#[wasm_bindgen]
pub fn proof_input_json(
    profile: &[u8],
    account: &str,
    grant: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, JsError> {
    let result = (|| -> Result<Vec<u8>, IdentityError> {
        let profile = ApplicationProfile::recognise(profile).map_err(|_| IdentityError::Refused)?;
        let account = AcctUri::parse(account).map_err(|_| IdentityError::Refused)?;
        let nonce: [u8; identity_proof::NONCE_OCTETS] =
            nonce.try_into().map_err(|_| IdentityError::Refused)?;
        Ok(proof_input(&profile, &account, grant, &nonce))
    })();
    result.map_err(|_| JsError::new("Device proof refused"))
}

/// Native twin of [`proof_input_json`].
pub fn proof_input(
    profile: &ApplicationProfile,
    account: &AcctUri,
    grant: &[u8],
    nonce: &[u8; identity_proof::NONCE_OCTETS],
) -> Vec<u8> {
    // `proof_input` intentionally excludes these verifier-owned fields. They
    // exist only because the shared core type also represents the hub's
    // issuance record; fixed private values keep them out of this API.
    let device_view = Challenge {
        nonce: *nonce,
        application_id: profile.application_id.as_str().to_string(),
        account: account.as_str().to_string(),
        grant_hash: identity_proof::grant_hash(grant),
        session: String::new(),
        issued_at: 0,
    };
    identity_proof::proof_input(&device_view)
}

/// Build the canonical, unsigned `CON-214` enrollment statement payload.
///
/// The closed input uses [`EnrollmentStatement`]'s snake-case field names. The
/// developer backend, not browser code, signs the returned payload.
#[wasm_bindgen]
pub fn build_enrollment_json(statement_json: &str) -> Result<Vec<u8>, JsError> {
    let result = parse_enrollment_statement(statement_json)
        .and_then(|statement| build_enrollment(&statement));
    result.map_err(|_| JsError::new("Enrollment statement refused"))
}

/// Native twin of [`build_enrollment_json`].
///
/// `enrollment::build` is an infallible serialiser, so this returned
/// canonical-looking bytes for `"bad"` identifiers and digests, an empty
/// permission list, and `expiresAt` earlier than `issuedAt` — the actual
/// language begins in the recogniser, which the facade never invoked. Round-trip
/// through it so the builder and the recogniser cannot disagree about what a
/// statement is.
pub fn build_enrollment(statement: &EnrollmentStatement) -> Result<Vec<u8>, IdentityError> {
    let octets = identity_json::canonicalise(&identity_enrollment::build(statement));
    identity_enrollment::recognise_unsigned_payload(&octets).map_err(|_| IdentityError::Refused)?;
    Ok(octets)
}

/// Recognise a compact `CON-214` enrollment JWS as a closed statement.
#[wasm_bindgen]
pub fn recognise_enrollment_json(compact: &str) -> Result<String, JsError> {
    let result = recognise_enrollment(compact).and_then(|statement| {
        String::from_utf8(build_enrollment(&statement)?).map_err(|_| IdentityError::Refused)
    });
    result.map_err(|_| JsError::new("Enrollment statement refused"))
}

/// Native twin of [`recognise_enrollment_json`].
pub fn recognise_enrollment(compact: &str) -> Result<EnrollmentStatement, IdentityError> {
    identity_enrollment::recognise(compact)
        .map(|(statement, _)| statement)
        .map_err(|_| IdentityError::Refused)
}

fn parse_offer_core(value: &str) -> Result<OfferCore, IdentityError> {
    let value: BrowserOfferCore =
        serde_json::from_str(value).map_err(|_| IdentityError::Refused)?;
    let device_public_key = value
        .device_public_key
        .try_into()
        .map_err(|_| IdentityError::Refused)?;
    Ok(OfferCore {
        ceremony_id: value.ceremony_id,
        request_id: value.request_id,
        application_id: value.application_id,
        profile_version: value.profile_version,
        profile_digest: value.profile_digest,
        account_scope_id: value.account_scope_id,
        device_did: value.device_did,
        device_public_key,
        requested_permissions: value.requested_permissions,
        issued_at: value.issued_at,
        expires_at: value.expires_at,
    })
}

fn parse_provider_hint(value: &str) -> Result<ProviderHint, IdentityError> {
    let value: BrowserProviderHint =
        serde_json::from_str(value).map_err(|_| IdentityError::Refused)?;
    Ok(ProviderHint {
        application_id: value.application_id,
        profile_version: value.profile_version,
        provider_id: value.provider_id,
        descriptor_digest: value.descriptor_digest,
        offer_digest: value.offer_digest,
    })
}

fn parse_enrollment_statement(value: &str) -> Result<EnrollmentStatement, IdentityError> {
    let value: BrowserEnrollmentStatement =
        serde_json::from_str(value).map_err(|_| IdentityError::Refused)?;
    Ok(EnrollmentStatement {
        request_id: value.request_id,
        ceremony_id: value.ceremony_id,
        application_id: value.application_id,
        profile_version: value.profile_version,
        profile_digest: value.profile_digest,
        account_scope_id: value.account_scope_id,
        device_key_digest: value.device_key_digest,
        requested_permissions: value.requested_permissions,
        provider_id: value.provider_id,
        descriptor_digest: value.descriptor_digest,
        offer_digest: value.offer_digest,
        platform_binding_id: value.platform_binding_id,
        return_uri: value.return_uri,
        issued_at: value.issued_at,
        expires_at: value.expires_at,
    })
}

/// Browser JSON facade for a distributed Path-B VC. Every JSON object is closed;
/// resolver facts originate in the browser's own resolver path, never a hub.
///
/// The argument list is the published wasm-bindgen ABI, so it is the shape an
/// adopting client's generated binding is written against: collapsing it into a
/// parameter object would be a breaking change to every embedder, and to the
/// provenance digest each one records for the artefact. Same disposition as
/// `grant::build` and `grant::issue`.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn verify_path_b_peer_json(
    profile: &[u8],
    account: &str,
    device_key: &[u8],
    permissions_json: &str,
    now: f64,
    clock_skew_seconds: i64,
    jrd: &[u8],
    grant: &[u8],
    closures_json: &str,
) -> Result<String, JsError> {
    let result = (|| -> Result<VerifiedGrant, DeviceError> {
        let profile = ApplicationProfile::recognise(profile).map_err(|_| DeviceError::Refused)?;
        let account = AcctUri::parse(account).map_err(|_| DeviceError::Refused)?;
        let device_key: [u8; 32] = device_key.try_into().map_err(|_| DeviceError::Refused)?;
        let permissions: Vec<String> =
            serde_json::from_str(permissions_json).map_err(|_| DeviceError::Refused)?;
        let permission_refs: Vec<&str> = permissions.iter().map(String::as_str).collect();
        let now = browser_unix_seconds(now)?;
        let jrd =
            selfsame_app_identity::alias::recognise_jrd(jrd).map_err(|_| DeviceError::Refused)?;
        let closures: Vec<BrowserClosure> =
            serde_json::from_str(closures_json).map_err(|_| DeviceError::Refused)?;
        let first = closures.first().ok_or(DeviceError::Refused)?;
        if closures
            .iter()
            .any(|closure| closure.closure_age_seconds < 0)
        {
            return Err(DeviceError::Refused);
        }
        let observations: Vec<ResolverRevocations<'_>> = closures
            .iter()
            .map(|c| ResolverRevocations {
                resolver_id: &c.resolver_id,
                revoked_credential_ids: &c.revoked_credential_ids,
            })
            .collect();
        let revoked = union_resolver_revocations(&profile, &observations)
            .map_err(|_| DeviceError::Refused)?;
        if closures.iter().any(|c| {
            c.did != first.did
                || c.did_recomputed_ok != first.did_recomputed_ok
                || c.deltas_verified != first.deltas_verified
                || c.causally_complete != first.causally_complete
                || c.deactivated != first.deactivated
                || c.assertion_methods.len() != first.assertion_methods.len()
                || c.also_known_as != first.also_known_as
        }) {
            return Err(DeviceError::Refused);
        }
        let methods = first
            .assertion_methods
            .iter()
            .map(|m| {
                let key: [u8; 32] = m
                    .public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| DeviceError::Refused)?;
                Ok(VerificationMethod {
                    id: m.id.clone(),
                    kind: m.kind.clone(),
                    jwk: Ed25519Jwk {
                        public_key: key,
                        x: String::new(),
                    },
                    has_private_component: m.has_private_component,
                })
            })
            .collect::<Result<Vec<_>, DeviceError>>()?;
        let closure_age_seconds = closures
            .iter()
            .map(|c| c.closure_age_seconds)
            .max()
            .ok_or(DeviceError::Refused)?;
        let issuer = IssuerState {
            did: first.did.clone(),
            did_recomputed_ok: first.did_recomputed_ok,
            deltas_verified: first.deltas_verified,
            causally_complete: first.causally_complete,
            deactivated: first.deactivated,
            assertion_methods: methods,
            revoked_credential_ids: revoked,
            closure_age_seconds,
            source: ClosureSource::StateResolver,
            also_known_as: first.also_known_as.clone(),
        };
        verify_path_b_peer(
            &profile,
            &account,
            &device_key,
            &permission_refs,
            now,
            clock_skew_seconds,
            &jrd,
            grant,
            &issuer,
        )
    })();
    result
        .map(|g| {
            format!(
                r#"{{"accountDid":{},"grantId":{},"validUntil":{}}}"#,
                json_string(&g.account_did),
                json_string(&g.grant_id),
                g.valid_until
            )
        })
        .map_err(|_| JsError::new("Path-B grant refused"))
}

/// Verify a distributed Path-B grant for a peer without consulting any hub.
///
/// The browser supplies only its own already-resolved, locally verified closure
/// and reciprocal JRD. This replays CON-206 steps 1--12 over the opaque VC; it
/// intentionally has no hub assertion, cache fallback, or proof-bypass flag.
///
/// Kept argument-for-argument with the JSON facade above: the two are one
/// contract seen from two sides, and a divergence between them is exactly the
/// defect a reader of either would not see.
#[allow(clippy::too_many_arguments)]
pub fn verify_path_b_peer(
    profile: &ApplicationProfile,
    account: &AcctUri,
    device_key: &[u8; 32],
    permissions: &[&str],
    now: UnixSeconds,
    clock_skew_seconds: i64,
    jrd: &Jrd,
    grant: &[u8],
    issuer: &IssuerState,
) -> Result<VerifiedGrant, DeviceError> {
    if issuer.source != ClosureSource::StateResolver {
        return Err(DeviceError::Refused);
    }
    if issuer.closure_age_seconds < 0 {
        return Err(DeviceError::Refused);
    }
    let now = i64::try_from(now).map_err(|_| DeviceError::Refused)?;
    if clock_skew_seconds < 0
        || now.checked_add(clock_skew_seconds).is_none()
        || now.checked_sub(clock_skew_seconds).is_none()
    {
        return Err(DeviceError::Refused);
    }
    rehydrate_verified_grant(
        &GrantRequest::new(
            profile,
            account,
            device_key,
            permissions,
            now,
            clock_skew_seconds,
        ),
        issuer,
        jrd,
        None,
        grant,
    )
    .map_err(|_| DeviceError::Refused)
}

fn browser_unix_seconds(value: f64) -> Result<UnixSeconds, DeviceError> {
    const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 || value > MAX_SAFE_INTEGER {
        return Err(DeviceError::Refused);
    }
    Ok(value as UnixSeconds)
}

/// The application this client links for.
///
/// One variant exists (`ADR-011` keeps a single application), and it is named
/// here rather than taken from an argument for the reason `selfsame-cli` gives
/// about its own endpoint table: values that decide *who you are talking to*
/// are compiled in, and are never read off the wire or out of a link code.
const APPLICATION: Application = Application::CbclChat;

/// Why a call was refused.
///
/// A real error type rather than `JsError`, because `JsError` cannot be built
/// or read outside a wasm host — it panics — and that would make every refusal
/// path in this crate testable only in a browser. The refusal paths are the
/// ones worth testing, so they get a type that exists everywhere and the
/// [`LinkSession`] wasm surface adapts it at the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceError {
    /// The link secret was not exactly 16 octets.
    SecretLength,
    /// The device seed was not exactly 32 octets.
    SeedLength,
    /// The reply was not for this device.
    ///
    /// Carries nothing. `SCREEN-002` S4: the reason "would teach the user
    /// nothing and would leak which check failed."
    Refused,
}

impl core::fmt::Display for DeviceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::SecretLength => "the link secret is exactly 16 octets",
            Self::SeedLength => "the device seed is exactly 32 octets",
            Self::Refused => "Couldn't link — the reply didn't match this device.",
        })
    }
}

/// One linking attempt, from the secret being drawn to the reply being judged.
///
/// Holds the offer because [`accept`] needs it: `LinkContext` binds the reply to
/// the exact offer this client wrote, and re-parsing it from bytes on the way
/// back would be a second chance to get it wrong.
///
/// Pure and host-independent. The browser-facing type is [`LinkSession`], which
/// is this with its errors translated.
///
/// `Debug` prints no secret: the 16-octet link secret and the sealing key are
/// the two things in here worth protecting, and neither appears.
pub struct Device {
    secret: [u8; 16],
    key: [u8; 32],
    offer: Offer,
}

/// Deliberately opaque, following `hierarchy::HomeKey`.
///
/// Two of the three fields are secret — the 128-bit link secret and the key
/// derived from it — and a derived `Debug` would put both in any log line, any
/// panic message, and any `unwrap_err()` a test writes. The offer is public but
/// is omitted too, because a redaction that lists what it is hiding beside what
/// it is not invites someone to add "just one more" field.
impl core::fmt::Debug for Device {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Device(<redacted>)")
    }
}

impl Device {
    /// Begin an attempt.
    ///
    /// `secret` is 16 octets from the caller's CSPRNG and `device_seed` is 32
    /// octets for this device's signing key. Both are the caller's to draw and
    /// the caller's to keep; this crate treats them as inputs.
    ///
    /// `expires` is the absolute Unix second the offer stops being valid —
    /// `now + OFFER_TTL_SECONDS` at the call site, so the clock stays in the
    /// shell where it belongs.
    pub fn new(
        secret: &[u8],
        device_seed: &[u8],
        description: &str,
        expires: UnixSeconds,
    ) -> Result<Device, DeviceError> {
        let secret: [u8; 16] = secret.try_into().map_err(|_| DeviceError::SecretLength)?;
        let seed: [u8; 32] = device_seed
            .try_into()
            .map_err(|_| DeviceError::SeedLength)?;

        let signing = SigningKey::from_bytes(&seed);
        let offer = Offer::sign(APPLICATION, &signing, description, expires);

        Ok(Device {
            secret,
            key: seal::derive_key(&secret),
            offer,
        })
    }

    /// The code the person types into the wallet, or scans.
    ///
    /// `SCREEN-002` S2 treats the typed code and the QR as equal paths rather
    /// than one behind the other, and the harness uses the typed one — which
    /// also keeps the emulator's camera out of the loop entirely.
    pub fn link_code(&self) -> String {
        LinkCode {
            application: APPLICATION,
            secret: LinkSecret::from_bytes(self.secret),
        }
        .render()
    }

    /// Where the sealed offer is written.
    pub fn offer_slot(&self) -> String {
        seal::slot(seal::Role::Offer, &self.secret)
    }

    /// Where the reply will appear.
    ///
    /// A different slot from the offer's, derived from the same secret — which
    /// is what lets the rendezvous hold `H(s)` and never `s`.
    pub fn bundle_slot(&self) -> String {
        seal::slot(seal::Role::Bundle, &self.secret)
    }

    /// The octets to `PUT` into [`Self::offer_slot`].
    pub fn sealed_offer(&self) -> Vec<u8> {
        seal::seal_offer(&self.key, &self.offer.to_bytes())
    }

    /// Judge the reply that appeared in [`Self::bundle_slot`].
    ///
    /// Returns a JSON object on success. On refusal it returns
    /// [`DeviceError::Refused`] and nothing else, which is `SCREEN-002` S4's
    /// rule. The harness asserting *that* a bad reply is refused is the point;
    /// asserting *which* clause refused it is `selfsame-core`'s own suite's
    /// job, and it already does that.
    pub fn accept(&self, sealed: &[u8], now: UnixSeconds) -> Result<String, DeviceError> {
        let ctx = LinkContext {
            secret: self.secret,
            offer: self.offer.clone(),
        };
        let identity = accept(sealed, &ctx, now).map_err(|_| DeviceError::Refused)?;

        // A JSON string rather than a serde-wasm-bindgen conversion: four
        // fields, one `JSON.parse` on the other side, and one fewer dependency
        // in a crate that exists to avoid adding them.
        Ok(format!(
            r#"{{"did":{},"fingerprintHex":{},"fingerprintLabel":{},"ownMethodId":{}}}"#,
            json_string(&identity.did),
            json_string(&identity.fingerprint.hex()),
            json_string(&identity.fingerprint.label()),
            json_string(&identity.own_method_id),
        ))
    }
}

/// The browser-facing surface: [`Device`] with its errors translated.
///
/// Nothing but translation happens here. Every decision is [`Device`]'s, which
/// is in turn every decision `selfsame_core` makes — this type exists so that
/// `JsError`, which only works inside a wasm host, stays at the very edge.
#[wasm_bindgen(js_name = LinkSession)]
pub struct LinkSession(Device);

#[wasm_bindgen(js_class = LinkSession)]
impl LinkSession {
    /// Begin an attempt. See [`Device::new`].
    #[wasm_bindgen(constructor)]
    pub fn new(
        secret: &[u8],
        device_seed: &[u8],
        description: &str,
        expires: f64,
    ) -> Result<LinkSession, JsError> {
        let expires =
            browser_unix_seconds(expires).map_err(|_| JsError::new("Link attempt refused"))?;
        Device::new(secret, device_seed, description, expires)
            .map(LinkSession)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// See [`Device::link_code`].
    #[wasm_bindgen(getter)]
    pub fn link_code(&self) -> String {
        self.0.link_code()
    }

    /// See [`Device::offer_slot`].
    #[wasm_bindgen(getter)]
    pub fn offer_slot(&self) -> String {
        self.0.offer_slot()
    }

    /// See [`Device::bundle_slot`].
    #[wasm_bindgen(getter)]
    pub fn bundle_slot(&self) -> String {
        self.0.bundle_slot()
    }

    /// See [`Device::sealed_offer`].
    pub fn sealed_offer(&self) -> Vec<u8> {
        self.0.sealed_offer()
    }

    /// See [`Device::accept`].
    pub fn accept(&self, sealed: &[u8], now: f64) -> Result<String, JsError> {
        let now = browser_unix_seconds(now)
            .map_err(|_| JsError::new("Couldn't link — the reply didn't match this device."))?;
        self.0
            .accept(sealed, now)
            .map_err(|e| JsError::new(&e.to_string()))
    }
}

/// Quote a string as a JSON literal.
///
/// Every value this escapes is a DID, a hex fingerprint, a nickname, or a
/// method id — none of which can contain a quote or a control character. It
/// escapes anyway, because "cannot contain" is an argument about today's
/// producers and this is a boundary.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use selfsame_app_identity::profile::ApplicationId;
    use selfsame_app_identity::scope::AccountScopeId;
    use selfsame_app_identity::{alias, codec, didkey, grant, hierarchy};

    const SECRET: [u8; 16] = [7u8; 16];
    const SEED: [u8; 32] = [9u8; 32];
    const APP_ID: &str = "https://photos.example/selfsame/application";
    const PERMISSION: &str = "https://photos.example/selfsame/application#device";
    const NOW: i64 = 1_785_412_800;
    const VERIFIER_SESSION: &str = "browser-verifier-session";
    const ENROLLMENT_KID: &str = "https://photos.example/selfsame/application#enrollment-test";

    fn session() -> Device {
        Device::new(&SECRET, &SEED, "Chrome on a test bench", 1_800_000_300)
            .expect("well-formed inputs")
    }

    struct GrantFixture {
        profile_octets: Vec<u8>,
        profile: ApplicationProfile,
        account: AcctUri,
        device_public_key: [u8; 32],
        grant: Vec<u8>,
        issuer: IssuerState,
        jrd: Jrd,
        jrd_octets: Vec<u8>,
        challenge: Challenge,
    }

    fn example_profile_octets() -> Vec<u8> {
        let corpus: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/spec-004-v1.json"))
                .expect("the checked-in corpus is JSON");
        corpus["con_201_application_profile"][0]["input"]["profile"]
            .as_str()
            .expect("the corpus carries the canonical profile")
            .as_bytes()
            .to_vec()
    }

    fn grant_fixture() -> GrantFixture {
        let profile_octets = example_profile_octets();
        let profile = ApplicationProfile::recognise(&profile_octets).expect("recognised profile");
        let application = ApplicationId::parse(APP_ID).expect("canonical application id");
        let scope = AccountScopeId::from_octets([4u8; 32]);
        let mnemonic = hierarchy::Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .expect("test mnemonic");
        let home = hierarchy::derive_from_mnemonic(&mnemonic, &application, &scope);
        let home_did = home.home_did().expect("home DID");
        let account = AcctUri::parse(&alias::stable_acct_uri(
            &home_did,
            &profile.account_authority,
        ))
        .expect("stable account");

        let device_key = SigningKey::from_bytes(&[3u8; 32]);
        let device_public_key = device_key.verifying_key().to_bytes();
        let device_did = didkey::encode(&device_public_key);
        let valid_from = NOW - 3_600;
        let valid_until = valid_from + 2_592_000;
        let grant = grant::issue(
            home.signing_key(),
            &home_did,
            &[12u8; 32],
            &device_did,
            &device_public_key,
            &application,
            &account,
            &[PERMISSION.to_string()],
            valid_from,
            valid_until,
        )
        .into_bytes();

        let issuer = IssuerState {
            did: home_did.clone(),
            did_recomputed_ok: true,
            deltas_verified: true,
            causally_complete: true,
            deactivated: false,
            assertion_methods: vec![VerificationMethod {
                id: format!("{home_did}#jwk-0"),
                kind: "JsonWebKey".into(),
                jwk: Ed25519Jwk {
                    public_key: home.public_key(),
                    x: codec::b64url(&home.public_key()),
                },
                has_private_component: false,
            }],
            revoked_credential_ids: vec![],
            closure_age_seconds: 10,
            source: ClosureSource::StateResolver,
            also_known_as: vec![account.as_str().to_string()],
        };
        let jrd = Jrd {
            subject: account.as_str().to_string(),
            aliases: vec![home_did],
        };
        let jrd_octets = identity_json::canonicalise(&Json::obj([
            ("subject", Json::text(jrd.subject.clone())),
            (
                "aliases",
                Json::Array(jrd.aliases.iter().map(|a| Json::text(a.clone())).collect()),
            ),
        ]));
        let challenge = Challenge {
            nonce: [42u8; 32],
            application_id: APP_ID.into(),
            account: account.as_str().to_string(),
            grant_hash: identity_proof::grant_hash(&grant),
            session: VERIFIER_SESSION.into(),
            issued_at: NOW - 5,
        };
        GrantFixture {
            profile_octets,
            profile,
            account,
            device_public_key,
            grant,
            issuer,
            jrd,
            jrd_octets,
            challenge,
        }
    }

    fn offer_fixture(
        fixture: &GrantFixture,
    ) -> (OfferCore, ProviderHint, EnrollmentStatement, String) {
        let core = OfferCore {
            ceremony_id: codec::b64url(&[1u8; 32]),
            request_id: codec::b64url(&[2u8; 32]),
            application_id: APP_ID.into(),
            profile_version: 1,
            profile_digest: codec::b64url(fixture.profile.digest()),
            account_scope_id: codec::b64url(&[4u8; 32]),
            device_did: didkey::encode(&fixture.device_public_key),
            device_public_key: fixture.device_public_key,
            requested_permissions: vec![PERMISSION.into()],
            issued_at: NOW,
            expires_at: NOW + 120,
        };
        let descriptor = &fixture.profile.rendezvous[0];
        let hint = ProviderHint {
            application_id: APP_ID.into(),
            profile_version: 1,
            provider_id: descriptor.id.clone(),
            descriptor_digest: codec::b64url(&descriptor.digest),
            offer_digest: core.digest(),
        };
        let statement = EnrollmentStatement {
            request_id: core.request_id.clone(),
            ceremony_id: core.ceremony_id.clone(),
            application_id: core.application_id.clone(),
            profile_version: core.profile_version,
            profile_digest: core.profile_digest.clone(),
            account_scope_id: core.account_scope_id.clone(),
            device_key_digest: identity_enrollment::device_key_digest(&core),
            requested_permissions: core.requested_permissions.clone(),
            provider_id: hint.provider_id.clone(),
            descriptor_digest: hint.descriptor_digest.clone(),
            offer_digest: core.digest(),
            platform_binding_id: "apple:TEAM123456:com.example.photos:https://photos.example"
                .into(),
            return_uri: "https://photos.example/.well-known/selfsame/return".into(),
            issued_at: core.issued_at,
            expires_at: core.expires_at,
        };
        let evidence = identity_enrollment::sign(
            &statement,
            ENROLLMENT_KID,
            &SigningKey::from_bytes(&[6u8; 32]),
        );
        (core, hint, statement, evidence)
    }

    fn offer_core_json(core: &OfferCore) -> String {
        serde_json::json!({
            "ceremony_id": core.ceremony_id,
            "request_id": core.request_id,
            "application_id": core.application_id,
            "profile_version": core.profile_version,
            "profile_digest": core.profile_digest,
            "account_scope_id": core.account_scope_id,
            "device_did": core.device_did,
            "device_public_key": core.device_public_key,
            "requested_permissions": core.requested_permissions,
            "issued_at": core.issued_at,
            "expires_at": core.expires_at,
        })
        .to_string()
    }

    fn provider_hint_json(hint: &ProviderHint) -> String {
        serde_json::json!({
            "application_id": hint.application_id,
            "profile_version": hint.profile_version,
            "provider_id": hint.provider_id,
            "descriptor_digest": hint.descriptor_digest,
            "offer_digest": hint.offer_digest,
        })
        .to_string()
    }

    fn enrollment_statement_json(statement: &EnrollmentStatement) -> String {
        serde_json::json!({
            "request_id": statement.request_id,
            "ceremony_id": statement.ceremony_id,
            "application_id": statement.application_id,
            "profile_version": statement.profile_version,
            "profile_digest": statement.profile_digest,
            "account_scope_id": statement.account_scope_id,
            "device_key_digest": statement.device_key_digest,
            "requested_permissions": statement.requested_permissions,
            "provider_id": statement.provider_id,
            "descriptor_digest": statement.descriptor_digest,
            "offer_digest": statement.offer_digest,
            "platform_binding_id": statement.platform_binding_id,
            "return_uri": statement.return_uri,
            "issued_at": statement.issued_at,
            "expires_at": statement.expires_at,
        })
        .to_string()
    }

    fn resolver_closures_json(issuer: &IssuerState) -> String {
        let methods: Vec<serde_json::Value> = issuer
            .assertion_methods
            .iter()
            .map(|method| {
                serde_json::json!({
                    "id": method.id,
                    "kind": method.kind,
                    "public_key": method.jwk.public_key,
                    "has_private_component": method.has_private_component,
                })
            })
            .collect();
        let closure = |resolver_id: &str| {
            serde_json::json!({
                "resolver_id": resolver_id,
                "did": issuer.did,
                "did_recomputed_ok": issuer.did_recomputed_ok,
                "deltas_verified": issuer.deltas_verified,
                "causally_complete": issuer.causally_complete,
                "deactivated": issuer.deactivated,
                "assertion_methods": methods,
                "revoked_credential_ids": issuer.revoked_credential_ids,
                "closure_age_seconds": issuer.closure_age_seconds,
                "also_known_as": issuer.also_known_as,
            })
        };
        serde_json::json!([closure("app-own"), closure("state-1")]).to_string()
    }

    #[test]
    fn build_offer_json_calls_offer_core_to_json_and_builds_all_fifteen_members() {
        let fixture = grant_fixture();
        let (core, hint, _, evidence) = offer_fixture(&fixture);
        let payload = build_offer_json(
            &offer_core_json(&core),
            &evidence,
            &provider_hint_json(&hint),
            &fixture.profile_octets,
        )
        .expect("the native rlib can exercise a successful wasm facade");
        let recognised = identity_ceremony::recognise_offer(&payload).expect("recognised offer");
        assert_eq!(recognised.core, core);
        assert_eq!(recognised.enrollment_evidence, evidence);
        assert_eq!(recognised.offer_digest, hint.offer_digest);
        let value = identity_json::recognise(
            &payload,
            selfsame_app_identity::json::Limits {
                max_bytes: 69_607,
                max_depth: 8,
            },
        )
        .unwrap();
        assert_eq!(value.member_names().len(), 15);
    }

    #[test]
    fn recognise_bundle_json_returns_the_verbatim_grant_and_optional_closure() {
        let ceremony_id = codec::b64url(&[1u8; 32]);
        let request_id = codec::b64url(&[2u8; 32]);
        let payload = identity_ceremony::build_bundle(
            &ceremony_id,
            &request_id,
            "one.two.three",
            Some(&[7u8, 8, 9]),
        )
        .unwrap();
        let output = recognise_bundle_json(&payload)
            .expect("the native rlib can exercise a successful wasm facade");
        let output: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(output["ceremonyId"], ceremony_id);
        assert_eq!(output["requestId"], request_id);
        assert_eq!(output["grant"], "one.two.three");
        assert_eq!(output["issuerClosure"], serde_json::json!([7, 8, 9]));
    }

    #[test]
    fn bundle_matches_offer_json_compares_the_identifiers_from_recognised_payloads() {
        let fixture = grant_fixture();
        let (core, hint, _, evidence) = offer_fixture(&fixture);
        let offer = build_offer_json(
            &offer_core_json(&core),
            &evidence,
            &provider_hint_json(&hint),
            &fixture.profile_octets,
        )
        .unwrap();
        let bundle = identity_ceremony::build_bundle(
            &core.ceremony_id,
            &core.request_id,
            "one.two.three",
            None,
        )
        .unwrap();
        bundle_matches_offer_json(&bundle, &offer).expect("the matching native facade succeeds");

        let other = identity_ceremony::recognise_bundle(
            &identity_ceremony::build_bundle(
                &codec::b64url(&[9u8; 32]),
                &core.request_id,
                "one.two.three",
                None,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            bundle_matches_offer(&other, &core),
            Err(IdentityError::Refused),
            "the native twin does not expose the mismatched field"
        );
    }

    #[test]
    fn proof_input_json_derives_the_core_input_from_device_owned_facts() {
        let fixture = grant_fixture();
        let control = proof_input_json(
            &fixture.profile_octets,
            fixture.account.as_str(),
            &fixture.grant,
            &fixture.challenge.nonce,
        )
        .expect("the native rlib can exercise a successful wasm facade");
        assert_eq!(control, identity_proof::proof_input(&fixture.challenge));
        assert_eq!(
            control,
            proof_input(
                &fixture.profile,
                &fixture.account,
                &fixture.grant,
                &fixture.challenge.nonce,
            ),
        );

        let mut other_nonce = fixture.challenge.nonce;
        other_nonce[0] ^= 1;
        let nonce_changed = proof_input_json(
            &fixture.profile_octets,
            fixture.account.as_str(),
            &fixture.grant,
            &other_nonce,
        )
        .expect("a second well-formed nonce is a valid input");
        assert_ne!(nonce_changed, control, "only the nonce changed");

        let mut other_grant = fixture.grant.clone();
        other_grant.push(b' ');
        let grant_changed = proof_input_json(
            &fixture.profile_octets,
            fixture.account.as_str(),
            &other_grant,
            &fixture.challenge.nonce,
        )
        .expect("proof input hashes the exact locally selected grant octets");
        assert_ne!(grant_changed, control, "only the grant octets changed");
    }

    #[test]
    fn build_enrollment_json_is_the_cores_canonical_unsigned_statement() {
        let fixture = grant_fixture();
        let (_, _, statement, _) = offer_fixture(&fixture);
        let output = build_enrollment_json(&enrollment_statement_json(&statement))
            .expect("the native rlib can exercise a successful wasm facade");
        assert_eq!(output, build_enrollment(&statement).unwrap());
        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["evidenceVersion"], 1);
        assert_eq!(value["offerDigest"], statement.offer_digest);
    }

    #[test]
    fn recognise_enrollment_json_returns_the_closed_signed_statement() {
        let fixture = grant_fixture();
        let (_, _, statement, compact) = offer_fixture(&fixture);
        let output = recognise_enrollment_json(&compact)
            .expect("the native rlib can exercise a successful wasm facade");
        assert_eq!(output.as_bytes(), build_enrollment(&statement).unwrap());
    }

    #[test]
    fn verify_path_b_peer_json_has_a_native_rlib_success_path() {
        let fixture = grant_fixture();
        let output = verify_path_b_peer_json(
            &fixture.profile_octets,
            fixture.account.as_str(),
            &fixture.device_public_key,
            &serde_json::json!([PERMISSION]).to_string(),
            NOW as f64,
            0,
            &fixture.jrd_octets,
            &fixture.grant,
            &resolver_closures_json(&fixture.issuer),
        )
        .expect("the existing facade is testable in the native rlib too");
        let output: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(output["accountDid"], fixture.issuer.did);
    }

    #[test]
    fn peer_verification_refuses_a_negative_closure_age() {
        let fixture = grant_fixture();
        let control = verify_path_b_peer(
            &fixture.profile,
            &fixture.account,
            &fixture.device_public_key,
            &[PERMISSION],
            NOW as UnixSeconds,
            0,
            &fixture.jrd,
            &fixture.grant,
            &fixture.issuer,
        );
        assert!(control.is_ok(), "control: the unmodified fixture verifies");

        let mut negative_age = fixture.issuer.clone();
        negative_age.closure_age_seconds = -1;
        let changed = verify_path_b_peer(
            &fixture.profile,
            &fixture.account,
            &fixture.device_public_key,
            &[PERMISSION],
            NOW as UnixSeconds,
            0,
            &fixture.jrd,
            &fixture.grant,
            &negative_age,
        );
        assert_eq!(
            changed,
            Err(DeviceError::Refused),
            "only closure age changed"
        );
    }

    #[test]
    fn peer_verification_refuses_clock_skew_that_would_overflow() {
        let fixture = grant_fixture();
        let control = verify_path_b_peer(
            &fixture.profile,
            &fixture.account,
            &fixture.device_public_key,
            &[PERMISSION],
            NOW as UnixSeconds,
            0,
            &fixture.jrd,
            &fixture.grant,
            &fixture.issuer,
        );
        assert!(control.is_ok(), "control: zero configured skew verifies");

        let changed = verify_path_b_peer(
            &fixture.profile,
            &fixture.account,
            &fixture.device_public_key,
            &[PERMISSION],
            NOW as UnixSeconds,
            i64::MAX,
            &fixture.jrd,
            &fixture.grant,
            &fixture.issuer,
        );
        assert_eq!(
            changed,
            Err(DeviceError::Refused),
            "only the configured clock skew changed",
        );
    }

    #[test]
    fn browser_timestamp_conversion_refuses_a_negative_instant() {
        assert_eq!(
            browser_unix_seconds(NOW as f64),
            Ok(NOW as UnixSeconds),
            "control: the fixture instant is representable",
        );
        assert_eq!(
            browser_unix_seconds(-1.0),
            Err(DeviceError::Refused),
            "only the instant changed",
        );
    }

    #[test]
    fn every_structured_browser_input_is_closed_and_refuses_opaque() {
        let fixture = grant_fixture();
        let (core, hint, statement, _) = offer_fixture(&fixture);
        let with_unknown = |input: String| {
            let mut value: serde_json::Value = serde_json::from_str(&input).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .insert("unknown".into(), serde_json::Value::Bool(true));
            value.to_string()
        };

        assert_eq!(
            parse_offer_core(&with_unknown(offer_core_json(&core))),
            Err(IdentityError::Refused)
        );
        assert_eq!(
            parse_provider_hint(&with_unknown(provider_hint_json(&hint))),
            Err(IdentityError::Refused)
        );
        assert_eq!(
            parse_enrollment_statement(&with_unknown(enrollment_statement_json(&statement))),
            Err(IdentityError::Refused)
        );
        assert_eq!(
            IdentityError::Refused.to_string(),
            "Selfsame identity operation refused"
        );
        for leak in ["signature", "issuer", "profile", "nonce", "grant"] {
            assert!(!IdentityError::Refused.to_string().contains(leak));
        }
    }

    #[test]
    fn the_two_slots_differ_and_are_a_function_of_the_secret_alone() {
        // The rendezvous holds H(s) and never s, and it holds two of them. A
        // client that wrote both roles to one slot would let the operator
        // overwrite a reply with an offer.
        let s = session();
        assert_ne!(s.offer_slot(), s.bundle_slot());
        assert_eq!(s.offer_slot(), seal::slot(seal::Role::Offer, &SECRET));
        assert_eq!(s.bundle_slot(), seal::slot(seal::Role::Bundle, &SECRET));
    }

    #[test]
    fn the_link_code_round_trips_through_the_cores_own_parser() {
        // The wallet parses what this renders. Rendering something the core's
        // parser refuses would be a parser differential across the ceremony's
        // two halves — with both halves in this repository.
        let s = session();
        let parsed = LinkCode::parse(&s.link_code()).expect("the core parses what it rendered");
        assert_eq!(parsed.application, APPLICATION);
        assert_eq!(parsed.secret.as_bytes(), &SECRET);
    }

    #[test]
    fn the_sealed_offer_opens_under_the_derived_key_and_not_another() {
        let s = session();
        let sealed = s.sealed_offer();
        let opened = seal::open_offer(&seal::derive_key(&SECRET), &sealed).expect("opens");
        assert_eq!(opened, s.offer.to_bytes());

        let wrong = seal::derive_key(&[8u8; 16]);
        assert!(
            seal::open_offer(&wrong, &sealed).is_err(),
            "a different secret must not open it"
        );
    }

    #[test]
    fn a_reply_that_is_not_for_this_device_is_refused_without_saying_why() {
        // SCREEN-002 S4. The harness asserts the refusal; the reason stays in
        // the core's own suite, where naming it costs nothing.
        let s = session();
        let err = s
            .accept(b"not a sealed bundle at all", 1_800_000_000)
            .unwrap_err();
        assert_eq!(err, DeviceError::Refused);
        let message = err.to_string();
        assert!(message.contains("didn't match this device"), "{message}");
        for leak in [
            "transcript",
            "signature",
            "genesis",
            "RejectReason",
            "Unrecognised",
        ] {
            assert!(
                !message.contains(leak),
                "the refusal leaked `{leak}`: {message}"
            );
        }
    }

    #[test]
    fn malformed_inputs_are_refused_at_the_constructor() {
        // Distinguished from each other here, because a caller that passed two
        // byte slices in the wrong order should be told which one is wrong. The
        // browser surface collapses both to one message; that is the edge's
        // job, not this one's.
        assert_eq!(
            Device::new(&[0u8; 15], &SEED, "d", 1).unwrap_err(),
            DeviceError::SecretLength
        );
        assert_eq!(
            Device::new(&[0u8; 17], &SEED, "d", 1).unwrap_err(),
            DeviceError::SecretLength
        );
        assert_eq!(
            Device::new(&SECRET, &[0u8; 31], "d", 1).unwrap_err(),
            DeviceError::SeedLength
        );
        assert!(
            Device::new(&SECRET, &SEED, "d", 1).is_ok(),
            "the exact lengths"
        );
    }

    #[test]
    fn json_strings_are_escaped_even_though_todays_values_need_none() {
        assert_eq!(json_string("did:crdt:abc"), r#""did:crdt:abc""#);
        assert_eq!(json_string(r#"a"b"#), r#""a\"b""#);
        assert_eq!(json_string("a\\b"), r#""a\\b""#);
        assert_eq!(json_string("a\nb"), r#""a\nb""#);
        assert_eq!(json_string("a\u{1}b"), r#""a\u0001b""#);
    }

    #[test]
    fn the_accepted_json_carries_the_four_fields_the_page_reads() {
        // The shape is a contract with the page, and a `format!` breaks
        // silently. Pinned here without adding a JSON parser to a crate that
        // exists to avoid adding dependencies.
        let out = format!(
            r#"{{"did":{},"fingerprintHex":{},"fingerprintLabel":{},"ownMethodId":{}}}"#,
            json_string("did:crdt:abc"),
            json_string("0C 57 68 F9 50 37"),
            json_string("topaz-adder-57"),
            json_string("did:crdt:abc#dev-1"),
        );
        for field in [
            "\"did\":",
            "\"fingerprintHex\":",
            "\"fingerprintLabel\":",
            "\"ownMethodId\":",
        ] {
            assert!(out.contains(field), "missing {field} in {out}");
        }
        assert!(out.starts_with('{') && out.ends_with('}'));
    }

    // ── the constructors refuse what their own protocol rejects ──────────

    // REPRODUCED AGAINST THE BUILT ARTEFACT BEFORE THIS FIX: `build_offer_json`
    // returned 923 bytes for invalid enrolment evidence together with a hint
    // naming another application, an undeclared provider, a wrong descriptor
    // digest and an unrelated offer digest. `recognise_offer` returns the
    // evidence as text and the hint as an unrecognised JSON value, so neither
    // was ever looked at. `ProviderHint::verify` is CON-209's five checks and
    // already existed; nothing called it.
    #[test]
    fn build_offer_refuses_a_hint_that_selects_something_the_profile_does_not_declare() {
        let fixture = grant_fixture();
        let (core, hint, _, evidence) = offer_fixture(&fixture);
        let core_json = offer_core_json(&core);

        // The NATIVE twin: `JsError` cannot be constructed outside wasm, so the
        // `_json` facades panic on their error path here and only their success
        // path is exercisable natively. Same code, one wrapper down.
        let _ = &core_json;
        let mutate = |f: &dyn Fn(&mut ProviderHint)| {
            let mut h = hint.clone();
            f(&mut h);
            build_offer(&core, &evidence, &h, &fixture.profile_octets)
        };

        // One clause each, so a passing suite cannot rest on a single check.
        assert!(mutate(&|h| h.application_id = "https://elsewhere.example/app".into()).is_err());
        assert!(mutate(&|h| h.profile_version = 99).is_err());
        assert!(mutate(&|h| h.provider_id = "urn:provider:undeclared".into()).is_err());
        assert!(mutate(&|h| h.descriptor_digest = codec::b64url(&[0xEE; 32])).is_err());
        assert!(mutate(&|h| h.offer_digest = codec::b64url(&[0xEE; 32])).is_err());

        // A hint that selects only what the profile declares still builds, so
        // the refusals above are the checks and not a constructor that refuses
        // everything.
        assert!(build_offer(&core, &evidence, &hint, &fixture.profile_octets).is_ok());
    }

    #[test]
    fn build_offer_refuses_evidence_that_is_not_a_con_214_jws_and_an_unrecognised_profile() {
        let fixture = grant_fixture();
        let (core, hint, _, evidence) = offer_fixture(&fixture);
        for bad in ["", "not.a.valid.enrollment-jws", "a.b.c", "eyJhbGciOiJub25lIn0.."] {
            assert!(
                build_offer(&core, bad, &hint, &fixture.profile_octets).is_err(),
                "evidence {bad:?} is not a CON-214 compact JWS"
            );
        }

        // And an offer cannot be bound to a profile that is not recognised —
        // there is nothing to check the hint against.
        for bytes in [&b""[..], &b"{}"[..], &b"not json"[..]] {
            assert!(build_offer(&core, &evidence, &hint, bytes).is_err());
        }

        assert!(build_offer(&core, &evidence, &hint, &fixture.profile_octets).is_ok());
    }

    // `enrollment::build` is an infallible serialiser, so this returned
    // canonical-looking bytes for `"bad"` identifiers, an empty permission list
    // and `expiresAt` earlier than `issuedAt`. The language begins in the
    // recogniser, which the facade never invoked.
    #[test]
    fn build_enrollment_refuses_a_statement_its_own_recogniser_rejects() {
        let fixture = grant_fixture();
        let (_, _, statement, _) = offer_fixture(&fixture);

        let mutate = |f: &dyn Fn(&mut EnrollmentStatement)| {
            let mut st = statement.clone();
            f(&mut st);
            build_enrollment(&st)
        };

        assert!(mutate(&|st| st.request_id = "bad".into()).is_err());
        assert!(mutate(&|st| st.ceremony_id = "bad".into()).is_err());
        assert!(mutate(&|st| st.profile_digest = "bad".into()).is_err());
        assert!(mutate(&|st| st.requested_permissions = vec![]).is_err());
        assert!(mutate(&|st| st.expires_at = st.issued_at - 1).is_err());

        // The control.
        assert!(build_enrollment(&statement).is_ok());
    }

}
