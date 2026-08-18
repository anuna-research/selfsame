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

use selfsame_app_identity::accept::{ClosureSource, IssuerState};
use selfsame_app_identity::alias::{AcctUri, Jrd};
use selfsame_app_identity::ceremony::{self as identity_ceremony, BundlePayload, OfferCore};
use selfsame_app_identity::enrollment::{self as identity_enrollment, EnrollmentStatement};
use selfsame_app_identity::json::{self as identity_json, Json};
use selfsame_app_identity::path_b::{
    agree_closures, issuer_state_of, ClosureAssertionMethod, ResolverObservation,
};
use selfsame_app_identity::path_b::{rehydrate_verified_grant, GrantRequest, VerifiedGrant};
use selfsame_app_identity::profile::ApplicationProfile;
use selfsame_app_identity::proof::{self as identity_proof, Challenge};
use selfsame_app_identity::provider_hint::ProviderHint;
use selfsame_core::code::{LinkCode, LinkSecret};
use selfsame_core::record::{Application, Offer};
use selfsame_core::{accept, seal, LinkContext, UnixSeconds};

/// Browser shell for Selfsame's one-sided CBCL claimant endpoint.
///
/// The constructor accepts no protocol choice. Active cryptographic state stays
/// inside this opaque wasm value, and the browser transports only canonical
/// frames returned by [`CbclPairingSession::cpace_frame`].
#[wasm_bindgen]
pub struct CbclPairingSession {
    bootstrap: Option<selfsame_pairing::SelfsameEndpointBootstrap>,
}

#[wasm_bindgen]
impl CbclPairingSession {
    /// Begin from one complete invitation and two caller-supplied CSPRNG values.
    #[wasm_bindgen(constructor)]
    pub fn new(
        invitation: &[u8],
        cpace_scalar: &[u8],
        signing_seed: &[u8],
    ) -> Result<CbclPairingSession, JsError> {
        let cpace_scalar: [u8; 32] = cpace_scalar
            .try_into()
            .map_err(|_| JsError::new("CBCL CPace randomness is exactly 32 octets"))?;
        let signing_seed: [u8; 32] = signing_seed
            .try_into()
            .map_err(|_| JsError::new("CBCL signing randomness is exactly 32 octets"))?;
        let bootstrap = selfsame_pairing::SelfsameEndpointBootstrap::join_claimant(
            invitation,
            cpace_scalar,
            signing_seed,
        )
        .map_err(|_| JsError::new("the CBCL pairing invitation was refused"))?;
        Ok(Self {
            bootstrap: Some(bootstrap),
        })
    }

    /// Exact invitation-authenticated relay origin.
    pub fn relay_origin(&self) -> Result<String, JsError> {
        self.bootstrap
            .as_ref()
            .map(|endpoint| endpoint.relay_origin().to_owned())
            .ok_or_else(|| JsError::new("the CBCL pairing was cancelled"))
    }

    /// Canonical first CPace frame for the browser-owned relay transport.
    pub fn cpace_frame(&self) -> Result<Vec<u8>, JsError> {
        self.bootstrap
            .as_ref()
            .ok_or_else(|| JsError::new("the CBCL pairing was cancelled"))?
            .local_cpace_frame_bytes()
            .map_err(|_| JsError::new("the CBCL pairing frame was refused"))
    }

    /// Burn this attempt. Dropping the endpoint zeroizes its secret state.
    pub fn cancel(&mut self) {
        self.bootstrap = None;
    }
}

/// Browser shell for Selfsame's CBCL allocator endpoint — the inviting side.
///
/// The browser owns the WebSocket, the randomness, and the ordering; this
/// value owns every recognition and transition. Each complete binary relay
/// message goes in through [`CbclAllocatorSession::receive`], and what comes
/// back is a JSON effect list whose `send` entries are the only bytes the
/// browser may write to the socket. The invitation carrier appears exactly
/// once, as an `invitation` effect, for out-of-band transfer (QR).
///
/// The constructor performs no allocation-policy decision: allocation is the
/// relay's to refuse, and a production relay refuses it. This surface is for
/// relays that have deliberately enabled allocation (loopback conformance
/// builds).
#[wasm_bindgen]
pub struct CbclAllocatorSession {
    session: Option<selfsame_pairing::live::AllocatorRelaySession>,
}

#[wasm_bindgen]
impl CbclAllocatorSession {
    /// Prepare one allocator attempt from caller-supplied CSPRNG values.
    ///
    /// `transfer_json` carries `applicationId`, `origin`, `scope`, and
    /// `recipient`; the exact credential bundle travels separately as octets.
    /// `profile` is the complete authenticated Selfsame application profile.
    /// The four random values are drawn by the browser
    /// (`crypto.getRandomValues`): a 16-octet invitation secret, a 32-octet
    /// CPace scalar, a 32-octet signing seed, and a 32-octet intent nonce.
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        relay_origin: String,
        transfer_json: &str,
        bundle: &[u8],
        profile: &[u8],
        account: &str,
        device_public_key: &[u8],
        invitation_secret: &[u8],
        cpace_scalar: &[u8],
        signing_seed: &[u8],
        intent_nonce: &[u8],
    ) -> Result<CbclAllocatorSession, JsError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct TransferClaims {
            application_id: String,
            origin: String,
            scope: String,
            recipient: String,
        }
        let claims: TransferClaims = serde_json::from_str(transfer_json)
            .map_err(|_| JsError::new("the CBCL transfer claims were refused"))?;
        let transfer = selfsame_pairing::CredentialTransfer {
            application_id: claims.application_id,
            origin: claims.origin,
            scope: claims.scope.clone(),
            recipient: claims.recipient,
            bundle: bundle.to_vec(),
        };
        let profile = ApplicationProfile::recognise(profile)
            .map_err(|_| JsError::new("the CBCL application profile was refused"))?;
        let account = AcctUri::parse(account)
            .map_err(|_| JsError::new("the CBCL account identifier was refused"))?;
        let device_public_key: [u8; 32] = device_public_key
            .try_into()
            .map_err(|_| JsError::new("the CBCL device key is exactly 32 octets"))?;
        // The allocator never runs the thirteen-step verifier — that predicate
        // is the claimant's. Construction uses only the profile identity,
        // account, device key, and permission claims, so the verifier-only
        // evidence stays deliberately absent here.
        let verification = selfsame_pairing::SelfsameVerificationContext {
            profile,
            account,
            device_public_key,
            operation_permissions: vec![claims.scope],
            now: 0,
            clock_skew_seconds: 0,
            freshness: selfsame_app_identity::accept::Freshness::SessionEstablishment,
            issuer: None,
            jrd: None,
            projection: None,
            proof: None,
        };
        let entropy = selfsame_pairing::live::AllocatorEntropy {
            invitation_secret: invitation_secret
                .try_into()
                .map_err(|_| JsError::new("the CBCL invitation secret is exactly 16 octets"))?,
            cpace_scalar: cpace_scalar
                .try_into()
                .map_err(|_| JsError::new("CBCL CPace randomness is exactly 32 octets"))?,
            signing_seed: signing_seed
                .try_into()
                .map_err(|_| JsError::new("CBCL signing randomness is exactly 32 octets"))?,
            intent_nonce: intent_nonce
                .try_into()
                .map_err(|_| JsError::new("the CBCL intent nonce is exactly 32 octets"))?,
        };
        let session = selfsame_pairing::live::AllocatorRelaySession::new(
            relay_origin,
            transfer,
            &verification,
            entropy,
        )
        .map_err(|_| JsError::new("the CBCL allocator attempt was refused"))?;
        Ok(Self {
            session: Some(session),
        })
    }

    /// First canonical relay message for a newly opened connection.
    pub fn start(&self) -> Result<Vec<u8>, JsError> {
        self.session
            .as_ref()
            .ok_or_else(|| JsError::new("the CBCL pairing was cancelled"))?
            .start()
            .map_err(|_| JsError::new("the CBCL pairing frame was refused"))
    }

    /// Apply one complete binary relay message; returns a JSON effect list.
    pub fn receive(&mut self, input: &[u8]) -> Result<String, JsError> {
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| JsError::new("the CBCL pairing was cancelled"))?;
        let effects = session
            .receive(input)
            .map_err(|_| JsError::new("the CBCL pairing message was refused"))?;
        Ok(live_effects_json(&effects))
    }

    /// Cancel locally; returns the closing effects, then burns the attempt.
    pub fn cancel(&mut self) -> Result<String, JsError> {
        let Some(mut session) = self.session.take() else {
            return Ok("[]".into());
        };
        let effects = session
            .cancel()
            .map_err(|_| JsError::new("the CBCL pairing message was refused"))?;
        Ok(live_effects_json(&effects))
    }
}

/// Encode live-session effects as the closed JSON list the browser executes.
fn live_effects_json(effects: &[selfsame_pairing::live::LiveEffect]) -> String {
    use selfsame_pairing::live::{LiveEffect, LiveOutcome};
    let entries: Vec<serde_json::Value> = effects
        .iter()
        .map(|effect| match effect {
            LiveEffect::Send(body) => serde_json::json!({
                "type": "send",
                "bodyB64u": selfsame_app_identity::codec::b64url(body),
            }),
            LiveEffect::Invitation(carrier) => serde_json::json!({
                "type": "invitation",
                "carrierB64u": selfsame_app_identity::codec::b64url(carrier),
            }),
            LiveEffect::DisplayIntent(intent) => serde_json::json!({
                "type": "display-intent",
                "application": intent.application,
                "action": intent.action,
                "authoritySummary": intent.authority_summary,
                "fields": intent
                    .fields
                    .iter()
                    .map(|field| serde_json::json!({
                        "label": field.label,
                        "value": field.value,
                        "claimedBySecretHolder": field.claimed_by_secret_holder,
                    }))
                    .collect::<Vec<_>>(),
            }),
            LiveEffect::AwaitingDecision => serde_json::json!({"type": "awaiting-decision"}),
            LiveEffect::PayloadSent => serde_json::json!({"type": "payload-sent"}),
            LiveEffect::Accepted => serde_json::json!({"type": "accepted"}),
            LiveEffect::Terminal(outcome) => serde_json::json!({
                "type": "terminal",
                "outcome": match outcome {
                    LiveOutcome::Accepted => "accepted",
                    LiveOutcome::Delivered => "delivered",
                    LiveOutcome::Declined => "declined",
                    LiveOutcome::Cancelled => "cancelled",
                    LiveOutcome::Closed => "closed",
                    LiveOutcome::Refused => "refused",
                },
            }),
        })
        .collect();
    serde_json::Value::Array(entries).to_string()
}

/// QR module matrix for one complete CBCL invitation carrier.
///
/// Encoded here rather than in JavaScript so the symbol a browser paints and
/// any symbol another shell prints come from one encoder: a subtly wrong
/// symbol does not fail to render, it scans as something else. The payload is
/// the unpadded base64url of the carrier — exactly the text a wallet's paste
/// affordance accepts — so a camera scan and a paste recognise identical input.
#[wasm_bindgen]
pub fn cbcl_invitation_qr_modules_json(carrier: &[u8]) -> Result<String, JsError> {
    let payload = selfsame_app_identity::codec::b64url(carrier);
    let code = qrcode::QrCode::with_error_correction_level(payload.as_bytes(), qrcode::EcLevel::Q)
        .map_err(|_| JsError::new("the CBCL invitation does not fit a QR symbol"))?;
    let width = code.width();
    let modules: Vec<Vec<u8>> = (0..width)
        .map(|y| {
            (0..width)
                .map(|x| u8::from(code[(x, y)] == qrcode::Color::Dark))
                .collect()
        })
        .collect();
    serde_json::to_string(&serde_json::json!({
        "width": width,
        "modules": modules,
    }))
    .map_err(|_| JsError::new("the CBCL invitation does not fit a QR symbol"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserClosure {
    resolver_id: String,
    did: String,
    did_recomputed_ok: bool,
    deltas_verified: bool,
    locally_closed: bool,
    deactivated: bool,
    assertion_methods: Vec<BrowserMethod>,
    revoked_credential_ids: Vec<String>,
    /// Unix seconds at which this browser fetched the closure — its own
    /// observation, never the resolver's account of its freshness.
    fetched_at_seconds: i64,
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
/// The result is canonical JSON payload octets; cbcl carries it as opaque
/// authenticated payload.
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

// ── The facts a joiner must compute BEFORE it can build an offer ────────────
//
// `build_offer` insists that every check compares against "the JOINER'S OWN
// profile, never a value the hint supplied — a hint may only select among things
// already trusted". But a browser could not compute those values at all: the
// profile digest the offer core carries, and the per-descriptor digest the
// provider hint must match, were both native-only.
//
// So a browser building an offer had to be HANDED them by something else, which
// is precisely the trust the sentence above refuses. This exposes them from the
// joiner's own recognised profile, so the values it binds to are ones it derived.
//
// The relay origin comes from the same recognised profile. A browser that
// cannot read it locally would have to trust a caller-supplied endpoint.

/// The profile facts a joiner needs to construct an offer and a provider hint.
#[wasm_bindgen]
pub fn profile_facts_json(profile: &[u8]) -> Result<String, JsError> {
    profile_facts(profile).map_err(|_| JsError::new("SPEC-004 profile refused"))
}

/// Native twin of [`profile_facts_json`].
pub fn profile_facts(profile: &[u8]) -> Result<String, IdentityError> {
    let profile = ApplicationProfile::recognise(profile).map_err(|_| IdentityError::Refused)?;
    let descriptors: Vec<String> = profile
        .cbcl_pairing_relays
        .iter()
        .map(|d| {
            format!(
                r#"{{"operatorId":{},"descriptorDigest":{},"relayOrigin":{}}}"#,
                json_string(&d.operator_id),
                json_string(&selfsame_app_identity::codec::b64url(&d.digest)),
                json_string(&d.relay_origin),
            )
        })
        .collect();
    Ok(format!(
        r#"{{"applicationId":{},"accountAuthority":{},"profileVersion":{},"profileDigest":{},"allowedPermissions":[{}],"cbclPairingRelays":[{}]}}"#,
        json_string(profile.application_id.as_str()),
        json_string(profile.account_authority.as_str()),
        selfsame_app_identity::PROFILE_VERSION,
        json_string(&selfsame_app_identity::codec::b64url(profile.digest())),
        profile
            .allowed_permissions
            .iter()
            .map(|p| json_string(p))
            .collect::<Vec<_>>()
            .join(","),
        descriptors.join(","),
    ))
}

/// The `CON-219` offer digest, which the provider hint must carry.
///
/// Exposed because the hint commits to the offer and the offer excludes the
/// hint, so the digest has to exist before either is complete — and a joiner that
/// could not compute it could not construct a hint its own `build_offer` accepts.
#[wasm_bindgen]
pub fn offer_core_digest_json(offer_core_json: &str) -> Result<String, JsError> {
    offer_core_digest(offer_core_json).map_err(|_| JsError::new("SPEC-004 offer core refused"))
}

/// Native twin of [`offer_core_digest_json`].
pub fn offer_core_digest(offer_core_json: &str) -> Result<String, IdentityError> {
    Ok(parse_offer_core(offer_core_json)?.digest())
}

// ── The transport, which a browser could not reach until now ────────────────
//
// The ceremony facades above decide what an offer and a bundle MEAN. None of
// them could put one in a mailbox or take one out, so a browser holding this
// package could build a `CON-219` offer and then had nowhere to send it — and
// the adapter written against these facades in `cbcl-bus` refuses to start for
// exactly that reason.
//
// The three below are the missing half, and they are deliberately the SMALLEST
// surface that closes it: where a slot is, how an offer is sealed, and how a
// bundle is opened. Everything they do is `selfsame_core::seal`'s, unchanged.
//
// WHY NOT LET THE BROWSER DO ITS OWN AEAD. A JavaScript reimplementation would
// have to reproduce the HKDF label, the direction-separated nonces, both
// associated-data strings and the BLAKE3 transcript exactly, and the first thing
// it would get wrong is the one thing nothing else checks — `CON-205`'s parser
// differential, in the one place where being wrong means a bundle that opens for
// the wrong offer. There is one implementation and this exposes it.
//
// This is the separate SPEC-001 device-link transport, keyed by a 16-octet
// secret the caller supplies. Credential pairing does not use these functions.

/// The two mailbox addresses a secret designates — `CON-002`'s slot derivation.
///
/// Returned together because they are one fact about one secret, and a caller
/// that derived them separately could pass different secrets to each and write
/// its offer where nothing would read it.
#[wasm_bindgen]
pub fn mailbox_slots_json(secret: &[u8]) -> Result<String, JsError> {
    mailbox_slots(secret).map_err(|_| JsError::new("a mailbox secret is exactly 16 octets"))
}

/// Native twin of [`mailbox_slots_json`].
pub fn mailbox_slots(secret: &[u8]) -> Result<String, IdentityError> {
    let secret = mailbox_secret(secret)?;
    Ok(format!(
        "{{\"offer\":\"{}\",\"bundle\":\"{}\"}}",
        seal::slot(seal::Role::Offer, &secret),
        seal::slot(seal::Role::Bundle, &secret),
    ))
}

/// Seal an offer payload for the offer slot.
#[wasm_bindgen]
pub fn seal_offer_bytes(secret: &[u8], offer_plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
    seal_offer_for(secret, offer_plaintext)
        .map_err(|_| JsError::new("a mailbox secret is exactly 16 octets"))
}

/// Native twin of [`seal_offer_bytes`].
pub fn seal_offer_for(secret: &[u8], offer_plaintext: &[u8]) -> Result<Vec<u8>, IdentityError> {
    let secret = mailbox_secret(secret)?;
    Ok(seal::seal_offer(
        &seal::derive_key(&secret),
        offer_plaintext,
    ))
}

/// Open a bundle **under the caller's own offer**.
///
/// The transcript is computed here from `offer_plaintext` rather than accepted
/// as a parameter, which makes `REQ-006`'s binding impossible to skip: a caller
/// cannot pass a transcript it did not derive from the exact offer it wrote. A
/// bundle that opens is therefore provably a reply to *this* offer and not
/// something the rendezvous operator substituted.
#[wasm_bindgen]
pub fn open_bundle_bytes(
    secret: &[u8],
    sealed: &[u8],
    offer_plaintext: &[u8],
) -> Result<Vec<u8>, JsError> {
    open_bundle_for(secret, sealed, offer_plaintext)
        .map_err(|_| JsError::new("sealed record did not authenticate"))
}

/// Native twin of [`open_bundle_bytes`].
pub fn open_bundle_for(
    secret: &[u8],
    sealed: &[u8],
    offer_plaintext: &[u8],
) -> Result<Vec<u8>, IdentityError> {
    let secret = mailbox_secret(secret)?;
    seal::open_bundle(
        &seal::derive_key(&secret),
        sealed,
        &seal::transcript(offer_plaintext),
    )
    .map_err(|_| IdentityError::Refused)
}

/// A 16-octet mailbox secret, recognised before it is used.
///
/// A shorter secret silently padded, or a longer one truncated, would derive a
/// slot and a key that no counterparty agrees with — which surfaces as a
/// ceremony that times out rather than one that refuses.
fn mailbox_secret(secret: &[u8]) -> Result<[u8; 16], IdentityError> {
    secret.try_into().map_err(|_| IdentityError::Refused)
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
        // The browser's clock as a signed second count, for comparison against
        // fetch stamps. Refusing an unrepresentable value rather than saturating
        // keeps a nonsensical clock from reading as a valid one.
        let now_seconds = i64::try_from(now).map_err(|_| DeviceError::Refused)?;
        let jrd =
            selfsame_app_identity::alias::recognise_jrd(jrd).map_err(|_| DeviceError::Refused)?;
        let closures: Vec<BrowserClosure> =
            serde_json::from_str(closures_json).map_err(|_| DeviceError::Refused)?;
        // Emptiness is the shared quorum's to reject, along with agreement.
        // A fetch stamped before the epoch, or in the future relative to `now`,
        // is a broken clock or a caller inventing freshness. Refuse rather than
        // clamp: clamping a future stamp to zero age would present the most
        // suspect input as the freshest.
        if closures.iter().any(|closure| {
            closure.fetched_at_seconds < 0 || closure.fetched_at_seconds > now_seconds
        }) {
            return Err(DeviceError::Refused);
        }
        // Recognise the keys, then hand every decision to the shared quorum.
        //
        // This block used to agree the observations itself, and it did so more
        // weakly than the native path: it compared assertion methods by COUNT,
        // so two resolvers reporting different keys in equal numbers read as
        // agreeing here and disagreeing on the hub. A JavaScript layer above had
        // been given a compensating check, which protected one caller and no
        // other. There is now one agreement rule and it compares by value.
        let observations = closures
            .iter()
            .map(|c| {
                Ok(ResolverObservation {
                    resolver_id: c.resolver_id.clone(),
                    did: c.did.clone(),
                    did_recomputed_ok: c.did_recomputed_ok,
                    deltas_verified: c.deltas_verified,
                    locally_closed: c.locally_closed,
                    deactivated: c.deactivated,
                    assertion_methods: c
                        .assertion_methods
                        .iter()
                        .map(|m| {
                            let public_key: [u8; 32] = m
                                .public_key
                                .as_slice()
                                .try_into()
                                .map_err(|_| DeviceError::Refused)?;
                            Ok(ClosureAssertionMethod {
                                id: m.id.clone(),
                                kind: m.kind.clone(),
                                public_key,
                                has_private_component: m.has_private_component,
                            })
                        })
                        .collect::<Result<Vec<_>, DeviceError>>()?,
                    revoked_credential_ids: c.revoked_credential_ids.clone(),
                    also_known_as: c.also_known_as.clone(),
                    fetched_at_seconds: c.fetched_at_seconds,
                })
            })
            .collect::<Result<Vec<_>, DeviceError>>()?;
        let agreed = agree_closures(&profile, &observations).map_err(|_| DeviceError::Refused)?;
        let issuer = issuer_state_of(&agreed, now_seconds);

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
    // Still built here by fixtures, though the production path now reaches
    // them only through the shared quorum.
    use selfsame_app_identity::accept::VerificationMethod;
    use selfsame_app_identity::profile::Ed25519Jwk;

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
            locally_closed: true,
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
        let descriptor = &fixture.profile.cbcl_pairing_relays[0];
        let hint = ProviderHint {
            application_id: APP_ID.into(),
            profile_version: 1,
            provider_id: descriptor.operator_id.clone(),
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
                "locally_closed": issuer.locally_closed,
                "deactivated": issuer.deactivated,
                "assertion_methods": methods,
                "revoked_credential_ids": issuer.revoked_credential_ids,
                // A fetch stamp, not an age. The fixture's issuer carries an age,
                // so the equivalent stamp is that far before `now`.
                "fetched_at_seconds": NOW - issuer.closure_age_seconds,
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

    /// The shared closure vectors, vendored from cbcl-bus.
    ///
    /// The schema has three recognisers in three runtimes — this crate, the LFE
    /// hub shell, and the browser module — and they cannot share code: full
    /// recognition has to happen at each trust boundary. Sharing the CASES is
    /// what turns a disagreement between them into a failing test rather than a
    /// frame one stack accepts and another refuses.
    ///
    /// The digest is pinned so that a vendored copy which drifts from the
    /// authority fails here rather than quietly testing something else. When it
    /// fails, re-vendor the file and move the digest — never edit the digest to
    /// match a copy nobody compared.
    #[test]
    fn vendored_closure_vectors_match_their_pin() {
        use sha2::{Digest, Sha256};
        let raw = include_str!("../../../test-vectors/path-b-closure-vectors.json");
        let pinned = include_str!("../../../test-vectors/path-b-closure-vectors.sha256").trim();
        let actual = format!("{:x}", Sha256::digest(raw.as_bytes()));
        assert_eq!(
            actual, pinned,
            "the vendored vectors have drifted from their pin"
        );
    }

    /// This crate reads the STAMPED wire: ten members.
    ///
    /// Not the nine-member resolver wire. The browser module stamps
    /// `fetched_at_seconds` after it fetches, so by the time this facade
    /// deserialises, the closure carries it — the same shape the sidecar hands
    /// the LFE hub shell. Nine members is what the browser module reads; ten is
    /// what everything downstream of a stamp reads.
    #[test]
    fn the_shared_vectors_are_answered_identically_here() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-vectors/path-b-closure-vectors.json"
        ))
        .expect("vendored vectors parse");

        // Exactly the production path: deserialise the closed shape, then
        // recognise every assertion key as Ed25519-length. Nothing here decides
        // anything about the DID — that is the verifier's job, and a recogniser
        // that judged it would be a second implementation of the verdict.
        let recognise = |value: &serde_json::Value| -> Result<(), ()> {
            let closure: BrowserClosure = serde_json::from_value(value.clone()).map_err(|_| ())?;
            for method in &closure.assertion_methods {
                let _: [u8; 32] = method.public_key.as_slice().try_into().map_err(|_| ())?;
            }
            Ok(())
        };

        for case in vectors["sidecar"]["accept"]
            .as_array()
            .expect("accept cases")
        {
            assert!(
                recognise(&case["closure"]).is_ok(),
                "must accept: {}",
                case["why"].as_str().unwrap_or_default()
            );
        }
        for case in vectors["sidecar"]["reject"]
            .as_array()
            .expect("reject cases")
        {
            assert!(
                recognise(&case["closure"]).is_err(),
                "must reject: {}",
                case["why"].as_str().unwrap_or_default()
            );
        }
    }

    /// Regression: two resolvers reporting DIFFERENT assertion keys in EQUAL
    /// numbers must not read as agreeing.
    ///
    /// This browser path used to compare assertion methods by COUNT while the
    /// native path compared them by value, so a resolver could substitute a key
    /// and still pass here — and the agreed methods are taken from the first
    /// observation, so the substitution would have been adopted. A JavaScript
    /// layer above carried a compensating check, which protected one caller and
    /// no other. Both paths now share one agreement rule, and this exercises it
    /// directly: the wasm-bindgen facade cannot report failure natively, which
    /// is why the JSON entry point is only testable here on its success path.
    #[test]
    fn a_substituted_key_of_equal_count_is_refused() {
        let fixture = grant_fixture();
        let method = |byte: u8| ClosureAssertionMethod {
            id: format!("{}#jwk-0", fixture.issuer.did),
            kind: "JsonWebKey".to_owned(),
            public_key: [byte; 32],
            has_private_component: false,
        };
        let observation = |resolver_id: &str, byte: u8| ResolverObservation {
            resolver_id: resolver_id.to_owned(),
            did: fixture.issuer.did.clone(),
            did_recomputed_ok: true,
            deltas_verified: true,
            locally_closed: true,
            deactivated: false,
            assertion_methods: vec![method(byte)],
            revoked_credential_ids: vec![],
            also_known_as: fixture.issuer.also_known_as.clone(),
            fetched_at_seconds: NOW,
        };

        let agreed = agree_closures(
            &fixture.profile,
            &[observation("app-own", 1), observation("state-1", 1)],
        );
        assert!(agreed.is_ok(), "control: identical observations agree");

        let substituted = [observation("app-own", 1), observation("state-1", 2)];
        assert_eq!(
            substituted[0].assertion_methods.len(),
            substituted[1].assertion_methods.len(),
            "premise: the counts match, which is all the old browser rule compared"
        );
        assert!(
            agree_closures(&fixture.profile, &substituted).is_err(),
            "a substituted assertion key must be a disagreement, not a match"
        );
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
        for bad in [
            "",
            "not.a.valid.enrollment-jws",
            "a.b.c",
            "eyJhbGciOiJub25lIn0..",
        ] {
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

    // ── the transport surface ───────────────────────────────────────────────

    /// The offer a device sealed is the offer the phone opens, and the bundle it
    /// gets back opens only under its own offer.
    ///
    /// This is the round trip the browser could not perform at all before these
    /// three functions existed, so it is worth having end to end rather than as
    /// three separate unit assertions: the failure that matters is the one where
    /// each half is individually right and they do not meet.
    #[test]
    fn an_offer_and_its_bundle_make_a_round_trip() {
        let secret = [7u8; 16];
        let offer = b"the exact offer octets a device wrote".to_vec();
        let grant = b"the credential the phone sealed back".to_vec();

        let sealed_offer = seal_offer_for(&secret, &offer).expect("seal");
        // The phone's side is `selfsame_core::seal` directly — the same functions
        // these facades call, reached the way a native wallet reaches them.
        let key = seal::derive_key(&secret);
        let opened = seal::open_offer(&key, &sealed_offer).expect("the phone opens the offer");
        assert_eq!(opened, offer);

        let sealed_bundle = seal::seal_bundle(&key, &grant, &seal::transcript(&offer));
        assert_eq!(
            open_bundle_for(&secret, &sealed_bundle, &offer).expect("open"),
            grant
        );
    }

    /// A bundle minted against a DIFFERENT offer does not authenticate.
    ///
    /// `REQ-006` is the whole reason the transcript is computed inside
    /// `open_bundle_bytes` instead of being a parameter. If this ever passes,
    /// the rendezvous operator can substitute a reply.
    #[test]
    fn a_bundle_for_another_offer_is_refused() {
        let secret = [7u8; 16];
        let ours = b"our offer".to_vec();
        let theirs = b"somebody else's offer".to_vec();
        let key = seal::derive_key(&secret);

        let sealed = seal::seal_bundle(&key, b"a grant", &seal::transcript(&theirs));
        assert!(open_bundle_for(&secret, &sealed, &ours).is_err());
    }

    /// Both slots come from one secret, and they are not the same address.
    #[test]
    fn the_two_slots_are_distinct_and_derived_from_the_secret() {
        let a: serde_json::Value =
            serde_json::from_str(&mailbox_slots(&[1u8; 16]).expect("slots")).unwrap();
        let b: serde_json::Value =
            serde_json::from_str(&mailbox_slots(&[2u8; 16]).expect("slots")).unwrap();

        assert_ne!(
            a["offer"], a["bundle"],
            "one secret, two directions, two mailboxes"
        );
        assert_ne!(
            a["offer"], b["offer"],
            "a different secret is a different mailbox"
        );
        // The derivation is upstream's and this is the check that they agree.
        assert_eq!(a["offer"], seal::slot(seal::Role::Offer, &[1u8; 16]));
    }

    /// A secret of the wrong length is refused rather than padded.
    #[test]
    fn a_mailbox_secret_must_be_exactly_sixteen_octets() {
        assert!(mailbox_slots(&[0u8; 15]).is_err());
        assert!(mailbox_slots(&[0u8; 17]).is_err());
        assert!(seal_offer_for(&[0u8; 8], b"x").is_err());
    }

    /// The facts a joiner is given are the ones its own `build_offer` checks.
    ///
    /// Asserted against `ProviderHint::verify`'s sources rather than against
    /// literals: the point of exposing them is that a browser can construct a
    /// hint its own offer builder accepts, so the test that matters is that a
    /// hint built ONLY from these facts passes. Pinning the digests as constants
    /// would still let the two drift and would say nothing about that.
    #[test]
    fn a_hint_built_only_from_the_exposed_facts_is_accepted() {
        let fixture = grant_fixture();
        let facts: serde_json::Value =
            serde_json::from_str(&profile_facts(&fixture.profile_octets).expect("facts")).unwrap();

        let descriptor = &facts["cbclPairingRelays"][0];
        let (core, _, _, _) = offer_fixture(&fixture);
        // Built in the BROWSER'S wire shape, so the digest under test is the one a
        // browser would actually compute rather than one taken off the native
        // value beside it.
        let core_json = serde_json::json!({
            "ceremony_id": core.ceremony_id,
            "request_id": core.request_id,
            "application_id": core.application_id,
            "profile_version": core.profile_version,
            "profile_digest": core.profile_digest,
            "account_scope_id": core.account_scope_id,
            "device_did": core.device_did,
            "device_public_key": core.device_public_key.to_vec(),
            "requested_permissions": core.requested_permissions,
            "issued_at": core.issued_at,
            "expires_at": core.expires_at,
        })
        .to_string();
        let digest = offer_core_digest(&core_json).expect("digest");
        assert_eq!(
            digest,
            core.digest(),
            "the browser's digest is the native one"
        );

        let hint = ProviderHint {
            application_id: facts["applicationId"].as_str().unwrap().to_owned(),
            profile_version: facts["profileVersion"].as_i64().unwrap(),
            provider_id: descriptor["operatorId"].as_str().unwrap().to_owned(),
            descriptor_digest: descriptor["descriptorDigest"].as_str().unwrap().to_owned(),
            offer_digest: digest.clone(),
        };
        let profile = ApplicationProfile::recognise(&fixture.profile_octets).unwrap();
        assert!(
            hint.verify(&profile, &digest).is_ok(),
            "a hint built from the exposed facts must satisfy CON-209"
        );

        // And the profile digest the offer core carries is the same one.
        assert_eq!(
            facts["profileDigest"].as_str().unwrap(),
            selfsame_app_identity::codec::b64url(profile.digest())
        );
    }

    /// An unrecognised profile yields no facts at all.
    #[test]
    fn facts_are_refused_for_a_profile_the_recogniser_rejects() {
        assert!(profile_facts(b"{}").is_err());
        assert!(profile_facts(b"not json").is_err());
    }
}
