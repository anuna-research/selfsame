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
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use selfsame_app_identity::accept::{ClosureSource, IssuerState};
use selfsame_app_identity::alias::{AcctUri, Jrd};
use selfsame_app_identity::ceremony::{self as identity_ceremony, BundlePayload, OfferCore};
use selfsame_app_identity::enrollment::{self as identity_enrollment, EnrollmentStatement};
use selfsame_app_identity::json::{self as identity_json, Json};
use selfsame_app_identity::path_b::{
    agree_closures, issuer_state_of, replay_resolver_closure, verify_inactive_staging,
    ClosureAssertionMethod, InactiveStagedGrant, ResolverObservation,
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
                "application": intent.application(),
                "action": intent.action(),
                "authoritySummary": intent.authority_summary(),
                "fields": intent
                    .fields()
                    .iter()
                    .map(|field| serde_json::json!({
                        "label": field.label(),
                        "value": field.value(),
                        "claimedBySecretHolder": field.claimed_by_secret_holder(),
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

const V2_ALLOCATOR_CHECKPOINT_INFO: &[u8] =
    b"cbcl-chat credential/v2 allocator checkpoint wrapping v1";

mod credential_v2_closure;
pub use credential_v2_closure::CredentialV2BrowserAllocatorClosureInspection;

/// Distinct browser allocator for standalone credential/v2 pairing.
///
/// This surface cannot select credential/v1. It returns a closed JSON effect
/// list consumed by `credential-v2-allocator.mjs`; checkpoint effects are
/// acknowledged through [`CredentialV2BrowserAllocatorSession::checkpoint_persisted`]
/// before the Rust session releases any cached relay frame.
#[wasm_bindgen]
pub struct CredentialV2BrowserAllocatorSession {
    session: Option<cbcl_pairing::credential_v2::CredentialV2AllocatorSession>,
    profile: ApplicationProfile,
    request_id: [u8; 32],
    intent_nonce: [u8; 32],
    carrier_ceremony_id: [u8; 32],
    expected_allocator_key: [u8; 32],
    transcript_hash: Option<[u8; 64]>,
    prepared_offer_core: Option<Vec<u8>>,
    prepared_offer_digest: Option<[u8; 32]>,
    offer_kid: Option<String>,
    authority_status: Option<selfsame_pairing::credential_v2::CredentialV2AuthorityStatus>,
    authority_response: Option<Vec<u8>>,
    body_authority: selfsame_pairing::credential_v2::CredentialV2BodyAuthority,
    last_received_object: Option<cbcl_pairing::credential_v2::CredentialV2Object>,
}

#[wasm_bindgen]
impl CredentialV2BrowserAllocatorSession {
    /// Construct Full mode with independent 16-octet C and T from the shell CSPRNG.
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile: &[u8],
        relay_origin: String,
        mailbox_id: &[u8],
        carrier_ceremony_id: &[u8],
        carrier_nonce: &[u8],
        cpace_secret: &[u8],
        claim_token: &[u8],
        cpace_scalar: &[u8],
        request_id: &[u8],
        intent_nonce: &[u8],
        expected_allocator_key: &[u8],
        installation_seed: &[u8],
    ) -> Result<CredentialV2BrowserAllocatorSession, JsError> {
        Self::new_inner(
            profile,
            relay_origin,
            mailbox_id,
            carrier_ceremony_id,
            carrier_nonce,
            cpace_secret,
            claim_token,
            cpace_scalar,
            request_id,
            intent_nonce,
            expected_allocator_key,
            installation_seed,
            cbcl_pairing::credential_v2::CredentialV2AllocatorMode::Full,
        )
        .map_err(|error| JsError::new(&error))
    }

    /// Construct Manual mode. The presence position takes exactly four CSPRNG
    /// octets; only the shared word codec maps those bytes to the CPace secret.
    #[wasm_bindgen(js_name = new_manual)]
    #[allow(clippy::too_many_arguments)]
    pub fn new_manual(
        profile: &[u8],
        relay_origin: String,
        mailbox_id: &[u8],
        carrier_ceremony_id: &[u8],
        carrier_nonce: &[u8],
        manual_word_randomness: &[u8],
        claim_token: &[u8],
        cpace_scalar: &[u8],
        request_id: &[u8],
        intent_nonce: &[u8],
        expected_allocator_key: &[u8],
        installation_seed: &[u8],
    ) -> Result<CredentialV2BrowserAllocatorSession, JsError> {
        Self::new_inner(
            profile,
            relay_origin,
            mailbox_id,
            carrier_ceremony_id,
            carrier_nonce,
            manual_word_randomness,
            claim_token,
            cpace_scalar,
            request_id,
            intent_nonce,
            expected_allocator_key,
            installation_seed,
            cbcl_pairing::credential_v2::CredentialV2AllocatorMode::Manual,
        )
        .map_err(|error| JsError::new(&error))
    }

    /// Restore one authenticated checkpoint with an explicit exact mode and
    /// fresh shell CSPRNG scalar on every call. Peer-bound state retains its
    /// authenticated scalar and cached response instead of using the fresh one.
    #[wasm_bindgen(js_name = restore)]
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        profile: &[u8],
        carrier: &[u8],
        checkpoint: &[u8],
        generation: u64,
        request_id: &[u8],
        intent_nonce: &[u8],
        expected_allocator_key: &[u8],
        installation_seed: &[u8],
        now: u64,
        mode: String,
        fresh_cpace_scalar: &[u8],
    ) -> Result<CredentialV2BrowserAllocatorSession, JsError> {
        Self::restore_inner(
            profile,
            carrier,
            checkpoint,
            generation,
            request_id,
            intent_nonce,
            expected_allocator_key,
            installation_seed,
            now,
            mode,
            fresh_cpace_scalar,
        )
        .map_err(|error| JsError::new(&error))
    }

    /// Inspect authenticated saved state, including elapsed expiry, without
    /// restoring a live allocator or granting relay or issuance authority.
    #[wasm_bindgen(js_name = restore_for_closure)]
    #[allow(clippy::too_many_arguments)]
    pub fn restore_for_closure(
        profile: &[u8],
        carrier: &[u8],
        checkpoint: &[u8],
        generation: u64,
        request_id: &[u8],
        intent_nonce: &[u8],
        expected_allocator_key: &[u8],
        installation_seed: &[u8],
        now: u64,
        mode: String,
    ) -> Result<CredentialV2BrowserAllocatorClosureInspection, JsError> {
        CredentialV2BrowserAllocatorClosureInspection::restore_inner(
            profile,
            carrier,
            checkpoint,
            generation,
            request_id,
            intent_nonce,
            expected_allocator_key,
            installation_seed,
            now,
            mode,
        )
        .map_err(|error| JsError::new(&error))
    }

    /// Authenticated live bootstrap mode only; established and terminal state
    /// grants no mode or bootstrap capability. Never infer a mode from C.
    pub fn bootstrap_mode(&self) -> Option<String> {
        self.session
            .as_ref()
            .and_then(|session| session.bootstrap_mode())
            .map(|mode| {
                match mode {
                    cbcl_pairing::credential_v2::CredentialV2AllocatorMode::Full => "full",
                    cbcl_pairing::credential_v2::CredentialV2AllocatorMode::Manual => "manual",
                }
                .into()
            })
    }

    /// Private transfer only. Reconstructed from live core on each call, with
    /// exactly bootstrap/words JSON fields and no retained adapter string cache.
    /// The shell gates display on checkpoint/hub commits and the earlier deadline.
    pub fn manual_transfer_text(&self) -> Result<Option<String>, JsError> {
        self.manual_transfer_text_inner().map_err(JsError::new)
    }

    /// Return the restored endpoint phase, or `bootstrap` before Finished.
    pub fn restored_phase(&self) -> String {
        use cbcl_pairing::credential_v2::{CredentialV2AllocatorBootstrapPhase, CredentialV2Phase};
        if let Some(phase) = self
            .session
            .as_ref()
            .and_then(|session| session.bootstrap_phase())
        {
            return match phase {
                CredentialV2AllocatorBootstrapPhase::Allocated => "allocated",
                CredentialV2AllocatorBootstrapPhase::Claimed => "claimed",
                CredentialV2AllocatorBootstrapPhase::ShareSent => "share-sent",
                CredentialV2AllocatorBootstrapPhase::FinishedSent => "finished-sent",
            }
            .into();
        }
        match self
            .session
            .as_ref()
            .and_then(|session| session.endpoint_phase())
        {
            None => "bootstrap",
            Some(CredentialV2Phase::Begin) => "begin",
            Some(CredentialV2Phase::Offered) => "offered",
            Some(CredentialV2Phase::IntentApproved) => "intent-approved",
            Some(CredentialV2Phase::Prepared) => "prepared",
            Some(CredentialV2Phase::Confirmed) => "confirmed",
            Some(CredentialV2Phase::FinalApproved) => "final-approved",
            Some(CredentialV2Phase::PayloadSent) => "payload-sent",
            Some(CredentialV2Phase::Terminal) => "terminal",
            Some(_) => "unknown",
        }
        .into()
    }

    /// Reconstruct confidential scan material from this exact live core session.
    /// The caller releases it only after durable hub allocation and clears it at
    /// the earlier hub/relay deadline. Consumed T cannot be reconstructed here.
    pub fn handoff_text(&self) -> Result<Option<String>, JsError> {
        self.handoff_text_inner()
            .map_err(|error| JsError::new(&error))
    }

    /// Return the restored one-use presence code while the claim token remains
    /// sealed in the allocator bootstrap checkpoint.
    pub fn restored_presence_code(&self) -> Option<String> {
        self.session
            .as_ref()
            .and_then(|session| session.presence_code())
    }

    /// Re-validate and retain public hub offer facts needed by the browser
    /// shell after process restart. The sealed body authority remains the sole
    /// source for application decisions and payload display.
    #[allow(clippy::too_many_arguments)]
    pub fn restore_offer_context(
        &mut self,
        raw_carrier: &[u8],
        offer_core: &[u8],
        offer_core_digest: &[u8],
        pending_expires_at: u64,
        signed_offer: &[u8],
        authority_response: &[u8],
        authority_digest: &[u8],
        now: u64,
    ) -> Result<(), JsError> {
        self.restore_offer_context_inner(
            raw_carrier,
            offer_core,
            offer_core_digest,
            pending_expires_at,
            signed_offer,
            authority_response,
            authority_digest,
            now,
        )
        .map_err(|error| JsError::new(&error))
    }

    #[allow(clippy::too_many_arguments)]
    fn restore_offer_context_inner(
        &mut self,
        raw_carrier: &[u8],
        offer_core: &[u8],
        offer_core_digest: &[u8],
        pending_expires_at: u64,
        signed_offer: &[u8],
        authority_response: &[u8],
        authority_digest: &[u8],
        now: u64,
    ) -> Result<(), String> {
        if now >= pending_expires_at {
            return Err("the credential/v2 restored offer expired".into());
        }
        let carrier = cbcl_pairing::credential_v2::decode_carrier(raw_carrier)
            .map_err(|_| "the credential/v2 carrier was refused".to_owned())?;
        let supplied_digest: [u8; 32] =
            fixed_browser_bytes_inner(offer_core_digest, "offer-core digest")?;
        let supplied_authority_digest: [u8; 32] =
            fixed_browser_bytes_inner(authority_digest, "authority-status digest")?;
        let recognised =
            selfsame_pairing::credential_v2::recognise_signed_offer(&self.profile, signed_offer)
                .map_err(|_| "the credential/v2 signed offer was refused".to_owned())?;
        if carrier.carrier_ceremony_id() != &self.carrier_ceremony_id
            || carrier.application_context() != self.profile.application_id.as_str()
            || recognised.offer_core.as_slice() != offer_core
            || recognised.claims.offer_core_digest() != &supplied_digest
            || <[u8; 32]>::from(Sha256::digest(offer_core)) != supplied_digest
            || recognised.request_id != self.request_id
            || recognised.intent_nonce != self.intent_nonce
            || recognised.expires_at != pending_expires_at
            || <[u8; 32]>::from(Sha256::digest(authority_response)) != supplied_authority_digest
        {
            return Err("the credential/v2 restored offer binding was refused".into());
        }
        let status = selfsame_pairing::credential_v2::recognise_authority_status_response(
            &self.profile,
            authority_response,
            &recognised.kid,
            self.carrier_ceremony_id,
            supplied_digest,
        )
        .map_err(|_| "the credential/v2 signed authority was refused".to_owned())?;
        if !matches!(
            self.session
                .as_ref()
                .and_then(|session| session.endpoint_phase()),
            Some(cbcl_pairing::credential_v2::CredentialV2Phase::Begin) | None
        ) {
            self.body_authority
                .require_bound_offer(&self.profile, &recognised)
                .map_err(|_| "the restored body authority was refused".to_owned())?;
        }
        self.prepared_offer_core = Some(offer_core.to_vec());
        self.prepared_offer_digest = Some(supplied_digest);
        self.offer_kid = Some(recognised.kid);
        self.authority_status = Some(status);
        self.authority_response = Some(authority_response.to_vec());
        Ok(())
    }

    /// Return the first relay binding as one closed send effect.
    pub fn start(&self) -> Result<String, JsError> {
        let body = self
            .session
            .as_ref()
            .ok_or_else(|| JsError::new("the credential/v2 attempt was cancelled"))?
            .start()
            .map_err(|_| JsError::new("the credential/v2 relay frame was refused"))?;
        Ok(v2_allocator_effects_json(
            &[cbcl_pairing::credential_v2::CredentialV2AllocatorEffect::Send(body)],
            &self.request_id,
            &self.intent_nonce,
            &self.carrier_ceremony_id,
            self.restored_presence_code()
                .map(Zeroizing::new)
                .as_deref()
                .map(String::as_str),
        ))
    }

    /// Apply one relay response with a fresh checkpoint nonce and shell clock.
    pub fn receive(
        &mut self,
        input: &[u8],
        now: u64,
        checkpoint_nonce: &[u8],
    ) -> Result<String, JsError> {
        self.receive_inner(input, now, checkpoint_nonce)
            .map_err(|error| JsError::new(&error))
    }

    /// Confirm one durable checkpoint and release only its covered effects.
    pub fn checkpoint_persisted(&mut self, generation: u64) -> Result<String, JsError> {
        self.checkpoint_persisted_inner(generation)
            .map_err(|error| JsError::new(&error))
    }

    /// Return the public receipt-recovery commitment after the protected
    /// channel is established. The HMAC token and exporter remain in Rust.
    pub fn receipt_recovery_commitment(&self) -> Result<Vec<u8>, JsError> {
        self.session
            .as_ref()
            .ok_or_else(|| JsError::new("the credential/v2 attempt was cancelled"))?
            .receipt_recovery_commitment()
            .map(|commitment| commitment.to_vec())
            .map_err(|_| {
                JsError::new("the credential/v2 receipt-recovery commitment is unavailable")
            })
    }

    /// Recognise the unsigned hub core against this attempt and return the exact
    /// 32-octet installation-device possession signing input.
    #[allow(clippy::too_many_arguments)]
    pub fn device_possession_input(
        &mut self,
        raw_carrier: &[u8],
        offer_core: &[u8],
        socket_generation_digest: &[u8],
        offer_core_digest: &[u8],
        pending_expires_at: u64,
        now: u64,
    ) -> Result<Vec<u8>, JsError> {
        if self.prepared_offer_core.is_some() || now >= pending_expires_at {
            return Err(JsError::new("the credential/v2 prepared offer was refused"));
        }
        let transcript_hash = self
            .transcript_hash
            .ok_or_else(|| JsError::new("the credential/v2 channel is not established"))?;
        let carrier = cbcl_pairing::credential_v2::decode_carrier(raw_carrier)
            .map_err(|_| JsError::new("the credential/v2 carrier was refused"))?;
        let recognised =
            selfsame_pairing::credential_v2::recognise_offer_core(&self.profile, offer_core)
                .map_err(|_| JsError::new("the credential/v2 prepared offer was refused"))?;
        let supplied_digest: [u8; 32] =
            fixed_browser_bytes(offer_core_digest, "offer-core digest")?;
        let actual_digest: [u8; 32] = Sha256::digest(offer_core).into();
        let expected_device_jwk = identity_json::canonicalise(&Json::obj([
            ("crv", Json::text("Ed25519")),
            ("kty", Json::text("OKP")),
            (
                "x",
                Json::text(selfsame_app_identity::codec::b64url(
                    &self.expected_allocator_key,
                )),
            ),
        ]));
        let claims = &recognised.claims;
        if supplied_digest != actual_digest
            || supplied_digest != *claims.offer_core_digest()
            || carrier.application_context() != self.profile.application_id.as_str()
            || carrier.relay_origin() != claims.relay_origin()
            || carrier.carrier_ceremony_id() != &self.carrier_ceremony_id
            || carrier.expected_allocator_key() != Some(&self.expected_allocator_key)
            || carrier.digest() != recognised.carrier_digest
            || claims.carrier_ceremony_id() != &self.carrier_ceremony_id
            || recognised.request_id != self.request_id
            || recognised.intent_nonce != self.intent_nonce
            || recognised.transcript_hash != transcript_hash
            || recognised.expires_at != pending_expires_at
            || pending_expires_at > carrier.relay_expires_at()
            || claims.device_binding().device_key_digest()
                != &<[u8; 32]>::from(Sha256::digest(&expected_device_jwk))
        {
            return Err(JsError::new("the credential/v2 prepared offer was refused"));
        }
        let socket_generation_digest =
            fixed_browser_bytes(socket_generation_digest, "socket-generation digest")?;
        let input = selfsame_pairing::credential_v2::device_possession_proof_input(
            socket_generation_digest,
            self.carrier_ceremony_id,
            supplied_digest,
        )
        .map_err(|_| JsError::new("the credential/v2 possession input was refused"))?;
        self.prepared_offer_core = Some(offer_core.to_vec());
        self.prepared_offer_digest = Some(supplied_digest);
        Ok(input.to_vec())
    }

    /// Verify the exact signed offer and signed reciprocal authority, then seal
    /// the allocator's first application object behind the checkpoint barrier.
    pub fn prepare_offer(
        &mut self,
        signed_offer: &[u8],
        authority_response: &[u8],
        authority_digest: &[u8],
        now: u64,
        checkpoint_nonce: &[u8],
    ) -> Result<String, JsError> {
        let prepared_core = self
            .prepared_offer_core
            .as_ref()
            .ok_or_else(|| JsError::new("the credential/v2 offer was not prepared"))?;
        let prepared_digest = self
            .prepared_offer_digest
            .ok_or_else(|| JsError::new("the credential/v2 offer was not prepared"))?;
        let recognised =
            selfsame_pairing::credential_v2::recognise_signed_offer(&self.profile, signed_offer)
                .map_err(|_| JsError::new("the credential/v2 signed offer was refused"))?;
        let supplied_authority_digest: [u8; 32] =
            fixed_browser_bytes(authority_digest, "authority-status digest")?;
        if recognised.offer_core.as_slice() != prepared_core
            || recognised.claims.offer_core_digest() != &prepared_digest
            || recognised.expires_at <= now
            || <[u8; 32]>::from(Sha256::digest(authority_response)) != supplied_authority_digest
        {
            return Err(JsError::new(
                "the credential/v2 signed authority was refused",
            ));
        }
        let status = selfsame_pairing::credential_v2::recognise_authority_status_response(
            &self.profile,
            authority_response,
            &recognised.kid,
            self.carrier_ceremony_id,
            prepared_digest,
        )
        .map_err(|_| JsError::new("the credential/v2 signed authority was refused"))?;
        let object = cbcl_pairing::credential_v2::CredentialV2Object::new(
            cbcl_pairing::credential_v2::CredentialV2Kind::Offer,
            cbcl_pairing::credential_v2::credential_v2_intent_digest(prepared_digest),
            signed_offer.to_vec(),
        )
        .map_err(|_| JsError::new("the credential/v2 offer object was refused"))?;
        self.body_authority
            .bind_offer(self.profile.clone(), &recognised)
            .map_err(|_| JsError::new("the credential/v2 body authority was refused"))?;
        self.offer_kid = Some(recognised.kid.clone());
        let checkpoint_nonce: [u8; 12] = fixed_browser_bytes(checkpoint_nonce, "checkpoint nonce")?;
        let effects = self
            .session
            .as_mut()
            .ok_or_else(|| JsError::new("the credential/v2 attempt was cancelled"))?
            .prepare_application_object(
                &object,
                now,
                cbcl_pairing::credential_v2::CredentialV2CheckpointNonce::from_csprng(
                    checkpoint_nonce,
                ),
            )
            .map_err(|_| JsError::new("the credential/v2 offer release was refused"))?;
        self.authority_status = Some(status);
        self.authority_response = Some(authority_response.to_vec());
        Ok(v2_allocator_effects_json(
            &effects,
            &self.request_id,
            &self.intent_nonce,
            &self.carrier_ceremony_id,
            self.restored_presence_code()
                .map(Zeroizing::new)
                .as_deref()
                .map(String::as_str),
        ))
    }

    /// After an authenticated claimant preparation and the person's browser
    /// comparison action, seal the signed comparison result behind the
    /// allocator checkpoint barrier.
    pub fn prepare_comparison(
        &mut self,
        now: u64,
        checkpoint_nonce: &[u8],
    ) -> Result<String, JsError> {
        let preparation = self
            .last_received_object
            .as_ref()
            .filter(|object| {
                object.kind() == cbcl_pairing::credential_v2::CredentialV2Kind::Preparation
            })
            .ok_or_else(|| JsError::new("the credential/v2 preparation is unavailable"))?;
        let authority_response = self
            .authority_response
            .as_deref()
            .ok_or_else(|| JsError::new("the credential/v2 authority response is unavailable"))?;
        let object = self
            .body_authority
            .comparison(preparation, authority_response)
            .map_err(|_| JsError::new("the credential/v2 comparison was refused"))?;
        let checkpoint_nonce: [u8; 12] = fixed_browser_bytes(checkpoint_nonce, "checkpoint nonce")?;
        let effects = self
            .session
            .as_mut()
            .ok_or_else(|| JsError::new("the credential/v2 attempt was cancelled"))?
            .prepare_application_object(
                &object,
                now,
                cbcl_pairing::credential_v2::CredentialV2CheckpointNonce::from_csprng(
                    checkpoint_nonce,
                ),
            )
            .map_err(|_| JsError::new("the credential/v2 comparison release was refused"))?;
        Ok(v2_allocator_effects_json(
            &effects,
            &self.request_id,
            &self.intent_nonce,
            &self.carrier_ceremony_id,
            self.restored_presence_code()
                .map(Zeroizing::new)
                .as_deref()
                .map(String::as_str),
        ))
    }

    /// Return only the Rust-authenticated preparation display. Raw peer body
    /// fields never become browser display authority.
    pub fn preparation_view_json(&self) -> Result<String, JsError> {
        if self
            .last_received_object
            .as_ref()
            .map(|object| object.kind())
            != Some(cbcl_pairing::credential_v2::CredentialV2Kind::Preparation)
        {
            return Err(JsError::new("the credential/v2 preparation is unavailable"));
        }
        let preview = self
            .body_authority
            .retained_preview()
            .map_err(|_| JsError::new("the credential/v2 preparation is unavailable"))?;
        let fingerprint: serde_json::Value =
            serde_json::from_str(&fingerprint_did_json(preview.did()))
                .map_err(|_| JsError::new("the credential/v2 fingerprint is unavailable"))?;
        Ok(serde_json::json!({
            "previewIssuerDid": preview.did(),
            "previewFingerprintDigestB64u": selfsame_app_identity::codec::b64url(
                preview.fingerprint_digest()
            ),
            "fingerprint": fingerprint,
        })
        .to_string())
    }

    /// Return only the Rust-authenticated reverse-payload projection. The
    /// browser never parses peer body bytes to obtain grant or account facts.
    pub fn payload_view_json(&self) -> Result<String, JsError> {
        let object = self
            .last_received_object
            .as_ref()
            .filter(|object| {
                object.kind() == cbcl_pairing::credential_v2::CredentialV2Kind::Payload
            })
            .ok_or_else(|| JsError::new("the credential/v2 payload is unavailable"))?;
        let payload = self
            .body_authority
            .retained_payload()
            .map_err(|_| JsError::new("the credential/v2 payload is unavailable"))?;
        Ok(serde_json::json!({
            "applicationId": self.profile.application_id.as_str(),
            "profileDigestB64u": selfsame_app_identity::codec::b64url(self.profile.digest()),
            "bodyB64u": selfsame_app_identity::codec::b64url(object.body()),
            "contentHashB64u": selfsame_app_identity::codec::b64url(&object.content_hash()),
            "offerCoreDigestB64u": selfsame_app_identity::codec::b64url(
                payload.offer_core_digest()
            ),
            "previewIssuerDid": payload.preview_issuer_did(),
            "previewFingerprintDigestB64u": selfsame_app_identity::codec::b64url(
                payload.preview_fingerprint_digest()
            ),
            "accountPrincipalDigestB64u": selfsame_app_identity::codec::b64url(
                payload.account_principal_digest()
            ),
            "accountScopeIdB64u": selfsame_app_identity::codec::b64url(
                payload.account_scope_id()
            ),
            "deviceDid": payload.device_did(),
            "grantIdB64u": selfsame_app_identity::codec::b64url(payload.grant_id()),
            "grantMediaType": selfsame_app_identity::grant::GRANT_MEDIA_TYPE,
            "grant": payload.grant(),
            "migrationConfirmationDigestB64u": selfsame_app_identity::codec::b64url(
                payload.migration_confirmation_digest()
            ),
        })
        .to_string())
    }

    /// Return the exact digest the browser installation key signs after the
    /// authenticated payload has been durably staged.
    pub fn staging_receipt_signature_input(&self) -> Result<Vec<u8>, JsError> {
        selfsame_pairing::credential_v2::browser_staging_signature_input(
            &self.browser_staging_input()?,
        )
        .map(|value| value.to_vec())
        .map_err(|_| JsError::new("the credential/v2 staging receipt input was refused"))
    }

    /// Verify the browser installation signature and return the one canonical
    /// staging receipt accepted by the hub.
    pub fn build_staging_receipt(&self, signature: &[u8]) -> Result<Vec<u8>, JsError> {
        let signature: [u8; 64] = fixed_browser_bytes(signature, "staging receipt signature")?;
        selfsame_pairing::credential_v2::build_browser_staging_receipt(
            &self.browser_staging_input()?,
            self.expected_allocator_key,
            signature,
        )
        .map_err(|_| JsError::new("the credential/v2 staging receipt was refused"))
    }

    /// Verify the immutable hub acknowledgement against every authenticated
    /// offer and payload fact retained inside this allocator session.
    pub fn verify_final_status(
        &self,
        final_status: &[u8],
        final_status_digest: &[u8],
        finalized_at: u64,
    ) -> Result<(), JsError> {
        let staging = self.browser_staging_input()?;
        let expected = selfsame_pairing::credential_v2::CredentialV2FinalStatusInput {
            application_id: staging.application_id,
            carrier_ceremony_id: staging.carrier_ceremony_id,
            request_id: self.request_id,
            account_principal_digest: staging.account_principal_digest,
            account_scope_id: staging.account_scope_id,
            device_did: staging.device_did,
            offer_core_digest: staging.offer_core_digest,
            payload_digest: staging.payload_digest,
            grant_id: staging.grant_id,
            issuer_did: staging.issuer_did,
            receipt_recovery_commitment: staging.receipt_recovery_commitment,
            finalized_at,
        };
        let jws = std::str::from_utf8(final_status)
            .map_err(|_| JsError::new("the credential/v2 final status was refused"))?;
        let digest = fixed_browser_bytes(final_status_digest, "final-status digest")?;
        let kid = self
            .offer_kid
            .as_deref()
            .ok_or_else(|| JsError::new("the credential/v2 signed offer is unavailable"))?;
        selfsame_pairing::credential_v2::recognise_final_status(
            &self.profile,
            jws,
            digest,
            &expected,
            kid,
        )
        .map_err(|_| JsError::new("the credential/v2 final status was refused"))
    }

    /// Seal the already verified immutable status into the allocator receipt.
    /// The browser calls this only after its active record is durable; the
    /// returned checkpoint effect then places the relay send behind the usual
    /// checkpoint-persisted barrier.
    pub fn prepare_receipt(
        &mut self,
        final_status: &[u8],
        final_status_digest: &[u8],
        finalized_at: u64,
        now: u64,
        checkpoint_nonce: &[u8],
    ) -> Result<String, JsError> {
        self.verify_final_status(final_status, final_status_digest, finalized_at)?;
        let predecessor = self
            .last_received_object
            .as_ref()
            .filter(|object| {
                object.kind() == cbcl_pairing::credential_v2::CredentialV2Kind::Payload
            })
            .ok_or_else(|| JsError::new("the credential/v2 payload is unavailable"))?;
        let jws = std::str::from_utf8(final_status)
            .map_err(|_| JsError::new("the credential/v2 final status was refused"))?;
        let digest = fixed_browser_bytes(final_status_digest, "final-status digest")?;
        let receipt = self
            .body_authority
            .receipt(
                predecessor,
                selfsame_pairing::credential_v2::CredentialV2ReceiptInput {
                    final_status_jws: jws.into(),
                    final_status_digest: digest,
                },
            )
            .map_err(|_| JsError::new("the credential/v2 receipt was refused"))?;
        let checkpoint_nonce: [u8; 12] = fixed_browser_bytes(checkpoint_nonce, "checkpoint nonce")?;
        let effects = self
            .session
            .as_mut()
            .ok_or_else(|| JsError::new("the credential/v2 attempt was cancelled"))?
            .prepare_application_object(
                &receipt,
                now,
                cbcl_pairing::credential_v2::CredentialV2CheckpointNonce::from_csprng(
                    checkpoint_nonce,
                ),
            )
            .map_err(|_| JsError::new("the credential/v2 receipt release was refused"))?;
        Ok(v2_allocator_effects_json(
            &effects,
            &self.request_id,
            &self.intent_nonce,
            &self.carrier_ceremony_id,
            self.restored_presence_code()
                .map(Zeroizing::new)
                .as_deref()
                .map(String::as_str),
        ))
    }

    /// Burn the local attempt without releasing another protocol frame.
    pub fn cancel(&mut self) -> String {
        self.session = None;
        r#"[{"outcome":"cancelled","type":"terminal"}]"#.into()
    }

    fn capture_allocator_effects(
        &mut self,
        effects: &[cbcl_pairing::credential_v2::CredentialV2AllocatorEffect],
    ) -> Result<(), String> {
        for effect in effects {
            match effect {
                cbcl_pairing::credential_v2::CredentialV2AllocatorEffect::Established {
                    transcript_hash,
                } => {
                    if self.transcript_hash.replace(*transcript_hash).is_some() {
                        return Err("the credential/v2 transcript was established twice".to_owned());
                    }
                }
                cbcl_pairing::credential_v2::CredentialV2AllocatorEffect::ReceivedObject {
                    object,
                } => self.last_received_object = Some(object.clone()),
                _ => {}
            }
        }
        Ok(())
    }

    fn browser_staging_input(
        &self,
    ) -> Result<selfsame_pairing::credential_v2::CredentialV2BrowserStagingInput, JsError> {
        let object = self
            .last_received_object
            .as_ref()
            .filter(|object| {
                object.kind() == cbcl_pairing::credential_v2::CredentialV2Kind::Payload
            })
            .ok_or_else(|| JsError::new("the credential/v2 payload is unavailable"))?;
        let payload = self
            .body_authority
            .retained_payload()
            .map_err(|_| JsError::new("the credential/v2 payload is unavailable"))?;
        let receipt_recovery_commitment = self
            .session
            .as_ref()
            .ok_or_else(|| JsError::new("the credential/v2 attempt was cancelled"))?
            .receipt_recovery_commitment()
            .map_err(|_| {
                JsError::new("the credential/v2 receipt-recovery commitment is unavailable")
            })?;
        Ok(
            selfsame_pairing::credential_v2::CredentialV2BrowserStagingInput {
                application_id: self.profile.application_id.as_str().into(),
                carrier_ceremony_id: self.carrier_ceremony_id,
                account_principal_digest: *payload.account_principal_digest(),
                account_scope_id: *payload.account_scope_id(),
                device_did: payload.device_did().into(),
                offer_core_digest: *payload.offer_core_digest(),
                payload_digest: object.content_hash(),
                grant_id: *payload.grant_id(),
                issuer_did: payload.preview_issuer_did().into(),
                profile_digest: *self.profile.digest(),
                receipt_recovery_commitment,
            },
        )
    }
}

// Native-testable error boundary. JsError is constructed only by the exports.
impl CredentialV2BrowserAllocatorSession {
    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        profile: &[u8],
        relay_origin: String,
        mailbox_id: &[u8],
        carrier_ceremony_id: &[u8],
        carrier_nonce: &[u8],
        cpace_secret: &[u8],
        claim_token: &[u8],
        cpace_scalar: &[u8],
        request_id: &[u8],
        intent_nonce: &[u8],
        expected_allocator_key: &[u8],
        installation_seed: &[u8],
        mode: cbcl_pairing::credential_v2::CredentialV2AllocatorMode,
    ) -> Result<CredentialV2BrowserAllocatorSession, String> {
        let profile = ApplicationProfile::recognise(profile)
            .map_err(|_| "the credential/v2 application profile was refused".to_owned())?;
        if !profile
            .cbcl_pairing_relays
            .iter()
            .any(|descriptor| descriptor.relay_origin == relay_origin)
        {
            return Err(
                "the credential/v2 relay is absent from the application profile".to_owned(),
            );
        }
        let mailbox_id = fixed_browser_bytes_inner(mailbox_id, "mailbox ID")?;
        let carrier_ceremony_id =
            fixed_browser_bytes_inner(carrier_ceremony_id, "carrier ceremony ID")?;
        let carrier_nonce = fixed_browser_bytes_inner(carrier_nonce, "carrier nonce")?;
        let cpace_secret = match mode {
            cbcl_pairing::credential_v2::CredentialV2AllocatorMode::Full => {
                fixed_browser_bytes_inner(cpace_secret, "CPace presence secret")?
            }
            cbcl_pairing::credential_v2::CredentialV2AllocatorMode::Manual => {
                let entropy: [u8; 4] =
                    fixed_browser_bytes_inner(cpace_secret, "manual word randomness")?;
                *cbcl_pairing::credential_v2::CredentialV2ManualWords::from_csprng(entropy)
                    .cpace_secret()
            }
        };
        let claim_token = fixed_browser_bytes_inner(claim_token, "relay claim token")?;
        let cpace_scalar = fixed_browser_bytes_inner(cpace_scalar, "CPace scalar")?;
        let request_id = fixed_browser_bytes_inner(request_id, "request ID")?;
        let intent_nonce = fixed_browser_bytes_inner(intent_nonce, "intent nonce")?;
        let expected_allocator_key =
            fixed_browser_bytes_inner(expected_allocator_key, "allocator key")?;
        let installation_seed: [u8; 32] =
            fixed_browser_bytes_inner(installation_seed, "installation seed")?;
        let mut wrapping_key = [0_u8; 32];
        hkdf::Hkdf::<sha2::Sha512>::new(Some(&carrier_ceremony_id), &installation_seed)
            .expand(V2_ALLOCATOR_CHECKPOINT_INFO, &mut wrapping_key)
            .map_err(|_| "credential/v2 checkpoint key derivation failed".to_owned())?;
        let input = cbcl_pairing::credential_v2::CredentialV2AllocatorSessionInput {
            application_context: profile.application_id.as_str().into(),
            relay_origin,
            mailbox_id,
            carrier_ceremony_id,
            carrier_nonce,
            mode,
            cpace_secret,
            claim_token,
            cpace_scalar,
            profile_digest: *profile.digest(),
            expected_allocator_key: Some(expected_allocator_key),
            checkpoint_wrapping_key: wrapping_key,
        };
        let (body_authority, body_verifier) =
            selfsame_pairing::credential_v2::credential_v2_body_authority();
        let session = cbcl_pairing::credential_v2::CredentialV2AllocatorSession::new(
            input,
            Box::new(body_verifier),
        )
        .map_err(|_| "the credential/v2 allocator attempt was refused".to_owned())?;
        Ok(Self {
            session: Some(session),
            profile,
            request_id,
            intent_nonce,
            carrier_ceremony_id,
            expected_allocator_key,
            transcript_hash: None,
            prepared_offer_core: None,
            prepared_offer_digest: None,
            offer_kid: None,
            authority_status: None,
            authority_response: None,
            body_authority,
            last_received_object: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn restore_inner(
        profile: &[u8],
        carrier: &[u8],
        checkpoint: &[u8],
        generation: u64,
        request_id: &[u8],
        intent_nonce: &[u8],
        expected_allocator_key: &[u8],
        installation_seed: &[u8],
        now: u64,
        mode: String,
        fresh_cpace_scalar: &[u8],
    ) -> Result<CredentialV2BrowserAllocatorSession, String> {
        // No legacy ABI or scalar default: recognize both inputs on every restore,
        // including established checkpoints (which grant no bootstrap capability).
        let mode = match mode.as_str() {
            "full" => cbcl_pairing::credential_v2::CredentialV2AllocatorMode::Full,
            "manual" => cbcl_pairing::credential_v2::CredentialV2AllocatorMode::Manual,
            _ => return Err("the credential/v2 allocator mode was refused".into()),
        };
        let fresh_cpace_scalar: [u8; 32] =
            fixed_browser_bytes_inner(fresh_cpace_scalar, "fresh CPace scalar")?;
        let profile = ApplicationProfile::recognise(profile)
            .map_err(|_| "the credential/v2 application profile was refused".to_owned())?;
        let carrier = cbcl_pairing::credential_v2::decode_carrier(carrier)
            .map_err(|_| "the credential/v2 carrier was refused".to_owned())?;
        let request_id = fixed_browser_bytes_inner(request_id, "request ID")?;
        let intent_nonce = fixed_browser_bytes_inner(intent_nonce, "intent nonce")?;
        let expected_allocator_key =
            fixed_browser_bytes_inner(expected_allocator_key, "allocator key")?;
        let installation_seed: [u8; 32] =
            fixed_browser_bytes_inner(installation_seed, "installation seed")?;
        if generation == 0
            || carrier.application_context() != profile.application_id.as_str()
            || carrier.expected_allocator_key() != Some(&expected_allocator_key)
        {
            return Err("the credential/v2 checkpoint binding was refused".to_owned());
        }
        let mut wrapping_key = [0_u8; 32];
        hkdf::Hkdf::<sha2::Sha512>::new(Some(carrier.carrier_ceremony_id()), &installation_seed)
            .expand(V2_ALLOCATOR_CHECKPOINT_INFO, &mut wrapping_key)
            .map_err(|_| "credential/v2 checkpoint key derivation failed".to_owned())?;
        let (body_authority, body_verifier) =
            selfsame_pairing::credential_v2::credential_v2_body_authority_for_restore(
                profile.clone(),
            );
        let session = cbcl_pairing::credential_v2::CredentialV2AllocatorSession::restore(
            checkpoint,
            &wrapping_key,
            carrier.clone(),
            generation,
            *profile.digest(),
            now,
            mode,
            fresh_cpace_scalar,
            Box::new(body_verifier),
        )
        .map_err(|_| "the credential/v2 allocator checkpoint was refused".to_owned())?;
        let transcript_hash = session.transcript_hash();
        let last_received_object = session
            .last_received_object()
            .map_err(|_| "the credential/v2 restored object was refused".to_owned())?;
        if let Some(object) = last_received_object.as_ref() {
            body_authority
                .restore_retained_received_object(object)
                .map_err(|_| "the credential/v2 retained body was refused".to_owned())?;
        }
        Ok(Self {
            session: Some(session),
            profile,
            request_id,
            intent_nonce,
            carrier_ceremony_id: *carrier.carrier_ceremony_id(),
            expected_allocator_key,
            transcript_hash,
            prepared_offer_core: None,
            prepared_offer_digest: None,
            offer_kid: None,
            authority_status: None,
            authority_response: None,
            body_authority,
            last_received_object,
        })
    }

    fn handoff_text_inner(&self) -> Result<Option<String>, String> {
        let Some(session) = self.session.as_ref() else {
            return Ok(None);
        };
        session
            .handoff_text()
            .map(|text| text.map(|value| value.as_str().to_owned()))
            .map_err(|_| "the pairing invitation was refused".to_owned())
    }

    fn receive_inner(
        &mut self,
        input: &[u8],
        now: u64,
        checkpoint_nonce: &[u8],
    ) -> Result<String, String> {
        let checkpoint_nonce: [u8; 12] =
            fixed_browser_bytes_inner(checkpoint_nonce, "checkpoint nonce")?;
        let effects = self
            .session
            .as_mut()
            .ok_or_else(|| "the credential/v2 attempt was cancelled".to_owned())?
            .receive(
                input,
                now,
                cbcl_pairing::credential_v2::CredentialV2CheckpointNonce::from_csprng(
                    checkpoint_nonce,
                ),
            )
            .map_err(|_| "the credential/v2 relay message was refused".to_owned())?;
        self.capture_allocator_effects(&effects)?;
        Ok(v2_allocator_effects_json(
            &effects,
            &self.request_id,
            &self.intent_nonce,
            &self.carrier_ceremony_id,
            self.restored_presence_code()
                .map(Zeroizing::new)
                .as_deref()
                .map(String::as_str),
        ))
    }

    fn checkpoint_persisted_inner(&mut self, generation: u64) -> Result<String, String> {
        let effects = self
            .session
            .as_mut()
            .ok_or_else(|| "the credential/v2 attempt was cancelled".to_owned())?
            .checkpoint_persisted(generation)
            .map_err(|_| "the credential/v2 checkpoint acknowledgement was refused".to_owned())?;
        self.capture_allocator_effects(&effects)?;
        Ok(v2_allocator_effects_json(
            &effects,
            &self.request_id,
            &self.intent_nonce,
            &self.carrier_ceremony_id,
            self.restored_presence_code()
                .map(Zeroizing::new)
                .as_deref()
                .map(String::as_str),
        ))
    }

    fn manual_transfer_text_inner(&self) -> Result<Option<String>, &'static str> {
        let Some(session) = self.session.as_ref() else {
            return Ok(None);
        };
        let Some((bootstrap, words)) = session
            .manual_transfer_text()
            .map_err(|_| "the pairing invitation was refused")?
        else {
            return Ok(None);
        };
        // Borrow the zeroizing core strings so serialization creates only the
        // intentional private return value, not another native secret cache.
        #[derive(serde::Serialize)]
        struct Transfer<'a> {
            bootstrap: &'a str,
            words: &'a str,
        }
        serde_json::to_string(&Transfer {
            bootstrap: &bootstrap,
            words: &words,
        })
        .map(Some)
        .map_err(|_| "the pairing invitation was refused")
    }
}

fn fixed_browser_bytes<const LENGTH: usize>(
    value: &[u8],
    label: &str,
) -> Result<[u8; LENGTH], JsError> {
    fixed_browser_bytes_inner(value, label).map_err(|error| JsError::new(&error))
}

fn fixed_browser_bytes_inner<const LENGTH: usize>(
    value: &[u8],
    label: &str,
) -> Result<[u8; LENGTH], String> {
    value
        .try_into()
        .map_err(|_| format!("the credential/v2 {label} is exactly {LENGTH} octets"))
}

/// ABI capability gate for all allocator starts/restores, including Full mode.
#[wasm_bindgen]
pub fn cbcl_allocator_api_version() -> u32 {
    2
}

fn v2_allocator_effects_json(
    effects: &[cbcl_pairing::credential_v2::CredentialV2AllocatorEffect],
    request_id: &[u8; 32],
    intent_nonce: &[u8; 32],
    carrier_ceremony_id: &[u8; 32],
    presence_code: Option<&str>,
) -> String {
    use cbcl_pairing::credential_v2::CredentialV2AllocatorEffect;
    let values = effects
        .iter()
        .map(|effect| match effect {
            CredentialV2AllocatorEffect::Send(body) => serde_json::json!({
                "type": "send",
                "bodyB64u": selfsame_app_identity::codec::b64url(body),
            }),
            CredentialV2AllocatorEffect::Checkpoint {
                generation,
                checkpoint,
                carrier,
            } => serde_json::json!({
                "type": "checkpoint",
                "generation": generation,
                "checkpointB64u": selfsame_app_identity::codec::b64url(checkpoint.as_bytes()),
                "rawCarrierB64u": selfsame_app_identity::codec::b64url(carrier),
                "carrierCeremonyIdB64u": selfsame_app_identity::codec::b64url(carrier_ceremony_id),
            }),
            CredentialV2AllocatorEffect::PendingAllocation { carrier } => serde_json::json!({
                "type": "pending-allocation",
                "rawCarrierB64u": selfsame_app_identity::codec::b64url(carrier),
                "requestIdB64u": selfsame_app_identity::codec::b64url(request_id),
                "carrierCeremonyIdB64u": selfsame_app_identity::codec::b64url(carrier_ceremony_id),
                "intentNonceB64u": selfsame_app_identity::codec::b64url(intent_nonce),
                "presenceCode": presence_code,
            }),
            CredentialV2AllocatorEffect::Established { transcript_hash } => serde_json::json!({
                "type": "established",
                "transcriptHashB64u": selfsame_app_identity::codec::b64url(transcript_hash),
            }),
            CredentialV2AllocatorEffect::ReceivedObject { object } => serde_json::json!({
                "type": "received-object",
                "kind": object.kind().number(),
                "bodyB64u": selfsame_app_identity::codec::b64url(object.body()),
                "contentHashB64u": selfsame_app_identity::codec::b64url(&object.content_hash()),
            }),
            CredentialV2AllocatorEffect::Terminal => serde_json::json!({
                "type": "terminal",
                "outcome": "closed",
            }),
        })
        .collect::<Vec<_>>();
    serde_json::Value::Array(values).to_string()
}

/// Read the public carrier's original deadline through the shared recognizer.
/// Browser display uses this alongside the authenticated hub deadline.
#[wasm_bindgen]
pub fn cbcl_carrier_relay_expires_at(carrier: &[u8]) -> Result<u64, JsError> {
    cbcl_pairing::credential_v2::decode_carrier(carrier)
        .map(|carrier| carrier.relay_expires_at())
        .map_err(|_| JsError::new("the pairing invitation was refused"))
}

// SPEC-077 TEST-005: a pure boundary keeps recognition/capacity errors testable
// natively, without constructing a JavaScript exception outside WASM.
fn handoff_qr_modules_json(handoff: &str) -> Result<String, &'static str> {
    let _: cbcl_pairing::credential_v2::CredentialV2Handoff = handoff
        .parse()
        .map_err(|_| "the pairing invitation was refused")?;
    transfer_qr_modules_json(handoff)
}

fn manual_bootstrap_qr_modules_json(text: &str, now: u64) -> Result<String, &'static str> {
    cbcl_pairing::credential_v2::CredentialV2ManualBootstrap::recognise(text, now)
        .map_err(|_| "the pairing invitation was refused")?;
    transfer_qr_modules_json(text)
}

/// Encode the exact complete text with the existing Q-level implementation.
/// Capacity failure leaves the caller's private paste text intact.
fn transfer_qr_modules_json(text: &str) -> Result<String, &'static str> {
    let code = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::Q)
        .map_err(|_| "the pairing invitation does not fit a QR symbol")?;
    let size = code.width();
    let dark: Vec<u8> = (0..size)
        .flat_map(|y| (0..size).map(move |x| (x, y)))
        .map(|(x, y)| u8::from(code[(x, y)] == qrcode::Color::Dark))
        .collect();
    serde_json::to_string(&serde_json::json!({ "size": size, "dark": dark }))
        .map_err(|_| "the pairing invitation was refused")
}

/// Render a fully recognized confidential handoff, without another encoding layer.
#[wasm_bindgen]
pub fn cbcl_handoff_qr_modules_json(handoff: &str) -> Result<String, JsError> {
    handoff_qr_modules_json(handoff).map_err(JsError::new)
}

/// Render a fully recognized, unexpired manual bootstrap as one Q-level QR.
#[wasm_bindgen]
pub fn cbcl_manual_bootstrap_qr_modules_json(text: &str, now: u64) -> Result<String, JsError> {
    manual_bootstrap_qr_modules_json(text, now).map_err(JsError::new)
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
    // `{size, dark}` with `dark` as one flat row-major 0/1 array is the shape
    // the chat application's painter already consumes; keep that contract.
    let size = code.width();
    let dark: Vec<u8> = (0..size)
        .flat_map(|y| (0..size).map(move |x| (x, y)))
        .map(|(x, y)| u8::from(code[(x, y)] == qrcode::Color::Dark))
        .collect();
    serde_json::to_string(&serde_json::json!({
        "size": size,
        "dark": dark,
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

/// The SPEC-002 fingerprint of an issuer DID, as the application must render it
/// for the CON-221 cross-screen comparison.
///
/// The application derives this *itself* from the issuer DID the phone
/// announced, so a substituted issuer produces a visibly different fingerprint
/// — the whole point of the human comparison. `hex` is the normative compared
/// value (REQ-103); the label and 32×32 LifeHash are recognition aids rendered
/// beside it, exactly as the wallet renders them.
#[wasm_bindgen]
pub fn fingerprint_did_json(did: &str) -> String {
    let fp = selfsame_core::fingerprint::fingerprint_did(did);
    format!(
        r#"{{"hex":{},"label":{},"lifehash":{}}}"#,
        json_string(&fp.hex()),
        json_string(&fp.label()),
        json_string(&fp.lifehash().base64()),
    )
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
    let resolvers: Vec<String> = profile
        .state_resolvers
        .iter()
        .map(|resolver| {
            format!(
                r#"{{"id":{},"protocol":{},"url":{}}}"#,
                json_string(&resolver.id),
                json_string(&resolver.protocol),
                json_string(&resolver.url),
            )
        })
        .collect();
    Ok(format!(
        r#"{{"applicationId":{},"accountAuthority":{},"profileVersion":{},"profileDigest":{},"allowedPermissions":[{}],"cbclPairingRelays":[{}],"stateResolvers":[{}]}}"#,
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
        resolvers.join(","),
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

const MAX_CREDENTIAL_V2_RESOLVER_CLOSURE_OCTETS: usize = 1_048_576;
const MAX_CREDENTIAL_V2_RESOLVER_CLOSURE_DEPTH: usize = 64;

#[derive(Clone, Copy)]
struct ClosedJsonSeed {
    depth: usize,
}

impl<'de> serde::de::DeserializeSeed<'de> for ClosedJsonSeed {
    type Value = ();
    fn deserialize<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(ClosedJsonVisitor { depth: self.depth })
    }
}

struct ClosedJsonVisitor {
    depth: usize,
}

impl<'de> serde::de::Visitor<'de> for ClosedJsonVisitor {
    type Value = ();
    fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("bounded JSON without duplicate members or floating-point numbers")
    }
    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Err(E::custom("floating-point numbers are not admitted"))
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_string<E>(self, _: String) -> Result<(), E> {
        Ok(())
    }
    fn visit_none<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_some<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        serde::de::DeserializeSeed::deserialize(ClosedJsonSeed { depth: self.depth }, deserializer)
    }
    fn visit_seq<A>(self, mut sequence: A) -> Result<(), A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        if self.depth >= MAX_CREDENTIAL_V2_RESOLVER_CLOSURE_DEPTH {
            return Err(serde::de::Error::custom(
                "resolver closure JSON is too deep",
            ));
        }
        while sequence
            .next_element_seed(ClosedJsonSeed {
                depth: self.depth + 1,
            })?
            .is_some()
        {}
        Ok(())
    }
    fn visit_map<A>(self, mut object: A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if self.depth >= MAX_CREDENTIAL_V2_RESOLVER_CLOSURE_DEPTH {
            return Err(serde::de::Error::custom(
                "resolver closure JSON is too deep",
            ));
        }
        let mut names = std::collections::BTreeSet::new();
        while let Some(name) = object.next_key::<String>()? {
            if !names.insert(name) {
                return Err(serde::de::Error::custom(
                    "resolver closure JSON has a duplicate member",
                ));
            }
            object.next_value_seed(ClosedJsonSeed {
                depth: self.depth + 1,
            })?;
        }
        Ok(())
    }
}

fn recognise_closed_resolver_closure_json(input: &[u8]) -> Result<(), DeviceError> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    serde::de::DeserializeSeed::deserialize(ClosedJsonSeed { depth: 0 }, &mut deserializer)
        .map_err(|_| DeviceError::Refused)?;
    deserializer.end().map_err(|_| DeviceError::Refused)
}

/// Verify a credential/v2 payload for an inactive browser stage.
///
/// `resolver_closure` is raw signed history fetched by this browser from the
/// named profile resolver. Rust replays it; no JavaScript-provided verification
/// boolean or materialized DID document can enter this boundary. Success is
/// explicitly non-authorizing until the hub's atomic finalization.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn verify_credential_v2_inactive_staging_json(
    profile: &[u8],
    preview_issuer_did: &str,
    device_key: &[u8],
    permissions_json: &str,
    now: f64,
    clock_skew_seconds: i64,
    resolver_id: &str,
    grant: &[u8],
    resolver_closure: &[u8],
) -> Result<String, JsError> {
    let result = (|| -> Result<InactiveStagedGrant, DeviceError> {
        let profile = ApplicationProfile::recognise(profile).map_err(|_| DeviceError::Refused)?;
        let device_key: [u8; 32] = device_key.try_into().map_err(|_| DeviceError::Refused)?;
        identity_json::recognise(
            permissions_json.as_bytes(),
            selfsame_app_identity::json::Limits {
                max_bytes: 1_024,
                max_depth: 2,
            },
        )
        .map_err(|_| DeviceError::Refused)?;
        let permissions: Vec<String> =
            serde_json::from_str(permissions_json).map_err(|_| DeviceError::Refused)?;
        if permissions.is_empty()
            || permissions.len() > 4
            || permissions.windows(2).any(|pair| pair[0] >= pair[1])
            || serde_json::to_string(&permissions).ok().as_deref() != Some(permissions_json)
        {
            return Err(DeviceError::Refused);
        }
        let refs: Vec<&str> = permissions.iter().map(String::as_str).collect();
        verify_credential_v2_inactive_staging(
            &profile,
            preview_issuer_did,
            &device_key,
            &refs,
            browser_unix_seconds(now)?,
            clock_skew_seconds,
            resolver_id,
            grant,
            resolver_closure,
        )
    })();
    result
        .and_then(|staged| {
            serde_json::to_string(&serde_json::json!({
        "accountDid": staged.account_did, "account": staged.account,
        "grantId": staged.grant_id,
        "grantTokenB64u": selfsame_app_identity::codec::b64url(&staged.grant_token),
        "deviceDid": staged.device_did,
        "devicePublicKeyB64u": selfsame_app_identity::codec::b64url(&staged.device_public_key),
        "permissions": staged.permissions, "validUntil": staged.valid_until,
    })).map_err(|_| DeviceError::Refused)
        })
        .map_err(|_| JsError::new("credential/v2 inactive staging refused"))
}

#[allow(clippy::too_many_arguments)]
fn verify_credential_v2_inactive_staging(
    profile: &ApplicationProfile,
    preview_issuer_did: &str,
    device_key: &[u8; 32],
    permissions: &[&str],
    now: UnixSeconds,
    clock_skew_seconds: i64,
    resolver_id: &str,
    grant: &[u8],
    resolver_closure: &[u8],
) -> Result<InactiveStagedGrant, DeviceError> {
    let now_seconds = i64::try_from(now).map_err(|_| DeviceError::Refused)?;
    if resolver_closure.is_empty()
        || resolver_closure.len() > MAX_CREDENTIAL_V2_RESOLVER_CLOSURE_OCTETS
        || clock_skew_seconds < 0
        || now_seconds.checked_add(clock_skew_seconds).is_none()
        || now_seconds.checked_sub(clock_skew_seconds).is_none()
    {
        return Err(DeviceError::Refused);
    }
    recognise_closed_resolver_closure_json(resolver_closure)?;
    let bundle: did_crdt::core::recon::ClosureBundle =
        serde_json::from_slice(resolver_closure).map_err(|_| DeviceError::Refused)?;
    if serde_json::to_vec(&bundle).ok().as_deref() != Some(resolver_closure) {
        return Err(DeviceError::Refused);
    }
    let observation = replay_resolver_closure(bundle, preview_issuer_did, resolver_id, now_seconds)
        .map_err(|_| DeviceError::Refused)?;
    let agreed = agree_closures(profile, &[observation]).map_err(|_| DeviceError::Refused)?;
    let issuer = issuer_state_of(&agreed, now_seconds);
    let account = AcctUri::parse(&selfsame_app_identity::alias::stable_acct_uri(
        preview_issuer_did,
        &profile.account_authority,
    ))
    .map_err(|_| DeviceError::Refused)?;
    verify_inactive_staging(
        &GrantRequest::new(
            profile,
            &account,
            device_key,
            permissions,
            now_seconds,
            clock_skew_seconds,
        ),
        &issuer,
        None,
        grant,
    )
    .map_err(|_| DeviceError::Refused)
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

// ── CON-219 first-contact enrolment allocator (IMPL-008 ADR-913) ────────────
//
// The chat web app is the developer allocator: it builds a CON-219 offer,
// gets its CON-214 evidence signed by the hub, seals the offer to the
// rendezvous, and shows the person a link code. Every intricate field —
// `did:key`, the device-key digest, the offer digest, the web binding, the
// link code — is computed here in Rust where the recogniser and the digests
// are unit-tested, not hand-rolled in JS across the wasm boundary. The four
// CSPRNG values are the caller's to draw (this module generates nothing), the
// same discipline `Device`/`LinkSession` follow.
/// One first-contact CON-219 enrolment allocator attempt (`IMPL-008` `ADR-913`).
///
/// Holds the offer, provider hint, and unsigned statement between building the
/// statement (sent to the hub to sign) and sealing the offer (with the returned
/// evidence), plus the offer plaintext needed to open the wallet's bundle.
#[wasm_bindgen(js_name = EnrolmentAllocator)]
pub struct EnrolmentAllocator {
    secret: [u8; 16],
    profile_octets: Vec<u8>,
    core: OfferCore,
    hint: ProviderHint,
    statement: EnrollmentStatement,
    offer_plaintext: Option<Vec<u8>>,
}

impl EnrolmentAllocator {
    /// Build one allocator attempt from a recognised profile and caller
    /// randomness. `now` is the absolute Unix second the offer is issued at;
    /// the offer expires `OFFER_TTL_SECONDS` later.
    pub fn new_native(
        profile_octets: &[u8],
        secret: &[u8],
        device_seed: &[u8],
        account_scope: &[u8],
        ceremony_id: &[u8],
        request_id: &[u8],
        now: i64,
    ) -> Result<Self, IdentityError> {
        use selfsame_app_identity::{codec, didkey};
        let secret: [u8; 16] = secret.try_into().map_err(|_| IdentityError::Refused)?;
        let seed: [u8; 32] = device_seed.try_into().map_err(|_| IdentityError::Refused)?;
        if account_scope.len() != 32 || ceremony_id.len() != 32 || request_id.len() != 32 {
            return Err(IdentityError::Refused);
        }
        let profile =
            ApplicationProfile::recognise(profile_octets).map_err(|_| IdentityError::Refused)?;
        let descriptor = profile
            .cbcl_pairing_relays
            .first()
            .ok_or(IdentityError::Refused)?;
        let origin = profile.application_id.origin().to_string();
        let device_public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();

        let core = OfferCore {
            ceremony_id: codec::b64url(ceremony_id),
            request_id: codec::b64url(request_id),
            application_id: profile.application_id.as_str().to_string(),
            profile_version: 1,
            profile_digest: codec::b64url(profile.digest()),
            account_scope_id: codec::b64url(account_scope),
            device_did: didkey::encode(&device_public_key),
            device_public_key,
            requested_permissions: profile.allowed_permissions.clone(),
            issued_at: now,
            // The offer and the CON-214 statement share this expiry, so it is
            // bounded by CON-214's 120-second evidence window, not the longer
            // SPEC-001 device-link offer TTL.
            expires_at: now + identity_enrollment::MAX_EVIDENCE_WINDOW_SECONDS,
        };
        let hint = ProviderHint {
            application_id: core.application_id.clone(),
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
            // First contact is the manual cross-device path: the CON-227 web
            // binding, which the wallet accepts against unattributed evidence.
            platform_binding_id: format!("web:{origin}"),
            return_uri: format!("{origin}/.well-known/selfsame/return"),
            issued_at: core.issued_at,
            expires_at: core.expires_at,
        };
        Ok(Self {
            secret,
            profile_octets: profile_octets.to_vec(),
            core,
            hint,
            statement,
            offer_plaintext: None,
        })
    }

    /// The canonical CON-214 statement octets to send to the hub for signing.
    pub fn statement_bytes_native(&self) -> Vec<u8> {
        identity_json::canonicalise(&identity_enrollment::build(&self.statement))
    }

    /// Seal the offer once the hub has returned its compact JWS evidence, and
    /// retain the plaintext for opening the bundle later.
    pub fn seal_offer_native(&mut self, evidence: &str) -> Result<Vec<u8>, IdentityError> {
        let offer = build_offer(&self.core, evidence, &self.hint, &self.profile_octets)?;
        let sealed = seal::seal_offer(&seal::derive_key(&self.secret), &offer);
        self.offer_plaintext = Some(offer);
        Ok(sealed)
    }

    fn link_code_native(&self) -> String {
        LinkCode {
            application: APPLICATION,
            secret: LinkSecret::from_bytes(self.secret),
        }
        .render()
    }
}

#[wasm_bindgen(js_class = EnrolmentAllocator)]
impl EnrolmentAllocator {
    /// Begin. See [`EnrolmentAllocator::new_native`]; the four random values are
    /// drawn by the browser with `crypto.getRandomValues`.
    #[wasm_bindgen(constructor)]
    pub fn new(
        profile: &[u8],
        secret: &[u8],
        device_seed: &[u8],
        account_scope: &[u8],
        ceremony_id: &[u8],
        request_id: &[u8],
        now: f64,
    ) -> Result<EnrolmentAllocator, JsError> {
        Self::new_native(
            profile,
            secret,
            device_seed,
            account_scope,
            ceremony_id,
            request_id,
            now as i64,
        )
        .map_err(|_| JsError::new("SPEC-004 enrolment refused"))
    }

    /// The canonical CON-214 statement octets to POST to `/selfsame/enrolment/sign`.
    pub fn statement_bytes(&self) -> Vec<u8> {
        self.statement_bytes_native()
    }

    /// The link code the person enters into the wallet.
    #[wasm_bindgen(getter)]
    pub fn link_code(&self) -> String {
        self.link_code_native()
    }

    /// The rendezvous slot the sealed offer is written to.
    #[wasm_bindgen(getter)]
    pub fn offer_slot(&self) -> String {
        seal::slot(seal::Role::Offer, &self.secret)
    }

    /// The rendezvous slot the wallet's sealed bundle appears in.
    #[wasm_bindgen(getter)]
    pub fn bundle_slot(&self) -> String {
        seal::slot(seal::Role::Bundle, &self.secret)
    }

    /// The rendezvous slot the wallet's pre-grant issuer announcement appears
    /// in (SPEC-004 CON-221). Present only when the wallet requires the
    /// fingerprint comparison; the client polls it alongside the bundle slot.
    #[wasm_bindgen(getter)]
    pub fn announce_slot(&self) -> String {
        seal::slot(seal::Role::Announce, &self.secret)
    }

    /// Open the wallet's sealed issuer announcement over the retained offer
    /// plaintext, returning the announced issuer DID. Bound to this allocator's
    /// own offer transcript, so an announcement answering a different offer
    /// cannot open here.
    pub fn open_announce(&self, sealed_announce: &[u8]) -> Result<String, JsError> {
        let offer = self
            .offer_plaintext
            .as_ref()
            .ok_or_else(|| JsError::new("no offer sealed yet"))?;
        let did = seal::open_announce(
            &seal::derive_key(&self.secret),
            sealed_announce,
            &seal::transcript(offer),
        )
        .map_err(|_| JsError::new("SPEC-004 announcement refused"))?;
        String::from_utf8(did).map_err(|_| JsError::new("SPEC-004 announcement refused"))
    }

    /// Seal the offer given the hub's compact JWS evidence.
    pub fn seal_offer(&mut self, evidence: &str) -> Result<Vec<u8>, JsError> {
        self.seal_offer_native(evidence)
            .map_err(|_| JsError::new("SPEC-004 offer refused"))
    }

    /// Open the wallet's sealed bundle over the retained offer plaintext, and
    /// require it to name *this* allocator's offer.
    ///
    /// Codex review, "one ceremony's grant delivered into another": AEAD alone
    /// authenticates the bundle to whatever secret and transcript opened it, so
    /// a grant sealed under this allocator's secret decrypts here even when its
    /// ceremony/request IDs name a different offer. `bundle_matches_offer` binds
    /// the opened bundle to this allocator's own `OfferCore` before any field is
    /// used, so a cross-ceremony grant is refused rather than accepted.
    pub fn open_bundle(&self, sealed_bundle: &[u8]) -> Result<Vec<u8>, JsError> {
        let offer = self
            .offer_plaintext
            .as_ref()
            .ok_or_else(|| JsError::new("no offer sealed yet"))?;
        let opened = open_bundle_for(&self.secret, sealed_bundle, offer)
            .map_err(|_| JsError::new("SPEC-004 bundle refused"))?;
        let bundle =
            recognise_bundle(&opened).map_err(|_| JsError::new("SPEC-004 bundle refused"))?;
        bundle_matches_offer(&bundle, &self.core)
            .map_err(|_| JsError::new("SPEC-004 bundle refused"))?;
        Ok(opened)
    }
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
        resolver_closure: Vec<u8>,
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
        let identity = selfsame_app_identity::issuer::create(
            home.signing_key(),
            &profile.account_authority,
            (NOW as u64) * 1_000,
        )
        .expect("issuer closure");
        assert_eq!(identity.did, home_did);
        let resolver_closure = serde_json::to_vec(&identity.closure).expect("closure JSON");
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
            resolver_closure,
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
    fn credential_v2_inactive_staging_replays_raw_signed_closure() {
        let fixture = grant_fixture();
        recognise_closed_resolver_closure_json(&fixture.resolver_closure)
            .expect("strict closure JSON");
        let staged = verify_credential_v2_inactive_staging(
            &fixture.profile,
            &fixture.issuer.did,
            &fixture.device_public_key,
            &[PERMISSION],
            NOW as UnixSeconds,
            0,
            "app-own",
            &fixture.grant,
            &fixture.resolver_closure,
        )
        .expect("raw resolver history establishes an inactive stage");
        assert_eq!(staged.account_did, fixture.issuer.did);
        assert_eq!(staged.account, fixture.account.as_str());
        assert_eq!(staged.device_public_key, fixture.device_public_key);
        assert_eq!(staged.grant_token, [12u8; 32]);
        assert_eq!(staged.permissions, vec![PERMISSION]);
    }

    #[test]
    fn credential_v2_inactive_staging_refuses_unclosed_or_substituted_history() {
        let fixture = grant_fixture();
        let mut with_extra: serde_json::Value =
            serde_json::from_slice(&fixture.resolver_closure).expect("closure JSON");
        with_extra
            .as_object_mut()
            .expect("closure object")
            .insert("trusted".to_owned(), serde_json::Value::Bool(true));
        let with_extra = serde_json::to_vec(&with_extra).expect("mutated JSON");
        assert!(verify_credential_v2_inactive_staging(
            &fixture.profile,
            &fixture.issuer.did,
            &fixture.device_public_key,
            &[PERMISSION],
            NOW as UnixSeconds,
            0,
            "app-own",
            &fixture.grant,
            &with_extra,
        )
        .is_err());
        assert!(verify_credential_v2_inactive_staging(
            &fixture.profile,
            "did:crdt:not-the-preview",
            &fixture.device_public_key,
            &[PERMISSION],
            NOW as UnixSeconds,
            0,
            "app-own",
            &fixture.grant,
            &fixture.resolver_closure,
        )
        .is_err());
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
        assert_eq!(facts["stateResolvers"][0]["id"], "app-own");
        assert_eq!(
            facts["stateResolvers"][0]["protocol"],
            "did-crdt-service-v1"
        );
        assert!(facts["stateResolvers"][0]["url"]
            .as_str()
            .is_some_and(|url| url.starts_with("https://")));

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

#[cfg(test)]
mod enrolment_allocator_tests {
    //! IMPL-008 ADR-913 — the browser CON-219 allocator builds a web-binding
    //! offer the wallet recogniser accepts, a link code the wallet parses, and
    //! well-formed rendezvous slots. The full ceremony (rendezvous I/O + the
    //! wallet accept) is the e2e harness's; this pins the construction.
    use super::*;
    use ed25519_dalek::SigningKey;
    use selfsame_app_identity::enrollment as en;

    const KID: &str = "https://photos.example/selfsame/application#enrollment-test";
    const NOW: i64 = 1_785_412_800;

    fn profile_octets() -> Vec<u8> {
        let corpus: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/spec-004-v1.json")).unwrap();
        corpus["con_201_application_profile"][0]["input"]["profile"]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    fn allocator() -> EnrolmentAllocator {
        EnrolmentAllocator::new_native(
            &profile_octets(),
            &[9u8; 16],
            &[3u8; 32],
            &[4u8; 32],
            &[1u8; 32],
            &[2u8; 32],
            NOW,
        )
        .expect("a recognised profile and 16/32-octet randomness build an allocator")
    }

    #[test]
    fn the_statement_names_the_web_binding_and_the_application_origin() {
        let alloc = allocator();
        let statement = en::recognise_unsigned_payload(&alloc.statement_bytes_native())
            .expect("the built statement is a recognised CON-214 payload");
        assert_eq!(statement.platform_binding_id, "web:https://photos.example");
        assert_eq!(
            statement.return_uri,
            "https://photos.example/.well-known/selfsame/return"
        );
        assert_eq!(
            statement.application_id,
            "https://photos.example/selfsame/application"
        );
    }

    #[test]
    fn the_link_code_round_trips_and_the_slots_are_well_formed() {
        let alloc = allocator();
        let code = alloc.link_code_native();
        let parsed = selfsame_core::code::LinkCode::parse(&code).expect("wallet parses the code");
        assert_eq!(parsed.secret.as_bytes(), &[9u8; 16]);
        assert_eq!(alloc.offer_slot().len(), 26);
        assert_eq!(alloc.bundle_slot().len(), 26);
        assert_ne!(alloc.offer_slot(), alloc.bundle_slot());
    }

    #[test]
    fn the_sealed_offer_opens_and_recognises_as_a_con_219_offer() {
        let mut alloc = allocator();
        // The hub would sign the statement; here a test key stands in for the
        // enrolment key, exercising the seal + recognise path.
        let statement = en::recognise_unsigned_payload(&alloc.statement_bytes_native()).unwrap();
        let evidence = en::sign(&statement, KID, &SigningKey::from_bytes(&[6u8; 32]));
        let sealed = alloc.seal_offer_native(&evidence).expect("the offer seals");

        let opened =
            seal::open_offer(&seal::derive_key(&[9u8; 16]), &sealed).expect("the offer opens");
        let offer = selfsame_app_identity::ceremony::recognise_offer(&opened)
            .expect("the sealed offer recognises as CON-219");
        assert_eq!(
            offer.core.application_id,
            "https://photos.example/selfsame/application"
        );
        // The offer digest the statement bound equals the offer's own.
        assert_eq!(statement.offer_digest, offer.core.digest());
    }
}

#[cfg(test)]
mod scan_handoff_tests {
    use super::handoff_qr_modules_json;

    fn allocated_session() -> super::CredentialV2BrowserAllocatorSession {
        use cbcl_pairing::wire::{encode_server_message, ServerMessage};
        let corpus: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/spec-004-v1.json")).unwrap();
        let profile = corpus["con_201_application_profile"][0]["input"]["profile"]
            .as_str()
            .unwrap();
        let mut session = super::CredentialV2BrowserAllocatorSession::new(
            profile.as_bytes(),
            "https://cbcl-au.provider.example".into(),
            &[0x11; 32],
            &[0x12; 32],
            &[0x13; 32],
            &[0x14; 16],
            &[0x15; 16],
            &[0x18; 32],
            &[0x21; 32],
            &[0x22; 32],
            &[0x19; 32],
            &[0x16; 32],
        )
        .unwrap();
        session
            .receive(
                &encode_server_message(&ServerMessage::Welcome).unwrap(),
                1_800_000_000,
                &[0x31; 12],
            )
            .unwrap();
        session
            .receive(
                &encode_server_message(&ServerMessage::AllocatedV2 {
                    mailbox_id: [0x11; 32],
                    membership_token: [0x20; 32],
                    expires_at: 1_800_000_900,
                })
                .unwrap(),
                1_800_000_000,
                &[0x32; 12],
            )
            .unwrap();
        session.checkpoint_persisted(1).unwrap();
        assert!(session.handoff_text().unwrap().is_some());
        assert!(session.restored_presence_code().is_some());
        session
    }

    #[test]
    fn scan_handoff_terminal_and_core_error_erase_every_secret_export() {
        use cbcl_pairing::wire::{encode_server_message, CloseReason, ServerMessage};
        for closed in [true, false] {
            let mut session = allocated_session();
            let frame = encode_server_message(&if closed {
                ServerMessage::Closed(CloseReason::Closed)
            } else {
                ServerMessage::Welcome
            })
            .unwrap();
            // Execute the same adapter implementation as the export, without
            // constructing a native JsError on its refusal path.
            let result = session.receive_inner(&frame, 1_800_000_000, &[0x33; 12]);
            assert_eq!(result.is_ok(), closed);
            assert!(session.handoff_text().unwrap().is_none());
            assert!(
                session.restored_presence_code().is_none(),
                "legacy export must follow terminal core state even without effect capture"
            );
        }
    }

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../test-vectors/spec-077-handoff.json")).unwrap()
    }

    #[test]
    fn scan_handoff_public_deadline_preserves_the_exact_carrier_u64() {
        let corpus = vectors();
        for (index, expected) in [1_800_000_900, u64::MAX].into_iter().enumerate() {
            let handoff: cbcl_pairing::credential_v2::CredentialV2Handoff =
                corpus[index]["handoff"].as_str().unwrap().parse().unwrap();
            let carrier = cbcl_pairing::credential_v2::encode_carrier(handoff.carrier()).unwrap();
            assert_eq!(super::cbcl_carrier_relay_expires_at(&carrier).unwrap(), expected);
        }
    }

    #[test]
    fn scan_handoff_normal_invitation_fits_one_qr() {
        let corpus = vectors();
        let text = corpus[0]["handoff"].as_str().unwrap();
        let modules: serde_json::Value =
            serde_json::from_str(&handoff_qr_modules_json(text).unwrap()).unwrap();
        let size = modules["size"].as_u64().unwrap() as usize;
        let dark = modules["dark"].as_array().unwrap();
        assert!(size >= 21 && size <= 177);
        assert_eq!(dark.len(), size * size);
        assert!(dark
            .iter()
            .all(|value| matches!(value.as_u64(), Some(0 | 1))));
        assert!(dark.iter().any(|value| value.as_u64() == Some(1)));
    }

    #[test]
    fn scan_handoff_capacity_refusal_keeps_the_complete_input_intact() {
        let corpus = vectors();
        let text = corpus[1]["handoff"].as_str().unwrap();
        assert_eq!(text.len(), 3691);
        assert_eq!(
            handoff_qr_modules_json(text).unwrap_err(),
            "the pairing invitation does not fit a QR symbol"
        );
        assert_eq!(text, corpus[1]["handoff"].as_str().unwrap());
    }

    #[test]
    fn scan_handoff_qr_rejects_unrecognized_or_public_input() {
        for text in [
            "",
            "SSPAIR9:invalid",
            "SSPAIR1:invalid",
            "https://example.org/",
            "o2ZyZWxheQ",
        ] {
            assert_eq!(
                handoff_qr_modules_json(text).unwrap_err(),
                "the pairing invitation was refused"
            );
        }
    }
}

#[cfg(test)]
mod credential_v2_manual_tests;
