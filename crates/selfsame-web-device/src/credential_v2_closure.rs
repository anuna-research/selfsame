//! Closure-only projection over the existing authenticated checkpoint decoder.
use super::*;
use cbcl_pairing::credential_v2::{
    CredentialV2AllocatorCheckpointInspection as Inspection, CredentialV2AllocatorMode,
    CredentialV2Carrier, CredentialV2Kind, CredentialV2Phase,
};
use selfsame_pairing::credential_v2::{
    self as bodies, CredentialV2BodyAuthority, RecognisedCredentialV2Offer,
};

/// Authenticated saved facts for exact hub closure, with no live allocator.
///
/// Expiry is not closure proof. The browser still verifies the exact hub result
/// and its ownership fence before deleting or replacing durable recovery.
/// Bootstrap/Begin metadata cannot supply missing authenticated body context.
///
/// ```compile_fail
/// use selfsame_web_device::CredentialV2BrowserAllocatorClosureInspection;
/// fn send(view: CredentialV2BrowserAllocatorClosureInspection) { view.start(); }
/// ```
/// ```compile_fail
/// use selfsame_web_device::CredentialV2BrowserAllocatorClosureInspection;
/// fn export(view: CredentialV2BrowserAllocatorClosureInspection) { view.handoff_text(); }
/// ```
/// ```compile_fail
/// use selfsame_web_device::{CredentialV2BrowserAllocatorClosureInspection,
///     CredentialV2BrowserAllocatorSession};
/// fn resume(view: CredentialV2BrowserAllocatorClosureInspection)
///     -> CredentialV2BrowserAllocatorSession { view.into() }
/// ```
#[wasm_bindgen]
pub struct CredentialV2BrowserAllocatorClosureInspection {
    inspection: Option<Inspection>,
    profile: ApplicationProfile,
    carrier: CredentialV2Carrier,
    request_id: [u8; 32],
    intent_nonce: [u8; 32],
    expected_allocator_key: [u8; 32],
    body_authority: CredentialV2BodyAuthority,
    offer: Option<RecognisedCredentialV2Offer>,
}

#[wasm_bindgen]
impl CredentialV2BrowserAllocatorClosureInspection {
    /// Authenticated saved phase, using the live adapter's phase spellings.
    pub fn restored_phase(&self) -> String {
        use cbcl_pairing::credential_v2::CredentialV2AllocatorBootstrapPhase as Bootstrap;
        let Some(view) = self.inspection.as_ref() else {
            return "cancelled".into();
        };
        if let Some(phase) = view.bootstrap_phase() {
            return match phase {
                Bootstrap::Allocated => "allocated",
                Bootstrap::Claimed => "claimed",
                Bootstrap::ShareSent => "share-sent",
                Bootstrap::FinishedSent => "finished-sent",
            }
            .into();
        }
        match view.endpoint_phase() {
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

    /// Authenticated bootstrap mode only; established state supplies no mode.
    pub fn restored_mode(&self) -> Option<String> {
        self.inspection
            .as_ref()?
            .bootstrap_mode()
            .map(|mode| match mode {
                CredentialV2AllocatorMode::Full => "full".into(),
                CredentialV2AllocatorMode::Manual => "manual".into(),
            })
    }

    /// Verify exact signed public context for closure. Elapsed offer time grants
    /// no live authority and is permitted only on this separate inspector.
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
        .map_err(JsError::new)
    }

    /// Verify actual immutable signed status against retained Payload facts or
    /// the exact sealed terminal Receipt, never browser staging metadata.
    pub fn verify_final_status(
        &self,
        final_status: &[u8],
        final_status_digest: &[u8],
        finalized_at: u64,
    ) -> Result<(), JsError> {
        self.verify_final_status_inner(final_status, final_status_digest, finalized_at)
            .map_err(JsError::new)
    }

    /// Drop the inspection projection without a frame, persistence, or effect.
    pub fn cancel(&mut self) -> String {
        self.inspection = None;
        self.offer = None;
        "[]".into()
    }
}

#[cfg(test)]
#[path = "credential_v2_closure_tests.rs"]
mod tests;

impl CredentialV2BrowserAllocatorClosureInspection {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn restore_inner(
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
    ) -> Result<Self, String> {
        let mode = match mode.as_str() {
            "full" => CredentialV2AllocatorMode::Full,
            "manual" => CredentialV2AllocatorMode::Manual,
            _ => return Err("the credential/v2 allocator mode was refused".into()),
        };
        let profile = ApplicationProfile::recognise(profile)
            .map_err(|_| "the credential/v2 application profile was refused")?;
        let carrier = cbcl_pairing::credential_v2::decode_carrier(carrier)
            .map_err(|_| "the credential/v2 carrier was refused")?;
        let request_id = fixed_browser_bytes_inner(request_id, "request ID")?;
        let intent_nonce = fixed_browser_bytes_inner(intent_nonce, "intent nonce")?;
        let expected_allocator_key =
            fixed_browser_bytes_inner(expected_allocator_key, "allocator key")?;
        let seed = Zeroizing::new(fixed_browser_bytes_inner::<32>(
            installation_seed,
            "installation seed",
        )?);
        if generation == 0
            || carrier.application_context() != profile.application_id.as_str()
            || carrier.expected_allocator_key() != Some(&expected_allocator_key)
            || !profile
                .cbcl_pairing_relays
                .iter()
                .any(|d| d.relay_origin == carrier.relay_origin())
        {
            return Err("the credential/v2 checkpoint binding was refused".into());
        }
        let mut wrapping_key = Zeroizing::new([0_u8; 32]);
        hkdf::Hkdf::<sha2::Sha512>::new(Some(carrier.carrier_ceremony_id()), seed.as_ref())
            .expand(V2_ALLOCATOR_CHECKPOINT_INFO, wrapping_key.as_mut())
            .map_err(|_| "credential/v2 checkpoint key derivation failed")?;
        let (body_authority, verifier) =
            bodies::credential_v2_body_authority_for_restore(profile.clone());
        let inspection = Inspection::inspect(
            checkpoint,
            &wrapping_key,
            &carrier,
            generation,
            *profile.digest(),
            now,
            mode,
            Box::new(verifier),
        )
        .map_err(|_| "the credential/v2 allocator checkpoint was refused")?;
        if let Some(object) = inspection.last_received_object() {
            body_authority
                .restore_retained_received_object(object)
                .map_err(|_| "the credential/v2 retained body was refused")?;
        }
        Ok(Self {
            inspection: Some(inspection),
            profile,
            carrier,
            request_id,
            intent_nonce,
            expected_allocator_key,
            body_authority,
            offer: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn restore_offer_context_inner(
        &mut self,
        raw_carrier: &[u8],
        offer_core: &[u8],
        offer_core_digest: &[u8],
        pending_expires_at: u64,
        signed_offer: &[u8],
        authority_response: &[u8],
        authority_digest: &[u8],
        _now: u64,
    ) -> Result<(), &'static str> {
        // Refused replacement context must not leave prior context usable.
        self.offer = None;
        let view = self
            .inspection
            .as_ref()
            .ok_or("the credential/v2 inspection was cancelled")?;
        let carrier = cbcl_pairing::credential_v2::decode_carrier(raw_carrier)
            .map_err(|_| "the credential/v2 carrier was refused")?;
        let digest: [u8; 32] = offer_core_digest
            .try_into()
            .map_err(|_| "the credential/v2 offer digest was refused")?;
        let authority_digest: [u8; 32] = authority_digest
            .try_into()
            .map_err(|_| "the credential/v2 authority digest was refused")?;
        let offer = bodies::recognise_signed_offer(&self.profile, signed_offer)
            .map_err(|_| "the credential/v2 signed offer was refused")?;
        let descriptor = self
            .profile
            .cbcl_pairing_relays
            .iter()
            .find(|d| d.relay_origin == self.carrier.relay_origin())
            .ok_or("the credential/v2 relay was refused")?;
        if carrier != self.carrier
            || offer.offer_core != offer_core
            || offer.claims.offer_core_digest() != &digest
            || <[u8; 32]>::from(Sha256::digest(offer_core)) != digest
            || offer.profile_digest != *self.profile.digest()
            || offer.descriptor_digest != descriptor.digest
            || offer.carrier_digest != self.carrier.digest()
            || offer.claims.carrier_ceremony_id() != self.carrier.carrier_ceremony_id()
            || offer.claims.application_id() != self.carrier.application_context()
            || offer.claims.relay_origin() != self.carrier.relay_origin()
            || offer.claims.device_binding().device_did()
                != selfsame_app_identity::didkey::encode(&self.expected_allocator_key)
            || offer.request_id != self.request_id
            || offer.intent_nonce != self.intent_nonce
            || view
                .transcript_hash()
                .is_some_and(|hash| hash != offer.transcript_hash)
            || offer.expires_at != pending_expires_at
            || pending_expires_at > self.carrier.relay_expires_at()
            || <[u8; 32]>::from(Sha256::digest(authority_response)) != authority_digest
        {
            return Err("the credential/v2 restored offer binding was refused");
        }
        bodies::recognise_authority_status_response(
            &self.profile,
            authority_response,
            &offer.kid,
            *self.carrier.carrier_ceremony_id(),
            digest,
        )
        .map_err(|_| "the credential/v2 signed authority was refused")?;
        if !matches!(view.endpoint_phase(), None | Some(CredentialV2Phase::Begin)) {
            self.body_authority
                .require_bound_offer(&self.profile, &offer)
                .map_err(|_| "the restored body authority was refused")?;
        }
        self.offer = Some(offer);
        Ok(())
    }

    pub(super) fn verify_final_status_inner(
        &self,
        final_status: &[u8],
        final_status_digest: &[u8],
        finalized_at: u64,
    ) -> Result<(), &'static str> {
        let view = self
            .inspection
            .as_ref()
            .ok_or("the credential/v2 inspection was cancelled")?;
        let offer = self
            .offer
            .as_ref()
            .ok_or("the credential/v2 signed offer is unavailable")?;
        let commitment = view
            .receipt_recovery_commitment()
            .ok_or("the credential/v2 receipt commitment is unavailable")?;
        let digest: [u8; 32] = final_status_digest
            .try_into()
            .map_err(|_| "the credential/v2 final status was refused")?;
        let jws = std::str::from_utf8(final_status)
            .map_err(|_| "the credential/v2 final status was refused")?;
        if let Some(binding) = view.terminal_receipt_binding() {
            return bodies::recognise_final_status_for_retained_receipt(
                &self.profile,
                jws,
                digest,
                &offer.signed_offer,
                commitment,
                binding,
                finalized_at,
            )
            .map_err(|_| "the credential/v2 final status was refused");
        }
        let object = view
            .last_received_object()
            .filter(|o| o.kind() == CredentialV2Kind::Payload)
            .ok_or("the credential/v2 payload is unavailable")?;
        let payload = self
            .body_authority
            .retained_payload()
            .map_err(|_| "the credential/v2 payload is unavailable")?;
        let expected = bodies::CredentialV2FinalStatusInput {
            application_id: self.profile.application_id.as_str().into(),
            carrier_ceremony_id: *self.carrier.carrier_ceremony_id(),
            request_id: offer.request_id,
            account_principal_digest: *payload.account_principal_digest(),
            account_scope_id: *payload.account_scope_id(),
            device_did: payload.device_did().into(),
            offer_core_digest: *payload.offer_core_digest(),
            payload_digest: object.content_hash(),
            grant_id: *payload.grant_id(),
            issuer_did: payload.preview_issuer_did().into(),
            receipt_recovery_commitment: commitment,
            finalized_at,
        };
        bodies::recognise_final_status(&self.profile, jws, digest, &expected, &offer.kid)
            .map_err(|_| "the credential/v2 final status was refused")
    }
}
