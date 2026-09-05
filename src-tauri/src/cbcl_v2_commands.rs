//! Tauri shell for standalone credential/v2 consent, preview, and completion.

use cbcl_pairing::credential_v2::{
    CredentialV2ClaimantEffect, CredentialV2Kind, CredentialV2TofuState,
};
use rand::RngCore as _;
use serde::Serialize;
use sha2::Digest as _;
use std::{
    net::TcpStream,
    time::{Duration, Instant},
};
use tauri::State;
use tungstenite::{stream::MaybeTlsStream, Message, WebSocket};
use zeroize::Zeroizing;

use crate::{
    cbcl_transport,
    cbcl_v2_claimant::{
        self, PreparedClaimant, RelayConsentDecision, RelayConsentPlan, RelayConsentView,
    },
    cbcl_v2_completion::{
        NoPrePayloadFaults, PrePayloadBoundary, PrePayloadFaultSink, PrePayloadPendingTransaction,
    },
    cbcl_v2_policy::ExactPairState,
    commands::{AppSession, UiError},
    session::{CredentialV2Attempt, CredentialV2Effect, CredentialV2Flow, CredentialV2Operation},
};

type Result<T> = std::result::Result<T, UiError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CredentialV2Phase {
    Intent,
    PreviewReady,
    PreviewUnpainted,
    ReviewReady,
    Comparing,
    FinalReview,
    PayloadSent,
}

impl CredentialV2Phase {
    fn require(self, expected: Self) -> Result<()> {
        if self != expected {
            return Err(UiError::from("PairingWrongPhase"));
        }
        Ok(())
    }
}

/// Consumes the local preview continuation before the first preparation send.
fn continue_preview<T>(
    phase: &mut CredentialV2Phase,
    attempt: &CredentialV2Attempt,
    compare: impl FnOnce() -> Result<T>,
) -> Result<T> {
    phase.require(CredentialV2Phase::PreviewReady)?;
    *phase = CredentialV2Phase::Comparing;
    let comparison = attempt.run(compare)?;
    *phase = CredentialV2Phase::FinalReview;
    Ok(comparison)
}

/// Live claimant held only after the one-use pre-socket authority is consumed.
pub struct PendingCredentialV2Pairing {
    attempt: CredentialV2Attempt,
    phase: CredentialV2Phase,
    claimant: PreparedClaimant,
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    intent_approve: Option<cbcl_pairing::credential_v2::CredentialV2Object>,
    preview_did: Option<Zeroizing<String>>,
    comparison: Option<cbcl_pairing::credential_v2::CredentialV2Object>,
    recovered_receipt: Option<cbcl_pairing::credential_v2::CredentialV2ClaimantRecoveredReceipt>,
    /// One final-consent authorization.  It is never persisted or exposed to
    /// the web view, and is zeroised when this live pairing is dropped.
    ceremony_custody: Option<CeremonyCustody>,
}

/// A deliberately short, single-ceremony authorization.  Final pairing has
/// several durable checkpoints but only one person decision; re-prompting for
/// every checkpoint makes the biometric prompt an accidental protocol loop.
const CEREMONY_CUSTODY_LIFETIME: Duration = Duration::from_secs(120);

enum CeremonyCustody {
    Legacy {
        root: selfsame_app_identity::hierarchy::HierarchyRoot,
        authorized_at: Instant,
    },
    Bounded(CredentialV2Attempt),
}
impl Drop for CeremonyCustody {
    fn drop(&mut self) {
        if let Self::Bounded(attempt) = self {
            attempt.clear_custody();
        }
    }
}
impl CeremonyCustody {
    fn with_root<T>(
        &self,
        action: impl FnOnce(&selfsame_app_identity::hierarchy::HierarchyRoot) -> Result<T>,
    ) -> Result<T> {
        match self {
            Self::Legacy { root, .. } => action(root),
            Self::Bounded(attempt) => attempt.with_custody(action),
        }
    }
}

impl PendingCredentialV2Pairing {
    fn ensure_ceremony_custody(&mut self, passcode: &str) -> Result<()> {
        self.attempt.check()?;
        if self.attempt.mode() == CredentialV2Flow::SingleLink {
            return if self.ceremony_custody.is_some() {
                Ok(())
            } else {
                Err(UiError::from("PairingExpired"))
            };
        }
        if self
            .ceremony_custody
            .as_ref()
            .is_some_and(|custody| matches!(custody, CeremonyCustody::Legacy { authorized_at, .. } if authorized_at.elapsed() >= CEREMONY_CUSTODY_LIFETIME))
        {
            self.ceremony_custody = None;
        }
        if self.ceremony_custody.is_none() {
            self.ceremony_custody = Some(CeremonyCustody::Legacy {
                root: crate::custody::Custody::unlock_hierarchy_root(passcode)?,
                authorized_at: Instant::now(),
            });
        }
        self.attempt.check()?;
        Ok(())
    }

    fn clear_ceremony_custody(&mut self) {
        self.ceremony_custody = None;
    }
}

/// Authenticated preliminary consent values; no peer string is display authority.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialV2IntentView {
    application_id: String,
    https_origin: String,
    relay_origin: String,
    permissions: Vec<String>,
    device_did: String,
    account_principal_digest: String,
    tofu_state: &'static str,
    transition: CredentialV2TransitionView,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CredentialV2TransitionView {
    kind: &'static str,
    legacy_handle: Option<String>,
    migration_rooms: Vec<String>,
}

/// Relay-decision result, either declined or advanced to authenticated intent.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialV2RelayDecisionView {
    outcome: &'static str,
    intent: Option<CredentialV2IntentView>,
}

/// Authenticated final-review projection after pure preview and comparison.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialV2FinalReviewView {
    application_id: String,
    preview_issuer_did: String,
    preview_fingerprint: crate::commands::Fp,
    comparison: &'static str,
}

/// Preliminary decision result.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialV2PreliminaryDecisionView {
    outcome: &'static str,
    final_review: Option<CredentialV2FinalReviewView>,
}

/// Final decision result. Provisioning continues only from a durable pending
/// checkpoint; decline performs no identity effect.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialV2FinalDecisionView {
    outcome: &'static str,
}

/// Terminal wallet result after the reciprocal binding and installed slot are
/// both durable.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialV2FinishView {
    outcome: &'static str,
}

/// Restart-safe result of the direct application-origin recovery adapter.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialV2RecoveryView {
    outcome: &'static str,
    application_id: String,
    retry_after_seconds: Option<u8>,
    authority_rotation: Option<CredentialV2AuthorityRotationView>,
}

/// Reload result. Capability is true only after every retained and live
/// cryptographic predicate has been rechecked in this invocation.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialV2ReloadView {
    outcome: &'static str,
    application_id: String,
    capability: bool,
    record_retained: bool,
    rotation: Option<CredentialV2InstalledRotationView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CredentialV2InstalledRotationView {
    kind: &'static str,
    retained: String,
    current: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialV2UnlinkView {
    outcome: &'static str,
    application_id: String,
    remote_revocation_claimed: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CredentialV2AuthorityRotationView {
    retained_kid: String,
    current_kid: Option<String>,
    retained_profile_digest: String,
    current_profile_digest: String,
}

/// Recognise one complete confidential invitation before profile or relay effects.
#[tauri::command]
pub async fn cbcl_v2_recognise_handoff(
    handoff: String,
    session: State<'_, AppSession>,
) -> Result<RelayConsentView> {
    let _input = Zeroizing::new(handoff);
    let _ = session;
    Err(UiError::from("PairingWrongMode"))
}

/// Explicit legacy carrier and presence entry shares the same attempt and policy gate.
#[tauri::command]
pub async fn cbcl_v2_recognise(
    invitation: String,
    presence_code: String,
    session: State<'_, AppSession>,
) -> Result<RelayConsentView> {
    recognise_v2_entry(
        CredentialV2Entry::Legacy {
            invitation,
            presence_code: Zeroizing::new(presence_code),
        },
        &session,
    )
    .await
}

enum CredentialV2Entry {
    Legacy {
        invitation: String,
        presence_code: Zeroizing<String>,
    },
}

async fn recognise_v2_entry(
    input: CredentialV2Entry,
    session: &AppSession,
) -> Result<RelayConsentView> {
    let operation = {
        let mut guard = session
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard
            .cbcl_v2_attempts
            .require_entry_mode(CredentialV2Flow::LegacyTwoDecision)?;
        let operation = guard.cbcl_v2_attempts.begin()?;
        guard.pending_cbcl_v2_relay = None;
        guard.pending_cbcl_v2 = None;
        operation
    };
    operation.attempt.check()?;
    let now = crate::commands::now() as i64;
    let plan = match input {
        CredentialV2Entry::Legacy {
            invitation,
            presence_code,
        } => {
            cbcl_v2_claimant::recognise_claimant_invitation(
                invitation.trim(),
                presence_code.trim(),
                now,
            )
            .await?
        }
    };
    let view = plan.view();
    let mut guard = session
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.update_cbcl_v2_attempt(&operation.attempt, |guard| {
        guard.pending_cbcl_v2_relay = Some(plan);
        Ok(())
    })?;
    operation.retain();
    Ok(view)
}

/// Consume the exact relay decision, open WSS only on approval, and stop at
/// the authenticated preliminary-intent display.
#[tauri::command]
pub async fn cbcl_v2_relay_decide(
    approve: bool,
    session: State<'_, AppSession>,
) -> Result<CredentialV2RelayDecisionView> {
    let (plan, operation) = take_relay_plan(&session)?;
    operation.attempt.check()?;
    let decision = match (plan.pair_state(), approve) {
        (_, false) => RelayConsentDecision::Decline,
        (ExactPairState::NewPair, true) => RelayConsentDecision::Approve,
        (ExactPairState::TrustedPair, true) => RelayConsentDecision::ExistingTrust,
    };
    let Some(capability) = cbcl_v2_claimant::authorise_claimant_relay(plan, decision)? else {
        ensure_current(&session, &operation.attempt)?;
        return Ok(CredentialV2RelayDecisionView {
            outcome: "declined",
            intent: None,
        });
    };

    let mut cpace_scalar = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut cpace_scalar);
    let claimant = cbcl_v2_claimant::prepare_claimant(capability, cpace_scalar)?;
    let relay_origin = claimant.relay_origin().to_owned();
    let target = cbcl_transport::relay_target(&relay_origin)
        .map_err(|_| UiError::from("PairingRelayRefused"))?;
    let attempt = operation.attempt.clone();
    let (pending, intent) = pairing_blocking(&operation, move || {
        let socket = attempt.run(|| cbcl_transport::connect_wss(&target).map_err(map_transport))?;
        pump_to_offer(claimant, socket, attempt)
    })
    .await?;
    put_pending(&session, pending, operation)?;
    Ok(CredentialV2RelayDecisionView {
        outcome: "intent",
        intent: Some(intent),
    })
}

/// Commit preliminary consent. Approval permits exactly one custody call for
/// pure DID preview and returns it before preparation disclosure. The UI must
/// paint this result before invoking cbcl_v2_compare. No identity effect occurs.
#[tauri::command]
pub async fn cbcl_v2_preliminary_decide(
    approve: bool,
    passcode: Option<String>,
    session: State<'_, AppSession>,
) -> Result<CredentialV2PreliminaryDecisionView> {
    let (mut pending, operation) = take_pending(&session, CredentialV2Phase::Intent)?;
    let offer = pending
        .claimant
        .authenticated_offer()
        .cloned()
        .ok_or_else(|| UiError::from("PairingFailed"))?;
    let decision = pending
        .claimant
        .body_authority()
        .intent_decision(
            &offer,
            if approve {
                selfsame_pairing::credential_v2::CredentialV2IntentDecision::Approve
            } else {
                selfsame_pairing::credential_v2::CredentialV2IntentDecision::Decline
            },
        )
        .map_err(|_| UiError::from("PairingFailed"))?;
    let passcode = if approve {
        Some(
            passcode
                .filter(|value| !value.is_empty())
                .ok_or_else(|| UiError::from("PresenceRequired"))?,
        )
    } else {
        None
    };
    send_claimant_object(&mut pending, &decision)?;
    if !approve {
        ensure_current(&session, &operation.attempt)?;
        return Ok(CredentialV2PreliminaryDecisionView {
            outcome: "declined",
            final_review: None,
        });
    }
    let passcode = Zeroizing::new(passcode.expect("approved path checked presence above"));
    let (pending, view) = pairing_blocking(&operation, move || {
        wait_outbound_ack(&mut pending)?;
        let (preview_did, view) = prepare_preview(
            &mut pending.phase,
            &pending.attempt,
            pending.claimant.profile().application_id.as_str(),
            || preview_identity(&pending.claimant, &passcode),
        )?;
        pending.preview_did = Some(preview_did);
        pending.intent_approve = Some(decision);
        Ok((pending, view))
    })
    .await?;
    put_pending(&session, pending, operation)?;
    Ok(view)
}

/// One continuation after the local preview has painted. It carries no new
/// decision, custody input, or peer-supplied identity value.
#[tauri::command]
pub async fn cbcl_v2_compare(
    session: State<'_, AppSession>,
) -> Result<CredentialV2FinalReviewView> {
    let (mut pending, operation) = take_pending(&session, CredentialV2Phase::PreviewReady)?;
    let (pending, view) = pairing_blocking(&operation, move || {
        let attempt = pending.attempt.clone();
        let mut phase = pending.phase;
        let comparison = continue_preview(&mut phase, &attempt, || {
            let decision = pending
                .intent_approve
                .as_ref()
                .ok_or_else(|| UiError::from("PairingFailed"))?;
            let preview = pending
                .preview_did
                .as_ref()
                .ok_or_else(|| UiError::from("PairingFailed"))?;
            let preparation = pending
                .claimant
                .body_authority()
                .preparation(decision, preview)
                .map_err(|_| UiError::from("PairingFailed"))?;
            send_claimant_object(&mut pending, &preparation)?;
            pump_to_comparison(&mut pending)
        })?;
        let comparison_name = match comparison.kind() {
            CredentialV2Kind::ComparisonConfirmed => "no-binding-person-compared",
            CredentialV2Kind::BindingConfirmed => "bound-same-did",
            _ => return Err(UiError::from("PairingFailed")),
        };
        pending.phase = phase;
        pending.comparison = Some(comparison);
        let view = final_review_view(&pending, comparison_name)?;
        Ok((pending, view))
    })
    .await?;
    put_pending(&session, pending, operation)?;
    Ok(view)
}

fn prepare_preview(
    phase: &mut CredentialV2Phase,
    attempt: &CredentialV2Attempt,
    application_id: &str,
    derive: impl FnOnce() -> Result<String>,
) -> Result<(Zeroizing<String>, CredentialV2PreliminaryDecisionView)> {
    phase.require(CredentialV2Phase::Intent)?;
    let did = attempt.run(|| derive().map(Zeroizing::new))?;
    let view = CredentialV2PreliminaryDecisionView {
        outcome: "preview",
        final_review: Some(review_projection(application_id, &did, "waiting")),
    };
    *phase = CredentialV2Phase::PreviewReady;
    Ok((did, view))
}

fn review_projection(
    application_id: &str,
    preview: &str,
    comparison: &'static str,
) -> CredentialV2FinalReviewView {
    CredentialV2FinalReviewView {
        application_id: application_id.into(),
        preview_issuer_did: preview.into(),
        preview_fingerprint: selfsame_core::fingerprint::fingerprint_did(preview).into(),
        comparison,
    }
}

fn final_review_view(
    pending: &PendingCredentialV2Pairing,
    comparison: &'static str,
) -> Result<CredentialV2FinalReviewView> {
    pending.attempt.check()?;
    let preview = pending
        .preview_did
        .as_ref()
        .ok_or_else(|| UiError::from("PairingFailed"))?;
    Ok(review_projection(
        pending.claimant.profile().application_id.as_str(),
        preview,
        comparison,
    ))
}

/// Check cancellation around the existing injectable transaction boundaries.
struct CancellationFaults<'a, F> {
    attempt: &'a CredentialV2Attempt,
    inner: &'a mut F,
    entry: Option<CredentialV2Effect>,
}

impl<F: PrePayloadFaultSink> PrePayloadFaultSink for CancellationFaults<'_, F> {
    fn after(&mut self) -> Result<()> {
        self.attempt.check()
    }
    fn before(&mut self, boundary: PrePayloadBoundary) -> Result<()> {
        self.attempt.check()?;
        self.inner.before(boundary)?;
        self.entry = Some(self.attempt.enter()?);
        Ok(())
    }
}

/// Commit the second person decision. Final approval is checkpointed into the
/// application's secure-store slot before its protocol frame is released.
#[tauri::command]
pub async fn cbcl_v2_final_decide(
    approve: bool,
    passcode: Option<String>,
    session: State<'_, AppSession>,
) -> Result<CredentialV2FinalDecisionView> {
    let mut faults = NoPrePayloadFaults;
    cbcl_v2_final_decide_with_faults(approve, passcode, session, &mut faults).await
}

async fn cbcl_v2_final_decide_with_faults(
    approve: bool,
    passcode: Option<String>,
    session: State<'_, AppSession>,
    faults: &mut impl PrePayloadFaultSink,
) -> Result<CredentialV2FinalDecisionView> {
    let (mut pending, operation) = take_pending(&session, CredentialV2Phase::FinalReview)?;
    let comparison = pending
        .comparison
        .clone()
        .ok_or_else(|| UiError::from("PairingFailed"))?;
    let final_decision = pending
        .claimant
        .body_authority()
        .final_decision(
            &comparison,
            if approve {
                selfsame_pairing::credential_v2::CredentialV2FinalDecision::Approve
            } else {
                selfsame_pairing::credential_v2::CredentialV2FinalDecision::Decline
            },
        )
        .map_err(|_| UiError::from("PairingFailed"))?;
    if !approve {
        send_claimant_object(&mut pending, &final_decision)?;
        ensure_current(&session, &operation.attempt)?;
        return Ok(CredentialV2FinalDecisionView {
            outcome: "declined",
        });
    }

    let passcode = passcode
        .filter(|value| !value.is_empty())
        .ok_or_else(|| UiError::from("PresenceRequired"))?;
    let ceremony_custody = CeremonyCustody::Legacy {
        root: pending
            .attempt
            .run(|| Ok(crate::custody::Custody::unlock_hierarchy_root(&passcode)?))?,
        authorized_at: Instant::now(),
    };
    complete_approved(
        pending,
        operation,
        final_decision,
        ceremony_custody,
        &session,
        faults,
    )
    .await
}

/// Shared transaction executor: its caller already owns the distinct protocol
/// final approval and native custody. It is not a command or a consent source.
async fn complete_approved(
    mut pending: PendingCredentialV2Pairing,
    operation: CredentialV2Operation,
    final_decision: cbcl_pairing::credential_v2::CredentialV2Object,
    ceremony_custody: CeremonyCustody,
    session: &AppSession,
    faults: &mut impl PrePayloadFaultSink,
) -> Result<CredentialV2FinalDecisionView> {
    let attempt = pending.attempt.clone();
    let mut cancellation_faults = CancellationFaults {
        attempt: &attempt,
        inner: faults,
        entry: None,
    };
    let faults = &mut cancellation_faults;
    let comparison = pending
        .comparison
        .clone()
        .ok_or_else(|| UiError::from("PairingFailed"))?;
    let preview_did = pending
        .preview_did
        .clone()
        .ok_or_else(|| UiError::from("PairingFailed"))?;
    attempt.run(|| Ok(crate::custody::Custody::require_backup_confirmed()?))?;
    let offer_object = pending
        .claimant
        .authenticated_offer()
        .cloned()
        .ok_or_else(|| UiError::from("PairingFailed"))?;
    let recognised = selfsame_pairing::credential_v2::recognise_signed_offer(
        pending.claimant.profile(),
        offer_object.body(),
    )
    .map_err(|_| UiError::from("PairingFailed"))?;
    let now = crate::commands::now();
    if now >= recognised.expires_at {
        return Err(UiError::from("PairingOfferExpired"));
    }
    let intent_approve = pending
        .intent_approve
        .clone()
        .ok_or_else(|| UiError::from("PairingFailed"))?;
    let application_id = pending
        .claimant
        .profile()
        .application_id
        .as_str()
        .to_owned();
    let profile_digest = *pending.claimant.profile().digest();
    let carrier = pending.claimant.carrier().clone();
    let root_generation =
        crate::cbcl_v2_completion::root_generation(&crate::custody::Custody::root_public_key()?);
    let preview_fingerprint: [u8; 32] = sha2::Sha256::digest(preview_did.as_bytes()).into();
    let mut checkpoint_nonce = [0_u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut checkpoint_nonce);
    attempt.check()?;
    let (generation, checkpoint) = ceremony_custody.with_root(|root| -> Result<_> {
        let claims = recognised.claims.account_provenance();
        let scope =
            selfsame_app_identity::scope::AccountScopeId::from_octets(*claims.account_scope_id());
        let home = selfsame_app_identity::hierarchy::derive(
            root,
            &pending.claimant.profile().application_id,
            &scope,
        );
        let final_did = home
            .home_did()
            .map_err(|_| UiError::from("PairingIdentityUnavailable"))?;
        let final_fingerprint: [u8; 32] = sha2::Sha256::digest(final_did.as_bytes()).into();
        if final_did != *preview_did || final_fingerprint != preview_fingerprint {
            return Err(UiError::from("PairingPreviewChanged"));
        }
        let wrapping_key = crate::cbcl_v2_completion::checkpoint_wrapping_key(
            root,
            &application_id,
            carrier.carrier_ceremony_id(),
        )?;
        let effects = pending
            .claimant
            .core_mut()
            .prepare_final_approval(
                &final_decision,
                &wrapping_key,
                cbcl_pairing::credential_v2::CredentialV2CheckpointNonce::from_csprng(
                    checkpoint_nonce,
                ),
                now,
            )
            .map_err(|_| UiError::from("PairingFailed"))?;
        let mut effects = effects.into_iter();
        let Some(CredentialV2ClaimantEffect::Checkpoint {
            generation,
            checkpoint,
        }) = effects.next()
        else {
            return Err(UiError::from("PairingFailed"));
        };
        if effects.next().is_some() {
            return Err(UiError::from("PairingFailed"));
        }
        Ok((generation, checkpoint))
    })?;

    let durable = crate::cbcl_v2_completion::PendingCredentialV2Completion::new(
        crate::cbcl_v2_completion::PendingCredentialV2Input {
            root_generation,
            application_id: &application_id,
            profile_digest,
            offer_profile_octets: pending.claimant.profile_octets(),
            carrier: &carrier,
            offer: &offer_object,
            intent_approve: &intent_approve,
            comparison: &comparison,
            final_approve: &final_decision,
            preview_issuer_did: &preview_did,
            offer_expires_at: recognised.expires_at,
            checkpoint_generation: generation,
            checkpoint: &checkpoint,
        },
    )?;
    let durable = durable.with_flow(attempt.mode());
    let mut transaction = attempt.run(|| PrePayloadPendingTransaction::begin(durable))?;
    transaction.try_step(faults, PrePayloadBoundary::FinalApprovalRelease, || {
        let effects = pending
            .claimant
            .core_mut()
            .checkpoint_persisted(generation)
            .map_err(|_| UiError::from("PairingFailed"))?;
        send_effects(&mut pending.socket, &pending.attempt, effects)
    })?;

    // The blind relay acknowledgement changes the cached-frame projection.
    // Seal and replace the pending record before any identity signature.
    let acknowledgement =
        transaction.try_step(faults, PrePayloadBoundary::AcknowledgementRead, || {
            read_binary(&mut pending.socket, &pending.attempt)
        })?;
    let acknowledgement_now = crate::commands::now();
    let mut acknowledgement_nonce = [0_u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut acknowledgement_nonce);
    let (acknowledgement_generation, acknowledgement_checkpoint) = transaction.try_step(
        faults,
        PrePayloadBoundary::AcknowledgementRecognition,
        || {
            let acknowledgement_effects = ceremony_custody.with_root(|root| -> Result<_> {
                let wrapping_key = crate::cbcl_v2_completion::checkpoint_wrapping_key(
                    root,
                    &application_id,
                    carrier.carrier_ceremony_id(),
                )?;
                pending
                    .claimant
                    .core_mut()
                    .receive_durable(
                        &acknowledgement,
                        acknowledgement_now,
                        &wrapping_key,
                        cbcl_pairing::credential_v2::CredentialV2CheckpointNonce::from_csprng(
                            acknowledgement_nonce,
                        ),
                    )
                    .map_err(|_| UiError::from("PairingFailed"))
            })?;
            one_checkpoint(acknowledgement_effects)
        },
    )?;
    let acknowledged = transaction
        .current()
        .with_checkpoint(acknowledgement_generation, &acknowledgement_checkpoint)?;
    transaction.replace_at(
        faults,
        PrePayloadBoundary::AcknowledgementCheckpointReplacement,
        acknowledged,
    )?;
    transaction.try_step(
        faults,
        PrePayloadBoundary::AcknowledgementCheckpointCommit,
        || {
            let after_acknowledgement = pending
                .claimant
                .core_mut()
                .checkpoint_persisted(acknowledgement_generation)
                .map_err(|_| UiError::from("PairingFailed"))?;
            if !after_acknowledgement.is_empty() {
                return Err(UiError::from("PairingFailed"));
            }
            Ok(())
        },
    )?;

    let profile = pending.claimant.profile().clone();
    let (plan, effect_time, grant_id) =
        transaction.try_step(faults, PrePayloadBoundary::PlanConstruction, || {
            let plan =
                crate::cbcl_v2_completion::CredentialV2ProvisioningPlan::from_authenticated_offer(
                    &profile,
                    &recognised,
                    &preview_did,
                )?;
            let effect_time = i64::try_from(crate::commands::now())
                .map_err(|_| UiError::from("PairingProvisioningRefused"))?;
            if u64::try_from(effect_time).map_or(true, |value| value >= recognised.expires_at) {
                return Err(UiError::from("PairingOfferExpired"));
            }
            let mut grant_id = [0_u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut grant_id);
            Ok((plan, effect_time, grant_id))
        })?;
    let planned = transaction.current().planned(effect_time, grant_id)?;
    transaction.replace_at(faults, PrePayloadBoundary::PlannedStageReplacement, planned)?;

    // First final signature: issuer creation only. The deterministic plan was
    // durable before this ceremony authorization, and the preview is
    // re-derived before issuer construction.
    let issuer = transaction.try_step(faults, PrePayloadBoundary::IssuerCustody, || {
        ceremony_custody.with_root(|root| {
            crate::cbcl_v2_completion::build_issuer_artifacts(root, &plan, effect_time)
        })
    })?;
    let issuer_created = transaction.current().issuer_created(&issuer)?;
    transaction.replace_at(
        faults,
        PrePayloadBoundary::IssuerStageReplacement,
        issuer_created,
    )?;

    transaction.before_async(faults, PrePayloadBoundary::IssuerPublication)?;
    let publication = attempt
        .io(async {
            selfsame_app_identity_net::state::publish_issuer_identity(&profile, &issuer.identity)
                .await
                .map_err(|_| UiError::from("PairingResolverUnavailable"))
        })
        .await?;
    attempt.check()?;
    if publication.acknowledged.is_empty() {
        return Err(UiError::from("PairingResolverUnavailable"));
    }
    transaction.before_async(faults, PrePayloadBoundary::ResolverVerification)?;
    let resolved = attempt
        .io(async {
            selfsame_app_identity_net::state::resolve_closure(
                &profile,
                &issuer.identity.did,
                None,
                selfsame_app_identity_net::state::Acceptance::Repeat,
            )
            .await
            .map_err(|_| UiError::from("PairingResolverUnavailable"))
        })
        .await?;
    attempt.check()?;
    if resolved.document.did.as_str() != issuer.identity.did
        || resolved.document.is_deactivated()
        || !resolved
            .document
            .also_known_as()
            .iter()
            .any(|value| value == &issuer.identity.acct_uri)
    {
        return Err(UiError::from("PairingResolverRefused"));
    }

    // Grant construction follows verified resolver closure. Reciprocal
    // WebFinger cannot exist until the hub consumes this grant; the browser/hub
    // finalizer provisions it atomically, and wallet installation verifies it
    // from the authenticated receipt before granting capability.
    let grant = transaction.try_step(faults, PrePayloadBoundary::GrantConstruction, || {
        ceremony_custody.with_root(|root| {
            crate::cbcl_v2_completion::build_grant_artifacts(
                root,
                &plan,
                &issuer,
                grant_id,
                effect_time,
                profile.revocation.max_grant_lifetime_seconds,
            )
        })
    })?;
    let provisioned = transaction.current().provisioned(&grant)?;
    transaction.replace_at(
        faults,
        PrePayloadBoundary::ProvisionedStageReplacement,
        provisioned,
    )?;

    let payload = transaction.try_step(faults, PrePayloadBoundary::PayloadConstruction, || {
        pending
            .claimant
            .body_authority()
            .payload(
                &final_decision,
                selfsame_pairing::credential_v2::CredentialV2PayloadInput {
                    grant_id: grant.grant_id,
                    grant: grant.grant.clone(),
                },
            )
            .map_err(|_| UiError::from("PairingFailed"))
    })?;
    let (payload_generation, payload_checkpoint) = transaction.try_step(
        faults,
        PrePayloadBoundary::PayloadCheckpointPreparation,
        || {
            let payload_now = crate::commands::now();
            if payload_now >= recognised.expires_at {
                return Err(UiError::from("PairingOfferExpired"));
            }
            let mut payload_nonce = [0_u8; 12];
            rand::rngs::OsRng.fill_bytes(&mut payload_nonce);
            let payload_effects = ceremony_custody.with_root(|root| -> Result<_> {
                let wrapping_key = crate::cbcl_v2_completion::checkpoint_wrapping_key(
                    root,
                    &application_id,
                    carrier.carrier_ceremony_id(),
                )?;
                pending
                    .claimant
                    .core_mut()
                    .prepare_payload(
                        &payload,
                        &wrapping_key,
                        cbcl_pairing::credential_v2::CredentialV2CheckpointNonce::from_csprng(
                            payload_nonce,
                        ),
                        payload_now,
                    )
                    .map_err(|_| UiError::from("PairingFailed"))
            })?;
            one_checkpoint(payload_effects)
        },
    )?;
    let payload_prepared = transaction
        .current()
        .payload_prepared(payload.content_hash())?
        .with_checkpoint(payload_generation, &payload_checkpoint)?;
    let _payload_prepared = attempt.run(|| transaction.commit_payload(payload_prepared))?;
    let payload_release = attempt.run(|| {
        pending
            .claimant
            .core_mut()
            .checkpoint_persisted(payload_generation)
            .map_err(|_| UiError::from("PairingFailed"))
    })?;
    send_effects(&mut pending.socket, &pending.attempt, payload_release)?;
    pending.ceremony_custody = Some(ceremony_custody);
    pending.phase = CredentialV2Phase::PayloadSent;
    put_pending(session, pending, operation)?;
    Ok(CredentialV2FinalDecisionView {
        outcome: "payload-sent",
    })
}

/// Wait for the allocator's authenticated Receipt, verify the hub's immutable
/// status and live reciprocal account binding, atomically install the grant,
/// and only then release the receipt acknowledgement.
#[tauri::command]
pub async fn cbcl_v2_finish(
    passcode: Option<String>,
    session: State<'_, AppSession>,
) -> Result<CredentialV2FinishView> {
    // Mode refusal precedes even the legacy presence requirement, while a
    // missing presence value must not take and cancel the live pending worker.
    session
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .cbcl_v2_attempts
        .require_mode(CredentialV2Flow::LegacyTwoDecision)?;
    let passcode = passcode
        .filter(|value| !value.is_empty())
        .ok_or_else(|| UiError::from("PresenceRequired"))?;
    let (pending, operation) = take_pending(&session, CredentialV2Phase::PayloadSent)?;
    finish_pending(pending, operation, Zeroizing::new(passcode), &session).await
}

async fn finish_pending(
    pending: PendingCredentialV2Pairing,
    operation: CredentialV2Operation,
    passcode: Zeroizing<String>,
    session: &AppSession,
) -> Result<CredentialV2FinishView> {
    let attempt = operation.attempt.clone();
    let (mut pending, prepared) = pairing_blocking(&operation, move || {
        Ok(prepare_received_receipt(pending, &passcode))
    })
    .await?;
    let (durable, receipt_recovery_commitment) = match prepared {
        Ok(value) => value,
        Err(error) => {
            pending.clear_ceremony_custody();
            put_pending(session, pending, operation)?;
            return Err(error);
        }
    };
    let receipt = pending
        .recovered_receipt
        .as_ref()
        .ok_or_else(|| UiError::from("PairingReceiptRefused"))?;
    let installed =
        match crate::cbcl_v2_completion::InstalledCredentialV2Link::from_authenticated_receipt(
            &durable,
            pending.claimant.profile_octets(),
            receipt.object(),
            receipt_recovery_commitment,
        ) {
            Ok(value) => value,
            Err(error) => {
                pending.clear_ceremony_custody();
                put_pending(session, pending, operation)?;
                return Err(error);
            }
        };
    let live_profile = pending.claimant.profile().clone();
    let live_account = match installed.account() {
        Ok(value) => value,
        Err(error) => {
            pending.clear_ceremony_custody();
            put_pending(session, pending, operation)?;
            return Err(error);
        }
    };
    let live_issuer_did = installed.issuer_did().to_owned();
    attempt.check()?;
    let jrd = match verify_live_installation_guarded(
        live_profile,
        live_account,
        live_issuer_did,
        &attempt,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            pending.clear_ceremony_custody();
            put_pending(session, pending, operation)?;
            return Err(error);
        }
    };
    if let Err(error) = install_guarded(&attempt, &durable, &installed, &jrd) {
        pending.clear_ceremony_custody();
        put_pending(session, pending, operation)?;
        return Err(error);
    }

    // Installation is already durable. Failure to deliver the relay ACK must
    // not roll back or misreport the installed account capability.
    if let Some(receipt) = pending.recovered_receipt.take() {
        if let Ok(effects) = pending
            .claimant
            .core_mut()
            .commit_recovered_receipt(receipt)
        {
            let _ = pairing_blocking(&operation, move || {
                send_effects(&mut pending.socket, &pending.attempt, effects)
            })
            .await;
        }
    }
    ensure_current(session, &attempt)?;
    Ok(CredentialV2FinishView {
        outcome: "installed",
    })
}

/// Discover crash-safe claimant slots without exposing checkpoint or recovery
/// material to JavaScript.
#[tauri::command]
pub async fn cbcl_v2_pending_recoveries() -> Result<Vec<String>> {
    crate::cbcl_v2_completion::pending_application_ids()
}

/// List every interrupted local link so pre-payload failures remain visible
/// and person-removable after restart without exposing checkpoint material.
#[tauri::command]
pub async fn cbcl_v2_pending_links(
) -> Result<Vec<crate::cbcl_v2_completion::PendingCredentialV2LinkSummary>> {
    crate::cbcl_v2_completion::pending_links()
}

/// List installed credential/v2 links without returning grants, scopes,
/// recovery material, or receipt evidence to JavaScript.
#[tauri::command]
pub async fn cbcl_v2_installed_links(
) -> Result<Vec<crate::cbcl_v2_completion::InstalledCredentialV2LinkSummary>> {
    crate::cbcl_v2_completion::installed_links()
}

/// Re-establish one installed application capability after restart.
///
/// The caller must name the account handle it is attempting to use. A changed
/// handle is refused before any enrollment or pairing frame can be emitted.
/// The immutable historical hub status is reverified while the current
/// profile, resolver closure, reciprocal account binding, revocation set, and
/// stored grant are fetched and checked afresh.
#[tauri::command]
pub async fn cbcl_v2_reload_verify(
    application_id: String,
    observed_account: String,
    approve_rotation: bool,
) -> Result<CredentialV2ReloadView> {
    use crate::cbcl_v2_completion::{
        CredentialV2ReloadObservation as Observation, CredentialV2ReloadOutcome as Outcome,
    };

    let installed = crate::cbcl_v2_completion::load_installed(&application_id)?;
    let current_root_generation =
        crate::cbcl_v2_completion::root_generation(&crate::custody::Custody::root_public_key()?);
    if installed
        .require_root_generation(current_root_generation)
        .is_err()
    {
        return reload_view(
            &installed,
            Outcome::FreshPairingRequired,
            approve_rotation,
            None,
        );
    }
    if observed_account != installed.account_text() {
        return reload_view(&installed, Outcome::HandleChanged, approve_rotation, None);
    }

    let application = selfsame_app_identity::profile::ApplicationId::parse(&application_id)
        .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
    let now = i64::try_from(crate::commands::now())
        .map_err(|_| UiError::from("PairingProfileUnavailable"))?;
    let current = match selfsame_app_identity_net::profile::fetch(&application, now).await {
        Ok(value) => value,
        Err(_) => {
            let check = installed.verify_reload(Observation::Unavailable, None)?;
            return reload_view(&installed, check.outcome, approve_rotation, None);
        }
    };
    let offer_key_retained = installed.offer_key_retained_in(&current.profile)?;
    if current.profile.account_authority != installed.account_authority() || !offer_key_retained {
        let rotation = CredentialV2InstalledRotationView {
            kind: if current.profile.account_authority != installed.account_authority() {
                "account-authority"
            } else {
                "profile-signing-key"
            },
            retained: if current.profile.account_authority != installed.account_authority() {
                installed.account_authority().into()
            } else {
                installed.current_profile_digest().into()
            },
            current: if current.profile.account_authority != installed.account_authority() {
                current.profile.account_authority.clone()
            } else {
                selfsame_app_identity::codec::b64url(current.profile.digest())
            },
        };
        return reload_view(
            &installed,
            Outcome::AuthorityRotation,
            approve_rotation,
            Some(rotation),
        );
    }

    let account = installed.account()?;
    let jrd = match selfsame_app_identity_net::webfinger::fetch(&account).await {
        Ok(value) => value,
        Err(error) => match classify_webfinger_failure(error) {
            WebFingerReloadFailure::HubDeleted => {
                let check = installed.verify_reload(Observation::HubDeleted, None)?;
                return reload_view(&installed, check.outcome, approve_rotation, None);
            }
            WebFingerReloadFailure::Unavailable => {
                let check = installed.verify_reload(Observation::Unavailable, None)?;
                return reload_view(&installed, check.outcome, approve_rotation, None);
            }
            WebFingerReloadFailure::InvalidBinding => {
                return reload_verified_view(
                    &installed,
                    &current,
                    current_root_generation,
                    &observed_account,
                    installed.issuer_did(),
                    offer_key_retained,
                    false,
                    true,
                    approve_rotation,
                    None,
                );
            }
        },
    };
    if jrd.subject != observed_account {
        return reload_verified_view(
            &installed,
            &current,
            current_root_generation,
            &observed_account,
            installed.issuer_did(),
            offer_key_retained,
            false,
            true,
            approve_rotation,
            None,
        );
    }
    if !jrd
        .aliases
        .iter()
        .any(|value| value == installed.issuer_did())
    {
        if let Some(rotated) = jrd.aliases.iter().find(|value| {
            value.as_str() != installed.issuer_did() && value.parse::<did_crdt::Did>().is_ok()
        }) {
            let rotation = CredentialV2InstalledRotationView {
                kind: "issuer",
                retained: installed.issuer_did().into(),
                current: rotated.clone(),
            };
            return reload_verified_view(
                &installed,
                &current,
                current_root_generation,
                &observed_account,
                rotated,
                offer_key_retained,
                false,
                false,
                approve_rotation,
                Some(rotation),
            );
        }
        return reload_verified_view(
            &installed,
            &current,
            current_root_generation,
            &observed_account,
            installed.issuer_did(),
            offer_key_retained,
            false,
            true,
            approve_rotation,
            None,
        );
    }

    let quorum = match selfsame_app_identity_net::state::resolve_path_b_quorum(
        &current.profile,
        installed.issuer_did(),
    )
    .await
    {
        Ok(value) => value,
        Err(_) => {
            let check = installed.verify_reload(Observation::Unavailable, None)?;
            return reload_view(&installed, check.outcome, approve_rotation, None);
        }
    };
    let observations = path_b_observations(&quorum, now)?;
    let agreed = selfsame_app_identity::path_b::agree_closures(&current.profile, &observations)
        .map_err(|_| UiError::from("PairingResolverRefused"))?;
    let revoked = agreed
        .revoked_credential_ids
        .iter()
        .any(|value| value == installed.credential_id());
    let issuer = selfsame_app_identity::path_b::issuer_state_of(&agreed, now);
    let reciprocal = selfsame_app_identity::alias::verify_reciprocal_binding(
        &jrd,
        &account,
        installed.issuer_did(),
        &agreed.also_known_as,
    )
    .is_ok();
    let device_key = installed.installation_device_public_key()?;
    let request = selfsame_app_identity::path_b::GrantRequest::new(
        &current.profile,
        &account,
        &device_key,
        &[],
        now,
        0,
    );
    let verified = if reciprocal && !revoked {
        selfsame_app_identity::path_b::rehydrate_verified_grant(
            &request,
            &issuer,
            &jrd,
            None,
            installed.grant_bytes(),
        )
        .ok()
    } else {
        None
    };
    let grant_matches = verified.as_ref().is_some_and(|grant| {
        grant.account_did == installed.issuer_did()
            && grant.grant_id == installed.credential_id()
            && grant.device_public_key == device_key
    });
    reload_verified_view(
        &installed,
        &current,
        current_root_generation,
        &observed_account,
        installed.issuer_did(),
        offer_key_retained,
        grant_matches,
        revoked || !reciprocal,
        approve_rotation,
        None,
    )
}

/// Explicitly remove only one local credential/v2 application link. This
/// authenticates presence but does not use, rotate, or erase the hierarchy
/// root and never claims to revoke the remote hub record.
#[tauri::command]
pub async fn cbcl_v2_unlink(
    application_id: String,
    confirmation: bool,
    passcode: String,
) -> Result<CredentialV2UnlinkView> {
    if crate::cbcl_v2_completion::authorise_unlink(confirmation)
        == crate::cbcl_v2_completion::CredentialV2UnlinkOutcome::ConfirmationRequired
    {
        return Ok(CredentialV2UnlinkView {
            outcome: "confirmation-required",
            application_id,
            remote_revocation_claimed: false,
        });
    }
    if passcode.is_empty() {
        return Err(UiError::from("PresenceRequired"));
    }
    let local = crate::cbcl_v2_completion::load_local_link(&application_id)?;
    let pending = local.is_pending();
    local.require_root_generation(crate::cbcl_v2_completion::root_generation(
        &crate::custody::Custody::root_public_key()?,
    ))?;
    crate::custody::Custody::use_hierarchy_root(&passcode, |_| ())?;
    crate::cbcl_v2_completion::unlink_local(&local)?;
    Ok(CredentialV2UnlinkView {
        outcome: if pending { "abandoned" } else { "unlinked" },
        application_id,
        remote_revocation_claimed: false,
    })
}

// This is the closed assembly boundary for ten independently authenticated
// reload facts. Grouping them would only move the same trust decisions into an
// unverified bag, so keep the call explicit and acknowledge the lint here.
#[allow(clippy::too_many_arguments)]
fn reload_verified_view(
    installed: &crate::cbcl_v2_completion::InstalledCredentialV2Link,
    current: &selfsame_app_identity_net::profile::FetchedProfile,
    root_generation: [u8; 32],
    observed_account: &str,
    current_issuer_did: &str,
    offer_key_retained: bool,
    grant_matches: bool,
    revoked: bool,
    approve_rotation: bool,
    rotation: Option<CredentialV2InstalledRotationView>,
) -> Result<CredentialV2ReloadView> {
    let check = installed.verify_reload(
        crate::cbcl_v2_completion::CredentialV2ReloadObservation::Verified {
            root_generation,
            application_id: current.profile.application_id.as_str().into(),
            observed_account: observed_account.into(),
            account_authority: current.profile.account_authority.clone(),
            issuer_did: current_issuer_did.into(),
            profile_digest: *current.profile.digest(),
            offer_key_retained,
            grant_matches,
            revoked,
        },
        Some(&current.octets),
    )?;
    if let Some(replacement) = check.replacement.as_ref() {
        crate::cbcl_v2_completion::replace_installed(installed, replacement)?;
    }
    reload_view(installed, check.outcome, approve_rotation, rotation)
}

fn reload_view(
    installed: &crate::cbcl_v2_completion::InstalledCredentialV2Link,
    outcome: crate::cbcl_v2_completion::CredentialV2ReloadOutcome,
    approve_rotation: bool,
    rotation: Option<CredentialV2InstalledRotationView>,
) -> Result<CredentialV2ReloadView> {
    use crate::cbcl_v2_completion::CredentialV2ReloadOutcome as Outcome;
    let (outcome, capability) = match outcome {
        Outcome::Usable => ("usable", true),
        Outcome::ProfileRefresh => ("profile-refreshed", true),
        Outcome::AuthorityRotation if approve_rotation => ("fresh-pairing-required", false),
        Outcome::AuthorityRotation => ("authority-rotation", false),
        Outcome::IssuerRotation if approve_rotation => ("fresh-pairing-required", false),
        Outcome::IssuerRotation => ("issuer-rotation", false),
        Outcome::Unavailable => ("unavailable", false),
        Outcome::Revoked => ("revoked", false),
        Outcome::HandleChanged => ("account-device-handle-change-refused", false),
        Outcome::HubDeleted => ("hub-deleted", false),
        Outcome::FreshPairingRequired => ("fresh-pairing-required", false),
    };
    Ok(CredentialV2ReloadView {
        outcome,
        application_id: installed.application_id().into(),
        capability,
        record_retained: true,
        rotation,
    })
}

fn path_b_observations(
    quorum: &selfsame_app_identity_net::state::PathBResolverQuorum,
    fetched_at: i64,
) -> Result<Vec<selfsame_app_identity::path_b::ResolverObservation>> {
    quorum
        .nif_closures(fetched_at)
        .map_err(|_| UiError::from("PairingResolverRefused"))?
        .into_iter()
        .map(|closure| {
            let assertion_methods = closure
                .assertion_methods
                .into_iter()
                .map(|method| {
                    let public_key: [u8; 32] = method
                        .public_key
                        .try_into()
                        .map_err(|_| UiError::from("PairingResolverRefused"))?;
                    Ok(selfsame_app_identity::path_b::ClosureAssertionMethod {
                        id: method.id,
                        kind: method.kind,
                        public_key,
                        has_private_component: method.has_private_component,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(selfsame_app_identity::path_b::ResolverObservation {
                resolver_id: closure.resolver_id,
                did: closure.did,
                did_recomputed_ok: closure.did_recomputed_ok,
                deltas_verified: closure.deltas_verified,
                locally_closed: closure.locally_closed,
                deactivated: closure.deactivated,
                assertion_methods,
                revoked_credential_ids: closure.revoked_credential_ids,
                also_known_as: closure.also_known_as,
                fetched_at_seconds: closure.fetched_at_seconds,
            })
        })
        .collect()
}

/// Recover the immutable terminal result after the blind relay window closes.
///
/// The raw recovery token exists only in cbcl-pairing and the native bounded
/// POST body. JavaScript receives only this closed result projection.
#[tauri::command]
pub async fn cbcl_v2_recover(
    application_id: String,
    passcode: String,
    approve_rotation: bool,
) -> Result<CredentialV2RecoveryView> {
    if passcode.is_empty() {
        return Err(UiError::from("PresenceRequired"));
    }
    recover_claimant_completion(&application_id, &passcode, approve_rotation).await
}

async fn recover_claimant_completion(
    application_id: &str,
    passcode: &str,
    approve_rotation: bool,
) -> Result<CredentialV2RecoveryView> {
    let durable = crate::cbcl_v2_completion::load_pending(application_id)?;
    let application = selfsame_app_identity::profile::ApplicationId::parse(application_id)
        .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
    let carrier = durable.carrier()?;
    let now = crate::commands::now();
    if now < carrier.relay_expires_at() {
        return Ok(recovery_view(
            application_id,
            "relay-window-open",
            None,
            None,
        ));
    }

    let historical_profile_octets = durable.offer_profile_octets()?;
    let historical_profile =
        selfsame_app_identity::profile::ApplicationProfile::recognise(&historical_profile_octets)
            .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
    let offer_object = durable.offer_object()?;
    let offer = selfsame_pairing::credential_v2::recognise_signed_offer(
        &historical_profile,
        offer_object.body(),
    )
    .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
    let payload = durable.payload_facts()?;
    let checkpoint = durable.endpoint_checkpoint_octets()?;
    durable.require_root_generation(crate::cbcl_v2_completion::root_generation(
        &crate::custody::Custody::root_public_key()?,
    ))?;

    let (_body_authority, body_verifier) =
        selfsame_pairing::credential_v2::credential_v2_body_authority_for_restore(
            historical_profile.clone(),
        );
    let mut claimant = crate::custody::Custody::use_hierarchy_root(passcode, |root| {
        let wrapping_key = crate::cbcl_v2_completion::checkpoint_wrapping_key(
            root,
            application_id,
            carrier.carrier_ceremony_id(),
        )?;
        cbcl_pairing::credential_v2::CredentialV2ClaimantSession::restore(
            checkpoint.as_slice(),
            &wrapping_key,
            carrier.clone(),
            durable.checkpoint_generation(),
            now,
            Box::new(body_verifier),
        )
        .map_err(|_| UiError::from("PairingCheckpointRefused"))
    })??;
    let receipt_recovery_commitment = claimant
        .receipt_recovery_commitment()
        .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
    let request = claimant
        .with_receipt_recovery_token(|token| {
            selfsame_pairing::credential_v2::encode_receipt_recovery_request(
                application_id,
                *carrier.carrier_ceremony_id(),
                token,
            )
        })
        .map_err(|_| UiError::from("PairingCheckpointRefused"))?
        .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
    let request = Zeroizing::new(request);
    let current = selfsame_app_identity_net::profile::fetch(
        &application,
        i64::try_from(now).map_err(|_| UiError::from("PairingProfileUnavailable"))?,
    )
    .await
    .map_err(|_| UiError::from("PairingProfileUnavailable"))?;
    let http = match selfsame_app_identity_net::pairing_status::post(&application, &request).await {
        Ok(value) => value,
        Err(selfsame_app_identity_net::NetError::Timeout)
        | Err(selfsame_app_identity_net::NetError::Transport(_)) => {
            return Ok(recovery_view(application_id, "unavailable", None, None));
        }
        Err(_) => return Err(UiError::from("PairingRecoveryRefused")),
    };
    use selfsame_app_identity_net::pairing_status::PairingStatusHttpStatus as HttpStatus;
    if http.status == HttpStatus::Unavailable {
        return Ok(recovery_view(application_id, "unavailable", None, None));
    }
    let response = selfsame_pairing::credential_v2::decode_receipt_recovery_response(&http.body)
        .map_err(|_| UiError::from("PairingRecoveryRefused"))?;
    use selfsame_pairing::credential_v2::CredentialV2RecoveryResponse as Recovery;
    match (http.status, response) {
        (
            HttpStatus::Terminal,
            Recovery::Accepted {
                final_status_jws,
                final_status_digest,
            },
        ) => {
            let receipt = selfsame_pairing::credential_v2::recovered_receipt_object(
                *offer_object.intent_digest(),
                *carrier.carrier_ceremony_id(),
                payload.payload_content_hash,
                selfsame_pairing::credential_v2::CredentialV2ReceiptInput {
                    final_status_jws,
                    final_status_digest,
                },
            )
            .map_err(|_| UiError::from("PairingReceiptRefused"))?;
            let recovered = claimant
                .authenticate_recovered_receipt_object(receipt)
                .map_err(|_| UiError::from("PairingReceiptRefused"))?;
            let installed =
                crate::cbcl_v2_completion::InstalledCredentialV2Link::from_authenticated_receipt(
                    &durable,
                    &historical_profile_octets,
                    recovered.object(),
                    receipt_recovery_commitment,
                )?;
            let rotation = accepted_rotation(&historical_profile, &current.profile, &offer.kid);
            if rotation.is_some() && !approve_rotation {
                return Ok(recovery_view(
                    application_id,
                    "authority-rotation",
                    None,
                    rotation,
                ));
            }
            let account = installed.account()?;
            let issuer_did = installed.issuer_did().to_owned();
            let jrd = verify_live_installation(current.profile, account, issuer_did).await?;
            crate::cbcl_v2_completion::install(&durable, &installed, &jrd)?;
            claimant
                .commit_recovered_receipt(recovered)
                .map_err(|_| UiError::from("PairingReceiptRefused"))?;
            Ok(recovery_view(application_id, "installed", None, None))
        }
        (
            HttpStatus::Terminal,
            Recovery::NotFinalized {
                recovery_status_jws,
                recovery_status_digest,
            },
        ) => {
            let negative =
                selfsame_pairing::credential_v2::recognise_recovery_not_finalized_status(
                    &current.profile,
                    &recovery_status_jws,
                    recovery_status_digest,
                    application_id,
                    *carrier.carrier_ceremony_id(),
                    receipt_recovery_commitment,
                )
                .map_err(|_| UiError::from("PairingRecoveryRefused"))?;
            let rotation = negative_rotation(
                &historical_profile,
                &current.profile,
                &offer.kid,
                &negative.kid,
            );
            if rotation.is_some() && !approve_rotation {
                return Ok(recovery_view(
                    application_id,
                    "authority-rotation",
                    None,
                    rotation,
                ));
            }
            crate::cbcl_v2_completion::remove_pending(&durable)?;
            Ok(recovery_view(application_id, "not-finalized", None, None))
        }
        (
            HttpStatus::InProgress,
            Recovery::InProgress {
                retry_after_seconds,
            },
        ) => Ok(recovery_view(
            application_id,
            "in-progress",
            Some(retry_after_seconds),
            None,
        )),
        (HttpStatus::Unknown, Recovery::Unknown) => {
            Ok(recovery_view(application_id, "unknown", None, None))
        }
        _ => Err(UiError::from("PairingRecoveryRefused")),
    }
}

fn recovery_view(
    application_id: &str,
    outcome: &'static str,
    retry_after_seconds: Option<u8>,
    authority_rotation: Option<CredentialV2AuthorityRotationView>,
) -> CredentialV2RecoveryView {
    CredentialV2RecoveryView {
        outcome,
        application_id: application_id.into(),
        retry_after_seconds,
        authority_rotation,
    }
}

fn accepted_rotation(
    historical: &selfsame_app_identity::profile::ApplicationProfile,
    current: &selfsame_app_identity::profile::ApplicationProfile,
    retained_kid: &str,
) -> Option<CredentialV2AuthorityRotationView> {
    let retained = historical
        .enrollment_keys
        .iter()
        .find(|candidate| candidate.kid == retained_kid)?;
    let unchanged = current
        .enrollment_keys
        .iter()
        .any(|candidate| candidate.kid == retained_kid && candidate.jwk == retained.jwk);
    (!unchanged).then(|| rotation_view(historical, current, retained_kid, None))
}

fn negative_rotation(
    historical: &selfsame_app_identity::profile::ApplicationProfile,
    current: &selfsame_app_identity::profile::ApplicationProfile,
    retained_kid: &str,
    current_kid: &str,
) -> Option<CredentialV2AuthorityRotationView> {
    let retained = historical
        .enrollment_keys
        .iter()
        .find(|candidate| candidate.kid == retained_kid)?;
    let selected = current
        .enrollment_keys
        .iter()
        .find(|candidate| candidate.kid == current_kid)?;
    (retained_kid != current_kid || retained.jwk != selected.jwk)
        .then(|| rotation_view(historical, current, retained_kid, Some(current_kid.into())))
}

fn rotation_view(
    historical: &selfsame_app_identity::profile::ApplicationProfile,
    current: &selfsame_app_identity::profile::ApplicationProfile,
    retained_kid: &str,
    current_kid: Option<String>,
) -> CredentialV2AuthorityRotationView {
    CredentialV2AuthorityRotationView {
        retained_kid: retained_kid.into(),
        current_kid,
        retained_profile_digest: selfsame_app_identity::codec::b64url(historical.digest()),
        current_profile_digest: selfsame_app_identity::codec::b64url(current.digest()),
    }
}

/// Invalidate even a command which currently owns the socket. Dropping an idle
/// socket closes it; in-flight I/O retains its existing bounded transport wait.
/// Sealed post-payload recovery belongs to the durable slot and is preserved.
#[tauri::command]
pub async fn cbcl_v2_cancel(session: State<'_, AppSession>) -> Result<()> {
    let mut guard = session
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard
        .cbcl_v2_attempts
        .require_mode(CredentialV2Flow::LegacyTwoDecision)?;
    guard.revoke_cbcl_v2();
    Ok(())
}

fn take_relay_plan(session: &AppSession) -> Result<(RelayConsentPlan, CredentialV2Operation)> {
    let mut guard = session
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard
        .cbcl_v2_attempts
        .require_mode(CredentialV2Flow::LegacyTwoDecision)?;
    if guard.pending_cbcl_v2_relay.is_none() {
        return Err(UiError::from("PairingNotStarted"));
    }
    let operation = guard.cbcl_v2_attempts.start_work()?;
    let plan = guard
        .pending_cbcl_v2_relay
        .take()
        .expect("checked relay plan");
    Ok((plan, operation))
}

async fn pairing_blocking<T: Send + 'static>(
    operation: &CredentialV2Operation,
    action: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let lease = operation.lease();
    let attempt = operation.attempt.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _lease = lease;
        attempt.run(action)
    })
    .await
    .map_err(|_| UiError::from("PairingFailed"))?
}

fn pump_to_offer(
    mut claimant: PreparedClaimant,
    mut socket: WebSocket<MaybeTlsStream<TcpStream>>,
    attempt: CredentialV2Attempt,
) -> Result<(PendingCredentialV2Pairing, CredentialV2IntentView)> {
    attempt.check()?;
    let start = claimant
        .core_mut()
        .start()
        .map_err(|_| UiError::from("PairingFailed"))?;
    send_binary(&mut socket, &attempt, start)?;
    loop {
        let bytes = read_binary(&mut socket, &attempt)?;
        let effects = claimant
            .core_mut()
            .receive(&bytes, crate::commands::now())
            .map_err(|_| UiError::from("PairingFailed"))?;
        for effect in effects {
            attempt.check()?;
            match effect {
                CredentialV2ClaimantEffect::Send(bytes) => {
                    send_binary(&mut socket, &attempt, bytes)?
                }
                CredentialV2ClaimantEffect::Established { transcript_hash } => {
                    attempt.run(|| claimant.bind_finished_profile(transcript_hash))?;
                }
                CredentialV2ClaimantEffect::DisplayIntent(display) => {
                    let view = intent_view(&display);
                    return Ok((
                        PendingCredentialV2Pairing {
                            attempt,
                            phase: CredentialV2Phase::Intent,
                            claimant,
                            socket,
                            intent_approve: None,
                            preview_did: None,
                            comparison: None,
                            recovered_receipt: None,
                            ceremony_custody: None,
                        },
                        view,
                    ));
                }
                CredentialV2ClaimantEffect::ReceivedObject { .. }
                | CredentialV2ClaimantEffect::Checkpoint { .. }
                | CredentialV2ClaimantEffect::Terminal => {
                    return Err(UiError::from("PairingFailed"))
                }
            }
        }
    }
}

fn ensure_current(session: &AppSession, attempt: &CredentialV2Attempt) -> Result<()> {
    session
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .cbcl_v2_attempts
        .ensure_current(attempt)
}

fn put_pending(
    session: &AppSession,
    pending: PendingCredentialV2Pairing,
    operation: CredentialV2Operation,
) -> Result<()> {
    let mut guard = session
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.update_cbcl_v2_attempt(&operation.attempt, |guard| {
        guard.cbcl_v2_attempts.ensure_current(&pending.attempt)?;
        if guard.pending_cbcl_v2.is_some() || guard.pending_cbcl_v2_relay.is_some() {
            return Err(UiError::from("PairingAlreadyActive"));
        }
        guard.pending_cbcl_v2 = Some(pending);
        Ok(())
    })?;
    operation.retain();
    Ok(())
}

fn prepare_received_receipt(
    mut pending: PendingCredentialV2Pairing,
    passcode: &str,
) -> (
    PendingCredentialV2Pairing,
    Result<(
        crate::cbcl_v2_completion::PendingCredentialV2Completion,
        [u8; 32],
    )>,
) {
    let result = (|| {
        let application_id = pending
            .claimant
            .profile()
            .application_id
            .as_str()
            .to_owned();
        let carrier = pending.claimant.carrier().clone();
        // The normal path reuses final consent.  A stalled ceremony requires
        // one fresh presence check rather than retaining an authorization.
        pending.ensure_ceremony_custody(passcode)?;
        let (claimant, socket, ceremony_custody) = (
            &mut pending.claimant,
            &mut pending.socket,
            &pending.ceremony_custody,
        );
        let custody = ceremony_custody
            .as_ref()
            .expect("ceremony custody was installed");
        let mut durable = crate::cbcl_v2_completion::load_pending(&application_id)?;
        while claimant.core_mut().has_cached_outbound_frame() {
            let acknowledgement = read_binary(socket, &pending.attempt)?;
            let mut nonce = [0_u8; 12];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let effects = custody.with_root(|root| {
                let wrapping_key = crate::cbcl_v2_completion::checkpoint_wrapping_key(
                    root,
                    &application_id,
                    carrier.carrier_ceremony_id(),
                )?;
                claimant
                    .core_mut()
                    .receive_durable(
                        &acknowledgement,
                        crate::commands::now(),
                        &wrapping_key,
                        cbcl_pairing::credential_v2::CredentialV2CheckpointNonce::from_csprng(
                            nonce,
                        ),
                    )
                    .map_err(|_| UiError::from("PairingFailed"))
            })?;
            let (generation, checkpoint) = one_checkpoint(effects)?;
            let acknowledged = durable.with_checkpoint(generation, &checkpoint)?;
            pending
                .attempt
                .run(|| crate::cbcl_v2_completion::replace_pending(&durable, &acknowledged))?;
            let after = claimant
                .core_mut()
                .checkpoint_persisted(generation)
                .map_err(|_| UiError::from("PairingFailed"))?;
            if !after.is_empty() {
                return Err(UiError::from("PairingFailed"));
            }
            durable = acknowledged;
        }
        let receipt_recovery_commitment = pending
            .claimant
            .core_mut()
            .receipt_recovery_commitment()
            .map_err(|_| UiError::from("PairingFailed"))?;
        if pending.recovered_receipt.is_none() {
            let frame = read_binary(&mut pending.socket, &pending.attempt)?;
            pending.recovered_receipt = Some(
                pending
                    .claimant
                    .core_mut()
                    .receive_recovered_receipt(&frame)
                    .map_err(|_| UiError::from("PairingReceiptRefused"))?,
            );
        }
        Ok((durable, receipt_recovery_commitment))
    })();
    (pending, result)
}

fn install_guarded(
    attempt: &CredentialV2Attempt,
    durable: &crate::cbcl_v2_completion::PendingCredentialV2Completion,
    installed: &crate::cbcl_v2_completion::InstalledCredentialV2Link,
    jrd: &selfsame_app_identity::alias::Jrd,
) -> Result<()> {
    attempt.run(|| crate::cbcl_v2_completion::install(durable, installed, jrd))
}

async fn verify_live_installation_guarded(
    profile: selfsame_app_identity::profile::ApplicationProfile,
    account: selfsame_app_identity::alias::AcctUri,
    issuer_did: String,
    attempt: &CredentialV2Attempt,
) -> Result<selfsame_app_identity::alias::Jrd> {
    let account_text = account.as_str().to_owned();
    let resolved = attempt
        .io(async {
            selfsame_app_identity_net::state::resolve_closure(
                &profile,
                &issuer_did,
                None,
                selfsame_app_identity_net::state::Acceptance::Repeat,
            )
            .await
            .map_err(|_| UiError::from("PairingResolverUnavailable"))
        })
        .await?;
    if resolved.document.did.as_str() != issuer_did
        || resolved.document.is_deactivated()
        || !resolved
            .document
            .also_known_as()
            .iter()
            .any(|v| v == &account_text)
    {
        return Err(UiError::from("PairingResolverRefused"));
    }
    attempt
        .io(async {
            selfsame_app_identity_net::webfinger::fetch_and_verify(
                &account,
                &issuer_did,
                &[account_text],
            )
            .await
            .map_err(|_| UiError::from("PairingAuthorityRefused"))
        })
        .await
}

async fn verify_live_installation(
    profile: selfsame_app_identity::profile::ApplicationProfile,
    account: selfsame_app_identity::alias::AcctUri,
    issuer_did: String,
) -> Result<selfsame_app_identity::alias::Jrd> {
    let account_text = account.as_str().to_owned();
    let resolved = selfsame_app_identity_net::state::resolve_closure(
        &profile,
        &issuer_did,
        None,
        selfsame_app_identity_net::state::Acceptance::Repeat,
    )
    .await
    .map_err(|_| UiError::from("PairingResolverUnavailable"))?;
    if resolved.document.did.as_str() != issuer_did
        || resolved.document.is_deactivated()
        || !resolved
            .document
            .also_known_as()
            .iter()
            .any(|value| value == &account_text)
    {
        return Err(UiError::from("PairingResolverRefused"));
    }
    selfsame_app_identity_net::webfinger::fetch_and_verify(&account, &issuer_did, &[account_text])
        .await
        .map_err(|_| UiError::from("PairingAuthorityRefused"))
}

fn take_pending(
    session: &AppSession,
    phase: CredentialV2Phase,
) -> Result<(PendingCredentialV2Pairing, CredentialV2Operation)> {
    let mut guard = session
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard
        .cbcl_v2_attempts
        .require_mode(CredentialV2Flow::LegacyTwoDecision)?;
    let pending = guard
        .pending_cbcl_v2
        .as_ref()
        .ok_or_else(|| UiError::from("PairingNotStarted"))?;
    guard.cbcl_v2_attempts.ensure_current(&pending.attempt)?;
    pending.phase.require(phase)?;
    let operation = guard.cbcl_v2_attempts.start_work()?;
    let pending = guard.pending_cbcl_v2.take().expect("checked pending phase");
    Ok((pending, operation))
}

fn send_claimant_object(
    pending: &mut PendingCredentialV2Pairing,
    object: &cbcl_pairing::credential_v2::CredentialV2Object,
) -> Result<()> {
    pending.attempt.check()?;
    let effects = pending.attempt.run(|| {
        pending
            .claimant
            .core_mut()
            .prepare_application_object(object)
            .map_err(|_| UiError::from("PairingFailed"))
    })?;
    send_effects(&mut pending.socket, &pending.attempt, effects)
}

fn send_binary(
    socket: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    attempt: &CredentialV2Attempt,
    bytes: Vec<u8>,
) -> Result<()> {
    attempt.run(|| {
        socket
            .send(Message::Binary(bytes.into()))
            .map_err(|_| UiError::from("PairingRelayUnavailable"))
    })
}

fn send_effects(
    socket: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    attempt: &CredentialV2Attempt,
    effects: Vec<CredentialV2ClaimantEffect>,
) -> Result<()> {
    attempt.check()?;
    for effect in effects {
        match effect {
            CredentialV2ClaimantEffect::Send(bytes) => send_binary(socket, attempt, bytes)?,
            _ => return Err(UiError::from("PairingFailed")),
        }
    }
    Ok(())
}

fn one_checkpoint(
    effects: Vec<CredentialV2ClaimantEffect>,
) -> Result<(u64, cbcl_pairing::credential_v2::EndpointCheckpointV2)> {
    let mut effects = effects.into_iter();
    let Some(CredentialV2ClaimantEffect::Checkpoint {
        generation,
        checkpoint,
    }) = effects.next()
    else {
        return Err(UiError::from("PairingFailed"));
    };
    if effects.next().is_some() {
        return Err(UiError::from("PairingFailed"));
    }
    Ok((generation, checkpoint))
}

fn wait_outbound_ack(pending: &mut PendingCredentialV2Pairing) -> Result<()> {
    pending.attempt.check()?;
    while pending.claimant.core_mut().has_cached_outbound_frame() {
        let bytes = read_binary(&mut pending.socket, &pending.attempt)?;
        let effects = pending
            .claimant
            .core_mut()
            .receive(&bytes, crate::commands::now())
            .map_err(|_| UiError::from("PairingFailed"))?;
        for effect in effects {
            match effect {
                CredentialV2ClaimantEffect::Send(bytes) => {
                    send_binary(&mut pending.socket, &pending.attempt, bytes)?
                }
                _ => return Err(UiError::from("PairingFailed")),
            }
        }
    }
    Ok(())
}

fn pump_to_comparison(
    pending: &mut PendingCredentialV2Pairing,
) -> Result<cbcl_pairing::credential_v2::CredentialV2Object> {
    loop {
        let bytes = read_binary(&mut pending.socket, &pending.attempt)?;
        let effects = pending
            .claimant
            .core_mut()
            .receive(&bytes, crate::commands::now())
            .map_err(|_| UiError::from("PairingFailed"))?;
        for effect in effects {
            match effect {
                CredentialV2ClaimantEffect::Send(bytes) => {
                    send_binary(&mut pending.socket, &pending.attempt, bytes)?
                }
                CredentialV2ClaimantEffect::ReceivedObject { object }
                    if matches!(
                        object.kind(),
                        CredentialV2Kind::ComparisonConfirmed | CredentialV2Kind::BindingConfirmed
                    ) =>
                {
                    return Ok(object);
                }
                _ => return Err(UiError::from("PairingFailed")),
            }
        }
    }
}

fn preview_identity(claimant: &PreparedClaimant, passcode: &str) -> Result<String> {
    let offer = claimant
        .authenticated_offer()
        .ok_or_else(|| UiError::from("PairingFailed"))?;
    let recognised =
        selfsame_pairing::credential_v2::recognise_signed_offer(claimant.profile(), offer.body())
            .map_err(|_| UiError::from("PairingFailed"))?;
    let application = claimant.profile().application_id.clone();
    let scope = selfsame_app_identity::scope::AccountScopeId::from_octets(
        *recognised.claims.account_provenance().account_scope_id(),
    );
    crate::custody::Custody::use_hierarchy_root(passcode, move |root| {
        let home = selfsame_app_identity::hierarchy::derive(root, &application, &scope);
        home.home_did()
            .map_err(|_| UiError::from("PairingIdentityUnavailable"))
    })?
}

fn intent_view(
    display: &cbcl_pairing::credential_v2::CredentialV2Display,
) -> CredentialV2IntentView {
    let transition = match display.transition().as_path_a_to_b() {
        Some(path) => CredentialV2TransitionView {
            kind: "path-a-to-b",
            legacy_handle: Some(path.legacy_handle().into()),
            migration_rooms: path.migration_rooms().to_vec(),
        },
        None => CredentialV2TransitionView {
            kind: "none",
            legacy_handle: None,
            migration_rooms: Vec::new(),
        },
    };
    let tofu_state = match display.tofu_state() {
        CredentialV2TofuState::NewPair => "new-pair",
        CredentialV2TofuState::TrustedPair => "trusted-pair",
        CredentialV2TofuState::CeremonyGesture => "ceremony-gesture",
        _ => "unknown",
    };
    CredentialV2IntentView {
        application_id: display.application_id().into(),
        https_origin: display.https_origin().into(),
        relay_origin: display.relay_origin().into(),
        permissions: display.permissions().to_vec(),
        device_did: display.device_binding().device_did().into(),
        account_principal_digest: selfsame_app_identity::codec::b64url(
            display.account_provenance().account_principal_digest(),
        ),
        tofu_state,
        transition,
    }
}

fn read_binary(
    socket: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    attempt: &CredentialV2Attempt,
) -> Result<Vec<u8>> {
    let waiting_since = Instant::now();
    if attempt.mode() == CredentialV2Flow::SingleLink {
        let tcp = match socket.get_ref() {
            MaybeTlsStream::Plain(tcp) => tcp,
            MaybeTlsStream::Rustls(tls) => &tls.sock,
            _ => return Err(UiError::from("PairingRelayUnavailable")),
        };
        tcp.set_read_timeout(Some(Duration::from_millis(50)))
            .map_err(|_| UiError::from("PairingRelayUnavailable"))?;
    }
    loop {
        attempt.check()?;
        let entry = attempt.enter()?;
        let message = socket.read();
        drop(entry);
        attempt.check()?;
        match message {
            Ok(Message::Binary(bytes)) => return Ok(bytes.to_vec()),
            Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => {}
            Err(tungstenite::Error::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if attempt.mode() != CredentialV2Flow::SingleLink
                    || waiting_since.elapsed() >= cbcl_transport::IO_TIMEOUT
                {
                    return Err(UiError::from("PairingRelayTimedOut"));
                }
            }
            Ok(Message::Close(_)) | Err(_) => {
                return Err(UiError::from("PairingRelayUnavailable"));
            }
            Ok(Message::Text(_)) => return Err(UiError::from("PairingFailed")),
        }
    }
}

fn map_transport(error: cbcl_transport::TransportError) -> UiError {
    match error {
        cbcl_transport::TransportError::Tls => UiError::from("PairingRelayTlsRefused"),
        cbcl_transport::TransportError::Origin => UiError::from("PairingRelayRefused"),
        cbcl_transport::TransportError::Connect | cbcl_transport::TransportError::Handshake => {
            UiError::from("PairingRelayUnavailable")
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WebFingerReloadFailure {
    HubDeleted,
    Unavailable,
    InvalidBinding,
}

fn classify_webfinger_failure(
    error: selfsame_app_identity_net::NetError,
) -> WebFingerReloadFailure {
    match error {
        selfsame_app_identity_net::NetError::NotFound => WebFingerReloadFailure::HubDeleted,
        selfsame_app_identity_net::NetError::TooLarge
        | selfsame_app_identity_net::NetError::Timeout
        | selfsame_app_identity_net::NetError::Transport(_)
        | selfsame_app_identity_net::NetError::Refused(_) => WebFingerReloadFailure::Unavailable,
        selfsame_app_identity_net::NetError::Recognition(_) => {
            WebFingerReloadFailure::InvalidBinding
        }
    }
}

#[cfg(all(
    test,
    not(any(target_os = "android", target_os = "ios", target_arch = "wasm32"))
))]
#[path = "scan_integration_native_host.rs"]
mod scan_integration_host;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_preview_returns_identity_before_continuation_and_derives_only_once() {
        use std::cell::Cell;
        let attempt = CredentialV2Attempt::default();
        let derivations = Cell::new(0);
        let preparations = Cell::new(0);
        let mut phase = CredentialV2Phase::Intent;
        let (did, view) = prepare_preview(&mut phase, &attempt, "https://app.example", || {
            derivations.set(derivations.get() + 1);
            Ok("did:crdt:test-preview".into())
        })
        .unwrap();
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["outcome"], "preview");
        assert_eq!(json["finalReview"]["applicationId"], "https://app.example");
        assert_eq!(json["finalReview"]["previewIssuerDid"], did.as_str());
        assert!(json["finalReview"]["previewFingerprint"].is_object());
        assert_eq!(json["finalReview"]["comparison"], "waiting");
        assert_eq!(preparations.get(), 0);
        assert!(phase.require(CredentialV2Phase::FinalReview).is_err());
        assert!(
            prepare_preview(&mut phase, &attempt, "https://app.example", || {
                derivations.set(derivations.get() + 1);
                Ok("did:crdt:changed".into())
            })
            .is_err()
        );
        continue_preview(&mut phase, &attempt, || {
            preparations.set(preparations.get() + 1);
            Ok(())
        })
        .unwrap();
        assert_eq!(derivations.get(), 1);
        assert_eq!(preparations.get(), 1);
        assert_eq!(did.as_str(), "did:crdt:test-preview");
        assert_eq!(phase, CredentialV2Phase::FinalReview);
    }

    #[test]
    fn scan_preview_cancellation_during_derivation_or_comparison_erases_result() {
        for during_preview in [true, false] {
            let mut attempts = crate::session::CredentialV2Attempts::default();
            let work = attempts.begin().unwrap();
            if during_preview {
                let mut phase = CredentialV2Phase::Intent;
                assert!(
                    prepare_preview(&mut phase, &work.attempt, "https://app.example", || {
                        attempts.cancel();
                        Ok("did:crdt:cancelled".into())
                    })
                    .is_err()
                );
                assert_eq!(phase, CredentialV2Phase::Intent);
            } else {
                let mut phase = CredentialV2Phase::PreviewReady;
                assert!(continue_preview(&mut phase, &work.attempt, || {
                    attempts.cancel();
                    Ok("authenticated comparison arrived after cancellation")
                })
                .is_err());
                assert_ne!(phase, CredentialV2Phase::FinalReview);
            }
        }
    }

    #[test]
    fn scan_preview_cancelled_transport_sends_zero_frames() {
        use std::net::TcpListener;
        use tungstenite::protocol::Role;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let mut socket =
            WebSocket::from_raw_socket(MaybeTlsStream::Plain(client), Role::Client, None);
        let mut attempts = crate::session::CredentialV2Attempts::default();
        let work = attempts.begin().unwrap();
        attempts.cancel();
        assert!(send_binary(&mut socket, &work.attempt, vec![1, 2, 3]).is_err());
        assert!(send_effects(
            &mut socket,
            &work.attempt,
            vec![CredentialV2ClaimantEffect::Send(vec![4])]
        )
        .is_err());
        use std::io::Read;
        let mut bytes = [0; 32];
        let error = peer.read(&mut bytes).unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
    }

    #[test]
    fn scan_preview_final_boundaries_refuse_cancellation_observed_after_wait() {
        struct CancelAtBoundary(crate::session::CredentialV2Attempts);
        impl PrePayloadFaultSink for CancelAtBoundary {
            fn before(&mut self, _: PrePayloadBoundary) -> Result<()> {
                self.0.cancel();
                Ok(())
            }
        }
        for boundary in [
            PrePayloadBoundary::FinalApprovalRelease,
            PrePayloadBoundary::AcknowledgementRead,
            PrePayloadBoundary::AcknowledgementRecognition,
            PrePayloadBoundary::AcknowledgementCheckpointReplacement,
            PrePayloadBoundary::AcknowledgementCheckpointCommit,
            PrePayloadBoundary::PlanConstruction,
            PrePayloadBoundary::PlannedStageReplacement,
            PrePayloadBoundary::IssuerCustody,
            PrePayloadBoundary::IssuerStageReplacement,
            PrePayloadBoundary::IssuerPublication,
            PrePayloadBoundary::ResolverVerification,
            PrePayloadBoundary::GrantConstruction,
            PrePayloadBoundary::ProvisionedStageReplacement,
            PrePayloadBoundary::PayloadConstruction,
            PrePayloadBoundary::PayloadCheckpointPreparation,
        ] {
            let mut inner = CancelAtBoundary(Default::default());
            let work = inner.0.begin().unwrap();
            let mut faults = CancellationFaults {
                attempt: &work.attempt,
                inner: &mut inner,
                entry: None,
            };
            assert!(
                faults.before(boundary).is_err(),
                "{boundary:?} must refuse its effect"
            );
        }
    }

    #[tokio::test]
    async fn scan_preview_blocking_wrapper_keeps_lease_after_command_is_dropped() {
        use std::sync::mpsc;
        let mut attempts = crate::session::CredentialV2Attempts::default();
        let operation = attempts.begin().unwrap();
        let (started, entered) = mpsc::channel();
        let (release, blocked) = mpsc::channel();
        let command = tokio::spawn(async move {
            pairing_blocking(&operation, move || {
                started.send(()).unwrap();
                blocked.recv_timeout(Duration::from_secs(5)).unwrap();
                Ok(())
            })
            .await
        });
        // Yield this runtime's thread until the actual blocking wrapper entered.
        let start_deadline = Instant::now() + Duration::from_secs(5);
        while entered.try_recv().is_err() {
            assert!(Instant::now() < start_deadline);
            tokio::task::yield_now().await;
        }
        command.abort();
        assert!(command.await.unwrap_err().is_cancelled());
        assert!(attempts.begin().is_err());
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if attempts.begin().is_ok() {
                break;
            }
            assert!(Instant::now() < deadline);
            tokio::task::yield_now().await;
        }
    }

    #[test]
    fn scan_preview_continuation_is_single_use_and_wrong_phases_have_no_effects() {
        use std::cell::Cell;
        let preparations = Cell::new(0);
        let grants = Cell::new(0);
        for mut phase in [
            CredentialV2Phase::Intent,
            CredentialV2Phase::Comparing,
            CredentialV2Phase::FinalReview,
            CredentialV2Phase::PayloadSent,
        ] {
            assert!(continue_preview(&mut phase, &Default::default(), || {
                preparations.set(preparations.get() + 1);
                Ok(())
            })
            .is_err());
        }
        assert_eq!(preparations.get(), 0);
        let mut phase = CredentialV2Phase::PreviewReady;
        continue_preview(&mut phase, &Default::default(), || {
            preparations.set(preparations.get() + 1);
            Ok(())
        })
        .unwrap();
        assert!(continue_preview(&mut phase, &Default::default(), || {
            preparations.set(preparations.get() + 1);
            Ok(())
        })
        .is_err());
        assert_eq!(preparations.get(), 1);
        let phase = CredentialV2Phase::PreviewReady;
        if phase.require(CredentialV2Phase::FinalReview).is_ok() {
            grants.set(grants.get() + 1);
        }
        assert_eq!(grants.get(), 0);
    }

    #[test]
    fn scan_preview_cancel_blocked_continuation_refuses_send_and_return() {
        use crate::session::CredentialV2Attempts;
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            mpsc, Arc,
        };
        let mut attempts = CredentialV2Attempts::default();
        let work = attempts.begin().unwrap();
        let attempt = work.attempt.clone();
        let lease = work.lease();
        let effects = Arc::new(AtomicUsize::new(0));
        let worker_effects = effects.clone();
        let (entered, blocked) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _lease = lease;
            let mut phase = CredentialV2Phase::PreviewReady;
            continue_preview(&mut phase, &attempt, || {
                entered.send(()).unwrap();
                wait.recv_timeout(Duration::from_secs(5)).unwrap();
                attempt.run(|| {
                    worker_effects.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
            })
        });
        blocked.recv_timeout(Duration::from_secs(5)).unwrap();
        attempts.cancel();
        drop(work);
        assert!(
            attempts.begin().is_err(),
            "blocked worker retains the only lease"
        );
        release.send(()).unwrap();
        assert!(worker.join().unwrap().is_err());
        assert_eq!(effects.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_1163_oversized_webfinger_is_unavailable_not_revoked() {
        assert_eq!(
            classify_webfinger_failure(selfsame_app_identity_net::NetError::TooLarge),
            WebFingerReloadFailure::Unavailable
        );
    }
}

#[path = "cbcl_v2_single_link.rs"]
pub mod single_link;
