//! SPEC079 CON-001..004: complete/manual entry, local preview and one person Link.
//! The live capability owns the existing immutable claimant and its predecessor
//! chain; no independent mutable digest ledger or serialized authority exists.
use super::*;
use crate::cbcl_v2_claimant::RecognisedCredentialV2Entry;
use serde::{Deserialize, Deserializer};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BeginHandoffRequest {
    handoff: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BeginManualRequest {
    bootstrap: String,
    words: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaggedRequest {
    #[serde(deserialize_with = "tag")]
    attempt_tag: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnlockPreviewRequest {
    #[serde(deserialize_with = "tag")]
    attempt_tag: String,
    passcode: String,
}
fn tag<'de, D: Deserializer<'de>>(input: D) -> std::result::Result<String, D::Error> {
    let value = String::deserialize(input)?;
    if value.len() != 32
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(serde::de::Error::custom("PairingStaleAttempt"));
    }
    Ok(value)
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReservationView {
    attempt_tag: String,
    phase: &'static str,
    application_id: String,
    relay_origin: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactView {
    phase: &'static str,
    intent: CredentialV2IntentView,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewView {
    phase: &'static str,
    review: CredentialV2FinalReviewView,
}
#[derive(Serialize)]
pub struct PhaseView {
    phase: &'static str,
}

#[tauri::command]
pub async fn cbcl_v2_begin_handoff(
    request: BeginHandoffRequest,
    session: State<'_, AppSession>,
) -> Result<ReservationView> {
    let handoff = Zeroizing::new(request.handoff);
    let now = i64::try_from(crate::cbcl_v2_clock::snapshot()?.utc)
        .map_err(|_| UiError::from("PairingClockUnavailable"))?;
    let entry = RecognisedCredentialV2Entry::handoff(&handoff, now)?;
    reserve_entry(entry, &session)
}

/// Explicit manual entry shares the complete bounded Rust recognizer before
/// creating any reservation, profile contact, relay work or custody authority.
#[tauri::command]
pub async fn cbcl_v2_begin_manual(
    request: BeginManualRequest,
    session: State<'_, AppSession>,
) -> Result<ReservationView> {
    let bootstrap = Zeroizing::new(request.bootstrap);
    let words = Zeroizing::new(request.words);
    let now = crate::cbcl_v2_clock::snapshot()?.utc;
    let (carrier, presence) =
        cbcl_pairing::credential_v2::CredentialV2ManualBootstrap::recognise_pair(
            &bootstrap, &words, now,
        )
        .map_err(|_| UiError::from("RecognitionFailed"))?;
    let now = i64::try_from(now).map_err(|_| UiError::from("PairingClockUnavailable"))?;
    let entry = RecognisedCredentialV2Entry::from_parts(carrier, presence, now)?;
    reserve_entry(entry, &session)
}

/// Shared by complete and manual entry after complete local recognition.
pub(crate) fn reserve_entry(
    entry: RecognisedCredentialV2Entry,
    session: &AppSession,
) -> Result<ReservationView> {
    let mut guard = session.0.lock().unwrap_or_else(|p| p.into_inner());
    let operation = guard.cbcl_v2_attempts.begin_single_link()?;
    let view = ReservationView {
        attempt_tag: operation.attempt.tag(),
        phase: "reserved",
        application_id: entry.application_id().into(),
        relay_origin: entry.relay_origin().into(),
    };
    guard.pending_cbcl_v2 = None;
    guard.pending_cbcl_v2_relay = None;
    guard.pending_cbcl_v2_execution = None;
    guard.pending_cbcl_v2_entry = Some(entry);
    operation.retain();
    Ok(view)
}

#[tauri::command]
pub async fn cbcl_v2_contact(
    request: TaggedRequest,
    session: State<'_, AppSession>,
) -> Result<ContactView> {
    let (entry, operation) = {
        let mut guard = session.0.lock().unwrap_or_else(|p| p.into_inner());
        guard
            .cbcl_v2_attempts
            .tagged(&request.attempt_tag)?
            .check()?;
        if guard.pending_cbcl_v2_entry.is_none() {
            return Err(UiError::from("PairingWrongPhase"));
        }
        let operation = guard.cbcl_v2_attempts.start_work()?;
        (
            guard
                .pending_cbcl_v2_entry
                .take()
                .expect("checked reservation"),
            operation,
        )
    };
    let now = i64::try_from(crate::cbcl_v2_clock::snapshot()?.utc)
        .map_err(|_| UiError::from("PairingClockUnavailable"))?;
    let capability = operation.attempt.io(entry.contact(now)).await?;
    let mut scalar = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut scalar);
    let claimant = operation
        .attempt
        .run(|| cbcl_v2_claimant::prepare_claimant(capability, scalar))?;
    let target = cbcl_transport::relay_target(claimant.relay_origin()).map_err(map_transport)?;
    let attempt = operation.attempt.clone();
    let (pending, intent) = pairing_blocking(&operation, move || {
        let socket = attempt.run(|| cbcl_transport::connect_wss(&target).map_err(map_transport))?;
        pump_to_offer(claimant, socket, attempt)
    })
    .await?;
    put_pending(&session, pending, operation)?;
    Ok(ContactView {
        phase: "authenticated-request",
        intent,
    })
}

fn take_single(
    session: &AppSession,
    tag: &str,
    phase: CredentialV2Phase,
) -> Result<(PendingCredentialV2Pairing, CredentialV2Operation)> {
    let mut guard = session.0.lock().unwrap_or_else(|p| p.into_inner());
    let attempt = guard.cbcl_v2_attempts.tagged(tag)?;
    attempt.check()?;
    let pending = guard
        .pending_cbcl_v2
        .as_ref()
        .ok_or_else(|| UiError::from("PairingWrongPhase"))?;
    if pending.claimant.flow() != CredentialV2Flow::SingleLink {
        return Err(UiError::from("PairingWrongMode"));
    }
    guard.cbcl_v2_attempts.ensure_current(&pending.attempt)?;
    pending.phase.require(phase)?;
    let operation = guard.cbcl_v2_attempts.start_work()?;
    Ok((
        guard.pending_cbcl_v2.take().expect("checked pending"),
        operation,
    ))
}

fn derive_preview(
    claimant: &PreparedClaimant,
    root: &selfsame_app_identity::hierarchy::HierarchyRoot,
) -> Result<String> {
    let offer = claimant
        .authenticated_offer()
        .ok_or_else(|| UiError::from("PairingFailed"))?;
    let recognised =
        selfsame_pairing::credential_v2::recognise_signed_offer(claimant.profile(), offer.body())
            .map_err(|_| UiError::from("PairingFailed"))?;
    let scope = selfsame_app_identity::scope::AccountScopeId::from_octets(
        *recognised.claims.account_provenance().account_scope_id(),
    );
    selfsame_app_identity::hierarchy::derive(root, &claimant.profile().application_id, &scope)
        .home_did()
        .map_err(|_| UiError::from("PairingIdentityUnavailable"))
}

#[tauri::command]
pub async fn cbcl_v2_unlock_preview(
    request: UnlockPreviewRequest,
    session: State<'_, AppSession>,
) -> Result<PreviewView> {
    let passcode = Zeroizing::new(request.passcode);
    let (mut pending, operation) =
        take_single(&session, &request.attempt_tag, CredentialV2Phase::Intent)?;
    let (pending, review) = pairing_blocking(&operation, move || {
        // No decision builder, reducer preparation, or I/O occurs during unlock.
        let offer = pending
            .claimant
            .authenticated_offer()
            .ok_or_else(|| UiError::from("PairingFailed"))?;
        let recognised = selfsame_pairing::credential_v2::recognise_signed_offer(
            pending.claimant.profile(),
            offer.body(),
        )
        .map_err(|_| UiError::from("PairingFailed"))?;
        let (root, start) = pending.attempt.run(|| {
            let root = crate::custody::Custody::unlock_hierarchy_root(&passcode)?;
            let start = crate::cbcl_v2_clock::snapshot()?;
            Ok((root, start))
        })?;
        pending.attempt.bind_deadline(
            start,
            recognised.expires_at,
            pending.claimant.carrier().relay_expires_at(),
        )?;
        let preview = pending
            .attempt
            .run(|| derive_preview(&pending.claimant, &root))?;
        pending.attempt.retain_custody(root)?;
        pending.ceremony_custody = Some(CeremonyCustody::Bounded(pending.attempt.clone()));
        pending.preview_did = Some(Zeroizing::new(preview));
        pending.phase = CredentialV2Phase::PreviewUnpainted;
        let review = final_review_view(&pending, "waiting")?;
        Ok((pending, review))
    })
    .await?;
    put_pending(&session, pending, operation)?;
    Ok(PreviewView {
        phase: "preview-unpainted",
        review,
    })
}

#[tauri::command]
pub async fn cbcl_v2_preview_rendered(
    request: TaggedRequest,
    session: State<'_, AppSession>,
) -> Result<PhaseView> {
    let (mut pending, operation) = take_single(
        &session,
        &request.attempt_tag,
        CredentialV2Phase::PreviewUnpainted,
    )?;
    pending.attempt.check()?;
    pending.phase = CredentialV2Phase::ReviewReady;
    put_pending(&session, pending, operation)?;
    Ok(PhaseView {
        phase: "review-ready",
    })
}

#[cfg(test)]
static DECISIONS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
fn intent_approval(
    pending: &PendingCredentialV2Pairing,
) -> Result<cbcl_pairing::credential_v2::CredentialV2Object> {
    pending.attempt.run(|| {
        let offer = pending
            .claimant
            .authenticated_offer()
            .ok_or_else(|| UiError::from("PairingFailed"))?;
        let decision = pending
            .claimant
            .body_authority()
            .intent_decision(
                offer,
                selfsame_pairing::credential_v2::CredentialV2IntentDecision::Approve,
            )
            .map_err(|_| UiError::from("PairingFailed"))?;
        #[cfg(test)]
        DECISIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(decision)
    })
}

// Neither type implements Clone, Debug or serde. The whole claimant owns all
// exact immutable carrier/profile/transcript/offer/claims and the only reducer.
struct LinkAuthorization {
    pending: PendingCredentialV2Pairing,
}
pub(crate) struct LinkExecution {
    pending: PendingCredentialV2Pairing,
}
impl LinkAuthorization {
    fn consume(mut self) -> Result<LinkExecution> {
        let pending = &mut self.pending;
        pending.attempt.check()?;
        pending.phase.require(CredentialV2Phase::ReviewReady)?;
        pending.phase = CredentialV2Phase::Comparing;
        let approval = intent_approval(pending)?;
        send_claimant_object(pending, &approval)?;
        wait_outbound_ack(pending)?;
        let preview = pending
            .preview_did
            .as_ref()
            .ok_or_else(|| UiError::from("PairingFailed"))?;
        let preparation = pending.attempt.run(|| {
            pending
                .claimant
                .body_authority()
                .preparation(&approval, preview)
                .map_err(|_| UiError::from("PairingFailed"))
        })?;
        send_claimant_object(pending, &preparation)?;
        pending.intent_approve = Some(approval);
        Ok(LinkExecution {
            pending: self.pending,
        })
    }
}

#[tauri::command]
pub async fn cbcl_v2_link(
    request: TaggedRequest,
    session: State<'_, AppSession>,
) -> Result<PhaseView> {
    // take_single consumes ReviewReady under Session's mutex before any await.
    let (pending, operation) = take_single(
        &session,
        &request.attempt_tag,
        CredentialV2Phase::ReviewReady,
    )?;
    let authorization = LinkAuthorization { pending };
    let execution = pairing_blocking(&operation, move || authorization.consume()).await?;
    let mut guard = session.0.lock().unwrap_or_else(|p| p.into_inner());
    guard.update_cbcl_v2_attempt(&operation.attempt, |s| {
        if s.pending_cbcl_v2_execution.is_some() {
            return Err(UiError::from("PairingWrongPhase"));
        }
        s.pending_cbcl_v2_execution = Some(execution);
        Ok(())
    })?;
    operation.retain();
    Ok(PhaseView { phase: "comparing" })
}

#[tauri::command]
pub async fn cbcl_v2_continue_link(
    request: TaggedRequest,
    session: State<'_, AppSession>,
) -> Result<PhaseView> {
    continue_link_with_faults(request, &session, &mut NoPrePayloadFaults).await
}

async fn continue_link_with_faults(
    request: TaggedRequest,
    session: &AppSession,
    faults: &mut impl PrePayloadFaultSink,
) -> Result<PhaseView> {
    let (execution, operation) = {
        let mut guard = session.0.lock().unwrap_or_else(|p| p.into_inner());
        guard
            .cbcl_v2_attempts
            .tagged(&request.attempt_tag)?
            .check()?;
        if guard.pending_cbcl_v2_execution.is_none() {
            return Err(UiError::from("PairingWrongPhase"));
        }
        let operation = guard.cbcl_v2_attempts.start_work()?;
        (
            guard
                .pending_cbcl_v2_execution
                .take()
                .expect("checked execution"),
            operation,
        )
    };
    let (mut pending, final_approval) = pairing_blocking(&operation, move || {
        let mut pending = execution.pending;
        let comparison = pump_to_comparison(&mut pending)?;
        let final_approval = pending.attempt.run(|| {
            pending
                .claimant
                .body_authority()
                .final_decision(
                    &comparison,
                    selfsame_pairing::credential_v2::CredentialV2FinalDecision::Approve,
                )
                .map_err(|_| UiError::from("PairingFailed"))
        })?;
        pending.comparison = Some(comparison);
        pending.phase = CredentialV2Phase::FinalReview;
        Ok((pending, final_approval))
    })
    .await?;
    let custody = pending
        .ceremony_custody
        .take()
        .ok_or_else(|| UiError::from("PairingExpired"))?;
    complete_approved(pending, operation, final_approval, custody, session, faults).await?;
    Ok(PhaseView {
        phase: "await-receipt",
    })
}

#[tauri::command]
pub async fn cbcl_v2_finish_link(
    request: TaggedRequest,
    session: State<'_, AppSession>,
) -> Result<CredentialV2FinishView> {
    let (pending, operation) = take_single(
        &session,
        &request.attempt_tag,
        CredentialV2Phase::PayloadSent,
    )?;
    finish_pending(pending, operation, Zeroizing::new(String::new()), &session).await
}

#[tauri::command]
pub async fn cbcl_v2_cancel_link(
    request: TaggedRequest,
    session: State<'_, AppSession>,
) -> Result<()> {
    let mut guard = session.0.lock().unwrap_or_else(|p| p.into_inner());
    // Cancellation requires only the exact tag/mode, even after expiry/background.
    guard.cbcl_v2_attempts.tagged(&request.attempt_tag)?;
    guard.revoke_cbcl_v2();
    Ok(())
}

#[cfg(test)]
#[path = "cbcl_v2_single_link_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "cbcl_v2_manual_entry_tests.rs"]
mod manual_tests;
