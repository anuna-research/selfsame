//! Tauri shell for standalone credential/v2 relay and preliminary consent.

use cbcl_pairing::{
    credential_v2::{CredentialV2ClaimantEffect, CredentialV2Kind, CredentialV2TofuState},
    wire::{encode_client_message, ClientMessage},
};
use rand::RngCore as _;
use serde::Serialize;
use sha2::Digest as _;
use std::net::TcpStream;
use tauri::State;
use tungstenite::{stream::MaybeTlsStream, Message, WebSocket};
use zeroize::Zeroizing;

use crate::{
    cbcl_transport,
    cbcl_v2_claimant::{
        self, PreparedClaimant, RelayConsentDecision, RelayConsentPlan, RelayConsentView,
    },
    cbcl_v2_policy::ExactPairState,
    commands::{AppSession, UiError},
};

type Result<T> = std::result::Result<T, UiError>;

/// Live claimant held only after the one-use pre-socket authority is consumed.
pub struct PendingCredentialV2Pairing {
    claimant: PreparedClaimant,
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    intent_approve: Option<cbcl_pairing::credential_v2::CredentialV2Object>,
    preview_did: Option<String>,
    comparison: Option<cbcl_pairing::credential_v2::CredentialV2Object>,
    recovered_receipt: Option<cbcl_pairing::credential_v2::CredentialV2ClaimantRecoveredReceipt>,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CredentialV2AuthorityRotationView {
    retained_kid: String,
    current_kid: Option<String>,
    retained_profile_digest: String,
    current_profile_digest: String,
}

/// Recognise carrier, PAIR1, live profile, declared relay, and exact-pair state.
/// No relay socket is opened by this command.
#[tauri::command]
pub async fn cbcl_v2_recognise(
    invitation: String,
    presence_code: String,
    session: State<'_, AppSession>,
) -> Result<RelayConsentView> {
    let now = crate::commands::now() as i64;
    let plan = cbcl_v2_claimant::recognise_claimant_invitation(
        invitation.trim(),
        presence_code.trim(),
        now,
    )
    .await?;
    let view = plan.view();
    let mut guard = session
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.pending_cbcl_v2.is_some() {
        return Err(UiError::from("PairingAlreadyActive"));
    }
    guard.pending_cbcl_v2_relay = Some(plan);
    Ok(view)
}

/// Consume the exact relay decision, open WSS only on approval, and stop at
/// the authenticated preliminary-intent display.
#[tauri::command]
pub async fn cbcl_v2_relay_decide(
    approve: bool,
    session: State<'_, AppSession>,
) -> Result<CredentialV2RelayDecisionView> {
    let plan = take_relay_plan(&session)?;
    let decision = match (plan.pair_state(), approve) {
        (_, false) => RelayConsentDecision::Decline,
        (ExactPairState::NewPair, true) => RelayConsentDecision::Approve,
        (ExactPairState::TrustedPair, true) => RelayConsentDecision::ExistingTrust,
    };
    let Some(capability) = cbcl_v2_claimant::authorise_claimant_relay(plan, decision)? else {
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
    let (pending, intent) = tauri::async_runtime::spawn_blocking(move || {
        let socket = cbcl_transport::connect_wss(&target).map_err(map_transport)?;
        pump_to_offer(claimant, socket)
    })
    .await
    .map_err(|_| UiError::from("PairingFailed"))??;
    session
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .pending_cbcl_v2 = Some(pending);
    Ok(CredentialV2RelayDecisionView {
        outcome: "intent",
        intent: Some(intent),
    })
}

/// Commit preliminary consent. Approval permits exactly one custody call for
/// pure DID preview, sends that preview inside the protected channel, and
/// stops at the authenticated comparison result. It signs or publishes nothing.
#[tauri::command]
pub async fn cbcl_v2_preliminary_decide(
    approve: bool,
    passcode: Option<String>,
    session: State<'_, AppSession>,
) -> Result<CredentialV2PreliminaryDecisionView> {
    let mut pending = take_pending(&session)?;
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
        return Ok(CredentialV2PreliminaryDecisionView {
            outcome: "declined",
            final_review: None,
        });
    }
    let passcode = passcode.expect("approved path checked presence above");
    let (pending, view) = tauri::async_runtime::spawn_blocking(move || {
        wait_outbound_ack(&mut pending)?;
        let preview_did = preview_identity(&pending.claimant, &passcode)?;
        let preparation = pending
            .claimant
            .body_authority()
            .preparation(&decision, &preview_did)
            .map_err(|_| UiError::from("PairingFailed"))?;
        send_claimant_object(&mut pending, &preparation)?;
        let comparison = pump_to_comparison(&mut pending)?;
        let comparison_name = match comparison.kind() {
            CredentialV2Kind::ComparisonConfirmed => "no-binding-person-compared",
            CredentialV2Kind::BindingConfirmed => "bound-same-did",
            _ => return Err(UiError::from("PairingFailed")),
        };
        let application_id = pending.claimant.profile().application_id.as_str().into();
        let preview_fingerprint = selfsame_core::fingerprint::fingerprint_did(&preview_did).into();
        pending.preview_did = Some(preview_did.clone());
        pending.intent_approve = Some(decision);
        pending.comparison = Some(comparison);
        Ok::<_, UiError>((
            pending,
            CredentialV2FinalReviewView {
                application_id,
                preview_issuer_did: preview_did,
                preview_fingerprint,
                comparison: comparison_name,
            },
        ))
    })
    .await
    .map_err(|_| UiError::from("PairingFailed"))??;
    session
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .pending_cbcl_v2 = Some(pending);
    Ok(CredentialV2PreliminaryDecisionView {
        outcome: "final-review",
        final_review: Some(view),
    })
}

/// Commit the second person decision. Final approval is checkpointed into the
/// application's secure-store slot before its protocol frame is released.
/// No issuer or grant effect is performed by this first durable boundary.
#[tauri::command]
pub async fn cbcl_v2_final_decide(
    approve: bool,
    passcode: Option<String>,
    session: State<'_, AppSession>,
) -> Result<CredentialV2FinalDecisionView> {
    let mut pending = take_pending(&session)?;
    let comparison = pending
        .comparison
        .clone()
        .ok_or_else(|| UiError::from("PairingFailed"))?;
    let preview_did = pending
        .preview_did
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
        return Ok(CredentialV2FinalDecisionView {
            outcome: "declined",
        });
    }

    let passcode = passcode
        .filter(|value| !value.is_empty())
        .ok_or_else(|| UiError::from("PresenceRequired"))?;
    crate::custody::Custody::require_backup_confirmed()?;
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

    let (generation, checkpoint) =
        crate::custody::Custody::use_hierarchy_root(&passcode, |root| -> Result<_> {
            let claims = recognised.claims.account_provenance();
            let scope = selfsame_app_identity::scope::AccountScopeId::from_octets(
                *claims.account_scope_id(),
            );
            let home = selfsame_app_identity::hierarchy::derive(
                root,
                &pending.claimant.profile().application_id,
                &scope,
            );
            let final_did = home
                .home_did()
                .map_err(|_| UiError::from("PairingIdentityUnavailable"))?;
            let final_fingerprint: [u8; 32] = sha2::Sha256::digest(final_did.as_bytes()).into();
            if final_did != preview_did || final_fingerprint != preview_fingerprint {
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
        })??;

    let mut durable = crate::cbcl_v2_completion::PendingCredentialV2Completion::new(
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
    crate::cbcl_v2_completion::persist_pending(&durable)?;
    let effects = pending
        .claimant
        .core_mut()
        .checkpoint_persisted(generation)
        .map_err(|_| UiError::from("PairingFailed"))?;
    send_effects(&mut pending.socket, effects)?;

    // The blind relay acknowledgement changes the cached-frame projection.
    // Seal and replace the pending record before any identity signature.
    let acknowledgement = read_binary(&mut pending.socket)?;
    let acknowledgement_now = crate::commands::now();
    let mut acknowledgement_nonce = [0_u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut acknowledgement_nonce);
    let acknowledgement_effects =
        crate::custody::Custody::use_hierarchy_root(&passcode, |root| -> Result<_> {
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
        })??;
    let (acknowledgement_generation, acknowledgement_checkpoint) =
        one_checkpoint(acknowledgement_effects)?;
    let acknowledged =
        durable.with_checkpoint(acknowledgement_generation, &acknowledgement_checkpoint)?;
    crate::cbcl_v2_completion::replace_pending(&durable, &acknowledged)?;
    let after_acknowledgement = pending
        .claimant
        .core_mut()
        .checkpoint_persisted(acknowledgement_generation)
        .map_err(|_| UiError::from("PairingFailed"))?;
    if !after_acknowledgement.is_empty() {
        return Err(UiError::from("PairingFailed"));
    }
    durable = acknowledged;

    let profile = pending.claimant.profile().clone();
    let plan = crate::cbcl_v2_completion::CredentialV2ProvisioningPlan::from_authenticated_offer(
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
    let planned = durable.planned(effect_time, grant_id)?;
    crate::cbcl_v2_completion::replace_pending(&durable, &planned)?;
    durable = planned;

    // First final signature: issuer creation only. The deterministic plan was
    // durable before this custody call, and the preview is re-derived before
    // issuer construction inside the call.
    let issuer = crate::custody::Custody::use_hierarchy_root(&passcode, |root| {
        crate::cbcl_v2_completion::build_issuer_artifacts(root, &plan, effect_time)
    })??;
    let issuer_created = durable.issuer_created(&issuer)?;
    crate::cbcl_v2_completion::replace_pending(&durable, &issuer_created)?;
    durable = issuer_created;

    let publication =
        selfsame_app_identity_net::state::publish_issuer_identity(&profile, &issuer.identity)
            .await
            .map_err(|_| UiError::from("PairingResolverUnavailable"))?;
    if publication.acknowledged.is_empty() {
        return Err(UiError::from("PairingResolverUnavailable"));
    }
    let resolved = selfsame_app_identity_net::state::resolve_closure(
        &profile,
        &issuer.identity.did,
        None,
        selfsame_app_identity_net::state::Acceptance::Repeat,
    )
    .await
    .map_err(|_| UiError::from("PairingResolverUnavailable"))?;
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
    let grant = crate::custody::Custody::use_hierarchy_root(&passcode, |root| {
        crate::cbcl_v2_completion::build_grant_artifacts(
            root,
            &plan,
            &issuer,
            grant_id,
            effect_time,
            profile.revocation.max_grant_lifetime_seconds,
        )
    })??;
    let provisioned = durable.provisioned(&grant)?;
    crate::cbcl_v2_completion::replace_pending(&durable, &provisioned)?;

    let payload = pending
        .claimant
        .body_authority()
        .payload(
            &final_decision,
            selfsame_pairing::credential_v2::CredentialV2PayloadInput {
                grant_id: grant.grant_id,
                grant: grant.grant.clone(),
            },
        )
        .map_err(|_| UiError::from("PairingFailed"))?;
    let payload_now = crate::commands::now();
    if payload_now >= recognised.expires_at {
        return Err(UiError::from("PairingOfferExpired"));
    }
    let mut payload_nonce = [0_u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut payload_nonce);
    let payload_effects =
        crate::custody::Custody::use_hierarchy_root(&passcode, |root| -> Result<_> {
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
        })??;
    let (payload_generation, payload_checkpoint) = one_checkpoint(payload_effects)?;
    let payload_prepared = provisioned
        .payload_prepared(payload.content_hash())?
        .with_checkpoint(payload_generation, &payload_checkpoint)?;
    crate::cbcl_v2_completion::replace_pending(&provisioned, &payload_prepared)?;
    let payload_release = pending
        .claimant
        .core_mut()
        .checkpoint_persisted(payload_generation)
        .map_err(|_| UiError::from("PairingFailed"))?;
    send_effects(&mut pending.socket, payload_release)?;
    session
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .pending_cbcl_v2 = Some(pending);
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
    let passcode = passcode
        .filter(|value| !value.is_empty())
        .ok_or_else(|| UiError::from("PresenceRequired"))?;
    let pending = take_pending(&session)?;
    let (mut pending, prepared) =
        tauri::async_runtime::spawn_blocking(move || prepare_received_receipt(pending, &passcode))
            .await
            .map_err(|_| UiError::from("PairingFailed"))?;
    let (durable, receipt_recovery_commitment) = match prepared {
        Ok(value) => value,
        Err(error) => {
            put_pending(&session, pending);
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
                put_pending(&session, pending);
                return Err(error);
            }
        };
    let live_profile = pending.claimant.profile().clone();
    let live_account = match installed.account() {
        Ok(value) => value,
        Err(error) => {
            put_pending(&session, pending);
            return Err(error);
        }
    };
    let live_issuer_did = installed.issuer_did().to_owned();
    let jrd = match verify_live_installation(live_profile, live_account, live_issuer_did).await {
        Ok(value) => value,
        Err(error) => {
            put_pending(&session, pending);
            return Err(error);
        }
    };
    if let Err(error) = crate::cbcl_v2_completion::install(&durable, &installed, &jrd) {
        put_pending(&session, pending);
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
            let _ = tauri::async_runtime::spawn_blocking(move || {
                let _ = send_effects(&mut pending.socket, effects);
            })
            .await;
        }
    }
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

/// Cancel a pre-socket decision or close one live credential/v2 relay session.
#[tauri::command]
pub async fn cbcl_v2_cancel(session: State<'_, AppSession>) -> Result<()> {
    let pending = {
        let mut guard = session
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.pending_cbcl_v2_relay = None;
        guard.pending_cbcl_v2.take()
    };
    if let Some(mut pending) = pending {
        let _ = tauri::async_runtime::spawn_blocking(move || {
            if let Ok(close) = encode_client_message(&ClientMessage::Close) {
                let _ = pending.socket.send(Message::Binary(close.into()));
            }
        })
        .await;
    }
    Ok(())
}

fn take_relay_plan(session: &State<'_, AppSession>) -> Result<RelayConsentPlan> {
    session
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .pending_cbcl_v2_relay
        .take()
        .ok_or_else(|| UiError::from("PairingNotStarted"))
}

fn pump_to_offer(
    mut claimant: PreparedClaimant,
    mut socket: WebSocket<MaybeTlsStream<TcpStream>>,
) -> Result<(PendingCredentialV2Pairing, CredentialV2IntentView)> {
    let start = claimant
        .core_mut()
        .start()
        .map_err(|_| UiError::from("PairingFailed"))?;
    socket
        .send(Message::Binary(start.into()))
        .map_err(|_| UiError::from("PairingRelayUnavailable"))?;
    loop {
        let bytes = read_binary(&mut socket)?;
        let effects = claimant
            .core_mut()
            .receive(&bytes, crate::commands::now())
            .map_err(|_| UiError::from("PairingFailed"))?;
        for effect in effects {
            match effect {
                CredentialV2ClaimantEffect::Send(bytes) => socket
                    .send(Message::Binary(bytes.into()))
                    .map_err(|_| UiError::from("PairingRelayUnavailable"))?,
                CredentialV2ClaimantEffect::Established { transcript_hash } => {
                    claimant.bind_finished_profile(transcript_hash)?;
                }
                CredentialV2ClaimantEffect::DisplayIntent(display) => {
                    let view = intent_view(&display);
                    return Ok((
                        PendingCredentialV2Pairing {
                            claimant,
                            socket,
                            intent_approve: None,
                            preview_did: None,
                            comparison: None,
                            recovered_receipt: None,
                        },
                        view,
                    ));
                }
                CredentialV2ClaimantEffect::ReceivedObject { .. }
                | CredentialV2ClaimantEffect::Checkpoint { .. }
                | CredentialV2ClaimantEffect::Terminal => {
                    return Err(UiError::from("PairingFailed"));
                }
            }
        }
    }
}

fn put_pending(session: &State<'_, AppSession>, pending: PendingCredentialV2Pairing) {
    session
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .pending_cbcl_v2 = Some(pending);
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
        let mut durable = crate::cbcl_v2_completion::load_pending(&application_id)?;
        while pending.claimant.core_mut().has_cached_outbound_frame() {
            let acknowledgement = read_binary(&mut pending.socket)?;
            let mut nonce = [0_u8; 12];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let effects = crate::custody::Custody::use_hierarchy_root(passcode, |root| {
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
                        crate::commands::now(),
                        &wrapping_key,
                        cbcl_pairing::credential_v2::CredentialV2CheckpointNonce::from_csprng(
                            nonce,
                        ),
                    )
                    .map_err(|_| UiError::from("PairingFailed"))
            })??;
            let (generation, checkpoint) = one_checkpoint(effects)?;
            let acknowledged = durable.with_checkpoint(generation, &checkpoint)?;
            crate::cbcl_v2_completion::replace_pending(&durable, &acknowledged)?;
            let after = pending
                .claimant
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
            let frame = read_binary(&mut pending.socket)?;
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

fn take_pending(session: &State<'_, AppSession>) -> Result<PendingCredentialV2Pairing> {
    session
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .pending_cbcl_v2
        .take()
        .ok_or_else(|| UiError::from("PairingNotStarted"))
}

fn send_claimant_object(
    pending: &mut PendingCredentialV2Pairing,
    object: &cbcl_pairing::credential_v2::CredentialV2Object,
) -> Result<()> {
    let effects = pending
        .claimant
        .core_mut()
        .prepare_application_object(object)
        .map_err(|_| UiError::from("PairingFailed"))?;
    for effect in effects {
        match effect {
            CredentialV2ClaimantEffect::Send(bytes) => pending
                .socket
                .send(Message::Binary(bytes.into()))
                .map_err(|_| UiError::from("PairingRelayUnavailable"))?,
            _ => return Err(UiError::from("PairingFailed")),
        }
    }
    Ok(())
}

fn send_effects(
    socket: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    effects: Vec<CredentialV2ClaimantEffect>,
) -> Result<()> {
    for effect in effects {
        match effect {
            CredentialV2ClaimantEffect::Send(bytes) => {
                socket
                    .send(Message::Binary(bytes.into()))
                    .map_err(|_| UiError::from("PairingRelayUnavailable"))?
            }
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
    while pending.claimant.core_mut().has_cached_outbound_frame() {
        let bytes = read_binary(&mut pending.socket)?;
        let effects = pending
            .claimant
            .core_mut()
            .receive(&bytes, crate::commands::now())
            .map_err(|_| UiError::from("PairingFailed"))?;
        for effect in effects {
            match effect {
                CredentialV2ClaimantEffect::Send(bytes) => pending
                    .socket
                    .send(Message::Binary(bytes.into()))
                    .map_err(|_| UiError::from("PairingRelayUnavailable"))?,
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
        let bytes = read_binary(&mut pending.socket)?;
        let effects = pending
            .claimant
            .core_mut()
            .receive(&bytes, crate::commands::now())
            .map_err(|_| UiError::from("PairingFailed"))?;
        for effect in effects {
            match effect {
                CredentialV2ClaimantEffect::Send(bytes) => pending
                    .socket
                    .send(Message::Binary(bytes.into()))
                    .map_err(|_| UiError::from("PairingRelayUnavailable"))?,
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

fn read_binary(socket: &mut WebSocket<MaybeTlsStream<TcpStream>>) -> Result<Vec<u8>> {
    loop {
        match socket.read() {
            Ok(Message::Binary(bytes)) => return Ok(bytes.to_vec()),
            Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => {}
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
