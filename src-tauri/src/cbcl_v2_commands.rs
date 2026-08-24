//! Tauri shell for standalone credential/v2 relay and preliminary consent.

use cbcl_pairing::{
    credential_v2::{CredentialV2ClaimantEffect, CredentialV2Kind, CredentialV2TofuState},
    wire::{encode_client_message, ClientMessage},
};
use rand::RngCore as _;
use serde::Serialize;
use std::net::TcpStream;
use tauri::State;
use tungstenite::{stream::MaybeTlsStream, Message, WebSocket};

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
    preview_did: Option<String>,
    comparison: Option<cbcl_pairing::credential_v2::CredentialV2Object>,
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
                            preview_did: None,
                            comparison: None,
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
