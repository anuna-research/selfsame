//! Tauri's one-sided `cbcl-pairing` claimant shell.
//!
//! Ordinary builds retain only the invitation-authenticated pending endpoint.
//! A build carrying the explicit `local-pairing-demo` capability connects only
//! to a canonical `https://localhost:PORT` invitation and maps that origin to
//! the same loopback port's plain WebSocket conformance listener. Production
//! invitation allocation remains compile-time disabled.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use rand::RngCore as _;
use serde::Serialize;
use tauri::State;

use crate::commands::{AppSession, UiError};
#[cfg(not(feature = "local-pairing-demo"))]
use selfsame_pairing::SelfsameEndpointBootstrap;
use selfsame_pairing::{
    legacy::{self, LegacyRejectionClass, LegacySurface},
    IntegrationError,
};

#[cfg(feature = "local-pairing-demo")]
use {
    selfsame_app_identity::cbcl_relay::{self, RelayPolicy},
    selfsame_pairing::{
        live::{ClaimantRelaySession, LiveEffect, LiveOutcome},
        local_demo,
    },
    std::{net::TcpStream, time::Duration},
    tungstenite::{client, Message, WebSocket},
};

type Result<T> = std::result::Result<T, UiError>;

/// Non-secret values returned after the claimant reaches exact-intent consent.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CbclPairingStartView {
    relay_origin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpace_frame: Option<String>,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    intent: Option<CbclIntentView>,
}

/// Exact intent fields released by the authenticated CBCL profile.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CbclIntentView {
    application: String,
    action: String,
    authority_summary: String,
    fields: Vec<CbclIntentFieldView>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CbclIntentFieldView {
    label: String,
    value: String,
    claimed_by_secret_holder: bool,
}

/// Terminal text contains no credential or verifier detail.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CbclPairingResultView {
    outcome: &'static str,
    title: &'static str,
    message: &'static str,
}

/// Live socket state exists only in the compile-time local demo build.
#[cfg(feature = "local-pairing-demo")]
pub struct PendingCbclPairing {
    core: ClaimantRelaySession,
    socket: WebSocket<TcpStream>,
}

/// Begin Selfsame's claimant endpoint with no protocol choice or legacy path.
#[tauri::command]
pub async fn cbcl_pairing_start(
    invitation: String,
    session: State<'_, AppSession>,
) -> Result<CbclPairingStartView> {
    #[cfg(feature = "local-pairing-demo")]
    {
        let (pending, view) = tauri::async_runtime::spawn_blocking(move || start_live(invitation))
            .await
            .map_err(|_| UiError::from("PairingFailed"))??;
        session
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pending_cbcl_pairing = Some(pending);
        return Ok(view);
    }

    #[cfg(not(feature = "local-pairing-demo"))]
    {
        let invitation = decode_carrier(&invitation)?;
        let mut cpace_scalar = [0_u8; 32];
        let mut signing_seed = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut cpace_scalar);
        rand::rngs::OsRng.fill_bytes(&mut signing_seed);
        let endpoint =
            SelfsameEndpointBootstrap::join_claimant(&invitation, cpace_scalar, signing_seed)
                .map_err(map_error)?;
        let view = CbclPairingStartView {
            relay_origin: endpoint.relay_origin().to_owned(),
            cpace_frame: Some(Base64UrlUnpadded::encode_string(
                &endpoint.local_cpace_frame_bytes().map_err(map_error)?,
            )),
            status: "Secure pairing started. Waiting for the application.",
            intent: None,
        };
        session
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pending_cbcl_pairing = Some(endpoint);
        Ok(view)
    }
}

/// Commit the exact displayed approval and wait for Selfsame acceptance.
#[tauri::command]
pub async fn cbcl_pairing_approve(
    _session: State<'_, AppSession>,
) -> Result<CbclPairingResultView> {
    #[cfg(feature = "local-pairing-demo")]
    {
        let pending = take_pending(&_session)?;
        return tauri::async_runtime::spawn_blocking(move || finish_live(pending, true))
            .await
            .map_err(|_| UiError::from("PairingFailed"))?;
    }
    #[cfg(not(feature = "local-pairing-demo"))]
    Err(UiError::from("PairingUnavailable"))
}

/// Commit an explicit decline; no payload or Selfsame verifier call follows.
#[tauri::command]
pub async fn cbcl_pairing_decline(
    _session: State<'_, AppSession>,
) -> Result<CbclPairingResultView> {
    #[cfg(feature = "local-pairing-demo")]
    {
        let pending = take_pending(&_session)?;
        return tauri::async_runtime::spawn_blocking(move || finish_live(pending, false))
            .await
            .map_err(|_| UiError::from("PairingFailed"))?;
    }
    #[cfg(not(feature = "local-pairing-demo"))]
    Err(UiError::from("PairingUnavailable"))
}

/// Burn the pending endpoint locally and close its development mailbox.
#[tauri::command]
pub async fn cbcl_pairing_cancel(session: State<'_, AppSession>) -> Result<()> {
    #[cfg(feature = "local-pairing-demo")]
    {
        let pending = session
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pending_cbcl_pairing
            .take();
        if let Some(mut pending) = pending {
            let _ = tauri::async_runtime::spawn_blocking(move || {
                if let Ok(effects) = pending.core.cancel() {
                    let _ = send_effects(&mut pending.socket, effects);
                }
            })
            .await;
        }
    }
    #[cfg(not(feature = "local-pairing-demo"))]
    {
        session
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pending_cbcl_pairing = None;
    }
    Ok(())
}

#[cfg(feature = "local-pairing-demo")]
fn start_live(invitation: String) -> Result<(PendingCbclPairing, CbclPairingStartView)> {
    let invitation = decode_carrier(&invitation)?;
    let recognised =
        selfsame_pairing::decode_selfsame_invitation(&invitation).map_err(map_error)?;
    let relay_origin = recognised.relay_origin.clone();
    let fixture = local_demo::credential(&relay_origin).map_err(map_error)?;
    let approved = [local_demo::LOCAL_CONFORMANCE_DIGEST];
    cbcl_relay::verify_invitation_origin(
        &fixture.verification.profile,
        &RelayPolicy {
            forbidden_operator_ids: &[],
            approved_conformance: &approved,
            allow_loopback: true,
        },
        &relay_origin,
    )
    .map_err(|_| UiError::from("PairingRelayRefused"))?;

    let (websocket_url, port) = local_websocket_url(&relay_origin)?;
    let stream = TcpStream::connect(("127.0.0.1", port))
        .map_err(|_| UiError::from("PairingRelayUnavailable"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|_| UiError::from("PairingRelayUnavailable"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(15)))
        .map_err(|_| UiError::from("PairingRelayUnavailable"))?;
    let (mut socket, _) = client(websocket_url.as_str(), stream)
        .map_err(|_| UiError::from("PairingRelayUnavailable"))?;

    let mut cpace_scalar = [0_u8; 32];
    let mut signing_seed = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut cpace_scalar);
    rand::rngs::OsRng.fill_bytes(&mut signing_seed);
    let mut core = ClaimantRelaySession::new(
        &invitation,
        cpace_scalar,
        signing_seed,
        fixture.verification,
    )
    .map_err(map_error)?;
    socket
        .send(Message::Binary(core.start().map_err(map_error)?.into()))
        .map_err(|_| UiError::from("PairingRelayUnavailable"))?;

    loop {
        let bytes = read_binary(&mut socket)?;
        let effects = core.receive(&bytes).map_err(map_error)?;
        let mut intent = None;
        for effect in effects {
            match effect {
                LiveEffect::Send(bytes) => socket
                    .send(Message::Binary(bytes.into()))
                    .map_err(|_| UiError::from("PairingRelayUnavailable"))?,
                LiveEffect::DisplayIntent(value) => intent = Some(value),
                LiveEffect::Terminal(_) => return Err(UiError::from("PairingFailed")),
                LiveEffect::Invitation(_)
                | LiveEffect::AwaitingDecision
                | LiveEffect::PayloadSent
                | LiveEffect::Accepted => return Err(UiError::from("PairingFailed")),
            }
        }
        if let Some(intent) = intent {
            let view = CbclPairingStartView {
                relay_origin,
                cpace_frame: None,
                status: "Secure channel ready. Review the exact request.",
                intent: Some(intent_view(intent)),
            };
            return Ok((PendingCbclPairing { core, socket }, view));
        }
    }
}

#[cfg(feature = "local-pairing-demo")]
fn finish_live(mut pending: PendingCbclPairing, approve: bool) -> Result<CbclPairingResultView> {
    let decision = if approve {
        selfsame_pairing::live::Decision::Approve
    } else {
        selfsame_pairing::live::Decision::Decline
    };
    let effects = pending.core.decide(decision).map_err(map_error)?;
    send_effects(&mut pending.socket, effects)?;
    let expected = if approve {
        LiveOutcome::Accepted
    } else {
        LiveOutcome::Declined
    };
    loop {
        let bytes = read_binary(&mut pending.socket)?;
        let effects = pending.core.receive(&bytes).map_err(map_error)?;
        let mut terminal = None;
        for effect in effects {
            match effect {
                LiveEffect::Send(bytes) => pending
                    .socket
                    .send(Message::Binary(bytes.into()))
                    .map_err(|_| UiError::from("PairingRelayUnavailable"))?,
                LiveEffect::Accepted if approve => {}
                LiveEffect::Terminal(outcome) => terminal = Some(outcome),
                _ => return Err(UiError::from("PairingFailed")),
            }
        }
        if terminal == Some(expected) {
            return Ok(if approve {
                CbclPairingResultView {
                    outcome: "accepted",
                    title: "Application connected",
                    message: "Selfsame accepted all 13 credential checks.",
                }
            } else {
                CbclPairingResultView {
                    outcome: "declined",
                    title: "Request declined",
                    message: "No credential was shared and the invitation is spent.",
                }
            });
        }
        if terminal.is_some() {
            return Err(UiError::from("PairingFailed"));
        }
    }
}

#[cfg(feature = "local-pairing-demo")]
fn send_effects(socket: &mut WebSocket<TcpStream>, effects: Vec<LiveEffect>) -> Result<()> {
    for effect in effects {
        match effect {
            LiveEffect::Send(bytes) => socket
                .send(Message::Binary(bytes.into()))
                .map_err(|_| UiError::from("PairingRelayUnavailable"))?,
            LiveEffect::Terminal(LiveOutcome::Cancelled) => {}
            _ => return Err(UiError::from("PairingFailed")),
        }
    }
    Ok(())
}

#[cfg(feature = "local-pairing-demo")]
fn read_binary(socket: &mut WebSocket<TcpStream>) -> Result<Vec<u8>> {
    loop {
        match socket.read() {
            Ok(Message::Binary(bytes)) => return Ok(bytes.to_vec()),
            Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => {}
            Ok(Message::Close(_)) | Err(_) => return Err(UiError::from("PairingRelayUnavailable")),
            Ok(Message::Text(_)) => return Err(UiError::from("PairingFailed")),
        }
    }
}

#[cfg(feature = "local-pairing-demo")]
fn local_websocket_url(origin: &str) -> Result<(String, u16)> {
    let port = origin
        .strip_prefix("https://localhost:")
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or_else(|| UiError::from("PairingRelayRefused"))?;
    Ok((format!("ws://localhost:{port}/relay"), port))
}

#[cfg(feature = "local-pairing-demo")]
fn intent_view(intent: selfsame_pairing::live::DisplayIntent) -> CbclIntentView {
    CbclIntentView {
        application: intent.application,
        action: intent.action,
        authority_summary: intent.authority_summary,
        fields: intent
            .fields
            .into_iter()
            .map(|field| CbclIntentFieldView {
                label: field.label.into(),
                value: field.value,
                claimed_by_secret_holder: field.claimed_by_secret_holder,
            })
            .collect(),
    }
}

#[cfg(feature = "local-pairing-demo")]
fn take_pending(session: &State<'_, AppSession>) -> Result<PendingCbclPairing> {
    session
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .pending_cbcl_pairing
        .take()
        .ok_or_else(|| UiError::from("PairingUnavailable"))
}

fn decode_carrier(input: &str) -> Result<Vec<u8>> {
    if legacy::reject(LegacySurface::Carrier, input.as_bytes()).class
        == LegacyRejectionClass::PairingVersionUnsupported
    {
        return Err(UiError::from("PairingVersionUnsupported"));
    }
    Base64UrlUnpadded::decode_vec(input.trim()).map_err(|_| UiError::from("RecognitionFailed"))
}

fn map_error(error: IntegrationError) -> UiError {
    match error {
        IntegrationError::PairingVersionUnsupported => UiError::from("PairingVersionUnsupported"),
        IntegrationError::Recognition | IntegrationError::Profile => {
            UiError::from("RecognitionFailed")
        }
        _ => UiError::from("PairingFailed"),
    }
}
