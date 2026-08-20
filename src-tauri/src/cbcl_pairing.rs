//! Tauri's one-sided `cbcl-pairing` claimant shell.
//!
//! One pump drives every build (`IMPL-008` `ADR-910`): a blocking WebSocket
//! loop around the sans-io `ClaimantRelaySession`, over
//! `MaybeTlsStream<TcpStream>`. An ordinary build reaches it only through
//! `SPEC-008`'s gates — profile-anchored origin trust (`REQ-906`), real
//! context assembly (`CON-902`), TLS transport (`REQ-901`/`NFR-901`) — and
//! commits live approve/decline (`REQ-903`). A build carrying the explicit
//! `local-pairing-demo` capability keeps its loopback origin→`ws://` mapping
//! and fixture context. Production invitation allocation remains held
//! upstream (`REQ-907` does not touch `SPEC-007` `REQ-809`).

use base64ct::{Base64UrlUnpadded, Encoding as _};
use rand::RngCore as _;
use serde::Serialize;
use std::net::TcpStream;
#[cfg(feature = "local-pairing-demo")]
use std::time::Duration;
use tauri::State;
use tungstenite::{stream::MaybeTlsStream, Message, WebSocket};

use crate::commands::{AppSession, UiError};
use selfsame_pairing::{
    legacy::{self, LegacyRejectionClass, LegacySurface},
    live::{ClaimantRelaySession, LiveEffect, LiveOutcome},
    IntegrationError,
};

#[cfg(not(feature = "local-pairing-demo"))]
use crate::{cbcl_context, cbcl_registry, cbcl_transport};

#[cfg(feature = "local-pairing-demo")]
use selfsame_app_identity::cbcl_relay::{self, RelayPolicy};
#[cfg(feature = "local-pairing-demo")]
use selfsame_pairing::local_demo;

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

/// The live claimant between consent display and the person's decision.
/// Never persisted or exposed to the page; erased on cancel and terminal.
pub struct PendingCbclPairing {
    core: ClaimantRelaySession,
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
}

/// What this build's pairing path actually is (`REQ-908`): the screens
/// derive their copy from this instead of hardcoding either build's prose.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CbclPairingCapabilityView {
    /// The compile-gated loopback demo relay path.
    demo_relay: bool,
    /// The SPEC-008 production claimant path (wss + custody presence).
    production_claimant: bool,
}

/// Report the build's pairing capability, derived from the compiled feature.
#[tauri::command]
pub async fn cbcl_pairing_capability() -> Result<CbclPairingCapabilityView> {
    Ok(CbclPairingCapabilityView {
        demo_relay: cfg!(feature = "local-pairing-demo"),
        production_claimant: !cfg!(feature = "local-pairing-demo"),
    })
}

/// Begin Selfsame's claimant endpoint with no protocol choice or legacy path.
///
/// Ordinary builds take the person's passcode here: the origin gate needs no
/// key, but `CON-902` assembly derives the wallet's per-application identity
/// inside custody before any socket opens. The demo build ignores it.
#[tauri::command]
pub async fn cbcl_pairing_start(
    invitation: String,
    passcode: Option<String>,
    session: State<'_, AppSession>,
) -> Result<CbclPairingStartView> {
    // Review finding m-4: a second start must not silently drop a live
    // ceremony mid-flight — cancel it properly (erase path + mailbox close)
    // before any new work.
    let previous = {
        // Scoped so the guard never crosses an await point.
        let mut guard = session.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.pending_cbcl_pairing.take()
    };
    if let Some(mut previous) = previous {
        let _ = tauri::async_runtime::spawn_blocking(move || {
            if let Ok(effects) = previous.core.cancel() {
                let _ = send_effects(&mut previous.socket, effects);
            }
        })
        .await;
    }

    #[cfg(feature = "local-pairing-demo")]
    let (pending, view) = {
        let _ = passcode;
        tauri::async_runtime::spawn_blocking(move || start_live_demo(invitation))
            .await
            .map_err(|_| UiError::from("PairingFailed"))??
    };

    #[cfg(not(feature = "local-pairing-demo"))]
    let (pending, view) = {
        let carrier = decode_carrier(&invitation)?;
        let recognised =
            selfsame_pairing::decode_selfsame_invitation(&carrier).map_err(map_error)?;
        let relay_origin = recognised.relay_origin.clone();

        // REQ-906 — before any socket: exactly one held authenticated profile
        // pre-declares this origin, under the compiled registry.
        let held = cbcl_context::held_trust_records();
        let profiles: Vec<_> = held.iter().map(|(_, profile)| profile.clone()).collect();
        let policy = cbcl_registry::production_relay_policy();
        let matched = cbcl_context::gate_invitation_origin(&profiles, &policy, &relay_origin)
            .map_err(|refusal| match refusal {
                cbcl_context::OriginRefusal::NoEligibleMatch => {
                    UiError::from("PairingRelayRefused")
                }
                cbcl_context::OriginRefusal::AmbiguousMatch => {
                    UiError::from("PairingRelayAmbiguous")
                }
            })?;
        let record = held
            .iter()
            .find(|(record, _)| record.application_id == matched.application_id.as_str())
            .map(|(record, _)| record.clone())
            .ok_or_else(|| UiError::from("PairingRelayRefused"))?;

        // CON-902 — the real context, refused closed on any missing source.
        let passcode = passcode.ok_or_else(|| UiError::from("PresenceRequired"))?;
        let assembled =
            cbcl_context::assemble_claimant(&record, &passcode, &relay_origin, &policy).await?;

        // REQ-901/NFR-901 — one TLS connect path, after both gates.
        let target = cbcl_transport::relay_target(&relay_origin)
            .map_err(|_| UiError::from("PairingRelayRefused"))?;
        tauri::async_runtime::spawn_blocking(move || {
            let socket = cbcl_transport::connect_wss(&target).map_err(transport_error)?;
            let core = claimant_core(&carrier, assembled.context)?
                .with_deferred_proof(assembled.deferred);
            pump_to_intent(core, socket, relay_origin)
        })
        .await
        .map_err(|_| UiError::from("PairingFailed"))??
    };

    session
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .pending_cbcl_pairing = Some(pending);
    Ok(view)
}

/// Commit the exact displayed approval and wait for Selfsame acceptance.
#[tauri::command]
pub async fn cbcl_pairing_approve(
    session: State<'_, AppSession>,
) -> Result<CbclPairingResultView> {
    let pending = take_pending(&session)?;
    tauri::async_runtime::spawn_blocking(move || finish_live(pending, true))
        .await
        .map_err(|_| UiError::from("PairingFailed"))?
}

/// Commit an explicit decline; no payload or Selfsame verifier call follows.
#[tauri::command]
pub async fn cbcl_pairing_decline(
    session: State<'_, AppSession>,
) -> Result<CbclPairingResultView> {
    let pending = take_pending(&session)?;
    tauri::async_runtime::spawn_blocking(move || finish_live(pending, false))
        .await
        .map_err(|_| UiError::from("PairingFailed"))?
}

/// Burn the pending endpoint locally and close its relay mailbox.
#[tauri::command]
pub async fn cbcl_pairing_cancel(session: State<'_, AppSession>) -> Result<()> {
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
    Ok(())
}

/// Fresh ceremony entropy plus the sans-io claimant core.
fn claimant_core(
    carrier: &[u8],
    verification: selfsame_pairing::SelfsameVerificationContext,
) -> Result<ClaimantRelaySession> {
    let mut cpace_scalar = [0_u8; 32];
    let mut signing_seed = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut cpace_scalar);
    rand::rngs::OsRng.fill_bytes(&mut signing_seed);
    ClaimantRelaySession::new(carrier, cpace_scalar, signing_seed, verification).map_err(map_error)
}

/// Drive one connected socket from `start()` to the displayed exact intent.
fn pump_to_intent(
    mut core: ClaimantRelaySession,
    mut socket: WebSocket<MaybeTlsStream<TcpStream>>,
    relay_origin: String,
) -> Result<(PendingCbclPairing, CbclPairingStartView)> {
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
fn start_live_demo(invitation: String) -> Result<(PendingCbclPairing, CbclPairingStartView)> {
    let carrier = decode_carrier(&invitation)?;
    let recognised = selfsame_pairing::decode_selfsame_invitation(&carrier).map_err(map_error)?;
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
    let (socket, _) = tungstenite::client::client(
        websocket_url.as_str(),
        MaybeTlsStream::Plain(stream),
    )
    .map_err(|_| UiError::from("PairingRelayUnavailable"))?;

    let core = claimant_core(&carrier, fixture.verification)?;
    pump_to_intent(core, socket, relay_origin)
}

fn finish_live(mut pending: PendingCbclPairing, approve: bool) -> Result<CbclPairingResultView> {
    // Review finding m-3: the consent screen is a human pause of unbounded
    // length; the acceptance clock is the decision moment, not the moment
    // the socket opened.
    pending.core.refresh_now(crate::commands::now() as i64);
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

fn send_effects(
    socket: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    effects: Vec<LiveEffect>,
) -> Result<()> {
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

fn read_binary(socket: &mut WebSocket<MaybeTlsStream<TcpStream>>) -> Result<Vec<u8>> {
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

#[cfg(not(feature = "local-pairing-demo"))]
fn transport_error(error: crate::cbcl_transport::TransportError) -> UiError {
    use crate::cbcl_transport::TransportError;
    match error {
        TransportError::Origin => UiError::from("PairingRelayRefused"),
        TransportError::Connect => UiError::from("PairingRelayUnavailable"),
        TransportError::Tls => UiError::from("PairingRelayTlsRefused"),
        TransportError::Handshake => UiError::from("PairingRelayUnavailable"),
    }
}

fn take_pending(session: &State<'_, AppSession>) -> Result<PendingCbclPairing> {
    session
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .pending_cbcl_pairing
        .take()
        .ok_or_else(|| UiError::from("PairingUnavailable"))
}

fn decode_carrier(input: &str) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    if legacy::reject(LegacySurface::Carrier, input.as_bytes()).class
        == LegacyRejectionClass::PairingVersionUnsupported
    {
        return Err(UiError::from("PairingVersionUnsupported"));
    }
    // The carrier holds the 16-octet invitation secret; the shell's copy
    // erases on drop (review finding m-6).
    Base64UrlUnpadded::decode_vec(input.trim())
        .map(zeroize::Zeroizing::new)
        .map_err(|_| UiError::from("RecognitionFailed"))
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

#[cfg(test)]
mod tests {
    use super::*;

    // TEST-908 (REQ-905): the carrier is exactly unpadded base64url of the
    // invitation — a URL wrapper, base64 padding, or a legacy prefix each
    // refuses at recognition, before any state change.
    #[test]
    fn wrapped_padded_and_legacy_carriers_refuse() {
        let refused = |input: &str| serde_json::to_string(&decode_carrier(input).unwrap_err()).expect("token");
        assert_eq!(
            refused("https://pair.example/#AAAA"),
            "\"RecognitionFailed\"",
            "a URL-wrapped carrier is never navigated or unwrapped"
        );
        assert_eq!(refused("AAAA=="), "\"RecognitionFailed\"");
        assert_eq!(refused("AA AA"), "\"RecognitionFailed\"");
        assert_eq!(
            refused("alpha-bravo-carrot-delta-echo-fox-golf-hotel-india-jam-kilo-lima"),
            "\"PairingVersionUnsupported\"",
            "a retired human-word carrier is recognised as retired, not decoded"
        );
    }

    // TEST-908 (positive shape): a bare unpadded base64url string decodes;
    // trimming surrounding whitespace is transport hygiene, not repair.
    #[test]
    fn bare_unpadded_base64url_decodes() {
        assert_eq!(*decode_carrier("AAAA").expect("decodes"), vec![0, 0, 0]);
        assert_eq!(*decode_carrier("  AAAA\n").expect("decodes"), vec![0, 0, 0]);
    }
}
