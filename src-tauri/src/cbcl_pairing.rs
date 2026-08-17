//! Tauri's one-sided `cbcl-pairing` claimant shell.
//!
//! The webview hands this module only the out-of-band invitation. Cryptographic
//! state remains in [`Session`], while relay I/O consumes the returned opaque
//! frame. Production invitation allocation is not enabled here.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use rand::RngCore as _;
use serde::Serialize;
use tauri::State;

use crate::commands::{AppSession, UiError};
use selfsame_pairing::{
    legacy::{self, LegacyRejectionClass, LegacySurface},
    IntegrationError, SelfsameEndpointBootstrap,
};

type Result<T> = std::result::Result<T, UiError>;

/// Non-secret values the shell needs to begin relay transport.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CbclPairingStartView {
    /// Exact origin committed by the recognised invitation.
    relay_origin: String,
    /// Canonical opaque CPace frame, base64url for the Tauri bridge.
    cpace_frame: String,
    /// Accessible status text for the pending UI state.
    status: &'static str,
}

/// Begin Selfsame's claimant endpoint with no protocol choice or legacy path.
#[tauri::command]
pub fn cbcl_pairing_start(
    invitation: String,
    session: State<'_, AppSession>,
) -> Result<CbclPairingStartView> {
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
        cpace_frame: Base64UrlUnpadded::encode_string(
            &endpoint.local_cpace_frame_bytes().map_err(map_error)?,
        ),
        status: "Secure pairing started. Waiting for the application.",
    };
    session
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .pending_cbcl_pairing = Some(endpoint);
    Ok(view)
}

/// Burn the pending endpoint locally. Dropping it zeroizes its invitation and keys.
#[tauri::command]
pub fn cbcl_pairing_cancel(session: State<'_, AppSession>) {
    session
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .pending_cbcl_pairing = None;
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
