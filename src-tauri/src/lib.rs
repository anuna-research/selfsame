//! **Selfsame** — the root-key custodian.
//!
//! *The phone is the home key; every other client gets a copy cut from it, and
//! the phone can change the lock.*
//!
//! This is the one component in [SPEC-001] that holds a [Root Key]. Everything
//! else in the system reads identity state; only this signs it. It exists as a
//! separate application because it depends on a keychain with a user-presence
//! policy and a camera — available nowhere else in the system (SPEC-001 §6.12).
//!
//! ```text
//!   ┌──────────── Selfsame ────────────┐
//!   │  custody   keychain + presence     │  REQ-024, REQ-002
//!   │  session   signed closure + queue  │  REQ-020, REQ-021
//!   │  net       rendezvous + resolver   │  CON-002, CON-005, CON-006
//!   │  commands  one per user action     │  REQ-018, REQ-019, REQ-010
//!   └───────────────┬───────────────────┘
//!                   ▼  every decision
//!            selfsame-core (pure)
//! ```
//!
//! # Tier-1 status
//!
//! SPEC-001 is `draft` behind a **Tier-1 gate that has not been passed**: round
//! 2 of the cross-model adversarial review and human security sign-off are
//! outstanding, and three open questions ([OQ-003] key reuse, [OQ-005]
//! freshness evidence, [OQ-007] plaintext-channel authorship) are gate-blocking.
//! This code implements the specification as written; it is not cleared for
//! production use, and the README says so in the same words.
//!
//! [SPEC-001]: ../../../../anuna-ssi/specs/SPEC-001-device-key-provisioning.md
//! [Root Key]: ../../../../anuna-ssi/specs/concepts/Root-Key.md
//! [OQ-003]: ../../../../anuna-ssi/specs/SPEC-001-device-key-provisioning.md
//! [OQ-005]: ../../../../anuna-ssi/specs/SPEC-001-device-key-provisioning.md
//! [OQ-007]: ../../../../anuna-ssi/specs/SPEC-001-device-key-provisioning.md

pub mod app_grant;
mod app_identity;
pub mod cbcl_context;
pub mod cbcl_pairing;
pub mod cbcl_registry;
pub mod cbcl_transport;
pub mod cbcl_v2_claimant;
mod cbcl_v2_clock;
pub mod cbcl_v2_commands;
pub mod cbcl_v2_completion;
pub mod cbcl_v2_policy;
mod commands;
pub mod custody;
pub mod net;
pub mod replay;
pub mod session;
pub mod store;

#[cfg(test)]
#[path = "../../crates/selfsame-app-identity/tests/common/mod.rs"]
mod fixture;

/// Build and run the application.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();

    // The camera and the biometric presence check are mobile-only. On desktop
    // their places are taken by the typed code of REQ-011 and the device
    // passcode of REQ-024 — both of which the specification makes first-class
    // routes rather than fallbacks, so nothing is missing, only different.
    #[cfg(mobile)]
    let builder = builder
        .plugin(tauri_plugin_barcode_scanner::init())
        .plugin(tauri_plugin_biometric::init());

    // `keyring` has no Android backend and falls back to an in-memory mock, so
    // without this the APK accepts every write to the root record and keeps
    // none — which is exactly what it did. `store::init` refuses to start if
    // this is ever true again, on any platform.
    #[cfg(target_os = "android")]
    let builder = builder.plugin(tauri_plugin_selfsame_store::init());

    builder
        .on_window_event(|window, event| {
            use tauri::Manager as _;
            let foreground = match event {
                // Android's biometric plugin opens another Activity in this
                // app. Window focus is not the application's lifecycle.
                #[cfg(not(target_os = "android"))]
                tauri::WindowEvent::Focused(foreground) => Some(*foreground),
                #[cfg(mobile)]
                tauri::WindowEvent::Suspended => Some(false),
                #[cfg(mobile)]
                tauri::WindowEvent::Resumed => Some(true),
                _ => None,
            };
            if let Some(foreground) = foreground {
                if let Some(session) = window.try_state::<commands::AppSession>() {
                    let mut state = session.0.lock().unwrap_or_else(|p| p.into_inner());
                    state.cbcl_v2_attempts.foreground(foreground);
                    if !foreground {
                        state.revoke_cbcl_v2();
                    }
                }
                #[cfg(target_os = "android")]
                if !foreground {
                    use tauri::Emitter as _;
                    let _ = window.emit("selfsame-pairing-backgrounded", ());
                }
            }
        })
        .setup(|app| {
            commands::init(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_state,
            commands::create_identity,
            commands::confirm_backup,
            commands::restore_identity,
            commands::read_link_code,
            commands::reject_offer,
            commands::authorise,
            commands::unlink_device,
            commands::flush_publications,
            commands::forget_identity,
            commands::service_endpoint,
            commands::build_info,
            app_identity::alias_preview,
            app_identity::home_fingerprint,
            app_identity::app_identity_derive,
            cbcl_pairing::cbcl_pairing_capability,
            cbcl_pairing::cbcl_pairing_start,
            cbcl_pairing::cbcl_pairing_approve,
            cbcl_pairing::cbcl_pairing_decline,
            cbcl_pairing::cbcl_pairing_cancel,
            cbcl_v2_commands::single_link::cbcl_v2_begin_handoff,
            cbcl_v2_commands::single_link::cbcl_v2_begin_manual,
            cbcl_v2_commands::single_link::cbcl_v2_contact,
            cbcl_v2_commands::single_link::cbcl_v2_unlock_preview,
            cbcl_v2_commands::single_link::cbcl_v2_preview_rendered,
            cbcl_v2_commands::single_link::cbcl_v2_link,
            cbcl_v2_commands::single_link::cbcl_v2_continue_link,
            cbcl_v2_commands::single_link::cbcl_v2_finish_link,
            cbcl_v2_commands::single_link::cbcl_v2_cancel_link,
            cbcl_v2_commands::cbcl_v2_recognise,
            cbcl_v2_commands::cbcl_v2_recognise_handoff,
            cbcl_v2_commands::cbcl_v2_relay_decide,
            cbcl_v2_commands::cbcl_v2_preliminary_decide,
            cbcl_v2_commands::cbcl_v2_compare,
            cbcl_v2_commands::cbcl_v2_final_decide,
            cbcl_v2_commands::cbcl_v2_finish,
            cbcl_v2_commands::cbcl_v2_pending_recoveries,
            cbcl_v2_commands::cbcl_v2_pending_links,
            cbcl_v2_commands::cbcl_v2_installed_links,
            cbcl_v2_commands::cbcl_v2_reload_verify,
            cbcl_v2_commands::cbcl_v2_unlink,
            cbcl_v2_commands::cbcl_v2_recover,
            cbcl_v2_commands::cbcl_v2_cancel,
            app_grant::app_grant_review,
            app_grant::app_grant_prepare,
            app_grant::app_grant_confirm,
            app_grant::cbcl_enrol_start,
            app_grant::cbcl_enrol_prepare,
            app_grant::cbcl_enrol_confirm,
            app_identity::provision_username,
            app_identity::revoke_grant,
            app_identity::revocation_status,
        ])
        .run(tauri::generate_context!())
        .expect("Selfsame failed to start");
}
