//! Hardware-wrapped custody for the Selfsame root record on Android.
//!
//! # Why this crate exists
//!
//! `keyring` 3 selects its credential store by `cfg`, and its final arm is
//!
//! ```text
//! #[cfg(not(any(linux, freebsd, openbsd, macos, ios, windows)))]
//! pub use mock as default;
//! ```
//!
//! `target_os = "android"` matches none of those names, so an Android build
//! links the crate's **testing mock** — documented as having *"no persistence
//! other than in the entry itself"*. No feature flag fixes it; `keyring` 3 has
//! no Android backend to enable. The result was a published APK in which
//! `set_password` returned `Ok(())`, the sealed root was dropped on the floor,
//! and identity creation failed one line later with *"no identity on this
//! device"* — every time, for every user.
//!
//! # What it provides
//!
//! `SPEC-001 REQ-024` asks for three things, and Android supplies all three
//! natively — this plugin is rung 3 of the Simplicity Ladder, the native
//! platform feature, not a re-implementation of one:
//!
//! | REQ-024 clause | Mechanism |
//! |---|---|
//! | stored in the platform keychain | `AndroidKeyStore` + app-private `SharedPreferences` |
//! | wrapped by a hardware-protected key | AES-256-GCM key held in the TEE, StrongBox where present |
//! | user presence for every root-key use | enforced by `Custody::use_root_key`; see the ceiling below |
//!
//! The value handed to [`SelfsameStore::set`] is already sealed by
//! `custody::store` under an Argon2id key derived from the user's passcode, so
//! the Keystore wrap is the **second** layer, not the only one. An attacker
//! holding the ciphertext needs both the device (to use the non-exportable
//! Keystore key) and the passcode (to open the Argon2id seal).
//!
// SIMPLIFY: the presence check is enforced by `Custody::use_root_key` calling
// `tauri-plugin-biometric` before it unseals, not by the Keystore refusing to
// decrypt. Ceiling: an attacker already executing in the app process can skip
// the prompt — they still need the passcode, but the OS is not the one saying
// no. Upgrade path: move `sealed_seed` to a second Keystore key built with
// `setUserAuthenticationRequired(true)`, leaving the public half under this one
// so `root_public_key` stays prompt-free (trace: REQ-024, ADR-002).
//!
//! # Not reachable from the webview
//!
//! `build.rs` declares no commands, so no permission exists that would let
//! JavaScript call `get`, `set` or `delete`. The only caller is `Custody`.

#![cfg(target_os = "android")]

use serde::{Deserialize, Serialize};
use tauri::{
    plugin::{Builder, PluginHandle, TauriPlugin},
    Manager, Runtime,
};

mod error;

pub use error::{Error, Result};

/// Must match the `namespace` in `android/build.gradle.kts`.
const PLUGIN_IDENTIFIER: &str = "io.anuna.selfsame.store";

/// Access to the Keystore-backed record store.
pub struct SelfsameStore<R: Runtime>(PluginHandle<R>);

#[derive(Serialize)]
struct KeyPayload<'a> {
    key: &'a str,
}

#[derive(Serialize)]
struct SetPayload<'a> {
    key: &'a str,
    value: &'a str,
}

/// `value` is absent when the record does not exist.
///
/// Absent means *absent*: the Kotlin side rejects rather than resolving with
/// `null` when a record is present but will not decrypt, so a `None` here can
/// only mean a genuine first run. Conflating the two is what turned the
/// original defect into a message about identity rather than about storage.
#[derive(Deserialize)]
struct ReadResponse {
    #[serde(default)]
    value: Option<String>,
}

impl<R: Runtime> SelfsameStore<R> {
    /// Read a record, or `None` if this device has never stored one.
    pub fn get(&self, key: &str) -> Result<Option<String>> {
        let response: ReadResponse = self.0.run_mobile_plugin("get", KeyPayload { key })?;
        Ok(response.value)
    }

    /// Store a record, replacing any previous value under the same key.
    pub fn set(&self, key: &str, value: &str) -> Result<()> {
        self.0
            .run_mobile_plugin("set", SetPayload { key, value })
            .map_err(Into::into)
    }

    /// Remove a record. Succeeds whether or not one was present.
    pub fn delete(&self, key: &str) -> Result<()> {
        self.0
            .run_mobile_plugin("delete", KeyPayload { key })
            .map_err(Into::into)
    }
}

/// Extension trait giving [`tauri::App`] and friends access to the store.
pub trait SelfsameStoreExt<R: Runtime> {
    fn selfsame_store(&self) -> &SelfsameStore<R>;
}

impl<R: Runtime, T: Manager<R>> SelfsameStoreExt<R> for T {
    fn selfsame_store(&self) -> &SelfsameStore<R> {
        self.state::<SelfsameStore<R>>().inner()
    }
}

/// Initialise the plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("selfsame-store")
        .setup(|app, api| {
            let handle = api.register_android_plugin(PLUGIN_IDENTIFIER, "StorePlugin")?;
            app.manage(SelfsameStore(handle));
            Ok(())
        })
        .build()
}
