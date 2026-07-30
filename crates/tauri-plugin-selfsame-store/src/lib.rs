//! Keystore-wrapped storage for the Selfsame root record on Android.
//!
//! Implements [SPEC-004] CON-301. This crate exists because `keyring` has no
//! Android backend and silently falls back to an in-memory mock store, which is
//! how BUG-201 shipped a build that stored the root key nowhere.
//!
//! # What this is and is not
//!
//! It is *the box*, not the envelope. The blob handed to [`SecureStore::store`]
//! is already sealed under an Argon2id key derived from the user's passcode by
//! `custody.rs`; this crate encrypts that sealed blob again under an AES-256-GCM
//! key held in the [Android Keystore] and writes the result to app-private
//! storage. ADR-302 keeps both layers: the Keystore defeats an attacker holding
//! the filesystem, and Argon2id defeats one who has also defeated the Keystore.
//! Neither is a substitute for the other, and this crate never sees an unsealed
//! seed — the blob is opaque to it.
//!
//! # Not reachable from the webview
//!
//! `build.rs` registers **no** commands, so no capability can name this plugin's
//! functions and no script in the webview can call them. The three commands on
//! the Kotlin class are reached only from Rust, through
//! [`tauri::plugin::PluginHandle::run_mobile_plugin`], which bypasses the ACL.
//!
//! # Threading
//!
//! [`tauri::plugin::PluginHandle::run_mobile_plugin`] posts the call to the
//! Android main thread and **blocks the caller** until the Kotlin side resolves.
//! Every one of these functions therefore MUST NOT be called from the main
//! thread, or the call deadlocks against itself. In this application the callers
//! are Tauri command futures and `spawn_blocking` closures, neither of which
//! runs on the main thread; `custody.rs` records the same constraint at its own
//! boundary.
//!
//! [SPEC-004]: ../../../specs/SPEC-004-android-secure-storage.md
//! [Android Keystore]: https://developer.android.com/privacy-and-security/keystore

// The plugin machinery below is Android-only, by design: every other platform
// Selfsame builds for has a real keychain and reaches it through `keyring`, and
// a second arm here would be a second implementation of storage that already
// works (ADR-303).
//
// The **types** are not gated, and that is deliberate. [`LoadResponse`] is the
// contract between this crate and the Kotlin in `android/`, and it is the piece
// most able to break silently: rename a state on one side and the other stops
// understanding it. Leaving it compiled on every host means `cargo test` on a
// laptop checks it, instead of that check existing only inside an APK nobody can
// run in CI.

use serde::{Deserialize, Serialize};

#[cfg(target_os = "android")]
use tauri::{
    plugin::{Builder, PluginHandle, TauriPlugin},
    Manager, Runtime,
};

/// The Kotlin package that owns `SecureStorePlugin`, which is what
/// `register_android_plugin` looks the class up by.
#[cfg(target_os = "android")]
const PLUGIN_IDENTIFIER: &str = "io.anuna.selfsame.store";

pub type Result<T> = std::result::Result<T, StoreError>;

/// CON-301's error model.
///
/// The distinction that matters is **absent versus undecryptable**, and it is
/// deliberately not carried in this type: absence is `Ok(None)` from
/// [`SecureStore::load`], because a device that has never stored anything is not
/// in an error state. What this type must never do is let a *damaged* record
/// look like an absent one — telling a user with a damaged store that they have
/// no identity would invite them to create a second one over the top of the
/// first, and the first is the one their contacts have already accepted.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A record is present but did not decrypt: a failed GCM tag, an
    /// unrecognised header, or a Keystore key that is no longer there.
    ///
    /// `custody.rs` maps this to `CustodyError::Corrupt` and never to
    /// `NoIdentity`.
    #[error("the stored record is present but could not be read: {0}")]
    Corrupt(String),
    /// The store itself could not be reached — no Keystore, an I/O failure.
    /// Distinct from [`StoreError::Corrupt`]: nothing is known about whether a
    /// record exists, so the caller must not conclude that none does.
    #[error("the secure store is unavailable: {0}")]
    Unavailable(String),
    #[cfg(target_os = "android")]
    #[error(transparent)]
    PluginInvoke(#[from] tauri::plugin::mobile::PluginInvokeError),
}

#[derive(Serialize)]
pub struct StorePayload<'a> {
    pub blob: &'a str,
}

/// What `loadRecord` resolves with.
///
/// The absent/present/corrupt distinction travels as **data on the success
/// path**, not as a rejection code. A rejection would arrive in Rust as a
/// `PluginInvokeError` carrying an `Option<String>` code, and the whole error
/// model of CON-301 would then rest on matching a string. Here it rests on a
/// tagged enum that fails to deserialise if the Kotlin side ever stops
/// honouring it.
#[derive(Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum LoadResponse {
    Absent,
    Present { blob: String },
    Corrupt { detail: String },
}

impl LoadResponse {
    /// Collapse the wire response into what a caller wants: absence is not an
    /// error, a damaged record is.
    pub fn into_blob(self) -> Result<Option<String>> {
        match self {
            LoadResponse::Absent => Ok(None),
            LoadResponse::Present { blob } => Ok(Some(blob)),
            LoadResponse::Corrupt { detail } => Err(StoreError::Corrupt(detail)),
        }
    }
}

/// Access to the Keystore-backed record store.
#[cfg(target_os = "android")]
pub struct SecureStore<R: Runtime>(PluginHandle<R>);

#[cfg(target_os = "android")]
impl<R: Runtime> SecureStore<R> {
    /// Overwrite the stored record. A fresh GCM IV is generated per call by the
    /// Keystore itself — see the Kotlin side for why it is not ours to choose.
    pub fn store(&self, blob: &str) -> Result<()> {
        self.0
            .run_mobile_plugin::<()>("storeRecord", StorePayload { blob })
            .map_err(StoreError::from)
    }

    /// Read the stored record. `Ok(None)` means this device has never stored
    /// one, which is not an error and matches how `custody.rs` already treats
    /// `keyring::Error::NoEntry`.
    pub fn load(&self) -> Result<Option<String>> {
        self.0
            .run_mobile_plugin::<LoadResponse>("loadRecord", ())?
            .into_blob()
    }

    /// Remove the record and the Keystore key that wrapped it. Idempotent:
    /// deleting nothing succeeds.
    pub fn delete(&self) -> Result<()> {
        self.0
            .run_mobile_plugin::<()>("deleteRecord", ())
            .map_err(StoreError::from)
    }
}

/// Reach the store from a [`tauri::AppHandle`] or any other [`Manager`].
#[cfg(target_os = "android")]
pub trait SecureStoreExt<R: Runtime> {
    fn secure_store(&self) -> &SecureStore<R>;
}

#[cfg(target_os = "android")]
impl<R: Runtime, T: Manager<R>> SecureStoreExt<R> for T {
    fn secure_store(&self) -> &SecureStore<R> {
        self.state::<SecureStore<R>>().inner()
    }
}

/// Initialise the plugin. Must be registered on the Tauri builder before
/// anything calls [`SecureStoreExt::secure_store`].
#[cfg(target_os = "android")]
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("selfsame-store")
        .setup(|app, api| {
            let handle = api.register_android_plugin(PLUGIN_IDENTIFIER, "SecureStorePlugin")?;
            app.manage(SecureStore(handle));
            Ok(())
        })
        .build()
}
