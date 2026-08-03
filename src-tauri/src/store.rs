//! Where the root record lives — and the guard that it lives anywhere at all.
//!
//! [`custody`](crate::custody) used to call `keyring` directly. That was correct
//! on three platforms and silently wrong on the fourth: `keyring` 3 picks its
//! backend by `cfg`, and its last arm is
//!
//! ```text
//! #[cfg(not(any(linux, freebsd, openbsd, macos, ios, windows)))]
//! pub use mock as default;
//! ```
//!
//! `target_os = "android"` matches none of those names, so the APK linked the
//! crate's **testing mock** — "no persistence other than in the entry itself".
//! Every `set_password` returned `Ok(())` and dropped the sealed root, the next
//! read reported `NoEntry`, and identity creation died one line later with
//! *"no identity on this device"*. The store was not failing; it was agreeing.
//!
//! # Two things changed
//!
//! Android now goes through [`tauri_plugin_selfsame_store`], which wraps the
//! record in a non-exportable AES-256-GCM key held in the TEE. That is the
//! `REQ-024` clause *"wrapped by a hardware-protected key where the platform
//! provides one"*, met on the platform that provides one.
//!
//! And [`assert_durable`] round-trips a probe value through whatever backend
//! this build actually linked, at startup, before anything can be lost through
//! it. A store that accepts writes and forgets them now fails the app at launch
//! with a message naming the storage, instead of failing an hour later with a
//! message about identity. It is a general check rather than a `keyring`-mock
//! check on purpose: it tests the property that was violated, not the one
//! implementation that violated it.
//!
//! Trace: SPEC-001-device-key-provisioning#REQ-024.

/// Keychain service name. Shared by every entry this application owns.
const SERVICE: &str = "io.anuna.selfsame";

/// The entry holding the sealed root record.
pub const ROOT_ENTRY: &str = "root-v1";

/// The entry [`assert_durable`] writes and removes. Never holds anything
/// secret, and is deliberately not `ROOT_ENTRY`: a probe that shared a name
/// with the real record could destroy one.
const PROBE_ENTRY: &str = "durability-probe-v1";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("secure storage unavailable: {0}")]
    Backend(String),
    #[error(
        "this build has no persistent secure storage, so an identity created on \
         it would be lost immediately. {0}"
    )]
    NotDurable(String),
    #[error("that wasn't confirmed on the device: {0}")]
    PresenceRefused(String),
    #[error("stored record is corrupt")]
    Corrupt,
}

// ── the platform backends ───────────────────────────────────────────────────

#[cfg(target_os = "android")]
mod backend {
    use super::{StoreError, SERVICE};
    use std::sync::OnceLock;
    use tauri::Manager;
    use tauri_plugin_selfsame_store::SelfsameStore;

    /// Set once during setup. The plugin is reached through the `AppHandle`,
    /// and `Custody` is a static facade with no place to hold one; threading a
    /// handle through every call site would change a dozen signatures to carry
    /// a value that is process-global in fact.
    static APP: OnceLock<tauri::AppHandle> = OnceLock::new();

    pub fn adopt(app: &tauri::App) -> Result<(), StoreError> {
        APP.set(app.handle().clone())
            .map_err(|_| StoreError::Backend("secure storage adopted twice".into()))
    }

    fn store() -> Result<&'static SelfsameStore<tauri::Wry>, StoreError> {
        let app = APP
            .get()
            .ok_or_else(|| StoreError::Backend("secure storage used before setup".into()))?;
        app.try_state::<SelfsameStore<tauri::Wry>>()
            .map(|state| state.inner())
            .ok_or_else(|| {
                StoreError::Backend(
                    "the selfsame-store plugin is not registered in this build".into(),
                )
            })
    }

    /// Namespaced the same way the desktop keychain namespaces its entries, so
    /// the two backends agree on what an entry is called.
    fn qualify(entry: &str) -> String {
        format!("{SERVICE}.{entry}")
    }

    pub fn get(entry: &str) -> Result<Option<String>, StoreError> {
        store()?
            .get(&qualify(entry))
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    pub fn set(entry: &str, value: &str) -> Result<(), StoreError> {
        store()?
            .set(&qualify(entry), value)
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    pub fn delete(entry: &str) -> Result<(), StoreError> {
        store()?
            .delete(&qualify(entry))
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    /// REQ-024's user-presence check.
    ///
    /// `allow_device_credential` means this is satisfied by the device PIN,
    /// pattern or password as well as by a fingerprint or face, which is what
    /// makes it the *"biometric or device passcode"* the requirement asks for
    /// rather than a biometrics-only gate.
    ///
    /// **Fails closed on every error, including "this device has no screen
    /// lock".** That is deliberate and it is what the platforms do: iOS's
    /// `kSecAccessControlUserPresence` also refuses when no passcode is set. A
    /// device with no lock screen cannot perform a presence check, so on such a
    /// device the root key is unusable until the owner sets one — which is the
    /// answer REQ-024 implies, not a degradation of it.
    pub fn require_presence(reason: &str) -> Result<(), StoreError> {
        use tauri::Manager;
        use tauri_plugin_biometric::{AuthOptions, Biometric};

        let app = APP
            .get()
            .ok_or_else(|| StoreError::Backend("secure storage used before setup".into()))?;

        let biometric = app
            .try_state::<Biometric<tauri::Wry>>()
            .ok_or_else(|| {
                StoreError::PresenceRefused("the biometric plugin is not registered".into())
            })?;

        biometric
            .authenticate(
                reason.to_owned(),
                AuthOptions {
                    allow_device_credential: true,
                    title: Some("Confirm it's you".to_owned()),
                    subtitle: Some(reason.to_owned()),
                    confirmation_required: Some(false),
                    ..Default::default()
                },
            )
            .map_err(|e| StoreError::PresenceRefused(e.to_string()))
    }
}

#[cfg(not(target_os = "android"))]
mod backend {
    use super::{StoreError, SERVICE};

    pub fn adopt(_app: &tauri::App) -> Result<(), StoreError> {
        Ok(())
    }

    fn entry(name: &str) -> Result<keyring::Entry, StoreError> {
        keyring::Entry::new(SERVICE, name).map_err(|e| StoreError::Backend(e.to_string()))
    }

    pub fn get(name: &str) -> Result<Option<String>, StoreError> {
        match entry(name)?.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(StoreError::Backend(e.to_string())),
        }
    }

    pub fn set(name: &str, value: &str) -> Result<(), StoreError> {
        entry(name)?
            .set_password(value)
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    pub fn delete(name: &str) -> Result<(), StoreError> {
        match entry(name)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(StoreError::Backend(e.to_string())),
        }
    }

    /// On desktop the presence check *is* the passcode, and it has already
    /// happened: `Custody::use_root_key` cannot derive the wrapping key without
    /// it, so an unattended caller gets `BadPasscode` rather than a key. There
    /// is no biometric API Tauri exposes on desktop to add to that, which
    /// REQ-024 admits in as many words.
    pub fn require_presence(_reason: &str) -> Result<(), StoreError> {
        Ok(())
    }
}

// ── the interface `custody` uses ────────────────────────────────────────────

pub fn get(entry: &str) -> Result<Option<String>, StoreError> {
    backend::get(entry)
}

pub fn set(entry: &str, value: &str) -> Result<(), StoreError> {
    backend::set(entry, value)
}

pub fn delete(entry: &str) -> Result<(), StoreError> {
    backend::delete(entry)
}

/// REQ-024 — *"every operation that uses the Root Key SHALL require that
/// user-presence check"*.
///
/// Called from `Custody::use_root_key`, which is the single point every
/// root-key operation passes through: signing the genesis, signing an
/// `AddVerificationMethod`, signing a `RevokeVerificationMethod`. Putting the
/// check anywhere else would mean auditing every caller instead of one callee.
pub fn require_presence(reason: &str) -> Result<(), StoreError> {
    backend::require_presence(reason)
}

/// Adopt the running application, then prove the store keeps what it is given.
///
/// Called from `commands::init`, so a failure here fails Tauri's setup and the
/// application does not start. That is the intended severity. A root-key
/// custodian whose storage silently discards writes is worse than one that will
/// not launch: the first loses identities and blames the user, the second says
/// what is wrong while nothing is at stake.
pub fn init(app: &tauri::App) -> Result<(), StoreError> {
    backend::adopt(app)?;
    assert_durable()
}

/// Write a probe, read it back, remove it.
///
/// The round trip is the whole point. Asking a backend to *describe* its own
/// persistence — `keyring` will answer `CredentialPersistence::EntryOnly` — only
/// catches the backends that answer honestly, and only the ones that have been
/// thought about. Writing a value and looking for it catches any store that
/// does not keep what it is given, including ones that do not exist yet.
pub fn assert_durable() -> Result<(), StoreError> {
    const TOKEN: &str = "selfsame-durability-probe";

    let write = set(PROBE_ENTRY, TOKEN);
    let read = get(PROBE_ENTRY);
    // Always attempt removal, including on the failure paths — a probe left
    // behind is litter in the user's keychain.
    let _ = delete(PROBE_ENTRY);

    write.map_err(|e| StoreError::NotDurable(format!("The store rejected a test write: {e}")))?;

    match read {
        Err(e) => Err(StoreError::NotDurable(format!(
            "The store rejected a test read: {e}"
        ))),
        Ok(None) => Err(StoreError::NotDurable(
            "A value written to secure storage was not there when read back. On \
             Android this means the selfsame-store plugin is not registered and \
             `keyring` has fallen back to its in-memory testing mock."
                .into(),
        )),
        Ok(Some(found)) if found != TOKEN => Err(StoreError::NotDurable(
            "Secure storage returned a different value from the one written.".into(),
        )),
        Ok(Some(_)) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The probe must never be able to address the real record.
    #[test]
    fn the_probe_entry_is_not_the_root_entry() {
        assert_ne!(PROBE_ENTRY, ROOT_ENTRY);
    }

    /// On the host the backend is a real keychain, so the guard passes. This is
    /// the positive case; `tests/android_custody.rs` supplies the negative one
    /// by installing the store Android actually links.
    #[test]
    fn a_real_keychain_satisfies_the_durability_guard() {
        assert!(
            assert_durable().is_ok(),
            "the host keychain should round-trip a probe value",
        );
    }
}
