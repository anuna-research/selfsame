//! The APK could not create an identity, and this is the regression test.
//!
//! # The defect
//!
//! `keyring` 3.6.3 selects its credential store by `cfg`, and its final arm is
//!
//! ```text
//! #[cfg(not(any(linux, freebsd, openbsd, macos, ios, windows)))]
//! pub use mock as default;
//! ```
//!
//! `target_os = "android"` matches none of those names, so the Android build
//! linked the crate's **mock** store — the one it ships for testing, documented
//! as having "no persistence other than in the entry itself". No feature flag
//! fixed it: `keyring` 3 has no Android backend to enable.
//!
//! `Custody` builds a fresh `keyring::Entry` for every read and every write,
//! which is correct against a real keystore and fatal against that one.
//! `set_password` stored the sealed root in a `MockCredential` that was dropped
//! at the end of the call, and the next `Entry` started empty. So the write was
//! *accepted and discarded*, the read reported `NoEntry`, and `Custody::read`
//! mapped that to `Ok(None)` — indistinguishable from a first run.
//!
//! `create_identity` then failed one line after `Custody::create` returned
//! success, because `Custody::root_public_key` read back what had just been
//! written and found nothing. The user typed a passcode to make a home key and
//! got **"no identity on this device"**, every time.
//!
//! # What is tested here
//!
//! Android now stores through `tauri-plugin-selfsame-store` and the Keystore,
//! which needs a device. What does *not* need a device — and is what would have
//! caught this before it shipped — is [`store::assert_durable`]: it writes a
//! probe value to whatever backend the build linked, reads it back, and refuses
//! to start the application if the value does not survive.
//!
//! So these tests install the exact store Android used to link and assert that
//! the guard now stops it. The failure is no longer silent, no longer deferred
//! to the next call, and no longer phrased as a fact about the user's identity.
//!
//! Trace: SPEC-001-device-key-provisioning#REQ-024.

use selfsame_lib::store::{self, StoreError};

/// Install the store the broken Android build got, and refuse to continue if it
/// did not take effect.
///
/// `set_default_credential_builder` is process-global and first-write-wins, so
/// a silent no-op here would send the rest of the test at the developer's real
/// login keychain under the application's own service name. The probe entry is
/// deliberately not the root record's: it must not collide with a real
/// identity even in the failure case it exists to prevent.
fn install_the_old_android_store() {
    keyring::set_default_credential_builder(keyring::mock::default_credential_builder());

    let probe = keyring::Entry::new("io.anuna.selfsame", "android-custody-probe")
        .expect("the mock builder never fails to build");
    assert!(
        probe
            .get_credential()
            .downcast_ref::<keyring::mock::MockCredential>()
            .is_some(),
        "the mock builder did not take effect — refusing to touch the real keychain",
    );
}

/// The guard catches a store that accepts writes and keeps none.
///
/// This is the whole regression. Before the guard existed, this configuration
/// started the application happily and failed at the first identity; now it
/// cannot get past setup.
#[test]
fn a_store_that_forgets_is_refused_at_startup() {
    install_the_old_android_store();

    let verdict = store::assert_durable();

    assert!(
        matches!(verdict, Err(StoreError::NotDurable(_))),
        "a store with no persistence must be refused, got {verdict:?}",
    );
}

/// The guard blames storage, not the user's identity.
///
/// The original defect was not only that the write was lost — it was that the
/// message said *"no identity on this device"*, which is a claim about the
/// user and sends them to the first-run screen to try again. Whatever this
/// build cannot do, it must not say that.
#[test]
fn the_refusal_names_storage_rather_than_identity() {
    install_the_old_android_store();

    let message = store::assert_durable()
        .expect_err("a store with no persistence must be refused")
        .to_string();

    assert!(
        !message.contains("no identity"),
        "the refusal must not repeat the misleading message: {message}",
    );
    assert!(
        message.contains("storage"),
        "the refusal must name storage as the problem: {message}",
    );
}
