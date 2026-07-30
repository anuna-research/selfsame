# tauri-plugin-selfsame-store

Keystore-wrapped storage for the Selfsame root record on Android. Implements
[`SPEC-004`](../../specs/SPEC-004-android-secure-storage.md) CON-301.

## Why this exists

`keyring` has no Android backend. Its store selection is `#[cfg]`-driven and its
catch-all arm is an **in-memory mock**, so on Android the crate compiled, the
build stayed green, and the published APK stored the root key nowhere — BUG-201.
The mock is also per-instance, so a write and the read three lines after it
addressed different maps, and `Custody::create` was followed immediately by a
`root_public_key()` that reported no identity.

This crate is the real store for that platform. `keyring` is no longer an Android
dependency at all, and `custody.rs` carries a `compile_error!` so the next target
without a real store fails to build rather than shipping.

## What it does

```
  custody.rs ──▶ SecureStore ──▶ SecureStorePlugin.kt ──▶ AndroidKeyStore
   (sealed        (Rust)           (Kotlin)                 AES-256-GCM key
    record)                                                 alias io.anuna.selfsame.root
                                          │
                                          └─▶ noBackupFilesDir/root-v1.bin
                                              version ‖ IV ‖ ciphertext
```

The blob it is handed is **already sealed** with Argon2id under the user's
passcode. This crate adds the second layer of ADR-302 — an AES-256-GCM key
generated inside the Keystore and never exported — and writes the result to
app-private storage. It never sees an unsealed seed; the blob is opaque to it.

| Rust (CON-301)                                | Kotlin command  |
| --------------------------------------------- | --------------- |
| `store(&str) -> Result<()>`                   | `storeRecord`   |
| `load() -> Result<Option<String>>`            | `loadRecord`    |
| `delete() -> Result<()>`                      | `deleteRecord`  |

The Kotlin names differ because `Plugin` already defines `load(WebView)`.

## Two properties worth knowing

**Nothing here is reachable from the webview.** `build.rs` registers no
commands, so no capability can name them and no script in the app can read or
destroy the record. The Kotlin class is reached only through
`PluginHandle::run_mobile_plugin` from Rust, which does not pass through the ACL.

**Absent is not corrupt.** `loadRecord` resolves with a tagged object —
`absent`, `present`, or `corrupt` — rather than rejecting, because the three
outcomes are not all errors and the distinction is load-bearing. A user whose
record is damaged and is told they have no identity will create a second one over
the top of the first, and the first is the one their contacts have accepted.

## Verifying it

```sh
cargo test -p tauri-plugin-selfsame-store          # the Rust↔Kotlin contract
cargo check -p tauri-plugin-selfsame-store --target aarch64-linux-android
```

The second needs the Android NDK on `PATH`; the first does not.

`tests/wire_contract.rs` is the only automated coverage that runs without a
device: it checks that every command Rust calls exists on the Kotlin class, that
the Kotlin class exposes nothing more, that `COMMANDS` is still empty, and that
the three state literals agree across the two languages.

**TEST-301 through TEST-303 are not covered.** They need an Android runtime — the
CI runner builds an APK, it does not run one — so the first real test of the
storage path is a human installing the APK. SPEC-004's *Verification* section
says so rather than assuming it away.
