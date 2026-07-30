---
id: SPEC-004
title: Android Secure Storage for the Root Key
status: draft
version: 0.1.0
last-updated: 2026-07-30
---

# SPEC-004 — Android Secure Storage for the Root Key

## Orientation

**Intent:** Store the sealed root record on Android in the platform's
[[Android Keystore]], so that an identity created on a phone survives the app
being closed — and so that the key material is hardware-wrapped, as it already
is on iOS and macOS.

**Metaphor:** *a safe deposit box, not a drawer.* The record inside is already
in a sealed envelope (Argon2id under the user's passcode). What Android must
supply is the box: something the OS holds, bound to this app and ideally to
this device's hardware. The current build has neither box nor drawer — it posts
the envelope into a shredder.

**Structure:**

```
  custody.rs  (the only module that touches key material)
       │
       ├── macos / ios / windows / linux ──▶ keyring  ──▶ OS keychain
       │
       └── android ──────────────────────▶ CON-301   ──▶ Keystore-wrapped
                                            plugin        app-private blob
  the sealed record is identical on every arm; only the box differs
```

**Decisions:**
[[SPEC-004-android-secure-storage#ADR-301]] Keystore-wrapped, not a plain file ·
[[SPEC-004-android-secure-storage#ADR-302]] keep the Argon2id seal underneath ·
[[SPEC-004-android-secure-storage#ADR-303]] a Tauri mobile plugin, not JNI in
`custody.rs` ·
[[SPEC-004-android-secure-storage#ADR-304]] `compile_error!` rather than a
runtime fallback

**Open:**
- Whether the Keystore key sets `setUserAuthenticationRequired(true)` — see
  [[SPEC-004-android-secure-storage#ADR-305]]. Owner: HOC.
- **Verification requires a physical device.** Nobody can test this in CI as it
  stands; see [[SPEC-004-android-secure-storage#Verification]].

**Detail:** [[SPEC-003-android-apk-distribution]] · [[PROTO-001]]

---

## Conformance

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in
all capitals.

Artefacts are numbered from **301**, continuing the banding rationale in
[[SPEC-002-visual-key-fingerprint]].

---

## BUG-201: On Android the root key was stored nowhere

**Severity:** S1 · **Priority:** P0 · **Status:** confirmed
**Reported by:** user, on a physical device, from the published APK
**Violates:** [[SPEC-001-device-key-provisioning]] REQ-001 (an identity persists
on the device that created it). Not previously specified for Android at all —
which is the deeper defect.

### Symptom

Install the APK, tap *Create my home key*, enter a passcode →
**"no identity on this device"**.

### Root cause

`design-error`, compounded by a dependency that degrades silently.

`keyring` 3.6.3 picks its store by target, and its catch-all arm is the mock
store — `keyring-3.6.3/src/lib.rs:300`:

```rust
#[cfg(not(any(
    target_os = "linux", target_os = "freebsd", target_os = "openbsd",
    target_os = "macos",  target_os = "ios",     target_os = "windows",
)))]
pub use mock as default;
```

Android matches none of those arms, and the crate ships **no `android.rs`** —
its store modules are `ios`, `macos`, `windows`, `secret_service`, `keyutils`,
`mock`, and that is the complete list. `Cargo.toml` requests `apple-native`,
`windows-native` and `sync-secret-service`; none is Android.

The mock store is also per-instance, not process-global — `mock.rs:50`:

```rust
pub struct MockCredential { pub inner: Mutex<RefCell<MockData>> }
// …constructed with Default::default() per `new()`
```

and `custody.rs::entry()` builds a **new** `keyring::Entry` on every call. So a
write and the read that follows it never address the same map. The sequence in
`commands.rs::create_identity` is:

```rust
let phrase   = … Custody::create(&passcode) …;  // writes to mock entry A, dropped
let root_pk  = Custody::root_public_key()?;     // reads mock entry B → NoIdentity
```

The failure is three lines after the write, in the same function.

### Why nothing caught it

`custody.rs`'s own platform table lists macOS/iOS, Windows and Linux. **Android
was never a row in it.** Nothing in the test suite exercises the shell's storage
on an Android target, the dependency compiled happily, CI went green, and an APK
was published and installed.

### One piece of luck, and it is only luck

`create_identity` calls `root_public_key()` *before* returning the twelve words,
so the command errors before any recovery phrase reaches the screen. Had the
ordering been different, the app would have shown a user a recovery phrase for
an identity it had already discarded. For a custody application that is the
worst failure available, and nothing in the design prevented it — only the
order of two statements.

### Resolution

This specification. Plus, landed immediately and independently:
[[SPEC-004-android-secure-storage#ADR-304]] makes the condition a compile error,
so no further APK can be published from a tree that cannot persist a key.

---

## Requirements

### REQ-301: The sealed record persists across app restarts

The system SHALL store the sealed root record such that an identity created on
an Android device is readable by a subsequent launch of the application, FOR the
lifetime of the installation.

Trace: [[SPEC-004-android-secure-storage#TEST-301]],
[[SPEC-004-android-secure-storage#CON-301]]

### REQ-302: Key material is wrapped by the platform

The stored record SHALL be encrypted under a key held in the
[[Android Keystore]], generated on first use and never exported from it.

Trace: [[SPEC-004-android-secure-storage#TEST-302]]

### REQ-303: Uninstall destroys the record

Uninstalling the application SHALL render the record unrecoverable, so that the
twelve words are the only recovery path — matching the guarantee the other
platforms already make.

Trace: [[SPEC-004-android-secure-storage#TEST-303]]

### NFR-301: No plaintext key material at rest

At no point SHALL an unsealed seed or signing key be written to storage, on any
platform, CONFORMING TO [[SPEC-001-device-key-provisioning]] NFR-002.

---

## Architecture decisions

### ADR-301: Keystore-wrapped, not a plain app-private file

**Status:** accepted

**Context.** The record is *already* sealed with Argon2id under the user's
passcode; `custody.rs` states that "possession of the keychain entry alone does
not yield the root key". A plain file in app-private storage would therefore
have made the app work, and would have been a fraction of the effort.

**Decision.** Use the [[Android Keystore]] anyway.

**Rationale.** Android app-private storage is sandboxed, not encrypted at rest
against a rooted device or an adb backup on a permissive OEM build. Every other
platform in this app gets hardware-wrapped storage; Android is the one most
likely to be lost or stolen. Accepting a weaker box on the platform with the
worst threat model, in the application whose entire purpose is key custody,
would be the wrong trade — and it is the trade the existing `// SIMPLIFY:`
annotation in `custody.rs` already anticipated closing.

### ADR-302: Keep the Argon2id seal underneath

**Status:** accepted

Keystore wrapping replaces nothing. The record stays sealed under the
passcode-derived key, then that sealed blob is encrypted by the Keystore key.

**Rationale.** They defend against different things. Keystore stops an attacker
who has the device's filesystem; Argon2id stops an attacker who has *also*
defeated the Keystore, or who is running on the unlocked device. Dropping either
would trade defence in depth for a marginal simplification.

### ADR-303: A Tauri mobile plugin, not JNI inside `custody.rs`

**Status:** accepted

**Decision.** A Tauri v2 mobile plugin with a small Kotlin implementation, and
`custody.rs` calling it behind `#[cfg(target_os = "android")]`.

**Rationale.** `src-tauri/gen/android` is generated per build and gitignored
([[SPEC-003-android-apk-distribution#ADR-204]]), so Kotlin placed in the app
would be destroyed on the next `android init`. A plugin owns its own source tree
outside `gen/`. Doing it with the `jni` crate directly would keep everything in
Rust but put hand-written JNI in the one module where a mistake costs a root key.

### ADR-304: `compile_error!`, not a runtime fallback

**Status:** accepted, landed

A target with no real keychain backend now fails to compile.

**Rationale.** The alternative — detect at runtime and refuse — still produces a
shippable artefact, and this defect already reached a user's phone because
nothing objected at build time. A custody module that cannot persist a key
should not produce a binary. This deliberately breaks the Android build until
[[SPEC-004-android-secure-storage#CON-301]] lands, which is the correct state.

### ADR-305: Platform-enforced user authentication — DEFERRED

**Status:** open

The Keystore key can be created with `setUserAuthenticationRequired(true)`,
making the OS demand biometric or device credential before the key will
decrypt. That is [[SPEC-001-device-key-provisioning]] REQ-024's presence check
enforced by the platform rather than by our passcode, and it is strictly
stronger.

**Deferred, not rejected.** It changes the interaction model: every root-key use
needs a `BiometricPrompt` round-trip, invalidation on biometric enrolment change
has to be handled, and devices without enrolled biometrics need a fallback path.
The app already depends on `tauri-plugin-biometric`, so the pieces exist.

Recommendation: land [[SPEC-004-android-secure-storage#CON-301]] without it
first — hardware-wrapped storage plus the existing Argon2id gate is already a
large improvement on storing nothing — then add it as a separate, reviewable
change. Owner: HOC.

---

## Contracts

### CON-301: The Android secure-store plugin

```rust
// Rust side, called only under #[cfg(target_os = "android")]
fn store(blob: &str) -> Result<(), StoreError>;   // overwrites
fn load() -> Result<Option<String>, StoreError>;  // None when absent
fn delete() -> Result<(), StoreError>;            // idempotent
```

Kotlin side, backed by `AndroidKeyStore`:

- An AES-256-GCM key aliased `io.anuna.selfsame.root`, generated on first
  `store` with `setBlockModes(GCM)`, `setEncryptionPaddings(NONE)`, and
  hardware backing where the device provides it.
- The ciphertext and its IV written to app-private storage. The IV is not
  secret; it MUST be fresh per `store`.

**Pre-conditions:** none. `load` on a device that has never stored returns
`Ok(None)`, matching `keyring::Error::NoEntry`'s handling in `custody.rs::read`.

**Post-conditions:**
- `store(x)` then `load()` yields `Some(x)` — including across process restart,
  which is the whole point (REQ-301).
- `delete()` then `load()` yields `Ok(None)`.
- No call returns unsealed key material; the blob is opaque to this contract.

**Error model:** `StoreError` distinguishes *absent* (not an error) from
*present but undecryptable* — the latter MUST surface as
`CustodyError::Corrupt` and never as `NoIdentity`, because telling a user with a
damaged store that they have no identity would invite them to create a second
one over the top of the first.

---

## Test specifications

### TEST-301: The record survives a restart
**Validates:** [[SPEC-004-android-secure-storage#REQ-301]]
- *positive:* store, kill the process, launch, load → the same blob.
- *negative-output:* a fresh install loads `None`, not a stale blob.

### TEST-302: The key does not leave the Keystore
**Validates:** [[SPEC-004-android-secure-storage#REQ-302]]
- *positive:* the Keystore entry reports `isInsideSecureHardware` where the
  device supports it; the key is not present in app-private storage.
- *negative-output:* app-private storage contains no value that decrypts the
  blob without the Keystore.

### TEST-303: Uninstall destroys it
**Validates:** [[SPEC-004-android-secure-storage#REQ-303]]
- *positive:* uninstall, reinstall, `load()` → `None`.

### TEST-304: A damaged store is not reported as an absent one
**Validates:** [[SPEC-004-android-secure-storage#CON-301]]'s error model
- *negative-input:* corrupt the ciphertext → `CustodyError::Corrupt`, and the
  UI does **not** offer to create a new identity.

---

## Verification

**This cannot be verified in CI as it stands, and that must not be glossed
over.** TEST-301 through TEST-304 all require an Android runtime: a physical
device or an emulator. The runner builds an APK; it does not run one.

Two honest consequences:

1. **The first verification of this work will be a human installing an APK.**
   The same loop that found BUG-201 — which is the only reason it was found.
2. An emulator in CI (`avdmanager` + a headless AVD + `adb`) is the way to make
   TEST-301 automated, and it is a separate piece of work with its own cost. It
   is not a precondition for landing this, but without it the Android storage
   path stays covered by manual testing only, and that should be written down
   rather than assumed away.

---

## Changelog

<details>
<summary>Revision history — 0.1.0</summary>

- 0.1.0 — BUG-201 root-caused from a user's device report; specification for
  Keystore-backed storage drafted. `compile_error!` guard landed immediately.
</details>
