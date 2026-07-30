---
id: SPEC-004
title: Android Secure Storage for the Root Key
status: implementing
version: 0.2.0
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
  custody.rs::platform  (the boundary — an opaque JSON string crosses it)
       │
       ├── macos / ios / windows / linux ──▶ keyring  ──▶ OS keychain
       │
       └── android ──▶ tauri-plugin-selfsame-store  ──▶ AndroidKeyStore
                       │   SecureStore (Rust)             AES-256-GCM key
                       └─▶ SecureStorePlugin.kt           never exported
                                    │
                                    └─▶ noBackupFilesDir/root-v1.bin
                                        version ‖ IV ‖ ciphertext

  the sealed record is identical on every arm; only the box differs
```

**Decisions:**
[[SPEC-004-android-secure-storage#ADR-301]] Keystore-wrapped, not a plain file ·
[[SPEC-004-android-secure-storage#ADR-302]] keep the Argon2id seal underneath ·
[[SPEC-004-android-secure-storage#ADR-303]] a Tauri mobile plugin, not JNI in
`custody.rs` ·
[[SPEC-004-android-secure-storage#ADR-304]] `compile_error!` rather than a
runtime fallback ·
[[SPEC-004-android-secure-storage#ADR-305]] platform-enforced user
authentication deferred ·
[[SPEC-004-android-secure-storage#ADR-306]] the record lives outside Android
backup ·
[[SPEC-004-android-secure-storage#ADR-307]] no webview-reachable command surface

**Load-bearing:** [[SPEC-004-android-secure-storage#REQ-301]] the record
survives a restart · [[SPEC-004-android-secure-storage#REQ-302]] the platform
wraps the key · [[SPEC-004-android-secure-storage#CON-301]]'s error model —
*absent and undecryptable are different answers*

**Open:**
- **Verification still requires a physical device.** TEST-301 through TEST-303
  cannot run in CI as it stands; the contract between the two languages now can,
  and does ([[SPEC-004-android-secure-storage#TEST-305]]). See
  [[SPEC-004-android-secure-storage#Verification]]. Owner: HOC.
- Whether to automate TEST-301 with a headless AVD in CI. Costed, not scheduled;
  not a precondition for this specification reaching `implemented`. Owner: HOC.

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

**Severity:** S1 · **Priority:** P0 · **Status:** fixed in code, **unverified on a
device** — see [[SPEC-004-android-secure-storage#Verification]]
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

Three changes, and it is worth being clear that only the first *fixes* anything:

1. **A real store.** [[SPEC-004-android-secure-storage#CON-301]], implemented as
   `crates/tauri-plugin-selfsame-store`.
2. **The dependency that degraded is gone from the target.** `keyring` is now
   declared under `cfg(not(target_os = "android"))`, so the mock store is not
   merely unused on Android — it cannot be linked into the APK.
3. **The build refuses the class of mistake.**
   [[SPEC-004-android-secure-storage#ADR-304]]'s `compile_error!` landed
   immediately and stays, now guarding the *next* target rather than this one. A
   target with no arm in `custody::platform` does not produce a binary.

The `custody.rs` platform table gained an Android row and a note saying why the
table is load-bearing. Its absence was not a documentation gap: the table stated
what was true of four platforms while the code silently did something else on a
fifth, and no reader of that module had any reason to doubt it.

**Not yet closed.** Nothing above has run on a phone. The fix is verified by
compilation and by [[SPEC-004-android-secure-storage#TEST-305]]; the *symptom* is
verified by installing the APK and tapping the button, which is where this bug
came from in the first place.

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

**Composition-first check (Simplicity Ladder rung 4), recorded because the
answer was not obvious.** `androidx.security:security-crypto` —
[[EncryptedSharedPreferences]] and `EncryptedFile` — is Google's own wrapper that
does *precisely* this: it generates an AES-256-GCM master key in the
[[Android Keystore]] and encrypts a file or a preferences store under it. Using
it would have replaced the whole Kotlin implementation below with about four
lines, and rung 4 says to prefer exactly that.

**Rejected, on two grounds.** It was **deprecated in April 2025** at
`1.1.0-alpha07`, so adopting it would mean taking a new dependency that Google
has already stopped maintaining, with DataStore + Tink named as the direction of
travel. More pointedly, one of the two documented reasons for the deprecation is
*keyset corruption on particular OEM devices* — and a store that intermittently
cannot decrypt its own contents is the exact failure
[[SPEC-004-android-secure-storage#CON-301]]'s error model exists to survive. A
library whose known defect is the failure mode our contract is built around is
not a shortcut.

Settled at **rung 5**: the minimum new code that works, against
`java.security.KeyStore` and `javax.crypto` in the platform itself. The
consequence is worth naming — the plugin's Gradle module has **no androidx
dependency at all**, so nothing it pulls in can widen the merged manifest that
[[SPEC-003-android-apk-distribution]] REQ-203 checks against an allowlist.

### ADR-302: Keep the Argon2id seal underneath

**Status:** accepted

Keystore wrapping replaces nothing. The record stays sealed under the
passcode-derived key, then that sealed blob is encrypted by the Keystore key.

**Rationale.** They defend against different things. Keystore stops an attacker
who has the device's filesystem; Argon2id stops an attacker who has *also*
defeated the Keystore, or who is running on the unlocked device. Dropping either
would trade defence in depth for a marginal simplification.

### ADR-303: A Tauri mobile plugin, not JNI inside `custody.rs`

**Status:** accepted, landed as `crates/tauri-plugin-selfsame-store`

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

**Status:** deferred by decision, 2026-07-30. Owner: HOC. Not rejected; revisit
as its own change.

The Keystore key can be created with `setUserAuthenticationRequired(true)`,
making the OS demand biometric or device credential before the key will
decrypt. That is [[SPEC-001-device-key-provisioning]] REQ-024's presence check
enforced by the platform rather than by our passcode, and it is strictly
stronger.

**Decision.** Land [[SPEC-004-android-secure-storage#CON-301]] without it.
Hardware-wrapped storage plus the existing Argon2id gate is already a large
improvement on storing nothing, and the deferral keeps the change that fixes
BUG-201 separable from the change that strengthens REQ-024.

**Why this is a decision and not a flag.** Adding the flag later is not a
one-line edit to the key builder — it changes CON-301's shape. `load()` would
have to be able to block on a `BiometricPrompt`, so the contract gains at least
two error cases that do not exist today:

- `KeyPermanentlyInvalidatedException` on biometric re-enrolment. The key is
  destroyed by the OS, the record becomes permanently undecryptable, and the
  twelve words become the only path back. That needs its own REQ, its own screen
  copy, and a TEST — it is a *new way to lose an identity*, introduced by a
  security improvement.
- Devices with no enrolled biometric or device credential. Without a fallback the
  app cannot store a key at all on such a device.

Both are real work with user-visible consequences, and neither belongs in the
same change as the fix for a store that persisted nothing. The app already
depends on `tauri-plugin-biometric`, so the pieces exist when this is taken up.

**What stands in for it today.** The presence check is the Argon2id gate in
`custody.rs`, exactly as on desktop, which
[[SPEC-001-device-key-provisioning]] REQ-024 admits in as many words. The
deferral is recorded at the point of code too: the `generateKey` doc comment in
`SecureStorePlugin.kt` names this ADR and says the flag is absent by decision
rather than by oversight — the failure mode of BUG-201 was precisely a gap that
nothing in the source acknowledged.

### ADR-306: The record lives outside Android's backup

**Status:** accepted

**Context.** `Context.getFilesDir()` is the obvious place for an app-private
file, and its contents are swept up by Android's automatic backup — copied to the
user's Google account and restored onto a replacement device.

**Decision.** Write the record to `Context.getNoBackupFilesDir()` instead.

**Rationale.** The ciphertext is useless without the Keystore key, which is
device-bound and never backed up, so [[SPEC-004-android-secure-storage#REQ-303]]
would hold either way. The problem is not secrecy but *what the user is told*.
Restore a backup onto a new phone and the app would find a record it cannot
decrypt, and would correctly report a **corrupt store** — to a user whose actual
situation is a new phone and a recovery phrase in a drawer. Excluding the file
from backup makes that case read as *no identity here*, which is both true and
the state the restore flow is built for.

The alternative — `android:allowBackup="false"` — would work but is a
whole-application decision made from inside a plugin, and reaching it from a
library manifest needs a `tools:replace` override that fights the manifest
merger. `noBackupFilesDir` is the platform's own answer to this exact question
(Simplicity Ladder rung 3) and touches nothing outside this module.

### ADR-307: No webview-reachable command surface

**Status:** accepted

**Decision.** The plugin registers **zero** commands: `COMMANDS` in its
`build.rs` is an empty slice.

**Rationale.** `tauri_plugin::Builder` autogenerates an `allow-$command`
permission for every name listed there, which is what makes a command callable
from the webview over IPC. A webview-reachable `loadRecord` would hand the sealed
root record to any script running in the app; a reachable `deleteRecord` would let
one destroy the identity. Neither is needed: `custody.rs` reaches the Kotlin class
through `PluginHandle::run_mobile_plugin`, which is a direct Rust→JNI call and
does not pass through the ACL at all.

So the capability surface is empty **by construction** rather than by a capability
file that someone must remember not to widen. The frontend gains nothing it had
before — it never touched storage directly on any platform — and
[[SPEC-004-android-secure-storage#TEST-305]] fails if `COMMANDS` stops being
empty.

---

## Contracts

### CON-301: The Android secure-store plugin

**Implemented** as `crates/tauri-plugin-selfsame-store`.

```rust
// Rust side, called only under #[cfg(target_os = "android")]
impl<R: Runtime> SecureStore<R> {
    fn store(&self, blob: &str) -> Result<(), StoreError>;   // overwrites
    fn load(&self) -> Result<Option<String>, StoreError>;    // None when absent
    fn delete(&self) -> Result<(), StoreError>;              // idempotent
}
```

Reached from `custody.rs::platform::android`, which holds the `AppHandle` in a
`OnceLock` set by `commands::init` during Tauri's `setup`. `Custody`'s functions
take no receiver — the module deliberately holds nothing between calls, which is
what keeps a derived signing key out of a field — so the handle is *found* rather
than threaded through five platforms' worth of signatures to serve one.

Kotlin side, `SecureStorePlugin.kt`, backed by `AndroidKeyStore`:

- An AES-256-GCM key aliased `io.anuna.selfsame.root`, generated on first
  `store` with `setBlockModes(GCM)`, `setEncryptionPaddings(NONE)`,
  `setKeySize(256)` and hardware backing where the device provides it. Generated
  inside the Keystore and never exported (REQ-302).
- The ciphertext and its IV written to `noBackupFilesDir/root-v1.bin`
  ([[SPEC-004-android-secure-storage#ADR-306]]).
- **The IV is not ours to choose.** `setRandomizedEncryptionRequired(true)` — the
  default, stated explicitly in the builder — makes the platform reject an
  IV supplied to `Cipher.init` for encryption and generate a fresh one per call.
  "Fresh per `store`" is therefore enforced by the OS rather than remembered by
  us, which is the stronger form of the same requirement.

The wire names are `storeRecord` / `loadRecord` / `deleteRecord`: `Plugin`
already defines `load(WebView)`, and a command called `load` would be a same-name
overload on a class whose commands are indexed by reflection over method names.

#### Input grammar (Constitutional Principle 14)

The stored record is the one input this contract parses, and it is recognised in
full before any `Cipher` is touched. The language is fixed-width and regular —
the weakest class that expresses it:

```abnf
record     = version iv ciphertext
version    = %x01
iv         = 12 OCTET
ciphertext = 17*OCTET   ; >= 1 byte of payload + the 16-byte GCM tag
```

A byte string outside this language is `corrupt`, never `absent`, and no
decryption is attempted on it. The GCM tag is the second recogniser: a record
whose header is well-formed but whose ciphertext was altered fails
authentication and is also `corrupt`.

**Pre-conditions:** the plugin has been registered and `attach_secure_store` has
run. `load` on a device that has never stored returns `Ok(None)`, matching
`keyring::Error::NoEntry`'s handling in `custody.rs`.

**Post-conditions:**
- `store(x)` then `load()` yields `Some(x)` — including across process restart,
  which is the whole point (REQ-301).
- `store(y)` after `store(x)` yields `Some(y)`, and **a failure part-way through
  leaves `Some(x)`**. The write goes to a temporary file and is moved into place
  with `rename(2)`, so a crash mid-overwrite cannot truncate a record that
  already exists. `confirm_backup` rewrites the record of an identity the user
  already has; without this, a crash there would cost them that identity.
- `delete()` then `load()` yields `Ok(None)`.
- No call returns unsealed key material; the blob is opaque to this contract.
- Behaviour does not vary with the caller. In particular there is no caller for
  whom these are reachable from the webview
  ([[SPEC-004-android-secure-storage#ADR-307]]).

**Error model.** *Absent* and *present but undecryptable* are different answers,
and the distinction MUST survive the trip from Kotlin to Rust. It travels as data
on the success path rather than as a rejection code, so it rests on a tagged type
that fails to deserialise if either side stops honouring it — not on matching a
string:

```jsonc
{ "state": "absent"  }                 // Ok(None)
{ "state": "present", "blob": "…" }    // Ok(Some(blob))
{ "state": "corrupt", "detail": "…" }  // Err(StoreError::Corrupt) → CustodyError::Corrupt
```

Genuine failures — no Keystore, an I/O error — reject instead, and become
`CustodyError::Keychain`. That case says nothing about whether a record exists,
so the caller MUST NOT conclude that none does.

`StoreError::Corrupt` MUST surface as `CustodyError::Corrupt` and never as
`NoIdentity`, because telling a user with a damaged store that they have no
identity would invite them to create a second one over the top of the first —
and the first is the one their contacts have already accepted, signed by a root
key that would now be gone. The mapping is one `match` in
`custody.rs::platform::android::lift`, verified by
[[SPEC-004-android-secure-storage#TEST-305]].

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
- *negative-input:* truncate the record below the grammar's minimum, and flip the
  version byte → `corrupt` in both cases, with no decryption attempted.

**Partially automated.** The platform-independent half — that a record which
will not parse is `Corrupt` and not an absence — runs on every host as
`custody::tests::a_record_that_will_not_parse_is_corrupt_and_not_an_absence`.
The half that needs a real Keystore and a real file to damage does not.

### TEST-305: The two languages still agree
**Validates:** [[SPEC-004-android-secure-storage#CON-301]]'s wire contract,
[[SPEC-004-android-secure-storage#ADR-307]]

`crates/tauri-plugin-selfsame-store/tests/wire_contract.rs`. Runs on any host, no
device. It reads both source files at compile time and asserts:

- every command Rust calls exists as a command on the Kotlin class — a mismatch
  is otherwise a runtime *"No command … found"* on a phone, found by a user;
- the Kotlin class exposes nothing Rust does not call, so there is no dead
  command surface on the module holding the root key;
- `COMMANDS` is still empty, so nothing became webview-reachable (ADR-307);
- the three state literals and two field names are byte-identical on both sides;
- each of the three states deserialises to the right outcome, an unknown state is
  refused rather than treated as absent, and `present` without a `blob` is not a
  present record.

**This test has teeth, and that was checked rather than assumed.** Renaming
`"loadRecord"` to `"loadRekord"` on the Rust side alone fails two of these tests
with the diagnostic naming the runtime error it would have caused. Red Gate could
not be applied — the implementation and the tests were written together — so the
mutation stands in for it, as [[PROTO-001]] requires when temporal enforcement is
impractical.

**What it does not do.** It cannot compile the Kotlin, so a Kotlin *type* error
is still CI's job, and it cannot tell whether the Keystore behaves. It closes the
cheapest and most likely gap, not the deepest one.

---

## Verification

**The behaviour this specification exists for still cannot be verified in CI, and
that must not be glossed over.** The runner builds an APK; it does not run one.

What *is* verified, and how:

| Check | Where it runs | Covers |
|---|---|---|
| `cargo test -p tauri-plugin-selfsame-store` — 8 tests | any host | [[SPEC-004-android-secure-storage#TEST-305]]; the parse half of [[SPEC-004-android-secure-storage#TEST-304]] |
| `cargo test -p selfsame` — 6 unit tests | any host | the `Corrupt`-not-absent mapping, platform-independent |
| `cargo check -p tauri-plugin-selfsame-store --target aarch64-linux-android` | host with NDK | the plugin's Rust compiles for Android; `register_android_plugin` and `run_mobile_plugin` typecheck; the build script's Android branch runs and stages `android/.tauri/tauri-api` for Gradle |
| `cargo check -p selfsame --target aarch64-linux-android` | **NDK required** | that `custody.rs`'s Android arm compiles and the `compile_error!` no longer fires. Needs a cross C toolchain because `ring` is in the graph, so it is CI's job unless an NDK is installed locally |
| Kotlin compiles at all | CI only | `cargo tauri android build` |

What is **not** verified by anything above:

- **TEST-301, TEST-302, TEST-303 — every requirement about actual persistence.**
  They need an Android runtime.
- Whether the Keystore key is hardware-backed on a given device.
- Whether `noBackupFilesDir` behaves as ADR-306 assumes on a real
  backup/restore cycle.

Two honest consequences, unchanged by the tests added in 0.2.0:

1. **The first real verification of this work is a human installing an APK.**
   The same loop that found BUG-201 — which is the only reason it was found. The
   tests above narrow what that human is likely to hit; they do not replace them.
2. An emulator in CI (`avdmanager` + a headless AVD + `adb`) is the way to make
   TEST-301 automated, and it is a separate piece of work with its own cost. It
   is not a precondition for landing this, but without it the Android storage
   path stays covered by manual testing only, and that should be written down
   rather than assumed away.

### What to check on the device

In order, because each step's failure means something different:

1. Install, tap *Create my home key*, enter a passcode. **A recovery phrase
   appears** → `store` and the `root_public_key()` read three lines later both
   worked. This is the exact sequence that failed in BUG-201.
2. Force-stop the app and reopen it. **The home screen shows the identity and its
   fingerprint** → REQ-301, and it is the first thing the old build could not do.
3. Complete the backup confirmation, force-stop, reopen. **Still confirmed** →
   the overwrite path works, not just the create path.
4. Uninstall, reinstall. **"No identity on this device"** → REQ-303, and *not*
   "stored record is corrupt", which would mean ADR-306 is wrong.

---

## Changelog

<details>
<summary>Revision history — 0.2.0</summary>

- 0.2.0 — [[SPEC-004-android-secure-storage#CON-301]] implemented as
  `crates/tauri-plugin-selfsame-store`; `keyring` removed from the Android
  dependency graph so the mock store cannot be linked into the APK; the
  `compile_error!` narrowed to admit Android and rewritten to guard the *next*
  target. [[SPEC-004-android-secure-storage#ADR-305]] decided (deferred, with the
  reason it is a decision rather than a flag).
  [[SPEC-004-android-secure-storage#ADR-306]] and
  [[SPEC-004-android-secure-storage#ADR-307]] added — both decisions taken while
  implementing, recorded rather than left in the code.
  [[SPEC-004-android-secure-storage#ADR-301]] gained the composition-first record
  that rejected [[EncryptedSharedPreferences]].
  [[SPEC-004-android-secure-storage#TEST-305]] added and mutation-checked.
  Status `draft` → `implementing`: the code is written, and TEST-301 through
  TEST-303 remain unrun for want of a device.
- 0.1.0 — BUG-201 root-caused from a user's device report; specification for
  Keystore-backed storage drafted. `compile_error!` guard landed immediately.
</details>
