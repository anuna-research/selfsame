---
id: SPEC-003
title: Android APK Build and Distribution
status: implemented
version: 1.2.0
last-updated: 2026-08-03
implemented-date: 2026-07-30
---

# SPEC-003 — Android APK Build and Distribution

## Orientation

**Intent:** Build an Android APK on every push to `main` and publish it to the
`anuna-files` [[Cloudflare R2]] bucket under `selfsame/`, so a phone build can
be sideloaded without anyone running a local Android toolchain.

**Status: implemented and verified.** The runner's container limit was raised
from 3 GiB to 8 GiB, and the pipeline produced and published the first Android
build of this application — 20m02s, retrievable at
`https://files.anuna.io/selfsame/selfsame-UNSIGNED-DEV.apk`.

**Metaphor:** *a bakery whose oven was too small for the tray.* Every
ingredient was on the bench and the recipe was written; only the oven was
wrong. Enlarging it changed nothing else.

**Structure:**

```
   push to main
        │
        ▼
  ┌───────────────────────────────────────────┐
  │ job: android          (ubuntu-latest)     │
  │   JDK 17 + SDK + NDK        ← ~20 min cold│
  │   cargo tauri android init --ci    ← 8 s  │
  │   cargo tauri android build --apk         │
  │     --debug -t aarch64      ← needs 8 GiB │
  │   ▸ merged-manifest permission allowlist  │
  └────────────────────┬──────────────────────┘
                       │ selfsame-UNSIGNED-DEV-<sha>.apk
                       ▼
        ┌──────────────────────────────────────┐
        │ anuna-files (Cloudflare R2)          │
        │   selfsame/selfsame-UNSIGNED-DEV.apk │ ← flat = latest
        │   selfsame/<sha>/…-<sha>.apk         │ ← immutable
        └──────────────────────────────────────┘
     flat-is-latest follows hark's release pipeline, not a new convention
```

**Decisions:**
[[SPEC-003-android-apk-distribution#ADR-201]] debug-signed, loudly named ·
[[SPEC-003-android-apk-distribution#ADR-202]] arm64 only ·
[[SPEC-003-android-apk-distribution#ADR-203]] the allowlist reads the *merged*
manifest ·
[[SPEC-003-android-apk-distribution#ADR-204]] `gen/android` stays generated,
not committed

**Open:**
- **`BUG-201`: the published APK could never create a home key** — `keyring` has
  no Android backend and falls through to its testing mock, so every write to
  the root record was accepted and discarded. A Keystore-backed store and a
  startup durability guard are in; neither has run on a device
  ([[SPEC-003-android-apk-distribution#BUG-201]]). Owner: HOC.
- **`OBS-203`: the APK is 208 MB** — cause now *measured* rather than suspected
  (90% of it is DWARF in one `.so`), fix applied, awaiting the next run's
  number ([[SPEC-003-android-apk-distribution#OBS-203]]). Owner: HOC.
- `android.permission.DUMP` is in the shipped manifest and nobody asked for it
  ([[SPEC-003-android-apk-distribution#OBS-202]]). Owner: HOC.

**Detail:** [[SPEC-002-visual-key-fingerprint]] · [[PROTO-001]]

---

## Conformance

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in
all capitals.

Artefacts are numbered from **201** in every prefix, continuing the banding
rationale recorded in [[SPEC-002-visual-key-fingerprint]].

This document adds three dead links — [[Cloudflare R2]], and [[Keyring]] and
[[AndroidKeyStore]] from
[[SPEC-003-android-apk-distribution#BUG-201]] — and defers all three under the
same rule: vendor and tool pages are vault-wide vocabulary and belong in the
shared `anuna-ssi` vault rather than duplicated into this repository's local
`specs/`. Owner: HOC. The remaining dead targets are the ones already tabulated
in [[SPEC-002-visual-key-fingerprint]].

---

## Experiment findings

Five runs of a throwaway `android-spike` workflow, per [[PROTO-001]]'s
experiment-vs-specify rule: novelty and data-certainty were both High —
Selfsame had never been built for Android, and Tauri publishes **no Android CI
recipe** (its example pipeline is desktop-only and `tauri-action` does not build
Android at all). Its prerequisites tell a human to point `JAVA_HOME` at Android
Studio's bundled JBR, which no runner has.

Findings were returned through **commit statuses**, because this Forgejo
exposes no log endpoint — the same constraint that already makes `ci.yml` post
its first error into one.

| # | Question | Answer |
|---|---|---|
| 1 | Does an Android toolchain install on this runner? | **Yes.** No `sudo`, `apt-get` or disk problems. ~20 min cold, essentially all SDK + NDK download. |
| 2 | Does `tauri android init --ci` work headless? | **Yes — 8 seconds.** The `--ci` flag reads the `CI` env var. Requires **both** `ANDROID_HOME` and `NDK_HOME`; fails cleanly and writes nothing without them. |
| 3 | What does the app actually ask the OS for? | See [[SPEC-003-android-apk-distribution#OBS-202]]. |
| 4 | Does an APK come out? | **Not at 3 GiB** — see [[SPEC-003-android-apk-distribution#OBS-201]], since resolved. At 8 GiB, yes. |
| 5 | Cold run cost? | ~20 min, dominated by the NDK download. Cached thereafter. |

### OBS-201: The runner capped job containers at 3 GiB — RESOLVED

**Resolved 2026-07-30** by raising the limit to 8 GiB. The next run built and
published successfully in 20m02s with Gradle at a 2 GB heap and
`CARGO_BUILD_JOBS=4`. The record below is kept because the measurement is what
justified the change, and because it documents an alternative that was tested
and rejected.


```
mem:        15Gi total, 14Gi available
cgroup-max: 3221225472        ← 3 GiB
cpus:       8
```

Every build attempt died with Gradle's `Gradle build daemon disappeared
unexpectedly (it may have been killed or may have crashed)`. That message is an
OOM kill in polite clothing.

The cause is structural, not incidental: a Tauri Android build runs
`cargo build --target aarch64-linux-android` **inside** a Gradle task, so
`rustc` and the JVM are resident simultaneously. rustc alone takes 1–2 GB on
this workspace. Bounding Gradle to a 2 GB heap, 512 MB metaspace, no daemon and
no parallelism (run 3) did not help, because the sum still exceeds 3 GiB.

**Resolution, applied:** the runner's container memory limit was raised to
8 GiB (`container.options: "--memory=8g"` in `act_runner`). The next run built
and published.

Explicitly *not* the resolution: a prebuilt Android container image. An earlier
draft of this recommendation said it was, and that was wrong — a different
image does not change a cgroup memory cap.

#### The alternative, tested and rejected

The first four runs bounded Gradle's heap and workers but left **cargo's**
parallelism untouched. A Tauri Android build runs `cargo build` inside a Gradle
task, and cargo defaults to one rustc process per core; the runner reports 8.
Up to eight rustc processes in a 3 GiB container is a more plausible cause of
an OOM than Gradle's heap, and declaring an infrastructure blocker without
having tested it was premature.

Run 5 set `CARGO_BUILD_JOBS=1` and dropped the Gradle heap to 1 GB. It **still
died the same way**, with no APK.

The evidence that the change took effect is the wall-clock: **55m08s against
~25–30m for every previous run.** That near-doubling is what serialising rustc
looks like. So the build was genuinely compiling one crate at a time, in a 1 GB
JVM, and 3 GiB was still not enough.

This is why the memory ask is stated as a conclusion rather than a guess: the
cheaper explanation was tested first and did not hold.

### OBS-202: The shipped manifest declares `DUMP`

Gradle merges each dependency's manifest at build time. The manifest `init`
writes declares only `INTERNET`; the **merged** manifest, at
`app/build/intermediates/merged_manifest/universalDebug/…`, declares:

```
ACCESS_NETWORK_STATE, BIND_JOB_SERVICE, CAMERA, DUMP,
INTERNET, USE_BIOMETRIC, USE_FINGERPRINT, VIBRATE
```

Two things follow.

**Good news:** `CAMERA` and `USE_BIOMETRIC`/`USE_FINGERPRINT` do reach the app,
so the QR scanner and the presence check are genuinely wired up. `app.js`
branches on `window.__TAURI__.barcodeScanner` to choose the scan-or-type route,
and that branch will resolve correctly on device.

**Concern:** `android.permission.DUMP` is a signature-level permission for
reading system service state, and it arrives from a transitive Gradle
dependency in a root-key custodian. Nobody chose it. Neither Tauri's own
`mobile/android` manifest nor any vendored Rust crate declares it, so it comes
from an AAR.

**Attribution attempted and not obtained.** Run 4 added extraction of Gradle's
manifest-merger report, which names the contributing library for every merged
element. The report was located, but the extraction returned
`not attributed in report` — the pattern searched for a bare
`group:artifact:version` coordinate, while the merger writes attributions as:

```
uses-permission#android.permission.DUMP
ADDED from [androidx.some:library:1.2.3] /path/AndroidManifest.xml:24:5-79
```

The coordinate is inside square brackets, on an `ADDED from` line.

Run 5 tried exactly that — `ADDED from \[([^]]+)\]` across four lines of
context, with a bare `\[[^]]+\]` fallback — and returned
`not attributed in report` again.

**Two guesses at this file's format have now failed, so stop guessing.** The
remaining possibilities are that the located file is not the merger report (the
`find` matches `*outputs/logs*/manifest-merger-*-report.txt`, which may resolve
to a different variant), that the permission appears without an `ADDED from`
attribution, or that the context window is too narrow. Distinguishing them
requires *looking at the file*, which no amount of pattern-guessing from here
substitutes for — and each attempt costs a ~30–55 minute CI round-trip.

**To finish this without a CI run**, once a machine has the Android SDK:

```sh
cargo tauri android init --ci
cargo tauri android build --apk --debug -t aarch64      # or just far enough to merge
grep -A 3 'android.permission.DUMP' \
  src-tauri/gen/android/app/build/outputs/logs/manifest-merger-*-report.txt
```

Until then the permission is known to ship and its source is not known. That is
the honest state, and it is why this is an `OBS` with an owner rather than a
closed finding.

---

## Architecture decisions

### ADR-201: Debug-signed, loudly named

**Status:** accepted

The APK is built with `--debug`, using the standard debug keystore, and named
`selfsame-UNSIGNED-DEV-<shortsha>.apk`.

**Rationale.** Minting a release signing identity for an application whose
Tier-1 security gate is explicitly unpassed — the README says *"Do not put an
identity you rely on into this"* — creates a key that must then be protected
forever, for an artefact nobody should be relying on. The filename carries the
warning that the signature otherwise would.

**Consequence, stated so it is not discovered later:** a debug-signed APK
**cannot be upgraded in place** by a later release-signed build. Whoever
sideloads this will have to uninstall before moving to a real build, losing
local state. That is acceptable for a pre-production artefact and would not be
for a shipping one.

Note the default for `tauri android build` is **release**, which would demand a
signing config. `--debug` is load-bearing, not a convenience.

### ADR-202: arm64 only

**Status:** accepted

Build `-t aarch64` rather than all four ABIs. Four ABIs quadruple an already
25-minute build for a sideloaded development artefact, and every device worth
testing on is arm64. Revisit only if a REQ demands x86 emulator support.

### ADR-203: The permission allowlist reads the merged manifest

**Status:** accepted

A committed allowlist of permissions the app may declare, checked in CI. The
check MUST read the **merged** manifest, not the one `init` writes.

**Rationale.** This is the correction the experiment forced. The original design
checked the post-`init` manifest, which declares only `INTERNET` — so the check
would have passed trivially on every run and never seen `CAMERA`,
`USE_BIOMETRIC`, or `DUMP`. A guard that reads the wrong file is worse than no
guard: it reports safety it never established.

The merged manifest only exists after a build reaches the merge task, so the
check runs post-build, not post-init.

### ADR-204: `gen/android` stays generated, not committed

**Status:** accepted

`src-tauri/gen/` remains gitignored; CI runs `tauri android init --ci` each
build.

**Rationale.** Committing the Gradle project would put the manifest under review
— genuinely desirable — but requires an Android SDK and NDK on a maintainer's
machine before anything can be committed at all, which is the setup cost this
work exists to avoid. [[SPEC-003-android-apk-distribution#ADR-203]] recovers the
reviewability that matters: the permissions are guarded whether or not the
project is committed.

**Trade-off, recorded honestly:** the Gradle project is regenerated by whatever
Tauri CLI version CI resolves, so a CLI bump can change the build without a
commit to this repository. The allowlist catches permission changes; it does not
catch everything.

---

## Requirements (drafted, unverifiable until OBS-201 is resolved)

### REQ-201: An APK is published for every push to main

The system SHALL build a debug-signed arm64 APK on every push to `main` and
upload it to the `anuna-files` R2 bucket under `selfsame/`, WITHIN the runner's
job timeout.

### REQ-202: Each build is retrievable by commit, and `latest` moves

The system SHALL publish each APK at an immutable per-commit key and SHALL
additionally update a moving `latest` pointer, mirroring the existing
`files.anuna.io/<tool>/latest/…` convention.

```
anuna-files/selfsame/selfsame-UNSIGNED-DEV-<shortsha>.apk
anuna-files/selfsame/latest/selfsame-UNSIGNED-DEV.apk
```

### REQ-203: An unexpected permission fails the build

The system SHALL compare the merged manifest's declared permissions against a
committed allowlist and SHALL fail the job on any permission not on it.

### NFR-201: The job does not gate the existing checks

The Android job SHALL NOT block or slow the `rust` and `screens` jobs, which
report in ~5 and ~2 minutes respectively against this job's ~25.

---

## Contracts

### CON-201: The R2 upload

Cloudflare R2 via its S3-compatible API.

```
endpoint : https://<R2_ACCOUNT_ID>.r2.cloudflarestorage.com
bucket   : anuna-files
prefix   : selfsame/
secrets  : R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY
```

**Still required before implementation:** the account ID, confirmation of the
bucket name, and the key pair added to the repository's Forgejo secrets. None of
these are known to this document.

**Error model:** an upload failure fails the job. A built-but-unpublished APK is
indistinguishable from no APK to anyone downstream, so it MUST NOT be reported
as success.

---

## OBS-203: The APK is 208 MB — measured, and stripped

**Cause measured 2026-08-03. Fix applied. Not yet confirmed by a run.**

The first record of this said an unstripped native library was "the obvious
suspect". It was the right suspect, and a suspect is not a measurement. This
is the measurement.

### What is actually in the APK

`208,453,025` bytes as published. Its ZIP central directory apportions them:

| Entry | Bytes | Stored as |
|---|---|---|
| `lib/arm64-v8a/libselfsame_lib.so` | 199.33 MB | **uncompressed** |
| `classes*.dex` (9 files) | 8.04 MB | deflated |
| `resources.arsc` | 1.27 MB | uncompressed |
| everything else (1,000 entries) | ~0.35 MB | mixed |

So the question is not "what is in the APK". One file is **95.6%** of it.

### What is in that file

Reading the ELF section header table of the `.so` — possible without
downloading it, because it is stored uncompressed and so can be range-read in
place:

| Section | Bytes | |
|---|---|---|
| `.debug_info` | 66.79 MB | debug |
| `.debug_str` | 65.49 MB | debug |
| `.debug_line` | 14.56 MB | debug |
| `.debug_ranges` | 9.43 MB | debug |
| `.debug_loc` | 2.37 MB | debug |
| `.debug_aranges` | 2.23 MB | debug |
| `.debug_abbrev` | 0.92 MB | debug |
| `.strtab` | 12.02 MB | symbols |
| `.symtab` | 5.46 MB | symbols |
| **`.text`** | **13.00 MB** | *the program* |
| `.eh_frame` | 2.48 MB | |
| `.rodata` | 1.34 MB | |
| `.gcc_except_table` | 1.03 MB | |
| remainder | ~2.7 MB | |

`161.8 MB` of DWARF and `17.5 MB` of symbol table against `13 MB` of code.
**90% of the library, and 86% of the APK, is debug information.** The
10–20 MB figure this observation originally guessed at was close: the program
is 13 MB of `.text`.

### How it was measured

Two HTTP range requests against the published artefact — the last 1 MiB for the
ZIP central directory, then the ELF section headers from inside the stored
`.so`. No 208 MB download and no local Android toolchain, which matters because
the alternative is a ~20-minute CI round-trip per question
([[SPEC-003-android-apk-distribution#OBS-202]] is still open for want of
exactly that). Anyone can re-run it against any published build.

### The fix

`CARGO_PROFILE_DEV_STRIP: debuginfo` in the job environment.

Of the two routes the original entry proposed, this is neither, and it is
smaller than both. Stripping in the Gradle packaging step means reaching into a
generated project that [[SPEC-003-android-apk-distribution#ADR-204]]
deliberately does not commit. Building the release profile and signing it with
the debug keystore changes what
[[SPEC-003-android-apk-distribution#ADR-201]] means by `--debug`, which is
load-bearing for the signing config. Setting the profile key by environment
variable leaves both decisions untouched: same profile, same keystore, same
`--debug` invocation, and the linker simply does not emit the DWARF.

`debuginfo` and not `symbols`, matching the workspace's own `[profile.release]`.
That leaves the 17.5 MB symbol table in place, which is what makes a native
backtrace name functions rather than addresses — worth more on a build whose
entire purpose is to be sideloaded and broken than the 17.5 MB is.

It is set in the workflow rather than in `[profile.dev]` because it is a
property of the *published artefact*, not of the profile. A maintainer's local
`cargo build` keeps full debug information and stays debuggable.

**Predicted: ~47 MB**, a 4.4× reduction. Stated as a prediction because no run
has produced one yet. [[SPEC-003-android-apk-distribution#OBS-203]] closes when
a run does, and not before.

### The guard

`CARGO_PROFILE_DEV_STRIP` is an environment variable consumed by a `cargo` that
Gradle invokes on our behalf, three processes below the shell that sets it, and
under a profile name Tauri chooses. If a CLI bump ever builds under a different
profile, the variable silently stops applying — the same class of failure as the
allowlist reading the wrong manifest
([[SPEC-003-android-apk-distribution#ADR-203]]): a control that reports a
property it no longer establishes.

So the job now fails above a **100 MiB** ceiling. That is not a growth budget
and it is not an NFR — stripped is ~47 MB and unstripped was 208 MB, nothing in
between is reachable by ordinary growth, and the only thing 100 MiB can detect
is the debug information returning. It is deliberately *not* numbered as a new
artefact: the 2xx band already carries a genuine collision between this document
and [[SPEC-004-application-scoped-identity]], recorded in
[[SPEC-005-sskr-sharded-recovery#Artefact numbering]], and a regression check
belonging to a resolved `OBS` does not need to deepen it.

The check runs **after** the upload, unlike the permission allowlist, which runs
before. An over-permissioned APK is worse than no APK; a large one is merely
large. Failing first would cost the artefact as well as the run.

### Two further levers, deliberately not pulled

**`.text` is 13 MB at `opt-level = 0`.** Release-grade codegen would remove
several more MB. Not taken: `[profile.release]` here is `lto = true` with
`codegen-units = 1`, which are precisely the memory-hungry settings, and this
job has a documented OOM history
([[SPEC-003-android-apk-distribution#OBS-201]]) that was resolved by raising
the container to 8 GiB rather than by having room to spare. That trade wants
measuring before it is made, and the 4.4× is already banked without it.

**`android.useLegacyPackaging=true`** would deflate the `.so` inside the APK
instead of storing it, worth roughly 2.5–3× on the download. Not taken: it
trades download size for *installed* size, because Android then extracts the
library to `/data` rather than mapping it from the APK, and install gets slower.
The complaint that prompted this was the download, but the trade is real and
belongs to whoever owns the on-device experience rather than to a size fix.

Owner: HOC.

---

## BUG-201: the published APK could never create a home key

**Found 2026-08-03, on the first attempt to use a published build. Cause
measured, fix applied, not yet confirmed on a device.**

The section below this one says, of the 2026-07-30 verification: *"What is
verified is that an APK builds and publishes. Not that the application works on
a phone. Nobody has installed it."* Somebody did. It does not.

Entering a passcode on the first-run screen returns **"no identity on this
device"** — under the passcode field, where a validation message goes. It is
not intermittent and it is not device-specific: it fails on every attempt, on
every Android build published to date.

### What is actually wrong

[[Keyring]] selects its credential store by `cfg`, and its final arm is:

```rust
#[cfg(not(any(
    target_os = "linux",   target_os = "freebsd", target_os = "openbsd",
    target_os = "macos",   target_os = "ios",     target_os = "windows",
)))]
pub use mock as default;
```

`target_os = "android"` matches none of those names, so an Android build links
the crate's **mock** store — the one it ships for testing, whose own
documentation reads *"no persistence other than in the entry itself, so getting
a password before setting it will always result in a `NoEntry` error."* No
feature flag fixes this. `keyring` 3 has no Android backend to enable, and the
three this workspace requested — `apple-native`, `windows-native`,
`sync-secret-service` — are the stores for three platforms this is not.

`custody.rs` constructs a fresh `keyring::Entry` for every read and every write,
which is correct against a real keystore and fatal against that one. So:

| Step | Expected | What happened |
|---|---|---|
| `Custody::create` seals the root, calls `set_password` | stored | mock returns `Ok(())`, credential dropped |
| `create_identity` calls `Custody::root_public_key` | the key | fresh mock → `NoEntry` → `Ok(None)` |
| `.ok_or(CustodyError::NoIdentity)` | — | **"no identity on this device"** |

The write was not rejected. It was *accepted and discarded*, and the failure
surfaced one call later at a function whose name suggests reading was the
problem. `Custody::exists` answers `false` forever for the same reason, so the
`AlreadyExists` guard never fires either: every retry derived fresh entropy,
sealed it, and threw it away again.

### Why nothing caught it

Three things had to line up, and they are worth naming separately because each
is a different lesson:

1. **The tests run on the host.** `cargo test` on macOS or a CI runner links
   `apple-native` or `sync-secret-service`, both real stores. Every custody test
   passed, and would have passed no matter how broken Android was, because the
   defect is selected by a `cfg` no host test evaluates.
2. **The mock fails by agreeing.** A store that returned an error would have
   been caught by the first person to run the app. This one returns `Ok(())`.
3. **`REQ-024` had no Android row.** `custody.rs` tabulated custody for
   macOS/iOS, Windows and Linux. [[SPEC-001-device-key-provisioning#ADR-002]]
   makes this a phone application and this specification publishes an Android
   APK, and the requirement governing the root key did not mention the platform
   either of them targets. The missing backend is downstream of that gap, not of
   a coding slip.

**Root cause: `implementation-error/platform-assumption`** — a dependency's
platform support was assumed from the platforms it was configured for, rather
than verified against the platform it was shipped to. New subtype; the existing
taxonomy had no entry for "the dependency compiled, and compiled to nothing".

### The fix

Two changes, and the second matters more than the first.

**A real store.** `crates/tauri-plugin-selfsame-store` is a Tauri Android plugin
holding the record under an AES-256-GCM key in [[AndroidKeyStore]] — StrongBox
where the device has it, TEE otherwise — with the ciphertext in app-private
`SharedPreferences`. That is rung 3 of [[PROTO-001]]'s Simplicity Ladder, the
native platform feature, and it satisfies `REQ-024`'s *"wrapped by a
hardware-protected key where the platform provides one"* on the platform that
provides one. The value it receives is **already** sealed under an Argon2id key
derived from the user's passcode, so the Keystore wrap is the second layer
rather than the only one.

The plugin declares **no commands**, so no capability can grant JavaScript
access to the sealed root; `Custody` reaches it from Rust through
`run_mobile_plugin`. `AndroidManifest.xml` adds no permissions, which keeps
[[SPEC-003-android-apk-distribution#REQ-203]]'s allowlist unchanged.

**A guard that does not depend on knowing this could happen.** `store::init`
writes a probe value to whatever backend the build linked, reads it back,
removes it, and fails Tauri's setup if the value did not survive. The
application does not start.

That severity is deliberate. A custodian whose storage silently discards writes
is worse than one that refuses to launch: the first loses identities and blames
the user, the second says what is wrong while nothing is yet at stake. And the
check is a round trip rather than an inspection of
`CredentialPersistence` — asking a backend to describe its own durability only
catches the backends that answer honestly, and only the ones somebody thought
to ask. Writing a value and looking for it catches any store that does not keep
what it is given, including ones that do not exist yet.

**The guard's first version was too broad, and CI caught it.** It treated any
unhappy probe as a refusal to start, including a store that returned an
*error*. On a headless runner that is the normal case — with no session bus,
Secret Service answers *"Unable to autolaunch a dbus-daemon without a
$DISPLAY"* — so the `rust` job went red on the very check meant to prevent a
silent failure. A locked desktop keyring would have done the same to a user.

The distinction the second version draws is the one that matters. A store that
**errors** is *unavailable*, and that was never the invisible failure: `keyring`
has always returned those errors and they have always surfaced where storage is
used, naming storage. A store that takes the write, reports `Ok(())`, and does
not have it is *lying*, and nothing anywhere raises an error — which is exactly
what shipped. Only the second refuses to start.

That split also made the check environment-independent to test: the decision is
a pure function of what the probe observed, so its cases are enumerated in unit
tests that say the same thing on a laptop and on a bare runner, and the I/O half
is covered end to end by the mock-store regression test.

### What is verified, and what is not

`src-tauri/tests/android_custody.rs` installs the identical mock store the
Android target compiled in, and asserts that the guard now refuses it and that
its message names storage rather than the user's identity. It passes, and it
needs no device.

**The Keystore plugin itself is unverified.** No emulator or device has run it;
`ANDROID_HOME` and `NDK_HOME` are unset on the machine that wrote it. CI
compiles the Kotlin as part of the APK build, so a syntax or Gradle error will
surface on the next run — but "it compiles" and "it stores a key" are different
claims and only the first will have evidence. This entry closes when someone
sideloads a build and creates a home key, and not before.

Owner: HOC.

---

## Status

`implemented`. The pipeline runs on every push to `main`
(`.forgejo/workflows/android.yml`) and publishes to
`anuna-files/selfsame/`.

Verified end to end on 2026-07-30: build 20m02s, both the flat pointer and the
per-commit copy return HTTP 200 with matching etags, and the permission
allowlist matched the merged manifest exactly.

**What is verified is that an APK builds and publishes. Not that the
application works on a phone.** The merged manifest shows `CAMERA` and
`USE_BIOMETRIC` reach the app, which means the scanner and presence-check
plugins are wired — not that they function on a device. Those are different
claims and only the first has evidence.

That distinction stopped being hypothetical on 2026-08-03, when somebody
installed one: it could not create a home key at all
([[SPEC-003-android-apk-distribution#BUG-201]]). The paragraph above was
written as a caveat and turned out to be a prediction.

The experiment workflow that produced the findings above has been deleted, as
an experiment should be. Its history is on pull requests #4 and #6.

---

## Changelog

<details>
<summary>Revision history — 1.2.0</summary>

- 1.2.0 — [[SPEC-003-android-apk-distribution#BUG-201]]: the published APK could
  never create a home key, because `keyring` has no Android backend and falls
  through to its testing mock. Keystore-backed store added
  (`crates/tauri-plugin-selfsame-store`), plus a startup durability guard that
  round-trips a probe value and refuses to start if it does not survive. New
  root-cause subtype `implementation-error/platform-assumption`. No requirement,
  contract, or decision of this specification changed — the defect belongs to
  [[SPEC-001-device-key-provisioning#REQ-024]] and is recorded here because this
  is the specification that publishes the artefact it broke.
- 1.1.0 — [[SPEC-003-android-apk-distribution#OBS-203]] measured rather than
  suspected: 90% of the shipped `.so` is DWARF. `CARGO_PROFILE_DEV_STRIP` set
  in the job, plus a 100 MiB ceiling that fails the run if it stops applying.
  No requirement, contract, or decision changed.
- 0.1.0 — findings from four spike runs converted to specification. Blocked on
  a 3 GiB runner container cap.
</details>
