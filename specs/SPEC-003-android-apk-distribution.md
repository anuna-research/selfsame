---
id: SPEC-003
title: Android APK Build and Distribution
status: draft
version: 0.1.0
last-updated: 2026-07-29
---

# SPEC-003 — Android APK Build and Distribution

## Orientation

**Intent:** Build an Android APK on every push to `main` and publish it to the
`anuna-files` [[Cloudflare R2]] bucket under `selfsame/`, so a phone build can
be sideloaded without anyone running a local Android toolchain.

**Status: blocked, not abandoned.** Everything needed to write this
specification has been measured rather than assumed — see
[[SPEC-003-android-apk-distribution#Experiment findings]] — and one
infrastructure change stands between the findings and a working pipeline.

**Metaphor:** *a bakery with an oven too small for the tray.* Every ingredient
is on the bench, the recipe is written, and the tray does not fit. Nothing is
wrong with the recipe.

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
  │     --debug -t aarch64      ← ✗ OOM TODAY │
  │   ▸ merged-manifest permission allowlist  │
  └────────────────────┬──────────────────────┘
                       │ selfsame-UNSIGNED-DEV-<sha>.apk
                       ▼
        ┌──────────────────────────────┐
        │ anuna-files (Cloudflare R2)  │
        │   selfsame/<sha>.apk         │
        │   selfsame/latest/…apk       │
        └──────────────────────────────┘
```

**Decisions:**
[[SPEC-003-android-apk-distribution#ADR-201]] debug-signed, loudly named ·
[[SPEC-003-android-apk-distribution#ADR-202]] arm64 only ·
[[SPEC-003-android-apk-distribution#ADR-203]] the allowlist reads the *merged*
manifest ·
[[SPEC-003-android-apk-distribution#ADR-204]] `gen/android` stays generated,
not committed

**Open:**
- **Blocking:** the runner caps job containers at 3 GiB
  ([[SPEC-003-android-apk-distribution#OBS-201]]). Owner: whoever administers
  the Forgejo runner.
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

This document adds one dead link, [[Cloudflare R2]], and defers it under the
same rule as the rest: vendor and tool pages are vault-wide vocabulary and
belong in the shared `anuna-ssi` vault rather than duplicated into this
repository's local `specs/`. Owner: HOC. The remaining dead targets are the
ones already tabulated in [[SPEC-002-visual-key-fingerprint]].

---

## Experiment findings

Four runs of a throwaway `android-spike` workflow, per [[PROTO-001]]'s
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
| 4 | Does an APK come out? | **No.** Blocked by [[SPEC-003-android-apk-distribution#OBS-201]] — not by configuration. |
| 5 | Cold run cost? | ~25–30 min per run, dominated by the NDK. |

### OBS-201: The runner caps job containers at 3 GiB

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

**Resolution:** raise the runner's container memory limit — in `act_runner`,
`container.options: "--memory=8g"` or equivalent. Then one spike run confirms.

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

## Status and what unblocks this

This specification is `draft` and **cannot proceed to implementation** until
[[SPEC-003-android-apk-distribution#OBS-201]] is resolved. That is one
configuration change on the runner host, which is outside this repository.

Everything else is ready: the toolchain steps are known to work, the manifest
contents are known, the signing and ABI decisions are made, and the upload
contract is specified but for three secrets.

The experiment workflow that produced these findings has been deleted, as an
experiment should be. Its history is on the `spike/android-apk` branch and in
pull request #4 should anyone want to re-run it.

---

## Changelog

<details>
<summary>Revision history — 0.1.0</summary>

- 0.1.0 — findings from four spike runs converted to specification. Blocked on
  a 3 GiB runner container cap.
</details>
