---
id: EXP-002
title: End-to-end linking harness — a governed spike before the specification
status: brief
tier: 3
audience: agent, human
author: Anuna Research (drafted with Claude, 2026-08-01)
last-updated: 2026-08-01
owner-repo: selfsame
governs: SPEC-001 device linking, verified against the real application
---

# EXP-002 — End-to-end linking harness

## Why this is an experiment and not a specification

[[PROTO-001-usdd-agent-protocol]]'s *Experiment vs Specify* decision table is
rated below. Two of the three factors it singles out — novelty, performance,
data — come out High, which routes this to experimentation first.

| Factor | Rating | Basis |
|---|---|---|
| Problem clarity | High | The ceremony, the two roles, and the environment are settled |
| Interface stability | Medium | `ar-crawl android` documents its own API as "experimental — some features may change" |
| **Technical novelty** | **High** | No one has attached `ar-crawl` to a [[Tauri]] Android [[WebView]]; `src-tauri/gen` has never been generated in this repository |
| **Data certainty** | **Low** | Unknown whether `ar-crawl android`'s `webviews` can see the Tauri view at all, and endpoint injection has three untried candidates |
| Performance risk | Low | A local harness; slowness is acceptable by construction |
| Safety / regulatory risk | Low | No production writes, no real identities, loopback only |
| Reversibility | High | A test harness, deletable without consequence |

The honest statement of the problem: **the contracts cannot be written yet.**
A `CON-###` declares an interface and, where it takes external input, a
grammar. The interface here is "what the harness can command the wallet to do",
and that is a function of what `ar-crawl android` can reach inside a Tauri
[[WebView]] — which is unmeasured. Specifying it first would be inventing a
contract and then discovering whether the world supports it.

## The gap this closes

Two harnesses exist and neither drives the real application against a real
counterparty:

- `crates/selfsame-rendezvous/tests/end_to_end.rs` runs the whole
  [[SPEC-001-device-key-provisioning]] loop over real HTTP against the real
  service, and says in its own header that *"the only thing simulated is the
  user tapping Authorise."* The application never runs.
- `tests/screens.mjs` drives the real user interface, but against a **stubbed**
  `window.__TAURI__` bridge. The backend never runs.

So the seam between the two — the real application's custody, keychain, session
and network code, exercised by a real person-shaped interaction — is covered by
nothing. That seam is where [[SPEC-003-android-apk]]'s build lands, and it is
the one place a defect reaches a person unmediated.

## Hypothesis

> A harness on one developer machine can drive the real Selfsame application in
> an Android emulator through the whole [[SPEC-001-device-key-provisioning]]
> linking ceremony against a real browser device client and a real rendezvous
> service, and assert that both parties agree on the resulting [[DID]] and its
> [[fingerprint]] — using `ar-crawl` as the sole driver for both roles.

Falsified if any of the exit criteria below cannot be met inside the timebox.

## Approach

Four processes on one machine. The two client roles are genuinely separate,
which is the topology [[SPEC-001-device-key-provisioning]] describes: a laptop
linking itself to the identity held on a phone.

```
  ┌──────────────────────── host ────────────────────────┐
  │  driver ──── stdin/JSON ────┐                         │
  │     │                       ▼                         │
  │     │              ar-crawl session                   │
  │     │              (host Chrome)                      │
  │     │                       │ drives                  │
  │     │                       ▼                         │
  │     │              web device + selfsame-core.wasm    │
  │     │                       │ HTTP                    │
  │     │                       ▼                         │
  │     │           selfsame-rendezvous (loopback)        │
  │     │                       ▲                         │
  │     └─ stdin/JSON ─┐        │ adb reverse             │
  │                    ▼        │                         │
  │         ar-crawl android session                      │
  └────────────────────┼────────┼─────────────────────────┘
                       ▼        │
           ┌─── emulator ───────┴────┐
           │  Selfsame APK (debug)   │
           │  real custody + keychain│
           └─────────────────────────┘

  arrows point toward the party being driven; the driver holds no secrets
```

The link code is minted fresh per run, so it must pass through the driver at
runtime: `ar-crawl`'s `commit`/`replay` cannot carry the whole ceremony. Replay
remains useful for sub-flows and screenshot regression, and that limit is itself
a finding to record rather than a defect to fix.

**Composition-first.** `ar-crawl` is rung 4 of the Simplicity Ladder — an
existing dependency of this toolchain, already installed, already the
skill-sanctioned driver. It replaces what would otherwise have been a
hand-rolled [[Chrome DevTools Protocol]] client: it drives native selectors
(`res=`, `text=`, `desc=`) *and* [[WebView]] contexts, passes [[ADB]] `shell`
through, and records and replays. The rejected alternative, [[Appium]], is a
new server plus driver plus capability configuration for a capability
`ar-crawl` already has.

## Isolation

Experiment Governance requires the blast radius be capped and stated:

- **No production writes.** The rendezvous service is a fresh loopback instance
  per run. No request leaves the machine.
- **No real identities.** Fixture keys only. The emulator is a disposable
  [[AVD]]; the harness may wipe application data between runs and nothing of
  value is lost.
- **No production code changed to suit the harness**, with one candidate
  exception recorded as a question below (endpoint injection). Any change that
  does prove necessary is a finding, is justified in its own right, and does not
  reach a release path.
- **Cost cap:** one Android SDK installation and one emulator image on one
  developer machine. Nothing is provisioned in CI, and nothing gates a merge —
  [[SPEC-003-android-apk#NFR-201]] forbids a slow Android job from blocking a
  fast one, and this harness is slower than the build it would sit behind.

## The three unknowns this spike exists to settle

**U1 — Can `ar-crawl android` drive the Tauri WebView's DOM?**
Its help says WebView automation needs Chrome 87+ on the device and lists a
`webviews` command, but a Tauri application's [[WebView]] is embedded in a
native activity rather than being Chrome. If the DOM is reachable, the harness
asserts against the same `data-action` hooks
[[IMPL-004-application-scoped-identity-screens]] already mandates on every
interactive element, and `tests/screens.mjs`'s selector discipline transfers
whole. If it is not, the harness falls back to native selectors and loses
DOM-level assertion, which is a materially weaker harness and must be recorded
as such.

**U2 — How does the application reach a loopback rendezvous?**
`src-tauri/src/net.rs:35` honours a `SELFSAME_ENDPOINT` environment variable,
but Android does not let a process environment be set casually. Three
candidates, to be tried in this order:

1. A [[Cargo feature]] on the debug build defaulting the endpoint to `http://10.0.2.2:8787`.
   Compile-time, explicit, cannot reach a release binary. Preferred because it
   is inspectable and reversible.
2. `setprop wrap.<package>` — Android's supported environment injection for
   debuggable applications. No source change, but version-sensitive.
3. DNS or hosts redirection, which needs a trusted [[TLS]] certificate inside
   the emulator. Heaviest; recorded for completeness and expected to be
   rejected.

**U3 — What does the presence check require?**
[[SPEC-001-device-key-provisioning#REQ-024]]'s presence check is biometric on
mobile, which is a native dialog rather than a DOM element. `adb emu finger
touch` is the expected answer and `ar-crawl`'s `shell` passthrough is the
expected route to it. Unverified.

## Metrics

Recorded per run, because a harness nobody will wait for is a harness nobody
runs:

- Wall-clock from `driver` start to assertion, cold and warm.
- Whether the run is deterministic across five consecutive executions.
- Lines of harness code, as a proxy for what there is to maintain.

## Exit criteria

The spike **succeeds** when all of these hold:

1. A debug APK builds from this repository and installs on an emulator.
2. `ar-crawl android session` attaches, and U1 is answered either way **with
   evidence** — a captured `webviews` response and a DOM assertion, or a
   recorded failure and the native-selector fallback demonstrated instead.
3. U2 is answered: the application performs a real linking request against the
   loopback rendezvous.
4. A full ceremony completes and both parties independently report the same
   [[DID]] and [[fingerprint]].
5. The two app-side refusals reach their screens: an invalid code renders
   `refused-code`, and an explicitly rejected offer leaves the device unlinked.

The spike **terminates unsuccessfully**, which is a legitimate outcome, if the
timebox expires or if U1 and U2 both resolve against the approach. In that case
the findings still convert — into a recorded [[ADR]] explaining why this seam
stays uncovered and what would have to change.

## Timebox

One working session. The Android SDK installation and first Tauri Android build
are the dominant cost and are largely unattended; if the spike is still
unresolved after that plus one hour of driving, it stops and reports.

## What converts to SDD assets afterwards

Per Experiment Governance, findings convert and the prototype is decommissioned.
Expected shape, reserved but not yet written:

- A `SPEC-###` for the harness's obligations, with the happy path and the two
  refusals as `REQ-###`, and the determinism metric as an `NFR-###`.
- A `CON-###` per driven surface — the wallet session and the web device
  session — each declaring the grammar of the commands it accepts, since both
  are trust boundaries in the [[LangSec]] sense even though both ends are ours.
- `TEST-###` entries derived from those requirements, including the
  prohibited-action form: the harness must assert the device is **not** linked
  after a rejected offer, not merely that a screen appeared.
- An `ADR-###` recording the `ar-crawl`-over-[[Appium]] choice and the endpoint
  injection mechanism actually adopted.

None of these are written yet, deliberately. They are what the spike is for.

## Open questions for the owner

- **Q1.** Does the endpoint injection candidate U2.1 — a debug-only [[Cargo
  feature]] — count as production code changed to suit a test? It is small and
  gated, but it is a source change made for a harness, and the isolation clause
  above says such changes are findings rather than conveniences.
- **Q2.** The web device client needs a wasm surface over
  [[selfsame-core]]. Placing it in a new crate keeps the core untouched and its
  `tests/purity.rs` guard intact; placing `#[wasm_bindgen]` in the core itself
  would be smaller but adds a dependency to the one crate whose dependency
  graph is asserted. The brief assumes a new crate. Confirm.

## Concept-page backlog (explicit deferral)

This brief introduces dead `[[wikilinks]]` and, per
[[PROTO-001-usdd-agent-protocol]], they are recorded rather than removed. Two
kinds, with different owners:

- **Documents in the `anuna-ssi` vault**, which is not checked out here:
  [[SPEC-001-device-key-provisioning]], [[SPEC-003-android-apk]],
  [[PROTO-001-usdd-agent-protocol]]. These resolve when the vaults are read
  together and are the same deferral
  [[IMPL-004-application-scoped-identity-screens]] already records. Owner: HOC.
- **Concept pages this repository could author**: [[WebView]], [[Tauri]],
  [[ADB]], [[AVD]], [[Appium]], [[Chrome DevTools Protocol]], [[Cargo feature]],
  [[TLS]], [[DID]], [[fingerprint]], [[LangSec]], [[selfsame-core]]. Deferred
  until the spike resolves, because a spike that fails takes most of them with
  it and authoring them first would be writing definitions for a design that may
  not survive contact. Owner: whoever converts these findings to SDD assets.
