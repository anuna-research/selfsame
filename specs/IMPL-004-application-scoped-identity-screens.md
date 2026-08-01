---
id: IMPL-004
title: Application- and Account-Scoped Identity — the person-facing surface
status: implemented
tier: 2
version: 0.3.0
audience: agent, human, frontend implementer
author: Anuna Research (drafted with Claude, 2026-08-01)
last-updated: 2026-08-01
owner-repo: selfsame
affects-repos: selfsame, anuna-ssi
implements: SPEC-004-application-scoped-identity
review-gate: not-approved — plan awaiting adversarial review per Constitutional Principle 12
depends-on: SPEC-004 (draft, Tier-1 gate open); SPEC-002 visual key fingerprint; Tauri v2; WCAG 2.2 AA
---

# IMPL-004 — Application- and Account-Scoped Identity: the person-facing surface

## Orientation

**Intent.** [[SPEC-004-application-scoped-identity]] has no screens. Twenty-six
contracts are implemented and the only thing that walks them end to end is a
CLI. This plan adds the surface a person actually touches, and adds nothing to
the specification: every screen presents an obligation SPEC-004 already carries.

**Metaphor.** *Devices are how you reach your identity; applications are what it
does.* The wallet already shows the first list. This adds the second, beside it,
under one identity — not a second wallet, not a second account system.

**Structure.**

```
                   ┌─────────────────────────────┐
                   │  index.html   11 sections   │  markup, one document
                   └──────────────┬──────────────┘
                                  │
              ┌───────────────────┴───────────────────┐
              │                                       │
    ┌─────────▼─────────┐                 ┌───────────▼───────────┐
    │  app.js           │  exports        │  app-identity.js      │
    │  SPEC-001 screens │ ──────────────▶ │  SPEC-004 screens     │
    └─────────┬─────────┘                 └───────────┬───────────┘
              │                                       │
              └──────────────────┬────────────────────┘
                                 │  invoke()  ← trust boundary
                   ┌─────────────▼──────────────┐
                   │  src-tauri  CON-601..603   │  recognise, then act
                   └─────────────┬──────────────┘
                                 │
                   ┌─────────────▼──────────────┐
                   │  selfsame-app-identity     │  pure core
                   │  selfsame-core             │  decides everything
                   └────────────────────────────┘

Dependencies point inward. No screen decides anything.
```

**Decisions.**

- [[IMPL-004-application-scoped-identity-screens#ADR-601]] — split the frontend
  along the specification boundary, not by concern.
- [[IMPL-004-application-scoped-identity-screens#ADR-602]] — wire the two pure
  commands; stub home-DID derivation rather than change custody.
- [[IMPL-004-application-scoped-identity-screens#ADR-603]] — consent reuses the
  existing verified-vs-claimed row treatment rather than inventing a hierarchy.

**Load-bearing.**

- [[SPEC-004-application-scoped-identity#REQ-222]] — the wallet authenticates
  the requesting application; a name, icon, or TLS connection is not evidence.
- [[SPEC-004-application-scoped-identity#REQ-217]] — `AccountScopeUnavailable`
  forbids guessing and forbids prompting.
- [[SPEC-004-application-scoped-identity#REQ-230]] — no skip may be offered for
  first-enrollment confirmation.
- [[SPEC-004-application-scoped-identity#CON-210]] — revocation reports pending
  until a verified closure carries the grant ID.
- [[SPEC-002-visual-key-fingerprint#NFR-104]] — the comparison screen paints
  within 400 ms.

**Controls.** Exhaustive. Each is a hard stop this surface MUST NOT soften.

- No screen decides anything — every value and refusal arrives from Rust.
  ([[IMPL-004-application-scoped-identity-screens#ADR-601]])
- `scope-unavailable` SHALL offer no remedial action.
  ([[SPEC-004-application-scoped-identity#REQ-217]])
- `fingerprint-compare` SHALL offer no skip.
  ([[SPEC-004-application-scoped-identity#REQ-230]])
- `remove-pending` SHALL NOT report success before a verified closure.
  ([[SPEC-004-application-scoped-identity#CON-210]])
- `consent-application` SHALL render the application's own name under the
  untrusted treatment. ([[SPEC-004-application-scoped-identity#REQ-222]])
- `binding-mismatch` SHALL show the claimed identity under the untrusted
  treatment and offer no retry.
  ([[SPEC-004-application-scoped-identity#CON-222]],
  [[SPEC-004-application-scoped-identity#REQ-225]])
- No screen SHALL render an `accountScopeId`.
  ([[SPEC-004-application-scoped-identity#NFR-203]])
- Refusal screens SHALL render one closed token and no further detail.
  ([[SPEC-004-application-scoped-identity#CON-226]])

**Open.**

- `SCREEN-003`…`SCREEN-015` cannot be authored in this repository. Deferred to
  the `anuna-ssi` vault. Owner: HOC. See
  [[IMPL-004-application-scoped-identity-screens#Concept-page backlog (explicit deferral)]].
- Home-DID derivation is stubbed; the custody gap is `FINDING-016`. Owner: HOC.
- Permission rendering for unrecognised permission URIs is specified as
  fail-visible, not fail-friendly. Owner: HOC.

**Detail.** [[IMPL-004-application-scoped-identity-screens#Screen inventory]] ·
[[IMPL-004-application-scoped-identity-screens#Contracts]] ·
[[IMPL-004-application-scoped-identity-screens#Purity Boundary Map]] ·
[[IMPL-004-application-scoped-identity-screens#Test specifications]]

---

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in
all capitals.

---

## Context

The seventeen screens the wallet ships are [[SPEC-001-device-key-provisioning]]:
one identity, many devices. SPEC-004 is a different shape — one identity serving
many applications, each with its own account, home DID, `acct:` alias, and
devices — and none of it is visible to a person.

The gap is not cosmetic, and the review of the SPEC-004 prototype produced two
proofs of it:

- `android_select` returned `UnverifiedWalletTarget` when no wallet was
  installed, so an ordinary device with no wallet rendered as a *failed security
  check*. [[SPEC-004-application-scoped-identity#CON-222]] requires
  `WalletUnavailable` and an install action. The outcomes are now distinct, and
  nothing in **this** repository consumes the distinction — nor should it. That
  outcome belongs to the developer application's adapter, and the surface it
  needs is the SDK's, not the wallet's. See Out of scope.
- `Handoff::binds_to` validates a return URI against the authenticated platform
  binding, per [[SPEC-004-application-scoped-identity#CON-215]]. It has no
  caller.

Both are correct and unreachable. A contract with no surface is a contract
nobody has walked.

### Scope of this plan

This plan introduces **no `REQ-###`**. Every screen presents an obligation
already carried by SPEC-004, and every behaviour traces to an existing
requirement. That is deliberate and it is what keeps this document clear of
[[SPEC-004-application-scoped-identity#Amendment Channels]]: a screen that
needed a new requirement would be a specification change wearing a plan's
clothes, and several of these screens touch Tier-1 amendment territory
(first-enrollment confirmation, same-device dispatch, mobile caller identity).

New artefacts are allocated in the **6xx band**, which is unused across every
prefix in this vault. Bands 0xx–5xx are taken by SPEC-001, SPEC-002/003,
SPEC-004, [[PROTO-002-selfsame-rendezvous-v1]],
[[PROTO-003-selfsame-pairing-v1]], and
[[PROTO-004-selfsame-ceremony-envelope-v1]] respectively.

### What HP-1 and HP-2 do not need

[[person-happy-paths]] specifies seven paths. Two are absent from this plan by
design: `HP-1` (add a second application) and `HP-2` (switch accounts) are
specified as having **no person-visible step at all** — "this is the path where
the promise is kept by there being no ceremony." Building screens for them would
be building the thing the specification is proud not to need, and is Simplicity
Ladder rung 1 applied correctly.

---

## Concept-page backlog (explicit deferral)

Per the [[SPEC-002-visual-key-fingerprint#Concept-page backlog (explicit deferral)]]
precedent, dead links are visible backlog and are **not** to be deleted to clean
the report.

| Target | Disposition |
|---|---|
| `SCREEN-003` … `SCREEN-015` | **Cannot be authored here.** [[SCREEN-001-authorise-a-device]] and [[SCREEN-002-device-client]] live in the `anuna-ssi` vault, which is not checked out in this working copy. The `SCREEN-###` sequence is therefore unverifiable here, and minting thirteen IDs against it would guarantee the collision SPEC-002 already refused. This document carries the per-screen detail in the interim. Resolves when `anuna-ssi` is present. Owner: HOC. |
| [[SPEC-001-device-key-provisioning]], [[PROTO-001]] | Same vault, same disposition. Already recorded in SPEC-002's table; cited here because this plan depends on both. Owner: HOC. |
| [[Tauri]], [[LangSec]], [[WCAG 2.2]] | **Deferred to the shared vault.** Tool, discipline, and standard pages are vault-wide vocabulary cited across Anuna projects; per Constitutional Principle 15 they belong in the layer all of them can reach, not duplicated into one repository. Owner: HOC. |

The gate this plan holds itself to is **no new dead links beyond this table**.
Baseline at authoring: 66 dead links, 0 orphans, 0 syntax errors.

---

## Architecture decisions

### ADR-601: Split the frontend along the specification boundary

**Status.** PROPOSED.

**Context.** `src/app.js` is 750 lines and `src/index.html` 449. Thirteen
screens with their render and sequence logic add roughly 420 and 350
respectively. Markup cannot split — the screen harness serves one document — so
the only question is where the logic lives.

**Decision.** `app.js` retains SPEC-001 and gains exports for the shared
primitives (`show`, `invoke`, `fail`, `busy`, `idle`, `clearErrors`,
`lifehashElement`, `since`). A new `src/app-identity.js` holds the SPEC-004
screens and imports them.

**Rationale.** Not line count. The boundary already exists everywhere else in
this repository — `selfsame-core`, `selfsame-app-identity`, and
`selfsame-app-identity-net` are separate crates, and `tests/purity.rs` fails the
build if a network-capable crate enters the core's graph. The frontend would be
the only place where the two specifications interleave with no boundary at all.

It also bounds the blast radius of an open gate: SPEC-004's review gate is
`not-approved`. If it closes differently, this surface is one file and one
import line.

**Alternatives rejected.**

- *Extend in place.* Simplest diff, but produces a 1,250-line file in which two
  specifications' logic interleaves with no boundary. Rejected on Principle 1.
- *Full concern-split* (`bridge.js`, `screens.js`, `lifehash.js`, `spec001.js`,
  `spec004.js`). Better long-term shape, but rewrites working SPEC-001 code that
  nothing in this plan requires touching — Simplicity Ladder rung 5 exceeded for
  no accepted requirement.

**Consequences.** `app.js` gains its first exports. A shared primitive that
drifts breaks both surfaces at once, which is the intended coupling: they are
one wallet.

**Ladder rung.** 5 — minimum new code. One new module, no new abstraction.

Implements: [[SPEC-004-application-scoped-identity#REQ-222]]

---

### ADR-602: Wire the two pure commands; stub home-DID derivation

**Status.** PROPOSED.

**Context.** The plan calls for three commands. Two are pure functions over
strings. The third cannot be wired at all.

SPEC-004's hierarchy roots at the BIP-39 seed:

```rust
// crates/selfsame-app-identity/src/hierarchy.rs:176
pub fn recovery_seed(mnemonic: &Mnemonic) -> RecoverySeed {
    Zeroizing::new(mnemonic.to_seed_normalized(""))
}
```

SPEC-001's custody stores something else and says so explicitly — *"The phrase
is not stored"* (`src-tauri/src/custody.rs:206`). What it seals under the
passcode is `derive::root_seed(mnemonic, PERSONA_ZERO)`, a one-way KDF output
from which the BIP-39 seed is not recoverable.

**Decision.** `src-tauri` links `selfsame-app-identity` and exposes
[[IMPL-004-application-scoped-identity-screens#CON-601]] and
[[IMPL-004-application-scoped-identity-screens#CON-602]] against real core
functions. [[IMPL-004-application-scoped-identity-screens#CON-603]] returns a
fixture home DID this cycle. Every alias and fingerprint rendered is a genuine
computation over that DID; only its provenance is fixture.

**Alternatives rejected.**

- *Store the BIP-39 seed alongside the root seed.* A custody format change
  requiring migration for existing identities, and it widens what a passcode
  compromise yields. That is a security decision and it does not belong inside a
  presentation change.
- *Prompt for the recovery phrase.* [[person-happy-paths#HP-3]]'s precondition
  is only "signed into A1". Requiring the phrase to read your own alias
  contradicts the happy path and returns the phrase to memory to display a name.

**Consequences.** The custody gap is recorded as `FINDING-016` in
[[EXP-001-findings]] as part of this work — documented, not resolved. Screens
depending on a *real* derived DID cannot be integration-tested against custody
until it closes.

**Ladder rung.** 1 for the stub — the capability does not need to exist yet to
satisfy any accepted requirement of this plan.

Implements: [[SPEC-004-application-scoped-identity#REQ-213]],
[[SPEC-004-application-scoped-identity#CON-212]]

---

### ADR-603: Consent reuses the existing verified-vs-claimed row treatment

**Status.** PROPOSED.

**Context.** SPEC-001's consent screen names a **device** asking to join your
identity. SPEC-004's must name an **application origin**, an **account within
it**, and an **exact permission set**.
[[SPEC-004-application-scoped-identity#REQ-222]] enumerates what cannot carry
the decision:

> A public application profile, display name, icon, bundle/package name, deep
> link, callback URI, or TLS connection is insufficient by itself.

Every recognisable thing a designer would lead with is on that list by name.
[[SPEC-004-application-scoped-identity#CON-217]] says the same from the other
direction: a valid PAKE confirmation "is never sufficient application
authentication or authorization".

**Decision.** Reuse the treatment `src/index.html` already carries, unchanged in
meaning:

```html
<div class="evidence__row">                          <!-- verified -->
  <p class="evidence__key">Asked by</p>

<div class="evidence__row evidence__row--untrusted">  <!-- claimed -->
  <p class="evidence__key">Calls itself</p>
  <p class="evidence__note">its own words, unchecked</p>
```

`consent-application` renders **Asked by** (authenticated origin, verified
treatment), **Calls itself** (the application's display name, untrusted
treatment), **For this account** (the `acct:` alias — never the scope, per
[[SPEC-004-application-scoped-identity#NFR-203]]), and **Gains** (the permission
set).

**Rationale.** The obvious decision is "foreground the origin", and it is
shallow: it asks the person to already know that origins are trustworthy and
names are not. The existing treatment shows them *which fact is which*, which is
the same information delivered without the prerequisite.

This is Simplicity Ladder rung 4 — an existing component solves it — and
Constitutional Principle 8, composition-first UI. No new component, no new
token.

**Consequences, stated rather than smoothed over.** Origin-forward consent
screens are under-read. The specification's answer is
[[SPEC-004-application-scoped-identity#CON-221]] — fingerprint comparison, once
per account ever — which is why [[person-happy-paths#HP-4a]] exists. This screen
is not load-bearing alone and MUST NOT be designed as if it were.

**Ladder rung.** 4 — existing component.

Implements: [[SPEC-004-application-scoped-identity#REQ-222]],
[[SPEC-004-application-scoped-identity#CON-217]]

---

## Screen inventory

Eleven screens, each tracing to an existing SPEC-004 obligation. `data-screen`
values are stable identifiers and MUST NOT be derived from display labels.

| `data-screen` | Path | Presents | Traces to |
|---|---|---|---|
| `applications` | HP-3 | applications this identity serves | [[SPEC-004-application-scoped-identity#REQ-216]] |
| `application` | HP-3 | account, alias, devices for one application | [[SPEC-004-application-scoped-identity#CON-203]] |
| `username-set` | HP-3 | live alias preview + correlation warning | [[SPEC-004-application-scoped-identity#CON-212]], [[SPEC-004-application-scoped-identity#NFR-201]] |
| `username-taken` | HP-3 | `UsernameUnavailable` | [[SPEC-004-application-scoped-identity#CON-212]] |
| `fingerprint-compare` | HP-4a | hex + [[LifeHash]], no skip | [[SPEC-004-application-scoped-identity#CON-221]], [[SPEC-004-application-scoped-identity#REQ-230]] |
| `consent-application` | HP-4, HP-5 | origin, account, permissions | [[SPEC-004-application-scoped-identity#REQ-222]] |
| `binding-mismatch` | HP-5 | `PlatformBindingMismatch` | [[SPEC-004-application-scoped-identity#CON-222]] |
| `remove-device` | HP-6 | names the account *and* the device | [[SPEC-004-application-scoped-identity#CON-210]] |
| `remove-pending` | HP-6 | the honest wait | [[SPEC-004-application-scoped-identity#CON-210]] |
| `remove-confirmed` | HP-6 | verified closure carries the grant ID | [[SPEC-004-application-scoped-identity#CON-210]] |
| `scope-unavailable` | HP-7 | `AccountScopeUnavailable`, no action | [[SPEC-004-application-scoped-identity#REQ-217]] |

### Two screens whose job is honesty rather than help

`scope-unavailable` is the screen this plan is least comfortable with, and the
discomfort is correct. [[person-happy-paths#HP-7]] calls it "the sharpest cliff
in the specification":

> **The recovery phrase alone does not restore a Selfsame identity.** It
> restores the *hierarchy*; the account scope comes from the application.

[[SPEC-004-application-scoped-identity#REQ-217]] forbids guessing and forbids
prompting. The screen therefore SHALL offer no **remedial** control — no field,
no retry, nothing implying the scope can be supplied from here — and SHALL NOT
imply a remedy that does not exist. It will read as a bug to anyone who has not
read HP-7, and softening it is a specification change, not a design improvement.

It SHALL nevertheless carry a navigation control back to
`applications`. Version 0.1.0 of this plan required "no action at all" and its
test forbade every `button`, which would have stranded the person who reached
it and failed the accessibility baseline besides. That was over-reading the
requirement: `REQ-217` prohibits offering a way to *supply the scope*, not
leaving without one. The test now forbids `.btn` — this app's action class —
and requires `.back`.

`remove-pending` is the same shape in miniature.
[[SPEC-004-application-scoped-identity#CON-210]] forbids reporting success until
a re-resolved verified closure contains the grant ID, so pending can persist
indefinitely when no resolver answers. HP-6 calls this "honest and
unsatisfying". The screen SHALL NOT add a reassuring animation to cover it.

### Rendering permissions

SPEC-004 fixes *that* permissions are shown and is silent on how. A raw URI is
faithful and useless:

```
https://photos.example/selfsame/application#device
```

Each permission renders as a readable line with its URI available but
subordinate. Where a permission is **not recognised**, the URI SHALL be rendered
verbatim rather than paraphrased — an unrecognised permission rendered as
friendly prose is a permission consented to under a description nobody wrote.

---

## Contracts

All three cross the [[Tauri]] `invoke` trust boundary. Per Constitutional
Principle 14 and [[LangSec]], each declares the grammar its inputs are
recognised against **before** any semantic action.

### CON-601: `alias_preview`

```
Interface:  invoke("alias_preview", { homeDid, accountAuthority, localpart? })
            → { stableAlias: String, usernameAlias: String | null }
```

**Input grammar.**

```abnf
home-did     = "did:crdt:" 64HEXDIG        ; BLAKE3, lower-case
authority    = label *("." label)          ; RFC 1123, lower-case A-label
label        = alnum / (alnum *61ldh alnum)
localpart    = 1*64(ALPHA / DIGIT / "-" / "_" / ".")
```

`home-did` is recognised by the method's own `Did::from_str`, not by a parser
written here. The distinction is not stylistic: a first draft of `CON-601`
capped the identifier at 63 characters and rejected every real DID, which the
unit tests caught immediately. A shell-side recogniser that disagrees with the
method's by one character is the parser differential
[[SPEC-004-application-scoped-identity#CON-205]] spends its length avoiding,
arriving through the back door.

**Pre-conditions.**

- `homeDid` recognises against `home-did`; otherwise `HandoffMalformed`.
- `accountAuthority` recognises against `authority` via
  `uri::recognise_dns_name`; otherwise `HandoffMalformed`.
- `localpart`, when present, recognises against `localpart`; otherwise
  `UsernameUnavailable`.

**Post-conditions.**

- `stableAlias` equals `alias::stable_acct_uri(homeDid, accountAuthority)`.
- `usernameAlias` equals `alias::username_acct_uri(localpart, accountAuthority)`
  when `localpart` is present, and `null` otherwise.
- The command performs no I/O and no network access.

**Error model.** One closed token from
[[SPEC-004-application-scoped-identity#CON-226]]'s set. No parse detail crosses
the boundary.

Implements: [[SPEC-004-application-scoped-identity#CON-203]],
[[SPEC-004-application-scoped-identity#CON-212]]

Verified by: [[IMPL-004-application-scoped-identity-screens#TEST-601]]

---

### CON-602: `home_fingerprint`

```
Interface:  invoke("home_fingerprint", { homeDid })
            → { hex: String, lifehash: String }
```

**Input grammar.** `home-did`, as CON-601.

**Pre-conditions.** `homeDid` recognises; otherwise `HandoffMalformed`.

**Post-conditions.**

- `hex` is the six-byte rendering of
  `selfsame_core::fingerprint::fingerprint_did(homeDid)`.
- `lifehash` is the same digest's [[LifeHash]] rendering, base64, exactly 4,096
  characters — the length `src/app.js` already validates before painting.
- Behaviour is invariant across calling context.

**Error model.** As CON-601.

Implements: [[SPEC-004-application-scoped-identity#CON-221]],
[[SPEC-002-visual-key-fingerprint#REQ-101]]

Verified by: [[IMPL-004-application-scoped-identity-screens#TEST-605]]

---

### CON-603: `app_identity_derive`

```
Interface:  invoke("app_identity_derive", { applicationId, accountScopeId })
            → { homeDid: String, publicKey: String }
```

**Status this cycle: STUBBED.** Returns a fixture. See
[[IMPL-004-application-scoped-identity-screens#ADR-602]].

**Input grammar.** `applicationId` per
[[SPEC-004-application-scoped-identity#CON-201]]; `accountScopeId` per
[[SPEC-004-application-scoped-identity#CON-211]] — 43 canonical base64url
characters.

**Pre-conditions.** Both recognise before any action. A malformed
`accountScopeId` yields `ScopeNotCanonical`, never a guess.

**Post-conditions.**

- The returned `homeDid` SHALL NOT be presented as derived from the person's
  recovery secret while this contract is stubbed.
- `accountScopeId` SHALL NOT appear in any rendered output
  ([[SPEC-004-application-scoped-identity#NFR-203]]).

**Error model.** `AccountScopeUnavailable` when the caller supplies no scope —
and the command SHALL NOT prompt for one
([[SPEC-004-application-scoped-identity#REQ-217]]).

Implements: [[SPEC-004-application-scoped-identity#REQ-213]]

Verified by: [[IMPL-004-application-scoped-identity-screens#TEST-611]]

---

## Purity Boundary Map

### Pure core (no I/O, no shared state, deterministic)

- `selfsame_app_identity::alias` — `acct:` URI construction and recognition.
- `selfsame_app_identity::hierarchy` — derivation (unreachable this cycle, see
  ADR-602).
- `selfsame_core::fingerprint` — digest and its two renderings.

### Effectful shell (orchestrates I/O, calls pure core)

- `src-tauri` CON-601..603 — recognises `invoke` payloads, calls the core,
  returns values or closed tokens.
- `src/app-identity.js` — sequence and presentation only.

### Boundary contracts (data types crossing the boundary)

- `{ homeDid, accountAuthority, localpart }` — inward, recognised at CON-601.
- `{ stableAlias, usernameAlias }` — outward, already valid by construction.
- `{ hex, lifehash }` — outward; `lifehash` is re-validated in the renderer
  before painting, because a 4,096-character string is a canvas write.

### Dependency rule

Dependencies point inward: `app-identity.js` → `src-tauri` → core. The core MUST
NOT import from the shell, and the frontend MUST NOT reimplement a core
decision.

### Enforcement

`crates/selfsame-app-identity/tests/purity.rs` fails the build if a
network-capable crate enters the core's dependency graph. The frontend half is
enforced by review and by the absence of any decision logic to enforce — the
screens have no branch that a core value does not determine.

---

## Test specifications

Each screen gets one `TEST-###`, derived from the requirement it presents rather
than from the implementation. Per Constitutional Principle 3, the tests are
written and observed to fail before the screens exist.

| ID | Screen | Asserts |
|---|---|---|
| TEST-601 | `applications` | renders one row per application; no `accountScopeId` in the DOM |
| TEST-602 | `application` | account, alias, device list; grant IDs held but not rendered |
| TEST-603 | `username-set` | preview updates live; the [[SPEC-004-application-scoped-identity#NFR-201]] correlation warning is present |
| TEST-604 | `username-taken` | exactly one closed token; no parse detail |
| TEST-605 | `fingerprint-compare` | hex and [[LifeHash]] both painted; **no skip control exists in the DOM** |
| TEST-606 | `consent-application` | origin under verified treatment, display name under `--untrusted`; permissions listed |
| TEST-607 | `binding-mismatch` | claimed identity under `--untrusted`; observed caller beside it; no retry control |
| TEST-608 | `remove-device` | names both the account and the device |
| TEST-609 | `remove-pending` | **no success affordance and no completion animation** |
| TEST-610 | `remove-confirmed` | reachable only from a closure-carrying state |
| TEST-611 | `scope-unavailable` | **no actionable control exists in the DOM** |
| TEST-612 | all eleven | exactly one screen visible; no horizontal overflow at phone width; nothing thrown |

### Negative-output tests

TEST-605, TEST-609, and TEST-611 are **prohibited-action** tests in the sense of
PROTO-001's prohibitive-requirement template: each asserts the *absence* of an
affordance. They are the half most easily lost, because a suite that checks only
that the screen renders passes a screen that renders and also offers a skip.

### Harness

`tests/screens.mjs` gains eleven shots. New `data-action` hooks are REQUIRED
on every interactive element, since the harness drives screens by clicking
`[data-action="…"]`. The stub bridge answers CON-601..603 with the shapes the
real commands return.

Rust-side, CON-601 and CON-602 get unit tests in `src-tauri`. There is no new
security logic to test: both are thin wrappers over functions already covered by
the core's suites, which is the point of placing them at rung 4.

### Accessibility

Constitutional Principle 9 — WCAG 2.2 AA. The [[LifeHash]] canvas carries
`aria-hidden="true"` and the hex string is the accessible comparison value, as
[[SPEC-002-visual-key-fingerprint]] already establishes: the image is a
recognition aid and the hex is the datum.

---

## Amendment Channels

This plan may be amended by a versioned change to this file that identifies the
affected ADR/CON/TEST artefacts, updates traceability, records the reason, and
is approved by the human owner.

**No channel may waive** the Controls digest in the Orientation block. Each
entry is an obligation of [[SPEC-004-application-scoped-identity]], not of this
plan, and this document has no authority to relax one. A change to any of them
is a SPEC-004 amendment and follows
[[SPEC-004-application-scoped-identity#Amendment Channels]] — including its
Tier-1 provisions, which cover first-enrollment confirmation, same-device
dispatch, and mobile caller/wallet identity.

Chat instructions, implementation drift, and passing screenshots are evidence or
amendment requests; none changes this plan by itself.

## Changelog

| Version | Date | Change |
|---|---|---|
| 0.3.0 | 2026-08-01 | **Thirteen screens to eleven.** `handoff`, `wallet-unavailable` and `handoff-refused` were application-side screens rendered in the wallet: `CON-222` assigns the wallet search to "the developer application", so a wallet showing *Selfsame isn't installed* asserts its own absence. Version 0.1.0 listed them as "modelled from the wallet's side", which is not something that can be done. Replaced by `binding-mismatch` — the `CON-222` caller comparison, which genuinely is the wallet's, and which gives the unattributed-Android-caller fix a surface it did not have. |
| 0.2.0 | 2026-08-01 | **Implemented.** Two corrections the build forced, both recorded rather than quietly applied: `CON-601`'s `home-did` grammar was `1*63(ALPHA / DIGIT)` and is `64HEXDIG` — the first draft rejected every real DID, and the recogniser is now the method's own `Did::from_str` rather than one written here. `scope-unavailable` required "no action at all"; that over-read `REQ-217`, which prohibits offering a way to supply the scope rather than leaving without one, so it now carries navigation and its test forbids `.btn` instead of every `button`. |
| 0.1.0 | 2026-08-01 | Initial plan. Thirteen screens, three contracts, three ADRs. No `REQ-###` introduced. `SCREEN-###` documents deferred to `anuna-ssi`. |
