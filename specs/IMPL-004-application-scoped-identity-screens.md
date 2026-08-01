---
id: IMPL-004
title: Application- and Account-Scoped Identity — the person-facing surface
status: implemented
tier: 2
version: 0.7.0
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
                   │  index.html   12 sections   │  markup, one document
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
                   │  src-tauri  CON-601..606   │  recognise, then act
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
- `remove-pending` SHALL NOT report success before a verified closure, and SHALL
  NOT be reached before the submission it asserts has succeeded.
  ([[SPEC-004-application-scoped-identity#CON-210]])
- `fingerprint-mismatch` SHALL terminate the enrollment and offer no retry.
  ([[SPEC-004-application-scoped-identity#CON-221]],
  [[SPEC-004-application-scoped-identity#REQ-230]])
- Every `invoke` this surface makes SHALL name a command the Tauri handler
  registers. ([[IMPL-004-application-scoped-identity-screens#CON-604]],
  [[IMPL-004-application-scoped-identity-screens#CON-605]],
  [[IMPL-004-application-scoped-identity-screens#CON-606]])
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

Twelve screens, each tracing to an existing SPEC-004 obligation. `data-screen`
values are stable identifiers and MUST NOT be derived from display labels.

| `data-screen` | Path | Presents | Traces to |
|---|---|---|---|
| `applications` | HP-3 | applications this identity serves | [[SPEC-004-application-scoped-identity#REQ-216]] |
| `application` | HP-3 | account, alias, devices for one application | [[SPEC-004-application-scoped-identity#CON-203]] |
| `username-set` | HP-3 | live alias preview + correlation warning | [[SPEC-004-application-scoped-identity#CON-212]], [[SPEC-004-application-scoped-identity#NFR-201]] |
| `username-taken` | HP-3 | `UsernameUnavailable` | [[SPEC-004-application-scoped-identity#CON-212]] |
| `fingerprint-compare` | HP-4a | hex + [[LifeHash]], no skip | [[SPEC-004-application-scoped-identity#CON-221]], [[SPEC-004-application-scoped-identity#REQ-230]] |
| `fingerprint-mismatch` | HP-4a | the comparison's other answer; terminal, no retry | [[SPEC-004-application-scoped-identity#CON-221]], [[SPEC-004-application-scoped-identity#REQ-230]] |
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

### Claim audit

Every sentence on all eleven screens was checked against one question: *is this
true of the build showing it?* The pass separated two kinds of statement, and
only one of them can be wrong here.

**Statements about the designed system** — "Devices check for this when they
next look", "this is publicly discoverable", "it stops being able to act for
this account" — describe `SPEC-004` behaviour. A screen SHOULD carry these; they
are what it says in production, and a prototype that hedged them would be
describing itself rather than the design.

**Statements about what just happened** — "a verified record now carries the
removal", "nothing has told you it worked" — assert state. These MUST be true of
the build rendering them, and they are where every defect found so far has been.

The distinguishing test is *delegation*. `remove-confirmed` asserts a verified
record and is reachable only when `revocation_status` says so, so the claim is
delegated to a command and is as true as that command — which is the correct
architecture, and the same status every other rendered value has. `remove-pending`
asserted a retry that **no command backed and the frontend did not perform**, so
nothing could make it true. That is the line.

Two defects were found and fixed at version 0.5.0; two gaps were recorded rather
than fixed:

| Screen | Claim | Finding |
|---|---|---|
| `username-set` | "Claim it", then the name shown under *Public username* | **Fixed.** Recognition is not reservation. `CON-212` step 3 has the authority validate, reserve and publish; the wallet was stopping at recognition and setting the name locally, putting a name nobody held on the application screen. It now asks `provision_username` and surfaces `AccountProvisioningFailed`. |
| `applications` | "Each one gets its own identity below your recovery words" | **Fixed in the fixture.** Both fixture applications shared one `home_did`, so the screen told the truth about a system the fixture did not model — and cross-application unlinkability is the property `SPEC-004` exists to deliver. A real linkability defect would have looked correct. |
| `fingerprint-compare` | "You are asked this once for this account, ever" | **Recorded.** `CON-221`'s once-per-account obligation is the wallet's, and nothing here records that the question was asked, so this build would re-ask. Borderline: the sentence tells the person what kind of moment this is rather than reporting state. Owner: HOC. |
| `fingerprint-compare` | shows a fingerprint at all | **Fixed.** SPEC-001's onboarding teaches "same fingerprint everywhere"; this one is legitimately different. See `FINDING-017`. |
| `username-taken` | "Someone holds it, or it is reserved" | **Recorded.** The specified reason for the token, asserted as fact without the build having determined which. Minor. Owner: HOC. Narrowed at 0.7.0: the shot now drives it with `ss-admin`, a name the core refuses *because it is reserved*, so the fixture at least exercises a case the sentence describes. |
| `remove-pending` | "Signed on this device and sent." | **Fixed at 0.7.0.** The audit's own delegation test was applied to a command that was never registered. `revoke_grant` rejected on every press, the frontend discarded the rejection, and the screen asserted a signature and a submission that had not happened — the same defect as the retry claim removed at 0.4.0, one level down. The command is now declared ([[IMPL-004-application-scoped-identity-screens#CON-605]]), refuses honestly, and the refusal is rendered on `remove-device`. |
| `binding-mismatch` | reached from "They're different" on `fingerprint-compare` | **Fixed at 0.7.0.** A fingerprint mismatch was routed to the `CON-222` caller-binding screen, whose two evidence fields nothing on that path populates — so the person was shown someone else's error with blanks in it, and the enrollment carried on. [[IMPL-004-application-scoped-identity-screens#Screen inventory]] gains `fingerprint-mismatch`, which terminates. |

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

### The three commands version 0.6.0 assumed and did not declare

Versions 0.4.0 and 0.5.0 changed the frontend to call `provision_username`,
`revoke_grant`, and `revocation_status`, and reasoned about the screens on the
basis that those calls reach commands. They reached nothing: the Tauri handler
registered `CON-601` to `CON-603` and no more, so every one of the three
rejected with a "command not found" the screens could not distinguish from any
other failure. The removal path discarded its rejection and advanced to
`remove-pending`, which opens *"Signed on this device and sent."*

That is the defect
[[IMPL-004-application-scoped-identity-screens#Claim audit]] already names, one
level down. Its own test is delegation — a claim delegated to a command "is as
true as that command" — and a claim delegated to a command that does not exist
is not delegated at all. Nothing could make the sentence true, which is exactly
the line the audit draws for the retry claim it removed at 0.4.0.

The three are therefore declared here. **All three refuse**, and the refusals are
not placeholders: they are what is the case for a build with no account
authority, no SPEC-004 home key
([[EXP-001-findings|FINDING-016]]), and no state resolver. A refusal is a
computation the surface can honestly delegate to; a missing command is not.

### CON-604: `provision_username`

```
Interface:  invoke("provision_username", { homeDid, accountAuthority, localpart })
            → () | UsernameUnavailable | AccountProvisioningFailed
```

**Status this cycle: REFUSES.**
[[SPEC-004-application-scoped-identity#CON-212]] step 3 has the *authority*
validate, reserve, and publish the reciprocal binding. This build is wired to no
authority, so `AccountProvisioningFailed` — "nothing was reserved" — is the true
answer rather than a stand-in for one, and it is the token
`username-set` already renders.

**Input grammar.** `homeDid` per
[[IMPL-004-application-scoped-identity-screens#CON-601]]; `accountAuthority` per
[[SPEC-004-application-scoped-identity#CON-204]]; `localpart` per
[[SPEC-004-application-scoped-identity#CON-212]], recognised by
`alias::recognise_username` and no second grammar.

**Pre-conditions.** All three recognise before the refusal. A command that
refused without recognising would leave its recognisers unexercised until the
day a real authority lands, which is the day they most need to already work.

**Post-conditions.** Nothing is reserved, published, or stored. The wallet SHALL
NOT set a local username on the strength of recognition
([[SPEC-004-application-scoped-identity#CON-212]]).

**Error model.** `UsernameUnavailable` when the localpart fails recognition —
the person picks another name. `AccountProvisioningFailed` when it recognises
and no authority answered.

Implements: [[SPEC-004-application-scoped-identity#CON-212]]

Verified by: [[IMPL-004-application-scoped-identity-screens#TEST-614]]

### CON-605: `revoke_grant`

```
Interface:  invoke("revoke_grant", { grantId })
            → () | HandoffMalformed | RevocationUnavailable
```

**Status this cycle: REFUSES.**
[[SPEC-004-application-scoped-identity#CON-210]] steps 2 to 4 sign the
`RevokeCredential` delta with the account's home key. `FINDING-016` is that this
wallet holds no material from which one can be derived. A wallet that cannot
sign cannot submit.

**Input grammar.** `grantId` per
[[SPEC-004-application-scoped-identity#CON-205]]:

```abnf
grant-id = home-did "#grant-" 43(ALPHA / DIGIT / "-" / "_")
```

The DID half uses the pinned method's own parser; the token is 32 octets
base64url. This is the pair
[[SPEC-004-application-scoped-identity#CON-210]] itself insists on before a
delta is built, checked at the boundary rather than inward.

**Pre-conditions.** Recognition precedes the refusal, as for
[[IMPL-004-application-scoped-identity-screens#CON-604]].

**Post-conditions.** No delta is signed and none is submitted. `remove-pending`
SHALL be reachable only when this command returned successfully, because its
first sentence asserts that a delta was signed and sent.

**Error model.** `HandoffMalformed` for an unrecognised identifier;
`RevocationUnavailable` when the identifier recognises and no home key exists.

Implements: [[SPEC-004-application-scoped-identity#CON-210]]

Verified by: [[IMPL-004-application-scoped-identity-screens#TEST-615]]

### CON-606: `revocation_status`

```
Interface:  invoke("revocation_status", { grantId })
            → { confirmed: Boolean } | HandoffMalformed
```

**Status this cycle: NEVER CONFIRMED**, which is
[[SPEC-004-application-scoped-identity#CON-210]]'s own answer rather than a
shortfall: *"The initiating application reports pending until a newly resolved,
cryptographically verified closure includes `grant_id`."* This build resolves no
closure, so no closure includes anything, so the report is pending. A resolver's
acknowledgement would not have changed it either.

**Input grammar.** `grantId`, as
[[IMPL-004-application-scoped-identity-screens#CON-605]].

**Post-conditions.** `confirmed` SHALL be true only on the evidence of a
resolved, cryptographically verified closure carrying the exact grant ID. A
timeout, an acknowledgement, and an elapsed interval are each insufficient.

**Error model.** `HandoffMalformed` for an unrecognised identifier. An
unobtainable status is `{ confirmed: false }`, never an error — a status the
verifier could not obtain leaves the screen at pending, which is the honest
report.

Implements: [[SPEC-004-application-scoped-identity#CON-210]]

Verified by: [[IMPL-004-application-scoped-identity-screens#TEST-616]]

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
| TEST-609 | `remove-pending` | **no success affordance, no completion animation, and no retry claim in the copy** |
| TEST-610 | `remove-confirmed` | reachable only from a closure-carrying state |
| TEST-611 | `scope-unavailable` | **no actionable control exists in the DOM** |
| TEST-612 | all twelve | exactly one screen visible; no horizontal overflow at phone width; nothing thrown |
| TEST-613 | `remove-device` after a refused submission | the refusal token is rendered, and **no sentence claims the delta was signed or sent** |
| TEST-614 | [[IMPL-004-application-scoped-identity-screens#CON-604]] | recognises all three inputs, then refuses; a malformed localpart is `UsernameUnavailable` and a recognised one is `AccountProvisioningFailed` |
| TEST-615 | [[IMPL-004-application-scoped-identity-screens#CON-605]] | a malformed `grantId` is `HandoffMalformed`; a well-formed one is `RevocationUnavailable` |
| TEST-616 | [[IMPL-004-application-scoped-identity-screens#CON-606]] | never `confirmed`; a malformed `grantId` is `HandoffMalformed` |
| TEST-617 | `fingerprint-mismatch` | reached from "They're different"; **no retry control, and none of the CON-222 evidence fields** |
| TEST-618 | [[IMPL-004-application-scoped-identity-screens#CON-601]] | the preview recognises exactly the language `alias::recognise_username` recognises, asserted as an equivalence over both |
| TEST-619 | [[IMPL-004-application-scoped-identity-screens#CON-603]] | the stub `publicKey` derives the stub `homeDid` |
| TEST-620 | the `invoke` surface | **every command the frontend calls is one the Tauri handler registers**; commands registered and unreached are reported, not failed |

### Negative-output tests

TEST-605, TEST-609, and TEST-611 are **prohibited-action** tests in the sense of
PROTO-001's prohibitive-requirement template: each asserts the *absence* of an
affordance. They are the half most easily lost, because a suite that checks only
that the screen renders passes a screen that renders and also offers a skip.

**A claim is a claim whether it is a control or a sentence.** TEST-609 asserts
forbidden *phrases* as well as forbidden selectors, because the first version of
`remove-pending` promised "this will keep trying until one does" and "it is
retained and retried" — both obligations `CON-210` places on a wired
implementation, neither true of a build that submits once and checks once. No
selector assertion could have caught it: the screen had no success affordance,
no tick, and a false sentence.

Copy drifts back more easily than controls do, because reassuring prose does not
read as an assertion. The forbidden-phrase list is what makes implementing retry
an edit someone has to make deliberately rather than one they can forget.

### Harness

`tests/screens.mjs` gains twelve shots. New `data-action` hooks are REQUIRED
on every interactive element, since the harness drives screens by clicking
`[data-action="…"]`. The stub bridge answers CON-601..606 with the shapes the
real commands return.

**"The shapes the real commands return" includes the refusals.** The bridge
previously answered three commands the backend did not register, and answered
two of them with success — which is how `remove-pending` was captured for a
build in which the invoke rejected and nothing was signed. A stub more capable
than the thing it stands for does not test the screen; it manufactures the state
the screen claims, and every assertion then runs against the fixture rather than
against the app.

Two screens — `remove-pending` and `remove-confirmed` — are consequently
unreachable in this build, because `revoke_grant` refuses. They are still
captured, from a state flag named `wired_backend` and under shot names prefixed
`wired-`, so that a reader of the shot list cannot mistake a render of the design
for a state the build produces. That flag is the only place this harness stands
in for a backend it does not have, and naming it is what keeps it from spreading.

### The check that would have caught it

Rewriting the bridge fixes this instance. It does not fix the class, and the
class is the interesting part: **a call site and its callee were each correct in
isolation, and no artefact compared them.** Reading either file carefully finds
nothing wrong; the harness made it harder still, because its stub answered.
[[PROTO-001-usdd-agent-protocol]] is direct about what a countermeasure may be
here — the control moves outside the reader, into something deterministic that
runs.

So [[IMPL-004-application-scoped-identity-screens#TEST-620]] scans `lib.rs`'s
`generate_handler!` block and every `invoke("…")` in the frontend, and fails the
build on a call the handler does not register. Commands registered and *not*
called are reported rather than failed: a declared contract nothing reaches is
worth knowing about and is not always a defect —
[[IMPL-004-application-scoped-identity-screens#CON-603]] is stubbed and has no
screen path yet.

It reads the handler block rather than a hand-kept list, which is the property
that matters: a list would need updating by the same person who forgot to
register the command. Verified by removing one registration and watching the
build fail with the exact defect this version repairs.

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

## Gate Evidence Record — version 0.7.0

One entry per gate closed in this cycle, written as each was run. A `pass` with
no `evidence` is invalid, not passed; `unverified` is a legitimate value and is
how an obligation with no available mechanism is recorded honestly.

```yaml
phase: 3
version: 0.7.0
gates:
  - gate: "Test-First (Red Gate): each fix has a test observed to fail first"
    mechanism: "revert the fix in place, run the suite, restore"
    result: pass
    evidence: >
      con_206_acceptance: 3 FAILED with the three checks neutered;
      con_219_ceremony: an_android_binding_with_nothing_attributed_is_refused… FAILED
      with the Android arm removed;
      screens.mjs: 26-remove-refused and 29-fingerprint-mismatch both FAILED with
      the frontend routing reverted — reaching remove-pending and binding-mismatch
      respectively, which is the reviewed behaviour exactly
  - gate: "All tests green"
    mechanism: "cargo test --workspace"
    result: fail
    evidence: >
      32 of 33 suites pass (207 core unit, 37 net unit, 35 CON-206, 30 CON-219).
      One failure, pre-existing and unrelated to this version:
      probe::an_unreachable_group_is_probed_in_parallel_and_not_in_sequence
      (NFR-207) measures wall-clock over four unresolvable hosts and asserts
      under 3x the 1500ms probe deadline. It passes in isolation in 0.02s,
      3 runs of 3, and fails in the whole-workspace run at ~7.98s. Attributed
      by reverting selfsame-app-identity-net to its pre-0.7.0 state and
      reproducing the failure there, so it is not a regression from this work.
      7.98s also exceeds the 6s a fully serial probe would take, which points
      at the DNS resolver threadpool saturating across concurrently-running
      test binaries rather than at probe_group serialising — the deadline does
      not cancel an in-flight lookup. Not repaired here: loosening the bound
      would weaken an NFR-207 assertion, and re-designing the measurement is a
      change to how that requirement is verified. Owner: HOC.
  - gate: "Presentation surface renders and every screen rule holds"
    mechanism: "node tests/screens.mjs"
    result: pass
    evidence: "31 shots, all screens rendered clean"
  - gate: "Every invoke names a registered command"
    mechanism: "node tests/screens.mjs (TEST-620)"
    result: pass
    evidence: >
      every invoke resolves; 2 registered and unreached (app_identity_derive,
      forget_identity), reported not failed. Red-gated by removing one
      registration and watching it report the exact 0.7.0 defect.
  - gate: "Architecture / lint clean"
    mechanism: "cargo clippy --workspace --all-targets"
    result: pass
    evidence: "0 warnings, 0 errors"
  - gate: "Traceability: no new dead links"
    mechanism: "zetl check --dead-links -d specs"
    result: pass
    evidence: "78 before this change, 78 after — the pre-existing concept-page backlog, unchanged"
  - gate: "Adversarial review of these fixes (Constitutional Principle 12)"
    mechanism: "cross-model review from a clean context"
    result: unverified
    evidence: >
      not run — this cycle *is* the response to such a review, and the session
      that wrote the fixes may not validate them. Owner: HOC.
  - gate: "Amendment approved through a declared channel"
    mechanism: "reviewer: human owner, per this document's Amendment Channels"
    result: unverified
    evidence: >
      0.7.0 declares CON-604..606 and a twelfth screen. The amendment is written
      and traceability updated; approval is outstanding. Owner: HOC.
  - gate: "Mutation testing on the changed predicates"
    mechanism: >
      cargo mutants --in-place -p selfsame-app-identity
      --file accept.rs --file proof.rs --file revocation.rs --file enrollment.rs
      -F "accept_grant|check_status|check_validity|AcceptError::public|consume|read_projection|verify|is_consumed"
    result: pass
    evidence: >
      first round 112 mutants, 90 caught, 17 missed, 5 unviable (84%);
      second round after the repairs 107 mutants, 101 caught, 5 unviable,
      0 missed, 1 reported timeout. The 5 fewer mutants are the mutation sites
      removed with the empty `if` in check_status. The timeout
      (revocation.rs read_projection, `<` to `<=`) is a tool artefact rather
      than a gap: applied by hand, it is caught by
      `the_projection_reading_is_asymmetric_at_every_age` in 0.09 s. So 102 of
      102 viable mutants are killed.
      Note: cargo-mutants' default copy-to-tmp strategy cannot build this
      workspace — the sibling path dependencies (`../did-crdt`, `../cbcl-rs`)
      do not survive the copy — so `--in-place` from a clean tree is required.
```

One gate is `fail` and two are `unverified`, each with a named owner, so this
phase is **not** reported complete. A phase MUST NOT be reported complete while
any gate is `fail`, and this one is — the failing test is pre-existing and
unrelated to this version, but "pre-existing" is a fact about its cause and not
a licence to record it as passing. The `review-gate` field in the frontmatter
still reads `not-approved`, and that is the accurate state.

**What the mutation round found is worth recording separately**, because it is
evidence about the *repairs* rather than about the original defects. Seventeen
mutants survived the first round, and they resolved into one deletion and five
test gaps — none of which any review pass had named:

- The clock-skew parameter of
  [[SPEC-004-application-scoped-identity#CON-206]] step 11 was never non-zero in
  any test, so `now + skew` and `now - skew` were indistinguishable. A skew
  applied with the wrong sign *narrows* the validity window instead of widening
  it: valid grants refused at one edge, expired grants accepted at the other.
- The step-10 freshness bound had no test at exactly the bound, and step 1's
  ordering was unobservable because the JWS recogniser carries the same 64 KiB
  limit and reports it as step 1 — so "refused before parsing" and "refused
  while parsing" looked identical from outside.
- `verify`'s second comparison of `applicationId`/`profileVersion`/
  `profileDigest` — the one its own comment explains at length, against the
  *offer* rather than the profile — could not be reached by any test, because
  mutating the statement trips the first comparison.
- `check_status` carried a three-clause condition guarding an empty block. Five
  mutants survived it and none could be killed: a condition with no body has no
  behaviour to change. It read as a control and enforced nothing.
- **And the Android caller fix made in this very version had an untested
  branch.** `observed_id != binding.id()` — the comparison
  [[SPEC-004-application-scoped-identity#CON-222]] exists to make — was never
  exercised with an attributed caller that *differs* from the binding, because
  the pre-existing mismatch case names a binding the profile does not carry and
  so fails the lookup first.

That last one is the reason this gate is worth its cost. A fix written in
response to a security review, reviewed by its own author, tested, and green,
still had no coverage on the branch that does the work.

---

## Changelog

| Version | Date | Change |
|---|---|---|
| 0.7.0 | 2026-08-01 | **Cross-model review response — the surface's claims, and the commands under them.** Three commands the frontend has called since 0.4.0 were registered nowhere, so every call rejected with a Tauri "command not found" the screens could not distinguish from any other failure. `remove-pending` — "Signed on this device and sent." — was reached by discarding that rejection, which is [[IMPL-004-application-scoped-identity-screens#Claim audit]]'s own defect one level down: a claim delegated to a command that does not exist is not delegated at all. `CON-604`/`CON-605`/`CON-606` are declared, recognise their inputs, and refuse honestly (no account authority, no home key, no resolver); the removal refusal is rendered on `remove-device` and `remove-pending` is reachable only after a successful submission. "They're different" on `fingerprint-compare` opened the `CON-222` caller-binding screen with two blank evidence fields and left the enrollment running — a twelfth screen, `fingerprint-mismatch`, terminates it. `CON-601` dropped a hand-written localpart grammar that admitted `Alice`, `.alice`, `ss-admin`, and 33–64-character names the core refuses, for `alias::recognise_username`; the username is now submitted exactly as typed rather than trimmed into a different name; and `CON-603`'s stub `publicKey` now derives its stub `homeDid`, which it did not. The screen harness answers only registered commands: two screens are consequently unreachable in this build and are captured under a named `wired_backend` flag rather than by a bridge that pretends. Six new TEST entries; every fix verified by reintroducing the defect and watching the assertion fail. **Awaiting owner approval per [[IMPL-004-application-scoped-identity-screens#Amendment Channels]].** |
| 0.6.0 | 2026-08-01 | **`FINDING-017`.** "Home key" names the SPEC-001 root in the wallet and a per-application-account key in SPEC-004, and both have a fingerprint. SPEC-001's created screen teaches "if one ever shows something else, it isn't part of your home key" — the `CON-221` comparison legitimately shows something else, so the rule either alarms at a correct value or teaches that mismatches are sometimes fine. Nothing renamed: `fingerprint-compare` now states the distinction before the stakes and names the application, `application` says it in passing, and a screen check asserts both phrases. The vocabulary decision spans two specs and the `anuna-ssi` vault. |
| 0.5.0 | 2026-08-01 | **Claim audit over all eleven screens.** Two defects fixed: `username-set` presented an unreserved name as held — recognition is not reservation, and it now asks `provision_username` and surfaces `AccountProvisioningFailed`; the `applications` fixture shared one home DID across two applications while the screen claimed each gets its own. Two gaps recorded (`fingerprint-compare`'s once-ever claim, `username-taken`'s asserted reason). New assertions for both fixes verified by reintroducing each regression and watching it fail. |
| 0.4.0 | 2026-08-01 | `remove-pending` claimed "this will keep trying until one does" and "it is retained and retried". Both are `CON-210` obligations on a wired implementation; neither is true of this build, which submits once and checks once. Removed, and TEST-609 gains forbidden-phrase assertions so the claim cannot return without a deliberate edit — verified by reintroducing the sentence and watching the test fail. `scope-unavailable` now names the application. |
| 0.3.0 | 2026-08-01 | **Thirteen screens to eleven.** `handoff`, `wallet-unavailable` and `handoff-refused` were application-side screens rendered in the wallet: `CON-222` assigns the wallet search to "the developer application", so a wallet showing *Selfsame isn't installed* asserts its own absence. Version 0.1.0 listed them as "modelled from the wallet's side", which is not something that can be done. Replaced by `binding-mismatch` — the `CON-222` caller comparison, which genuinely is the wallet's, and which gives the unattributed-Android-caller fix a surface it did not have. |
| 0.2.0 | 2026-08-01 | **Implemented.** Two corrections the build forced, both recorded rather than quietly applied: `CON-601`'s `home-did` grammar was `1*63(ALPHA / DIGIT)` and is `64HEXDIG` — the first draft rejected every real DID, and the recogniser is now the method's own `Did::from_str` rather than one written here. `scope-unavailable` required "no action at all"; that over-read `REQ-217`, which prohibits offering a way to supply the scope rather than leaving without one, so it now carries navigation and its test forbids `.btn` instead of every `button`. |
| 0.1.0 | 2026-08-01 | Initial plan. Thirteen screens, three contracts, three ADRs. No `REQ-###` introduced. `SCREEN-###` documents deferred to `anuna-ssi`. |
