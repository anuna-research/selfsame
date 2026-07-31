# SPEC-004 screens — design

**Date:** 2026-08-01
**Status:** design, approved for planning
**Scope:** the person-facing surface for [[SPEC-004-application-scoped-identity]]

## Why this exists

SPEC-004 has no screens. The specification defines twenty-six contracts, the
prototype implements all of them, and the only thing that exercises them
end to end is a CLI. The seventeen screens the app already ships are SPEC-001:
one identity, many devices. SPEC-004 is a different shape — one identity serving
many *applications*, each with its own account, home DID, alias, and devices —
and none of it is visible.

That gap is not cosmetic. Two examples from the review this design follows:

- `android_select` returned `UnverifiedWalletTarget` when no wallet was
  installed, so a device with no wallet rendered as a *failed security check*.
  The fix split the outcome from `WalletUnavailable`, and nothing consumes the
  distinction, because there is no screen.
- `Handoff::binds_to` validates a return URI against the authenticated platform
  binding. It has no caller.

Both are correct and unreachable. A contract with no surface is a contract
nobody has walked.

## What this covers

Thirteen screens, drawn from `HP-3` through `HP-7` in
[[person-happy-paths]] together with their failure modes.

`HP-1` (add a second application) and `HP-2` (switch accounts) are deliberately
absent. Both are specified as having **no person-visible step at all** — "this
is the path where the promise is kept by there being no ceremony". Building
screens for them would be building the thing the specification is proud not to
need.

| Screen | Path | Contract |
|---|---|---|
| `applications` | HP-3 | list of applications this identity serves |
| `application` | HP-3 | account, alias, devices for one application |
| `username-set` | HP-3 | live preview + the `NFR-201` correlation warning |
| `username-taken` | HP-3 | `UsernameUnavailable` |
| `fingerprint-compare` | HP-4a | `CON-221`, hex + LifeHash |
| `consent-application` | HP-4, HP-5 | origin, account, exact permissions |
| `handoff` | HP-5 | Continue in Selfsame |
| `wallet-unavailable` | HP-5 | `WalletUnavailable` + install action |
| `handoff-refused` | HP-5 | `UnverifiedWalletTarget` / `HandoffAmbiguous` |
| `remove-device` | HP-6 | names the account *and* the device |
| `remove-pending` | HP-6 | `CON-210`, the honest wait |
| `remove-confirmed` | HP-6 | a verified closure contains the grant ID |
| `scope-unavailable` | HP-7 | `REQ-217`, the sharp cliff |

## Architecture

### Where the surface attaches

`home` gains an **Applications** section beneath the existing Devices list.
One shell, one identity, two lists: devices are how you reach your identity,
applications are what it does.

```
home
  ├─ Your devices        SPEC-001, unchanged
  │    └─ device → unlink
  └─ Applications        SPEC-004, new
       └─ application
            ├─ alias / username
            └─ devices on this account
                 └─ remove → pending → confirmed
```

Ceremony screens (`consent-application`, `fingerprint-compare`, `handoff`) are
reachable from either entry, because a ceremony is something that happens *to*
the wallet rather than something browsed to.

### Code structure

Logic splits along the specification boundary. Markup does not — the screen
harness serves one document, so all thirteen `<section>`s join `index.html`.

```
src/app.js            750 → ~800   SPEC-001, plus exports
src/app-identity.js   new  ~420    SPEC-004 screens
src/index.html        449 → ~800   +13 sections
src/styles.css        931 → ~1030  new components only
```

`app.js` gains exports for the primitives both surfaces need: `show`, `invoke`,
`fail`, `busy`, `idle`, `clearErrors`, `lifehashElement`, `since`.

The reason for the split is not line count. The boundary already exists
everywhere else in this repository — `selfsame-core`, `selfsame-app-identity`,
and `selfsame-app-identity-net` are separate crates with a tested purity
boundary between them, and `tests/purity.rs` fails the build if it erodes. A
frontend that interleaves both specifications in one file is the only place that
boundary stops being visible.

It has a practical payoff too: SPEC-004 is a Tier-1 draft with an open review
gate. If the gate closes differently, this surface is one file and one import.

**Rejected: a full concern-split** into `bridge.js`, `screens.js`,
`lifehash.js`, `spec001.js`, `spec004.js`. Better long-term shape, but it
rewrites working SPEC-001 code that nothing here requires touching.

### Wiring

`src-tauri` links `selfsame-app-identity` and adds three commands.

| Command | Backed by | State |
|---|---|---|
| `alias_preview` | `selfsame_app_identity::alias::{stable_acct_uri, username_acct_uri}` | **real** |
| `home_fingerprint` | `selfsame_core::fingerprint::fingerprint_did` | **real** |
| `app_identity_derive` | `selfsame_app_identity::hierarchy::derive` | **stubbed** — see below |

Only the first and third need the new crate link; `fingerprint_did` is in
`selfsame-core`, which `src-tauri` already links and already calls in
`get_state`.

Ceremony screens render from stub state. There is no network, no pairing, no
grant issuance and no revocation submission in this work.

#### Why derivation is stubbed

The wallet holds no material from which a SPEC-004 home DID can be derived.

SPEC-004's hierarchy roots at the BIP-39 seed:

```rust
// hierarchy.rs:176
pub fn recovery_seed(mnemonic: &Mnemonic) -> RecoverySeed {
    Zeroizing::new(mnemonic.to_seed_normalized(""))
}
```

SPEC-001's custody stores something else, and is explicit that it does:
*"The phrase is not stored"* (`custody.rs:206`). What it seals under the
passcode is `derive::root_seed(mnemonic, PERSONA_ZERO)` — a one-way KDF output.
The BIP-39 seed is not recoverable from it.

Two ways to close that were considered and both were rejected for this work:

- **Store the BIP-39 seed** alongside the root seed. This is a custody format
  change needing a migration for existing identities, and it widens what a
  passcode compromise yields. That is a security decision, and it does not
  belong inside a UI change.
- **Ask for the recovery phrase.** `HP-3`'s precondition is only "signed into
  A1". Requiring the phrase to read your own alias contradicts the happy path
  and puts the phrase back in memory to display a name.

So the home DID is a stub fixture, and `alias_preview` and `home_fingerprint`
run for real over it. Every alias and every fingerprint on screen is a genuine
computation from a real DID string; only the DID's provenance is fixture.

Implementation records this as **FINDING-016** in the EXP-001 report — the gap
is documented, not resolved, and writing that finding is part of the work rather
than a reference to something that already exists.

### Data flow

Unchanged in kind. The frontend holds no security logic; values and errors
arrive from Rust. `ui.state` gains an `applications[]` array:

```js
applications: [{
  applicationId,        // canonical https origin + path
  displayName,          // UNTRUSTED — the application's own words
  accountAlias,         // acct: URI, from alias_preview
  username,             // optional human alias, or null
  homeDid,              // stub fixture this cycle
  fingerprint,          // { hex, lifehash }, from home_fingerprint
  devices: [{ label, grantId, addedAt, isThisDevice }],
}]
```

`grantId` is held so `remove-device` can name what it revokes; it is not
rendered. The device row shows the label and when it was added, matching the
existing SPEC-001 device list.

## The consent screen

The hardest of the thirteen, and the one the existing design language already
answers.

SPEC-001's consent screen names a **device** asking to join your identity.
SPEC-004's must name an **application origin**, an **account within it**, and an
**exact permission set**. `REQ-222` enumerates what cannot carry that decision:

> A public application profile, display name, icon, bundle/package name, deep
> link, callback URI, or TLS connection is insufficient by itself.

Every warm, recognisable thing a designer would lead with is on that list by
name. The one fact the wallet authenticated is the origin, via `CON-214`
evidence. `CON-217` says the same from the other direction: a valid PAKE
confirmation "is never sufficient application authentication or authorization".

**The existing screen already has the vocabulary.** `index.html` distinguishes
verified from claimed with two row treatments:

```html
<div class="evidence__row">                          <!-- verified -->
  <p class="evidence__key">Asked by</p>

<div class="evidence__row evidence__row--untrusted">  <!-- claimed -->
  <p class="evidence__key">Calls itself</p>
  <p class="evidence__note">its own words, unchecked</p>
```

`consent-application` reuses both, unchanged in meaning:

- **Asked by** — the authenticated origin. Verified treatment.
- **Calls itself** — the application's display name. Untrusted treatment, with
  the same "its own words, unchecked" lead-in.
- **For this account** — the alias, not the account scope. `REQ-217` and
  `NFR-203` both keep the scope off screen.
- **Gains** — the permission set.

This is better than "foreground the origin" because it does not ask the person
to know that origins are trustworthy and names are not. It shows them which is
which.

### Rendering permissions

The specification fixes *that* permissions are shown and says nothing about how.
A raw URI is faithful and useless:

```
https://photos.example/selfsame/application#device
```

Each permission renders as a readable line with the URI available but
subordinate. Where a permission is not recognised, the URI is shown verbatim
rather than guessed at — an unrecognised permission that renders as friendly
prose is a permission the person consented to under a description nobody wrote.

**Known limitation, carried deliberately.** Origin-forward consent screens are
under-read. The specification's answer is `CON-221` — the fingerprint
comparison, once per account ever — which is why `HP-4a` exists. This screen is
not load-bearing alone and is not designed as if it were.

## Error handling

Four screens each render exactly one closed token from the specification's set,
with no detail beyond it. This follows the existing rule, stated in `app.js`:

> The `RejectReason` detail from the core never reaches a user. SCREEN-001's
> error model is one line — "That code isn't valid." — because a parse detail
> teaches nothing and says which check failed.

| Screen | Token | What the person can do |
|---|---|---|
| `username-taken` | `UsernameUnavailable` | pick another; never edit a URI |
| `wallet-unavailable` | `WalletUnavailable` | install action, carrying no ceremony value |
| `handoff-refused` | `UnverifiedWalletTarget` / `HandoffAmbiguous` | start again; the ceremony is burned |
| `scope-unavailable` | `AccountScopeUnavailable` | **nothing** — see below |

`scope-unavailable` is the screen this design is least comfortable with, and
that discomfort is correct. `HP-7` calls it "the sharpest cliff in the
specification":

> **The recovery phrase alone does not restore a Selfsame identity.** It
> restores the *hierarchy*; the account scope comes from the application.

`REQ-217` forbids guessing and forbids prompting. So the screen offers no
action, and it must say why without implying a remedy that does not exist. It
is the one screen whose job is to be honest rather than helpful.

`remove-pending` has the same shape in a smaller way. `CON-210` forbids
reporting success until a re-resolved verified closure contains the grant ID, so
"pending" can persist indefinitely when no resolver answers. The happy-paths
document calls this "honest and unsatisfying". The screen does not add a
reassuring animation to cover it.

## Testing

`tests/screens.mjs` gains thirteen shots. Each asserts what the existing
seventeen assert: exactly one screen visible, no horizontal overflow at phone
width, nothing thrown on the way through.

- New `data-action` hooks on every interactive element, since the harness drives
  screens by clicking `[data-action="…"]`.
- The stub bridge answers `alias_preview`, `home_fingerprint` and
  `app_identity_derive` with the shapes the real commands return.
- `npm run screens` exports the PNGs.

Rust-side, the three commands get unit tests in `src-tauri`. There is no new
security logic to test — `alias_preview` and `home_fingerprint` are thin
wrappers over functions already covered in the core's own suites.

## Out of scope

Stated so the boundary is a decision rather than an omission:

- Network, pairing, grant issuance, revocation submission. Blocked in part by
  `FINDING-015` — the pinned `did:crdt` service publishes no signed-closure
  endpoint, so a conforming resolver cannot satisfy `CON-206` step 4.
- Custody format changes (see FINDING-016).
- The developer application's own screens. `handoff` and `wallet-unavailable`
  are modelled from the wallet's side; a real application ships its own.
- Any change to the seventeen SPEC-001 screens beyond adding the Applications
  section to `home`.
- A draft/prototype banner. Deliberately absent: the prototype status lives in
  the commit message, the specification and the findings report.
