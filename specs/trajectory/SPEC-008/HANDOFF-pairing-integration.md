# Handoff — integrate cbcl-pairing + selfsame + cbcl_chat

You are picking up an integration effort. **Goal: a Selfsame wallet can link with
the chat.anuna.io application (`cbcl_chat`), end to end, using the cbcl-pairing
ceremony.** Read this whole document before acting. The previous agent made
several architectural wrong turns (documented below so you don't repeat them) and
the work is currently paused at a design decision after an adversarial review
returned REJECT.

Date context: work is happening 2026-08-22. Toolchain that matters: rustc 1.96.0,
wasm-bindgen 0.2.126, host aarch64-apple-darwin.

## The three repos (sibling checkouts under ~/Code)

| Repo | Path | Role | Deploy |
|---|---|---|---|
| `selfsame` | `~/Code/selfsame` | the **wallet** (Rust/Tauri) + the SPEC vault (`specs/`) | desktop/Android app the user builds locally |
| `cbcl-bus` | `~/Code/cbcl-bus` | the **hub**: serves chat.anuna.io (`cbcl_chat`), the DID/rendezvous doors, and the **blind pairing relay** on :9443. LFE/Erlang + a Rust NIF | Fly app `cbcl-bus` (single machine, `immediate` strategy) |
| `cbcl-pairing` | `~/Code/cbcl-pairing` | the **pairing protocol**: CPace PAKE, blind relay, consent-gated ceremony (SPEC-075/SPEC-001). Rust | library, compiled into both sides |
| `did-crdt` | `~/Code/did-crdt` | DID resolver + the SPEC-001 rendezvous mailbox | Fly `did.anuna.io` |

Also relevant: `cbcl-rs` (`~/Code/cbcl-rs`) — CBCL core/parser, a dependency of the
WASM and the hub NIF. Its working tree carries many uncommitted files; the deploy
build clones deps fresh from remotes at pinned SHAs, so local dirtiness does not
reach production, but it blocks the strict reproducible-WASM vendor script.

## The architecture you must hold in your head

There are **two** ways a wallet gets an account grant from an application. They are
NOT alternatives — the spec makes them sequential:

1. **SPEC-004 CON-219 enrolment (ADR-913)** — "first contact." The browser
   allocates a signed offer to the did.anuna.io rendezvous mailbox; the wallet
   fetches it, authenticates the profile live (CON-220), consents, and on confirm
   **writes a held pairing-trust record** (`record_pairing_trust`, the ONLY writer
   of one). Transport: rendezvous + the hub's `/selfsame/enrolment/sign` endpoint.

2. **SPEC-008 cbcl-pairing claimant** — the "production pairing." The browser runs
   the cbcl-pairing **allocator** (an invitation over the blind :9443 relay); the
   wallet runs the **claimant** (`cbcl_pairing_start` → CPace → consent → grant).
   Its origin gate **REQ-906 requires a held pairing-trust record** to vouch for the
   relay.

**The binding fact (see `specs/trajectory/SPEC-008/pairing-completion-runbook.md`):**
pairing (2) needs the trust record that only enrolment (1) writes. So the sanctioned
flow is **enrol once → then pair**. A prior attempt to make pairing work as
first-contact on its own (REQ-909) was authored, adversarially reviewed, and
**REJECTED** (`specs/trajectory/SPEC-008/req-909-adversarial-review-2026-08-22.md`) —
read that review; its findings recur.

## Why relay trust exists (the anti-phishing core)

The invitation names which relay to dial, and it is untrusted input. If the wallet
dialed any named relay, a phishing invitation would point it at an attacker's
rendezvous. REQ-906 anchors relay trust to a profile the wallet already holds +
a compiled digest registry (`CON-903`). The user wants to replace this with
**user-managed TOFU** (no allowlist; prompt on a new relay; accept adds to the
person's own policy). That is the design in flight below.

## What the previous agent did — including the mistakes (do not repeat)

Deployed to production three times; chat.anuna.io is currently on Fly release
**v91**. Current live state and the mistakes:

- **MISTAKE 1 — built the wrong path.** Built out and deployed the entire SPEC-004
  CON-219 rendezvous+sign enrolment wire (new wallet commands, a new rendezvous
  slot `Role::Announce`, a rebuilt vendored WASM with `announce_slot`/
  `open_announce`/`fingerprint_did_json`, browser allocator changes) — when the
  user wanted the **cbcl-pairing** path. This work is committed on selfsame branch
  `spec/spec-004-web-manual-binding` and cbcl-bus branch `feat/ratify-production-profile`.
  It is NOT wrong code per se (it IS the sanctioned ADR-913 enrolment), but it was
  the wrong focus. It is deployed and live.
- **MISTAKE 2 — hid the pairing invite button**, then **removed it**, under a
  mistaken read of it as a dev-only affordance. It is the real cbcl-pairing
  allocator surface (`paintCbclInviteAffordance`, `cbcl-invite.mjs`). It was
  RESTORED and relabeled "link my Selfsame wallet" in cbcl-bus commit on
  `feat/ratify-production-profile`, and the CON-219 "link" button was removed.
  This is the current deployed UI (v91).
- **MISTAKE 3 — removed enrolment, leaving pairing unbootstrappable.** Because
  pairing needs enrolment's trust record (above), the deployed pairing button now
  correctly returns `PairingRelayRefused` for a first-time wallet — there is no
  held record. That is fail-closed, not a bug.

Net deployed state (v91): chat.anuna.io shows a "link my Selfsame wallet" button
that runs the cbcl-pairing allocator; the ratified profile + staged fixture both
name relay origin `https://chat.anuna.io:9443`; the relay is live (active pairing
rooms in logs). A first-time wallet pairing refuses at REQ-906 for lack of a held
record.

## The design decision in flight (this is where you resume)

The user directed: **drop the allowlist; TOFU relay trust — notify the person on a
new relay, accept (add to their own policy) or reject.** They chose **standalone
first-contact pairing** (no enrolment step) and approved a draft amendment:

- **`specs/trajectory/SPEC-008/spec-008-0.4.0-standalone-tofu-first-contact.md`** —
  reverses ADR-902 (relay trust from held record + compiled registry) to: live
  CON-220 application authentication + person-owned TOFU relay policy. Owner-approved.

**A fresh-context Tier-1 adversarial review then returned REJECT** with five
findings the owner approval had missed (this is the mandatory gate; owner approval
alone was also insufficient for the REJECTED REQ-909). The findings — you MUST
address these in any v0.4.1, or reconsider:

- **F-A (CRITICAL).** TOFU is relay-scoped, not (application, relay)-scoped. Once a
  relay is trusted, CON-906 never re-fires — so an attacker who authors a valid
  profile declaring the *same already-trusted relay* pairs the victim with no
  prompt. Fix: scope trust to **(applicationId, relayOrigin)**, or re-prompt
  whenever the CON-220-authenticated application is new, regardless of relay.
- **F-B (CRITICAL).** The exact-intent consent screen (cbcl-pairing
  `endpoint.rs` `apply_intent`, `profile.rs` `recognise_intent`) displays the
  applicationId the **wire counterpart claims** (`claimed_by_secret_holder: true`),
  not the CON-220-authenticated value. The cross-check
  (`transfer.application_id == verification.profile.application_id`,
  `selfsame-pairing/src/lib.rs` `recognise_transfer_claims`) runs only at
  `DeliverGrant`, **after** Approve is sent (`live.rs`, `cbcl_pairing.rs finish_live`).
  So the person approves against an untrusted string. Fix needs a **cbcl-pairing
  display-layer change**: show the authenticated value, cross-checked before the
  screen.
- **F-C (CRITICAL).** REQ-913 claims key derivation happens only after consent, but
  the reused `cbcl_context::assemble_claimant` (`src-tauri/src/cbcl_context.rs`
  ~244-357) derives the per-app identity via `Custody::use_hierarchy_root` /
  `hierarchy::derive` **before the socket opens**. Ordering claim contradicts the
  code. Fix: actually restructure so no key derivation / scope mint / publish /
  alias-provision happens before consent (inherited unwaivable hard stop
  SPEC-007 REQ-812).
- **F-D (HIGH).** `assemble_claimant` needs an `account_scope_id` that only a prior
  enrolment record supplies. Standalone first contact has none. OQ-3 deferred this,
  but it is load-bearing — the spec is not implementable without a specified
  fresh-scope bootstrap (touches SPEC-004). A second blocking dependency.
- **F-E (HIGH).** REQ-910(b)/`verify_invitation_origin` only checks the profile
  *named by the invitation's own applicationId* lists the relay. The attacker
  authors that profile, so they can declare **anyone's** relay (e.g. a popular
  trusted operator's). Nothing binds relay operatorship to the application. The
  F-A fix (per-app consent) mitigates the practical attack but does not bind
  operatorship.

Wikilinks and cross-refs in the amendment check out (F-G, LOW).

## The two ways forward (get the user's call before building)

1. **Rework to v0.4.1** addressing all five findings: (app,relay)-scoped consent;
   a cbcl-pairing display-layer amendment so the authenticated applicationId is what
   the person approves (F-B); a wallet ordering restructure so nothing is derived/
   minted/published before consent (F-C); a specified fresh-scope bootstrap (F-D);
   and either bind relay operatorship or accept the per-app-consent mitigation (F-E).
   This spans **cbcl-pairing (wire + display) + selfsame (wallet) + cbcl-bus
   (allocator)** and needs another Tier-1 adversarial review before code.
2. **Reconsider** — the review re-endorses the enrolment path (ADR-913) as the
   sound first-contact. Restoring **enrol → pair** works within the current spec
   today (the CON-219 wire is already built and deployed; you would re-expose an
   enrolment entry, let the user enrol once to write the trust record, then pair).

## Non-negotiable discipline (this is anuna-dev / PROTO-001 Tier-1 work)

- **No code before a fresh-context adversarial review passes.** Owner approval is
  necessary but NOT sufficient — it missed the fatal flaws in both REQ-909 and
  0.4.0. Run the review with a defect-finding mandate, cross-model, verifying every
  claim against the actual code (`Agent` tool, fresh general-purpose agent, a model
  different from your own).
- **Read `references/` for the anuna-dev skill and PROTO-001 before authoring
  artefacts.** Invoke the `anuna-dev` skill. Fully-qualify wikilink anchors. Use
  fresh sequential artefact numbers (SPEC-008 is at REQ-913/ADR-905/CON-906/TEST-926
  after 0.4.0; the REJECTED REQ-909/TEST-916/917 numbers are burned).
- **Verify claims against code, not prose.** Both rejected designs died on claims
  the code didn't back (a false wire premise; a display that shows untrusted data;
  an ordering that contradicts the reused function). Trace the real paths.
- **Production deploys are outward-facing and single-machine `immediate` (no
  canary).** Confirm with the user before deploying. Rollback target is the prior
  `fly releases -a cbcl-bus` version. Fly token: `~/.fly/config.yml` `access_token`,
  pass as `FLY_API_TOKEN`.

## Key files (verified this session)

- Wallet pairing claimant: `selfsame/src-tauri/src/cbcl_pairing.rs`
  (`cbcl_pairing_start`), `selfsame/src-tauri/src/cbcl_context.rs`
  (`gate_invitation_origin`, `held_trust_records`, `record_pairing_trust`,
  `assemble_claimant`), `selfsame/crates/selfsame-app-identity/src/cbcl_relay.rs`
  (`verify_invitation_origin`, `eligible`, `RelayPolicy`).
- Wallet pairing UI: `selfsame/src/pairing.js`, `selfsame/src/index.html`.
- Invitation decode + ceremony types: `selfsame/crates/selfsame-pairing/src/lib.rs`
  (`decode_selfsame_invitation`, `Invitation`, `CredentialTransfer`,
  `SelfsameVerificationContext`, `recognise_transfer_claims`).
- CON-220 profile authentication: `selfsame/crates/selfsame-app-identity-net/src/profile.rs`
  (`fetch`, `fetch_or_cached`).
- cbcl-pairing protocol: `cbcl-pairing/src/endpoint.rs` (`apply_intent`),
  `cbcl-pairing/src/profile.rs` (`recognise_intent`, `CREDENTIAL_APPLICATION`
  constant — the F-1 false-premise field), `cbcl-pairing/src/wire.rs`
  (`valid_application_id`).
- Browser allocator: `cbcl-bus/apps/cbcl_chat/priv/web/cbcl-invite.mjs`,
  `cbcl-bus/apps/cbcl_chat/priv/web/app.js` (`paintCbclInviteAffordance`),
  `cbcl-bus/fly.toml` (relay on :9443 → internal 18081).
- Specs: `selfsame/specs/SPEC-008-production-pairing-claimant.md`,
  `selfsame/specs/trajectory/SPEC-008/` (the 0.4.0 draft, the REQ-909 review, the
  completion runbook, and this handoff).

## First actions for the new agent

1. Read this file, the 0.4.0 draft, the REQ-909 review, and the completion runbook.
2. Invoke the `anuna-dev` skill; verify the toolchain.
3. Ask the user: rework to v0.4.1 (path 1) or reconsider toward enrol→pair (path 2)?
   Do not start building either until they choose and, for path 1, until a fresh
   adversarial review of the reworked design passes.
4. Whichever path: trace the real code before writing prose about it.

State to preserve: the user wants standalone TOFU pairing (no allowlist, no
enrolment step) if it can be made sound; the review shows that is a genuine
cross-repo effort with three critical holes to close, not a wallet patch. Be honest
about that cost every time it comes up.
