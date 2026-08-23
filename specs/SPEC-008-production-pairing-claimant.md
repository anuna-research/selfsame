---
id: SPEC-008
title: Production Pairing Claimant — Transport, Real Credential, and Origin Trust
status: implemented
version: 0.2.2
tier: 1
review-gate: approved
candidate-amendment: "[[spec-008-0.4.25-fail-closed-room-start-and-singular-authority#CON-984]] — standalone first-contact TOFU candidate; no implementation or production authority before coordinated Tier-1 PASS"
candidate-review-gate: not-approved; implementation-prohibited-pending-coordinated-fresh-cross-model-review
depends-on: "[[SPEC-007-cbcl-pairing-cutover]]; [[SPEC-004-application-scoped-identity]]; [[SPEC-003-android-apk-distribution]]; cbcl-pairing SPEC-001"
last-updated: 2026-08-23
---

# SPEC-008 — Production Pairing Claimant: Transport, Real Credential, and Origin Trust

> **Open candidate increment.**
> [[spec-008-0.4.25-fail-closed-room-start-and-singular-authority#CON-984]] specifies
> standalone first-contact TOFU. Its coordinated Tier-1 review gate is open.
> The implemented 0.2.2 baseline remains approved, but the candidate authorizes
> no implementation, allocation, release, or deployment.

## Orientation

Intent: Make the wallet's cbcl-pairing claimant work outside the loopback demo — a real
TLS WebSocket to a profile-trusted relay, a verification context built from the person's
real stored identity, and live approve/decline — without touching [[SPEC-007-cbcl-pairing-cutover#REQ-809]]'s
production-allocation hold, which this document cannot and does not amend.

Metaphor: the demo built the whole ceremony inside one locked room. This spec gives the
claimant a door and a passport — but the door only opens toward addresses the person's
own authenticated profile already vouches for.

Structure:

```
 QR / paste                 src-tauri shell                       relay operator
┌──────────┐  carrier   ┌──────────────────────┐   wss://…/relay ┌─────────────┐
│ scan()   │──────────▶ │ [[#CON-901]] origin   │◀───binary WS───▶│ blind relay │
│ (exists) │  b64u      │ gate + WSS transport │    frames        └─────────────┘
└──────────┘            └─────────┬────────────┘
                                  │ frames in / effects out (sans-io)
                        ┌─────────▼────────────┐
                        │ ClaimantRelaySession │  (upstream engine, already
                        │ (live.rs, unchanged) │   compiled into prod builds)
                        └─────────┬────────────┘
                                  │ needs SelfsameVerificationContext
                        ┌─────────▼────────────┐
                        │ [[#CON-902]] real-    │◀── Custody, active account,
                        │ context assembly     │    issuer via webfinger
                        └──────────────────────┘
      arrows point inward: the shell feeds the sans-io core; the core opens nothing
```

Decisions:    [[#ADR-901]] TLS via the existing tungstenite dep, rustls feature ·
              [[#ADR-902]] origin trust anchored in the authenticated profile, not a
              compiled endpoint table · [[#ADR-903]] the demo fixture is retired from
              reachability, not deleted
Load-bearing: [[#REQ-901]] WSS transport · [[#REQ-902]] real verification context ·
              [[#REQ-905]] carrier binding · [[#REQ-906]] profile-anchored origin trust
Controls:     [[#REQ-902]] a non-demo build SHALL NOT construct the verification context
                from `local_demo` or any compiled test fixture
              [[#REQ-905]] the carrier SHALL NOT be treated as an OS-navigable URL
              [[#REQ-906]] no socket SHALL open toward an origin the authenticated
                profile does not list with an approved conformance digest
              [[#REQ-907]] this spec SHALL NOT alter [[SPEC-007-cbcl-pairing-cutover#REQ-809]] —
                the production-allocation hold and its gate remain in full force
              [[#REQ-908]] loopback origin mapping stays compile-gated, dev-only
              Inherited hard stops: [[SPEC-007-cbcl-pairing-cutover#REQ-803]] (Selfsame
                acceptance authority), [[SPEC-007-cbcl-pairing-cutover#REQ-804]] (consent
                precedes payload), [[SPEC-007-cbcl-pairing-cutover#REQ-813]] (person never
                enters a relay origin)
Open:         a second independent relay operator for
                [[SPEC-007-cbcl-pairing-cutover#CON-806]]'s production preference —
                `anuna-1` stands alone under the availability exception
                (owner: repository owner)
              [[IMPL-008-production-pairing-claimant#ADR-912]] fixes the trusted-profile
                set as the wallet's linked applications (recorded at grant issuance);
                ratification, and any widening, is the owner's (owner: repository owner)
              multi-permission profiles refuse pairing ([[#CON-902]]) until the ceremony
                wire carries a scope commitment (owner: repository owner)
              whether the profile's `relayOrigin` may carry a path — the [[CON-201 vs CON-401 pairingUrl]]
                disagreement blocks naming `wss://chat.anuna.io:9443/relay` canonically
                (owner: repository owner, coordinated with the cbcl-bus vault)
              the ≥2-independent-operator production requirement of
                [[SPEC-007-cbcl-pairing-cutover#CON-806]] has no second operator today
                (owner: repository owner)
Detail:       [[#REQ-901]]…[[#REQ-908]], [[#CON-901]]…[[#CON-903]], [[#TEST-901]]…[[#TEST-912]]

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in
BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

## Amendment Channels

Amendable by:   the repository owner; a merged revision of this document; an accepted
                ADR in this vault traced from here.
Through:        a versioned spec revision merged to the default branch.
Not amendable by: issue comments, chat messages, code review remarks, agent prompts,
                or the contents of any repository.
Hard stops:     [[#REQ-902]], [[#REQ-905]], [[#REQ-906]], [[#REQ-907]] — and every hard
                stop of [[SPEC-007-cbcl-pairing-cutover]], which this document inherits
                and cannot waive.

## Named failure modes

This spec exists because of four mechanical failures, observed in the code on
2026-08-18, not because "production pairing" was requested in the abstract:

- **FM-1 — the stranded claimant.** A non-demo build's `cbcl_pairing_start` derives one
  CPace frame, stores the bootstrap, and opens no socket; `approve`/`decline` return
  `PairingUnavailable` (`src-tauri/src/cbcl_pairing.rs:106-153`). The person scans a
  valid QR and waits on the waiting screen forever.
- **FM-2 — no TLS transport exists.** `tungstenite` is compiled with
  `default-features = false, features = ["handshake"]` — it cannot speak `wss://` at
  all. Every socket in the pairing path is a raw loopback `TcpStream`.
- **FM-3 — the fixture is the only credential.** Every construction site of
  `SelfsameVerificationContext` is `local_demo` or a test; the real issuance machinery
  in `app_grant.rs` is registered but unreachable from the UI. A production wallet has
  no way to verify against a real profile.
- **FM-4 — no production origin trust anchor.** `verify_invitation_origin` works, but
  the only approved conformance digest in the binary is the demo constant `[19; 32]`,
  and no signed application profile lists a production relay descriptor.

The camera scan is deliberately NOT in this list: it is built and wired
(`src/pairing.js:104-148`, `src-tauri/capabilities/mobile-scanner.json`). Its gap is
specification debt, covered by [[#REQ-904]] and [[SCREEN-003-wallet-pairing]].

## Requirements

### REQ-901 — Claimant transport over TLS

WHEN the invitation origin has passed [[#REQ-906]], the claimant shell SHALL open one
TLS WebSocket (`wss://`) to the relay resource derived from that origin, and SHALL pump
binary WebSocket messages between the socket and the sans-io
`ClaimantRelaySession` until a terminal outcome, WITHIN the session's existing timeout
discipline, FOR the person pairing a wallet, WITH the ceremony reaching the same
terminal states the demo transport reaches today.

The origin→resource mapping SHALL be: canonical `https://host[:port]` origin →
`wss://host[:port]/relay`, matching the upstream cbcl-pairing SPEC-001 WebSocket shell.
The loopback mapping (`https://localhost:PORT` → plaintext `ws://`) SHALL remain
compile-gated to the development capability and absent from ordinary builds
([[SPEC-007-cbcl-pairing-cutover|IMPL-007's dev capability]] is unchanged).

Trace: [[#TEST-901]] [[#TEST-902]] [[#CON-901]] [[#OBS-901]]

### REQ-902 — Real verification context; fixture prohibition

The claimant SHALL construct its `SelfsameVerificationContext` exclusively from the
person's real stored identity: the authenticated application profile bytes (verified
under [[SPEC-004-application-scoped-identity#CON-201]]), the active account, the
custody-held device key, a fresh [[SPEC-004-application-scoped-identity#CON-207]]
device proof, and issuer state resolved through the existing verified webfinger path.

A non-demo build SHALL NOT construct any part of the verification context from
`local_demo`, from `LOCAL_CONFORMANCE_DIGEST`, or from any compiled test fixture.
Enforcement is compile-time: the fixture module stays behind the `local-pairing-demo`
feature, so the prohibited path does not exist in the ordinary binary — verified by
symbol absence ([[#TEST-904]]), not by a runtime check.

Trace: [[#TEST-903]] [[#TEST-904]] [[#CON-902]] [[#OBS-902]]

### REQ-903 — Live approve and decline

WHEN a verified session has displayed the recognised intent, `cbcl_pairing_approve`
and `cbcl_pairing_decline` SHALL commit the person's decision through the live session
over the [[#REQ-901]] transport, FOR non-demo builds, WITH the same terminal semantics
the demo build has today ([[SPEC-007-cbcl-pairing-cutover#REQ-804]] consent ordering
unchanged). The `PairingUnavailable` stubs SHALL be removed from the non-demo build.

Trace: [[#TEST-905]] [[#CON-901]]

### REQ-904 — Scan and paste converge (specification of existing behaviour)

The scan path and the paste path SHALL deliver byte-identical carriers to one entry
point, and the three distinct scan failure causes — permission refused by the platform,
permission declined by the person, plugin unavailable — SHALL each produce its own
message, FOR the Android wallet, WITH no cause collapsed into another (the
[[SPEC-003-android-apk-distribution#BUG-202]] lesson). Screen detail lives in
[[SCREEN-003-wallet-pairing]].

Trace: [[#TEST-906]] [[#TEST-907]]

### REQ-905 — Carrier binding

The QR payload SHALL be exactly the unpadded base64url encoding of the cbcl invitation
carrier — no URL scheme, no prefix, no wrapper — identical to the paste payload. The
wallet SHALL NOT treat the carrier as an OS-navigable URL, and SHALL fully recognise it
through the upstream invitation recogniser before any state change
([[LangSec]]: recognition precedes action; the grammar is upstream
cbcl-pairing SPEC-001 CON-001's carrier plus base64url transport encoding).

Trace: [[#TEST-908]] [[#CON-901]]

### REQ-906 — Profile-anchored origin trust

The claimant SHALL open a socket only toward an invitation origin that matches exactly
one eligible `cbclPairingRelays` descriptor in the person's authenticated application
profile, where eligible means: operator not forbidden, conformance evidence digest
present in the compiled approved registry ([[#CON-903]]), and non-loopback in ordinary
builds. Zero matches and multiple matches SHALL both refuse before any network I/O. A refusal
SHALL surface as one distinct, secret-free message and end the attempt: the wallet
SHALL NOT substitute another descriptor, retry a different origin, or offer any repair
path — the person SHALL NOT be offered any way to enter, choose, or repair a relay
origin (inherited: [[SPEC-007-cbcl-pairing-cutover#REQ-813]]).

Trace: [[#TEST-909]] [[#TEST-910]] [[#CON-903]] [[#OBS-903]]

### REQ-907 — The production-allocation hold is out of scope

This specification SHALL NOT alter, reinterpret, or provide any enablement path for
[[SPEC-007-cbcl-pairing-cutover#REQ-809]] or the SPEC-007 Production gate. A wallet
satisfying every requirement here can *claim* an invitation wherever one lawfully
exists (a development relay; a future gated production relay); it does not make
production invitations exist.

Trace: [[#TEST-911]]

### REQ-908 — Truthful surface

The pairing screens SHALL state capability truthfully per build: demo-specific error
copy ("check the demo server and adb reverse") SHALL NOT appear in non-demo builds, and
the "does not enable production pairing" boundary SHALL be derived from the build's
actual capability rather than hardcoded prose.

Trace: [[#TEST-912]] [[SCREEN-003-wallet-pairing]]

### NFR-901 — TLS posture

The `wss://` client SHALL verify server certificates against the platform or bundled
`rustls` roots, SHALL NOT offer a plaintext or invalid-certificate fallback, and SHALL
fail closed on any TLS error, UNDER all non-demo builds, WITH zero downgrade paths.

Trace: [[#TEST-902]] [[#CON-901]]

### NFR-902 — Secret-free observability (inherited)

[[SPEC-007-cbcl-pairing-cutover#NFR-801]] applies unchanged to every new transport and
context-assembly effect: no carrier bytes, secrets, frame plaintext, or credential
material in logs or errors.

Trace: [[#TEST-901]] [[#OBS-901]]

## Contracts

### CON-901 — WSS claimant transport shell

Endpoint/Interface: a shell function taking (verified origin, `ClaimantRelaySession`)
and driving one `wss://host[:port]/relay` connection: send `session.start()`, then loop
receive-binary → `session.receive(bytes)` → execute effects (send / display-intent /
terminal), exactly as the demo loop does today but over TLS.
Input grammar: one canonical CBOR `ClientMessage` per binary WebSocket message,
recognised solely by the upstream pinned `decode_client_message` — this shell SHALL NOT
parse relay bytes itself (one parser per language; the recogniser is upstream's).
Pre-conditions: [[#REQ-906]] passed; context assembled per [[#CON-902]].
Post-conditions: exactly one terminal outcome; socket closed; no identity side effect
on any non-accepted outcome ([[SPEC-007-cbcl-pairing-cutover#REQ-812]]).
Error model: TLS failure, connect failure, timeout, and close-before-terminal each map
to distinct, secret-free `UiError` values; none is retried silently.
Implements: [[#REQ-901]] [[#REQ-903]] [[#REQ-905]] [[#NFR-901]]
Verified by: [[#TEST-901]] [[#TEST-902]] [[#TEST-905]] [[#TEST-908]]

### CON-902 — Real verification-context assembly

Endpoint/Interface: a constructor producing `SelfsameVerificationContext` inside the
Tauri shell. Every field maps to its authoritative source, mirroring the
[[SPEC-007-cbcl-pairing-cutover#CON-803]] table:

| Field | Authoritative source |
|---|---|
| `profile` | authenticated profile bytes, verified under [[SPEC-004-application-scoped-identity#CON-201]] |
| `account` | the wallet's active account context |
| `device_public_key` | custody-held device key (`Custody::use_hierarchy_root` path) |
| `proof` | deferred [[SPEC-004-application-scoped-identity#CON-207]] device proof — its challenge binds the SHA-256 of the exact grant octets, so the adapter completes and verifies it at delivery from shell entropy plus a custody-backed signer (`DeferredProofSigner`); a context whose proof is absent with no signer refuses closed |
| `operation_permissions` | the matched profile's single `allowedPermissions` entry; a profile declaring more than one refuses (`PairingScopeAmbiguous`) until the ceremony wire carries a scope commitment |
| `issuer` / `jrd` | verified webfinger resolution (existing `fetch_and_verify` path) |
| `now` / `clock_skew_seconds` | shell clock; skew per SPEC-004's accepted bound |
| `freshness` | `SessionEstablishment` |

Pre-conditions: an unlocked custody session; an authenticated profile.
Post-conditions: a context containing no fixture-derived bytes.
Error model: any missing source refuses assembly before the transport opens; the
refusal names the missing capability, never the missing bytes.
Implements: [[#REQ-902]]
Verified by: [[#TEST-903]] [[#TEST-904]]

### CON-903 — Approved-conformance registry

Endpoint/Interface: a compiled, release-reviewed list of `[u8; 32]` conformance
evidence digests replacing `[LOCAL_CONFORMANCE_DIGEST]` in the non-demo
`RelayPolicy`. Each entry SHALL trace to published relay conformance evidence and the
operator that produced it; adding an entry is a reviewed release change, never runtime
configuration ([[SPEC-007-cbcl-pairing-cutover#CON-805]] release semantics apply).
Pre-conditions: the evidence document exists and is digest-stable.
Post-conditions: `verify_invitation_origin` admits exactly the descriptors whose
digests appear here.
Error model: an empty registry means every non-loopback origin refuses — a valid,
fail-closed state for builds shipped before any operator publishes evidence.
Implements: [[#REQ-906]]
Verified by: [[#TEST-909]] [[#TEST-910]]

## Decisions

### ADR-901 — TLS through the existing tungstenite dependency

Add the `rustls` TLS feature to the already-present `tungstenite` dependency and keep
the blocking, sans-io-driven loop shape the demo proved. Rejected: `tokio-tungstenite`
(drags an async runtime into a loop that is deliberately synchronous around a sans-io
core); a JS-side WebSocket in the webview (would require CSP loosening and moves relay
bytes into the webview, against the demo's own layering). Simplicity Ladder rung 4:
the dependency and the loop both already exist; only the TLS feature is new.

### ADR-902 — Origin trust lives in the profile, not a compiled endpoint table

The LinkCode path compiles its endpoint table (`net.rs`, "a URL in a scanned code is a
phishing primitive"). The cbcl invitation deliberately carries its relay origin, so the
same defence must anchor elsewhere: the authenticated profile's `cbclPairingRelays`
descriptors plus the compiled digest registry ([[#CON-903]]). A scanned origin is
never trusted for being scanned; it is trusted for being pre-declared by an
authenticated profile the person already holds. Rejected: compiling relay origins into
the wallet (couples wallet releases to relay topology; SPEC-007 CON-806 already chose
profile-carried descriptors).

### ADR-903 — The fixture is unreachable, not deleted

`local_demo` and the `local-pairing-demo` feature remain, compile-gated, as the
development harness ([[SPEC-007-cbcl-pairing-cutover]] evidence path needs them). What
changes: the non-demo build gains the real path, and [[#TEST-904]] proves fixture
symbols stay out of ordinary builds. Deleting the fixture would destroy the only
loopback e2e evidence harness for no security gain.

## Tests

Core (writable in one sitting, no new rig):

- **TEST-901** (positive, [[#REQ-901]]): claimant completes a ceremony over `wss://`
  against a loopback TLS relay (self-signed root injected into the test trust store);
  terminal `accepted` reached; log capture contains no carrier or frame bytes.
- **TEST-902** (negative-input, [[#NFR-901]]): invalid certificate → distinct TLS
  error, no bytes sent, no fallback attempt observed.
- **TEST-903** (positive, [[#REQ-902]]): context assembled from a real custody store
  and authenticated profile; ceremony verifier accepts; every field's source asserted.
- **TEST-904** (prohibited-action, [[#REQ-902]]): the non-demo binary contains no
  `local_demo` symbols and no `[19; 32]` digest (nm/strings assertion), and assembly
  with a locked custody refuses before any socket opens.
- **TEST-905** (positive, [[#REQ-903]]): non-demo approve and decline each drive the
  live session to its matching terminal state; the `PairingUnavailable` stub is gone.
- **TEST-906** (positive, [[#REQ-904]]): scan-delivered and pasted carriers produce
  byte-identical `cbcl_pairing_start` inputs.
- **TEST-907** (negative-input, [[#REQ-904]]): the three scan failure causes produce
  three distinct messages (unit-level; device confirmation is depth).
- **TEST-908** (negative-input, [[#REQ-905]]): a carrier wrapped in a URL scheme, with
  padding, or with a legacy prefix is refused by recognition before any state change.
- **TEST-909** (positive + negative, [[#REQ-906]]): origin matching exactly one
  eligible descriptor proceeds; zero-match and two-match both refuse with no socket
  opened (prohibited-action assertion on connection attempts).
- **TEST-910** (negative, [[#CON-903]]): descriptor with an unregistered conformance
  digest refuses; empty registry refuses every non-loopback origin.
- **TEST-911** (scope-invariant, [[#REQ-907]]): `PRODUCTION_ALLOCATION_ENABLED`
  remains `false`; `require_production_allocation()` still fails closed; the SPEC-007
  live-relay assertion suite passes unchanged.
- **TEST-912** (positive, [[#REQ-908]]): non-demo build renders no demo-specific error
  copy; the capability boundary line reflects the build.

Depth (needs a rig or a second party; deferrable with owner):

- **TEST-913** (owner: repository owner): ceremony against the real
  `chat.anuna.io` relay deployment once a descriptor and published evidence exist.
- **TEST-914** (owner: repository owner): on-device Android scan → wss ceremony via a
  real network (no `adb reverse`).
- **TEST-915** (owner: cbcl security owner): two-operator selection behaviour per
  [[SPEC-007-cbcl-pairing-cutover#CON-806]] against two independently operated relays.

Mutation gate: disable the origin check → [[#TEST-909]] must fail; accept an invalid
certificate → [[#TEST-902]] must fail; reintroduce the fixture context in non-demo →
[[#TEST-904]] must fail.

## Observability

- **OBS-901** — transport lifecycle events (connect, terminal outcome, close reason),
  secret-free, per [[#NFR-902]].
- **OBS-902** — context assembly refusals, by missing-capability class.
- **OBS-903** — origin-trust refusals, by class (zero-match / multi-match /
  unregistered digest / loopback-in-release).

## Traceability

| Requirement | Contract | Tests |
|---|---|---|
| REQ-901 | CON-901 | TEST-901, TEST-902 |
| REQ-902 | CON-902 | TEST-903, TEST-904 |
| REQ-903 | CON-901 | TEST-905 |
| REQ-904 | — | TEST-906, TEST-907 |
| REQ-905 | CON-901 | TEST-908 |
| REQ-906 | CON-903 | TEST-909, TEST-910 |
| REQ-907 | — | TEST-911 |
| REQ-908 | — | TEST-912 |
| NFR-901 | CON-901 | TEST-902 |
| NFR-902 | CON-901 | TEST-901 |

## Changelog

- **0.3.0-draft — 2026-08-22 — first-contact admission (REQ-909): authored,
  adversarially reviewed, REJECTED, withdrawn the same day.** The review
  found the mechanism had no wire source (the invitation's `application`
  member is the constant `anuna.io/credential/v1`, never an
  `applicationId`) and that its pre-consent publication/provisioning
  violated [[SPEC-007-cbcl-pairing-cutover#REQ-812]], an inherited
  unwaivable hard stop — a declined rogue ceremony would still have handed
  the attacker a fresh account DID. Every normative edit is reverted; this
  document is again exactly 0.2.2. Record:
  `specs/trajectory/SPEC-008/req-909-adversarial-review-2026-08-22.md`.
  First contact goes through
  [[IMPL-008-production-pairing-claimant#ADR-913]]'s enrolment wire, which
  the review itself endorses; the numbers REQ-909/TEST-916/TEST-917 are
  burned and not reused.
- **0.2.2** — status `implemented`, review gate `approved`: the repository
  owner reviewed and merged PR #43 (2026-08-20) after the fresh-context
  adversarial review closed with zero blocking findings
  (`evidence/spec-008-phase-3-gates.yaml`). Depth tests TEST-913/914/915
  stay open with their named owners; they gate live production claims,
  not this document's lifecycle.
- **0.2.1** — [[#CON-903]] first registry entry ratified (owner-directed,
  2026-08-20): `anuna-1`, the SHA-256 of cbcl-bus
  `docs/relay-conformance-anuna-1.md` (cbcl-bus PR #97). The publication
  Open item closes; the second-operator item remains.
- **0.2.0** — implementation findings folded back (branch
  `feature/spec-008-production-claimant`, [[IMPL-008-production-pairing-claimant]]):
  the CON-207 proof is grant-bound and therefore deferred to delivery; the
  ceremony scope is the profile's single allowed permission; the trusted-profile
  set is ADR-912's linked applications. Review gate unchanged: `not-approved`,
  Tier 1 review outstanding.
- **0.1.0** — first draft, authored from the 2026-08-18 gap analysis of the vault and
  the code (four named failure modes; camera scanning found already built and moved to
  specification debt rather than missing work).
