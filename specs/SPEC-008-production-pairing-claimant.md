---
id: SPEC-008
title: Production Pairing Claimant — Transport, Real Credential, and Origin Trust
status: draft
version: 0.5.1-draft
tier: 1
review-gate: not-approved; implementation-prohibited-pending-one-coordinated-fresh-cross-model-review
authority-form: consolidated-direct-current-authority
implementation-baseline: 0220cec2dec44cd95d4f411ea4814d790b6716d2
generation-model-family: OpenAI GPT-5
generation-model-version: gpt-5.6-sol
generation-session: 01a029aa-9127-7c42-ad28-81512b91ded6
generation-synthesis-trajectory: "owner-authorized standalone architecture -> F-A through F-E code traces -> rejected 0.4.0 through 0.4.26 reviews -> N11 stopping rule -> consolidated parent reissue"
depends-on: "[[SPEC-007-cbcl-pairing-cutover]]; [[SPEC-004-application-scoped-identity]]; [[SPEC-003-android-apk-distribution]]; cbcl-pairing SPEC-001"
amends: "[[SPEC-007-cbcl-pairing-cutover#REQ-812]] for credential/v2 reverse issuance only"
last-updated: 2026-08-24
---

# SPEC-008 — Production Pairing Claimant: Transport, Real Credential, and Origin Trust

> **Consolidated current-law reissue.** Version 0.5.1 states the standalone
> first-contact authority directly. Trajectory documents and review reports
> supply evidence only. They supply no current values.
> This draft authorizes no implementation, allocation, release, or deployment
> before one coordinated fresh-context Tier-1 PASS.

## Orientation

Intent: Link a wallet to a new application through cbcl-pairing without prior
enrolment or a compiled relay allowlist. The wallet authenticates the application
live, asks about the exact application-relay pair, and defers every identity effect
until the person approves the authenticated intent.

Metaphor: the invitation is an introduction, not a reference. The wallet checks
the application's passport, asks whether this application may use this relay, and
only then creates the application's account key.

Structure:

```
 invitation       live profile       exact-pair policy       cbcl-pairing
┌──────────┐     ┌─────────────┐     ┌────────────────┐     ┌────────────┐
│ recognise│────▶│ CON-220 auth│────▶│ pair policy    │────▶│ CPace relay│
└──────────┘     └─────────────┘     └────────────────┘     └──────┬─────┘
                                                                  │
                 ┌────────────────┐     ┌────────────────┐         │
                 │ post-consent   │◀────│ authenticated  │◀────────┘
                 │ scope + grant  │     │ exact intent   │
                 └────────────────┘     └────────────────┘
```

Decisions:    [[SPEC-008-production-pairing-claimant#ADR-902]] person-owned pair-scoped TOFU · [[SPEC-008-production-pairing-claimant#ADR-963]]
              typed unavailability before policy · [[SPEC-008-production-pairing-claimant#ADR-903]] fixture isolation
Load-bearing: [[SPEC-008-production-pairing-claimant#REQ-906]] exact-pair trust · [[SPEC-008-production-pairing-claimant#REQ-1005]] protocol and version
              isolation · [[SPEC-008-production-pairing-claimant#NFR-928]] total fail-closed consumers
Controls:     [[SPEC-008-production-pairing-claimant#REQ-902]] fixture data SHALL NOT enter an ordinary build
              [[SPEC-008-production-pairing-claimant#REQ-905]] the carrier SHALL NOT become an OS-navigable URL
              [[SPEC-008-production-pairing-claimant#REQ-906]] no socket SHALL open before live authentication and consent
              [[SPEC-008-production-pairing-claimant#CON-903]] policy is exact `(applicationId, relayOrigin)`, never relay-only
              [[SPEC-008-production-pairing-claimant#REQ-907]] production allocation remains closed pending its gate
              [[SPEC-008-production-pairing-claimant#CON-986]] no credential/v2 identity effect precedes final approval
              A fresh Tier-1 PASS precedes every plan or implementation change
              Production deployment requires separate owner approval
Open:         the coordinated fresh-context Tier-1 review (owner: repository owner)
              every production gate listed in [[SPEC-008-production-pairing-claimant#CON-985]] (owner: named gate owners)
Detail:       [[SPEC-008-production-pairing-claimant#REQ-901]], [[SPEC-008-production-pairing-claimant#REQ-906]], [[SPEC-008-production-pairing-claimant#REQ-1005]], [[SPEC-008-production-pairing-claimant#NFR-928]],
              [[SPEC-008-production-pairing-claimant#CON-903]], [[SPEC-008-production-pairing-claimant#CON-985]], [[SPEC-008-production-pairing-claimant#TEST-1156]], [[SPEC-008-production-pairing-claimant#TEST-1157]]

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in
BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

## Amendment Channels

Amendable by:   the repository owner; a merged revision of this document; an accepted
                ADR in this vault traced from here.
Through:        a versioned spec revision merged to the default branch.
Not amendable by: issue comments, chat messages, code review remarks, agent prompts,
                or the contents of any repository.
Hard stops:     [[SPEC-008-production-pairing-claimant#REQ-902]], [[SPEC-008-production-pairing-claimant#REQ-905]], [[SPEC-008-production-pairing-claimant#REQ-906]], [[SPEC-008-production-pairing-claimant#REQ-907]],
                [[SPEC-007-cbcl-pairing-cutover#REQ-812]], the coordinated Tier-1
                PASS, and separate production deployment approval.

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
- **FM-4 — no production origin trust anchor.** `verify_invitation_origin` works.
  The binary contains only the demo conformance digest `[19; 32]`. No signed
  application profile lists a production relay descriptor.

The camera scan is deliberately NOT in this list: it is built and wired
(`src/pairing.js:104-148`, `src-tauri/capabilities/mobile-scanner.json`). Its gap is
specification debt, covered by [[SPEC-008-production-pairing-claimant#REQ-904]] and [[SCREEN-003-wallet-pairing]].

## Requirements

### REQ-901 — Claimant transport over TLS

WHEN the invitation origin has passed [[SPEC-008-production-pairing-claimant#REQ-906]], the claimant shell SHALL open one
TLS WebSocket (`wss://`) to the derived relay resource. The shell SHALL pump binary
messages between that socket and the sans-io `ClaimantRelaySession`. It SHALL retain
the existing timeout discipline and terminal states.

The origin→resource mapping SHALL be: canonical `https://host[:port]` origin →
`wss://host[:port]/relay`, matching the upstream cbcl-pairing SPEC-001 WebSocket shell.
The loopback mapping (`https://localhost:PORT` → plaintext `ws://`) SHALL remain
compile-gated to the development capability and absent from ordinary builds
([[SPEC-007-cbcl-pairing-cutover|IMPL-007's dev capability]] is unchanged).

Trace: [[SPEC-008-production-pairing-claimant#TEST-901]] [[SPEC-008-production-pairing-claimant#TEST-902]] [[SPEC-008-production-pairing-claimant#CON-901]] [[SPEC-008-production-pairing-claimant#OBS-901]]

### REQ-902 — Two-stage identity context; fixture prohibition

Before the preliminary exact-intent decision, the claimant SHALL construct only a
zero-effect authenticated plan. It contains the live profile, recognised application
facts, authenticated account-principal digest and scope identifier, profile-declared
issuer constraints, and public ceremony bindings. It contains no derived application key,
issuer DID, WebFinger JRD, signature, or publication result.

Preliminary approval authorizes one hierarchy derivation inside a zeroizing custody
closure. It authorizes pure `HomeKey::home_did`, fingerprint computation, and preview
DID disclosure to the authenticated application. It authorizes no signature,
publication, grant, alias, bundle, or durable identity write. The preliminary screen
SHALL state the disclosure.

After the authenticated comparison or binding result, the wallet SHALL display its
locally recomputed DID and fingerprint. It SHALL also display the complete
authenticated transition and ask for final release approval. Final decline zeroizes
preview state and leaves no identity residue.

Final approval authorizes a new custody operation. It re-derives the same key and
requires byte-for-byte equality with the preview DID. Creation, signing, publication,
live issuer and WebFinger verification, and delivery of the application identity and
grant occur only then. CPace session-key computation is protocol transport work, not
an application identity effect.

A non-demo build SHALL NOT construct any part of the verification context from
`local_demo`, from `LOCAL_CONFORMANCE_DIGEST`, or from any compiled test fixture.
Enforcement occurs at compile time. The fixture module stays behind the
`local-pairing-demo` feature. The prohibited path is absent from the ordinary binary.
[[SPEC-008-production-pairing-claimant#TEST-904]] verifies symbol absence instead of a runtime check.

Trace: [[SPEC-008-production-pairing-claimant#TEST-903]] [[SPEC-008-production-pairing-claimant#TEST-904]] [[SPEC-008-production-pairing-claimant#CON-902]] [[SPEC-008-production-pairing-claimant#OBS-902]]

### REQ-903 — Live approve and decline

WHEN a verified session has displayed the recognised intent, the live decision
commands SHALL commit the person's decision. Those commands are
`cbcl_pairing_approve` and `cbcl_pairing_decline`. They use [[SPEC-008-production-pairing-claimant#REQ-901]] in non-demo
builds and retain SPEC-007 REQ-804 ordering. The `PairingUnavailable` stubs SHALL be
absent from the non-demo build.

Trace: [[SPEC-008-production-pairing-claimant#TEST-905]] [[SPEC-008-production-pairing-claimant#CON-901]]

### REQ-904 — Scan and paste converge (specification of existing behaviour)

The scan path and paste path SHALL deliver byte-identical carriers to one entry point.
The Android wallet SHALL distinguish three scan failures. They are platform refusal,
person refusal, and plugin unavailability. Each produces its own message. Screen
detail lives in [[SCREEN-003-wallet-pairing]].

Trace: [[SPEC-008-production-pairing-claimant#TEST-906]] [[SPEC-008-production-pairing-claimant#TEST-907]]

### REQ-905 — Carrier binding

The QR payload SHALL equal the unpadded base64url cbcl invitation carrier. It has no
URL scheme, prefix, or wrapper. It is identical to the paste payload. The wallet SHALL
NOT treat it as an OS-navigable URL. The upstream invitation recogniser SHALL fully
recognise it before any state change
(LangSec: recognition precedes action; the grammar is upstream
cbcl-pairing SPEC-001 CON-001's carrier plus base64url transport encoding).

Trace: [[SPEC-008-production-pairing-claimant#TEST-908]] [[SPEC-008-production-pairing-claimant#CON-901]]

### REQ-906 — Live application authentication and exact-pair TOFU

The claimant SHALL authenticate the invitation's application live under CON-220
before it opens any relay socket. The authenticated profile SHALL list the exact
invitation relay origin.

The wallet SHALL evaluate trust for the exact tuple
`(authenticatedApplicationId, canonicalRelayOrigin)`. Relay-only trust SHALL NOT
authorize a new application.

WHEN the tuple is absent, the wallet SHALL show one new-relay decision. The surface
SHALL name the authenticated application and canonical relay origin. Approval SHALL
seal the tuple into the person's policy before socket creation. Rejection SHALL create
no policy entry, socket, scope, key, alias, DID, grant, or publication.

WHEN the tuple is present and valid, the wallet MAY proceed without another TOFU
prompt. A changed application or changed relay origin is a new tuple and SHALL prompt.

The person SHALL NOT enter, choose, or repair a relay origin. A profile mismatch,
authentication failure, malformed origin, or policy-store failure SHALL end the
attempt before network I/O.

Trace: [[SPEC-008-production-pairing-claimant#TEST-909]] [[SPEC-008-production-pairing-claimant#TEST-910]] [[SPEC-008-production-pairing-claimant#CON-903]] [[SPEC-008-production-pairing-claimant#OBS-903]]

### REQ-907 — The production-allocation hold is out of scope

This specification SHALL NOT alter, reinterpret, or provide any enablement path for
[[SPEC-007-cbcl-pairing-cutover#REQ-809]] or the SPEC-007 Production gate. A wallet
satisfying every requirement here can *claim* an invitation wherever one lawfully
exists (a development relay; a future gated production relay); it does not make
production invitations exist.

Trace: [[SPEC-008-production-pairing-claimant#TEST-911]]

### REQ-908 — Truthful surface

The pairing screens SHALL state capability truthfully per build. Demo-specific error
copy SHALL NOT appear in non-demo builds. The production-pairing boundary SHALL derive
from the build's actual capability, not hardcoded prose.

Trace: [[SPEC-008-production-pairing-claimant#TEST-912]] [[SCREEN-003-wallet-pairing]]

### NFR-901 — TLS posture

The `wss://` client SHALL verify certificates against platform or bundled `rustls`
roots. It SHALL NOT offer a plaintext or invalid-certificate fallback. Every non-demo
build SHALL fail closed on a TLS error with no downgrade path.

Trace: [[SPEC-008-production-pairing-claimant#TEST-902]] [[SPEC-008-production-pairing-claimant#CON-901]]

### NFR-902 — Secret-free observability (inherited)

[[SPEC-007-cbcl-pairing-cutover#NFR-801]] applies unchanged to every new transport and
context-assembly effect: no carrier bytes, secrets, frame plaintext, or credential
material in logs or errors.

Trace: [[SPEC-008-production-pairing-claimant#TEST-901]] [[SPEC-008-production-pairing-claimant#OBS-901]]

## Contracts

### CON-901 — WSS claimant transport shell

Endpoint/Interface: a shell function accepts a verified origin and
`ClaimantRelaySession`. It drives one `wss://host[:port]/relay` connection. It sends
`session.start()`, receives one binary frame, calls `session.receive(bytes)`, and
executes returned effects until terminal.
Input grammar: each binary WebSocket message contains one canonical CBOR
`ClientMessage`. Only the pinned upstream `decode_client_message` recognises it. This
shell SHALL NOT parse relay bytes itself.
Pre-conditions: [[SPEC-008-production-pairing-claimant#REQ-906]] passed; context assembled per [[SPEC-008-production-pairing-claimant#CON-902]].
Post-conditions: exactly one terminal outcome; socket closed; no identity side effect
on any non-accepted outcome ([[SPEC-007-cbcl-pairing-cutover#REQ-812]]).
Error model: TLS failure, connect failure, timeout, and close-before-terminal each map
to distinct, secret-free `UiError` values; none is retried silently.
Implements: [[SPEC-008-production-pairing-claimant#REQ-901]] [[SPEC-008-production-pairing-claimant#REQ-903]] [[SPEC-008-production-pairing-claimant#REQ-905]] [[SPEC-008-production-pairing-claimant#NFR-901]]
Verified by: [[SPEC-008-production-pairing-claimant#TEST-901]] [[SPEC-008-production-pairing-claimant#TEST-902]] [[SPEC-008-production-pairing-claimant#TEST-905]] [[SPEC-008-production-pairing-claimant#TEST-908]]

### CON-902 — Split authenticated plan, preview, and effect assembly

Endpoint/Interface: `prepare_claimant` returns a zero-effect authenticated plan.
`preview_claimant_identity` consumes preliminary approval. It returns only zeroizable
preview DID and fingerprint material. `complete_claimant` consumes one final-approval
capability and re-derives the approved identity for effects.

The authenticated plan contains these authoritative sources:

| Field | Authoritative source |
|---|---|
| `profile` | live CON-220-authenticated bytes |
| `application_id` | the authenticated profile, never the wire claim |
| `relay_origin` | the invitation, cross-checked against the authenticated profile |
| `account_principal_digest` | the hub-signed digest of the private pending account ID |
| `account_scope_id` | the hub-signed pending `accountScopeId` |
| `device_public_key` | the hub-signed browser-installation key in the offer |
| `operation_permissions` | the authenticated offer and profile intersection |
| `issuer_constraints` | the live profile's authenticated issuance rules |
| `now` / `clock_skew_seconds` | shell clock and the accepted SPEC-004 bound |

The hub allocates the private account ID and account scope before public-carrier
release. The signed offer binds their account-principal digest and exact scope. They
become durable account identity only in the final hub migration transaction. Decline,
expiry, or pre-commit failure deletes the pending values. The wallet SHALL NOT invent
the raw account ID or persist the scope before final status.

The browser accepts an allocation acknowledgement only for one live
`(socketGeneration, requestId)` entry and consumes that entry before displaying the
carrier. An exact active retry returns the byte-identical acknowledgement and pending
values. A concurrent different request for the same authenticated application,
handle, and enrolled key refuses. It never creates two candidate accounts.

A fresh attempt after decline, expiry, or pre-commit failure receives fresh account
and scope randomness. If the resulting preview DID differs, the wallet SHALL display
and obtain both decisions again. Prior preview consent cannot authorize it.

A crash before hub allocation commit leaves no pending value. A crash after that
commit recovers the exact bounded pending record or deletes it at expiry. A crash
during final migration recovers either the complete pending state or the complete
immutable finalized state. A crash after final commit cannot recreate legacy rows or
roll the account back.

The preliminary capability permits one zeroizing derivation and pure DID preview. It
retains no hierarchy root or private key. The final capability contains no derived
key. After final approval, it permits a separate custody call and preview equality
check. It then permits the declared issuance effects.

The executor re-derives the wallet application home key and checks the preview. It
then creates and signs the issuer state and publishes the DID. It obtains and verifies
the live WebFinger JRD against the authenticated profile and new issuer. It constructs
the grant last. It performs no issuer or JRD lookup that depends on the derived DID
before final approval. A failure compensates only effects created by this ceremony
and never operator withdrawal state.

Pre-conditions: an unlocked custody session, authenticated profile and signed offer,
exact-pair policy, authenticated preliminary intent, successful comparison or binding
result, and final approved release.

Post-conditions: one real verification context contains no fixture bytes. Every
derived or published effect traces to the approved authenticated plan.

Error model: any missing source or failed effect refuses closed. A pre-consent error
creates no identity residue.
Implements: [[SPEC-008-production-pairing-claimant#REQ-902]]
Verified by: [[SPEC-008-production-pairing-claimant#TEST-903]] [[SPEC-008-production-pairing-claimant#TEST-904]]

### CON-903 — Person-owned application-relay policy

Endpoint/Interface: a sealed wallet-owned set keyed by the exact pair
`(applicationId, relayOrigin)`. The interface supports recognised lookup, atomic
insert after explicit approval, explicit removal, and root-lifecycle purge.

Input grammar: `applicationId` uses the authenticated profile's canonical identifier.
`relayOrigin` uses the recognised canonical HTTPS origin from the invitation and
profile. The recogniser accepts no path, query, fragment, credentials, or non-HTTPS
production origin.

Pre-conditions: CON-220 authenticated the profile and produced the application ID.
The profile lists the canonical relay origin. The person approved this exact pair.

Post-conditions: one durable sealed row exists for the exact pair. No relay-only key,
global allowlist, conformance-digest registry, or application wildcard participates.

Error model: missing, corrupt, unavailable, or ambiguous policy state refuses before
socket creation. Rejection and storage failure create no row or identity effect.
Implements: [[SPEC-008-production-pairing-claimant#REQ-906]]
Verified by: [[SPEC-008-production-pairing-claimant#TEST-909]] [[SPEC-008-production-pairing-claimant#TEST-910]]

## Decisions

### ADR-901 — TLS through the existing tungstenite dependency

Add the `rustls` TLS feature to the existing `tungstenite` dependency. Keep the
blocking, sans-io-driven loop shape proved by the demo. Rejected:
`tokio-tungstenite` adds an async runtime to a synchronous shell. A webview WebSocket
requires CSP loosening and moves relay bytes into the webview. Simplicity Ladder rung
4 applies because the dependency and loop already exist.

### ADR-902 — Relay trust is exact-pair, person-owned TOFU

The invitation supplies an untrusted relay origin. Live CON-220 authentication binds
the application identity and confirms that its profile lists that origin.

The person authorizes the exact application-relay pair. This keeps relay topology out
of wallet releases and prevents an accepted relay from authorizing another application.

The application profile does not prove relay operatorship. Exact-pair consent contains
that residual without claiming to solve it.

### ADR-903 — The fixture is unreachable, not deleted

`local_demo` and the `local-pairing-demo` feature remain, compile-gated, as the
development harness ([[SPEC-007-cbcl-pairing-cutover]] evidence path needs them). What
changes: the non-demo build gains the real path, and [[SPEC-008-production-pairing-claimant#TEST-904]] proves fixture
symbols stay out of ordinary builds. Fixture deletion destroys the only loopback e2e
evidence harness for no security gain.

## Tests

Core (writable in one sitting, no new rig):

### TEST-901 — TLS claimant completes

Positive for [[SPEC-008-production-pairing-claimant#REQ-901]]. Complete a
claimant ceremony over `wss://` against a loopback TLS relay. Give the test
trust store a self-signed root. Require terminal `accepted`. Logs contain no
carrier or frame bytes.

### TEST-902 — Invalid TLS cannot downgrade

Negative input for [[SPEC-008-production-pairing-claimant#NFR-901]]. Present
an invalid certificate. Require a distinct TLS error, no sent bytes, and no
fallback attempt.

### TEST-903 — Final approval consumes the only real context capability

Positive for [[SPEC-008-production-pairing-claimant#REQ-902]]. Preview
assembly performs zero custody derivations and zero writes. Final approval
consumes one capability and derives one real context from the authenticated
plan.

### TEST-904 — Ordinary binaries contain no fixture authority

Prohibited action for [[SPEC-008-production-pairing-claimant#REQ-902]]. The
non-demo binary contains no `local_demo` symbol or `[19; 32]` digest. An
`nm` and `strings` assertion proves absence. Locked custody refuses before any
socket opens.

### TEST-905 — Live approve and decline terminate

Positive for [[SPEC-008-production-pairing-claimant#REQ-903]]. Non-demo
approve and decline drive the live session to matching terminal states. The
`PairingUnavailable` stub is absent.

### TEST-906 — Scan and paste carriers converge

Positive for [[SPEC-008-production-pairing-claimant#REQ-904]]. Scan-delivered
and pasted carriers produce byte-identical `cbcl_pairing_start` inputs.

### TEST-907 — Scanner failures remain distinct

Negative input for [[SPEC-008-production-pairing-claimant#REQ-904]]. The three
scan failure causes produce distinct messages. Device confirmation remains a
depth case.

### TEST-908 — Carrier wrappers refuse before state

Negative input for [[SPEC-008-production-pairing-claimant#REQ-905]]. Wrap a
carrier in a URL scheme, padding, or a legacy prefix. Recognition refuses it
before any state change.

### TEST-909 — A new exact pair prompts once

Positive and negative for [[SPEC-008-production-pairing-claimant#REQ-906]]. A
new exact pair prompts once. Approval writes one pair row before socket
creation. Rejection and profile mismatch open no socket and create no state.

### TEST-910 — Pair trust cannot authorize another application

Negative for [[SPEC-008-production-pairing-claimant#CON-903]]. Trust for one
application-relay pair never authorizes another application on the same relay.
Corrupt or unavailable policy refuses without a socket or identity effect.

### TEST-911 — Production allocation remains closed

Scope invariant for [[SPEC-008-production-pairing-claimant#REQ-907]].
`PRODUCTION_ALLOCATION_ENABLED` remains `false`.
`require_production_allocation()` fails closed. The SPEC-007 live-relay suite
passes unchanged.

### TEST-912 — Build capability copy remains truthful

Positive for [[SPEC-008-production-pairing-claimant#REQ-908]]. A non-demo
build renders no demo-specific error copy. The capability boundary reflects
the build.

Depth (needs a rig or a second party; deferrable with owner):

### TEST-913 — Real relay ceremony

Owner: repository owner. Run a ceremony against `chat.anuna.io` after a
descriptor and published evidence exist.

### TEST-914 — Android uses the real network

Owner: repository owner. Run an on-device Android scan and WSS ceremony through
a real network without `adb reverse`.

### TEST-915 — Two independent operators select correctly

Owner: cbcl security owner. Exercise
[[SPEC-007-cbcl-pairing-cutover#CON-806]] against two independently operated
relays.

Mutation gate: disable the origin check and [[SPEC-008-production-pairing-claimant#TEST-909]] fails. Accept an invalid
certificate and [[SPEC-008-production-pairing-claimant#TEST-902]] fails. Reintroduce non-demo fixture context and
[[SPEC-008-production-pairing-claimant#TEST-904]] fails.

## Observability

### OBS-901 — Secret-free transport lifecycle

Record connect, terminal outcome, and close-reason classes under
[[SPEC-008-production-pairing-claimant#NFR-902]].

### OBS-902 — Context refusal classes

Record context-assembly refusals by missing-capability class.

### OBS-903 — Non-identifying origin-policy classes

Record new pair, accepted pair, rejected pair, profile mismatch, and policy
unavailable classes.

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

## Tier-1 generation provenance

OpenAI GPT-5 model `gpt-5.6-sol` generated this coordinated synthesis. Its
Codex session is `01a029aa-9127-7c42-ad28-81512b91ded6`.

The synthesis record begins with the owner-selected standalone architecture.
It includes the F-A through F-E code traces and every rejected review record.

The immediate correction input is
[[spec-008-0.4.26-claude-adversarial-review-2026-08-23#Corrections-and-owners-collected]].
This reissue removes the amendment ledger that caused the N11 rejection.

A qualifying reviewer SHALL use another model family and a fresh session. The
report SHALL record its model, authentication path, session, and Circus
attempt.

The reviewer SHALL execute strict controlled-language lint before deciding.
The reviewer SHALL trace both WebSocket room-start consumers through their
terminal boundaries.

## Requirement

### REQ-1005 — One complete companion and credential-v1 authority governs

This parent specification is the sole current Selfsame authority for this
increment. Trajectory documents provide evidence and no normative precedence.

Credential/v2 SHALL conform to cbcl-pairing SPEC-001 0.5.0-draft. The
cbcl-pairing parent records this document as its consumer.

The wallet and browser use separate typed machine-carrier and PAIR1
presence-field inputs. Cbcl-pairing enforces non-substitutability, version
isolation, CPace source, sender rules, state rules, and its envelope.

The wallet provides live approve and decline under [[SPEC-008-production-pairing-claimant#REQ-903]]. The two-stage
credential/v2 decision sequence follows [[SPEC-008-production-pairing-claimant#CON-902]] and
[[SPEC-007-cbcl-pairing-cutover#REQ-804]].

Scan and paste decode the machine carrier into the same recognised type under
[[SPEC-008-production-pairing-claimant#REQ-904]]. The separate PAIR1 presence field remains type-only.

The production scan is the completeness authority for every classified
credential-v1 site. Its closed identifier set is `PROFILE_VERSION`,
`profileVersion`, `profile_version`, `evidenceVersion`, and `payloadVersion`.

Matching uses exact case-sensitive substring matching for those five
identifiers. The scan classifies every production match before disposition.

Its classes are version-constant definition, version literal, comparison,
emitted member, typed version-field assignment, ingest substitution, and
untyped ingress conversion.

A field-to-field copy on an ingest path is a substitution. Extraction from
untyped input into a typed version-bearing value is an ingress conversion.

The scan distinguishes production code from `#[cfg(test)]` code,
member-name constants, type declarations, format templates, and comments.

The following production witnesses are current evidence.

| Production site | Current class |
|---|---|
| `crates/selfsame-web-device/src/lib.rs:600` | emitted member |
| `crates/selfsame-web-device/src/lib.rs:1346` | version literal |
| `crates/selfsame-web-device/src/lib.rs:1360` | version literal |
| `crates/selfsame-web-device/src/lib.rs:1369` | typed version-field assignment |
| `crates/selfsame-app-identity/src/ceremony.rs:185` | emitted member |
| `crates/selfsame-app-identity/src/ceremony.rs:190` | emitted member |
| `crates/selfsame-app-identity/src/ceremony.rs:308` | comparison |
| `crates/selfsame-app-identity/src/ceremony.rs:460` | emitted member |
| `crates/selfsame-app-identity/src/ceremony.rs:510` | comparison |
| `crates/selfsame-app-identity/src/enrollment.rs:373` | comparison |
| `crates/selfsame-app-identity/src/enrollment.rs:394` | comparison |
| `crates/selfsame-app-identity/src/enrollment.rs:452` | typed version-field assignment |
| `crates/selfsame-app-identity/src/enrollment.rs:552` | comparison |
| `crates/selfsame-app-identity/src/enrollment.rs:662` | emitted member |
| `crates/selfsame-app-identity/src/enrollment.rs:666` | emitted member |
| `crates/selfsame-app-identity/src/profile.rs:385` | comparison |
| `crates/selfsame-app-identity/src/provider_hint.rs:67` | emitted member |
| `crates/selfsame-app-identity/src/provider_hint.rs:115` | comparison |

Additional comparison evidence is
`crates/selfsame-app-identity/src/enrollment.rs:592`.

Ingest-substitution evidence is `crates/selfsame-web-device/src/lib.rs:831`,
`:847`, and `:861`.

Untyped ingress-conversion evidence includes
`crates/selfsame-app-identity/src/ceremony.rs:413`,
`crates/selfsame-app-identity/src/provider_hint.rs:96`, and
`crates/selfsame-app-identity/src/profile.rs:384`.

Production version-constant evidence includes
`crates/selfsame-app-identity/src/lib.rs:109` and
`crates/selfsame-app-identity/src/profile.rs:60`.

Named sites are evidence only. They cannot close or limit the production
scan.

`successionVersion` belongs to identity succession under
[[SPEC-004-application-scoped-identity#REQ-231]] and
[[SPEC-004-application-scoped-identity#CON-225]].

`WIRE_VERSION` belongs to the link-offer wire namespace. Its governing source
is `anuna-ssi` SPEC-001 CON-001 at commit
`c7d462029841ea1884bb6f089732058d8838728d`.

`CODE_VERSION` belongs to the link-code namespace. Its governing source is
`anuna-ssi` SPEC-001 CON-001 at the same pinned commit.

The `anuna-ssi` pin resolves namespaces only. It supplies no coordinated design
authority. This is an explicit cross-vault deferral because the anuna-ssi vault
is outside this repository and cannot be represented by a local wikilink.

Credential/v2 reaches no classified credential-v1 site. It SHALL NOT call
`EnrolmentAllocator::new_native`. Frozen v1 bytes remain byte-identical.

No sequencing list independently enumerates a companion test range. Release
blocking follows [[SPEC-008-production-pairing-claimant#CON-985]].

### REQ-1006 — V2 presence, authenticated display, and installed state are direct

The public machine carrier and human presence input SHALL remain separate typed
values. The carrier SHALL contain no `PAIR1-` text, CPace secret, or claim
bearer. The presence input SHALL contain exactly one recognised `PAIR1-` value
that yields independent raw sixteen-octet CPace and claim tokens under
cbcl-pairing SPEC-001 0.5.0-draft.

The scan and paste carrier paths SHALL never populate the presence input. The
type-only presence component SHALL have no paste, autofill, password-manager,
accessibility injection, deep-link, notification, QR, or peer-data path. It
SHALL never populate the carrier input. One input cannot be serialized into,
inferred from, or used as a fallback for the other.

The canonical code is `PAIR1-` followed by eleven hyphen-separated groups of
five Crockford Base32 characters. The decoded big-endian bits are
`C || T || checksum16 || 000`. The last three bits are zero. `checksum16` is
the first two octets of:

```text
SHA-256(UTF8("selfsame credential/v2 presence code\u0000") || C || T)
```

The accepted alphabet is `0123456789ABCDEFGHJKMNPQRSTVWXYZ`. The component MAY
normalize ASCII lower case to upper case before recognition. It SHALL reject
Unicode case folding, lookalikes, whitespace, missing separators, forbidden
letters, nonzero pad bits, checksum failure, and every valid twelve-word
BIP-39 mnemonic.

Before preliminary consent, `cbcl-pairing` SHALL construct one private
`CredentialV2Display` only after Selfsame verification. The verifier SHALL
authenticate the live profile, signed hub offer, carrier, and transcript. It
SHALL also authenticate the exact application, relay, account, scope,
permissions, installation key, and complete account transition.

The verifier SHALL return only a closed verdict. It cannot return, append,
replace, or mutate display text. Generic `DisplayField`, wire
`authority_summary`, wire application text, peer-provided labels, caller
booleans, and DOM room values SHALL NOT enter the credential/v2 consent
surface.

The preliminary screen SHALL show the authenticated application ID, HTTPS
origin, relay origin, and account assertion provenance. It SHALL also show
permissions, installation binding, exact-pair TOFU state, and the complete
authenticated transition. The final screen SHALL add only the locally derived
DID, fingerprint, and final-effect statement.

The wallet SHALL store relay policy only under the exact
`(applicationId, relayOrigin)` pair. It SHALL contain no compiled relay
allowlist, conformance-digest registry, relay wildcard, or relay-only trust
fallback in an ordinary build. A profile that names a previously accepted
relay under another application SHALL still require the new exact-pair prompt.

After the hub's immutable final acknowledgement, the wallet SHALL atomically
install one record. It SHALL contain the root generation, grant bytes, grant
digest, application ID, account-principal digest, and account scope ID. It SHALL
also contain the installation device key, profile digest, account authority,
issuer DID, offer-core digest, and hub status identifier.

Reload SHALL verify the installed grant, current profile, authority, issuer,
and hub status before granting application capability. Hub or resolver
unavailability SHALL be distinct from revocation or absence and SHALL NOT clear
the installed record.

A profile-only digest refresh with unchanged authority and issuer MAY re-pin
silently after full verification. Authority or issuer rotation SHALL prompt the
person. A changed installed handle SHALL refuse. No network input can silently
rename an installed account.

Unlink SHALL require explicit confirmation and remove only the application
record, exact-pair relay policy selected by the person, and application-owned
cached material. It SHALL retain the root seed and SHALL NOT claim remote hub
revocation. Re-grant after hub-side deletion requires a complete fresh pairing
ceremony. A local shortcut using the retained derived key is prohibited.

## Non-functional requirement

### NFR-928 — Typed unavailability is total at every production consumer

`withdraw/2` derives `requestedAlias` from `homeDid` before opening its
transaction. It passes that value to
`tombstone/3(account, homeDid, requestedAlias)`.

The live path takes the requested alias write lock first. It takes the exact
account write lock second.

An absent account row enters `already-withdrawn/2`. That path is non-mutating
and preserves idempotent success for the requested generation.

A present account row whose home DID differs returns
`#(error wrong-generation)`. A matching home DID with another stored alias
returns `#(error inconsistent-binding)`.

The write-locked alias row SHALL name that same account and home DID. An absent
or disagreeing alias row returns `#(error inconsistent-binding)`.

Every refusal deletes zero alias, account, and withdrawal rows. Only reciprocal
agreement reaches the withdrawal lock and both live-row deletes.

`reinstate/2` and `lift-tombstone/2` take no alias or account lock. Their
transaction takes one whole withdrawal write lock before its first
`index_read`.

The exact delete runs under that table lock. Provision and withdrawal already
serialize through their withdrawal write locks. Reinstatement performs no
read-to-write upgrade.

Every affected transaction runs at Mnesia level 1 through one shared wrapper.
The wrapper calls `mnesia:transaction(Fun, [], 3)`.

The default unary call, `infinity`, and an unbounded argument overload are
non-conforming. The wrapper maps only `{aborted, nomore}` to retry exhaustion.

Mnesia converts a level-1 exhausted cyclic restart to `{aborted, nomore}`.
An exhausted `#cyclic{}` is not a separate public terminal.

Proper nested transactions commit silently at the outer wrapper. Prohibited
nesting therefore has no runtime terminal and no runtime classifier.

A repository scan enumerates every production `mnesia:transaction` call under
`apps/`. Every row names module, function, line, public owner, and transaction
body.

Every row also names wrapper, lane membership, terminal mapping, and
call-graph evidence. Omitted, unclassified, or unsupported out-of-scope rows
are non-conforming.

Every transaction body has a complete static call graph. A body SHALL NOT open
another transaction or contention retry loop. A body SHALL NOT catch an
`{aborted, _}` exit.

Lane membership follows transitive transaction-body table access:

1. Authority contains `cbcl-device-grant`, `cbcl-member`, and
   `cbcl-pairaccount-grant`.
2. Ceremony migration contains `cbcl-account-binding`, `cbcl-room`,
   `cbcl-roommember`, `cbcl-account-roommember`, `cbcl-invite`, and
   `cbcl-sealedgrant`.
3. Ceremony migration also contains every `cbcl-selfsame-*` table created by
   the effective credential/v2 design.
4. WebFinger contains `cbcl-webfinger-alias`, `cbcl-webfinger-account`, and
   `cbcl-webfinger-withdrawn`.
5. The transaction-based schema-migration site is
   `cbcl-store-migrate:legacy-rows/0` over `cbcl-msg`.
6. Out-of-scope means the proved transitive body touches none of those tables.

A row can occupy several runtime lanes. Authority takes terminal precedence,
then ceremony migration, then WebFinger.

The named `legacy-rows/0` site does not overlap those runtime lanes.
`cbcl-chat-roommember:migrate-since/0` is a second schema migration. It uses
`mnesia:transform_table/4` and lies outside the transaction-call inventory.

The nonce allocator's outer collision loop is a semantic uniqueness retry. It
is not a Mnesia contention retry. Each transaction invocation remains
non-nested.

Authority and ceremony-migration owners map retry exhaustion to
`#(error authority-busy)`.

Public collection and predicate owners use tagged success. They return
`#(ok Value)` or `#(error authority-busy)`. Busy never becomes an empty list,
`false`, `undefined`, `exists`, absence, or non-membership.

Only collection and predicate owners adopt tagged success. Every other public
owner retains its declared success shape and adds its lane's typed busy shape.

The authority public owners are:

- `cbcl-chat-account-grants`: `confirmed-migrate-path-a-handle/3`,
  `bind-and-store-verified-device-grant/8`, and
  `store-verified-device-grant/6`;
- the same module: `device-grant/2`, `device-grants/1`, `peer-grants/1`,
  `accounts/0`, `revoke-observed/2`, and `revoke-device-grant/2`;
- `cbcl-chat-members`: `pubkey/1` and `enroll-or-check/2`;
- `cbcl-chat-pairaccount`: `claim/2`, `grants/1`, and
  `unratified-device?/1`; and
- `cbcl-chat-successor`: `accept/3`.

The ceremony-migration public owners are:

- `cbcl-chat-account-grants`: `account-binding/1` and `bind-account/2`;
- `cbcl-chat-account-roommember`: `grant/5`, `redeem-and-grant/5`,
  `re-admit?/3`, `member-grant?/2`, `rooms-for-account/1`, and `since-seq/2`;
- `cbcl-chat-roommember`: `since-seq/2`, `grant/5`,
  `redeem-and-grant/5`, `re-admit?/3`, `member-grant?/2`, and `revoke/2`;
- `cbcl-chat-invite`: `mint/3` and `redeem/2`;
- `cbcl-chat-sealedgrant`: `put/3` and `get/1`; and
- `cbcl-chat-roomcfg`: `ensure-room/3`, `ensure-room/4`, `claim/3`,
  `claim/4`, `claim/5`, `list-public/0`, `get/1`, and `creator/1`.

The room configuration set also includes `get-dialects/1`, `add-dialect/4`,
`add-dialect-capturing/4`, `rollback-add/5`, and `remove-dialect/3`.

Transaction-only helpers return no public busy terminal. They are called only
inside one wrapper-owned transaction. The inventory proves every such edge.

`enroll-or-check/2` performs its read, device guard, decision, and possible
write in one wrapper transaction. Its transaction result reaches
`enrol-commit`.

`cbcl-chat-invite:mint/3` returns `#(ok Token)` only after commit.
`cbcl-chat-roomcfg:ensure-room/4` returns `ok` only after commit.

`bind-and-store-unbound/8` calls `cbcl-chat-members:pubkey-tx/1`. It SHALL NOT
call transaction-opening `pubkey/1`.

`cbcl-chat-successor:accept/3` uses a transaction-only device-grant read. Its
`account-accepted?/2` helper SHALL NOT call transaction-opening
`device-grant/2`.

The successor helpers at `cbcl-chat-successor.lfe:109` and `:134` SHALL NOT
catch an `{aborted, _}` exit. Their transaction aborts reach the shared outer
wrapper.

A repository-wide production consumer scan is the completeness authority.
It covers every direct or transitive consumer of a value that can carry
`#(error authority-busy)`.

Every row names producer, consumer path and line, success sink, busy branch,
and terminal boundary. A scan limited to public-owner call sites is
non-conforming.

Every consumer handles the producer's success shape and
`#(error authority-busy)`. It unwraps `#(ok Value)` before use and never
handles busy through a wildcard default.

Known collection sinks include:

- `cbcl-chat-session-ws.lfe:512`, consuming `device-grants/1` into an
  admission map;
- `cbcl-chat-session-ws.lfe:869`, consuming `rooms-for-account/1` through
  `lists:foreach`;
- `cbcl-chat-session-ws.lfe:965`, consuming `list-public/0` through the wire
  channel encoder;
- `cbcl-chat-session-ws.lfe:1683`, consuming `grants/1` through `lists:map`;
- `cbcl-chat-room.lfe:677`, consuming `peer-grants/1` through `lists:map`;
- `cbcl-chat-path-b-poller.lfe:17`, consuming `accounts/0` through
  `lists:foreach`; and
- `cbcl-chat-room.lfe:221` and `:550`, consuming `get-dialects/1` into room
  state or a room-configuration frame.

The boolean contexts are `cbcl-chat-room.lfe:263-270`,
`cbcl-chat-pairgrant.lfe:78`, and `cbcl-chat-session-ws.lfe:1050`.

The inventory includes `unratified-device?/1` at
`cbcl-chat-session-ws.lfe:347` and `:385`. It includes
`cbcl-chat-path-b-poller.lfe:17` and `:32`.

It includes the discarded `claim/5` result at
`cbcl-chat-session-ws.lfe:1898`. Busy reaches WebSocket 1013 and never becomes
`'ok`.

The webhook inventory includes `cbcl-chat-rooms.lfe:54`, `:60`, and `:61`.
It includes `cbcl-chat-room.lfe:201` and `:221` during supervised room start.

It includes `cbcl-chat-rooms.lfe:49` and `:99-104`, plus the HTTP edge at
`apps/cbcl_router/src/cbcl-webhook-handler.lfe:76`.

It includes both WebSocket consumers of `cbcl-chat-rooms:get-or-start/1`.
The removal path is `cbcl-chat-session-ws.lfe:1076`. The hello path is
`cbcl-chat-session-ws.lfe:1788`.

At the removal path, room-start busy returns the existing `revoke-failed`
terminal. It preserves provenance and emits no removal acknowledgement.

At the hello path, room-start busy closes WebSocket 1013 with
`try-again-later`. It performs no room join and creates no membership grant.

Tagged success cannot enter a boolean operator, list function, admission map,
wire encoder, channel-policy default, or refusal wildcard.

Retry-exhausted transaction contention returns
`#(error authority-busy)`. Other transaction failure from
`cbcl-chat-roomcfg:get/1` remains `#(error store-unavailable)`.

The two results remain distinct through every consumer. Neither result SHALL
become `#(error unknown-room)`, a private-channel decision, or a channel
configuration.

Only `#(error unknown-room)` MAY select the ADR-007
`#(public undefined false)` default.

At supervised room start, `authority-busy` and `store-unavailable` both stop
the child. They create no ETS registration, room process, room state, or
fan-out.

Busy from `get-dialects/1` during room start also stops the child. Busy during
`refresh-dialects` retains the prior dialect set and emits no frame.

`cbcl-chat-rooms:get-or-start/1` preserves an `authority-busy` child-start
failure. `cbcl-chat-rooms:ingest/3` returns that value without calling
`cbcl-chat-room:ingest/3`.

For a periodic Path-B tick, busy from `accounts/0` emits
[[SPEC-008-production-pairing-claimant#OBS-907]] with phase `account-scan`. The
tick reports no success, calls no resolver, and leaves the poller alive.

Busy from `revoke-observed/2` emits
[[SPEC-008-production-pairing-claimant#OBS-907]] with phase `revocation-apply`. It
reports no applied union, performs no eviction, and defers that account to the
next scheduled tick.

The poller MAY continue other accounts after that result. It MUST NOT report
the discarded verified union as applied.

Busy from the webhook's room-configuration calls propagates as
`#(error authority-busy)`. The same value propagates from supervised room
start.

The webhook maps `authority-busy` to HTTP 503 with status `authority-busy` and
`cache-control: no-store`. It maps `store-unavailable` to a retryable HTTP 503
with its distinct status and the same cache policy.

Either 503 releases any reserved blob slot. It performs no room start, room
ingest, persistence, or channel fan-out.

HTTP 409 remains only for a committed non-public-channel decision.
Unavailability never becomes that policy refusal.

At every WebSocket boundary, busy closes with code 1013 and reason
`try-again-later`, unless this requirement names a narrower existing refusal.
It emits no allocation acknowledgement, invite, grant, or enrollment frame.

The browser treats 1013 as non-terminal. It cancels the old socket generation,
reconnects, and starts a fresh correlated attempt.

At startup, busy prevents the listener from opening. It never becomes a
successful default-room claim.

For the busy class, name-squatting checks propagate busy to the 1013 boundary.
They cannot report that a name is free.

The `cbcl-provenance` wildcard in `addagent-target-free?/3` is an accepted
out-of-lane residual for non-retryable failures. This specification does not claim
that the wildcard is safe outside the busy class.

Member enrollment performs no write after busy.

The WebFinger public owners remain `provision/3`, `withdraw/2`, `reinstate/2`,
and `lookup/1`. Their transaction bodies never open another transaction.

WebFinger mutations return `#(error authority-busy)` on retry exhaustion.
`lookup/1` is exempt from that result form and returns `unavailable`.

`cbcl-chat-webfinger-http` maps `unavailable` to HTTP 503. The response is
empty and carries `no-store`.

Contention never becomes `missing` or HTTP 404. Invalid syntax and committed
absence retain their existing 400 and 404 behavior.

`create-or-return/3`, `lookup-binding/1`, `tombstone/3`,
`already-withdrawn/2`, and `lift-tombstone/2` are WebFinger transaction bodies.
Their names specify locks, not public retry terminals.

Transaction-based schema exhaustion maps to
`#(error schema-migration-busy)`. The application refuses startup and opens no
listener. It never treats this result as `no-table`.

No partial effect survives any exhausted transaction. Existing success and
non-contention refusal meanings remain unchanged behind their declared result
shapes.

## Observation

### OBS-907 — Retryable authority failure is visible without identity data

The Path-B poller emits `path-b-revocation-authority-busy` for each busy
decision. Its phase is `account-scan` or `revocation-apply`.

The hub emits `room-start-authority-busy` when supervised room start refuses
retry-exhausted contention. It records the terminal boundary, not the room
name.

Neither event records a room name, channel capability, account DID,
credential, resolver payload, profile digest, or grant key.

A counter MAY aggregate Path-B events by phase. A counter MAY aggregate
room-start events by terminal boundary.

Neither signal claims a successful operation. The next scheduled Path-B tick
retries from a fresh resolver read.

## Contract

### CON-985 — Consolidated current authority and gate

This parent states every current Selfsame obligation for the coordinated
increment directly. Trajectory documents and review reports supply evidence
only.

The current Selfsame test set is TEST-901 through TEST-915 and TEST-1156
through TEST-1159. Every test is stated in this parent.

The exact current hub test set is TEST-043 through TEST-065, TEST-068,
TEST-070, TEST-093, TEST-094, TEST-098, and TEST-115 through TEST-117.

The coordinated review set contains this parent, cbcl-pairing SPEC-001
0.5.0-draft, cbcl-bus SPEC-053 0.17.1-draft, and did-crdt SPEC-037
0.1.0-draft.

The `anuna-ssi` namespace reference is outside that set. It is pinned at
`c7d462029841ea1884bb6f089732058d8838728d` only to resolve
[[SPEC-008-production-pairing-claimant#REQ-1005]]'s two namespace exclusions.
It is an explicit cross-vault deferral, not a coordinated design input.

The cbcl-pairing, cbcl-bus, did-crdt, and anuna-ssi parent identifiers are
explicit cross-vault pointers. Their vaults are outside this repository, so
these identifiers are deliberately not local wikilinks.

The cbcl-pairing SPEC-001 parent records this parent as its credential/v2
consumer. The hub and did-crdt parents record the same coordinated review set.

Every F-A through F-E correction remains a hard stop.
[[SPEC-007-cbcl-pairing-cutover#REQ-812]] also remains a hard stop.

A fresh PASS authorizes only the Elephant SPL and test-first plan. It
authorizes no production allocation, release, or deployment.

### CON-986 — Standalone claimant plan, decisions, effects, and rendezvous

`prepare_claimant` SHALL perform pure recognition and authenticated public
network reads only. It SHALL recognise the machine carrier and verify the live
[[SPEC-004-application-scoped-identity#CON-220]] profile and signed hub offer. It SHALL compare the exact
application-relay pair and recognise the PAIR1 input. It SHALL complete CPace
and both Finished values and produce a bounded authenticated plan.

The plan SHALL contain no custody handle, hierarchy root, or derived
application key. It SHALL contain no home DID, issuer state, WebFinger JRD,
resolver closure, signature, grant, alias, publication, scope mint, or durable
identity record. The hub-signed account-principal digest and scope are public
inputs to later derivation. The raw application account ID remains hub-private.
The wallet SHALL neither allocate nor persist the scope before final status.

The first decision capability authorizes exactly one zeroizing custody call.
That call derives the application home key and computes the pure home DID and
fingerprint preview. It returns only zeroizable public preview material. It
erases the key and hierarchy root before returning. It performs no signature,
issuer creation, resolver call, WebFinger call, grant construction,
publication, alias operation, bundle construction, or durable identity write.

The wallet SHALL disclose the preview DID and fingerprint only to the
[[SPEC-004-application-scoped-identity#CON-220]]-authenticated application inside the established cbcl-pairing channel.
The browser SHALL return the authenticated comparison or binding result. Any
mismatch, terminal, decline, cancellation, timeout, or relay failure erases the
preview and authorizes no later effect.

The final screen SHALL contain the same immutable typed display plus the local
preview DID and fingerprint. Final approval produces one single-use effect
capability. It binds the intent, offer-core, and transition digests. It also
binds the preview DID, application, account, scope, installation key,
permissions, relay, and expiry.

The final executor SHALL invoke custody again and re-derive the key. It SHALL
require byte-for-byte preview DID and fingerprint equality before its first
signature. It SHALL then create and sign the issuer and publish the DID. It
SHALL resolve and verify the closure and live WebFinger JRD. It SHALL then
construct the grant and approved reverse payload.

Those steps occur only after final approval and as the declared provisioning
work needed to deliver the approved payload. A failure releases no accepted
credential or application capability. Compensation is limited to effects
created by this ceremony and follows
[[SPEC-004-application-scoped-identity#CON-204]]. It never changes an
operator withdrawal or a pre-existing identity.

For credential/v2 reverse issuance only, this paragraph amends
[[SPEC-007-cbcl-pairing-cutover#REQ-812]]. After final approval, the wallet MAY
perform only causal work required to construct the approved reverse payload.
That work is signing, publication, resolution, issuance write, and bundle
construction. Before final approval, no such effect is permitted. Post-final
failure authorizes no application capability and enters the exact compensation
path. No other protocol profile or failure rule is weakened.

The browser SHALL verify the reverse payload, resolver closure, WebFinger
binding, grant chain, installation key, account, scope, issuer, profile,
permissions, transition, and device proof. It SHALL commit its strict local
installation before requesting hub finalization.

The wallet SHALL accept no receipt until the hub reports its immutable final
status and acknowledgement under the new installation key. It SHALL then
atomically install the record required by [[SPEC-008-production-pairing-claimant#REQ-1006]]. Crash or loss before
that wallet commit recovers from hub status and the retained bounded ceremony
state. It does not invent a local grant or repeat a hub migration.

The Selfsame rendezvous implementation is
`crates/selfsame-rendezvous/src/lib.rs`. It SHALL accept opaque bodies of 1
through 69,632 octets. It SHALL return HTTP 413 for 69,633 octets or more with
no storage effect. It SHALL preserve its current slot grammar, first-write,
read-once, lifetime, capacity, CORS, and blind-content behavior.

The did-crdt service owns its matching implementation under did-crdt SPEC-037
0.1.0-draft. Each server SHALL independently transit the 57,016-octet sealed
offer witness, the 62,016-octet sealed reverse-payload witness, and the
69,632-octet maximum. Neither server's test result proves the other.

The wallet ordinary build SHALL contain no compiled conformance registry,
relay allowlist, held-enrolment precondition, `record_pairing_trust` call edge,
or fallback to `assemble_claimant`. The new split functions SHALL be the only
credential/v2 construction path.

Implements: [[SPEC-008-production-pairing-claimant#REQ-902]], [[SPEC-008-production-pairing-claimant#REQ-906]], [[SPEC-008-production-pairing-claimant#REQ-1006]].
Verified by: [[SPEC-008-production-pairing-claimant#TEST-1158]], [[SPEC-008-production-pairing-claimant#TEST-1159]].

## Decision

### ADR-963 — Current law lives directly in the parent

The parent specification states current law directly. Historical amendments
record synthesis evidence and never determine precedence.

Every affected transaction belongs to a table-derived lane. The shared wrapper
recognises one observable retry-exhaustion result.

Static inventory prohibits nesting and abort-catching. Every changed success
shape has a corresponding consumer adaptation.

Busy is not absence, non-membership, name availability, or successful
creation. Socket consumers expose it as retryable 1013.

`authority-busy` and `store-unavailable` refuse room start before channel
policy. Only committed absence selects the public default.

The WebSocket hello owns its 1013 terminal. The removal path owns its existing
`revoke-failed` terminal.

The withdrawal live branch requires reciprocal account and alias agreement.
The idempotent absent-account branch remains non-mutating.

The production source scan is authoritative over version sites. A witness list
cannot weaken it. One direct cbcl-pairing parent governs credential/v2.

Authenticated display, post-consent effects, shared grammar, cap arithmetic,
and the sealed-grant graph remain unchanged.

## Test specification

### TEST-1156 — Total results and every terminal fail closed

Change only the installed profile digest while authority and issuer stay
fixed. Require grant verification and an atomic silent re-pin.

Change authority or issuer. Require the person prompt, cancellation, and
verified atomic acceptance.

Attempt a handle change while installed. Require
`account-device-handle-change-refused` and zero enrollment frames.

Confirm and cancel unlink. Verify exact local removal, seed retention, and
unchanged hub state.

Delete the hub grant and run a full new ceremony with the retained key. Require
current eligibility, capacity, both consent decisions, and a new verified
grant. Every local-only re-grant shortcut fails.

Generate all twelve authority cycles and every `AR` contention case. Generate
the complete ceremony-migration and WebFinger graphs.

Require the restored acquisition point and invite-before-room order. Require
no additional upgrade or cycle.

Enumerate every production transaction call under `apps/`. Require each row's
owner, body, tables, lane set, wrapper, terminal, and call-graph proof.

Require the shared wrapper's exact retry count. Reject unbounded, nested,
omitted, or unsupported out-of-scope sites.

Force `{aborted, nomore}` at every affected public owner. Require the lane's
exact busy terminal, zero partial effect, and unchanged non-contention
meanings.

Do not require a raw exhausted `#cyclic{}` or `nested_transaction` terminal.
Prove statically that no transaction body opens a transaction or catches an
`{aborted, _}` exit.

Require `cbcl-chat-successor:accept/3` in the authority inventory. Instrument
its transaction body and both helper edges.

Require a transaction-only device-grant read. Any `device-grant/2` edge or
abort-catching edge at `cbcl-chat-successor.lfe:109` or `:134` fails.

Generate the production consumer inventory from every result or transitive
value carrying `authority-busy`.

Require producer, consumer, success sink, busy branch, and terminal boundary
for every row. A public-owner-only inventory fails.

Drive every known collection sink and every newly discovered collection sink.
No tagged value reaches its sink before unwrap.

Drive every boolean consumer. No tagged value reaches a boolean operator,
admission map, wire encoder, policy default, or refusal wildcard.

At each WebSocket 1013 boundary, require `try-again-later`. Require no
acknowledgement, invite, grant, or enrollment frame.

Retry after reconnect with a new socket generation and request identifier.
Require one correlated success and no duplicate durable effect.

Force `cbcl-chat-rooms:get-or-start/1` to refuse the hello at
`cbcl-chat-session-ws.lfe:1788`. Require WebSocket 1013, zero join, and zero
membership grant.

Force the same refusal at `cbcl-chat-session-ws.lfe:1076`. Require
`revoke-failed`, preserved provenance, and zero removal acknowledgement.

Force member-enrollment exhaustion before its possible write. Require no
member row and no later rebind.

Force the in-lane half of name-squatting to exhaust. Require no name-free
result and a 1013 close.

Keep the `cbcl-provenance` wildcard recorded as an out-of-lane residual. Do not
claim this test repairs its non-retryable behavior.

Force exhaustion in `invite:mint/3` and `roomcfg:ensure-room/4`. Require no
token, no room row, and no reported success.

Instrument `bind-and-store-unbound/8`. Require only `pubkey-tx/1` inside its
outer transaction. Any `pubkey/1` edge fails.

Force retry exhaustion and another transaction failure at
`cbcl-chat-roomcfg:get/1`. Require distinct `authority-busy` and
`store-unavailable` results.

Force each result during supervised room start. Require a refused child, zero
ETS registration, zero default configuration, and zero fan-out.

Force `unknown-room` separately. Require only that result to select the
ADR-007 public and cleartext default.

Force busy at the webhook's initial `get/1`, `claim/3`, and post-claim
`get/1`. Force it again at supervised room-process start.

Require HTTP 503 `authority-busy`, `no-store`, released reservation, and zero
room ingest, persistence, or fan-out for each forcing.

Force `get-dialects/1` busy during room start. Require the same HTTP terminal
and zero room registration or fan-out.

Force `store-unavailable` on the webhook route. Require its distinct retryable
503 status, `no-store`, and zero effect.

Drive a committed private-channel decision. Require HTTP 409 and prove that
neither unavailability branch reaches that terminal.

Force `accounts/0` busy during a scheduled Path-B tick. Require OBS-907 phase
`account-scan`, no resolver call, no success report, and a live poller.

Force `revoke-observed/2` busy after a verified union. Require OBS-907 phase
`revocation-apply`, no eviction, and a fresh resolver pass next tick.

Force the WebFinger terminal through `lookup/1`. Require `unavailable`, HTTP
503, an empty `no-store` response, and no HTTP 404.

Successful and missing WebFinger lookups retain their existing responses.
Mutations use `#(error authority-busy)` and never false absence.

Force transaction-based schema exhaustion. Require
`schema-migration-busy`, no `no-table`, no listener, and no skipped history.

Record `cbcl-chat-roommember:migrate-since/0` as a separate
`transform_table/4` schema migration outside the transaction inventory.

Provision reciprocal account and alias rows. Withdraw and require both live
rows deleted under alias-before-account ordering.

Delete the requested alias row while retaining the account row. Require
`inconsistent-binding` and zero deletion.

Point the requested alias row at another account or DID. Require
`inconsistent-binding` and zero deletion.

Give withdrawal a matching home DID and another stored alias. Require
`#(error inconsistent-binding)` and zero deletion from all three tables.

Give withdrawal another home DID. Require `#(error wrong-generation)` and
zero deletion.

Remove the account row and retain a matching tombstone. Require the idempotent
already-withdrawn result and no mutation.

Require reinstatement's whole withdrawal write lock before its first
`index_read`. Require no alias or account lock.

Run cbcl-pairing TEST-063. The recogniser accepts 1, 23, 24, 255, 256, 2,047,
and 2,048 control-body octets.

It refuses 0, 2,049, 4,095, and 4,096 octets. No positive control row names
4,096.

### TEST-1157 — Resolved authority, pointers, and scan are singular

Require this parent to contain one protocol set, hub set, Selfsame set, review
set, and pointer set.

Require every current value to resolve from a direct clause in this parent.
Trajectory and review content cannot alter a current value.

Require the retained dispositions of
[[SPEC-008-production-pairing-claimant#REQ-903]] and
[[SPEC-008-production-pairing-claimant#REQ-904]].

Scan every production Rust source under
[[SPEC-008-production-pairing-claimant#REQ-1005]]'s closed five-identifier set
and seven-class classifier.

Use exact case-sensitive substring matching. Generate path, line, namespace,
class, and production-or-test disposition for every match.

Require every current witness and exclusion to resolve. Require
`profile_version` matches to include all three ingest substitutions.

Require `successionVersion`, `WIRE_VERSION`, and `CODE_VERSION` to resolve to
their named namespaces and governing contracts.

Require credential/v2 to reach no classified credential-v1 site. Require
frozen v1 bytes to remain byte-identical.

Require this Selfsame parent and its open review gate. Require cbcl-bus
SPEC-053 0.17.1-draft to name this coordinated review set.

Require the cbcl-pairing parent consumer pointer here. Require generation
family, version, session, and synthesis trajectory in all four parents.

Require another reviewer family and a fresh reviewer session. Require the
review to record its subscription or API authentication path.

Require the transaction inventory to cover every production call under
`apps/`. Require table-derived classifications and exact public-owner results.

Require the consumer inventory to cover every direct and transitive carrier
of `authority-busy`. Require both WebSocket `get-or-start/1` consumers.

Require all 42 cbcl-bus GATE-04 boxes. Require both non-conforming rendezvous
baselines, both owning parent clauses, and sealed cap arithmetic.

Require every installed-state clause in [[SPEC-008-production-pairing-claimant#REQ-1006]]. Require the four inline
regression groups in [[SPEC-008-production-pairing-claimant#TEST-1156]].

Require every N10 finding to have a code-backed disposition. Re-test every N9,
N8, and N7 disposition and every F-A through F-E hard stop.

Extract each consolidated current-law section by its exact heading boundaries.
Run `/Users/anuna-01/.agents/skills/anuna-dev/tools/usdd-lint.sh --type
descriptive --strict -` against each extraction. Run the same command against
the complete cbcl-pairing and did-crdt parents. Any error or warning fails this
test.

Removing any current obligation fails.

### TEST-1158 — Consent boundaries prohibit every early identity effect

Instrument custody opening, hierarchy derivation, home-DID computation, issuer
creation, signing, resolver publication, and closure resolution. Also
instrument WebFinger, grant construction, issuance persistence, alias
operations, hub migration, payload release, and wallet installation.

Before preliminary approval, require zero calls to every instrumented effect.
At preliminary approval, permit one zeroizing derivation, pure DID and
fingerprint computation, and authenticated preview disclosure only.

Decline, cancel, expire, close the relay, corrupt the comparison, and mutate the
preview after preliminary approval. Require zero signatures, publications,
authority calls, grants, aliases, hub migration, payload, and durable identity
records.

At final approval, require a new custody call and byte-identical preview
comparison before the first signature. Require issuer creation, publication,
closure verification, WebFinger verification, grant construction, and one
reverse payload in the declared order.

Fail each post-final operation independently. Require no accepted application
capability, exact ceremony-only compensation, and no changed pre-existing or
operator withdrawal state.

Require browser verification and strict local installation before hub final
commit. Require hub immutable status before wallet installation. Lose every
response and restart each component at every boundary. Require exact recovery
without duplicate migration or a local grant shortcut.

Statically require the production credential/v2 call graph to exclude
`assemble_claimant`. Require `prepare_claimant` to have no custody, issuer,
resolver-write, WebFinger, signing, grant, alias, or persistence edge.

### TEST-1159 — Presence, display, policy, installed state, and rendezvous are exact

Generate valid PAIR1 codes for minimum and maximum alphabet branches. Mutate
every separator, forbidden letter, pad bit, checksum bit, case mode, Unicode
lookalike, whitespace position, and BIP-39 collision. Require local refusal and
zeroization without populating the machine carrier.

Insert `C`, `T`, PAIR1 text, or a claim bearer into the carrier. Insert carrier
bytes, QR data, clipboard data, autofill, password-manager data, notification
data, deep-link data, or peer data into the presence component. Require refusal
before CPace.

Mutate each authenticated display source independently. Require no display for
a mismatch. Compile-fail attempts to construct or mutate
`CredentialV2Display`, to return display fields from the verifier, and to use
generic fields or `authority_summary`.

Accept one exact application-relay pair. Present the same relay under another
authenticated application and require a new prompt. Remove the descriptor from
the live profile and require refusal. Scan the ordinary binary and source graph
for a compiled conformance registry, relay allowlist, relay-only key,
held-enrolment precondition, and `record_pairing_trust` call edge. Every match
on the credential/v2 path fails.

Reload an installed link under unchanged, profile-refresh, authority-rotation,
issuer-rotation, unavailable, revoked, handle-change, confirmed-unlink, and
hub-deleted states. Require every [[SPEC-008-production-pairing-claimant#REQ-1006]] outcome. A hub deletion requires
a complete fresh ceremony even when the derived key remains available.

For both rendezvous implementations, PUT and retrieve exact opaque bodies of
1, 57,016, 62,016, and 69,632 octets. Require 69,633 to return 413 and create no
stored body. Re-run slot grammar, capacity, expiry, first-write, read-once,
CORS, and blindness tests. This increment SHALL NOT claim the other PROTO-002
changes.

## Changelog

- **0.5.1-draft — 2026-08-24 — direct standalone protocol reissue.** Defines
  typed authenticated display, exact PAIR1 separation, and zero-effect planning.
  Defines two consent boundaries, reverse issuance, pending-scope recovery,
  installed state, registry removal, and both rendezvous dependencies. No
  implementation or deployment is authorized.
- **0.5.0-draft — 2026-08-23 — consolidated current-authority reissue.**
  Preserves the reviewed standalone mechanism through CON-981. States the
  current authority, busy contracts, tests, pointers, and gate directly. The
  coordinated Tier-1 review remains open. No code or deployment is authorized.
- **0.3.0-draft — 2026-08-22 — first-contact admission (REQ-909): authored,
  adversarially reviewed, REJECTED, withdrawn the same day.** The review
  found no wire source for the mechanism. The invitation's `application`
  member is the constant `anuna.io/credential/v1`, never an `applicationId`.
  Its pre-consent publication violated
  [[SPEC-007-cbcl-pairing-cutover#REQ-812]]. A declined rogue ceremony still
  handed the attacker a fresh account DID. That revision reverted every
  normative edit. Record:
  `specs/trajectory/SPEC-008/req-909-adversarial-review-2026-08-22.md`.
  First contact goes through
  [[IMPL-008-production-pairing-claimant#ADR-913]]'s enrolment wire, which
  the review itself endorses; the numbers REQ-909/TEST-916/TEST-917 are
  burned and not reused.
- **0.2.2** — status `implemented`, review gate `approved`. The repository
  owner reviewed and merged PR #43 on 2026-08-20. The fresh-context review had
  zero blocking findings (`evidence/spec-008-phase-3-gates.yaml`). Depth tests
  TEST-913, TEST-914, and TEST-915 stayed open for production claims.
- **0.2.1** — [[SPEC-008-production-pairing-claimant#CON-903]] first registry entry ratified (owner-directed,
  2026-08-20): `anuna-1`, the SHA-256 of cbcl-bus
  `docs/relay-conformance-anuna-1.md` (cbcl-bus PR #97). The publication
  Open item closes; the second-operator item remains.
- **0.2.0** — implementation findings folded back on branch
  `feature/spec-008-production-claimant`; see
  [[IMPL-008-production-pairing-claimant]]. The CON-207 proof is grant-bound and
  deferred to delivery. The ceremony scope is the profile's single allowed
  permission. ADR-912's linked applications form the trusted-profile set.
- **0.1.0** — first draft, authored from the 2026-08-18 gap analysis of the vault and
  the code (four named failure modes; camera scanning found already built and moved to
  specification debt rather than missing work).
