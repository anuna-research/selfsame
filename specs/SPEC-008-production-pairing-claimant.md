---
id: SPEC-008
title: Production Pairing Claimant — Transport, Real Credential, and Origin Trust
status: draft
version: 0.5.20-draft
tier: 1
review-gate: test-first-implementation-owner-authorized; release-and-deployment-prohibited-pending-cross-model-pass
authority-form: consolidated-direct-current-authority
implementation-baseline: 60abb8b25e858be8005151e47ea2a8044d130e80
generation-model-family: OpenAI GPT-5
generation-model-version: gpt-5.6-sol
generation-session: 01a029aa-9127-7c42-ad28-81512b91ded6
generation-synthesis-trajectory: "owner-authorized standalone architecture -> F-A through F-E code traces -> rejected reviews through 0.5.13 -> continuously reachable Rust, browser, and relay-source gates"
depends-on: "[[SPEC-007-cbcl-pairing-cutover]]; [[SPEC-004-application-scoped-identity]]; [[SPEC-003-android-apk-distribution]]; cbcl-pairing SPEC-001"
last-updated: 2026-09-05
---

# SPEC-008 — Production Pairing Claimant: Transport, Real Credential, and Origin Trust

> **Consolidated current-law reissue.** Version 0.5.19 states the standalone
> first-contact authority directly. Trajectory documents and review reports
> supply evidence only. They supply no current values.
> The repository owner authorized local test-first implementation on
> 2026-08-24. This draft authorizes no production allocation, release, or
> deployment before one coordinated fresh-context Tier-1 PASS.

## Orientation

Intent: Link a wallet to a new application through cbcl-pairing without prior
enrolment or a compiled relay allowlist. The wallet authenticates the application
live and defers every identity effect until the person approves the authenticated intent.
The default complete scan/manual flow treats the entry gesture as current-ceremony
contact authority, then uses one unlock and one Link gesture with the existing
authenticated desktop comparison. Explicit legacy entry retains exact-pair TOFU
and two phone approvals.

Metaphor: the invitation is an introduction, not a reference. The wallet checks
the application's passport and binds the declared relay before it creates the
application's account key. Default entry carries contact permission for this
ceremony; explicit legacy entry asks whether the exact pair may be remembered.

Structure:

```
 invitation       live profile       contact authority       cbcl-pairing
┌──────────┐     ┌─────────────┐     ┌─────────────────┐     ┌────────────┐
│ recognise│────▶│ TLS profile │────▶│ ceremony/legacy │────▶│ CPace bind │
└──────────┘     └─────────────┘     └─────────────────┘     └──────┬─────┘
                                                                  │
                 ┌────────────────┐     ┌────────────────┐         │
                 │ post-consent   │◀────│ authenticated  │◀────────┘
                 │ scope + grant  │     │ exact intent   │
                 └────────────────┘     └────────────────┘
```

Decisions:    [[SPEC-008-production-pairing-claimant#ADR-902]] mode-scoped contact authority · [[SPEC-008-production-pairing-claimant#ADR-963]]
              typed unavailability before policy · [[SPEC-008-production-pairing-claimant#ADR-903]] fixture isolation
Load-bearing: [[SPEC-008-production-pairing-claimant#REQ-906]] ceremony or legacy contact authority · [[SPEC-008-production-pairing-claimant#REQ-1005]] protocol and version
              isolation · [[SPEC-008-production-pairing-claimant#NFR-928]] total fail-closed consumers
Controls:     [[SPEC-008-production-pairing-claimant#REQ-902]] fixture data SHALL NOT enter an ordinary build
              [[SPEC-008-production-pairing-claimant#REQ-905]] the carrier SHALL NOT become an OS-navigable URL
              [[SPEC-008-production-pairing-claimant#REQ-906]] no socket SHALL open before live origin recognition and consent
              [[SPEC-008-production-pairing-claimant#CON-903]] policy is exact `(applicationId, relayOrigin)`, never relay-only
              [[SPEC-008-production-pairing-claimant#REQ-907]] production allocation remains closed pending its gate
              [[SPEC-008-production-pairing-claimant#CON-986]] no credential/v2 identity effect precedes final approval
              [[SPEC-008-production-pairing-claimant#CON-990]] no pre-payload checkpoint can strand an application slot
              Owner-authorized test-first implementation may precede the PASS
              A fresh Tier-1 PASS precedes release and production allocation
              Production deployment requires separate owner approval
Open:         the coordinated fresh-context Tier-1 review (owner: repository owner)
              every production gate listed in [[SPEC-008-production-pairing-claimant#CON-985]] (owner: named gate owners)
Detail:       [[SPEC-008-production-pairing-claimant#REQ-901]], [[SPEC-008-production-pairing-claimant#REQ-906]], [[SPEC-008-production-pairing-claimant#REQ-1005]], [[SPEC-008-production-pairing-claimant#NFR-928]],
              [[SPEC-008-production-pairing-claimant#CON-903]], [[SPEC-008-production-pairing-claimant#CON-985]], [[SPEC-008-production-pairing-claimant#CON-990]], [[SPEC-008-production-pairing-claimant#TEST-1162]], [[SPEC-008-production-pairing-claimant#TEST-1163]], [[SPEC-008-production-pairing-claimant#TEST-1164]]

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

This specification records four historical mechanical failures. The current
baseline repairs each failure, and the successor requirements prevent regression:

- **FM-1 — historical stranded claimant.** The original non-demo path stopped
  before a socket. The current baseline opens WSS. TEST-901 and TEST-905 prevent
  that regression.
- **FM-2 — historical missing TLS.** The original dependency omitted TLS.
  The current baseline enables rustls for WSS. TEST-902 prevents downgrade.
- **FM-3 — historical fixture-only credential path.** The earlier path had no
  production verification context. The current baseline constructs
  `SelfsameVerificationContext` in `assemble_claimant` and `selfsame-web-device`.
  The production pairing command reaches `assemble_claimant`. That function
  fetches a live profile, verifies invitation origin and WebFinger, and resolves
  the live closure. The UI reaches `cbcl_enrol_prepare` and
  `cbcl_enrol_confirm` from `app.js`. Registered `app_grant_review`,
  `app_grant_prepare`, `app_grant_confirm`, and `cbcl_enrol_start` have no UI
  caller. This standing SPEC-004 enrolment path is not the credential/v2
  construction path.
- **FM-4 — historical missing production origin anchor.** The earlier fixture
  binary carried only `[19; 32]`. An ordinary current build omits that
  feature-gated digest. Its standing credential/v1 registry carries the
  production `anuna-1` digest and disables loopback. Credential/v2 replaces
  that path-specific registry with exact-pair TOFU under REQ-1006.

The camera scan is deliberately NOT in this list: it is built and wired
(`src/pairing.js:159`, `src-tauri/capabilities/mobile-scanner.json`). Its gap is
specification debt, covered by [[SPEC-008-production-pairing-claimant#REQ-904]] and [[SCREEN-003-wallet-pairing]].

## Requirements

### REQ-901 — Claimant transport over TLS

WHEN [[SPEC-008-production-pairing-claimant#REQ-906]]'s pre-socket recognition
and mode-appropriate contact authority have produced a `RelaySocketCapability`, the claimant
shell SHALL open one TLS WebSocket (`wss://`). It uses the derived relay
resource. The shell SHALL pump binary
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

In the default complete scan/manual flow, unlock authorizes one hierarchy derivation
inside bounded zeroizing native custody. It authorizes pure `HomeKey::home_did` and
fingerprint computation for local display, with no protocol decision or preview
disclosure. After the complete authenticated request and preview render, one Link
gesture permits disclosure and conditional completion.

The existing authenticated comparison or binding result remains mandatory. Only a
matching result permits the native engine to emit protocol final approval and begin
identity construction. Bounded success requires no second phone approval or unlock.

Explicit legacy entry retains preliminary approval before preview disclosure and a
separate final approval with its existing fresh custody operation. Every mode requires
preview equality before its first identity signature. Creation, signing, publication,
live issuer and WebFinger verification, and delivery occur only under the applicable
final protocol authority. CPace session-key computation remains transport work.

A non-demo build SHALL NOT construct any part of the verification context from
`local_demo`, from `LOCAL_CONFORMANCE_DIGEST`, or from any compiled test fixture.
Enforcement occurs at compile time. The fixture module stays behind the
`local-pairing-demo` feature. The prohibited path is absent from the ordinary binary.
[[SPEC-008-production-pairing-claimant#TEST-904]] verifies symbol absence instead of a runtime check.

Trace: [[SPEC-008-production-pairing-claimant#TEST-903]] [[SPEC-008-production-pairing-claimant#TEST-904]] [[SPEC-008-production-pairing-claimant#CON-902]] [[SPEC-008-production-pairing-claimant#CON-986]] [[SPEC-008-production-pairing-claimant#OBS-902]]

### REQ-903 — Live approve and decline

WHEN an explicit LegacyTwoDecision session has displayed the recognised intent,
`cbcl_pairing_approve` and `cbcl_pairing_decline` SHALL commit its preliminary
person decision. In SingleLink, only the rendered-review Link command can cause
the native engine to emit the equivalent protocol decision. Both use
[[SPEC-008-production-pairing-claimant#REQ-901]] in non-demo builds and retain
[[SPEC-007-cbcl-pairing-cutover#REQ-804]] ordering.

Trace: [[SPEC-008-production-pairing-claimant#TEST-905]] [[SPEC-008-production-pairing-claimant#CON-901]]

### REQ-904 — Scan, paste, and manual entry converge by mode

The default complete scan and paste paths SHALL deliver byte-identical `SSPAIR1:`
handoffs to one entry point. Explicit manual mode SHALL accept a scanned or pasted
`SSPAIR-M1:` bootstrap plus a separate three-word phrase under cbcl-bus SPEC-078
0.1.1-draft. It SHALL NOT combine, infer, or fall back between these modes.
The Android wallet SHALL distinguish three scan failures. They are platform refusal,
person refusal, and plugin unavailability. Each produces its own message. Screen
detail lives in [[SCREEN-003-wallet-pairing]].

Trace: [[SPEC-008-production-pairing-claimant#TEST-906]] [[SPEC-008-production-pairing-claimant#TEST-907]]

### REQ-905 — Carrier binding

Credential/v1 and explicitly selected legacy credential/v2 input retain the
unpadded base64url public carrier. New credential/v2 scan and paste use the
shared cbcl-pairing SPEC-001 0.5.10 confidential `SSPAIR1:` handoff recognizer.
The complete handoff contains the unchanged public carrier and independent C/T.
Neither input is an OS-navigable URL. Recognition, commitment matching, required
allocator key and exclusive relay-expiry checks precede profile/relay effects.
Unsupported prefixes never fall back to another input path. New scan starts
recognition automatically. A complete handoff requires no presence keystrokes.

Explicit manual entry uses only the fully recognized `SSPAIR-M1:` carrier-plus-T
bootstrap and three complete words. Local bounds, canonical decoding, list
recognition, and checksum verification precede profile or relay work. The resulting
typed C and T enter the unchanged credential/v2 protocol. A checksum-valid wrong
phrase consumes the invitation's single peer-share attempt; invalid local input does not.

Trace: [[SPEC-008-production-pairing-claimant#TEST-908]] [[SPEC-008-production-pairing-claimant#CON-901]]

### REQ-906 — Live application authentication and mode-scoped contact authority

Before a relay socket opens, the claimant SHALL dereference the invitation's
canonical application ID and complete [[SPEC-004-application-scoped-identity#CON-220]] steps 1 through 5. This
credential/v2 pre-socket result authenticates the HTTPS origin and completely
recognises one candidate profile. It does not claim to complete
[[SPEC-004-application-scoped-identity#CON-220]] step 6.
The candidate profile SHALL list the exact invitation relay origin and selected
descriptor.

The claimant SHALL bind that exact profile to the allocator. The binding uses
the credential/v2 CPace public context and both Finished values. It precedes a
new policy row, intent display, or profile-key use. The local profile digest
SHALL equal the peer-authenticated CPace digest. Mismatch is terminal and
creates no row.

Explicit legacy entry SHALL evaluate trust for the exact tuple
`(authenticatedApplicationId, canonicalRelayOrigin)`. Relay-only trust SHALL NOT
authorize a new application. SingleLink SHALL neither evaluate nor create this
durable trust state.

WHEN explicit legacy entry finds the tuple absent, the wallet SHALL show one new-relay decision. The surface
SHALL name the origin-recognised application and canonical relay origin. Approval SHALL
produce one provisional, single-use socket capability. After CPace binds the same
profile digest, the wallet SHALL atomically seal the tuple into the person's policy
before intent display. Rejection SHALL create no policy entry, socket, wallet scope,
key, alias, DID, grant, or publication.
The browser's bounded candidate scope remains ceremony-only and expires or aborts.

WHEN explicit legacy entry finds the tuple present and valid, the wallet MAY proceed without another TOFU
prompt. A changed application or changed relay origin is a new tuple and SHALL prompt.

For default complete scan/manual entry, the recognized foreground entry gesture
creates `CeremonyGesture` provenance after complete local recognition. It authorizes
only this ceremony's live profile fetch and socket to the unique matching declared
relay. It creates, modifies, and relies on no durable exact-pair row. The typed display
states ceremony contact provenance without claiming remembered relay trust.

The person SHALL NOT enter, choose, or repair a relay origin. TLS failure,
candidate-profile failure, or malformed origin SHALL end the attempt before
relay socket creation. Legacy consent-store unavailability SHALL also end its
attempt before socket creation. A peer profile-digest mismatch, or a legacy
durable policy-write failure, SHALL end it after Finished but before display or
identity work.

Trace: [[SPEC-008-production-pairing-claimant#TEST-909]] [[SPEC-008-production-pairing-claimant#TEST-910]] [[SPEC-008-production-pairing-claimant#CON-903]] [[SPEC-008-production-pairing-claimant#CON-986]] [[SPEC-008-production-pairing-claimant#CON-988]] [[SPEC-008-production-pairing-claimant#OBS-903]]

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
Pre-conditions: [[SPEC-008-production-pairing-claimant#REQ-906]]'s pre-socket
gates passed and its single-use socket capability exists; context assembled per
[[SPEC-008-production-pairing-claimant#CON-902]].
Post-conditions: exactly one terminal outcome; socket closed; no identity side effect
or accepted application capability survives a non-accepted outcome. Post-final
failure follows [[SPEC-007-cbcl-pairing-cutover#REQ-812]] compensation.
Error model: TLS failure, connect failure, timeout, and close-before-terminal each map
to distinct, secret-free `UiError` values; none is retried silently.
Implements: [[SPEC-008-production-pairing-claimant#REQ-901]] [[SPEC-008-production-pairing-claimant#REQ-903]] [[SPEC-008-production-pairing-claimant#REQ-905]] [[SPEC-008-production-pairing-claimant#NFR-901]]
Verified by: [[SPEC-008-production-pairing-claimant#TEST-901]] [[SPEC-008-production-pairing-claimant#TEST-902]] [[SPEC-008-production-pairing-claimant#TEST-905]] [[SPEC-008-production-pairing-claimant#TEST-908]]

### CON-902 — Split authenticated plan, preview, and effect assembly

Endpoint/Interface: explicit legacy `recognise_claimant_invitation` fully
recognises the machine carrier and PAIR1 value. Default entry fully recognizes
the complete handoff or manual bootstrap-plus-words pair before reserving one
native attempt. It then uses `CeremonyGesture` for the pre-socket candidate-profile
recognition in [[SPEC-008-production-pairing-claimant#CON-988]].

In LegacyTwoDecision, `authorise_claimant_relay` owns the exact-pair decision. The Tauri commands
`cbcl_pairing_relay_approve` and `cbcl_pairing_relay_decline` are its only UI
entry points from `pairing.js`.

Legacy approval returns one provisional `RelaySocketCapability`. Decline returns a
terminal without a policy write, socket, CPace operation, or identity effect.
An existing exact policy returns the same capability without another prompt.
SingleLink consumes its private current-ceremony contact authority to create an
equivalent one-use socket capability without policy lookup, prompt, or row write.

`prepare_claimant` consumes that capability before opening the relay socket.
It completes CPace and both Finished values. It requires the peer-bound profile
digest to equal the pre-socket candidate digest. In legacy mode it then atomically
persists a newly approved [[SPEC-008-production-pairing-claimant#CON-903]] row.
SingleLink persists no such row. Signed-offer verification and every authority
cross-check precede the zero-effect authenticated identity plan in both modes.

SingleLink unlock computes only local preview and retains bounded native custody.
After rendered review, its Link capability emits preliminary approval and preparation
once, then conditionally emits final protocol approval only after authenticated
comparison. Legacy `preview_claimant_identity` consumes preliminary approval and
returns preview material; `complete_claimant` consumes its separate final approval.

The authenticated plan contains these authoritative sources:

| Field | Authoritative source |
|---|---|
| `profile` | [[SPEC-008-production-pairing-claimant#CON-988]] live origin-recognised bytes bound by CPace Finished |
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
`(socketGeneration, requestId, carrierCeremonyId)` entry. It consumes that entry
before displaying the carrier. An exact active retry returns the byte-identical
acknowledgement and pending values.

After socket loss, the browser reconnects and requests status with the original
request, carrier ceremony, and persisted installation key. It starts a fresh
allocation only after authenticated status proves that no pending or finalized
record exists. A concurrent different allocation refuses while pending state exists.

A fresh attempt after authenticated exact-ceremony terminal or absence proof
receives fresh account and scope randomness. Local cancellation, deadline, or
ambiguous failure alone does not authorize it. If the resulting preview DID differs, the wallet SHALL display
it again and obtain the mode's complete person authority. Prior Link or legacy
approval cannot authorize it.

A crash before hub allocation commit leaves no pending value. A crash after that
commit recovers the exact bounded pending record or deletes it at expiry. A crash
during final migration recovers either the complete pending state or the complete
immutable finalized state. A crash after final commit cannot recreate legacy rows or
roll the account back.

SingleLink unlock permits one pure DID preview and retains the root only inside
zeroizing native custody until its bounded deadline. Its Link capability is
private, noncloneable, nonserializable, and single-use. It binds the exact
attempt, flow, root generation, carrier, profile, relay, transcript, offer,
intent, transition, account, scope, device, permissions, preview, predecessor,
and deadlines.
After comparison and protocol final approval, it recomputes preview equality within
that retained custody before effects. Legacy capabilities retain no hierarchy root
or private key and use their existing separate final custody call.

The executor re-derives the wallet application home key and checks the preview.
It then creates and signs the issuer state and publishes the DID. It resolves
and verifies the closure. It obtains and verifies the live WebFinger JRD against
the authenticated profile and new issuer. It constructs the grant last.

It performs no issuer, closure, or JRD operation that depends on the derived DID
before final approval. A failure compensates only effects created by this
ceremony and never operator withdrawal state.

Pre-conditions: authenticated profile and signed offer, authenticated preliminary
intent, successful comparison or binding result, and applicable final protocol
authority. SingleLink additionally requires live bounded Link authority and exact
ceremony provenance. Legacy requires its exact-pair policy and separate approvals.

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

This set governs only explicit LegacyTwoDecision entry. SingleLink neither reads
nor writes it and cannot convert `CeremonyGesture` into a durable row.

Input grammar: `applicationId` uses the
[[SPEC-008-production-pairing-claimant#CON-988]]-bound profile identifier.
`relayOrigin` uses the recognised canonical HTTPS origin from the invitation and
profile. The recogniser accepts no path, query, fragment, credentials, or non-HTTPS
production origin.

Pre-conditions: [[SPEC-004-application-scoped-identity#CON-220]] steps 1 through 5 authenticated the profile origin and
recognised its application ID. The person approved this exact pair before the
socket. CPace and both Finished values then bound the same profile digest and
carrier before a new row was written.

Post-conditions: one durable sealed row exists for the exact pair. No relay-only key,
global allowlist, conformance-digest registry, or application wildcard participates.

Error model: missing, corrupt, unavailable, or ambiguous existing policy state
refuses before socket creation. Rejection, CPace/profile mismatch, and storage
failure create no row or identity effect. A post-Finished storage failure closes
before intent display.
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

The invitation supplies an untrusted relay origin. [[SPEC-004-application-scoped-identity#CON-220]] steps 1 through 5
authenticate the serving origin before consent. Credential/v2 CPace then binds
that exact profile digest to the allocator. Policy persistence and display
follow that binding.

The person authorizes the exact application-relay pair. This keeps relay topology out
of wallet releases and prevents an accepted relay from authorizing another application.

The application profile does not prove relay operatorship. Exact-pair consent contains
that residual without claiming to solve it.

This decision remains current for explicit LegacyTwoDecision. For default complete
scan/manual entry, cbcl-bus SPEC-079 0.1.1-draft makes the foreground entry gesture
current-ceremony contact authority after exact live-profile recognition. It grants no
durable trust and cannot authorize another ceremony, application, relay, or effect.

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

Positive for [[SPEC-008-production-pairing-claimant#REQ-902]]. In SingleLink,
unlock performs one pure preview derivation and zero protocol decisions, disclosures,
or writes. Rendered Link consumes one capability. Authenticated comparison permits
one final protocol approval and the retained bounded custody supplies the real context.
Legacy retains its separate preliminary and final approvals and final custody call.

### TEST-904 — Ordinary binaries contain no fixture authority

Prohibited action for [[SPEC-008-production-pairing-claimant#REQ-902]]. The
non-demo binary contains no `local_demo` symbol or `[19; 32]` digest. An
`nm` and `strings` assertion proves absence. Locked custody refuses before any
socket opens.

### TEST-905 — Live approve and decline terminate

Positive for [[SPEC-008-production-pairing-claimant#REQ-903]]. Non-demo
approve and decline drive the live session to matching terminal states.

### TEST-906 — Scan and paste carriers converge

Positive for [[SPEC-008-production-pairing-claimant#REQ-904]]. Scan-delivered
and pasted complete handoffs produce byte-identical default inputs. Scanned and
pasted manual bootstraps plus the same words produce byte-identical typed manual
inputs. Cross-mode combinations refuse without fallback.

### TEST-907 — Scanner failures remain distinct

Negative input for [[SPEC-008-production-pairing-claimant#REQ-904]]. The three
scan failure causes produce distinct messages. Device confirmation remains a
depth case.

### TEST-908 — Carrier wrappers refuse before state

Negative input for [[SPEC-008-production-pairing-claimant#REQ-905]]. Wrap a
legacy carrier in a URL scheme, padding, or a legacy prefix. For complete handoffs, test unsupported versions, malformed/oversize/noncanonical wrappers and claim mismatch. Recognition refuses it
before any state change.
For manual input, test bootstrap/phrase bounds, canonical CBOR/base64url, word count,
list membership, ASCII normalization, checksum, commitment, and wrong-mode inputs.
Require every local refusal before profile, policy, relay, or endpoint state.

### TEST-909 — A new exact pair prompts once

Positive and negative for [[SPEC-008-production-pairing-claimant#REQ-906]]. A
new explicit legacy exact pair prompts once. Approval creates one provisional socket capability.
Matching CPace Finished values then permit one pair row before intent display.
Rejection and pre-socket profile failure open no socket. A CPace profile
mismatch creates no row or display.

Default complete scan/manual entry produces `CeremonyGesture`, opens only the
unique live-profile relay, and displays truthful current-ceremony provenance.
Require no policy lookup, relay prompt, new row, or conversion to legacy trust.

### TEST-910 — Pair trust cannot authorize another application

Negative for [[SPEC-008-production-pairing-claimant#CON-903]]. Trust for one
application-relay pair never authorizes another application on the same relay.
Corrupt or unavailable policy refuses without a socket or identity effect.
SingleLink ignores that policy for authority and cannot read, modify, or create it.

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
[[spec-008-0.5.7-claude-adversarial-review-2026-08-24#Collected corrections and owners]].
This reissue retains every closed mechanism finding. It closes the nested
socket-generation and recovery-proof inputs. It also resolves the seven
non-blocking observations identified there.

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

Credential/v2 SHALL conform to cbcl-pairing SPEC-001 0.5.10-draft. The
cbcl-pairing parent records this document as its consumer.

Explicit legacy entry uses separate typed machine-carrier and PAIR1
presence-field inputs. Default full entry uses the complete `SSPAIR1:` handoff.
Explicit manual entry uses separate typed `SSPAIR-M1:` bootstrap and three-word
inputs. Cbcl-pairing enforces non-substitutability, mode and version isolation,
CPace source, sender rules, state rules, and its envelope.

The wallet provides live approve and decline under [[SPEC-008-production-pairing-claimant#REQ-903]]. The two-stage
credential/v2 decision sequence follows [[SPEC-008-production-pairing-claimant#CON-902]] and
[[SPEC-007-cbcl-pairing-cutover#REQ-804]].

Within each mode, scan and paste decode the same accepted bootstrap form into
the same recognized type under [[SPEC-008-production-pairing-claimant#REQ-904]].
The separate legacy PAIR1 and manual word fields remain type-only.

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

Production version-constant evidence is
`crates/selfsame-app-identity/src/profile.rs:60`. The crate root at
`crates/selfsame-app-identity/src/lib.rs:109` publicly re-exports that item.
The implementation SHALL keep `profile::PROFILE_VERSION` as the sole constant
definition. The crate root MAY publicly re-export that item but SHALL NOT
define a second `pub const PROFILE_VERSION`. The executable workspace scan
SHALL prove exactly one definition, its owning source, and equality through
the public re-export. Named witnesses never replace that complete scan.

Named sites are evidence only. They cannot close or limit the production
scan.

`successionVersion` belongs to identity succession under
[[SPEC-004-application-scoped-identity#REQ-231]] and
[[SPEC-004-application-scoped-identity#CON-225]].

`WIRE_VERSION` belongs to the complete link-record wire namespace. It governs
both link-offer and link-grant records. Its governing source
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

The public machine carrier and presence remain separate typed values inside
the protocol. The public carrier contains no C, T, or PAIR1 text. The shared
confidential handoff yields those two typed inputs after full recognition.
Possession of the complete QR can authenticate bootstrap possession during the
attempt lifetime. It authorizes neither identity effects nor installation.
The default scan/paste entry accepts the complete handoff. Explicit manual entry
accepts cbcl-bus SPEC-078 0.1.1-draft CON-001's carrier-plus-T bootstrap and
CON-002's three complete words. Its typed mode, phrase-to-C mapping, one-peer-share
checkpoint, restoration, and expiry follow that draft's CON-003 and CON-005.
An explicitly selected legacy entry MAY accept a public carrier and separate
PAIR1 value. No input, C prefix, error, or restored unmodeled record automatically
selects or falls back to another mode. The legacy encoding follows.

A requested mode switch SHALL hide the old transfer values and retain the old
sealed recovery record. Release requires an authenticated exact-ceremony
`expired`, `aborted`, or `absent` hub result, or a verified accepted immutable
final status. Local cancellation, local or forward-clock expiry, hub
unavailability, and transport failure are not closure proof. Only verified
closure permits fresh independent mailbox, ceremony, nonce, T, C, scalar,
request, and intent material.

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

Before any disclosure consent, `cbcl-pairing` SHALL construct one private
`CredentialV2Display` only after Selfsame verification. The verifier SHALL
authenticate the live profile, signed hub offer, carrier, and transcript. It
SHALL also authenticate the exact application, relay, account, scope,
permissions, installation key, and complete account transition.

The verifier SHALL return only a closed verdict. It cannot return, append,
replace, or mutate display text. Generic `DisplayField`, wire
`authority_summary`, wire application text, peer-provided labels, caller
booleans, and DOM room values SHALL NOT enter the credential/v2 consent
surface.

The authenticated request SHALL show application ID, HTTPS origin, relay origin,
account assertion provenance, permissions, installation binding, contact provenance,
and the complete transition. Default entry truthfully shows `CeremonyGesture`, not
remembered trust. Legacy entry shows its exact-pair policy state.

In SingleLink, unlock adds the locally derived DID and fingerprint only to the
local display. After that complete review renders, one Link gesture authorizes
preview disclosure and conditional completion under cbcl-bus SPEC-079 0.1.1-draft
CON-002 and CON-003. Authenticated desktop comparison remains mandatory before
the native engine emits final protocol approval. The bounded success path requires
no second phone approval or passcode. LegacyTwoDecision retains its preliminary
and final approval screens and existing custody behavior.

For explicit legacy entry, the wallet SHALL store credential/v2 relay policy only under the exact
`(applicationId, relayOrigin)` pair. The credential/v2 path SHALL use no
compiled relay allowlist, conformance-digest registry, relay wildcard, or
relay-only trust fallback in an ordinary build. A profile that names a
previously accepted relay under another application SHALL still require the
new exact-pair prompt. SingleLink reads and writes no such row. The standing credential/v1 registry and selection
control remain compiled and unchanged. Their implementation comment SHALL cite
[[SPEC-007-cbcl-pairing-cutover#CON-806]], not
[[SPEC-008-production-pairing-claimant#CON-903]].

After the hub's immutable final acknowledgement, the wallet SHALL atomically
install one record. It SHALL contain the root generation, grant bytes, grant
digest, application ID, account-principal digest, and account scope ID. It SHALL
also contain the installation device key, profile digest, account authority,
issuer DID, offer-core digest, and carrier ceremony ID. It SHALL retain the
exact immutable hub status JWS and digest.

Reload SHALL verify the installed grant, current profile, authority, issuer,
and hub status before granting application capability. Hub or resolver
unavailability SHALL be distinct from revocation or absence and SHALL NOT clear
the installed record.

A profile-only digest refresh with unchanged authority and issuer MAY re-pin
silently after full verification. Authority or issuer rotation SHALL prompt the
person. A changed installed handle SHALL refuse. No network input can silently
rename an installed account.

Unlink SHALL apply to an installed record and to every recognised pending
record, including pre-payload phases that are not eligible for terminal
recovery. Every pending record SHALL be visible to the person as an interrupted
link after restart. Unlink SHALL require explicit confirmation and current-root
presence. Selection SHALL retain both the exact pending-or-installed slot and
its flow and contact provenance. Deletion SHALL refuse and retain the slot if
that value differs at confirmed execution. For LegacyTwoDecision only, selection
also retains the exact-pair policy state observed with the slot. Legacy deletion
SHALL refuse and retain the slot if that selected policy state also differs at
confirmed execution. An absent
legacy policy at selection SHALL not prevent deletion. A present selected
legacy policy SHALL be removed before the exact slot. If slot deletion fails,
legacy policy restoration is best effort. A later selection of the still-present
slot and now-absent legacy policy SHALL remain deletable. SingleLink SHALL NOT
read, compare, remove, or restore any exact-pair policy.

Successful unlink SHALL remove only the selected application record and its
contained profile cache. For LegacyTwoDecision, it SHALL also remove the selected
`(applicationId, relayOrigin)` policy when present. SingleLink SHALL preserve
every unrelated legacy policy row. Every mode retains the root seed, sibling
applications, and every remote hub record. It SHALL NOT claim remote hub
revocation. Re-grant after hub-side deletion or confirmed local abandonment
requires a complete fresh pairing ceremony. A local shortcut using the
retained derived key is prohibited.

Trace: [[SPEC-008-production-pairing-claimant#CON-986]], [[SPEC-008-production-pairing-claimant#CON-987]], [[SPEC-008-production-pairing-claimant#CON-988]], [[SPEC-008-production-pairing-claimant#CON-989]], [[SPEC-008-production-pairing-claimant#CON-990]], [[SPEC-008-production-pairing-claimant#TEST-1160]], [[SPEC-008-production-pairing-claimant#TEST-1161]], [[SPEC-008-production-pairing-claimant#TEST-1162]].

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
`cbcl-chat-roomcfg:transform-room/1` is the third schema migration. It also
lies outside that inventory.

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

The browser treats 1013 as non-terminal. It cancels the old socket generation
and reconnects. For credential/v2 allocation, it first recovers status under
the original request and carrier ceremony. It starts a fresh allocation only
after authenticated status returns absent.

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

The current SPEC-008 test set is TEST-901 through TEST-915 and TEST-1156
through TEST-1169. Every member of that set is stated in this parent.
[[SPEC-007-cbcl-pairing-cutover]] TEST-801 through TEST-821 remain the other
current Selfsame test set and are stated in that parent. No plan or review can
omit either set.

The exact coordinated hub test set is TEST-115 through TEST-121. The hub's
base-parent tests remain current outside this coordinated increment set.

The coordinated review set contains this parent,
[[SPEC-007-cbcl-pairing-cutover]] 0.3.10-draft, cbcl-pairing SPEC-001
0.5.10-draft, and cbcl-bus SPEC-053 0.17.15-draft.

The `anuna-ssi` namespace reference is outside that set. It is pinned at
`c7d462029841ea1884bb6f089732058d8838728d` only to resolve
[[SPEC-008-production-pairing-claimant#REQ-1005]]'s two namespace exclusions.
It is an explicit cross-vault deferral, not a coordinated design input.

The cbcl-pairing, cbcl-bus, and anuna-ssi parent identifiers are explicit
cross-vault pointers. Their vaults are outside this repository, so these
identifiers are deliberately not local wikilinks.

The cbcl-pairing SPEC-001 parent records this parent as its credential/v2
consumer. The hub parent records the same coordinated review set.

Every F-A through F-E correction remains a hard stop.
[[SPEC-007-cbcl-pairing-cutover#REQ-812]] also remains a hard stop.

The repository owner's 2026-08-24 waiver authorizes the Elephant SPL and local
test-first implementation before PASS. It authorizes no production allocation,
release, or deployment. Those actions still require the fresh Tier-1 PASS and
their separate gates.

The exact candidate closure is Selfsame
`48a0c7499ab83bdf1d77f6cfb8a09562a7c046f7`, cbcl-bus
`14f26065cb147633416def15d0a7d8603bce2e09`, cbcl-pairing
`62ef4a968b46b4836374fcee1d78c410f730a7a7`, cbcl-rs
`febc6691e6dd2d5f7116b1a4d84c984b64717564`, and did-crdt
`1f409a4229d07a62dd4cc6b2dce3b5a2e18e78a1`. The vendored Selfsame browser
WASM SHALL rebuild byte-identically under rustc 1.96.0 and wasm-bindgen
0.2.126 on `x86_64-unknown-linux-gnu`, the hub CI container host. Its SHA-256
is `a8f82e98e2e74eb8b5bf882d53bedfc7b3a11486620910408b82eda2e969ec07`.
The provenance record SHALL equal all four source pins, the tool versions,
host triple, and artefact digest. `--vendor` SHALL update those values from
the already verified pin files rather than retaining caller-edited stale SHAs.

### CON-986 — Standalone claimant decisions, effects, and recovery

`recognise_claimant_handoff` SHALL recognize the shared complete handoff.
`recognise_claimant_manual` SHALL recognize cbcl-bus SPEC-078 0.1.1-draft's
complete manual bootstrap and three-word language before profile or relay work.
`recognise_claimant_invitation` MAY retain explicit legacy carrier and PAIR1 input.
All modes SHALL perform [[SPEC-008-production-pairing-claimant#CON-988]]'s
pre-socket origin recognition and exact declared-relay check before a socket.
Default recognition creates a fresh opaque native attempt tag before contact and
binds `CeremonyGesture`; a stale tag cannot contact or cancel a newer attempt.
Legacy recognition alone enters the existing relay-policy gate.

For explicit legacy entry, `authorise_claimant_relay` SHALL own the exact-pair prompt and provisional
socket capability. `cbcl_pairing_relay_approve` returns that single-use
capability without writing a new pair row. `cbcl_pairing_relay_decline` creates
no row or socket. `prepare_claimant` atomically writes a newly approved
[[SPEC-008-production-pairing-claimant#CON-903]]
row only after CPace and both Finished values bind the candidate profile digest.

For default complete scan/manual entry, `CeremonyGesture` produces a private
single-use socket capability for only the exact live profile and unique declared
relay. It SHALL NOT read, write, or promote a legacy pair row. The typed display
names ceremony contact provenance instead of exact-pair trust.

`prepare_claimant` SHALL consume the socket capability before socket creation.
It SHALL complete CPace and both Finished values. The peer-bound profile digest
SHALL equal the pre-socket candidate digest. Only then SHALL it persist a newly
approved policy row in LegacyTwoDecision; SingleLink SHALL persist no such row.
Signed hub-offer verification and every overlapping
authority comparison SHALL precede the bounded authenticated plan.

The plan SHALL contain no custody handle, hierarchy root, or derived
application key. It SHALL contain no home DID, issuer state, WebFinger JRD,
resolver closure, signature, grant, alias, publication, scope mint, or durable
identity record. The hub-signed account-principal digest and scope are
authenticated non-secret KDF inputs. They travel inside the protected channel,
signed final status, and private installed record. None is a public identity
authority. The raw application account ID remains hub-private.
The wallet SHALL neither allocate nor persist the scope before final status.

In SingleLink, unlock authorizes exactly one zeroizing custody call. It derives
the application home key and computes the pure home DID and fingerprint for local
display. It retains the hierarchy root only in bounded native custody and performs
no protocol decision, disclosure, signature, issuer creation, or resolver/WebFinger
call. It also performs no grant construction, publication, alias, bundle, or
durable identity write.
Legacy preliminary approval retains its existing one-shot preview behavior and
erases the key and hierarchy root before returning.

When the live profile advertises `credential-v2-account-select/v1`
([[SPEC-004-application-scoped-identity#CON-201]]), `bind_finished_profile`
SHALL, after both Finished values and before any offer, select the account
this wallet already holds for the application from its private installed
record, or a new account when none is installed, and the transport SHALL send
exactly one cbcl-pairing `AccountSelect` object carrying that selection
([[SPEC-080-selfsame-account-continuity]] CON-001). The offer verifier SHALL
then refuse an offer whose `accountScopeId` differs from a selected scope.
The selection reads the installed record only: it mints, persists, and
discloses nothing else, and a non-advertising profile sends nothing.

The wallet SHALL disclose the preview DID and fingerprint only to the
[[SPEC-008-production-pairing-claimant#CON-988]]-bound application inside the established cbcl-pairing channel.
SingleLink SHALL first return the local preview to the UI with no decision or
preparation. After the complete request and preview render, one Link gesture
creates one private, noncloneable, nonserializable native authority. It emits the
existing preliminary protocol approval and preparation once, then awaits comparison.
Legacy SHALL retain preliminary approval before that disclosure and continuation.
A shared native attempt generation and UI epoch invalidate in-flight results on
cancellation; stale operations cannot restore state, send preparation, or authorize effects.
The browser SHALL return the authenticated comparison or binding result. Any
mismatch, terminal, decline, cancellation, timeout, or relay failure erases the
preview and authorizes no later effect.

SingleLink's Link authority binds attempt/generation, flow, root generation,
carrier/profile/descriptor/relay/transcript, offer/core/intent/transition,
account/scope, installation key, permissions, preview, predecessor, and deadlines.
Only exact authenticated comparison or binding consumes it into protocol final
approval and effect execution. A UI boolean, matching text, or duplicate command
cannot substitute. Legacy retains its separate final screen and approval capability
with the same immutable protocol bindings.

The offer deadline is exclusive and equals the hub's `pendingExpiresAt`. SingleLink
additionally expires at the earliest of 120 suspend-inclusive monotonic seconds from
unlock, offer expiry, and relay expiry. Every await/effect boundary resamples that
deadline, whole-UTC offer/relay time, attempt generation, root generation, and
cancellation fence. No clock failure, suspension, background transition, rollback,
renewal, or extension preserves authority. The
wallet SHALL refresh its whole-UTC-seconds clock after each human pause and
immediately before final approval, the first final identity effect, and payload
send. It SHALL require `now < expiresAt` at every check. No clock-skew allowance
applies to this offer deadline. Expiry before the durable recovery barrier
erases the capability and performs only ceremony-owned compensation. A fresh
ceremony still requires authenticated closure. The barrier is the transaction's
recognized durable `PayloadPrepared` value. That recognized commit remains the barrier,
including after an ambiguous write before observed payload release. After the
barrier, expiry or cancellation preserves the sealed pending slot. Recovery MAY
resume only its permitted exact cached frame and receipt transition. It never
authorizes another identity effect, payload construction, or fresh payload.
Every effect entry SHALL atomically recheck and register against the same
revocation fence before starting. Once cancellation or expiry is observed, an
already in-flight effect MAY perform only its exact ceremony-owned compensation.

Before the first final identity effect, `complete_claimant` SHALL write one
sealed `PendingCredentialV2Completion` into the application's secure-store
slot. The slot is a tagged pending-or-installed union, never two records.

The pending value contains authenticated final-decision protocol evidence, the
authenticated plan, and cbcl-pairing `EndpointCheckpointV2`. It contains no live
Link or legacy decision capability, hierarchy root, passcode, or renewable
custody permission. It contains no derived key, issuer key, grant key, signature,
publication result, or application capability.

Its checkpoint wrapping key is a distinct HKDF-SHA512 child of the 64-octet
hierarchy root. Let `labelBytes` be the UTF-8 bytes of
`selfsame credential/v2 claimant checkpoint wrapping v1`, and let
`applicationBytes` be the canonical UTF-8 application ID. The construction is:

```text
checkpointInfo =
  U32BE(len(labelBytes)) || labelBytes ||
  U32BE(len(applicationBytes)) || applicationBytes
checkpointPrk = HKDF-Extract-SHA512(carrierCeremonyId, hierarchyRoot)
checkpointWrappingKey = HKDF-Expand-SHA512(checkpointPrk, checkpointInfo, 32)
```

Both lengths count octets. `carrierCeremonyId` is the raw 32-octet salt. The
raw wrapping key never leaves the custody closure.

The SingleLink final executor SHALL use only the still-live bounded native custody
and recompute byte-for-byte preview DID and fingerprint equality. It SHALL NOT
reopen custody or reuse a cached passcode. The legacy final executor retains its
separate custody invocation and the same equality check. The applicable executor SHALL
then create and sign the issuer and publish the DID. It
SHALL resolve and verify the closure and live WebFinger JRD. It SHALL then
construct the grant and approved reverse payload.

Those steps occur only after the applicable final protocol approval and as the declared provisioning
work needed to deliver the approved payload. A failure releases no accepted
credential or application capability. Compensation is limited to effects
created by this ceremony and follows
[[SPEC-004-application-scoped-identity#CON-204]]. It never changes an
operator withdrawal or a pre-existing identity.

These effects conform directly to
[[SPEC-007-cbcl-pairing-cutover#REQ-812]] and
[[SPEC-007-cbcl-pairing-cutover#CON-807]]. Before final protocol approval, no causal
identity effect is permitted. Post-final failure authorizes no application
capability and enters the exact compensation path.

The browser SHALL verify the reverse payload, resolver closure, WebFinger
binding, grant chain, installation key, account, scope, issuer, profile,
permissions, transition, and device proof. It SHALL write one crash-safe
inactive staging record before requesting hub finalization. That record grants
no application capability.

The browser SHALL activate the staging record only after it authenticates the
hub's immutable `finalStatusJws` and acknowledgement. It SHALL verify the JWS
under the live profile request-signing key whose `kid` signed the offer. It
then sends that exact JWS and digest through the receipt's large body.

The wallet SHALL accept no receipt without that immutable JWS and digest. It
SHALL verify the signature against the live authenticated profile. It SHALL
also match every status field to its retained ceremony and accepted payload.
Before ordinary or recovered installation, it SHALL independently verify the
live reciprocal binding required by cbcl-bus SPEC-079 0.1.1-draft CON-004.
The signed status, receipt, pre-grant WebFinger check, and reload verification
cannot substitute. Unavailable or mismatched reciprocal binding preserves the
pending slot and grants no installed state.

The wallet SHALL then atomically install the record required by
[[SPEC-008-production-pairing-claimant#REQ-1006]]. Crash or loss before that
wallet commit recovers from the authenticated relay receipt or
[[SPEC-008-production-pairing-claimant#CON-989]]'s signed durable status and
retained sealed ceremony state. It does not invent a local grant or repeat a
hub migration.

Recovery SHALL unlock custody and open the exact pending slot. It SHALL
reauthenticate the current HTTPS origin and profile under CON-989. It first
resumes only its cached protocol frame. After relay
expiry it SHALL use only CON-989. Verified ordinary or recovered receipt
atomically replaces the tagged pending value with the installed record.
Decline before final-approval persistence creates no pending value. Every
terminal result after final-approval persistence and before a successful
durable `PayloadPrepared` replacement SHALL run
[[SPEC-008-production-pairing-claimant#CON-990]]'s exact-attempt compensation
before returning. Authenticated signed `not-finalized`, explicit unlink, or
root purge removes the applicable pending value. Relay, offer, or mailbox
expiry after a payload was durably sent SHALL NOT erase it.
Cbcl-pairing refuses a post-payload refusal object and retains the exact
`payload -> receipt` checkpoint for CON-989 recovery.

Every credential/v2 offer, decision, preparation, and payload crosses only the
cbcl-pairing relay. The ordinary receipt crosses that relay. After the relay
window, only CON-989's signed final-status recovery can supply the same receipt
authority over direct HTTPS to the authenticated application origin. The
credential/v2 call graph SHALL contain no Selfsame or did-crdt rendezvous read,
write, route, or client edge.

On the credential/v2 path, the wallet ordinary build SHALL contain no compiled
conformance registry, relay allowlist, held-enrolment precondition, or fallback
to `assemble_claimant`. That path SHALL contain no `record_pairing_trust` call
edge. The standing SPEC-004 caller remains unchanged.

Two mode-checked dispatch paths SHALL be the only credential/v2 claimant construction paths.
SingleLink owns recognized full/manual entry, tagged contact, unlock preview,
render acknowledgement, Link, comparison continuation, and bounded completion.
LegacyTwoDecision retains `recognise_claimant_invitation`, `authorise_claimant_relay`,
`prepare_claimant`, `preview_claimant_identity`, and `complete_claimant`.
Neither path invokes a command or consumes authority from the other.
`recover_claimant_completion` is a terminal recovery adapter only. It cannot
construct, derive, sign, publish, or resend the payload.

Implements: [[SPEC-008-production-pairing-claimant#REQ-902]], [[SPEC-008-production-pairing-claimant#REQ-906]], [[SPEC-008-production-pairing-claimant#REQ-1006]].
Verified by: [[SPEC-008-production-pairing-claimant#TEST-1158]], [[SPEC-008-production-pairing-claimant#TEST-1159]].

### CON-987 — Credential/v2 Selfsame logical bodies are closed

Every logical body below is exact deterministic CBOR. The map is closed: an
unknown, missing, duplicate, reordered, non-canonical, or trailing member
refuses before display, decision, or effect. Every `predecessorDigest` is the
raw `objectContentHash` from cbcl-pairing SPEC-001 0.5.10-draft CON-031. The
envelope field 2 carries the one retained `intentDigest`; no body can replace it.

The offer body is exactly cbcl-bus SPEC-053 0.17.15-draft CON-012's
`signed-offer-v2`. The receipt body is exactly cbcl-pairing SPEC-001
0.5.10-draft CON-028's `credential-v2-receipt-body`. The remaining nine bodies
are:

```cddl
credential-v2-intent-approve-body = {
  "carrierCeremonyId": bstr .size 32,
  "predecessorDigest": bstr .size 32,
  "offerCoreDigest": bstr .size 32,
  "decision": "approve"
}

credential-v2-intent-decline-body = {
  "carrierCeremonyId": bstr .size 32,
  "predecessorDigest": bstr .size 32,
  "offerCoreDigest": bstr .size 32,
  "decision": "decline"
}

credential-v2-preparation-body = {
  "carrierCeremonyId": bstr .size 32,
  "predecessorDigest": bstr .size 32,
  "offerCoreDigest": bstr .size 32,
  "previewIssuerDid": tstr .size (1..512),
  "previewFingerprintDigest": bstr .size 32
}

credential-v2-comparison-confirmed-body = {
  "carrierCeremonyId": bstr .size 32,
  "predecessorDigest": bstr .size 32,
  "result": "no-binding-person-compared",
  "previewIssuerDid": tstr .size (1..512),
  "previewFingerprintDigest": bstr .size 32,
  "authorityStatusResponse": bstr .size (1..768),
  "authorityStatusDigest": bstr .size 32
}

credential-v2-binding-confirmed-body = {
  "carrierCeremonyId": bstr .size 32,
  "predecessorDigest": bstr .size 32,
  "result": "bound-same-did",
  "previewIssuerDid": tstr .size (1..512),
  "previewFingerprintDigest": bstr .size 32,
  "authorityStatusResponse": bstr .size (1..768),
  "authorityStatusDigest": bstr .size 32
}

credential-v2-refusal-body = {
  "carrierCeremonyId": bstr .size 32,
  "predecessorDigest": bstr .size 32,
  "reason": "authority-unknown" / "binding-mismatch" /
            "hub-unavailable" / "expired" /
            "cancelled" / "protocol-error"
}

credential-v2-final-approve-body = {
  "carrierCeremonyId": bstr .size 32,
  "predecessorDigest": bstr .size 32,
  "previewIssuerDid": tstr .size (1..512),
  "previewFingerprintDigest": bstr .size 32,
  "decision": "approve"
}

credential-v2-final-decline-body = {
  "carrierCeremonyId": bstr .size 32,
  "predecessorDigest": bstr .size 32,
  "previewIssuerDid": tstr .size (1..512),
  "previewFingerprintDigest": bstr .size 32,
  "decision": "decline"
}

credential-v2-payload-body = {
  "carrierCeremonyId": bstr .size 32,
  "predecessorDigest": bstr .size 32,
  "offerCoreDigest": bstr .size 32,
  "previewIssuerDid": tstr .size (1..512),
  "previewFingerprintDigest": bstr .size 32,
  "accountPrincipalDigest": bstr .size 32,
  "accountScopeId": bstr .size 32,
  "deviceDid": tstr .size 56,
  "grantId": bstr .size 32,
  "grantMediaType": "application/vc+jwt",
  "grant": tstr .size (1..49152),
  "migrationConfirmationDigest": bstr .size 32
}
```

At grammar maxima, comparison-confirmed contains at most 1,583 octets and
binding-confirmed contains at most 1,570 octets. Both remain within the shared
2,048-octet control-body limit.

`previewIssuerDid` is one canonical `did:crdt` identifier and contains only
ASCII. `previewFingerprintDigest` is
`SHA-256(UTF8(previewIssuerDid))`; both peers render the human fingerprint from
those exact bytes. Every later occurrence is byte-identical to preparation.

`authorityStatusResponse` is the exact deterministic-CBOR
`authority-status-response-v2` from cbcl-bus SPEC-053 0.17.15-draft CON-012.
`authorityStatusDigest` is SHA-256 over those exact response bytes. The wallet
SHALL recompute that digest and verify the response signature under the same
profile `kid` and key that signed the offer. It SHALL require exact carrier
ceremony and offer-core-digest equality.

Comparison-confirmed requires response status `no-binding`, a null bound DID,
and the person's explicit comparison action. Binding-confirmed requires status
`bound` and a bound DID byte-identical to `previewIssuerDid`. Unknown status, a
different bound DID, invalid signature, wrong offer, or wrong ceremony can
produce only refusal. The browser cannot replace the signed response with an
outcome token or digest.

`migrationConfirmationDigest` is the exact raw digest defined by cbcl-bus
SPEC-053 0.17.15-draft CON-012. The wallet recomputes it from the authenticated
offer and its local `previewIssuerDid`. It copies no browser-supplied digest.

The payload grant is one verbatim compact JWS in ASCII. It contains exactly
two `.` separators and uses only base64url characters in its three non-empty
segments. It is not base64url-encoded a second time. The body contains no
resolver closure: the browser fetches and verifies the live closure itself.
At all maxima its deterministic-CBOR encoding is exactly 50,221 octets, below
the shared 62,000-octet logical-body limit.

The browser independently matches every payload field. Its references are the
signed offer, retained preparation and decision, fetched resolver closure,
recognised grant, installation key, transition, and hub pending state. The v1
[[SPEC-004-application-scoped-identity#CON-219]]
bundle grammar supplies no value, parser, or fallback to this body.

Implements: [[SPEC-008-production-pairing-claimant#REQ-1006]].
Verified by: [[SPEC-008-production-pairing-claimant#TEST-1160]].

### CON-988 — Credential/v2 binds the live profile without rendezvous

Before socket creation, the selected complete/manual/legacy recognizer performs exactly
[[SPEC-004-application-scoped-identity#CON-220]] steps 1 through 5. Those steps require HTTPS certificate validation,
no redirects, and exact media type and identity encoding. They also require the
65,536-octet body cap, complete
[[SPEC-004-application-scoped-identity#CON-201]] recognition, and exact profile
`applicationId` equality. The function computes
`profileDigest = SHA-256(RFC8785(profile))` and requires the carrier application
ID and selected relay descriptor to equal the recognised profile.

This result is `OriginRecognisedProfileCandidate`. It authenticates which
origin served the bytes. It is not a
[[SPEC-004-application-scoped-identity#CON-220]] result and cannot verify an offer,
construct a display, write policy, or supply an issuance key.

In LegacyTwoDecision, the exact-pair prompt can name only this candidate's application ID and the
selected canonical relay origin. Approval produces one private single-use
`RelaySocketCapability` bound to the candidate digest, carrier digest,
application ID, relay origin, and carrier ceremony ID. It writes no policy row.

In SingleLink, the prior explicit foreground entry and exact candidate match
produce `CeremonyGesture`. It creates the same narrowly bound one-use socket
capability without a prompt or policy read/write. It expires with the attempt and
cannot authorize identity disclosure, identity effects, or another contact.

Both cbcl-pairing endpoints independently place their recognised
`profileDigest` into the credential/v2 `ci`, `ad`, and public context. The
claimant SHALL require both Finished values before treating the candidate as
`BoundCredentialV2Profile`. A different digest, application, carrier, relay,
or ceremony makes Finished or the explicit equality check fail and erases the
provisional capability.

Only `BoundCredentialV2Profile` supplies profile keys or authenticated display
authority. In legacy mode it can atomically promote a newly approved tuple to
[[SPEC-008-production-pairing-claimant#CON-903]] durable policy. SingleLink performs
no promotion. Existing legacy policy skips only its prompt; neither mode skips
the live fetch, CPace digest binding, or Finished checks.

The exact substitute for
[[SPEC-004-application-scoped-identity#CON-220]] step 6 has these seven ordered steps:

1. obtain `OriginRecognisedProfileCandidate` and its digest;
2. obtain one socket capability from `CeremonyGesture` or legacy exact-pair authority;
3. place that digest and the carrier digest in both endpoint contexts;
4. complete CPace and verify both Finished values;
5. require peer-bound and candidate profile bytes and digests to be equal;
6. promote only a newly approved legacy exact pair to durable
   [[SPEC-008-production-pairing-claimant#CON-903]] policy, with no SingleLink write; and
7. expose profile keys and authenticated display authority only from
   `BoundCredentialV2Profile`.

This construction does not amend
[[SPEC-004-application-scoped-identity#CON-220]] or any credential/v1 caller. No
[[PROTO-003-selfsame-pairing-v1#CON-409]] record,
rendezvous slot, caller-supplied profile digest, TLS-only profile, or durable
TOFU row can substitute for the CPace binding.

Implements: [[SPEC-008-production-pairing-claimant#REQ-906]], [[SPEC-008-production-pairing-claimant#REQ-1006]].
Verified by: [[SPEC-008-production-pairing-claimant#TEST-1160]].

### CON-989 — Signed final status recovers after the relay window

After both Finished values, each Selfsame endpoint derives the same secret:

```text
receiptRecoveryToken = HMAC-SHA-256(
  EXPORTER,
  UTF8("selfsame credential/v2 receipt recovery token v1\u0000") || TH
)

receiptRecoveryCommitment = SHA-256(
  UTF8("selfsame credential/v2 receipt recovery commitment v1\u0000") ||
  receiptRecoveryToken || carrierCeremonyId || UTF8(applicationId)
)
```

`EXPORTER` and `TH` are the raw cbcl-pairing SPEC-001 0.5.10-draft CON-031
values. Both results contain 32 octets. The token is secret and zeroizable. It
is sealed inside the endpoint checkpoint. It never enters an offer, profile,
log, error, metric, URL, hub record, or JavaScript. The browser sends
only the commitment in the authenticated finalization command.

The hub includes that exact commitment in its signed immutable final status
and indexes the status under the carrier ceremony. After ordinary relay
receipt loss, `recover_claimant_completion` POSTs the token and ceremony. It
uses cbcl-bus SPEC-053 0.17.15-draft CON-036's closed CBOR request to the
exact application origin retained from
[[SPEC-008-production-pairing-claimant#CON-988]]. The wallet repeats
[[SPEC-004-application-scoped-identity#CON-220]] steps 1 through 5 against that
origin. It retains both the current candidate profile and the previously
CPace-bound offer profile.

An `accepted` response requires HTTPS verification. The wallet SHALL verify the
compact JWS under the retained CPace-bound offer key. It SHALL verify the
RFC-8785 status digest and locally recomputed recovery commitment. Every
retained application, ceremony, request, account, scope, device, offer, payload,
grant, issuer, and status byte SHALL match.

A signed `not-finalized` response requires the same origin, commitment,
ceremony, and digest checks. Its signature SHALL use a current live profile
key. The hub SHALL also prove under one lock that no final status exists. No
live pending transaction can remain able to finalize. If that key differs from
the retained offer key, the authority-rotation prompt SHALL precede pending
removal. Cancellation preserves pending.

If the current profile still lists the retained offer `kid` with the same key,
accepted recovery proceeds normally. If the current profile has rotated or
removed that key, the historical status signature SHALL still verify under the
sealed offer profile. Every retained binding SHALL also verify. The wallet
SHALL apply [[SPEC-008-production-pairing-claimant#REQ-1006]]'s
authority-rotation prompt before installation. Cancellation preserves pending. A changed
application ID, invalid current profile, invalid historical signature, or
unapproved rotation refuses.

For accepted status, the wallet constructs the exact CON-028 receipt body from
that JWS, digest, carrier ceremony, and its retained payload
`objectContentHash`. Selfsame verification causes cbcl-pairing to create the
private `CredentialV2RecoveredReceiptAuthority`. CON-032 then runs the
ordinary receipt transition. The adapter cannot rebuild a grant, repeat a
signature, republish a DID, or resend a payload. It cannot create an installed
record without the retained verified pending slot and a fresh independent live
reciprocal-binding verification.

`in-progress`, `unknown`, unavailable, rate-limited, malformed, unsigned, mismatched, and
ambiguous responses leave the pending slot unchanged and grant no capability.
Only verified accepted receipt installs. Only verified `not-finalized`,
explicit unlink, or root purge clears a post-payload pending slot.
After hub terminal evidence lapses, the indistinguishable `unknown` result
preserves pending. Only explicit unlink or root purge can then clear it.

Implements: [[SPEC-008-production-pairing-claimant#REQ-1006]].
Verified by: [[SPEC-008-production-pairing-claimant#TEST-1161]].

### CON-990 — Pre-payload failure cannot strand an application slot

Before attempting to persist final approval, the wallet SHALL arm one
compensation transaction over that immutable ceremony. Arming before the store
call covers a backend that commits the initial slot and then reports failure.
The transaction remains armed across the final-approval release and relay
acknowledgement. It also covers every checkpoint replacement, plan, custody,
publication, resolver, grant, payload, and payload-checkpoint operation.

Every error return while the transaction is armed SHALL attempt exact pending
removal before returning. Exact identity covers root generation, application,
relay, profile, carrier, offer, decisions, preview, and exclusive deadline. A
storage backend MAY have committed a replacement before reporting an error.
Compensation SHALL compare the immutable attempt identity, including flow and
contact provenance. It SHALL remove the
recognised current pre-payload phase without assuming an in-memory phase.
It SHALL NOT remove another attempt, an installed record, or a sibling
application. Compensation failure SHALL NOT replace or hide the original
protocol error.

One typed transaction SHALL own initial persistence, every phase replacement,
the fifteen named failure hooks, the final `PayloadPrepared` replacement, and
disarm. The command SHALL have no direct guard-disarm authority. The transaction
SHALL disarm only after the application's slot contains a successfully
recognised durable `PayloadPrepared` value with its endpoint checkpoint. If an
ambiguous storage result exposes that `PayloadPrepared` value, compensation
SHALL retain it for [[SPEC-008-production-pairing-claimant#CON-989]] recovery.
Errors in payload release or later receipt handling likewise retain it.

Automatic pre-payload compensation removes the pending ceremony cache. For
LegacyTwoDecision, it does not revoke the person's accepted exact-pair policy.
SingleLink has no such row to retain or delete. Independently,
[[SPEC-008-production-pairing-claimant#REQ-1006]]'s confirmed unlink SHALL
enumerate every pending phase. It SHALL remove the exact slot and contained
profile cache under current-root presence. LegacyTwoDecision also removes its
selected exact-pair policy. SingleLink performs no policy operation and preserves
unrelated legacy trust. Every mode retains the hierarchy root and remote state
and reports no remote revocation.

Implements: [[SPEC-008-production-pairing-claimant#REQ-1006]].
Verified by: [[SPEC-008-production-pairing-claimant#TEST-1162]].

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

Authenticated display, post-consent effects, shared grammar, cbcl-pairing
bounds, and the sealed-grant graph remain unchanged.

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

After credential/v2 allocation socket loss, reconnect with a new socket
generation. Recover the original request and carrier ceremony under the
persisted installation key. Require one correlated result and no duplicate
durable effect. Permit a new request only after authenticated absent status.

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

Force `accounts/0` busy during a scheduled Path-B tick. Require
[[SPEC-008-production-pairing-claimant#OBS-907]] phase
`account-scan`, no resolver call, no success report, and a live poller.

Force `revoke-observed/2` busy after a verified union. Require
[[SPEC-008-production-pairing-claimant#OBS-907]] phase
`revocation-apply`, no eviction, and a fresh resolver pass next tick.

Force the WebFinger terminal through `lookup/1`. Require `unavailable`, HTTP
503, an empty `no-store` response, and no HTTP 404.

Successful and missing WebFinger lookups retain their existing responses.
Mutations use `#(error authority-busy)` and never false absence.

Force transaction-based schema exhaustion. Require
`schema-migration-busy`, no `no-table`, no listener, and no skipped history.

Record `cbcl-chat-roommember:migrate-since/0` as a separate
`transform_table/4` schema migration outside the transaction inventory.
Record `cbcl-chat-roomcfg:transform-room/1` as the third schema migration
outside that inventory.

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

Require FM-3 to find both production verification contexts and the production
`assemble_claimant` caller. Require `app.js` to reach `cbcl_enrol_prepare` and
`cbcl_enrol_confirm`. Require the other four named commands to have no UI
caller. Require FM-4's ordinary registry and fixture exclusions to resolve.

Require `successionVersion`, `WIRE_VERSION`, and `CODE_VERSION` to resolve to
their named namespaces and governing contracts.

Require credential/v2 to reach no classified credential-v1 site. Require
frozen v1 bytes to remain byte-identical.

Require this Selfsame parent and its open review gate. Require cbcl-bus
SPEC-053 0.17.15-draft to name this coordinated review set.

Require the cbcl-pairing parent consumer pointer here. Require generation
family, version, session, and synthesis trajectory in this parent,
[[SPEC-007-cbcl-pairing-cutover]], cbcl-bus, and cbcl-pairing.

Require another reviewer family and a fresh reviewer session. Require the
review to record its subscription or API authentication path.

Require the transaction inventory to cover every production call under
`apps/`. Require table-derived classifications and exact public-owner results.

Require the consumer inventory to cover every direct and transitive carrier
of `authority-busy`. Require both WebSocket `get-or-start/1` consumers.

Require all 42 cbcl-bus GATE-04 boxes. Require ordinary credential/v2 transport
to use only the cbcl-pairing relay, permit only CON-989's post-window HTTPS
status recovery exception, and require no did-crdt rendezvous call edge.

Require every installed-state clause in [[SPEC-008-production-pairing-claimant#REQ-1006]]. Require the four inline
regression groups in [[SPEC-008-production-pairing-claimant#TEST-1156]].

Require every N10 finding to have a code-backed disposition. Re-test every N9,
N8, and N7 disposition and every F-A through F-E hard stop.

Extract each consolidated current-law section by its exact heading boundaries.
Run `/Users/anuna-01/.agents/skills/anuna-dev/tools/usdd-lint.sh --type
descriptive --strict -` against each extraction. Run the same command against
the complete cbcl-pairing and [[SPEC-007-cbcl-pairing-cutover]] parents. Any
error or warning fails this test.

Removing any current obligation fails.

### TEST-1158 — Consent boundaries prohibit every early identity effect

Instrument custody opening, hierarchy derivation, home-DID computation, issuer
creation, signing, resolver publication, and closure resolution. Also
instrument WebFinger, grant construction, issuance persistence, alias
operations, hub migration, payload release, and wallet installation.

For SingleLink before unlock, require zero calls to every instrumented effect.
Unlock permits one pure DID/fingerprint computation and bounded native custody,
with no decision, disclosure, or write. Render alone grants no authority. Link
permits one preliminary protocol decision and preview disclosure.

Decline, cancel, expire, close the relay, corrupt the comparison, and mutate the
preview after Link. Require zero signatures, publications,
authority calls, grants, aliases, hub migration, payload, and durable identity
records.

After authenticated comparison, require one native final protocol approval and
byte-identical preview comparison in the retained bounded custody before the first
signature. Require no second phone approval, passcode, or custody reopening.
Require issuer creation, publication,
closure verification, WebFinger verification, grant construction, and one
reverse payload in the declared order.

Run LegacyTwoDecision separately and retain preliminary disclosure, separate
final person approval, and its existing final custody call.

Fail each post-final operation independently. Require no accepted application
capability, exact ceremony-only compensation, and no changed pre-existing or
operator withdrawal state.

Require browser verification and inactive crash-safe staging before hub final
commit. The browser record remains inactive before that commit. Require hub
immutable status before browser activation and wallet installation. Lose every
response and restart each component at every boundary. Require exact recovery
without duplicate migration or a local grant shortcut.
Before ordinary or recovered wallet installation, require an independent live
reciprocal-binding verification. Make it unavailable or mismatched and require
the pending slot preserved with no wallet installation.

Before final protocol approval, a wallet restart SHALL abandon the ceremony and retain
no effect capability. After final protocol approval, require the sealed pending slot
before the first identity effect. Restart from each later boundary and require
only the cached frame, exact authenticated decision evidence, and one installed replacement.

Mutate the live attempt tag/capability before persistence. Mutate pending root
generation, flow, provenance, application, carrier ceremony, wrapping key,
checkpoint, plan, expiry, and cached frame. Require
refusal before identity work or protocol output.

Set current time to one second before signed `expiresAt` at every declared
deadline check. Repeat with time exactly at the deadline. Require only the first
value to proceed. Require no offer clock-skew allowance. After durable payload
send, cross the deadline. Require the pending slot to survive only for ordinary
or signed-status receipt recovery.

Require the hub status JWS under the live profile key that signed the offer.
Mutate its signature, digest, `kid`, field, ceremony binding, profile, and size.
Require browser activation and wallet installation to refuse every mutation.

Statically require the production credential/v2 call graph to exclude
`assemble_claimant`. Require every entry recognizer to open no socket. In
SingleLink, require native tag reservation before contact, `CeremonyGesture`,
no relay prompt/policy access, and exact Link/comparison guards. In legacy,
require `authorise_claimant_relay` to own the exact prompt and provisional
socket capability. Require `prepare_claimant` to own a legacy policy write only
after CPace profile-digest binding.
Require `prepare_claimant` to have no custody, issuer, resolver-write,
WebFinger, signing, grant, alias, or persistence edge.

### TEST-1159 — Presence, display, policy, installed state, and transport are exact

Generate valid explicit-legacy PAIR1 codes for minimum and maximum alphabet
branches. Mutate every separator, forbidden letter, pad bit, checksum bit, case
mode, Unicode lookalike, whitespace position, and BIP-39 collision. Require
local refusal and zeroization without populating the machine carrier.

Generate cbcl-bus SPEC-078 0.1.1-draft's exact manual bootstrap and three-word
vectors. Mutate the prefix, CBOR, bounds, T, word count, list membership,
separator, 30-bit value, checksum, authenticated mode, peer share, and exporter.
Require local refusal before contact for grammar/checksum failures. Require one
distinct peer-bound response for a checksum-valid phrase, durable exact-share
replay after restart, and terminal refusal of a different share. A fresh mode
invitation requires authenticated closure proof; a local deadline or clock
advance SHALL leave old recovery authoritative.

Insert `C`, `T`, PAIR1 text, or a claim bearer into the carrier. Insert carrier
bytes, QR data, clipboard data, autofill, password-manager data, notification
data, deep-link data, or peer data into the presence component. Require refusal
before CPace.

Mutate each authenticated display source independently. Require no display for
a mismatch. Compile-fail attempts to construct or mutate
`CredentialV2Display`, to return display fields from the verifier, and to use
generic fields or `authority_summary`.

In LegacyTwoDecision, accept one exact application-relay pair. Present the same
relay under another authenticated application and require a new prompt. In
SingleLink, require `CeremonyGesture`, the exact live application and relay in
the display, and zero policy lookup, write, promotion, or remembered-trust text.
Mutate the attempt tag, flow, contact provenance, profile, descriptor, application,
or relay and require refusal before contact, disclosure, or effect. Remove the
descriptor from the live profile and require refusal. Scan the ordinary binary and source graph
for a compiled conformance registry, relay allowlist, relay-only key,
held-enrolment precondition, and `record_pairing_trust` call edge. Every match
on the credential/v2 path fails.

Reload an installed link under unchanged, profile-refresh, authority-rotation,
issuer-rotation, unavailable, revoked, handle-change, confirmed-unlink, and
hub-deleted states. Require every [[SPEC-008-production-pairing-claimant#REQ-1006]] outcome. A hub deletion requires
a complete fresh ceremony even when the derived key remains available.

Trace every credential/v2 offer, decision, preparation, payload, and ordinary
receipt transport. Require only cbcl-pairing relay edges. Permit the exact
post-window CON-989 status-recovery route and no other exception. Any Selfsame
rendezvous, did-crdt rendezvous, enrolment-signing, or alternate mailbox edge
fails.

### TEST-1160 — Current wire objects and profile binding are self-contained

Extract only the four coordinated current parents. Do not read trajectory
documents or code. Generate independent encoders and recognisers for all eleven
logical bodies and the shared content hash. Include the selected relay
descriptor digest and 272-octet v2 relay origin. Require byte-identical vectors
and verdicts.

Count exactly nine Selfsame body grammars, one hub offer grammar, and one shared
receipt grammar. At the payload maximum require exactly 50,221 deterministic-
CBOR octets. Mutate every member, type, bound, literal, predecessor, padding,
and kind; require refusal before display or effect.

Generate both exact authority-status outcomes. Require the browser to carry the
unaltered response bytes into comparison-confirmed or binding-confirmed. Require
the wallet to recompute the digest, verify the offer-key signature, and match
ceremony, offer digest, outcome, nullable DID, and local preview. Mutate each
byte and require refusal before final display.

Run [[SPEC-004-application-scoped-identity#CON-220]] steps 1 through 5 against a live origin. Substitute the profile
after fetch, between CPace frames, before Finished, and before authority commit.
Require profile-digest mismatch, zero durable pair row, zero intent display,
and zero identity effect. With matching independent profile recognition,
require both Finished values before authenticated display authority exists.
SingleLink SHALL commit no exact-pair row. LegacyTwoDecision SHALL commit one
new exact-pair row only after both Finished values.

Present an existing exact-pair row with a changed profile digest. Require a
fresh live fetch and CPace binding without another pair prompt. The row never
turns TLS-only bytes into authenticated display authority.

### TEST-1161 — Final status recovery survives the relay window

**Validates:** [[SPEC-008-production-pairing-claimant#CON-989]] and
cbcl-pairing SPEC-001 0.5.10-draft TEST-067.

Lose the ordinary receipt and delete the expired relay mailbox. Restart the
wallet, browser, relay, and hub in every order. Retain only their declared
durable state. Require exact signed final-status recovery over the application
HTTPS route. Require the exact receipt body and one private recovered-receipt
authority. The wallet SHALL atomically install once.

Mutate the token, commitment, application, ceremony, request, account, scope,
device, offer, payload, grant, issuer, `kid`, JWS, digest, and predecessor.
Mutate the route, TLS origin, and profile key independently. Require no installation, no repeated
identity effect, and preservation of the sealed pending slot.
Also make the wallet's live reciprocal binding unavailable or mismatched after
valid status recovery. Require the same preservation and no installation.

Return `in-progress`, unavailable, rate-limited, malformed, unsigned, stale,
and ambiguous results. None clears pending or grants capability. Return a
correctly signed `not-finalized` only after the hub's locked terminal-absence
predicate; require atomic pending removal and no installed record.

Lapse the hub's optional replay tombstone and repeat the authenticated request.
Require `unknown`, preserved pending, and no reconstructed terminal authority.
Require explicit unlink or root purge to clear that state.

Rotate the current profile key. Require explicit authority-rotation consent
before either accepted installation or not-finalized removal. Cancellation
preserves the pending slot.

After durable payload send, deliver a validly framed refusal. Require protocol
refusal, preservation of the `payload -> receipt` checkpoint and pending slot,
and later completion through the exact recovered receipt authority.

Scan JavaScript, URLs, logs, errors, metrics, traces, hub rows, and ordinary
wallet state for `receiptRecoveryToken`. Require absence. Require one bounded
commitment and immutable status per finalized account and no recovery route to
accept a carrier, grant, or caller-selected status object.

### TEST-1162 — Pre-payload failure and confirmed abandonment release one exact slot

**Validates:** [[SPEC-008-production-pairing-claimant#REQ-1006]] and
[[SPEC-008-production-pairing-claimant#CON-990]].

Inject one terminal error after each successful final-approval persistence and
before each possible successful `PayloadPrepared` replacement. Include final
approval release, acknowledgement read, and recognition. Include every
replacement, custody, publication, resolver, grant, payload, and checkpoint
preparation boundary. Include a backend that commits a newer phase before
reporting failure. Require the original error, no installed record, no
pre-payload pending record, and successful persistence by a fresh ceremony for
the same application. The injected steps SHALL use the exact typed hooks in
`cbcl_v2_final_decide`. Each hook SHALL occur once and in causal order. They
SHALL NOT be labels over synthetic guard drops. Move arming after persistence
and require failure. Move disarm before durable `PayloadPrepared` and require
failure. Delete a hook or disarm the transaction and require failure.

Expose a recognised pending value at every phase after restart. Require a
person-visible interrupted-link row containing only application, relay, and
phase. Confirm local abandonment with current-root presence. Mutate flow or
contact provenance and require refusal rather than deletion. Require removal of
only the exact application slot and contained profile cache. In
LegacyTwoDecision, also remove the exact `(applicationId, relayOrigin)` policy
selected with the slot. In SingleLink, require no policy lookup or deletion.
Require the root, sibling application slots, and remote state to remain. Require
the result to claim no remote revocation and a fresh same-application ceremony
to occupy the released slot.

Persist a correct `PayloadPrepared` value and inject failures in payload release
and receipt handling. Require preservation for
[[SPEC-008-production-pairing-claimant#CON-989]] recovery. Substitute another
attempt, an installed value, or a changed root generation. For
LegacyTwoDecision, also substitute a changed exact-pair policy. Require refusal
rather than deletion.

The continuous gate SHALL execute this process-global keyring test in an
isolated test process, even while it remains ignored by the concurrent default
library suite. The continuous browser gate SHALL execute the wallet pairing
lifecycle suite that exposes and abandons interrupted pending rows. Removing
either explicit invocation SHALL fail review evidence for this test. The
isolated command SHALL assert the exact one-passed result so a renamed or
unselected test cannot exit successfully.

The Rust job SHALL pass its exact deny-warnings Clippy command before the
isolated process starts. The browser job SHALL pass its screen-render command
before the lifecycle suite starts. An earlier failing step does not satisfy
continuous execution of this test.

### TEST-1163 — Oversized reload evidence is unavailable, not revoked

**Validates:** [[SPEC-008-production-pairing-claimant#REQ-1006]].

Return every typed WebFinger failure while reloading an installed link. A
committed 404 absence SHALL select `hub-deleted`. Timeout, transport refusal,
policy refusal, and an oversized bounded body SHALL select `unavailable`, retain
the record, and grant no capability. A received but unrecognisable binding MAY
select the invalid-or-revoked result. No wildcard or future error arm can
silently classify unavailability as revocation. Mutate the oversized mapping to
revoked and require this test to fail.

### TEST-1164 — The local pin witness covers the whole sibling closure

**Validates:** [[SPEC-008-production-pairing-claimant#CON-985]] and
[[SPEC-007-cbcl-pairing-cutover#ADR-802]].

Run the compiled dependency witness with and without the explicitly labelled
development override. Independently compare `git rev-parse HEAD` and tracked
status for `cbcl-pairing`, `cbcl-rs`, and `did-crdt` against
`cbcl-pairing.sha`, `cbcl-rs.sha`, and `did-crdt.sha`. Change the HEAD or one
tracked byte in each sibling in turn. The witness SHALL fail in every case even
when the build override is set. Restore a clean exact-pin closure and require
the witness and locked workspace build to pass without the override.

### TEST-1165 — Hub CI reproduces the exact browser WASM

**Validates:** [[SPEC-008-production-pairing-claimant#CON-985]].

From clean detached checkouts at the five exact candidate revisions, execute
`scripts/check-selfsame-wasm-rebuild.sh` inside the same
`x86_64-unknown-linux-gnu` container platform as hub CI. Require rustc 1.96.0,
wasm-bindgen 0.2.126, exact byte equality for all four generated artifacts,
and SHA-256
`a8f82e98e2e74eb8b5bf882d53bedfc7b3a11486620910408b82eda2e969ec07`
for `selfsame_web_device_bg.wasm`. Change any recorded source SHA, tool
version, host triple, generated byte, or digest and require refusal before the
later hub gates claim success.

Run the gate from the actual Linux CI job. A locally successful macOS rebuild,
an unreachable runner platform, or a provenance-only edit is not evidence.

### TEST-1166 — One profile-version definition governs the workspace

**Validates:** [[SPEC-008-production-pairing-claimant#REQ-1005]].

Recursively scan every Rust source in the workspace while excluding build
outputs. Require exactly one `pub const PROFILE_VERSION` definition and require
it to be `selfsame-app-identity/src/profile.rs`. Require the crate-root export
to equal that item. Add a second definition at the crate root or elsewhere,
remove the re-export, or make the exported value diverge and require the test
to fail.

### TEST-1167 — Continuous Rust and browser jobs reach credential/v2 gates

**Validates:** [[SPEC-008-production-pairing-claimant#CON-985]] and
[[SPEC-008-production-pairing-claimant#CON-990]].

From the clean exact closure, run
`cargo clippy --workspace --all-targets --locked -- -D warnings`. Require exit
zero before the isolated [[SPEC-008-production-pairing-claimant#TEST-1162]]
step. Remove the explicit lint disposition from the credential/v2 browser
restore boundary and require the job to stop before TEST-1162.

Run `CI=true npm run screens`. The harness SHALL exercise default complete
scan/paste, manual bootstrap-plus-words, and explicit legacy invitation-plus-PAIR1
through the current credential/v2 surface. It SHALL render pre-contact provenance,
pre-socket authentication wait, default unlock/render/Link/comparison wait,
legacy new exact-pair consent, legacy preliminary/final consent, and verified result.

The invoke-surface check SHALL scan every JavaScript module that calls Tauri.
It SHALL recognise every module prefix inside the actual `generate_handler!`
block. Restore the legacy credential/v1 stub, omit the PAIR1 entry, exclude the
pairing module, or hard-code a prefix set that excludes `app_grant`. Require
the screen gate to fail for each mutation.

Require the screen-render gate, cbcl-pairing browser ceremony, and wallet
pairing lifecycle to pass in their declared continuous-job order. No later
passing command compensates for an earlier aborted step.

### TEST-1168 — Release relay authenticates the credential/v2 source closure

**Validates:** [[SPEC-008-production-pairing-claimant#CON-985]].

From the clean five-repository candidate closure, run the hub release-target
isolation harness and the pinned blind-relay shell matrix. Require the release
builder to authenticate cbcl-pairing
`62ef4a968b46b4836374fcee1d78c410f730a7a7` as its current executable
baseline before Cargo runs. Replace that baseline with the pre-credential/v2
revision `197d4cb3d1560ab5328df28fc984269799c510f9`; the isolation harness and
release builder SHALL refuse the executable drift.

Require the normal release build to pass. Inject the conformance-allocation
feature through `RUSTFLAGS` and require refusal before compilation. Run locked
default and conformance test suites plus deny-warnings Clippy in both feature
configurations. No successful browser or NIF test compensates for an
unauthenticated relay release source.

### TEST-1169 — Invoke caller discovery fails closed

**Validates:** [[SPEC-008-production-pairing-claimant#CON-985]] and
[[SPEC-008-production-pairing-claimant#TEST-1167]].

The screen gate SHALL recursively enumerate JavaScript source modules and
derive the invoke-caller set from their source. It SHALL scan every member of
that derived set. A reviewed caller-count ratchet SHALL make a narrowed or
broken discovery filter fail before the gate claims that every invoke
resolves.

From the clean candidate, run `CI=true npm run screens` and require success.
Then exclude `src/pairing.js` from the derived caller set without changing the
ratchet. Require exit one and an `invoke-surface` error that reports two
discovered callers where three are required. Restore the candidate and require
the gate to pass again.

## Scan-handoff local implementation evidence — 0.5.18-draft

Owner authorization dated 2026-09-05 covers local complete-handoff and preview
ordering work under cbcl-bus SPEC-077 0.1.1. Companion revisions are pairing
SPEC-001 0.5.9, Selfsame SPEC-007 0.3.9 and bus SPEC-053 0.17.14.
The new shared codec vectors plus scan/paste, render-order, wrong-phase and
in-flight cancellation tests are required. Evidence is pending implementation.
Old clients remain non-interoperable with new handoffs; explicit legacy input
remains separate. The final Selfsame commit pins the exact pairing commit;
browser integration pins that Selfsame commit and rebuilds WASM. Existing
production, human cryptographic and release gates remain open and effective.

## Successor entry and consent amendment — 0.5.19-draft

The 2026-09-05 owner instruction delegates the manual-entry and single-Link
parent amendment to Codex. The exact model build and generation session for
this amendment are unavailable. Historical generation metadata remains a
historical record and is not reused as provenance for this revision.

This parent coordinates Selfsame SPEC-007 0.3.10, cbcl-pairing SPEC-001
0.5.10, cbcl-bus SPEC-053 0.17.15, cbcl-bus SPEC-078 0.1.1, and cbcl-bus
SPEC-079 0.1.1. It preserves explicit legacy two-approval compatibility while
adding manual-mode isolation and the default one-unlock/one-Link conditional
flow. It records no independent human cryptographic, security, privacy,
release, production-allocation, or deployment approval. Existing gates remain
open and effective.

## Changelog

- 0.5.20-draft — 2026-09-08 — account selection before the offer. `CON-986`
  gains the cbcl-bus SPEC-080 selection step, gated on the profile capability
  from SPEC-004 0.16.1-draft; the offer verifier holds the offer to the
  selection. No production action is authorized.

- **0.5.19-draft — 2026-09-05 — manual entry and single-Link successor.**
  Adds explicit manual bootstrap/word mode, ceremony-only contact provenance,
  bounded native custody, rendered Link authority, comparison-gated final
  protocol approval, and flow-specific legacy policy behavior. Existing
  transaction, compatibility, human-review, and production gates remain effective.

- **0.5.18-draft — 2026-09-05 — confidential complete scan handoff.** Amends QR disclosure and typed entry policy, preserves the public carrier and authorization boundaries, and requires preview rendering before comparison continuation. Local implementation is authorized; production review is unchanged.

- **0.5.17-draft — 2026-08-25 — four-parent authority alignment.** The
  standalone protocol and implementation remain unchanged. The coordinated
  review set now names Selfsame SPEC-007 0.3.8, cbcl-pairing SPEC-001 0.5.8,
  and cbcl-bus SPEC-053 0.17.13. Production allocation, release, and deployment
  remain prohibited pending a fresh cross-model PASS.

- **0.5.16-draft — 2026-08-25 — fail-closed invoke caller discovery.** The
  screen gate recursively discovers JavaScript invoke callers instead of
  maintaining a file list. TEST-1169 ratchets the current caller count and
  kills the previously surviving `src/pairing.js` exclusion mutation. The
  coordinated safety citation names SPEC-007's actual 0.3.7 draft. Production
  allocation, release, and deployment remain prohibited pending a fresh
  cross-model PASS.

- **0.5.15-draft — 2026-08-25 — authenticated relay release source.** The hub
  release builder now authenticates the exact credential/v2 cbcl-pairing
  source closure instead of rejecting it against the pre-v2 baseline.
  TEST-1168 makes that source identity, the poisoned-cache isolation harness,
  the feature-injection refusal, and both relay feature configurations part of
  the coordinated evidence. A Linux rebuild also disproved the preceding
  byte-stability assumption: the Clippy disposition changed embedded source
  locations. The exact regenerated WASM and measured digest now form the
  candidate. Release and deployment remain prohibited pending fresh
  cross-model PASS and separate owner approval.

- **0.5.14-draft — 2026-08-25 — continuously reachable verification.** The
  exact Rust job now passes deny-warnings Clippy before TEST-1162. The browser
  harness drives credential/v2 with a PAIR1 code and renders pre-socket,
  exact-pair, and exact-intent states. Its invoke scanner recognises every
  handler module and includes the pairing caller. The coordinated hub gate
  rejects a conditionally skipped rebuild and directly checks exact host and
  tool provenance. Release and deployment remain prohibited pending a fresh
  cross-model Tier-1 PASS and separate owner approval.

- **0.5.13-draft — 2026-08-25 — production-boundary and reproducibility
  remediation.** This owner-authorized test-first reissue closes all four
  MEDIUM findings from the 0.5.12 fresh review. The post-approval command now
  executes fifteen injectable typed transaction boundaries; arming precedes
  initial persistence and only transaction-owned durable `PayloadPrepared`
  commit can disarm. Unlink compares the selected slot and selected policy
  state while permitting recovery from an absent-policy retry. One profile
  version definition is executable law. The hub artefact is re-vendored and
  byte-rebuilt on CI-compatible `x86_64-unknown-linux-gnu`. The isolated test
  selector now proves one test ran, and the credential-v1 registry citation is
  corrected. Release and deployment remain prohibited pending a fresh
  cross-model Tier-1 PASS and separate owner approval.

- **0.5.12-draft — 2026-08-24 — executable interrupted-link gate.** This
  owner-authorized test-first reissue closes the 0.5.11 review's only blocking
  finding. It executes [[SPEC-008-production-pairing-claimant#TEST-1162]] in an
  isolated CI process. It also executes the wallet lifecycle browser suite and
  covers all fifteen named boundaries. Its mutations remove payload retention,
  attempt identity, installed-slot protection, exact-slot deletion, and policy
  stability. Each mutation is killed. Release and deployment
  remain prohibited until a fresh cross-model Tier-1 PASS and separate owner
  approval.

- **0.5.11-draft — 2026-08-24 — adversarial implementation remediation.**
  This owner-authorized consolidated reissue closes the 0.5.10 review's two HIGH
  findings: allocator restoration and stranded pre-payload wallet slots. Every
  pending phase becomes person-visible and confirmed-abandonable. The reissue
  preserves post-payload recovery and closes oversized WebFinger handling. It
  extends the local pin witness to all three sibling dependencies. Test-first
  implementation is authorized;
  release and deployment remain prohibited until a fresh cross-model Tier-1
  PASS and separate deployment approval.

- **0.5.8-draft — 2026-08-24 — closed cryptographic inputs.** This revision
  coordinates exact socket-generation, recovery-proof, and checkpoint-key
  inputs. It fixes the v2 mailbox lifetime at 900 seconds. It records the
  global chat-frame narrowing, complete-frame measurement, retry rule, naming
  partition, and fully qualified local references. The owner authorizes local
  test-first implementation before PASS. Production allocation, release, and
  deployment remain prohibited.
- **0.5.7-draft — 2026-08-24 — possession proof and lifetime closure.**
  This revision coordinates the exact installation-device possession proof and
  the 900-second credential/v2 mailbox. It corrects the UI witness, relay
  boundary, receipt names, frame arithmetic, trace edges, and local links.
  No implementation or deployment is authorized.
- **0.5.6-draft — 2026-08-24 — baseline and recovery observation closure.**
  This revision corrects the two historical failure descriptions and the
  generation pointer. It makes scope travel and both recovery contracts
  explicit. It coordinates the hub capacity and carrier-boundary corrections.
  No implementation or deployment is authorized.
- **0.5.5-draft — 2026-08-24 — bounded final-command reissue.** This
  revision gives the logical-body contract direct traceability and removes the
  credential/v2 registry-scope ambiguity. It coordinates exact final-command
  capacity and the remaining review observations. No implementation or
  deployment is authorized.
- **0.5.4-draft — 2026-08-24 — response, expiry, and recovery closure.** This
  revision authenticates the transferable hub authority response. It fixes the
  claimant checkpoint KDF and binds all effects to one exclusive pending
  deadline. It scopes registry removal to credential/v2 and records the complete
  Selfsame test authority. No implementation or deployment is authorized.
- **0.5.3-draft — 2026-08-24 — self-contained protocol authority.** This
  revision promotes all credential/v2 logical-body grammars. It replaces the
  inapplicable [[SPEC-004-application-scoped-identity#CON-220]] step-6 claim with
  explicit CPace profile-digest binding.
  It reconciles descriptor and relay-origin rules. It adds signed post-window
  status recovery. No
  implementation or deployment is authorized.
- **0.5.2-draft — 2026-08-24 — executable recovery and direct safety
  authority.** Uses one carrier ceremony identifier, explicit status recovery,
  inactive browser staging, and five owned claimant functions. Removes the
  unused did-crdt rendezvous dependency. Revises SPEC-007 directly. No
  implementation or deployment is authorized.
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
  [[IMPL-008-production-pairing-claimant]]. The
  [[SPEC-004-application-scoped-identity#CON-207]] proof is grant-bound and
  deferred to delivery. The ceremony scope is the profile's single allowed
  permission. [[SPEC-004-application-scoped-identity#ADR-912]]'s linked
  applications form the trusted-profile set.
- **0.1.0** — first draft, authored from the 2026-08-18 gap analysis of the vault and
  the code (four named failure modes; camera scanning found already built and moved to
  specification debt rather than missing work).
