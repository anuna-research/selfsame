---
id: SPEC-007
title: cbcl-pairing Protocol Cutover
status: draft
tier: 1
version: 0.3.7-draft
last-updated: 2026-08-24
previous-approved-version: 0.2.1
owner-repo: selfsame
review-gate: test-first-implementation-owner-authorized; release-prohibited-pending-cross-model-pass
authority-form: direct-current-safety-authority
implementation-baseline: 0220cec2dec44cd95d4f411ea4814d790b6716d2
coordinated-claimant-design: selfsame SPEC-008 0.5.8-draft
coordinated-hub-design: cbcl-bus SPEC-053 0.17.8-draft
coordinated-pairing-design: cbcl-pairing SPEC-001 0.5.7-draft
generation-model-family: OpenAI GPT-5
generation-model-version: gpt-5.6-sol
generation-session: 01a029aa-9127-7c42-ad28-81512b91ded6
generation-synthesis-trajectory: "approved 0.2.1 cutover -> standalone credential/v2 ordering conflict -> rejected reviews through 0.5.7 -> direct 0.3.6 proof-input closure"
candidate-successor-to: SPEC-006
depends-on: cbcl-pairing SPEC-001; SPEC-004; SCREEN-001
---

# SPEC-007 — cbcl-pairing Protocol Cutover

> **Current draft safety revision.** Version 0.3.6 states the credential/v2
> consent and effect boundary directly. Version 0.2.1 remains the last approved
> revision. The owner authorizes local test-first implementation. This draft
> authorizes no production allocation, release, or deployment.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL are interpreted as described in BCP 14. Their
special meaning applies only when they appear in all capitals.

## Orientation

**Intent.** Selfsame uses [[cbcl-pairing]] as its only pairing protocol.
The cutover removes Selfsame's duplicate protocol before any production user exists.

**Metaphor.** Selfsame owns the credential and consent desk.
`cbcl-pairing` owns the sealed route between the two desks.

**Structure.**

```text
 application shell          blind relay             Selfsame wallet
+------------------+     +----------------+     +----------------------+
| cbcl endpoint A  |<===>| opaque frames  |<===>| cbcl endpoint B      |
| intent + payload |     | bounded state  |     | display + decision   |
+--------+---------+     +----------------+     +----------+-----------+
         |                                                   |
         | exact approved credential                         |
         +-----------------------+---------------------------+
                                 v
                    +----------------------------+
                    | Selfsame acceptance        |
                    | SPEC-004 CON-206 authority |
                    +----------------------------+

 legacy PROTO-003 input -> reject -> fresh cbcl-pairing invitation
```

**Decisions.** [[SPEC-007-cbcl-pairing-cutover#ADR-801]] replaces instead of
negotiating. [[SPEC-007-cbcl-pairing-cutover#ADR-802]] composes the upstream
engine. [[SPEC-007-cbcl-pairing-cutover#ADR-803]] separates endpoint shells.
[[SPEC-007-cbcl-pairing-cutover#ADR-804]] uses release rollback.
[[SPEC-007-cbcl-pairing-cutover#ADR-805]] permits only staged reverse issuance
after final approval.

**Load-bearing.** [[SPEC-007-cbcl-pairing-cutover#REQ-801]] selects one engine.
[[SPEC-007-cbcl-pairing-cutover#REQ-803]] preserves Selfsame authority.
[[SPEC-007-cbcl-pairing-cutover#REQ-804]] preserves explicit consent.
[[SPEC-007-cbcl-pairing-cutover#REQ-812]] bounds every credential/v2 effect.
[[SPEC-007-cbcl-pairing-cutover#REQ-809]] holds production allocation.

**Controls.**

- [[SPEC-007-cbcl-pairing-cutover#REQ-802]] forbids legacy pairing code and imports.
- [[SPEC-007-cbcl-pairing-cutover#REQ-803]] forbids pairing success from becoming credential acceptance.
- [[SPEC-007-cbcl-pairing-cutover#REQ-804]] forbids payload release before exact-intent approval.
- [[SPEC-007-cbcl-pairing-cutover#REQ-805]] keeps application meaning out of relay state.
- [[SPEC-007-cbcl-pairing-cutover#REQ-806]] forbids negotiation and fallback.
- [[SPEC-007-cbcl-pairing-cutover#REQ-807]] makes stale legacy carriers inert.
- [[SPEC-007-cbcl-pairing-cutover#REQ-809]] forbids production allocation before every named gate closes.
- [[SPEC-007-cbcl-pairing-cutover#REQ-811]] consumes invitations before online guesses.
- [[SPEC-007-cbcl-pairing-cutover#REQ-812]] forbids active capability before immutable final acceptance.
- [[SPEC-007-cbcl-pairing-cutover#NFR-801]] forbids secret-bearing telemetry.

**Open.** The 0.3.0 Gate Evidence Record identifies every pending review.
Production allocation remains disabled until the complete Production gate closes.

**Detail.** Reviewer: [[SPEC-007-cbcl-pairing-cutover#Architecture decisions]]
and [[SPEC-007-cbcl-pairing-cutover#Production gate]]. Implementer:
[[SPEC-007-cbcl-pairing-cutover#Contracts]] to
[[SPEC-007-cbcl-pairing-cutover#Test specification]]. Stakeholder:
[[SPEC-007-cbcl-pairing-cutover#Intent source]] to
[[SPEC-007-cbcl-pairing-cutover#Requirements]].

## Failure mode

Selfsame currently carries two pairing authorities.
The Tauri and CLI shells use the legacy Selfsame SPAKE2 path.
The integrated prototype uses `cbcl-pairing` for CPace, Finished, CBCL, channels,
endpoint reduction, and relay state.

Two engines duplicate transcript rules, consent ordering, invitation burn,
relay limits, and error closure. A repair in one engine leaves the other unchanged.

Credential/v2 adds a distinct ordering hazard. It needs a derived issuer and
grant to construct the reverse payload that the person finally approves.
The prior REQ-812 wording forbids that causal construction until after delivery.

The previous compatibility hold preserved the duplicate path for hypothetical users.
The repository owner reports that no users exist, so compatibility protects no deployed state.
Keeping both paths now adds downgrade surface without preserving a real user outcome.

## Intent source

The repository owner requested that Selfsame switch to `cbcl-pairing` as its
pairing protocol on 2026-08-17. The owner also reported that no users exist.
Breaking compatibility is therefore an accepted product constraint for this cutover.

The person in [[users/person/person-profile]] still reviews one recognised request
and makes one explicit decision. The developer in
[[users/developer/developer-profile]] receives one pairing API and one protocol model.

## Scope

This specification includes:

- one `cbcl-pairing` engine for the Tauri wallet, CLI, web-device, and application adapter;
- separate allocator and claimant endpoint sessions across a real blind relay;
- the `anuna.io/credential/v1` profile for [[Selfsame Credential Transfer]];
- the standalone `anuna.io/credential/v2` reverse-issuance safety boundary;
- a 62,000-octet maximum for its canonical CON-219 payload bytes;
- removal of legacy pairing commands, source modules, dependencies, profile fields, and tests;
- fail-closed rejection vectors for legacy words, QR payloads, sessions, and relay messages;
- release rollback without a runtime protocol selector;
- coordinated versioned amendments to SPEC-004, SPEC-006, and PROTO-002 through PROTO-004;
- production-enablement gates inherited from `cbcl-pairing` and Selfsame identity review.

This specification excludes:

- wire or cryptographic changes inside `cbcl-pairing`;
- a live-user data migration;
- dual-protocol operation;
- downgrade negotiation;
- production invitation allocation before [[SPEC-007-cbcl-pairing-cutover#REQ-809]] passes.

The [[SPEC-006-cbcl-pairing-integration]] demo remains evidence for the adapter.
This specification replaces its demo-only orchestration with independently hosted endpoints.

## Compatibility disposition

No deployed identity, invitation, session, relay record, or user preference requires migration.
The cutover therefore removes compatibility rather than emulating it.

Legacy `selfsame-pairing-v1` descriptors become invalid profile input.
Legacy twelve-word values and `selfsame-pairing-v2:` QR payloads produce one safe
`PairingVersionUnsupported` result before network or identity action.

The error identifies an obsolete development build without revealing which input clause failed.
Retry creates a fresh `cbcl-pairing` invitation with no retained ceremony value.

### Closed legacy fixture corpus

Only two legacy discriminators remain at a surviving input boundary:

```abnf
legacy-qr    = %s"selfsame-pairing-v2:" 1*1024(base64url-char)
base64url-char = ALPHA / DIGIT / "-" / "_"
legacy-human = legacy-word 11("-" legacy-word)
legacy-word  = 1*16LOWER
LOWER        = %x61-7A
```

Carrier input is trimmed of outer ASCII whitespace before this grammar runs.
No inner whitespace, case folding, Unicode normalization, or word-list lookup occurs.

An authenticated application profile is fully recognised under its current grammar.
The typed `protocol` discriminator then rejects exact `selfsame-pairing-v1`.

Legacy commands, storage imports, HTTP routes, relay routes, and SSE1 envelope
ingress do not survive the cutover. Their identifiers have no registered handler.

The `cbcl-pairing` ingress runs only its pinned complete canonical-CBOR recogniser.
It does not invoke a legacy classifier for old frame bytes.

The retirement corpus SHALL use a manifest with these exact classes:

| ID | Legacy class | Recognition source | Required fixture coverage |
|---|---|---|---|
| LEGACY-001 | PROTO-003 human carrier | `legacy-human` | canonical vector, word-count bounds, unknown word, checksum error, and case mutation |
| LEGACY-002 | PROTO-003 machine carrier | `legacy-qr` | canonical vector, invalid base64url, duplicate member, trailing input, and wrong version |
| LEGACY-003 | pairing descriptor | `selfsame-pairing-v1` profile discriminator and its fields | canonical profile entry, missing field, extra field, wrong origin, and wrong protocol |
| LEGACY-004 | local session record | every persisted PROTO-003 state and version discriminator | one fixture per state, unknown state, wrong version, truncation, and trailing input |
| LEGACY-005 | removed transport input | PROTO-002 routes, PROTO-003 frames, and PROTO-004 SSE1 records | one fixture per removed route or record class, wrong type, oversize, and non-canonical input |

The manifest SHALL name each fixture, its SHA-256, its expected result, and its
permitted pre-rejection side effects. The permitted side-effect set is empty.

The cutover SHALL generate this corpus from the last pinned legacy implementation.
The generated octets then become immutable rejection fixtures.

The new build SHALL NOT retain a legacy state machine to recognise the corpus.
The manifest records `PairingVersionUnsupported`, `SurfaceUnavailable`, or
`RecognitionFailed` as the exact expected class for each ingress path.

## Requirements

### REQ-801: One pairing authority

Every Selfsame pairing surface SHALL use the pinned `cbcl-pairing` endpoint,
channel, CBCL, profile, and relay contracts.

The release contains no second pairing state machine.

Trace:
- [[SPEC-007-cbcl-pairing-cutover#CON-801]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-801]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-802]]
- [[SPEC-007-cbcl-pairing-cutover#OBS-801]]

### REQ-802: Legacy implementation removal

The production dependency graph SHALL NOT contain `selfsame_core::spake2`,
`PairingSession`, `PairingCarrier`, PROTO-002 through PROTO-004 transport,
or their command, route, storage, and envelope handlers.

Trace:
- [[SPEC-007-cbcl-pairing-cutover#CON-805]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-802]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-812]]
- [[SPEC-007-cbcl-pairing-cutover#OBS-801]]

### REQ-803: Selfsame remains the credential authority

The integration SHALL apply
[[SPEC-004-application-scoped-identity#CON-206]] before it reports an accepted credential.

CPace, Finished, CBCL admission, carrier possession, and user approval SHALL NOT
constitute an accepted Selfsame credential.

Trace:
- [[SPEC-007-cbcl-pairing-cutover#CON-803]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-805]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-806]]
- [[SPEC-007-cbcl-pairing-cutover#OBS-802]]

### REQ-804: Consent precedes payload

For credential/v1, the allocator SHALL NOT release a payload before explicit
approval of the exact recognised intent digest.

For credential/v2, the claimant SHALL NOT construct or release the reverse
payload before final approval. Preliminary approval authorizes only the preview
specified by [[SPEC-007-cbcl-pairing-cutover#REQ-812]].

Trace:
- [[SPEC-007-cbcl-pairing-cutover#CON-801]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-804]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-813]]
- [[SPEC-007-cbcl-pairing-cutover#OBS-801]]

### REQ-805: Relay opacity

The relay SHALL NOT receive invitation secrets, application identifiers, identity
claims, intent, decision meaning, credential plaintext, or Selfsame verifier evidence.

Trace:
- [[SPEC-007-cbcl-pairing-cutover#CON-802]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-807]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-808]]
- [[SPEC-007-cbcl-pairing-cutover#OBS-803]]

### REQ-806: No negotiation or fallback

A Selfsame release SHALL NOT advertise, negotiate, select, or fall back to
`selfsame-rendezvous-v1`, `selfsame-pairing-v1`, SSE1, or any non-`cbcl-pairing` engine.

Trace:
- [[SPEC-007-cbcl-pairing-cutover#CON-805]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-802]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-811]]
- [[SPEC-007-cbcl-pairing-cutover#OBS-801]]

### REQ-807: Legacy input is inert

The shell SHALL reject every legacy carrier and descriptor before subsequent
network access, key derivation, profile fetch, or identity action.

Removed legacy commands, stores, and routes SHALL remain unavailable.

Trace:
- [[SPEC-007-cbcl-pairing-cutover#CON-804]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-809]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-810]]
- [[SPEC-007-cbcl-pairing-cutover#OBS-804]]

### REQ-808: cbcl-pairing is the development default

Every development build SHALL expose `cbcl-pairing` through its ordinary pairing action.
The build requires no protocol flag, compatibility preference, or alternate entry point.

The no-options default serves the only current usage profile because no deployed users exist.

Trace:
- [[SPEC-007-cbcl-pairing-cutover#CON-805]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-801]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-811]]
- [[SPEC-007-cbcl-pairing-cutover#OBS-801]]

### REQ-809: Production allocation hold

The release SHALL NOT allocate a production invitation until every item in
[[SPEC-007-cbcl-pairing-cutover#Production gate]] has durable approval evidence.

The hold includes the complete standing SPEC-004 Tier-1 gate until a coordinated
SPEC-004 amendment explicitly replaces its PROTO-003-specific items.

Trace:
- [[SPEC-007-cbcl-pairing-cutover#CON-805]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-810]]
- [[SPEC-007-cbcl-pairing-cutover#OBS-804]]

### REQ-810: Release rollback

When a prior reviewed `cbcl-pairing` release exists, rollback SHALL deploy it.
Rollback SHALL invalidate every unfinished pairing created by the reverted release.

Before that first reviewed release exists, rollback SHALL disable every pairing
entry point and production allocation while leaving unrelated identity functions available.

Rollback SHALL NOT reactivate the legacy protocol.

Trace:
- [[SPEC-007-cbcl-pairing-cutover#CON-805]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-811]]
- [[SPEC-007-cbcl-pairing-cutover#OBS-804]]

### REQ-811: Invitation consumption

An endpoint SHALL atomically consume an unused invitation before processing its
first peer CPace message.

Failure, decline, crowding, cancellation, expiry, and success leave the invitation consumed.

Trace:
- [[SPEC-007-cbcl-pairing-cutover#CON-801]]
- [[SPEC-007-cbcl-pairing-cutover#CON-804]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-803]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-813]]
- [[SPEC-007-cbcl-pairing-cutover#OBS-801]]

### REQ-812: Endpoint failures cannot authorise

For profiles without credential/v2 reverse issuance, failures SHALL produce no
accepted credential or identity side effect before approved payload delivery.

Before credential/v2 preliminary approval, the endpoint SHALL produce no
application identity effect. Preliminary approval authorizes one zeroizing
derivation, pure DID and fingerprint computation, and the stated authenticated
preview disclosure.

Before credential/v2 final approval, the endpoint SHALL NOT sign, publish,
resolve, issue, persist, stage capability, or construct a credential payload.

Final approval authorizes only causal work required to construct the approved
credential/v2 reverse payload. That work includes re-derivation, preview equality,
issuer creation, signing, DID publication, closure resolution, WebFinger
verification, grant construction, and payload construction.

Final approval also authorizes one encrypted non-authorizing completion
checkpoint before the first causal effect. That checkpoint binds only the
approved ceremony and cannot grant application capability.

Browser verification SHALL create only a crash-safe, non-authorizing staged
installation. The hub's immutable final acceptance SHALL precede activation of
that installation and every application capability.

Failure before immutable final acceptance yields no accepted capability.
Compensation SHALL remove only effects created by this ceremony. It SHALL NOT
change pre-existing identity state or operator withdrawal state.

Trace:
- [[SPEC-007-cbcl-pairing-cutover#CON-801]]
- [[SPEC-007-cbcl-pairing-cutover#CON-803]]
- [[SPEC-007-cbcl-pairing-cutover#CON-807]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-806]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-813]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-821]]
- [[SPEC-007-cbcl-pairing-cutover#OBS-802]]

### REQ-813: Authenticated profile selects the relay

The allocator SHALL select a relay only from the authenticated application profile.
The person SHALL NOT enter, choose, or repair a relay origin.

The claimant SHALL match the invitation relay origin to exactly one eligible
profile descriptor before consent. No declared relay match means refusal.

Credential/v2 eligibility uses the live authenticated descriptor and exact-pair
person policy. It SHALL NOT use a compiled relay allowlist or conformance registry.

Relay failure burns the attempt and requires a fresh selection and invitation.
The SDK SHALL NOT use an undeclared fallback.

Trace:
- [[SPEC-007-cbcl-pairing-cutover#CON-806]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-817]]
- [[SPEC-007-cbcl-pairing-cutover#OBS-804]]

### REQ-814: Credential payload fits the pinned profile

The canonical CON-219 bundle payload SHALL contain at most 62,000 octets.
The sender SHALL enforce this bound before invitation allocation.

Larger input returns `CredentialPayloadTooLarge` with no truncation, chunking,
invitation, network action, key operation, or identity effect.

Trace:
- [[SPEC-007-cbcl-pairing-cutover#CON-801]]
- [[SPEC-007-cbcl-pairing-cutover#CON-803]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-818]]
- [[SPEC-007-cbcl-pairing-cutover#OBS-801]]

## Non-functional requirements

### NFR-801: Secret-free observability

Logs and metrics SHALL contain zero invitation secrets, membership tokens,
channel keys, credential bytes, proof values, account aliases, or private identifiers.

Trace:
- [[SPEC-007-cbcl-pairing-cutover#TEST-807]]
- [[SPEC-007-cbcl-pairing-cutover#OBS-801]]
- [[SPEC-007-cbcl-pairing-cutover#OBS-803]]

### NFR-802: Relay bounds

Relay message, mailbox, lifetime, recognition-work, and unrelated-work limits SHALL
equal the exact pinned `cbcl-pairing` specification and assets.

Trace:
- [[SPEC-007-cbcl-pairing-cutover#CON-802]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-808]]
- [[SPEC-007-cbcl-pairing-cutover#OBS-803]]

### NFR-803: Accessibility continuity

The cutover SHALL introduce zero critical WCAG 2.2 AA violations in every
pairing state exposed by the Tauri wallet.

Trace:
- [[SPEC-007-cbcl-pairing-cutover#TEST-814]]
- [[SPEC-007-cbcl-pairing-cutover#OBS-801]]

## Architecture decisions

### ADR-801: Replace instead of coexist

**Status:** accepted by the repository owner on 2026-08-17.

Selfsame removes the legacy protocol in one release.
No users or deployed sessions require compatibility.

Dual operation was rejected because it preserves two cryptographic authorities,
adds negotiation, and creates downgrade paths. Rejection vectors provide safer closure.

**Simplicity Ladder:** rung 1 for compatibility and rung 4 for pairing.
Compatibility code does not need to exist. The existing dependency supplies pairing.

### ADR-802: Compose the upstream engine

**Status:** accepted by the repository owner on 2026-08-17.

Selfsame depends on one pinned `cbcl-pairing` revision.
Selfsame does not copy CPace, Finished, CBCL dialects, channel framing,
endpoint reduction, mailbox transitions, or relay limiting.

The candidate baseline is revision `62ef4a968b46b4836374fcee1d78c410f730a7a7`.
Changing that pin requires updated conformance evidence and owner review.

Selfsame owns only its credential profile adapter, shell effects, consent UI,
and [[SPEC-004-application-scoped-identity#CON-206]] acceptance boundary.

**Simplicity Ladder:** rung 4.

### ADR-803: Separate endpoint shells

**Status:** accepted by the repository owner on 2026-08-17.

The application and wallet each own one endpoint reducer.
The relay transports canonical opaque messages between independently hosted processes.

The `DemoCeremony` type from [[SPEC-006-cbcl-pairing-integration]] remains test evidence.
It does not become the production shell because it owns both endpoint reducers.

**Placement:** reusable one-sided composition lives in `selfsame-pairing`.
Tauri, CLI, and application shells supply storage, clock, randomness, and transport.

### ADR-804: Roll back releases, not protocols

**Status:** accepted by the repository owner on 2026-08-17.

Selfsame ships one protocol per release.
Rollback deploys the preceding reviewed `cbcl-pairing` release and burns unfinished invitations.
The first cutover instead disables pairing when no preceding reviewed release exists.

A runtime legacy selector was rejected because no user state requires it.
The selector creates a permanent downgrade surface and a second test matrix.

### ADR-805: Stage reverse issuance after final approval

**Status:** candidate, pending the coordinated Tier-1 review.

Credential/v2 needs identity material to construct the payload that travels
from the wallet to the application. Final approval therefore authorizes that
causal construction before delivery.

The application writes a non-authorizing staged record before hub finalization.
Only immutable hub acceptance activates it. This order supports crash recovery
without granting capability from a partial ceremony.

Construction before preliminary or final approval was rejected. Active browser
installation before hub acceptance was also rejected.

**Simplicity Ladder:** rung 5. Existing staging, status, and compensation
primitives compose the boundary without another identity authority.

## Contracts

### CON-801: One-sided Selfsame endpoint adapter

**Interface:** allocator and claimant sessions around `cbcl_pairing::endpoint::EndpointReducer`.

**Input grammar:** invitations, client messages, channel frames, intent, decisions,
and payloads use the exact canonical CBOR grammar pinned by [[cbcl-pairing]].

**Recognition:** the upstream recogniser consumes the complete input before a
session transition. Downstream code consumes typed values only.

**Preconditions:**

- The shell supplies OS-backed CSPRNG output for every random input.
- The credential profile is exactly `anuna.io/credential/v1`.
- The allocator uses a direct 32-octet mailbox identifier and 16-octet invitation secret.
- The sender fully recognises a canonical CON-219 payload of at most 62,000 octets.
- The shell durably binds an unused invitation before its first online guess.

**Postconditions:**

- Both Finished values verify before application traffic.
- CBCL verdicts gate every effect after invitation consumption.
- One recognised intent reaches one decision surface.
- Approval permits one matching payload attempt.
- Decline permits no payload attempt.
- Every terminal path erases endpoint secrets.

**Error model:** one closed Selfsame error mapping preserves safe upstream
recognition, pairing, profile, relay, terminal, and expiry classes.

**Implements:**
- [[SPEC-007-cbcl-pairing-cutover#REQ-801]]
- [[SPEC-007-cbcl-pairing-cutover#REQ-804]]
- [[SPEC-007-cbcl-pairing-cutover#REQ-811]]
- [[SPEC-007-cbcl-pairing-cutover#REQ-812]]
- [[SPEC-007-cbcl-pairing-cutover#REQ-814]]

**Verified by:**
- [[SPEC-007-cbcl-pairing-cutover#TEST-803]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-804]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-813]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-818]]

### CON-802: Selfsame relay transport

**Interface:** a transport shell around the pinned `cbcl_pairing::relay::RelayService` contract.

**Input grammar:** each transport unit contains one canonical CBOR `ClientMessage`.
The exact grammar and bounds come from [[cbcl-pairing]].

**Recognition:** `cbcl_pairing::wire::decode_client_message` performs full
recognition before relay state changes.

**Postconditions:** relay-owned state contains only membership hashes, opaque
bodies, sequence state, acknowledgements, expiry, and privacy-safe counters.

**Error model:** malformed, crowded, expired, oversized, out-of-order, and
unauthorised inputs return closed protocol errors without application effects.

**Implements:**
- [[SPEC-007-cbcl-pairing-cutover#REQ-805]]
- [[SPEC-007-cbcl-pairing-cutover#NFR-802]]

**Verified by:**
- [[SPEC-007-cbcl-pairing-cutover#TEST-807]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-808]]

### CON-803: Selfsame credential boundary

**Interface:** an opaque adapter value carries one recognised, approval-bound
`CredentialGrant` into the Selfsame verifier.

Only the reducer-effect handler constructs the opaque value.
It binds the payload to the exact intent digest and ceremony.

The private acceptance function invokes
[[SPEC-004-application-scoped-identity#CON-206]] with explicit verifier evidence.
Success contains that predicate's `Acceptance` value.

The adapter supplies every CON-206 input as follows:

| CON-206 input | Authoritative source |
|---|---|
| `grant_bytes` | compact JWS extracted byte-for-byte from the approved CON-219 payload of at most 62,000 octets |
| `application_profile` | exact CON-201 profile recognised from authenticated build or origin bytes |
| expected RFC 7565 account | current authenticated application-account context, never the pairing peer |
| offered device key | device key committed by the recognised intent and authenticated enrollment evidence |
| current time and skew | shell clock and the embedded profile's explicit clock-skew bound |
| operation permissions | intersection requested by the local operation and displayed in the exact intent |
| issuer closure | encrypted bundle, authenticated cache, or profile-declared resolver under the required freshness tier |
| reciprocal account record | authenticated CON-204 result for the exact expected account |
| optional projection | verified CON-210 observation; absence cannot bypass the CRDT check |
| device proof | one consumed CON-207 challenge bound to this verifier session and offered key |

The shell determines establishment or continuation before verification.
Its local accepted-grant session ledger is the only authority for that decision.
An absent, lost, unreadable, or unknown ledger entry uses session establishment.

For session establishment, a reachable profile-declared resolver supplies the closure.
Otherwise the shell chooses the bundle closure, then an authenticated cache entry.
CON-206 steps five and ten verify every chosen source and its required freshness.

The exact profile bytes are authenticated under CON-201.
Pairing claims SHALL NOT supply or replace profile-authentication keys.
The expected account comes only from the application's authenticated active-account context.

The offered key SHALL equal the intent recipient, grant device DID, grant JWK,
and CON-207 proof key. The requested scope SHALL equal the sole grant permission
and the sole local operation permission.

Profile, account, operation, device, and intent equality SHALL be checked before
the private acceptance call. The call performs CON-206 steps one through thirteen.

Credential persistence, session authorization, and success UI occur only after
that call returns its opaque `Acceptance` value.

The adapter itself performs no CON-204 provisioning.
The application shell performs the standing remote-wallet CON-204 order after approved delivery.
Provisioning failure executes only CON-204's required revoke or never-accepted record.
Those compensating effects do not create an accepted credential or session.

**Error model:** every numbered Selfsame acceptance failure remains a refusal.
No pairing success value can be converted into credential acceptance.

**Implements:**
- [[SPEC-007-cbcl-pairing-cutover#REQ-803]]
- [[SPEC-007-cbcl-pairing-cutover#REQ-812]]
- [[SPEC-007-cbcl-pairing-cutover#REQ-814]]

**Verified by:**
- [[SPEC-007-cbcl-pairing-cutover#TEST-805]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-806]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-818]]

### CON-804: Invitation and cutover record

**Persisted grammar:** only the secret-free upstream `InvitationRecord` encoding is permitted.

Active cryptographic state remains process-private.
A process exit burns the bound invitation and requires a fresh ceremony.

Legacy record recognition uses the closed corpus discriminators before canonical CBOR parsing.
Recognised legacy input returns `PairingVersionUnsupported` with zero side effect.

Unknown, malformed, trailing, duplicate, or non-canonical input returns one safe
recognition error with zero state change.

**Implements:**
- [[SPEC-007-cbcl-pairing-cutover#REQ-807]]
- [[SPEC-007-cbcl-pairing-cutover#REQ-811]]

**Verified by:**
- [[SPEC-007-cbcl-pairing-cutover#TEST-809]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-810]]

### CON-805: Build and release selection

**Development interface:** the ordinary pairing action starts one `cbcl-pairing`
credential session. No protocol selector exists.

**Production precondition:** a release with invitation allocation enabled carries
durable evidence for every item in [[SPEC-007-cbcl-pairing-cutover#Production gate]].

**Rollback:** close every unfinished mailbox from the reverted release.
Deploy the preceding reviewed `cbcl-pairing` release when one exists.
Otherwise disable every pairing entry point and keep production allocation disabled.

**Source prohibition:** production modules and dependency edges contain no legacy
pairing engine, carrier, relay client, or command registration.

**Implements:**
- [[SPEC-007-cbcl-pairing-cutover#REQ-802]]
- [[SPEC-007-cbcl-pairing-cutover#REQ-806]]
- [[SPEC-007-cbcl-pairing-cutover#REQ-808]]
- [[SPEC-007-cbcl-pairing-cutover#REQ-809]]
- [[SPEC-007-cbcl-pairing-cutover#REQ-810]]

**Verified by:**
- [[SPEC-007-cbcl-pairing-cutover#TEST-801]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-802]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-810]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-811]]
- [[SPEC-007-cbcl-pairing-cutover#TEST-812]]

### CON-806: Authenticated relay selection

**Profile grammar:** this contract defines `cbclPairingRelays` as one to
sixteen closed RFC-8785 JSON descriptors. No SPEC-004 amendment supplies this
member.

Each descriptor contains only `operatorId`, canonical `relayOrigin`, numeric
`priority`, numeric `weight`, `privacyPolicyDigest`, and `conformanceEvidenceDigest`.
Operator IDs and relay origins are unique within one profile.

`operatorId` contains 1 through 63 ASCII octets and matches
`[a-z0-9][a-z0-9-]{0,62}`. `relayOrigin` contains 1 through 272 ASCII octets
and is one canonical HTTPS origin with no credentials, path, query, or
fragment. `priority` and `weight` are JSON integers in `[0, 65535]`; a selected
descriptor has positive weight. Both digest strings are canonical unpadded
base64url and decode to exactly 32 octets.

For a completely recognised descriptor object `D`:

```text
descriptorDigest = SHA-256(RFC8785(D))
```

The browser-selected descriptor is the unique descriptor whose
`relayOrigin` equals the allocated carrier relay origin. That complete object,
and no origin-only projection or another descriptor at the same priority,
supplies `descriptorDigest` to the hub offer. The wallet recomputes the same
digest from the unique live-profile descriptor before display.

A production profile contains at least two eligible descriptors unless its
approved availability exception names one operator and its bounded consequence.

The release recogniser rejects unknown members, duplicate members, invalid
digests, zero weight, and non-canonical origins. Loopback origins are development-only.

**Selection:** the allocator applies these ordered steps:

1. recognise the authenticated profile under CON-201;
2. apply the standing build policy only for credential/v1;
3. take the lowest numeric priority that has an eligible descriptor;
4. choose within that group by CSPRNG-weighted selection;
5. allocate at the chosen relay and place its exact origin in the invitation; and
6. on failure, burn the attempt before repeating with fresh randomness and invitation material.

Selection uses no account, DID, device key, recovery value, or stable user identifier.
No capability probe or undeclared endpoint exists outside the pinned relay protocol.

For credential/v2, complete profile recognition makes a declared descriptor
eligible. No compiled relay allowlist, digest registry, or global relay policy
participates in selection or claimant trust.

For credential/v1 only, after the secure channel delivers intent, the claimant
authenticates the exact profile from the claimed application origin under
CON-201. Its application ID, HTTPS origin, and requested scope come from that
recognised credential/v1 intent.

For credential/v2, the application ID and HTTPS origin come only from the live
profile bound by [[SPEC-008-production-pairing-claimant#CON-988]]. The requested
scope comes only from the signed hub offer after equality with the protected
peer input. No unchecked or merely channel-authenticated peer string supplies
any of those values.

Before consent, the claimant requires the invitation relay origin to match one
eligible descriptor exactly. The descriptor's operator and privacy policy are display-only.

**Implements:**
- [[SPEC-007-cbcl-pairing-cutover#REQ-813]]

**Verified by:**
- [[SPEC-007-cbcl-pairing-cutover#TEST-817]]

### CON-807: Credential/v2 consent and activation boundary

**Interface:** the standalone credential/v2 claimant uses five ordered owned
functions followed by activation and terminal recovery.

1. `recognise_claimant_invitation` produces an origin-recognised zero-effect
   relay-consent plan without a socket.
2. `authorise_claimant_relay` produces only a single-use socket capability
   after an existing exact-pair lookup or explicit person approval.
3. `prepare_claimant` produces an authenticated zero-effect plan after relay
   consent and cbcl-pairing authentication.
4. `preview_claimant_identity` consumes preliminary approval and returns only
   zeroizable public preview material.
5. `complete_claimant` consumes final approval and performs the causal
   construction allowed by [[SPEC-007-cbcl-pairing-cutover#REQ-812]]. It first
   persists the sealed non-authorizing completion checkpoint.

Browser and wallet activation then consume the immutable hub final status.
`recover_claimant_completion` is not a sixth construction function: it can
only authenticate that retained status and finish the already-sent payload's
receipt transition.

**Preconditions:** the exact application-relay pair has person-owned policy.
The profile, carrier, transcript, hub offer, transition, and display sources
have passed complete recognition and authentication.

**Postconditions:** preliminary decline creates no derived identity residue.
Final decline creates no signature, publication, grant, staged record, or
application capability.

After final approval, the browser verifies the payload and writes one inactive
staged record. The hub verifies its receipt before one atomic final transaction.
The browser activates the staged record only after verifying the immutable
hub status JWS against the live profile key that signed the offer.

The cbcl-pairing receipt carries that exact JWS and its digest. The wallet
atomically replaces its pending completion checkpoint only after verifying
both against the live profile and retained ceremony state.

After relay expiry, the signed-status recovery in
[[SPEC-008-production-pairing-claimant#CON-989]] has the same activation
postcondition and no construction capability.

**Error model:** mismatch, cancellation, relay closure, expiry, unavailable
authority, and failed causal work return closed outcomes. Compensation touches
only ceremony-owned effects and leaves no accepted application capability.

**Implements:**
- [[SPEC-007-cbcl-pairing-cutover#REQ-804]]
- [[SPEC-007-cbcl-pairing-cutover#REQ-812]]

**Verified by:**
- [[SPEC-007-cbcl-pairing-cutover#TEST-821]]

## Purity Boundary Map

### Pure core

- `cbcl-pairing`: recognition, CPace, channels, CBCL monitors, endpoint reduction, and mailbox transitions.
- `selfsame-app-identity`: credential construction, recognition, and acceptance.

### Effectful shell

- Application shell: relay transport, storage, clock, randomness, and device-key proof.
- Tauri wallet: custody, consent, relay transport, session lifetime, and identity effects.
- Relay process: network transport and durable blind mailbox storage.

### Boundary values

- `Invitation`, `InvitationRecord`, `ClientMessage`, `ChannelFrame`, `EndpointEffect`,
  `CredentialGrant`, `CbclRelayDescriptor`, `StagedInstallation`,
  `PendingCredentialV2Completion`, and `Acceptance`.

### Dependency rule

Dependencies point from each shell through `selfsame-pairing` toward both pure cores.
Neither pure core imports a Selfsame shell.

### Enforcement

[[SPEC-007-cbcl-pairing-cutover#TEST-802]] and
[[SPEC-007-cbcl-pairing-cutover#TEST-812]] inspect imports, dependency edges,
commands, routes, profile tokens, and protocol assets.

## Amendment disposition

Approval of this specification proposes the following coordinated normative effects:

| Existing authority | Disposition |
|---|---|
| [[SPEC-006-cbcl-pairing-integration]] | Superseded by this production-cutover specification. Its demo remains evidence. |
| [[PROTO-002-selfsame-rendezvous-v1]] | Deprecated for the Selfsame credential-pairing path. The pinned `cbcl-pairing` relay replaces its mailbox transport. |
| [[PROTO-003-selfsame-pairing-v1]] | Deprecated for Selfsame. Its carriers, SPAKE2 suite, routing records, and relay protocol become rejection fixtures only. |
| [[PROTO-004-selfsame-ceremony-envelope-v1]] | Deprecated for the credential-pairing path. The cbcl secure channel carries recognised CON-219 payload bytes. |
| [[cbcl-pairing]] credential profile | A versioned profile disposition names CON-219 payload bytes, the existing 62,000-octet bound, and the CON-206 verifier. It changes no shared wire or cryptography. |
| [[SPEC-004-application-scoped-identity#REQ-209]], [[SPEC-004-application-scoped-identity#REQ-210]], and [[SPEC-004-application-scoped-identity#REQ-212]] | [[SPEC-007-cbcl-pairing-cutover#CON-806]] preserves authenticated selection, no undeclared fallback, exact relay following, and fresh restart. |
| [[SPEC-004-application-scoped-identity#REQ-211]] | Credential and media-type opacity remain. The cbcl secure channel replaces only the PROTO-004 envelope carrier. |
| [[SPEC-004-application-scoped-identity#REQ-219]] and [[SPEC-004-application-scoped-identity#REQ-226]] through [[SPEC-004-application-scoped-identity#REQ-229]] | `cbcl-pairing` credential-profile conformance replaces PROTO-003 conformance. |
| [[SPEC-004-application-scoped-identity#ADR-215]] through [[SPEC-004-application-scoped-identity#ADR-217]] | The pairing-specific decisions become superseded by ADR-801 through ADR-804. |
| [[SPEC-004-application-scoped-identity#ADR-218]] and [[SPEC-004-application-scoped-identity#CON-219]] | Member sets remain. The cbcl profile narrows the payload bound from 69,607 to 62,000 octets without truncation. |
| [[SPEC-004-application-scoped-identity#CON-216]] through [[SPEC-004-application-scoped-identity#CON-218]] | Replaced by CON-801, CON-802, CON-804, and CON-806. |
| [[SPEC-004-application-scoped-identity#TEST-226]] and [[SPEC-004-application-scoped-identity#TEST-232]] through [[SPEC-004-application-scoped-identity#TEST-235]] | Pairing assertions are rewritten against TEST-801 through TEST-818. Unrelated identity assertions remain. |

Approval of SPEC-007 alone does not amend any authority in this table.
Development implementation SHALL begin only after versioned local companion
changes land for SPEC-004, SPEC-006, and PROTO-002 through PROTO-004.
Each local companion change SHALL satisfy [[SPEC-007-cbcl-pairing-cutover#TEST-819]].

Production enablement additionally requires the upstream credential-profile disposition.
The `cbcl-pairing` owner SHALL approve the exact pin and Selfsame profile disposition.
No companion change is permitted to weaken an unrelated identity, security, or production gate.

Until the local companion changes land, this document changes no standing authority.

### Inherited SPEC-004 Tier-1 gate ledger

The numbered rows below follow the current SPEC-004 Tier-1 checklist order.
`Retained` means the companion amendment copies the obligation without weakening it.

| Item | Standing obligation | Cutover disposition |
|---:|---|---|
| 1 | fresh cross-model adversarial review | Retained and expanded for the cbcl cutover. |
| 2 | second review closes first-review blockers | Retained. |
| 3 | human review of identity, credential, pairing, and transport contracts | Identity contracts remain; CON-216 through CON-218 map to CON-801 through CON-806. |
| 4 | mobile platform security review | Retained. |
| 5 | first-issuer confirmation review | Retained. |
| 6 | identity-succession review | Retained. |
| 7 | OQ-201 freshness-value ratification | Retained. |
| 8 | two independent KDF and wire implementations | Retained. |
| 9 | hierarchy-root asset acceptance | Retained. |
| 10 | version-2 hierarchy corpus regeneration | Retained. |
| 11 | `did:crdt` JsonWebKey projection | Retained. |
| 12 | `did:crdt` relationship enforcement disposition | Retained. |
| 13 | causal commitment specification | Retained. |
| 14 | pinned `did:crdt` conformance | Retained. |
| 15 | immutable credential context publication | Retained. |
| 16 | complete privacy review | Retained and expanded for cbcl relay metadata. |
| 17 | open-question closure and no-user reconfirmation | Retained. |
| 18 | SPEC-001 reconciliation | Retained. |
| 19 | legacy protocol gates and two-stack integration | Standing until companion amendments retire them; then replaced by exact cbcl gates and TEST-801 through TEST-818. |
| 20 | PROTO-004 cryptography review | Standing until PROTO-004 retirement; then replaced by the upstream channel cryptography review. |
| 21 | production pairing-relay declarations | Rewritten only as CON-806 descriptors and the two-operator gate. |
| 22 | TEST-201 through TEST-226 | Retained; affected pairing cases gain TEST-801 through TEST-818 assertions. |
| 23 | TEST-227 through TEST-239 | Retained; affected mobile pairing cases use the cbcl adapter. |
| 24 | TEST-240 through TEST-243 and corpus publication | Retained. |
| 25 | versioned human security sign-off | Retained and expanded to name the cbcl pin and this ledger. |

Until every companion amendment is merged, every original SPEC-004 row remains standing.
After merge, a row closes only through its exact disposition above.

## Test specification

### Core

#### TEST-801: Default protocol selection

**Validates:** [[SPEC-007-cbcl-pairing-cutover#REQ-801]],
[[SPEC-007-cbcl-pairing-cutover#REQ-808]].

Invoke the ordinary pairing action in every Selfsame shell.
Verify each action creates a `cbcl-pairing` credential invitation with no protocol option.

#### TEST-802: Legacy source absence

**Validates:** [[SPEC-007-cbcl-pairing-cutover#REQ-802]],
[[SPEC-007-cbcl-pairing-cutover#REQ-806]].

Inspect Rust, JavaScript, Tauri commands, routes, wasm exports, features, and the dependency graph.
Reject every legacy pairing implementation or selectable legacy path.

#### TEST-803: Independent endpoint ceremony

**Validates:** [[SPEC-007-cbcl-pairing-cutover#REQ-811]].

Run allocator and claimant in separate processes through a real relay transport.
Verify CPace, both Finished values, roles, intent, decision, payload, and terminal erasure.

#### TEST-804: Consent prohibits early payload

**Validates:** [[SPEC-007-cbcl-pairing-cutover#REQ-804]].

Hold the claimant before approval, then decline.
Verify zero payload effects and zero Selfsame verifier calls in both states.

#### TEST-805: Selfsame verifier positive

**Validates:** [[SPEC-007-cbcl-pairing-cutover#REQ-803]].

Transfer one valid application-account grant.
Verify every CON-803 input comes from its named authority.
Verify [[SPEC-004-application-scoped-identity#CON-206]] succeeds at every numbered step.

#### TEST-806: Selfsame verifier negative output

**Validates:** [[SPEC-007-cbcl-pairing-cutover#REQ-803]],
[[SPEC-007-cbcl-pairing-cutover#REQ-812]].

Mutate the transferred grant signature after valid pairing.
Verify Selfsame refuses acceptance and creates no authorized session or credential.
Permit only the exact CON-204 compensation when provisioning already occurred.

#### TEST-807: Relay opacity and telemetry

**Validates:** [[SPEC-007-cbcl-pairing-cutover#REQ-805]],
[[SPEC-007-cbcl-pairing-cutover#NFR-801]].

Inspect relay state, logs, metrics, and errors after approval, decline, and failure.
Verify no prohibited secret, identity, intent, decision, credential, or verifier value appears.

#### TEST-808: Relay bounds and scope invariant

**Validates:** [[SPEC-007-cbcl-pairing-cutover#REQ-805]],
[[SPEC-007-cbcl-pairing-cutover#NFR-802]].

Run the pinned relay conformance and work-bound suites.
Verify one ceremony changes only its selected mailbox and bounded counters.

#### TEST-809: Legacy carrier rejection vectors

**Validates:** [[SPEC-007-cbcl-pairing-cutover#REQ-807]].

Submit valid and malformed legacy twelve-word codes and `selfsame-pairing-v2:` payloads.
Load every LEGACY-001 and LEGACY-002 manifest entry.
Verify its SHA-256, expected error class, and empty side-effect trace.
Verify the manifest records the exact source revision, generator command or tool,
and generator SHA-256 from the last pinned legacy implementation.

#### TEST-810: Legacy record and production prohibition

**Validates:** [[SPEC-007-cbcl-pairing-cutover#REQ-807]],
[[SPEC-007-cbcl-pairing-cutover#REQ-809]].

Load every LEGACY-003 through LEGACY-005 manifest entry.
Verify its SHA-256 and expected closed result with an empty side-effect trace.
Verify the manifest records the exact source revision, generator command or tool,
and generator SHA-256 from the last pinned legacy implementation.
Verify every removed command, storage importer, and route has no handler.
Attempt production allocation without complete gate evidence.
Verify zero sessions, listeners, relay writes, key operations, and identity effects.

#### TEST-811: Rollback and no fallback

**Validates:** [[SPEC-007-cbcl-pairing-cutover#REQ-806]],
[[SPEC-007-cbcl-pairing-cutover#REQ-810]].

Roll back across the cutover release with one unfinished invitation.
Verify the invitation closes and the prior reviewed `cbcl-pairing` release starts when present.
Without that release, verify every pairing entry point and allocation path remains disabled.
Verify no legacy protocol becomes reachable.
Verify unrelated identity, credential, revocation, recovery, and non-pairing routes remain available.

#### TEST-812: Removal scope invariant

**Validates:** [[SPEC-007-cbcl-pairing-cutover#REQ-802]].

Compare the repository before and after removal.
Verify legacy executables, registrations, and positive-path tests disappear.
Verify authority documents receive versioned deprecation instead of deletion.
Verify immutable legacy octets remain only in the rejection corpus.
Verify identity derivation, credential semantics, revocation, and unrelated routes remain unchanged.

#### TEST-813: Terminal and replay matrix

**Validates:** [[SPEC-007-cbcl-pairing-cutover#REQ-804]],
[[SPEC-007-cbcl-pairing-cutover#REQ-811]],
[[SPEC-007-cbcl-pairing-cutover#REQ-812]].

Exercise wrong secret, invalid Finished, cancellation, expiry, crowding, decision
replay, payload replay, simultaneous claims, and invitation reuse.
Verify closed results, consumed invitations, erased secrets, and zero extra effects.

#### TEST-814: Wallet accessibility

**Validates:** [[SPEC-007-cbcl-pairing-cutover#NFR-803]].

Scan every pairing state at desktop and 320 CSS pixel widths.
Verify zero critical WCAG 2.2 AA violations and complete keyboard operation.

### Depth

#### TEST-815: Independent endpoint interoperability

**Validates:** [[SPEC-007-cbcl-pairing-cutover#REQ-801]].

Run the pinned upstream public vectors against the Rust endpoint and one independent endpoint.
Require byte equality for invitation, contexts, controls, CPace boundary, Finished,
channel frames, intent, decisions, payload, and terminal classifications.

Owner: `cbcl-pairing` security owner.

#### TEST-816: Independent relay deployments

**Validates:** [[SPEC-007-cbcl-pairing-cutover#REQ-805]],
[[SPEC-007-cbcl-pairing-cutover#NFR-802]].

Complete approval, decline, failure, and expiry against two independently operated relays.
Verify the same endpoint outcomes and relay bounds.

Owner: Selfsame security owner and relay operators.

#### TEST-817: Authenticated relay selection and restart

**Validates:** [[SPEC-007-cbcl-pairing-cutover#REQ-813]].

Exercise priorities, weights, duplicate origins, missing evidence, loopback,
one-provider exception, zero eligible descriptors, and deterministic fixture randomness.

Fail the selected relay before and after allocation.
Verify fresh selection, fresh invitation material, and no undeclared fallback.

Present an invitation whose relay origin matches zero or two profile descriptors.
Verify refusal before consent, payload, or Selfsame acceptance.

For credential/v2, install an empty or hostile compiled relay registry.
Verify the registry has no selection, prompt, socket, or acceptance effect.

#### TEST-818: Credential payload boundary

**Validates:** [[SPEC-007-cbcl-pairing-cutover#REQ-814]].

Construct canonical CON-219 payloads of exactly 62,000 and 62,001 octets.
Verify the first passes the pinned credential-profile recogniser byte-for-byte.

Verify the second returns `CredentialPayloadTooLarge` before invitation allocation.
Verify no prefix, truncation, chunk, hash substitute, or second payload is accepted.

#### TEST-819: Local authority amendment integrity

**Validates:** [[SPEC-007-cbcl-pairing-cutover#REQ-801]],
[[SPEC-007-cbcl-pairing-cutover#REQ-802]].

Inspect versioned changes to SPEC-004, SPEC-006, and PROTO-002 through PROTO-004.
Verify each change names its affected artifacts, this specification, its human owner,
its approval, retained production holds, traceability evidence, and dated changelog.
Verify no change weakens unrelated identity, security, recovery, or protocol duties.

#### TEST-820: Development completion evidence

**Validates:** [[SPEC-007-cbcl-pairing-cutover#REQ-808]],
[[SPEC-007-cbcl-pairing-cutover#REQ-809]].

Inspect the Phase 3 Gate Evidence Record.
Verify every locally runnable TEST-801 through TEST-819 and TEST-821 check cites durable evidence.
Verify every external production gate remains unverified with a named owner until it passes.
Verify production invitation allocation remains false.

#### TEST-821: Credential/v2 effects follow both approvals and final acceptance

**Validates:** [[SPEC-007-cbcl-pairing-cutover#REQ-804]],
[[SPEC-007-cbcl-pairing-cutover#REQ-812]].

Instrument custody, derivation, DID computation, issuer creation, signing,
publication, closure, WebFinger, grant construction, persistence, payload,
hub finalization, and both installation activations.

Before preliminary approval, require zero calls. At preliminary approval,
permit one zeroizing derivation, pure preview computation, and stated disclosure.

Before final approval, require zero signatures, publications, resolutions,
grants, payloads, staged records, and active application capabilities.

After final approval, require causal construction in the declared order.
Require browser verification to write only one inactive staged record.

Lose every response before and after hub commit. Require status recovery to
return absent, pending, or immutable finalized state without duplicate effects.

Before immutable hub acceptance, require zero active application capability.
After that acceptance, require one browser activation and one authenticated
wallet installation.

Fail every causal operation independently. Require ceremony-only compensation,
zero active capability, and unchanged pre-existing and withdrawal state.

## Mutation gate

Before implementation completion, remove the explicit-approval check temporarily.
[[SPEC-007-cbcl-pairing-cutover#TEST-804]] SHALL fail behaviourally.

Before implementation completion, replace direct Selfsame acceptance with parse-only success.
[[SPEC-007-cbcl-pairing-cutover#TEST-806]] SHALL fail behaviourally.

Before implementation completion, register one legacy command temporarily.
[[SPEC-007-cbcl-pairing-cutover#TEST-802]] SHALL fail behaviourally.

Before implementation completion, activate a staged credential before hub
acceptance. [[SPEC-007-cbcl-pairing-cutover#TEST-821]] SHALL fail behaviourally.

## Observability

### OBS-801: Endpoint ceremony state

Each endpoint reports one closed stage, terminal reason, invitation-consumption
state, delivered-payload count, verifier-call count, and secret-erasure state.

It reports no secret or private identity value.

### OBS-802: Selfsame acceptance result

The adapter records success or the closed
[[SPEC-004-application-scoped-identity#CON-206]] failure step.

It records no credential, proof, account alias, or key material.

### OBS-803: Relay-safe counters

The relay reports operation outcomes, opaque frame counts, aggregate bytes,
mailbox counts, limiter outcomes, expiry, and capacity alerts.

It reports no application-layer meaning.

### OBS-804: Cutover and hold result

The release reports its exact `cbcl-pairing` pin, production-allocation status,
gate-evidence identifier, rollback release identifier, and safe legacy-input refusal count.

## Enable, rollback, and operation

Development builds enable `cbcl-pairing` through the ordinary pairing action.
They display the existing experimental boundary until the production gate closes.

Production invitation allocation remains absent from a release until every gate
has durable evidence. A release contains no hidden runtime override for this hold.

Rollback deploys the preceding reviewed `cbcl-pairing` release.
It closes unfinished mailboxes and requires fresh invitations after rollback.
Without such a release, rollback disables pairing and preserves unrelated identity functions.

The Selfsame security owner and affected application owners receive notice before
the first release that permits production invitation allocation.

## Gate Evidence Record — 0.3.6-draft

```yaml
phase: 2
gates:
  - gate: "Accepted rejection imported before repair"
    mechanism: "Circus Claude subscription review record"
    result: pass
    evidence: "[[spec-008-0.5.7-claude-adversarial-review-2026-08-24]] records REJECT and its N-1 blocker"
  - gate: "Coordinated 0.3.6 and 0.5.8 Tier-1 review returns PASS"
    mechanism: "fresh-context cross-model adversarial review"
    result: unverified
    owner: "Selfsame security owner"
    evidence: "pending after the consolidated specification reissue"
  - gate: "TEST-821 red, mutation, and final verification evidence exists"
    mechanism: "test-first implementation evidence"
    result: unverified
    owner: "Selfsame implementation owner"
    evidence: "owner waiver permits local test-first work; release remains prohibited"
  - gate: "Production invitation allocation is approved"
    mechanism: "complete Production gate and separate owner decision"
    result: unverified
    owner: "repository owner and named human reviewers"
    evidence: "production allocation remains disabled"
```

## Production gate

Production invitation allocation remains prohibited until all items have durable evidence:

- the repository owner approves the recorded no-users finding and no-migration disposition;
- coordinated SPEC-004, SPEC-006, and PROTO-002 through PROTO-004 amendments pass their own channels;
- the upstream credential-profile disposition passes the `cbcl-pairing` amendment channel;
- Selfsame SPEC-008 0.5.8-draft, cbcl-bus SPEC-053 0.17.8-draft,
  and cbcl-pairing SPEC-001 0.5.7-draft pass one coordinated Tier-1 review;
- every SPEC-004 Tier-1 row has the exact disposition in the inherited gate ledger;
- every retained or replaced SPEC-004 ledger row reaches pass through its exact disposition;
- the exact upstream `cbcl-pairing` production gates pass without local reinterpretation;
- the `cbcl-pairing` specification owner approves the exact pinned revision;
- the Selfsame specification owner approves this cutover and its [[SPEC-004-application-scoped-identity]] dispositions;
- a fresh-context cross-model adversarial review closes all blocking findings;
- a human cryptography reviewer approves CPace draft-21 inputs, Finished, key separation, and AEAD nonces;
- independent vectors cover the CPace boundary and complete endpoint protocol;
- two independently operated relays pass profile and operator integration tests;
- a privacy reviewer approves relay metadata, endpoint telemetry, retention, and traffic-analysis disclosures;
- a human security reviewer approves the credential profile and Selfsame acceptance boundary;
- every core, depth, red, mutation, accessibility, and traceability gate passes.

No green CI run, dependency pin, release build, feature flag, demo result,
or agent-authored report substitutes for these approvals.

## Reading paths

- Reviewer: [[SPEC-007-cbcl-pairing-cutover#Failure mode]] →
  [[SPEC-007-cbcl-pairing-cutover#Architecture decisions]] →
  [[SPEC-007-cbcl-pairing-cutover#Production gate]].
- Implementer: one [[SPEC-007-cbcl-pairing-cutover#Contracts]] entry →
  its requirements → its tests.
- Stakeholder: [[SPEC-007-cbcl-pairing-cutover#Intent source]] →
  [[SPEC-007-cbcl-pairing-cutover#Compatibility disposition]] →
  [[SPEC-007-cbcl-pairing-cutover#Requirements]].

## Amendment Channels

Amendable by: the Selfsame specification owner, affected SPEC-004 and
PROTO-002 through PROTO-004 human owners, and the affected `cbcl-pairing` owner.

Through: a reviewed, merged, versioned revision with updated tests, vectors,
traceability, changelog, and Gate Evidence Record.

Not amendable by: prompts, chat messages, issue comments, source comments,
implementation behaviour, passing tests, dependency drift, or demo output.

Hard stops: [[SPEC-007-cbcl-pairing-cutover#REQ-803]],
[[SPEC-007-cbcl-pairing-cutover#REQ-804]],
[[SPEC-007-cbcl-pairing-cutover#REQ-805]],
[[SPEC-007-cbcl-pairing-cutover#REQ-806]],
[[SPEC-007-cbcl-pairing-cutover#REQ-807]],
[[SPEC-007-cbcl-pairing-cutover#REQ-809]],
[[SPEC-007-cbcl-pairing-cutover#REQ-811]],
[[SPEC-007-cbcl-pairing-cutover#REQ-812]],
[[SPEC-007-cbcl-pairing-cutover#NFR-801]], and every production gate.

No channel can waive a hard stop without a new specification version and required Tier-1 review.

## Changelog

<details>
<summary>Revision history</summary>

- 0.3.7-draft — reconciles ADR-802, the root pin, the compiled dependency
  baseline, and the fail-closed build-time source-integrity check to reviewed
  cbcl-pairing revision `62ef4a968b46b4836374fcee1d78c410f730a7a7`.
  Release and deployment remain prohibited pending cross-model review PASS.
- 0.3.6-draft — coordinates exact socket-generation, recovery-proof, and
  checkpoint-key inputs. It records the fixed v2 lifetime and frame-safety
  disposition. The consent and effect boundary remains unchanged. The owner
  authorizes local test-first work. Release and deployment remain prohibited.
- 0.3.5-draft — coordinates the possession-proof input and credential/v2
  mailbox lifetime. The consent and effect boundary remains unchanged. The
  coordinated Tier-1 review remains open, so this revision authorizes no
  implementation.
- 0.3.4-draft — coordinates the corrected Selfsame and hub parents. The
  consent and effect boundary remains unchanged. The coordinated Tier-1 review
  remains open, so this revision authorizes no implementation.
- 0.3.3-draft — coordinates the bounded final authority command and the
  remaining attempt-5 observations. The coordinated Tier-1 review remains
  open, so this revision authorizes no implementation.
- 0.3.2-draft — coordinates the signed hub authority response, one exclusive
  offer deadline, exact object kinds, and retained post-payload recovery. The
  coordinated Tier-1 review remains open, so this revision authorizes no
  implementation.
- 0.3.1-draft — defines the relay descriptor and digest directly, scopes the
  peer-sourced identifier rule to credential/v1, and reconciles the five
  claimant functions plus terminal recovery. The coordinated Tier-1 review
  remains open, so this revision authorizes no implementation.
- 0.3.0-draft — directly states the standalone credential/v2 consent and effect
  boundary. It adds ADR-805, CON-807, and TEST-821. The coordinated Tier-1
  review remains open, so this revision authorizes no implementation.
- 0.2.1 — separates local development authority from upstream production approval.
  It accepts ADR-801 through ADR-804 and adds TEST-819 and TEST-820.
  It records legacy fixture provenance and preserves unrelated identity functions during rollback.
- 0.2.0 — records repository-owner approval and authorizes the development cutover.
  Production invitation allocation remains prohibited by [[SPEC-007-cbcl-pairing-cutover#REQ-809]].
- 0.1.0 — proposes a clean `cbcl-pairing` cutover before any production user exists.

</details>
