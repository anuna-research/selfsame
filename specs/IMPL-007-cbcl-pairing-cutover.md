---
id: IMPL-007
title: cbcl-pairing Protocol Cutover Implementation
status: draft
version: 0.3.0
last-updated: 2026-08-17
implements: SPEC-007
---

# IMPL-007 — cbcl-pairing Protocol Cutover Implementation

## Objective

Implement [[SPEC-007-cbcl-pairing-cutover]] as Selfsame's only pairing path.
Keep production invitation allocation disabled until its independent gate passes.

## Planning ledger

| Task | Produces | Acceptance | Prerequisite | Source |
|---|---|---|---|---|
| `authority-amendments` | versioned local companion dispositions and approval record | [[SPEC-007-cbcl-pairing-cutover#TEST-819]] | none | [[SPEC-007-cbcl-pairing-cutover#TEST-819]] |
| `endpoint-shells` | independent allocator and claimant session adapters | [[SPEC-007-cbcl-pairing-cutover#TEST-803]], [[SPEC-007-cbcl-pairing-cutover#TEST-813]] | `authority-amendments` | [[SPEC-007-cbcl-pairing-cutover#CON-801]] |
| `credential-boundary` | intent-bound opaque grant acceptance | [[SPEC-007-cbcl-pairing-cutover#TEST-804]], [[SPEC-007-cbcl-pairing-cutover#TEST-805]], [[SPEC-007-cbcl-pairing-cutover#TEST-806]] | `endpoint-shells` | [[SPEC-007-cbcl-pairing-cutover#CON-803]] |
| `relay-profile` | authenticated relay descriptors, selection, and size enforcement | [[SPEC-007-cbcl-pairing-cutover#TEST-817]], [[SPEC-007-cbcl-pairing-cutover#TEST-818]] | `authority-amendments` | [[SPEC-007-cbcl-pairing-cutover#CON-806]] |
| `relay-transport` | blind transport conformance and privacy-safe counters | [[SPEC-007-cbcl-pairing-cutover#TEST-807]], [[SPEC-007-cbcl-pairing-cutover#TEST-808]] | `endpoint-shells` | [[SPEC-007-cbcl-pairing-cutover#CON-802]] |
| `legacy-corpus` | immutable legacy fixtures and one inert recogniser | [[SPEC-007-cbcl-pairing-cutover#TEST-809]], [[SPEC-007-cbcl-pairing-cutover#TEST-810]] | `authority-amendments` | [[SPEC-007-cbcl-pairing-cutover#CON-804]] |
| `shell-cutover` | ordinary Tauri, CLI, and web-device cbcl actions | [[SPEC-007-cbcl-pairing-cutover#TEST-801]], [[SPEC-007-cbcl-pairing-cutover#TEST-814]] | `credential-boundary`, `relay-profile`, `relay-transport`, `legacy-corpus` | [[SPEC-007-cbcl-pairing-cutover#CON-805]] |
| `legacy-removal` | deleted legacy handlers, state machines, dependencies, and positive tests | [[SPEC-007-cbcl-pairing-cutover#TEST-802]], [[SPEC-007-cbcl-pairing-cutover#TEST-812]] | `shell-cutover` | [[SPEC-007-cbcl-pairing-cutover#REQ-802]] |
| `rollback-hold` | production-disabled build policy and release rollback checks | [[SPEC-007-cbcl-pairing-cutover#TEST-810]], [[SPEC-007-cbcl-pairing-cutover#TEST-811]] | `legacy-removal` | [[SPEC-007-cbcl-pairing-cutover#REQ-809]] |
| `documentation` | current architecture and user guidance | user and architecture documents identify cbcl as the only pairing path and retain the production hold | `legacy-removal`, `rollback-hold` | [[SPEC-007-cbcl-pairing-cutover#REQ-808]] |
| `verification` | focused, workspace, mutation, accessibility, and traceability evidence | [[SPEC-007-cbcl-pairing-cutover#TEST-820]] | `documentation` | [[SPEC-007-cbcl-pairing-cutover#TEST-820]] |
| `local-relay-e2e` | development-only application allocator, blind WebSocket relay, and Tauri claimant consent/acceptance flow | [[SPEC-007-cbcl-pairing-cutover#TEST-803]] through [[SPEC-007-cbcl-pairing-cutover#TEST-806]] and [[SPEC-007-cbcl-pairing-cutover#TEST-814]] pass through the real application and wallet shells | `shell-cutover`, `verification` | [[SPEC-007-cbcl-pairing-cutover#CON-802]] |
| `spec004-ledger-evidence` | durable evidence for all inherited Tier-1 rows | all 25 rows name retained or replacement evidence without weakening standing duties | `verification` | [[SPEC-007-cbcl-pairing-cutover#REQ-809]] |
| `upstream-profile-approval` | approved exact pin and credential-profile disposition | the cbcl specification owner approves the pinned revision and Selfsame profile | `verification` | [[SPEC-007-cbcl-pairing-cutover#REQ-809]] |
| `upstream-production-gates` | exact upstream production evidence | every upstream production gate passes without local reinterpretation | `upstream-profile-approval` | [[SPEC-007-cbcl-pairing-cutover#REQ-809]] |
| `adversarial-production-review` | fresh-context review and closed blocker ledger | every blocking cross-model finding is closed with durable evidence | `verification` | [[SPEC-007-cbcl-pairing-cutover#REQ-809]] |
| `cryptography-review` | human cryptography approval | human approval covers CPace, Finished, separation, and nonces | `verification` | [[SPEC-007-cbcl-pairing-cutover#REQ-809]] |
| `endpoint-vector-evidence` | independent CPace and endpoint vectors | [[SPEC-007-cbcl-pairing-cutover#TEST-815]] | `verification` | [[SPEC-007-cbcl-pairing-cutover#TEST-815]] |
| `relay-operator-evidence` | two-operator integration evidence | [[SPEC-007-cbcl-pairing-cutover#TEST-816]] | `verification` | [[SPEC-007-cbcl-pairing-cutover#TEST-816]] |
| `privacy-review` | human privacy approval | approval covers relay metadata, telemetry, retention, and traffic analysis | `verification` | [[SPEC-007-cbcl-pairing-cutover#NFR-801]] |
| `security-review` | human credential-boundary approval | approval covers the profile and Selfsame acceptance boundary | `verification` | [[SPEC-007-cbcl-pairing-cutover#REQ-803]] |
| `production-release-decision` | repository and specification owner release record | every production evidence task passes and production allocation is explicitly approved | `spec004-ledger-evidence`, `upstream-production-gates`, `adversarial-production-review`, `cryptography-review`, `endpoint-vector-evidence`, `relay-operator-evidence`, `privacy-review`, `security-review` | [[SPEC-007-cbcl-pairing-cutover#REQ-809]] |

## Capability placement

### Endpoint sessions

**Simplicity Ladder:** rung 4.

`selfsame-pairing` composes the upstream reducer into one-sided typed sessions.
Each shell owns transport, storage, time, randomness, and user interaction.

### Credential authority

**Simplicity Ladder:** rung 4.

The adapter reuses `CredentialProfile` and `accept_grant`.
It introduces one private approval-bound value and no second verifier.

### Relay selection

**Simplicity Ladder:** rung 4.

`selfsame-app-identity` recognises the authenticated descriptor grammar.
`selfsame-pairing` selects only from those typed descriptors.

### Legacy refusal

**Simplicity Ladder:** rung 3.

One regular recogniser classifies the closed carrier corpus before any effect.
Legacy protocol state and tolerant parsing do not survive.

### Shell integration

**Simplicity Ladder:** rung 4.

Tauri, CLI, and wasm bindings call the same `selfsame-pairing` adapter.
No shell contains protocol choreography.

The local E2E harness composes the pinned relay service behind a binary
WebSocket boundary. Its allocator and Tauri claimant exchange only canonical
CBCL messages. A compile-time development capability admits the loopback
HTTPS-origin to plain-WebSocket mapping needed by `adb reverse`. The capability
does not select a protocol. It cannot admit a non-loopback origin and is absent
from ordinary builds. It does not change the production-allocation hold.

## Purity Boundary Map

```text
Tauri / CLI / wasm ───────▶ selfsame-pairing adapter
       │                              │
       │                              ├────▶ cbcl-pairing pure endpoint
       │                              └────▶ Selfsame acceptance core
       │
       └──── opaque frames ─────▶ blind relay transport
```

The shells own effects. Both protocol cores remain independent of Selfsame shells.

## File plan

- `specs/SPEC-004-application-scoped-identity.md`: adopt the cbcl pairing profile and retire legacy pairing contracts.
- `specs/SPEC-006-cbcl-pairing-integration.md`: mark the prototype superseded by SPEC-007.
- `specs/PROTO-002-selfsame-rendezvous-v1.md`: deprecate credential-pairing use.
- `specs/PROTO-003-selfsame-pairing-v1.md`: deprecate Selfsame use and retain rejection fixtures.
- `specs/PROTO-004-selfsame-ceremony-envelope-v1.md`: deprecate credential-pairing transport use.
- `crates/selfsame-pairing/src/lib.rs`: expose independent endpoint sessions and the credential boundary.
- `crates/selfsame-pairing/src/legacy.rs`: recognise the closed inert legacy carrier language.
- `crates/selfsame-app-identity/src/profile.rs`: recognise cbcl relay descriptors and remove legacy pairing fields.
- `crates/selfsame-web-device/src/lib.rs`: expose the cbcl endpoint surface and remove legacy pairing exports.
- `src-tauri/src/lib.rs`: register only cbcl pairing commands.
- `crates/selfsame-pairing/src/live.rs`: drive typed allocator and claimant relay sessions without shell protocol choreography.
- `crates/selfsame-pairing/src/local_demo.rs`: provide compile-time-gated, deterministic local credential evidence for the complete Selfsame verifier.
- `crates/selfsame-pairing/examples/web-demo/live.rs`: expose the development-only binary WebSocket relay and external-wallet application mode.
- `crates/selfsame-pairing/examples/local-wallet.rs`: drive the same relay as an independent claimant process for local conformance checks.
- `src-tauri/src/cbcl_pairing.rs`: drive the claimant transport and retain endpoint state only for the current ceremony.
- `src/pairing.js`: drive invitation entry, exact-intent consent, terminal outcome, and cancellation while production relay allocation remains held.
- `test-vectors/spec-007-legacy/`: retain immutable legacy rejection fixtures and their manifest.
- `evidence/spec-007-phase-3-gates.yaml`: externalise every implementation result and open gate.
- `README.md`: describe cbcl-pairing as the only path and retain the production warning.

The upstream profile disposition remains a production prerequisite owned by the
`cbcl-pairing` amendment channel. Local implementation does not change it.

## Verification order

1. Add failing one-sided endpoint and invitation-consumption tests.
2. Implement the endpoint shells until those tests pass.
3. Add failing consent and Selfsame-authority tests.
4. Implement the opaque credential boundary until those tests pass.
5. Add failing relay-selection, payload-bound, and legacy-rejection tests.
6. Implement the profile and refusal recognisers until those tests pass.
7. Add failing shell-default and source-absence checks.
8. Switch each shell and remove legacy modules until those checks pass.
9. Apply the three deliberate mutations from the specification.
10. Run focused, workspace, accessibility, lint, and traceability checks.
11. Add a failing real-shell relay test that reaches neither intent nor acceptance.
12. Implement the typed local relay E2E path and require TEST-803 through TEST-806 and TEST-814 to pass through it.

## Development completion rule

The development cutover completes after `verification` passes.
The locally demonstrable application-to-wallet ceremony completes only after
`local-relay-e2e` passes; it is not evidence for production enablement.
The production release remains prohibited until `production-release-decision` also completes.

The executable theory is `spec-007`.
`elephant next -t spec-007 --json` is the authoritative selection query.

## Amendment Channels

Amendable by: the [[SPEC-007-cbcl-pairing-cutover]] owner.

Through: a versioned plan revision that updates affected tasks, tests, and evidence.

Not amendable by: implementation convenience, passing tests, dependency drift, or demo output.

Hard stops: no legacy fallback, no payload before approval, no acceptance bypass,
and no production allocation without the complete production gate.

## Changelog

<details>
<summary>Revision history</summary>

- 0.3.0 — adds the development-only live WebSocket relay task, application
  allocator, Tauri claimant consent flow, and real-shell E2E acceptance without
  changing production allocation.
- 0.2.1 — corrects the desktop file map and records that the development
  surface stops at the pending claimant state while production relay allocation
  remains held.
- 0.2.0 — derives local authority and development completion from TEST-819 and TEST-820.
  It separates upstream approval from local development.
  It splits the production gate into owner-assignable evidence tasks.
- 0.1.0 — maps the approved cutover to independently verifiable implementation work.

</details>
