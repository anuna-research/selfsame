---
id: IMPL-008
title: Standalone Credential V2 Pairing Implementation
status: active
version: 0.2.0
last-updated: 2026-08-24
implements: SPEC-008
review-gate: test-first-implementation-owner-authorized; release-and-deployment-prohibited-pending-cross-model-pass
---

# IMPL-008 — Standalone Credential V2 Pairing Implementation

## Objective

Implement the current [[SPEC-008-production-pairing-claimant#REQ-1006]]
standalone credential/v2 ceremony across `cbcl-pairing`, Selfsame, and
`cbcl-bus`. A new person links `chat.anuna.io` without prior enrolment.

The ceremony authenticates the application live, requests exact-pair relay
trust, and defers every identity effect until final approval. It then creates
the account, issues the application grant, and installs it in the wallet.

The work excludes `did-crdt`. Credential/v2 uses the blind pairing relay and
the hub's authenticated WebSocket authority. It uses no SPEC-001 rendezvous
mailbox and writes no enrolment trust record.

## Authority and release hold

The repository owner authorized local test-first implementation on 2026-08-24.
That waiver applies before a cross-model review returns PASS. It does not
authorize production invitation allocation, release, or deployment.

The latest review is the 0.5.7 Claude Opus review at commit `918ff685`.
It returned REJECT with one MEDIUM and seven LOW findings. The coordinated
0.5.8, 0.3.6, 0.5.7, and 0.17.8 drafts close those findings in prose.

Implementation begins from these exact revisions:

| Repository | Revision | Governing draft |
|---|---|---|
| `selfsame` | `8008585dac9d4028d6b76462035b09c02df970cb` | SPEC-008 0.5.8 and SPEC-007 0.3.6 |
| `cbcl-pairing` | `87a92a350506d1d0e749b035deda81b828e0cc55` | SPEC-001 0.5.7 |
| `cbcl-bus` | `2e456adb315889427ea0340ed8839f31eca8d2d3` | SPEC-053 0.17.8 |
| `did-crdt` | `6d1cdbebc097314323e7f8479cbfd28b3f8cc7d1` | excluded from credential/v2 |

[[SPEC-007-cbcl-pairing-cutover#REQ-809]] keeps production allocation false.
A fresh Circus review through the Claude subscription driver must return PASS.
The owner must separately approve any release or deployment after that PASS.

## Execution model

The durable `spec-008` Elephant theory is the executable task board. This
document explains its tasks, dependencies, files, and acceptance evidence.
The theory decides readiness; this document does not duplicate runtime state.

Each implementation task follows the Red Gate:

1. Add or select the normative test.
2. Run it against the unchanged implementation.
3. Record the expected failure.
4. Implement the smallest coherent behavior.
5. Run the focused test and its repository suite.
6. Record the exact commands and revisions.

No task is complete when only its happy path passes. Its negative cases,
bounds, retries, and rollback assertions are part of the same acceptance.

## End-to-end sequence

```text
browser allocator       blind relay       Selfsame claimant       hub authority
       |                     |                    |                      |
       |-- protected v2 room ------------------->|                      |
       |<=========== CPace + v2 channel =========>|                      |
       |                     |                    |-- live CON-220 ----->|
       |                     |                    |-- TOFU prompt         |
       |                     |                    |-- intent approval     |
       |                     |                    |-- final approval      |
       |                     |                    |-- possession proof -->|
       |                     |                    |<-- signed final state-|
       |<=========== authenticated receipt ======|                      |
```

The live profile value supplies the displayed application identity. The wire
claim never supplies that label. Exact-pair consent keys policy by
`(applicationId, relayOrigin)`.

Custody derivation, DID publication, alias provisioning, account creation,
scope creation, grant issuance, and installation occur after final approval.
Decline and pre-approval failure leave all those effect counts at zero.

## Planning ledger

| Task | Produces | Acceptance | Prerequisite | Source |
|---|---|---|---|---|
| `pairing-v2-admission` | protected v2 carrier, presence proof, mailbox admission, and exact 900-second lifetime | Pairing TEST-060 passes, including invalid proof, replay, role, and lifetime cases | none | [[SPEC-008-production-pairing-claimant#CON-987]] |
| `pairing-v2-channel` | public context, CPace schedule, Finished exchange, envelope reducer, typed display, and sealed checkpoints | Pairing TEST-061 through TEST-067 pass independently | `pairing-v2-admission` | [[SPEC-008-production-pairing-claimant#CON-987]] |
| `hub-v2-pending` | authenticated WebSocket commands and one bounded pending allocation | Hub TEST-117 pending, proof, generation, expiry, and retry rows pass | `pairing-v2-admission` | [[SPEC-008-production-pairing-claimant#CON-986]] |
| `browser-v2-allocator` | browser allocator for credential/v2 over the blind relay | A staged browser completes CPace and hub pending allocation; v1 remains unchanged | `pairing-v2-channel`, `hub-v2-pending` | [[SPEC-008-production-pairing-claimant#TEST-1157]] |
| `wallet-v2-admission` | carrier recognition, live profile authentication, exact-pair TOFU, and single-use socket authority | TEST-1156, TEST-1157, and TEST-1159 admission rows pass | `pairing-v2-channel` | [[SPEC-008-production-pairing-claimant#CON-988]] |
| `wallet-v2-consent` | authenticated display, preliminary preview, and final approval boundary | TEST-1158 and TEST-1160 prove authenticated labels and zero early effects | `wallet-v2-admission` | [[SPEC-008-production-pairing-claimant#CON-986]] |
| `hub-v2-finalization` | atomic account, scope, grant, migration, status, and recovery authority | Hub TEST-117 and TEST-119 pass, including crash and rebind retries | `hub-v2-pending`, `pairing-v2-channel` | [[SPEC-008-production-pairing-claimant#CON-986]] |
| `wallet-v2-completion` | post-consent custody effects, grant acceptance, receipt recovery, and installed state | TEST-1158 and TEST-1161 completion rows pass | `wallet-v2-consent`, `hub-v2-finalization` | [[SPEC-008-production-pairing-claimant#CON-989]] |
| `cross-repo-e2e` | one real browser-to-wallet credential/v2 harness | The full ceremony links a fresh wallet; decline leaves no account or grant | `browser-v2-allocator`, `wallet-v2-completion` | [[SPEC-008-production-pairing-claimant#TEST-1157]] |
| `fresh-adversarial-review` | fresh Circus review against specifications, code, tests, and evidence | A different model reports zero open blocking findings | `cross-repo-e2e` | [[SPEC-008-production-pairing-claimant#CON-985]] |
| `production-gate-evidence` | complete machine and human gate evidence without deployment | Every GATE-04 row has durable evidence; operator rows have human approval | `cross-repo-e2e` | [[SPEC-007-cbcl-pairing-cutover#REQ-809]] |
| `production-release-decision` | an explicit owner decision after all gates | Review PASS, gate evidence, rollback target, and separate owner approval exist | `fresh-adversarial-review`, `production-gate-evidence` | [[SPEC-007-cbcl-pairing-cutover#REQ-810]] |

The last task is intentionally not implementation acceptance. It represents a
future human decision and cannot become ready from test success alone.

## Repository slices

### `cbcl-pairing`

The protocol library owns syntax, cryptography, bounded state, and receipts.
Implementation centers on these existing modules:

- `src/wire.rs` owns closed deterministic-CBOR object recognition.
- `src/mailbox.rs` owns protected admission and bounded membership state.
- `src/relay.rs` owns relay transitions without application semantics.
- `src/channel.rs` owns CPace binding, the schedule, and envelopes.
- `src/endpoint.rs` owns reducer ordering and consent transitions.
- `src/profile.rs` owns authenticated typed display and receipt projection.

The relay binaries admit both frozen credential/v1 and credential/v2.
Credential/v2 receives no downgrade path and no v1 translation.

The first slice writes TEST-060 before adding v2 admission. The second slice
writes TEST-061 through TEST-067 before completing channel behavior.

### `cbcl-bus`

The hub owns pending authority and the browser allocator. The existing chat
WebSocket module gains closed credential/v2 commands without changing ordinary
chat command meanings.

Likely implementation sites include:

- `apps/cbcl_chat/src/cbcl-chat-session-ws.lfe` for command admission.
- focused pure LFE modules for pending and finalized reducers.
- bounded storage keyed by carrier ceremony and authenticated session.
- `apps/cbcl_chat/priv/web/cbcl-invite.mjs` for the allocator endpoint.
- `apps/cbcl_chat/priv/web/app.js` for the user-visible linking flow.
- Rust NIF code only where existing cryptographic ownership requires it.

Pending allocation occurs before final approval but creates no durable account.
Finalization performs every authority effect atomically after valid possession.

The global WebSocket frame ceiling is 1,500,000 bytes. Tests generate and
measure the full maximum credential/v2 frame. They also cover the deliberate
rejection of larger legacy chat frames.

### `selfsame`

The wallet owns live application authentication, exact-pair policy, consent,
custody effects, and installed state. Existing seams remain the starting point:

- `src-tauri/src/cbcl_pairing.rs` owns command state and the socket pump.
- `src-tauri/src/cbcl_context.rs` owns pre-consent planning and effect assembly.
- `crates/selfsame-pairing/src/lib.rs` owns carrier and transfer recognition.
- `crates/selfsame-app-identity-net/src/profile.rs` owns live CON-220 fetches.
- `crates/selfsame-app-identity/src/cbcl_relay.rs` owns exact relay decisions.
- `src-tauri/src/app_grant.rs` owns grant verification and installation.
- `src/pairing.js` owns the two consent surfaces and terminal feedback.

`assemble_claimant` cannot remain a pre-socket constructor if it derives
identity material. It splits into an effect-free authenticated plan and a
single-use post-approval effect capability.

The policy store records the exact authenticated application identifier and
canonical relay origin. Trust for one application never authorizes another
application on the same relay.

### Excluded repository

`did-crdt` receives no code, route, schema, or deployment change. Any proposed
credential/v2 dependency on it is an architecture regression and stops work.

## Cross-repository contracts

The following byte contracts receive shared fixtures with independent readers:

- carrier ceremony identifier and 900-second lifetime;
- presence-proof input and verification result;
- CPace public context and transcript schedule;
- envelope key, nonce, AAD, sequence, and content-hash inputs;
- typed authenticated display objects;
- sealed checkpoint key derivation and state;
- socket-generation context and digest;
- device-possession and device-recovery proof inputs;
- pending offer, finalized response, and recovered receipt;
- logical camelCase bodies and kebab-case transport carriers.

Each producer fixture is consumed outside its repository. Round trips through
one implementation alone do not prove interoperability.

The hub identifier is a non-empty binary of at most 64 bytes. The frame-key
digest binds the raw 32-byte Ed25519 key. A socket-generation digest binds both
values and the 16-byte recovery nonce.

A retry after socket rebind uses a newly signed proof for the current
generation. It retains the same ceremony and offer digest. Successful retry
returns the byte-identical finalized response without repeating effects.

## Test strategy

### Protocol tests

Use fixed cross-language vectors for every deterministic-CBOR structure.
Corrupt each field, member type, size, tag, and role independently. Test
trailing data, duplicate keys, indefinite lengths, and non-canonical integers.

Cryptographic tests compare intermediate bytes, not only final success.
Separate vectors cover extract input, info encoding, expand length, nonce,
AAD, Finished transcript, and signature preimage.

### Wallet tests

Instrument every identity effect behind counting fakes. Decline, timeout,
transport failure, policy rejection, and malformed peer data retain zero counts.

The display test supplies conflicting wire and authenticated application names.
Only the authenticated name appears. Approval is unavailable until that
cross-check succeeds.

Policy tests trust `(application A, relay R)`, then present application B on R.
The wallet prompts again and refusal creates no policy entry.

### Hub tests

Run pure reducer tests before socket integration tests. Exercise duplicate,
concurrent, expired, crashed, rebound, and recovered transitions.

Storage tests kill the process at each durability boundary. Recovery produces
either no effects or one complete finalized state. It never exposes a partial
account, scope, alias, or grant.

### Browser and end-to-end tests

Run the real allocator module in a browser harness. Do not replace CPace or the
relay with a fixture protocol. Test staged local endpoints only.

The final harness begins with a wallet that has no enrolment record and no
relay policy. It accepts live profile authentication, TOFU, intent, and final
approval. The installed application grant then authenticates a chat session.

A paired decline harness stops at each consent boundary. It proves absence of
hub accounts, wallet keys, published DIDs, aliases, grants, policy writes, and
installed state as applicable to that boundary.

## Evidence records

Red and green commands are recorded under `evidence/spec-008/`. Each record
names the repository revision, test selector, observed failure, and green run.
Secrets, carriers, proofs, device keys, and profile bodies are excluded.

The final evidence index includes:

- Red Gate records for every Elephant task;
- cross-language vector digests;
- repository suite results;
- Android and desktop network results;
- browser end-to-end recordings without identity data;
- the fresh Circus review and verifier result;
- the still-closed production allocation assertion.

## Hard stops

Stop implementation for any change that does one of these things:

- authorize a relay without exact-pair person consent;
- display a wire-claimed application identity as authenticated;
- derive or publish identity material before final approval;
- create a durable hub account before final approval;
- introduce a credential/v2 dependency on `did-crdt`;
- translate credential/v1 and credential/v2 objects;
- enable production invitation allocation;
- release or deploy without a fresh review PASS and owner approval.

These stops do not prohibit red tests or local implementation. Every passing
implementation respects them.

## Changelog

- **0.2.0 — 2026-08-24 — standalone credential/v2 execution plan.** Replaces
  the obsolete enrolment and compiled-allowlist plan. Adds the owner-authorized
  pre-PASS Red Gate, cross-repository tasks, Elephant board, and release hold.
- **0.1.0 — 2026-08-20 — held-profile claimant plan.** Planned credential/v1
  enrolment trust and a compiled relay registry. Git history preserves it as a
  superseded design record.
