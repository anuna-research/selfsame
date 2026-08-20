---
id: IMPL-008
title: Production Pairing Claimant Implementation
status: draft
version: 0.1.0
last-updated: 2026-08-20
implements: SPEC-008
---

# IMPL-008 — Production Pairing Claimant Implementation

## Objective

Implement [[SPEC-008-production-pairing-claimant]]: one TLS WebSocket claimant
transport, a real verification context, live consent, and profile-anchored
origin trust. The [[SPEC-007-cbcl-pairing-cutover#REQ-809]] production-allocation
hold stays untouched.

## Execution note

One agent executes this plan in one worktree, with the repository owner in the
loop. The planning ledger below is the board; no shared SPL theory is created.
Tier-1 duties that stay in force: the Red Gate, the mutation checks named by
[[SPEC-008-production-pairing-claimant]], LangSec recognition boundaries, and a
fresh-context adversarial review before merge.

## Planning ledger

| Task | Produces | Acceptance | Prerequisite | Source |
|---|---|---|---|---|
| `wss-transport` | one blocking claimant pump over `wss://` for every build, loopback `ws://` kept compile-gated | [[SPEC-008-production-pairing-claimant#TEST-901]], [[SPEC-008-production-pairing-claimant#TEST-902]] | none | [[SPEC-008-production-pairing-claimant#CON-901]] |
| `conformance-registry` | compiled approved-digest registry; non-demo `RelayPolicy` reads only it | [[SPEC-008-production-pairing-claimant#TEST-910]] | none | [[SPEC-008-production-pairing-claimant#CON-903]] |
| `origin-gate` | pre-connect exactly-one-eligible match over held authenticated profiles, closed refusals, no repair path | [[SPEC-008-production-pairing-claimant#TEST-909]] | `conformance-registry` | [[SPEC-008-production-pairing-claimant#REQ-906]] |
| `context-assembly` | real `SelfsameVerificationContext` from store, custody, and webfinger; fixture absent from ordinary builds | [[SPEC-008-production-pairing-claimant#TEST-903]], [[SPEC-008-production-pairing-claimant#TEST-904]] | `origin-gate` | [[SPEC-008-production-pairing-claimant#CON-902]] |
| `live-consent` | non-demo approve and decline drive the live session; `PairingUnavailable` stubs removed | [[SPEC-008-production-pairing-claimant#TEST-905]] | `wss-transport`, `context-assembly` | [[SPEC-008-production-pairing-claimant#REQ-903]] |
| `carrier-binding` | refusal evidence for URL-scheme, padded, and prefixed carriers | [[SPEC-008-production-pairing-claimant#TEST-908]] | none | [[SPEC-008-production-pairing-claimant#REQ-905]] |
| `scan-paste-convergence` | one carrier entry point; three distinct scan-failure messages | [[SPEC-008-production-pairing-claimant#TEST-906]], [[SPEC-008-production-pairing-claimant#TEST-907]] | none | [[SPEC-008-production-pairing-claimant#REQ-904]] |
| `truthful-surface` | build-derived capability copy on the pairing screens | [[SPEC-008-production-pairing-claimant#TEST-912]] | `live-consent` | [[SPEC-008-production-pairing-claimant#REQ-908]] |
| `hold-invariance` | evidence the SPEC-007 production hold is unchanged | [[SPEC-008-production-pairing-claimant#TEST-911]] | `live-consent` | [[SPEC-008-production-pairing-claimant#REQ-907]] |
| `verification` | full-suite, mutation-gate, and traceability evidence | every core TEST passes; the three named mutations each turn a test red | all above | [[SPEC-008-production-pairing-claimant]] |
| `adversarial-review` | fresh-context defect findings, closed or filed | zero open blocking findings | `verification` | Constitutional Principle 12 |
| `registry-first-entry` | the first production conformance digest, owner-signed | owner ratifies published relay evidence (depth [[SPEC-008-production-pairing-claimant#TEST-913]]) | `verification` | [[SPEC-008-production-pairing-claimant#CON-903]] (owner: repository owner) |

## Decisions

### ADR-910 — One pump for both builds

The demo pump in `src-tauri/src/cbcl_pairing.rs` and the new production pump
differ only in stream type. `tungstenite::MaybeTlsStream<TcpStream>` covers
both, so the demo's `cfg`-forked loop collapses into one function compiled in
every build. The `local-pairing-demo` capability keeps exactly two effects:
the loopback origin→`ws://` mapping ([[SPEC-008-production-pairing-claimant#REQ-908]]
inherits this boundary from IMPL-007) and the fixture context source. Deletion
over addition: the diff removes more `cfg` forks than it adds lines.

### ADR-911 — Bundled webpki roots

`tungstenite =0.30.0` gains its `rustls-tls-webpki-roots` feature. Bundled
roots behave identically on Android and desktop, satisfy
[[SPEC-008-production-pairing-claimant#NFR-901]]'s "platform or bundled" clause,
and keep certificate behaviour out of the platform's hands. Rejected:
`native-tls` (a second TLS stack, and Android NDK friction);
`rustls-tls-native-roots` (per-platform root divergence the tests cannot pin).
[[SPEC-008-production-pairing-claimant#TEST-901]] injects its self-signed test
root through a test-only constructor; the production constructor accepts no
extra roots.

### ADR-912 — The trusted-profile set is the wallet's linked applications

[[SPEC-008-production-pairing-claimant#REQ-906]] names "the person's
authenticated application profile" without fixing its acquisition.
[[SPEC-008-production-pairing-claimant#ADR-902]] rules out trusting the scanned
invitation to name the profile. The narrowest set the wallet already holds:
the applications the person has linked, whose CON-201-authenticated profile
octets the shell records at grant issuance and refreshes through
`selfsame-app-identity-net::profile::fetch_or_cached` at claim time. An
invitation origin no held profile pre-declares refuses closed — first contact
with an application goes through the existing LinkCode path first.
**Open, owner ratification needed:** this set choice is an interpretation of
[[SPEC-008-production-pairing-claimant#REQ-906]]; a future amendment MAY widen
it (for example authority-published application lists). The seam is one
function returning held `FetchedProfile` values, so widening it later touches
one site.

## Capability placement

### WSS claimant transport

**Simplicity Ladder:** rung 4. `tungstenite` is present; only its TLS feature
and one shared pump function are new. The pump lives in
`src-tauri/src/cbcl_pairing.rs` beside the state it drives.

### Approved-conformance registry

**Simplicity Ladder:** rung 5. One `const` slice in one new small module
(`src-tauri/src/cbcl_registry.rs`), reviewed as release content per
[[SPEC-008-production-pairing-claimant#CON-903]]. Empty at birth — fail-closed.

### Context assembly

**Simplicity Ladder:** rung 4. Every field source exists: profile octets in the
store, `Custody::use_hierarchy_root`, `proof.rs` (CON-207),
`webfinger::fetch_and_verify`. One new constructor composes them
(`src-tauri/src/cbcl_context.rs`); no new crate, no new verifier.

### Origin gate

**Simplicity Ladder:** rung 4. `cbcl_relay::verify_invitation_origin` already
decides eligibility; the gate iterates held profiles and demands exactly one
match across them, before any socket.

## Purity Boundary Map

```text
scan/paste (webview) ──carrier──▶ src-tauri shell
                                    │  origin gate → context assembly → WSS pump
                                    │        (effects: store, custody, net)
                                    ▼
                          selfsame-pairing ClaimantRelaySession (sans-io core)
                                    │
                                    ▼
                     cbcl-pairing wire recogniser + Selfsame accept_grant
```

The shell owns sockets, clocks, custody, and the store. The cores stay
side-effect free; the shell parses no relay bytes
([[SPEC-008-production-pairing-claimant#CON-901]] one-parser rule).

## File plan

- `src-tauri/Cargo.toml`: add the `rustls-tls-webpki-roots` feature to `tungstenite`.
- `src-tauri/src/cbcl_pairing.rs`: one build-independent pump over `MaybeTlsStream`; non-demo start/approve/decline drive it; stubs removed.
- `src-tauri/src/cbcl_registry.rs` (new): the compiled approved-conformance digest registry, empty at introduction.
- `src-tauri/src/cbcl_context.rs` (new): held-profile enumeration, the origin gate, and real `SelfsameVerificationContext` assembly.
- `src-tauri/src/app_grant.rs`: record the CON-201-authenticated profile octets at issuance (the [[IMPL-008-production-pairing-claimant#ADR-912]] source).
- `src/pairing.js`: build-derived capability copy; demo-only error text gated out of ordinary builds.
- `specs/SPEC-008-production-pairing-claimant.md`: status transitions and any amendment this implementation forces.
- `evidence/spec-008-phase-3-gates.yaml` (new): externalised gate results, one row per core TEST.

## Verification strategy

Example-based tests per TEST row, in-crate beside the code they verify;
[[SPEC-008-production-pairing-claimant#TEST-901]]/[[SPEC-008-production-pairing-claimant#TEST-902]]
run a loopback rustls WebSocket relay in-process. Symbol-absence
([[SPEC-008-production-pairing-claimant#TEST-904]]) checks the release binary
with `nm`/`strings`. The mutation gate runs the spec's three named mutations by
hand-applied patch, recording each red test in the evidence file.
