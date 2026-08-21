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

### ADR-913 — First contact rides the deployed PROTO-002 rendezvous

**Status:** PROPOSED (2026-08-22).

**Context.** [[IMPL-008-production-pairing-claimant#ADR-912]] sends first
contact "through the existing LinkCode path first", but the wallet's existing
LinkCode ceremony issues only the SPEC-001 device link: nothing in it fetches
a CON-201 profile, carries a CON-219 offer, or reaches
`app_grant_review`/`prepare`/`confirm` — the complete, tested issuance
pipeline in `src-tauri/src/app_grant.rs` that alone writes the ADR-912
pairing-trust record. On the application side, cbcl-bus's
`path-b-ceremony-adapter.mjs` injects a ceremony transport that is absent by
design: the Path-B readiness review's G4 (PROTO-003 relay path) and G5
(rendezvous) were never built for the browser allocator. So the trust record
that [[SPEC-008-production-pairing-claimant#REQ-906]] consumes has no
producer, and every pairing against `chat.anuna.io` refuses at the origin
gate however ratified its profile becomes.

**What is actually deployed, verified 2026-08-22.** Nothing serves the
rendezvous anywhere: the wallet's compiled endpoint
(`https://rendezvous.cbcl.chat`, `src-tauri/src/net.rs`) does not resolve in
DNS; the `selfsame-rendezvous` crate binds loopback by design ("this is a
development service"); and the cbcl-bus deployment routes only `/chat/v1`,
`/pair/v1`, `/mls-ds/v1`, the SPEC-075 relay on `:9443`, and static files.
The legacy LinkCode ceremony has therefore only ever completed against local
development servers. Any transport decision claiming to "reuse what is
deployed" would be reusing nothing.

**Decision.** The cbcl-bus deployment gains the rendezvous surface — the
settled hosting direction already names cbcl-bus an application *and* a
declared rendezvous provider — and first contact runs the ordinary ceremony
over it: the hub mints the [[SPEC-004-application-scoped-identity#CON-219]]
sealed offer, with hub-signed
[[SPEC-004-application-scoped-identity#CON-214]] evidence naming the
profile's CON-227 web binding, into the mailbox; the wallet's
`read_link_code` recognises which offer grammar arrived — a SPEC-001 offer
takes the existing device-link path unchanged, a CON-219 offer routes to the
`app_grant_*` pipeline, whose confirm step records pairing trust. The
wallet's compiled endpoint table gains the real host, which is a wallet
release. No browser-allocator G4/G5 build.

**Simplicity Ladder:** rung 4 on every axis but one — `net::fetch_offer`, the
offer recognisers, and the issuance pipeline exist; the rendezvous
*implementation* exists (`selfsame-rendezvous` serves the three SPEC-001
routes) and what is new is deploying it inside cbcl-bus plus the hub's offer
construction and the wallet's grammar dispatch. The `selfsame-rendezvous`
crate's own caveat — a network-reachable rendezvous is more than the SPEC-001
threat model covers — makes the deployment slice a reviewed cbcl-bus SPEC
with its own hardening pass, not a docker-compose afterthought. The
alternative browser-allocator transport is rung 6 twice over and remains the
right non-bootstrap shape; nothing here forecloses it.

**Open, owner ratification needed:** the hub-side offer minting is cbcl-bus
work (its enrolment signer and SPEC-053 GATE-00 posture govern when the
CON-214 signature can exist), and the wallet-side grammar dispatch touches
SCREEN-001's one linking flow — both are their own reviewed slices, traced
here so neither repo invents the contract alone.

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
