---
id: IMPL-006
title: cbcl-pairing Integration Implementation
status: implemented
version: 0.3.0
last-updated: 2026-08-17
implements: SPEC-006; SCREEN-001
---

# IMPL-006 — cbcl-pairing Integration Implementation

## Objective

Implement [[SPEC-006-cbcl-pairing-integration]] with the smallest composition
that proves [[Selfsame Credential Transfer]] in a real browser.

## Planning ledger

| Task | Produces | Acceptance | Prerequisite | Source |
|---|---|---|---|---|
| `branch-baseline` | recorded branch and main merge base | [[SPEC-006-cbcl-pairing-integration#TEST-719]] | none | [[SPEC-006-cbcl-pairing-integration#REQ-712]] |
| `dependency` | workspace dependency and exact pin | [[SPEC-006-cbcl-pairing-integration#TEST-701]] | `branch-baseline` | [[SPEC-006-cbcl-pairing-integration#REQ-701]] |
| `adapter` | Selfsame credential pairing adapter | [[SPEC-006-cbcl-pairing-integration#TEST-703]], [[SPEC-006-cbcl-pairing-integration#TEST-705]] | `dependency` | [[SPEC-006-cbcl-pairing-integration#REQ-702]] |
| `refusals` | prohibited-action and scope-invariant coverage | [[SPEC-006-cbcl-pairing-integration#TEST-706]] through [[SPEC-006-cbcl-pairing-integration#TEST-718]] | `adapter` | [[SPEC-006-cbcl-pairing-integration#REQ-708]] through [[SPEC-006-cbcl-pairing-integration#REQ-711]] |
| `web-demo` | loopback server and browser assets | [[SPEC-006-cbcl-pairing-integration#TEST-704]], [[SCREEN-001-cbcl-pairing-demo#TEST-713]] | `adapter` | [[SPEC-006-cbcl-pairing-integration#REQ-702]] |
| `http-boundary` | caller-bound Axum API and rejection matrix | [[SPEC-006-cbcl-pairing-integration#TEST-720]], [[SPEC-006-cbcl-pairing-integration#TEST-721]] | `web-demo` | [[SPEC-006-cbcl-pairing-integration#REQ-713]] |
| `browser-e2e` | browser acceptance and accessibility evidence | [[SCREEN-001-cbcl-pairing-demo#TEST-714]], [[SCREEN-001-cbcl-pairing-demo#TEST-715]] | `refusals`, `http-boundary` | [[SPEC-006-cbcl-pairing-integration#NFR-703]] |
| `documentation` | README and user guidance | [[SPEC-006-cbcl-pairing-integration#TEST-722]] | `browser-e2e` | [[SPEC-006-cbcl-pairing-integration#REQ-714]] |
| `verification` | mutation, lint, traceability, and gate evidence | every core test and gate record passes | `documentation` | [[SPEC-006-cbcl-pairing-integration#REQ-706]] |

## Capability placement

### Dependency integration

**Simplicity Ladder:** rung 4.

The existing `cbcl-pairing` dependency supplies the protocol. Selfsame adds only
the application adapter and dependency pin.

**Placement:** the root workspace declares the dependency. A new
`selfsame-pairing` crate owns Selfsame-specific composition for every shell.

### Credential authority

**Simplicity Ladder:** rung 4.

The integration reuses `CredentialProfile` and `selfsame_app_identity::accept_grant`.
It does not create another grant grammar or authorization policy.

**Placement:** `selfsame-pairing` bridges the two libraries. Neither upstream core imports the bridge.

### Demo server

**Simplicity Ladder:** rung 4.

Axum and Hyper supply HTTP recognition. Static assets use native HTML, CSS, and JavaScript.

**Placement:** a `web-demo` example in `selfsame-pairing` keeps demo-only I/O outside the library core.

### Browser test

**Simplicity Ladder:** rung 4.

The existing Puppeteer dependency drives the demo. No second browser framework enters the repository.

## File plan

- `Cargo.toml`: declare and pin the sibling integration dependency.
- `cbcl-pairing.sha`: record the inspected sibling revision.
- `crates/selfsame-pairing/Cargo.toml`: define the integration package.
- `crates/selfsame-pairing/src/lib.rs`: compose the credential ceremony and acceptance boundary.
- `crates/selfsame-pairing/examples/web-demo.rs`: serve the capability-bound Axum demo.
- `crates/selfsame-pairing/examples/web-demo/*`: implement [[SCREEN-001-cbcl-pairing-demo]].
- `crates/selfsame-pairing/tests/*`: verify positive, negative, prohibited, and scope-invariant cases.
- `tests/cbcl-pairing-demo.mjs`: drive the browser flow.
- `README.md`: document architecture, command, hold, and legacy transition.
- `evidence/spec-006-phase-3-gates.yaml`: externalize gate results.

## Verification order

1. Add failing adapter tests for approved, declined, wrong-secret, and invalid-grant paths.
2. Implement the minimum adapter until those tests pass.
3. Add failing HTTP and browser tests.
4. Implement the server and screen until those tests pass.
5. Apply the deliberate consent-bypass mutation and observe a failing test.
6. Apply the deliberate Selfsame-verifier bypass mutation and observe a failing test.
7. Run formatting, Clippy, package tests, browser tests, and workspace tests.
8. Run controlled-language, dead-link, traceability, and gate-record checks.

## Executable commands and evidence

| Acceptance | Command or evidence |
|---|---|
| branch baseline | `git merge-base main HEAD`, `git rev-parse main`, and branch name in `evidence/spec-006-branch.txt` |
| Rust core | `cargo test -p selfsame-pairing` |
| HTTP boundary | focused Axum router integration tests |
| browser flow | `node --test tests/cbcl-pairing-demo.mjs` |
| source isolation | `cargo tree -p selfsame-pairing` plus source import scan |
| launch | documented Cargo command with an ephemeral loopback port |
| mutation | failing consent and verifier mutations recorded in gate YAML |
| documentation | controlled-language lint and new-link delta |

## Known integration seam

`cbcl-pairing` fully recognises the credential profile before it emits a grant effect.
The Selfsame adapter then applies the authoritative thirteen-step predicate before exposing acceptance.

The adapter SHALL NOT expose raw `EndpointEffect::DeliverGrant` as an accepted Selfsame result.
This containment preserves [[SPEC-006-cbcl-pairing-integration#REQ-703]] without changing the sibling repository.

The private effect handler creates an opaque `ApprovedCredential`. External code
cannot construct that value or call the Selfsame acceptance function directly.

Construction binds every displayed authority field to the parsed grant and verifier context before creating an invitation.

## Completion rule

The implementation theory uses the collision-free alias `selfsame-spec-006` because
the global store already contains an unrelated completed `spec-006` theory.

Its theory identifier is
`85ea26a4cda9837ac2eade5fbe34d8a12b007a08a6e5a1904adcb3cea7cd89fd`.
`elephant next -t selfsame-spec-006 --json` is the authoritative selection command.

The signed theory contains `task-description/2` and `task-acceptance/2` facts
for every task. Every readiness rule carries its governing specification source.

```text
(normally r-ready-branch-baseline
  (and (task branch-baseline) (no-deps branch-baseline))
  (ready branch-baseline))
(normally r2-ready-dependency
  (and (task dependency) (completed branch-baseline))
  (ready dependency))
(normally r-ready-adapter
  (and (task adapter) (completed dependency))
  (ready adapter))
(normally r2-ready-refusals
  (and (task refusals) (completed adapter))
  (ready refusals))
(normally r-ready-web-demo
  (and (task web-demo) (completed adapter))
  (ready web-demo))
(normally r-ready-http-boundary
  (and (task http-boundary) (completed web-demo))
  (ready http-boundary))
(normally r2-ready-browser-e2e
  (and (task browser-e2e) (completed refusals) (completed http-boundary))
  (ready browser-e2e))
(normally r2-ready-documentation
  (and (task documentation) (completed browser-e2e))
  (ready documentation))
(normally r-ready-verification
  (and (task verification) (completed documentation))
  (ready verification))
(normally r-ready-completion-audit
  (and (task completion-audit) (completed verification))
  (ready completion-audit))
(normally r-spec-006-verified
  (and (completed completion-audit))
  (verified spec-006))
```

The implementation is complete only when the Elephant theory derives the terminal
completion literal from verified dependency, adapter, refusal, browser, documentation, and mutation evidence.

## Amendment Channels

Amendable by: the [[SPEC-006-cbcl-pairing-integration]] owner.

Through: a versioned plan revision that names affected requirements and tests.

Not amendable by: implementation convenience, test output, dependency drift, or demo screenshots.

Hard stops: no production enablement, no verifier bypass, no legacy cryptography in the adapter,
and no payload before explicit approval.
