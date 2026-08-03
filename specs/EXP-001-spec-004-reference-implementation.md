# EXP-001 — Governed prototype of SPEC-004

| Field | Value |
|---|---|
| id | EXP-001 |
| title | Reference implementation of [[SPEC-004-application-scoped-identity]] under Experiment Governance |
| status | active |
| opened | 2026-07-31 |
| owner | Anuna Research |
| branch | `prototype/spec-004-application-scoped-identity` |
| governs | [[PROTO-001-usdd-agent-protocol]] §Experiment Governance |

## Why this is an experiment and not implementation

[[SPEC-004-application-scoped-identity]] carries `status: draft`,
`review-gate: not-approved`, and three clauses that forbid its own
implementation:

- the Orientation `Controls` digest — "Tier-1 status prohibits implementation
  and shipment until the gate closes";
- §Conformance and status — "suitable for requirements review and prototype
  planning only … does not authorize implementation or shipment"; and
- §Scope → Out of scope — "implementation work in any affected repository".

Its Tier-1 gate nevertheless contains two boxes that cannot close without code:

- "Two independent implementations reproduce the normative KDF and wire vectors
  required by NFR-202"; and
- "TEST-201 through TEST-226 pass against the reference implementation, with the
  normative KDF, alias, VC, holder-binding, revocation, account-scope, and
  username vectors published."

The reading that makes the document self-consistent is that the prohibition
binds *production implementation and shipment*, while the positively permitted
"prototype planning" is the route by which the gate's own evidence is produced.
The human owner selected that reading on 2026-07-31. This file is the exploration
brief that PROTO-001 requires before such work begins.

The full conflict analysis, including the four resolutions offered and the
clauses quoted with line numbers, is `CONFLICT-001`.

## A recorded deferral

This document and its siblings link to [[PROTO-001-usdd-agent-protocol]] six
times, and that page is not in this vault — it lives in the `anuna-dev` skill,
which is tooling rather than project content. Those six are dead links.

They are recorded here rather than deleted, per the discipline PROTO-001 itself
sets: *"A dead `[[link]]` is **visible** debt … Do not delete a dead link to
clean up the report. Either author the target page or record an explicit
deferral."* [[SPEC-004-application-scoped-identity]] already links to the same
target ten times on the same basis.

**Deferral.** Mirroring the protocol into the vault is the SPEC-001 maintainer's
call, not this experiment's — it would make a tooling document into project
content and put a copy under version control that could drift from the skill.
Owner: the human owner.

## Hypothesis

The pure, deterministic core of SPEC-004 — key hierarchy, closed-language
recognisers, alias construction, credential issuance and the acceptance
predicate, device proof, provider selection, ceremony payloads, and succession —
can be implemented as a side-effect-free Rust library whose behaviour is fixed
entirely by the specification text, such that a second independent implementation
can reproduce it byte-for-byte from that text plus the published corpus.

Where the hypothesis fails, the failure is evidence about the *specification*,
not only about the code: a clause that cannot be implemented unambiguously is a
Phase-1 defect that the gate's adversarial review would otherwise have to find by
inspection.

## Approach

1. One new workspace crate, `selfsame-app-identity`, holding the pure core. It
   inherits the SPEC-001 §13 purity gate verbatim: no `tokio`, `reqwest`,
   `std::fs`, `std::net`, `std::time`, or `std::env` in the production graph, so
   the same predicate links into the phone, the CLI, and a wasm verifier.
2. Effects stay in the shell behind narrow traits. The contracts that need a
   network — profile discovery, WebFinger, state resolution, provider probes,
   delta submission — are split so that the *recognition and decision* half is
   pure and testable and only the *fetch* half is injected.
3. Test-first per Constitutional Principle 3. Each `TEST-2NN` in the spec
   supplies the acceptance criteria; tests are written and observed to fail
   before the implementation makes them pass.
4. Requirement-targeted decomposition per PROTO-001: positive, negative-input,
   negative-output, and — for every prohibitive or side-effecting REQ —
   prohibited-action and scope-invariant tests.
5. The Simplicity Ladder governs each capability. Rung 4 before rung 6: the
   existing `selfsame-core` fingerprint, `did-crdt` derivation, and workspace
   crypto dependencies are reused rather than re-implemented.

## Isolation and blast radius

- All work is on `prototype/spec-004-application-scoped-identity`. `main` is
  untouched.
- No production writes. No network calls in the core by construction — the
  purity gate is a test, not a convention.
- No sensitive data: every fixture is a published test vector or generated from
  a fixed seed.
- No release, no publish, no tag, no deployment.
- `specs/SPEC-004-application-scoped-identity.md` stays `status: draft` and no
  Tier-1 gate box is ticked by this work. The spec is amended only through its
  declared Amendment Channel, which this experiment does not use.

## Metrics

| Metric | Target |
|---|---|
| Contracts with a pure implementation and tests | every contract whose obligations are self-contained in SPEC-004 |
| CON-206 step coverage | a test per numbered step, each mutated independently (TEST-211) |
| Closed error tokens with a case | every token defined by CON-204, CON-211, CON-212, CON-214, CON-215, CON-219, CON-220, CON-221, CON-225 |
| Purity gate | passes |
| Corpus | `test-vectors/spec-004-v1.json` present, RFC 8785 canonical, satisfying the CON-226 completeness rule |

## Exit criteria

The experiment ends when either:

- **Converged** — the metrics above are met, and the findings report records what
  the specification got right, what it left ambiguous, and what a second
  implementer would need in order to agree byte-for-byte; or
- **Blocked** — a contract cannot be implemented from the specification text
  without inventing a normative decision. That is an Error Response condition:
  the ambiguity is documented against its artefact and escalated, and the
  remaining contracts continue.

Neither outcome closes a Tier-1 gate box. The gate is closed by the reviews and
sign-offs it names, and this experiment produces evidence for them, not a
substitute for them.

## Timebox

One working session. Unconverged surfaces are documented and escalated rather
than rushed, per PROTO-001 §Success Criteria termination condition 2.

## AI trust boundary record

| Field | Value |
|---|---|
| Model | Claude Opus 5 (1M context), `claude-opus-5[1m]` |
| Detection/authoring method | interactive session, spec read in full before authoring |
| Reviewer | none yet — Tier-1 requires cross-model adversarial review, outstanding |
| Decision | prototype authorised by the human owner, 2026-07-31 |

Constitutional Principle 12 forbids this session from validating its own output.
Every artefact produced here is unreviewed until a fresh-context reviewer with a
defect-finding mandate has seen it.
