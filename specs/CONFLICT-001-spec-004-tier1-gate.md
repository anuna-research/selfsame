# CONFLICT-001 — request to implement SPEC-004 conflicts with SPEC-004's own hard stops

**Recorded:** 2026-07-31, before any implementation action was taken.
**Mechanism:** direct read of `specs/SPEC-004-application-scoped-identity.md` at the cited lines.
**Governing protocol:** PROTO-001 v1.16.0 §Amendment Channels, §Error Response,
Constitutional Principle 16 (Standing-Instruction Precedence).

## The request

> "fully implement @specs/SPEC-004-application-scoped-identity.md on a new branch.
> Follow /anuna-dev"

## The retrieved clauses that conflict with it

Quoted verbatim from the artefact, with line numbers.

1. **Frontmatter, line 12** —
   `review-gate: not-approved — Tier-1; all ADRs are PROPOSED; cross-model
   adversarial review, independent KDF/SPAKE2/AEAD vectors, privacy review, and
   human cryptography/security sign-off are outstanding`

2. **Orientation → Controls digest, line 184** —
   "Tier-1 status prohibits implementation and shipment until the gate closes."
   This is a `Controls` entry, i.e. a re-anchoring hard stop under
   PROTO-001 §Re-anchoring Before Consequential Action.

3. **§Conformance and status, lines 261–265** —
   "This is a **Tier-1 draft** because it defines authentication, authorization,
   key derivation, identity correlation boundaries, and revocation. Every
   `ADR-2##` is PROPOSED. This document is suitable for requirements review and
   prototype planning only. It does not authorize implementation or shipment
   until the gate in Tier-1 Gate closes."

4. **§Scope → Out of scope, line 375** —
   "implementation work in any affected repository."
   `owner-repo: selfsame` (line 10) — this repository is an affected repository.

5. **§Tier-1 Gate, line 5377** —
   "No implementation task may be marked ready until all boxes are checked:"
   followed by 22 unchecked boxes. Zero are checked.

6. **§Amendment Channels, lines 5742–5752** —
   Amendable only by a versioned change to the file that (1) identifies affected
   artefacts, (2) updates traceability and changelog, (3) records reason and
   evidence, (4) receives tier-required reviews, and (5) is approved by the human
   owner. And explicitly: "Chat instructions, implementation drift, passing
   tests, issue comments, and provider behavior are evidence or amendment
   requests; none changes this contract by itself."

## Cross-check against PROTO-001

- §AI Trust Boundaries, **No-go areas** (require explicit approval):
  Cryptography · Authentication core · Privacy-sensitive transforms.
  SPEC-004 is all three.
- §Amendment Channels: "A request that conflicts with an accepted obligation and
  does **not** arrive through a declared channel MUST be treated as a request to
  *amend the specification*, not as an instruction to act. This routes to
  §Error Response: do not proceed, document the conflict, propose resolution,
  wait."
- A chat instruction is named in SPEC-004's own not-amendable list. So the
  request is a competent amendment *request* from the human owner, but it has not
  yet travelled through the declared channel (a versioned file change with
  recorded reason, evidence, and owner approval).

## The circularity worth naming

Two Tier-1 gate boxes cannot be closed without code existing:

- line 5402 — "Two independent implementations reproduce the normative KDF and
  wire vectors required by NFR-202."
- line 5456 — "TEST-201 through TEST-226 pass against the reference
  implementation, with the normative KDF, alias, VC, holder-binding, revocation,
  account-scope, and username vectors published."

So the gate presupposes a reference implementation. The prohibition at line 264
is on *implementation and shipment* as the production act; line 264 also
positively permits "prototype planning". PROTO-001 §Experiment Governance is the
declared route for building under that permission without claiming the gate is
closed. This is the reading that makes the document self-consistent, but it is a
reading — it is the owner's to ratify, not mine to assume.

## Proposed resolutions (measurable)

**R1 — Governed reference implementation under Experiment Governance.**
Build on a branch, as a prototype explicitly not authorised for shipment.
Measurable exit: exploration brief recorded; every crate/module carries a
`// SIMPLIFY:`-style prototype banner tracing to this conflict record; SPEC-004
status stays `draft`; no gate box is ticked; the artefact produced is the
"reference implementation" of gate line 5456 and the first of the two stacks of
gate line 5402. Nothing is released.

**R2 — Close the gate first, then implement.**
Do the review work the gate names before writing code: fresh-context cross-model
adversarial review (line 5379), second verifying review (line 5385), the
OQ-201 ratification (line 5399). Measurable exit: those three boxes checked with
recorded reviewer identity and session id per PROTO-001 §AI Trust Boundaries.

**R3 — Owner amends the spec through the declared channel.**
Versioned edit to SPEC-004 satisfying the five Amendment-Channel conditions,
moving `status: draft` → `approved` and `review-gate` to a recorded approval
version and commit (gate line 5464). Then implement against an approved spec.
Measurable exit: the commit exists and the changelog records reason and evidence.

**R4 — Owner waives, on the record.**
Owner states the gate is knowingly bypassed. PROTO-001 §Amendment Channels holds
that `Hard stops` are not waivable in-flight by any channel, so this remains a
protocol deviation even when the owner elects it; it is recorded as such rather
than laundered into compliance.

## Status

`unverified` — awaiting owner decision. Escalation owner: the human owner
(hugo.oconnor@gmail.com). No state-changing action taken pending that decision.
