---
id: spec-007-008-screen-003-successor-ux-amendments-2026-09-05
title: Successor manual-entry and single-Link parent amendments
status: draft-evidence
date: 2026-09-05
specs: "[[SPEC-007-cbcl-pairing-cutover]]; [[SPEC-008-production-pairing-claimant]]; [[SCREEN-003-wallet-pairing]]"
---

# Successor manual-entry and single-Link parent amendments

## Scope and provenance

The repository owner requested minimal current-law amendments for the manual
pairing design in cbcl-bus SPEC-078 0.1.1 and the single-Link consent design in
cbcl-bus SPEC-079 0.1.1. The repository owner is the amendment owner. Codex is
the delegated author. The exact model build and generation session are
unavailable; this note does not infer them from historical frontmatter.

The coordinated parent versions are:

- cbcl-pairing SPEC-001 0.5.10-draft;
- Selfsame [[SPEC-007-cbcl-pairing-cutover]] 0.3.10-draft;
- Selfsame [[SPEC-008-production-pairing-claimant]] 0.5.19-draft;
- cbcl-bus SPEC-053 0.17.15-draft;
- cbcl-bus SPEC-078 0.1.1; and
- cbcl-bus SPEC-079 0.1.1.

This amendment changes specifications and the wallet screen contract only. It
makes no code change, commit, index change, Elephant update, release, production
allocation, deployment, or independent human-review claim. Existing
cryptographic, security, privacy, release, production, and compatibility holds
remain effective. The pre-existing untracked presence-code word-encoding
proposal was left untouched.

## Backlink reading

The author read local backlinks for [[SPEC-007-cbcl-pairing-cutover]],
[[SPEC-008-production-pairing-claimant]], and [[SCREEN-003-wallet-pairing]] before
editing. Cross-vault successor backlinks were read in the current cbcl-bus
SPEC-078 and SPEC-079 parent-amendment inventories. No historical generation
record or trajectory note supplies current authority.

## Changed current-law anchors

[[SPEC-007-cbcl-pairing-cutover]] changes REQ-804, REQ-811, REQ-812,
REQ-813, ADR-805, CON-801, CON-806, CON-807, TEST-803, TEST-813, TEST-817,
and TEST-821. It distinguishes default complete/manual `SingleLink` from
explicit `LegacyTwoDecision`. It keeps both protocol decisions and gates final
protocol approval and effects on authenticated comparison. It also imports
manual one-peer-share and authenticated-closure mode-switch rules.

[[SPEC-008-production-pairing-claimant]] changes REQ-901 through REQ-906,
REQ-1006, ADR-902, CON-902, CON-903, CON-985 through CON-990, TEST-903,
TEST-906, TEST-908 through TEST-910, and TEST-1158 through TEST-1162 and
TEST-1167. It adds explicit full/manual/legacy recognition and a native tag
before contact. It requires truthful `CeremonyGesture` and no SingleLink durable
legacy row. It also adds one unlock plus rendered Link and bounded native
authority. Comparison precedes final protocol approval. Effect-entry revocation,
mode-aware compensation, and installed-state rules remain explicit.

[[SCREEN-003-wallet-pairing]] 0.2.0 adds REQ-954 through REQ-957 and
TEST-954 through TEST-958. It specifies explicit entry modes, manual bootstrap
plus words, and pre-contact recognition and tagging. It adds truthful contact
display, one-unlock/one-Link interaction, and legacy two-decision screens.
It requires cancellable comparison wait, stale-result refusal, and verified success.

## Mechanical receipts

`usdd-count.sh --json` reported these artefact-reference counts:

- SPEC-007: REQ 21, NFR 3, CON 20, TEST 29, ADR 8, OBS 4;
- SPEC-008: REQ 14, NFR 4, CON 29, TEST 24, ADR 8, OBS 4; and
- SCREEN-003: REQ 11, NFR 2, CON 4, TEST 9, and BUG 1.

Strict descriptive `usdd-lint.sh` reported zero errors and zero warnings for
all three parents and this note. Longest sentences were 25 words in every
parent and this note. `git diff --check` reported no whitespace error.

`zetl backlinks` completed for all three parents before and after editing.
The changed-source dead-link filter returned an empty set. The existing
vault-wide `zetl check --fail-on error` remains blocked by the unrelated
unclosed `[[Cargo` link in `EXP-002-e2e-linking-harness.md:263`. That file is
outside this amendment and was not changed.

These receipts are mechanical evidence only. They do not constitute review
acceptance or close any production gate.

## Known limits

The amendment does not redesign the authenticated desktop comparison, final
status transaction, or legacy exact-pair policy. It does not weaken their
existing tests. Manual and single-Link implementation still depends on the
completed confidential handoff integration and the exact successor acceptance
suites. Any existing vault-wide language or link debt outside these four files
is baseline debt and is not repaired here.
