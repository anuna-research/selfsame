# SPEC-004 0.16.0-draft — fresh-context adversarial review (2026-08-21)

Reviewer: fresh-context agent (same model family, clean context, defect-finding
mandate) over commit `13112c0` (ADR-224 / CON-227 / TEST-246), the wallet code
(`selfsame-app-identity` platform.rs / enrollment.rs / profile.rs), and the
cbcl-bus sibling repo the ADR's factual claims name. Constitutional
Principle 12 note: cross-model review and human security sign-off remain
outstanding per the Tier-1 gate; this record is the first of the required
reviews, not the last.

## Verdict

**APPROVE-WITH-CHANGES.** No security regression found. The equivalence claim
to [[SPEC-004-application-scoped-identity#CON-223]]'s unattributed case was
verified against code: the existing carve-out is binding-scoped, not
device-scoped (`caller_matches_binding` passes `(Unattributed, Apple)` on any
device), so a web binding accepted against unattributed evidence admits no
relay class the Apple carve-out does not already admit. The downgrade route
(statement re-routed to the weaker binding) is closed because the backend, not
the caller, signs `platformBindingId`, and any attributed caller against a web
binding refuses. ADR-224's factual predicates (fail-closed old recogniser; no
ratified profile anywhere; generator refusal discipline) all checked out
against both repositories.

## Findings and dispositions (all folded in the follow-up commit)

1. **Medium — `returnUri` unanchored under a web binding.** CON-214 requires
   the member; only CON-223 gave it meaning. Folded: CON-227 now fixes its
   grammar (HTTPS, `applicationId` origin, never dispatched or dereferenced,
   carries no authority) and TEST-246 gains the foreign-origin negative row.
2. **Medium — affected downstream artefacts unidentified.** cbcl-bus
   SPEC-053's CON-002 mobileBindings row ("empty is a statement… a browser
   cannot claim a platform binding") mandates the opposite disposition, and
   the profile generator makes the Apple blanks mandatory. Folded: the
   changelog names both as owing follow-up amendments.
3. **Medium — vectors deferred while Amendment Channels requires them.**
   Folded: the changelog entry now states owner approval SHALL NOT be
   recorded before the TEST-246 corpus cases and their SHA-256 land.
4. **Low/Medium — missing mixed-profile downgrade probe.** Folded: TEST-246
   gains the row (android + web declared; statement names web; caller
   attributed as the declared android package → `PlatformBindingMismatch`)
   with a matching mutation gate.
5. **Low — traceability.** Folded: CON-227 traces
   [[SPEC-004-application-scoped-identity#REQ-225]]; TEST-246's Validates
   gains [[SPEC-004-application-scoped-identity#CON-215]] and
   [[SPEC-004-application-scoped-identity#REQ-220]] for its depth row.
6. **Low — stale self-reference.** Folded: ADR-224 says the specification
   *was* `0.15.0-draft` at decision time.
7. **Low — corpus group filing ambiguity.** Folded: CON-226 group 3 states
   that `web-manual` traces are cross-device by construction and that web
   profile-recognition negatives belong to group 2.

## Accepted-by-design residual

An application that declares a web binding **beside** a native one re-admits
relay phishing that a native-only profile refused. CON-227 states this as a
profile-owner choice ("a deployment whose threat model requires platform
attribution declares native bindings and omits the web form"), and finding 4's
test row pins the refusal of the attributed-caller route around it.
