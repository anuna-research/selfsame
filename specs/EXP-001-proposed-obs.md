# EXP-001 — Proposed observability signals for SPEC-004

| Field | Value |
|---|---|
| id | EXP-001-proposed-obs |
| status | **proposal** — not an amendment |
| brief | [[EXP-001-spec-004-reference-implementation]] |
| findings | [[EXP-001-findings]] `FINDING-014` |
| target | [[SPEC-004-application-scoped-identity]] |
| date | 2026-07-31 |

## Why this is a separate file

[[SPEC-004-application-scoped-identity]] defines **zero** `OBS-###` artefacts.
Constitutional Principle 7 requires that "every `REQ-###` carries at least one
`OBS-###` link post-release", and PROTO-001's traceability chain is
`REQ → CON → TEST → CODE → OBS`. SPEC-004's own Traceability table has no OBS
column, so the chain terminates at TEST and the principle is unsatisfiable as
written.

This file does not fix that, because it cannot. SPEC-004's Amendment Channels
say plainly:

> Chat instructions, implementation drift, passing tests, issue comments, and
> provider behavior are evidence or amendment **requests**; none changes this
> contract by itself.

So this is a request, drafted in the form the owner would need in order to accept
it: a concrete OBS set, each entry traced to the requirements it serves, ready to
be lifted into SPEC-004 by a versioned change that satisfies the five
Amendment-Channel conditions. Nothing here is normative until that happens.

## The constraint that shapes the whole set

An observability signal for *this* specification is unusually constrained,
because the things a designer would reach for first are exactly the things three
other obligations forbid emitting:

| Tempting dimension | Forbidden by |
|---|---|
| `accountScopeId` | `REQ-217` — "SHALL NOT appear in … a log, analytics event, or other public protocol artifact" |
| home DID, `acct:` alias | `NFR-201` — a shared value across two accounts is a correlation handle |
| grant ID | `NFR-203`, and it is the revocation key |
| device DID, `cnf.jwk` | `REQ-215` — pairwise home DIDs do not give pairwise privacy if the device is shared |
| the application's own identity, on a wallet | `REQ-222` — not even branch *existence* may be disclosed |

Every signal below is therefore either a **counter** or a **latency
distribution**, dimensioned only by values that are already public to the party
emitting them. Where a dimension would be a correlation handle it is omitted, and
the entry says so.

That is not a limitation to work around; it is the point. A metric that would let
an operator reconstruct which accounts a person holds is a metric that defeats
`NFR-201` more thoroughly than any protocol flaw, because it does so quietly and
at scale.

## Proposed signals

### OBS-201: Grant acceptance outcome

**Signal.** Counter of `CON-206` outcomes, dimensioned by the numbered step that
refused (1–13) and by `accept` for success.

**Emitted by.** The verifier.
**Not dimensioned by.** Grant ID, account, device, or issuer — the step alone.
**Serves.** [[SPEC-004-application-scoped-identity#REQ-207]],
[[SPEC-004-application-scoped-identity#NFR-205]].

Why the step and not the outward reason: `CON-206` collapses externally visible
errors to a small set so an attacker gains no credential oracle, and that
collapse is correct for the *response*. A local metric is not a response, and a
verifier that cannot see which step fires cannot tell a clock-skew problem from
an attack.

### OBS-202: Issuer closure age at acceptance

**Signal.** Distribution of `closure_age_seconds` observed at `CON-206` step 10,
dimensioned by freshness tier (`establishment` / `continuation`) and closure
source (`resolver` / `bundle-or-cache`).

**Serves.** [[SPEC-004-application-scoped-identity#REQ-208]],
[[SPEC-004-application-scoped-identity#OQ-201]].

This is the signal `OQ-201` needs in order to be ratified on evidence rather than
on judgement. The four values it asks the owner to ratify are bounds on a
distribution nobody has yet measured.

### OBS-203: Bundle-supplied closure reliance

**Signal.** Counter of acceptances where `CON-206` step 10 relied on a
bundle-supplied closure at session establishment.

**Serves.** [[SPEC-004-application-scoped-identity#REQ-208]].

`CON-206` requires a verifier to *record* that it did so. This is that record,
made countable. It should be near zero: the contract calls it "a bootstrap for a
first ceremony on a degraded network, not a standing arrangement", and a rising
rate means an implementation has quietly made it standing.

### OBS-204: Revocation propagation latency

**Signal.** Distribution of the interval from `RevokeCredential` submission to
the first newly resolved, verified closure containing the credential ID.

**Serves.** [[SPEC-004-application-scoped-identity#REQ-208]],
[[SPEC-004-application-scoped-identity#OQ-201]].

**Temporal property** (PROTO-001 §Temporal Properties):

```text
REQ-208.a  submitted  = revocation_submitted
REQ-208.b  confirmed  = OBS-204 observed

REQ-208    always (submitted => eventually[0s, 60s] confirmed)
```

`60s` is `revocation.propagationSlaSeconds` at the `CON-201` default. The interval
carries an explicit unit, and the signal it is stated over is an `OBS-###`
identifier, which is what makes this monitorable in Phase 4 rather than merely
asserted in Phase 2.

### OBS-205: Revocation submissions outstanding

**Signal.** Gauge of revocations in `Submission::Pending`, dimensioned by age
bucket.

**Serves.** [[SPEC-004-application-scoped-identity#REQ-208]].

A revocation the controller believes it made and no verifier can see is the
failure `CON-210` is built around. A pending count that does not drain is that
failure, visible.

### OBS-206: Provider selection outcome and latency

**Signal.** Counter of `CON-208` outcomes (`selected` / `NoEligibleRendezvous`)
dimensioned by priority group index, plus a distribution of end-to-end selection
duration.

**Serves.** [[SPEC-004-application-scoped-identity#REQ-209]],
[[SPEC-004-application-scoped-identity#NFR-207]].

**Temporal property:**

```text
NFR-207    selection_duration <= 2000ms at p95, given >= 1 healthy declared provider
```

`NFR-207` is the one NFR in SPEC-004 with a numeric latency threshold and no
signal to evaluate it against. This is that signal.

**Not dimensioned by.** Provider ID on the *client*: a per-provider client metric
recreates the cohort `CON-208`'s random draw exists to prevent. An operator may
of course count its own traffic.

### OBS-207: Capability probe outcome

**Signal.** Counter of probe results dimensioned by service (`pairing` /
`mailbox`) and outcome (`pass` / `fail` / `deadline-exceeded`).

**Serves.** [[SPEC-004-application-scoped-identity#REQ-219]],
[[SPEC-004-application-scoped-identity#NFR-207]].

Separating the two services matters: `CON-213` requires both to pass, so a
descriptor failing on one is a different operational story from one failing on
both, and the aggregate hides it.

### OBS-208: Enrollment evidence rejection

**Signal.** Counter of `CON-214` outcomes dimensioned by the twelve closed error
tokens.

**Emitted by.** The wallet.
**Serves.** [[SPEC-004-application-scoped-identity#REQ-222]],
[[SPEC-004-application-scoped-identity#REQ-223]].

`EnrollmentReplay` deserves separate attention in any alerting built on this: a
non-trivial rate means either a broken retry loop or somebody replaying a
captured statement, and the two look identical here by design — `REQ-222` forbids
the wallet disclosing enough to tell them apart to the caller.

### OBS-209: Device proof outcome

**Signal.** Counter of `CON-207` outcomes dimensioned by reason (`ok`,
`bad-signature`, `nonce-expired`, `nonce-replayed`, `nonce-mismatch`,
`nonce-unknown`).

**Serves.** [[SPEC-004-application-scoped-identity#REQ-206]].

`nonce-replayed` is the interesting one, because `CON-207` consumes a nonce
whether verification succeeded or failed — so a replay counter that rises is
either a client retrying incorrectly or an attacker reusing a captured proof.

### OBS-210: Ceremony burn

**Signal.** Counter of ceremonies reaching `CON-218`'s terminal `burned` state,
dimensioned by cause: the nine `PairingDowngrade` modes plus `dispatch`,
`confirmation`, `timeout`, and `provider-change`.

**Serves.** [[SPEC-004-application-scoped-identity#REQ-225]],
[[SPEC-004-application-scoped-identity#REQ-229]].

The `PairingDowngrade` dimensions should be **zero** in a conforming deployment:
each names something no version-1 client does. A non-zero count is a
non-conforming peer or an attack, and it is worth alerting on rather than
graphing.

### OBS-211: Same-device dispatch outcome

**Signal.** Counter of `CON-215` dispatch results dimensioned by the seven closed
values and by platform.

**Serves.** [[SPEC-004-application-scoped-identity#REQ-220]],
[[SPEC-004-application-scoped-identity#REQ-225]].

`UnverifiedWalletTarget` and `HandoffAmbiguous` are the two that indicate a
hostile local app rather than a missing one, and `TEST-230` is their test.

### OBS-212: First-enrollment confirmation outcome

**Signal.** Counter of `CON-221` outcomes (`confirmed` / `rejected` /
`timed-out`), and a gauge of accounts whose authority state was `Unknown` and
therefore failed closed.

**Serves.** [[SPEC-004-application-scoped-identity#REQ-230]],
[[SPEC-004-application-scoped-identity#NFR-205]].

A rejection here means a person compared two fingerprints and they differed,
which is either a bug or the exact attack `CON-221` exists to catch. It should be
vanishingly rare and it should page someone.

### OBS-213: Account provisioning failure

**Signal.** Counter of `AccountProvisioningFailed`, dimensioned by whether the
grant was subsequently revoked or left to expire.

**Serves.** [[SPEC-004-application-scoped-identity#REQ-204]].

The dimension is the point. `CON-204` permits an application that cannot reach the
home controller to fall back on `validUntil`, and `REQ-208` calls grant lifetime
"the outer bound on how long a revoked or unprovisionable device keeps working".
This counts how often that degraded path is taken.

### OBS-214: Identity succession

**Signal.** Counter of `CON-225` attempts and `SuccessionRejected` outcomes.

**Serves.** [[SPEC-004-application-scoped-identity#REQ-231]].

**Not dimensioned by** the reason. `CON-225` collapses every failure to one token
precisely so a caller cannot learn why — "in particular, not whether it holds an
outgoing identity for that application" — and a dimensioned metric exported
anywhere the caller can see would undo that.

## Coverage against Principle 7

Every requirement with a post-release observable now has one. The mapping the
Traceability table would gain:

| REQ | OBS |
|---|---|
| REQ-204 | OBS-213 |
| REQ-206 | OBS-209 |
| REQ-207 | OBS-201 |
| REQ-208 | OBS-202, OBS-204, OBS-205 |
| REQ-209 | OBS-206 |
| REQ-219 | OBS-207 |
| REQ-220, REQ-225 | OBS-211, OBS-210 |
| REQ-222, REQ-223 | OBS-208 |
| REQ-229 | OBS-210 |
| REQ-230 | OBS-212 |
| REQ-231 | OBS-214 |
| NFR-205 | OBS-201, OBS-212 |
| NFR-207 | OBS-206 |

Requirements with **no** proposed signal, and why — this half matters as much as
the other, because a signal invented to fill a table is worse than an honest gap:

| REQ | Why no signal |
|---|---|
| REQ-201, REQ-213, REQ-216, REQ-217 | Derivation properties. Deterministic and unobservable at runtime by construction; a metric here would have to read the values the requirement exists to keep private. Verified by test, not by telemetry. |
| REQ-202, REQ-203, REQ-205, REQ-211 | Format and construction obligations. A conforming implementation cannot violate them at runtime; a non-conforming one is caught at `CON-206`, which OBS-201 already counts. |
| REQ-210 | Absence of a fallback. Observable only as the *non-existence* of traffic, which is a build property — `tests/purity.rs` — rather than a signal. |
| REQ-214, REQ-218 | Developer and person-facing affordances, measured by product analytics rather than by protocol telemetry. |
| REQ-215 | Device-key separation. A metric distinguishing device keys would itself be the correlation handle the requirement prevents. |
| REQ-221, REQ-224, REQ-226–228 | Structural properties of the ceremony, enforced by construction and covered by OBS-210's burn counter when violated. |

## What adopting this would require

A Tier-1 amendment under SPEC-004's declared channel, which per its own
Amendment Channels means a versioned change to the file that identifies the
affected artefacts, updates traceability and the changelog, records the reason
and evidence, receives the tier-required reviews, and is approved by the human
owner.

Two of the entries above (`OBS-204`, `OBS-206`) carry temporal properties, and
PROTO-001 requires exemplification before a formalised property set is marked
`approved` — a property set that exemplifies to nothing is unsatisfiable, and
that check is invisible to any amount of downstream testing.
