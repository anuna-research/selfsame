# EXP-001 — Synthetic user simulation

| Field | Value |
|---|---|
| id | EXP-001-synthetic-user-run |
| protocol | [[PROTO-001-usdd-agent-protocol]] §Synthetic User Protocol |
| profiles | [[person-profile]], [[developer-profile]] |
| happy paths | [[person-happy-paths]], [[developer-happy-paths]] |
| under test | [[SPEC-004-application-scoped-identity]] |
| model | Claude Opus 5 (1M context), `claude-opus-5[1m]` |
| date | 2026-07-31 |

## A limitation to read before the findings

PROTO-001 requires the synthetic user to be executed as a **sub-agent** working
"from the specification and user profile only", without access to the
implementation. This run was not.

It was performed by the same session that wrote the implementation, at the
operator's instruction not to spawn agents. That breaches the separation
Constitutional Principle 12 exists to enforce, and the breach is not cosmetic:
this reader knows what the code does, so it cannot reliably notice where the
specification is silent and the implementation quietly decided. Every "the spec
does not say" below is therefore a *weaker* claim than it would be from a fresh
reader — it survived one pass by someone predisposed to fill gaps from memory.

The findings are recorded anyway, because eight real ones found imperfectly is
better than none found properly. But this run does **not** discharge the
synthetic-user gate, and the Gate Evidence Record marks it `unverified` for that
reason.

## Method

Each happy path was walked step by step from the specification's own prose and
the user profile, narrating what the person sees, does, and expects. Findings
use PROTO-001's categories and template.

---

## Findings

### Finding: The recovery phrase alone does not restore an identity

- **Step:** `HP-7` step 3.
- **Category:** Assumption.
- **Description:** `REQ-217` requires the `accountScopeId` to come from "the
  authenticated application account record or protected Selfsame backup", and
  forbids guessing one or prompting for it. So a person who holds their twelve
  words and has not yet signed into the application has no identity: the words
  restore the *hierarchy*, and the application supplies the branch.

  The specification is mechanically clear and experientially silent. Nothing in
  the person's model distinguishes "my backup" from "my backup, plus every
  application account I had". The `Users and happy paths` §User restores section
  states the requirement in one clause — "it also requires that account's exact
  `accountScopeId`" — and moves on.
- **User impact:** A person recovering from a lost phone believes they are
  restored, discovers one application works and another does not, and has no
  action available. If the application account itself is lost, the identity is
  gone despite a perfectly correct recovery phrase.
- **Proposed resolution:** An `NFR-###` on recovery comprehensibility, or at
  minimum a normative clause requiring the wallet's backup UI to state what the
  phrase does and does not restore. The mechanism is right; the model the person
  forms about it is not addressed anywhere.
- **Trace:** amends [[SPEC-004-application-scoped-identity#REQ-217]]; new
  requirement candidate.
- **Severity:** the highest of the eight. It is the one that loses data.

### Finding: A mistyped word costs twelve new words, not a retype

- **Step:** `HP-4` step 3.
- **Category:** Friction.
- **Description:** `REQ-229` burns the complete ceremony on "a wrong code,
  conflicting claim, invalid point, confirmation mismatch, frame fork, timeout,
  carrier mismatch, ambiguous post-display request, or provider change", and a
  retry regenerates thirteen values including `C` itself.

  BIP-39's checksum catches most single-word errors locally, which softens this
  considerably — `ADR-406` names that as a reason for the encoding. But an error
  that passes the checksum, or a timeout, means the person reads twelve *fresh*
  words rather than correcting one.
- **User impact:** On the accessibility path — twelve words spoken aloud,
  because a QR is not usable — a failure costs the whole transcription again.
  For the person that path exists for, that is the difference between viable and
  not.
- **Proposed resolution:** None available at the protocol layer; N=1 burn is
  what makes a 128-bit password safe against online guessing, and weakening it
  is not on the table. This is a UX obligation: the interface must make
  re-reading cheap, and must not present a retry as though it were a correction.
  Candidate `NFR-###` on retry ergonomics for the spoken path.
- **Trace:** [[SPEC-004-application-scoped-identity#REQ-229]].

### Finding: The first-enrollment comparison assumes two visible screens

- **Step:** `HP-4a` step 4.
- **Category:** Accessibility barrier.
- **Description:** `CON-221` requires the person to compare a hexadecimal
  fingerprint shown by the wallet against one shown by the application, and
  `REQ-230` forbids any affordance to skip or suppress it.

  Both prohibitions are right — an affordance to skip is an affordance to
  reinstate the trust-on-first-use `NFR-205` removes. But the requirement
  presumes both screens are legible to the same person at the same moment, and
  the `person` profile's constraints include poor vision, a screen reader, and a
  laptop in another room.
- **User impact:** A person who cannot see both screens cannot complete a first
  enrollment, and there is no permitted alternative.
- **Proposed resolution:** `SPEC-002` already supplies a spoken-word rendering
  (`Fingerprint::label`) that `CON-221` does not mention. It carries fewer bits
  than the hex and is explicitly not a comparison value — but an accessible
  comparison at reduced strength, used once per account and only where the hex
  is unusable, may be better than an inaccessible one. This needs the human
  security reviewer, not an agent.
- **Trace:** [[SPEC-004-application-scoped-identity#CON-221]],
  [[SPEC-002-visual-key-fingerprint#ADR-107]].

### Finding: The correlation warning assumes knowledge the person lacks

- **Step:** `HP-3` step 2.
- **Category:** Assumption.
- **Description:** `REQ-218` requires the UI to "warn before publication that a
  reused username can correlate the person across services". The `person`
  profile holds the anti-tracking goal "weakly and rarely articulated", and does
  not contain the concept of correlation.
- **User impact:** The warning is shown, read as boilerplate, and dismissed. The
  requirement is satisfied and its purpose is not.
- **Proposed resolution:** Make the warning concrete rather than categorical —
  naming what an observer could conclude, rather than that correlation is
  possible. A measurable acceptance criterion is available here and the
  requirement currently has none.
- **Trace:** [[SPEC-004-application-scoped-identity#REQ-218]].

### Finding: The window where a grant exists and is unusable has no defined screen

- **Step:** `HP-4` step 7.
- **Category:** Error path gap.
- **Description:** In `CON-204`'s remote-controller ordering the wallet issues
  before the application provisions. Between the two the grant exists and
  `CON-206` step 9 fails closed. The contract is precise about the mechanism —
  "a verifier SHALL NOT relax step 9 on the grounds that the grant is newly
  issued" — and says nothing about what the person sees during it.
- **User impact:** They approved something and it has not worked yet. Whether
  that is a spinner, an error, or silence is unspecified, so two conforming
  applications may differ.
- **Proposed resolution:** A `SCREEN-###`, or a clause fixing the state as
  transient-and-retriable rather than failed.
- **Trace:** [[SPEC-004-application-scoped-identity#CON-204]].

### Finding: A revocation with no reachable resolver is pending forever

- **Step:** `HP-6` step 5.
- **Category:** Error path gap.
- **Description:** `CON-210` requires **pending** until a verified closure
  carries the ID, forbids reporting success on acknowledgement, and requires the
  delta be retained and retried. It defines no terminal failure and no bound on
  the pending state.

  That is correct — a revocation that gave up would be worse — but it means a
  person removing a lost device can be left indefinitely at "pending" with no
  guidance.
- **User impact:** At exactly the moment they are most anxious, the interface
  says the thing they asked for has not happened, and offers nothing.
- **Proposed resolution:** No change to the mechanism. A clause on what the
  application tells the person, and what `validUntil` guarantees in the
  meantime — `REQ-208` already bounds the damage at thirty days and the person
  has no way to know that.
- **Trace:** [[SPEC-004-application-scoped-identity#CON-210]].

### Finding: Embedding the enrollment key fails silently

- **Step:** `HP-D1` step 3 (developer).
- **Category:** Gap.
- **Description:** `CON-201` says the enrollment private keys "are backend
  credentials and MUST NOT be embedded in a native application". A developer who
  embeds one anyway has a system where **every test passes**: ceremonies
  complete, grants verify, devices authorize. The `REQ-222` guarantee is gone
  and nothing observable has changed.
- **User impact:** None, until a hostile sibling app extracts the key. Then
  `TEST-229`'s entire threat model is void.
- **Proposed resolution:** This is the most dangerous available integration
  mistake and the specification treats it as one clause among many in
  `CON-201`'s prose. It belongs in the Orientation `Controls` digest, where a
  developer re-reading before a consequential action will meet it.
- **Trace:** [[SPEC-004-application-scoped-identity#CON-201]],
  [[SPEC-004-application-scoped-identity#REQ-222]].
- **Note:** this finding is about *placement*, not about a missing obligation —
  which makes it exactly the kind PROTO-001's Orientation block exists for.

### Finding: A CDN or apex redirect breaks profile discovery on first deploy

- **Step:** `HP-D1` step 2 (developer).
- **Category:** Friction.
- **Description:** `CON-220` step 2 rejects **every** redirect including
  same-origin. Apex-to-www rules, trailing-slash normalisation, and CDN
  canonicalisation are all default behaviours in common hosting, and every one
  of them breaks discovery.
- **User impact:** A developer's first deploy fails with a rejection whose cause
  is in their CDN configuration rather than their code.
- **Proposed resolution:** The rule is right and the reasoning is sound. What is
  missing is a note in `CON-220` naming this as the expected first failure, and
  a distinguishable error. `DiscoveryError::Redirected` exists in the reference
  implementation for that reason.
- **Trace:** [[SPEC-004-application-scoped-identity#CON-220]].

---

## Summary

| Category | Count |
|---|---|
| Assumption | 2 |
| Error path gap | 2 |
| Friction | 2 |
| Accessibility barrier | 1 |
| Gap | 1 |

No finding contradicts a requirement. All eight are places where the
specification fixes a mechanism correctly and leaves the person's or developer's
experience of it undefined — which is the failure mode a synthetic-user pass is
for, and is consistent with a document that has had heavy protocol review and no
usability review.

Two deserve escalation ahead of the others:

- **the recovery cliff**, because it loses data and the person's mental model is
  wrong in a way nothing corrects; and
- **the silently-embedded enrollment key**, because every test passes and the
  guarantee is gone.

## Convergence

Not reached. PROTO-001 requires findings to be converted to `REQ`/`NFR`
artefacts and the simulation re-run against the amended specification. Neither
has happened: amending SPEC-004 needs its declared channel, and re-running needs
a fresh-context reader this session cannot supply.
