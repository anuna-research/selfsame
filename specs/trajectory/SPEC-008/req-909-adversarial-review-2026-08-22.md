# SPEC-008 0.3.0-draft (REQ-909 first-contact admission) — adversarial review: REJECT (2026-08-22)

Reviewer: fresh-context agent, defect-finding mandate, over the amendment and
the wire/ceremony/identity code it would drive. Verdict: **REJECT**; the
amendment was withdrawn the same day and SPEC-008 restored to 0.2.2.

## Blocking findings

- **F-1 (CRITICAL, false premise).** The cbcl-pairing invitation's
  `application` member is validated as `domain/profile/vN` and every real
  invitation carries the constant `anuna.io/credential/v1`
  (cbcl-pairing `wire.rs` `valid_application_id`, `profile.rs`
  `CREDENTIAL_APPLICATION`; enforced at `SelfsameEndpointBootstrap::start`).
  It is never a CON-201 `applicationId` and carries no per-application
  identity — the live-fetch mechanism REQ-909 specified had **no wire
  source**. The amendment's author had verified the field existed but not
  its value grammar.
- **F-2 (CRITICAL, hard-stop violation).** Pre-consent closure publication
  and reciprocal alias provisioning violate SPEC-007 REQ-812 ("no accepted
  credential or identity side effect before approved payload delivery";
  CON-204 provisioning only after approval) — inherited by SPEC-008's own
  CON-901 post-condition and declared unwaivable. Concretely: a person
  scanning a rogue QR and **declining** would already have published a home
  closure and provisioned an alias at the attacker's authority.
- **F-3/F-4 (HIGH).** The registry digest certifies the relay operator, not
  the application; any origin can serve a valid profile naming the anuna-1
  descriptor, so consent text was the only application-level barrier (and
  punycode lookalikes pass CON-201's ASCII rule). Repeated pre-acceptance
  first contacts mint unbounded scopes/closures/aliases — an amplification
  primitive.
- **F-5/F-6.** REQ-909's own step order contradicted ADR-914's; the
  amendment silently relaxed REQ-906's held-profile invariant without
  reconciling the hard-stop list.

## Disposition

Withdrawn in full: REQ-909, TEST-916/917, the REQ-906 edit, and the
Orientation-controls edit are reverted; ADR-914 stands in IMPL-008 with
status REJECTED pointing here. The conclusion the review itself reaches:
the sound first-contact path is [[IMPL-008-production-pairing-claimant#ADR-913]]'s
enrolment wire — the held-profile invariant stays, and the prior
relationship is manufactured honestly by a real grant ceremony, not
waived. Any future resurrection of pairing-first contact needs a
coordinated cbcl-pairing wire amendment (a per-application identity in the
invitation, reviewed for its own phishing surface), an application-level
anchor beyond the relay digest, and REQ-812-compliant ordering.

## What the process did

The owner had approved driving this path; the fresh-context review caught
a false factual premise and a hard-stop violation before any code was
written. This record exists so the next session reaches for ADR-913
directly instead of re-deriving the rejection.
