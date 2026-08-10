# SPEC-004 v0.14.0-draft — cross-model review and its disposition

- **Artefact:** [[SPEC-004-application-scoped-identity]] v0.14.0-draft, the
  key-derivation amendment only.
- **Prompt:** [[reviewer-prompt-0.14.0-draft]], in the scope it sets.
- **Reviewer:** a different model family (Codex), fresh context, given the
  specification, the amendment diff, [[SPEC-001-device-key-provisioning]], and
  four source files. The three prior Anthropic-family passes were deliberately
  withheld.
- **Returned:** two P1 and three P2 findings.
- **Disposition:** all five accepted. Four changed the document; one is a design
  ruling by the owner. Applied in commit `b45b08b`.

## Why this pass mattered

The amendment it reviewed was itself a replacement for a draft that three
earlier passes had destroyed — that draft rooted at SPEC-001's persona root and
its `REQ-232` made every account unrecoverable after every restore. This was the
third design for one problem, and the first assessed by a reviewer outside the
drafting model family.

It found two P1s the three earlier passes could not have found, because both
live in text those passes never saw: the `named` lookup mode and the account
selector were introduced *in response to* their findings.

## F1 — P1 — `named` defined no account selector

**Finding.** `REQ-217`'s `named` mode returns a scope to a caller that "names the
account", but neither it nor any contract defined what naming an account *is*.
`TEST-245` compounded it by permitting a caller to name the **application**. An
application with accounts A1/S1 and A2/S2 has nothing to distinguish them, so a
restored wallet cannot deterministically re-derive either.

**Accepted, and the drafting error is worse than the finding states.** No
selector could have been inferred: `accountScopeId` is what is being looked up,
and `CON-203`'s stable alias is a function of the home DID the caller is trying
to derive. Both are circular. The mode was written without checking that its own
input existed.

**Repair.** `REQ-217` fixes the selector as the account's human-readable alias
([[SPEC-004-application-scoped-identity#CON-212]],
[[SPEC-004-application-scoped-identity#REQ-218]]) and requires an application
declaring `named` to hold one for every account, or to declare `authenticated`.

The alias is mutable, and that is admissible **because it is a lookup key and
never a derivation input** — a rename re-points a mapping and changes no derived
value. This is the same distinction that makes deriving *from* a username
inadmissible under [[SPEC-004-application-scoped-identity#ADR-210]] and looking
up *by* one sound, and it is now stated rather than left to be re-derived.

`TEST-245` gains a two-account case — the case that actually detects an
application-keyed lookup — and a refusal for an unnamed account under `named`.

## F2 — P1 — a named scope does confer takeover to a root-holder

**Finding.** The claim that a named scope "confers no authority" and can cause
only denial of service is false once the caller also holds the victim's recovery
phrase or a stolen `hierarchy_root`. `accountScopeId` is a required KDF context
for `account_node`; returning it unauthenticated supplies exactly the input such
an attacker lacks. The reciprocal binding then succeeds, because the derived DID
is genuine. That is takeover, not denial of service.

**Accepted as stated, and dispositioned as a ruling rather than a repair.** The
finding is correct about the mechanism. What it exposed is a contradiction older
than the amendment: [[SPEC-004-application-scoped-identity#REQ-217]] has always
said the scope "is not a password or source of cryptographic entropy", while the
construction lets its confidentiality do real defensive work. Both cannot be
true, and `named` forced the choice into the open.

**The owner ruled that the scope is not a secret.** The recovery secret is the
only secret in this hierarchy; a party holding `hierarchy_root` is already in
possession of the identity, and whether it must additionally fetch a scope is a
speed bump rather than a boundary. `REQ-217` now states that ruling explicitly —
including *why a reader would conclude the opposite*, so the next reviewer does
not have to re-derive it — and names what the mode does cost: disclosure and
enumeration by account name.

**Residual, recorded rather than closed.** An attacker who steals a sealed
`hierarchy_root`, knows a `named` application's `applicationId`, and can guess or
enumerate the victim's account name obtains that account's key. This is accepted
on the ruling above. The controls that remain are the seal on the custody blob,
rate limiting, and the enumeration difficulty of account names — none of which is
claimed as a cryptographic boundary.

## F3 — P2 — the blast-radius statements omitted the account scope

**Finding.** `ADR-223` and the threat model claimed `hierarchy_root` alone yields
every `account_node` and `home_signing_seed` under the persona. It does not: each
additionally requires that account's independent 32-byte `accountScopeId`. The
Tier-1 acceptance box therefore asked reviewers to approve a radius the
construction does not produce.

**Accepted.** The statement was right by accident, having been written to correct
an earlier draft that stated the radius backwards — the correction overshot.

**Repair.** Both places now state the derivation accurately *and* keep the full
radius, on F2's ruling: the gap is a delay, not a boundary, and `SHALL NOT` be
counted as a mitigation. The accurate and the conservative statement coincide
only because of the ruling, so the two are now written together.

## F4 — P2 — `hierarchyVersion` had no representation or unsupported-value rule

**Finding.** The value became security-critical account-record input with no
type, grammar, canonical form, supported-value set, or rejection rule. Records
carrying `2`, `"2"`, `"v2"` or `3` had no specified outcome; `TEST-245` tested
only absence. Two implementations can disagree, and the one that coerces derives
the wrong identity silently on an empty restore.

**Accepted.** `CON-202` now fixes it as a JSON integer with no leading zero,
sign, fraction or exponent; recognises exactly `2`; and forbids coercion of any
other spelling.

A second closed token, `DerivationVersionUnsupported`, is added and kept
**distinct** from `DerivationProvenanceUnavailable`. The two situations differ in
what a person can do about them: a missing version may be recoverable from
another carrier, while an unsupported one means the account was written by newer
software and no retry, resolver or backup changes that. Collapsing them would
send an operator hunting for a record that already exists. Both tokens require
separate corpus cases under `CON-226`.

## F5 — P2 — `TEST-244`'s version separation tested a hybrid

**Finding.** The clause varied only the v1/v2 salts over "otherwise identical
inputs", but hierarchy version 1 rooted at `bip39_seed` while version 2 roots at
`hierarchy_root`. `KDF_v1(hierarchy_root, …)` is a synthetic value that existed
in neither version, so the test passes while leaving the real v1 tree
uncompared.

**Accepted.** The clause now varies **salt and root together**, and says why
both must move.

## What this pass did not cover

Recorded from the reviewer's own list, because a review discharges what it
assessed and nothing else:

- the non-amendment portions of SPEC-004, except where needed to test the above;
- the missing v2 corpus, vectors, and sign-off gate items;
- whether the current hierarchy-version-1 implementation conforms to the
  amendment; and
- application-account APIs, account-authority implementations, and unrelated
  protocol contracts.

## Standing

This pass was run against the version committed as `35fb051`. The repairs above
are `b45b08b`, so **what the reviewer assessed is no longer what is there** —
by the same rule this vault applies elsewhere, a further round is needed to
discharge the gate box against the repaired text. F1 and F2 are where a fourth
error is most likely: F1's selector is new text written in response to a
finding, and F2 is a ruling that closes a reading rather than a change that
removes it.
