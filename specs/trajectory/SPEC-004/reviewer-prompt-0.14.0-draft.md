# SPEC-004 v0.14.0-draft reviewer prompt — for a different model family

Prepared 2026-08-10 for [[SPEC-004-application-scoped-identity]]'s Tier-1 gate.
The subject is the **key-derivation amendment only**, not the whole
specification.

> ## Round 1 has been run — read this before reusing the prompt
>
> This prompt was used on 2026-08-10 against commit `35fb051` and returned two
> P1 and three P2 findings, dispositioned in
> [[review-disposition-0.14.0-draft]] and repaired in `b45b08b`.
>
> **What it assessed is therefore no longer what is there**, and the gate box is
> not discharged. A second round is needed against the repaired text. Before
> reusing this prompt, regenerate the attached diff and tell the reviewer — only
> *after* it has returned findings — that `REQ-217` now fixes the account
> selector as the human-readable alias, that the scope has been ruled not to be
> a secret, and that `CON-202` has gained a version grammar and a second error
> token. Attack angles 3 and 4 below are where a further error is most likely:
> angle 3's subject is now a ruling that closes a reading rather than a change
> that removes it, and angle 4's is text written in response to a finding.

## Why this pass exists

`FINDING-016` in [[EXP-001-findings]] recorded that hierarchy version 1 rooted
at the BIP-39 seed while [[SPEC-001-device-key-provisioning]] custody seals only
a one-way derivative of it and stores the phrase nowhere — so a wallet that had
completed onboarding could derive no home DID for any application, ever, without
the person re-entering twelve words. Version 0.14.0-draft re-roots the hierarchy
to close that gap.

**A first drafting attempt rooted at SPEC-001's persona root and was rejected on
review.** Three fresh-context passes over that draft returned findings that
killed it: the persona root would have been simultaneously an Ed25519 private
seed and HKDF input keying material; it collided with SPEC-001 `REQ-024`'s
per-use presence rule; `REQ-232` as then drafted made *every account
unrecoverable after every restore*; and the decision record stated the change's
blast radius backwards. This draft is the replacement.

**That history is the reason for this pass, not a reason to relax it.** The
replacement has been attacked by nobody. It was written by the same session that
wrote the draft those passes destroyed, and it is the third design for the same
problem in one day.

## For the operator, before you paste

**The reviewer must not be Claude.** Every prior pass on this material was
Anthropic-family, including the three that produced the findings above. The gate
box asks for cross-model review because same-family review shares the drafting
session's blind spots, and this document was drafted by Claude throughout.

**Attach exactly these.** Verify the diff is a real unified diff — it must open
with `diff --git` and contain `@@` hunk headers. Round 1 was prepared with a
file that a token-optimising shell wrapper had silently replaced with a
truncated summary ending in *"(more changes truncated)"*. A reviewer handed that
sees a changed-line count and no changed lines.

| Attach | Lines |
| --- | --- |
| `specs/SPEC-004-application-scoped-identity.md` (at v0.14.0-draft) | 6851 |
| `specs/trajectory/SPEC-004/spec-004-0.14.0-draft.diff` | 1054 |
| `../anuna-ssi/specs/SPEC-001-device-key-provisioning.md` | 1680 |
| `crates/selfsame-app-identity/src/hierarchy.rs` | 478 |
| `crates/selfsame-core/src/derive.rs` | 246 |
| `src-tauri/src/custody.rs` | 362 |
| `src-tauri/src/app_identity.rs` | 560 |

SPEC-001 is attached because `ADR-223` makes claims *about* it — that
`hierarchy_root` is a sibling of its persona root, that neither derives the
other, and that no obligation of SPEC-001 attaches to this hierarchy. Those
claims are checkable only against the document itself. The four source files are
attached so the reviewer can test whether the amendment is implementable against
the custody that exists, not to review the code.

**Do not attach** the three prior review reports, the disposition of their
findings, or `specs/trajectory/SPEC-053/selfsame-path-b-readiness-2026-08-10.md`
in the sibling repository. The first three name defects already found and would
convert an independent pass into a re-audit of somebody else's list; the fourth
is a readiness assessment whose framing would anchor the scope. If the reviewer
returns findings and you then want to know whether the earlier passes are
discharged, offer the reports afterwards and ask one short follow-up: *does this
change your assessment?*

---

## The prompt

You are reviewing a Tier-1 specification amendment adversarially. Your mandate is
to find defects. A review that reports none is a valid outcome and is more useful
than one that manufactures findings to look thorough.

**The subject is the v0.14.0-draft amendment and nothing else.** In the attached
specification that is: `CON-202` (the key hierarchy), `REQ-213`, `REQ-217`,
`REQ-232`, `ADR-201`'s amended paragraph, `ADR-223`, `TEST-244`, `TEST-245`, the
`accountScopeLookup` member of `CON-201`, the *User restores* narrative, the
threat model's Protected assets / Trust boundaries / Explicit exclusions, and the
three new Tier-1 gate boxes. The attached diff shows exactly what moved. The rest
of this 6851-line document has had other passes; findings about it are out of
scope unless the amendment falsified them — in which case they are the most
valuable findings you can return.

### Seven things to know, because they change what counts as a defect

1. **The specification is authoritative, not the code.** This document's
   Amendment Channels say an implementation that already exists is an amendment
   *request*. Where the two disagree, the disagreement is the finding.

2. **The implementation has not been updated, deliberately.**
   `hierarchy.rs` is still at the version-1 salt and still roots at the BIP-39
   seed. That is known and recorded; "the code does not implement this" is not a
   finding. What *is* a finding: anything in the amendment that the attached
   custody could not implement, or that would require custody to hold something
   it is designed never to hold.

3. **There are no users and no deployed identities.** Backwards compatibility is
   explicitly not a requirement, and a finding premised on migrating existing
   accounts is out of scope. **Migration between future hierarchy versions is
   firmly in scope** — the amendment claims to preserve what a later migration
   would need, and that claim is worth attacking.

4. **The binding requirement is a restore flow**, stated by the specification's
   owner: recreate the root from the seed phrase on a fresh device holding
   nothing else; later authenticate to — or merely name — a service; and at that
   moment the account key is re-derived. A previous draft failed this and the
   failure was not obvious. Trace it yourself rather than trusting `TEST-245`.

5. **`0.14.0-draft` is deliberate.** The document states that it does not satisfy
   its own Amendment Channels because a key-derivation change requires new
   vectors and renewed sign-off *for the amendment*, and neither exists. The
   missing corpus is known. Do not spend findings on it.

6. **Fail-closed is the required posture.** A derivation path that proceeds on
   unknown, absent, or unverifiable input is a P1 whatever the surrounding prose
   says.

7. **Two counters named "version" appear in this document.** The *specification*
   version is 0.14.0-draft; the *hierarchy* version is 2. `CON-202` claims to
   disambiguate them. Whether it succeeds is itself reviewable.

### What to attack

These are prompts, not a checklist. A finding outside them is worth more than one
inside them.

1. **The sibling claim.** `CON-202` asserts `hierarchy_root` and SPEC-001's
   persona root are siblings under `bip39_seed`, that neither derives the other,
   and that this hierarchy therefore carries no key-separation obligation.
   Check the derivations against SPEC-001's own text. Is there any input, label
   collision, length coincidence, or shared-construction interaction that makes
   the two related? Is "no obligation" actually earned, or merely asserted?

2. **The restore flow, traced input by input.** Enumerate every value needed to
   derive one account's `home_signing_seed`. For each, say where a freshly
   restored wallet obtains it and cite the clause. A wallet that cannot complete
   this is a P1 and the amendment's whole purpose fails.

3. **"The scope confers no authority."** `REQ-217`'s `named` mode returns an
   account scope to any caller that names the account, and rests entirely on this
   claim. Attack it. What can a caller do with a scope it should not have?
   Consider: correlation, existence disclosure, enumeration, an attacker who
   *also* holds a recovery phrase, and an attacker who serves a wrong scope. Is
   denial of service really the worst outcome?

4. **Substitution detection and its blind spot.** `REQ-232` requires a wallet to
   recompute and compare the home DID *"before using a derived home key for an
   account it has seen before"*. Ask what happens when the wallet has **not**
   seen it before — first enrolment, and a restore onto an empty wallet. Is the
   check reachable in the case where a hostile `named` lookup would substitute?
   If not, what covers it, and does that thing actually run?

5. **Persona containment.** `REQ-232` forbids an application to store, request or
   transmit a persona index and requires a wallet to refuse one. Is that
   enforceable? Consider a protected backup written under one persona and
   restored under another, a wallet holding two personas, and whether any other
   attached clause lets a persona reach the derivation from outside.

6. **The blast-radius statement.** `ADR-223` consequence 1 and the threat
   model's Explicit exclusions claim a custody compromise now yields every
   application key under one persona where version 1 yielded none. Is that
   accurate, complete, and correctly signed? An earlier draft stated it
   backwards. Check both directions, and check whether any *other* compromise
   listed in the threat model changed and was not updated.

7. **Future migration.** `ADR-223` claims `REQ-232`'s per-account version record
   preserves what a version-3 migration would need, and concedes `CON-202`'s
   constant salt does not let one wallet derive under two versions. Given
   `CON-225` requires signatures from both the outgoing and incoming home keys,
   is the preserved state actually sufficient — or does the amendment claim a
   door is open that is not?

8. **Contradictions the amendment created.** It changed a hierarchy root in a
   6851-line document. Search for surviving statements it falsified —
   requirements, ADRs, tests, narrative, and the traceability table. Three such
   statements were found and repaired during drafting, which is evidence the
   class exists rather than evidence it is exhausted.

9. **`REQ-232` as a requirement.** Is it unambiguous, verifiable, atomic, and
   free of conflict with `REQ-217`, `REQ-231` and `CON-225`? An earlier draft of
   this requirement commanded behaviour that `CON-225` forbids.

### How to report

Findings only. No summary of what the amendment says, no restatement of what is
correct, no praise. For each finding:

- **Severity** — `P1` if it makes the restore flow fail, admits an unauthorised
  derivation, makes a stated security or privacy property false, or contradicts
  a normative clause; `P2` otherwise.
- **Location** — specification section, or file and line. **Cite only lines you
  can see in the attachments.** If you cannot cite it, say the claim is unlocated
  rather than guessing.
- **The defect**, in one or two sentences.
- **Why it is one** — the clause, requirement or stated property it violates.
- **A concrete failure**: inputs and state producing the wrong outcome. A finding
  you cannot make concrete is a suspicion; mark it as one and report it anyway.

Close with two lists, both of which matter as much as the findings: **what you
covered**, traced to the clauses you actually reasoned about, and **what you did
not** — a review discharges what it assessed and nothing else.

Do not propose repairs unless a finding is meaningless without one. What follows
from your findings is the specification owner's decision.
