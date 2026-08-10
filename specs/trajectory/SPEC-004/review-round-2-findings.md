# SPEC-004 v0.14.0-draft — round 2, and why most of the amendment was withdrawn

- **Artefact:** [[SPEC-004-application-scoped-identity]] at `b45b08b`, i.e. the
  text produced by round 1's repairs ([[review-disposition-0.14.0-draft]]).
- **Reviewers:** three fresh-context passes with deliberately different lenses —
  (A) attack the two repairs, (B) trace the restore flow end to end, (C) sweep
  the whole 6,851-line document for contradictions and privacy regressions.
  Same model family as the drafting session, so **this round discharges no
  Tier-1 gate box**; it was run to find defects, not for the record.
- **Returned:** roughly two dozen P1 findings, heavily overlapping.
- **Outcome:** `89ec39f` — `REQ-232`, the `named` lookup mode, `CON-201`'s
  `accountScopeLookup` member and `TEST-245` withdrawn entirely. The re-root
  survives.

## The two structural findings

Everything else followed from these.

### `REQ-232` mandated a value no defined wire could carry

The requirement had the application return the hierarchy version "by the same
mechanism as the scope". The mechanism that actually delivers an
`accountScopeId` to a wallet is [[SPEC-004-application-scoped-identity#CON-219]]'s
offer payload plus [[SPEC-004-application-scoped-identity#CON-214]]'s enrollment
evidence — and both are **closed member sets**: *"The member set is exactly those
fifteen names"*, *"rejects duplicate members, unknown members"*. The return path
is worse: the bundle payload is *"exactly those seven names"* and is forbidden
from carrying the scope at all.

So a conforming wallet reaches `CON-202` with no version, and `REQ-232` forbade
assuming one. **Every ceremony would have failed closed, not only restores.**
Adding the field breaks `CON-214` recognition and the `offerDigest`.

The previous changelog stated *"`CON-206` and every credential, wire and ceremony
format are untouched"* as a reassurance. It was the defect statement.

Two consequences of the same class: at first enablement no record exists yet, so
`REQ-232`'s unqualified fail-closed rule meant an account could never be created;
and the persona index it required had no source on a wallet restored from twelve
words, so every implementation would have hardcoded `0` — the exact "assume the
constant your code implements" behaviour the requirement forbade one paragraph
earlier for the sibling input.

### `named` collided with the privacy architecture at every point it touched

- [[SPEC-004-application-scoped-identity#CON-211]], the contract that *implements*
  `REQ-217`: *"Providers and public protocols receive the resulting DID, alias,
  or credential identifiers, **never the scope itself**."* `named` published it.
- `REQ-217`'s own publication prohibition, 63 lines below the mode that violates
  it, forbids the scope in *"any other public protocol artifact"* — and names a
  WebFinger response, the directly analogous unauthenticated lookup at the same
  authority.
- [[SPEC-004-application-scoped-identity#REQ-218]] guarantees that a person who
  *declines* a username "retains the complete linking, authorization, revocation,
  and **recovery** functionality". `named` made the username the sole recovery
  selector.
- [[SPEC-004-application-scoped-identity#CON-212]] lets a person **remove** a
  username, or rename it with the old one permanently tombstoned — destroying
  that selector years later, through a flow the happy path presents as cosmetic.
- The mode defined **no wire at all**: no endpoint, request or response grammar,
  media type, TLS requirement, error tokens, or rate bound. Every other
  cross-party operation in this document is specified byte-exactly.
- Composed with what is already public, it yielded an anonymous enumerable chain:
  handle → scope and version → WebFinger → home DID →
  [[SPEC-004-application-scoped-identity#CON-203]] offline → resolve → that
  account's revocation history.

## One finding the owner rejected, correctly

Pass (A) and pass (C) both raised, as P1, that a `named` account has no selector
in the window between account creation and username provisioning.

**Rejected on review by the owner.** An account in that window contains nothing;
recovery means restoring what has accumulated, and nothing has. Under `REQ-217`'s
own rule a conforming application obtains the alias during account creation, so
the window is one signup flow. The finding was the transient and weakest instance
of a concern whose durable forms — `REQ-218`'s declining person, `CON-212`'s
removal and rename — stand on their own and did the actual work of withdrawing
the mode.

Recorded because it is the one place this round overstated, and because the
distinction between a transient and a durable instance of one concern is worth
keeping.

## What the tests could not have caught

Pass (B) read `TEST-245` last, deliberately, and found it blind to every finding
above. Several clauses could not fail at all: the sibling-root check compared a
64-octet value against a 32-octet one; the resolver-independence control was
inverted, so a version-guessing implementation with no reachable resolver behaves
identically to a conforming one; the persona-positive clause asserted that a
fixture the tester wrote omits a field it never contained. `TEST-244`'s surviving
clauses were repaired in `89ec39f`.

## Process observations

**The defect class repeated three times.** Version in wallet-local state,
destroyed by the restore it was written for. Moved to the account record, which
reaches the wallet over closed grammars. `named` invented to reach that record,
with no contract. Each fix relocated the problem, because none of them traced
whether the value could reach where it was needed.

**Withholding prior findings worked.** Round 2's passes were given the current
text and no list. They found a defect class round 1 had not — a mandated value
with no wire — which a re-audit of round 1's five findings would likely have
missed.

**Differentiated lenses paid.** The three passes overlapped heavily on `named`
but each found something the others did not: (A) the `CON-211` contradiction, (B)
the missing wire carrier, (C) the changelog asserting a repair that was never
made and the Orientation diagram falsified three lines from an edit.

**A changelog claimed work that had not been done.** The `b45b08b` entry listed
"Protected assets" among the threat-model sections amended; no diff hunk reached
it, and it still described the scope as private. That is the failure mode a
changelog exists to prevent.

## What survives, and what is open

Surviving: `CON-202`'s re-root, `ADR-223`, `REQ-213`, `TEST-244`, the
threat-model widening, `ADR-201`'s amendment. Round 1 and round 2 both assessed
the re-root and neither faulted it.

Open: [[SPEC-004-application-scoped-identity#OQ-208]] — an application whose only
account credential is the Selfsame identity still cannot authenticate a
just-restored wallet, so `REQ-217`'s carrier does not reach it. The OQ records
the shape a resolution probably takes and insists it arrive with a contract.

Still required before the version stops being `-draft`: regenerated `CON-226`
vectors with their SHA-256 recorded, a cross-model round against the reduced
text, and owner sign-off on the widened at-rest asset.
