# OQ-208 index design — cross-model review and its disposition

- **Artefact:** [[oq-208-account-index-design]] at `8e06ad7`.
- **Reviewer:** a different model family (Codex), fresh context.
- **Returned:** three P1 and one P2.
- **Disposition:** all four accepted. All four repaired in the design note; none
  required abandoning the design, but they change what it costs.

## The verdict in one line

> *"The proposed recovery design cannot reliably preserve independent
> application-account identities across concurrent creation, deletion, and
> account counts beyond its fixed scan window. Its new KDF input encoding is also
> underspecified."*

## What the three P1s have in common

Each is a consequence of removing the **coordinator**, and none of them was
visible while reasoning about the derivation in isolation.

```
  REQ-217 as it stands                 a derived index
  ────────────────────                 ───────────────
  one party allocates                  every wallet computes independently
    ├─ concurrency-safe   free           ├─ F1  needs arbitration
    ├─ never reassigned   free           ├─ F2  needs a non-withdrawal rule
    └─ unbounded count    free           └─ F3  needs a hard cap
```

Random allocation by a single coordinator supplies concurrency safety,
non-reuse, and an unbounded account count as properties of *being* a
coordinator. Trading it for derivability means buying each back explicitly. That
is the design's real price, and the note claimed a smaller specification without
counting it.

## F1 — P1 — concurrent creation of two *distinct* accounts

**Finding.** Two distinct authenticated accounts at one application, enrolled
concurrently from devices restored to the same phrase: both offers omit
`accountHomeDid`, both scan, both see `i = 0` free, both derive the same DID and
stable alias. [[SPEC-004-application-scoped-identity#CON-204]] *"SHALL reject an
alias already bound to another account or DID"*, so one creation fails — or the
two accounts share one identity, which
[[SPEC-004-application-scoped-identity#REQ-216]] forbids outright.

**Accepted, and the drafting error is worse than the finding states.** The note
asserted *"Concurrent creation converges rather than conflicting"* having
reasoned only about two devices creating **the same** account. The
different-accounts case was never enumerated. An earlier draft of this design
did carry an index negotiation, and it was removed on the strength of that
unexamined claim.

**Repair.** Arbitration at provisioning, using machinery that already exists.
The wallet scans, picks the lowest free index, and signs; the application
provisions under `CON-204` and refuses an index whose alias is already bound to a
different account, returning a defined token; the wallet increments and retries.
`CON-204` already specifies the failure path — *"SHALL return
`AccountProvisioningFailed`, SHALL NOT retry acceptance, and SHALL revoke the
exact grant ID"* — so a superseded grant does not linger.

## F2 — P1 — index reuse after deletion

**Finding.** A deleted account and a half-created account are both non-live to
the scan, and the rule forbidding durable gap bookkeeping leaves the wallet no
way to distinguish them. Reusing a half-created index therefore also reuses a
deleted account's index, recreating its DID, stable alias and authorisation
namespace for a different account — so a surviving pre-deletion grant reads as
valid for the new one.

**Accepted.** This is `REQ-217`'s *"a value SHALL never be reassigned to another
account"* — precisely the guarantee the design deletes. The note reasoned only
about half-created accounts.

**Repair, and it is smaller than the finding proposes.** The reviewer suggests a
tombstone; a non-withdrawal rule is enough and adds no new concept. Require the
account authority **not to withdraw the stable-alias JRD when an account is
deleted**. The two cases then separate cleanly on evidence the scan already
gathers:

| State | leg 1 — JRD | leg 2 — DID doc | scan reads | index |
|---|---|---|---|---|
| live | present | present | live | in use |
| deleted | **retained** | present | live | **burned, never reused** |
| half-created | absent | present | not live | free, reused — self-healing |

Deletion burns the index permanently, which is exactly the non-reuse property,
achieved by keeping a public record rather than a private one. No privacy is
lost: the JRD was already public, and retaining it discloses only that an
account existed, which it already disclosed.

The no-gap-bookkeeping rule survives unchanged. What was missing was not
bookkeeping but an obligation on the authority.

## F3 — P1 — accounts beyond the scan window

**Finding.** An account at index 16 is never queried, so a restore reports a
*complete* list while silently omitting it. `REQ-216` currently permits *"any
number"* of accounts, and the note explicitly said the ceiling is not
application policy — leaving the case allowed.

**Accepted, and it defeats the note's own rule 2.** That rule fails closed when a
scan cannot *complete*; here the scan completes and is simply too short. The
silent omission the rule exists to prevent arrives through the ceiling instead
of through a resolver outage.

**Repair.** `N` becomes a normative limit rather than a scan bound: at most 16
Selfsame-enabled accounts per `(person, application)`, enforced at creation with
a defined rejection, and `REQ-216`'s *"any number"* amended to match. This is a
product decision as much as a drafting one and is flagged as such — an
application needing more accounts than that cannot adopt the derived index.

## F4 — P2 — byte framing for the index KDF context

**Finding.** `CON-202` defines `LP(s)` over a Unicode string via UTF-8, and the
design supplies `U32BE(i)`, four raw octets, as the context. The exact HKDF
`info` bytes are therefore unspecified, leaving each implementation to pick a
conversion.

**Accepted.** This is the cross-implementation divergence `LP`'s injectivity
argument exists to prevent, reintroduced by the one line that added a non-string
context.

**Repair.** Broaden `LP` to octet strings — `LP(b) = U32BE(len(b)) || b`, with
`LP(s)` for a Unicode string defined as `LP(UTF8(s))`. Broadening preserves the
injectivity argument unchanged and avoids a second operator; the alternative,
adding `LPB`, would leave two length-prefix operators to confuse.

## What the repairs cost

Restored or added: arbitration with a retry at creation, a non-withdrawal
obligation on the authority, a normative 16-account cap, and one definitional
broadening.

Still deleted: `CON-211`, most of `REQ-217`, `AccountScopeUnavailable`, and the
"protected Selfsame recovery backup" that is defined nowhere in this vault.

The design remains a net simplification, but by less than the note claimed, and
the comparison with the authenticated-lookup alternative moves accordingly —
that design keeps the coordinator and so raises none of F1, F2 or F3. It is
recorded in [[oq-208-account-index-design]] as the alternative to reopen if the
16-account cap is unacceptable.

## Standing

This round assessed `8e06ad7`; the repairs are in the design note after it, so
**what the reviewer assessed is no longer what is there**. A further round is
needed before any of it reaches [[SPEC-004-application-scoped-identity]]. F1 and
F2 are where a further error is most likely: both are new text written in
response to a finding, and both concern failure modes the drafting session had
already reasoned about incorrectly once.
