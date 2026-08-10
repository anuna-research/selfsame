# OQ-208 — replace the account scope with a derived index: a worked design

- **Answers:** [[SPEC-004-application-scoped-identity#OQ-208]] — how does an
  application whose only account credential is the Selfsame identity return an
  account scope to a wallet that has just restored and holds no key?
- **Status:** design note. **Nothing here has been applied to
  [[SPEC-004-application-scoped-identity]], and nothing here has been reviewed.**
- **Answer in one line:** it doesn't have to, because the scope stops existing.

## Why this is not the design I started with

Two earlier shapes were worked and discarded, and both failures had one cause.

*An unauthenticated `named` lookup* keyed on the account's human-readable alias
was written into 0.14.0 and withdrawn — it published a value
[[SPEC-004-application-scoped-identity#CON-211]] forbids over a public protocol,
made mandatory a username [[SPEC-004-application-scoped-identity#REQ-218]]
guarantees is optional, and defined no wire.

*An authenticated lookup endpoint* keyed on a signature over `application_node`
fixed the privacy problems and still needed the application to hold a value only
the wallet can compute — with no wire in that direction to carry it, and, unlike
the home DID, no existing field it could ride inside.

**The cause both times was adding a requirement without checking which defined
wire carries its values, in which direction.** That check is run first here, and
its table is the substance of this note.

## What the account scope was actually for

Worth stating because the intuition is usually wrong — including mine.
[[SPEC-004-application-scoped-identity#REQ-217]] is explicit that the scope
*defeats* deterministic recovery rather than enabling it:

> *"The mnemonic and `applicationId` alone **cannot** identify one of several
> account children."*

Its whole second half is machinery to work around that — the account record, the
protected backup, `AccountScopeUnavailable`.
[[SPEC-004-application-scoped-identity#ADR-210]] gives the real purpose:

> *"The random scope is not intended to strengthen the recovery secret. Its
> purpose is stable, opaque child selection."*

Three jobs, none of them recovery:

| Job | Needs randomness? |
|---|---|
| **Child selection** — several accounts at one application, unlinkable | no — needs distinctness |
| **Indexing** — `REQ-216` keys keys, DIDs, aliases, grants, state, revocation and projections by `(applicationId, accountScopeId)` | no — needs stability |
| **Opacity** — reveals nothing, cannot be guessed | yes |

And it is explicitly *not* a secret: `REQ-217` — *"not a password or source of
cryptographic entropy."*

## The proposal

```text
LP(b) = U32BE(len(b)) || b                      ; b is an octet string
LP(s) = LP(UTF8(s))                             ; for a Unicode string

account_node = KDF(application_node, "account", U32BE(i), 64)      i = 0, 1, 2 …

  where the HKDF info is exactly  LP("account") || LP(U32BE(i))
                                = 00 00 00 07 "account" 00 00 00 04 <4 octets>
```

`accountScopeId` is deleted. The index never leaves the wallet.

`CON-202` today defines `LP` over Unicode strings only, so a four-octet index has
no defined framing and each implementation would pick its own — the exact
divergence `LP`'s injectivity argument exists to prevent. **Broadening `LP` to
octet strings** fixes it without adding a second operator, and the injectivity
argument carries over unchanged: the leading length still fixes how many octets
follow, so no two distinct `(label, context)` pairs encode alike.

**Removing the random value is a privacy gain, not a loss.** A 32-octet random
that `REQ-217` must forbid from DIDs, logs, JRDs, hints and analytics is a
*strong correlator* — that prohibition list exists because one leak links
everything it touches. An index links nothing: everyone's first account is `0`.
And low entropy costs nothing here, because walking indices requires
`application_node`, which requires the recovery secret; an outsider cannot, and
the application already knows how many accounts you hold with it.

## The carriage table — run before writing, not after

For every value this design moves: which defined wire carries it, in which
direction, and what changes.

| Value | Direction | Carrier today | Carrier under this design | Change |
|---|---|---|---|---|
| `accountScopeId` | app → wallet | `CON-219` offer, 1 of 15 closed names | **none — deleted** | `CON-219` member removed |
| account index `i` | — | — | **never leaves the wallet** | none |
| which account this ceremony is for | app → wallet | implied by `accountScopeId` | `accountHomeDid`, OPTIONAL — absent means *create a new account* | `CON-219` member added; `issuerClosure` is the precedent that an OPTIONAL member is representable here |
| which account was created | wallet → app | `grant.issuer` (`CON-205`) | **unchanged** — already the home DID | none |
| enrollment signature coverage | app backend | `offer_core`, 13 members incl. the scope | `offer_core`, 13 members incl. the OPTIONAL DID | `CON-214` signs different bytes; `payloadVersion` → 2 |
| index refusal at creation | app → wallet | — | `CON-204` failure path, new token `AccountIndexTaken` | one closed error token; the failure path itself already exists |
| account liveness, leg 1 | wallet ↔ authority | — | `CON-204` WebFinger | none — existing contract |
| account liveness, leg 2 | wallet ↔ resolver | — | DID resolution at `stateResolvers` | none — existing, but see the dependency below |

**Nothing new travels wallet → application.** That is the property both earlier
designs lacked, and it holds here because `ADR-202` already makes the home DID
the credential issuer, so the wallet has always told the application which
account it created.

## Recovery

Existing contracts, composed. The application does not participate.

```text
  for i in 0 .. N-1:
      account_node_i = KDF(application_node, "account", U32BE(i), 64)     CON-202
      home_did_i     = did:crdt genesis over the derived Ed25519 key      CON-202
      acct_uri_i     = "acct:ss-" BASE32LOWER(SHA-256(home_did_i)) "@" a  CON-203
      live_i         = both CON-204 legs agree:
                         authority JRD subject == acct_uri_i
                              and aliases contains home_did_i
                         DID document alsoKnownAs contains acct_uri_i
```

Both legs are public and unauthenticated, which is why this works with no
credential: the wallet is not asking permission, it is checking a binding two
independent parties already published. `accountAuthority` comes from the
embedded profile ([[SPEC-004-application-scoped-identity#ADR-008]]).

The wallet recovers **keys, not names** — it holds two opaque DIDs and does not
know which is "work". It presents them; the application matches them to records
it already holds and labels them in its own switcher. That is `ADR-210`
unchanged.

### Four rules

1. **Scan the whole window, never stop at the first miss** — and the window is a
   **normative limit, not merely a scan bound**. Accounts can sit at `{0, 2}`.
   `N = 16` is a specification constant, and an application SHALL refuse to
   create a seventeenth Selfsame-enabled account for one person, with a defined
   rejection; [[SPEC-004-application-scoped-identity#REQ-216]]'s *"any number of
   authenticated application accounts"* is amended to match.

   Stating it only as a scan bound is not enough, and rule 2 does not cover the
   gap: an account at index 16 makes a scan **complete** while silently omitting
   it, so the fail-closed rule never fires. That is the silent omission this
   design exists to prevent, arriving through the ceiling instead of through an
   outage.

   This is a product decision as much as a drafting one. An application that
   needs more than sixteen accounts per person cannot adopt the derived index,
   and should use the authenticated-lookup alternative, which keeps the
   coordinator and has no such limit.
2. **Fail closed on the whole scan.** If any index cannot be checked — a resolver
   down, a leg unreachable — return *incomplete* and **no list**. Never a partial
   list. A scan that silently omits an account whose resolver was down, and
   reports success, is the silent orphan this entire line of work exists to
   prevent.
3. **No gap bookkeeping — but the authority never withdraws a stable-alias JRD.**
   The window scan stays the only wallet-side mechanism, because a recorded gap
   is wallet-local state and a restore destroys wallet-local state, which is the
   error the withdrawn `REQ-232` made. What the scan needs instead is that a
   **deleted** account stays distinguishable from a **half-created** one, and an
   obligation on the authority supplies it at no wallet cost:

   | State | leg 1 — JRD | leg 2 — DID doc | scan reads | index |
   |---|---|---|---|---|
   | live | present | present | live | in use |
   | deleted | **retained** | present | live | **burned, never reused** |
   | half-created | absent | present | not live | free — reused, self-healing |

   Retaining the JRD after deletion burns that index permanently, which is
   exactly `REQ-217`'s *"a value SHALL never be reassigned to another account"*
   achieved through a public record rather than a private one. Without it, a
   deleted account's index is indistinguishable from a free one, and reusing it
   recreates that account's DID, alias and authorisation namespace — so a
   surviving pre-deletion grant would read as valid for the new account.

   No privacy is lost: the JRD was already public, and retaining it discloses
   only that an account existed, which it already disclosed.
4. **A wallet with local state trusts it, but re-scans on restore and on any
   refusal of a presented key.** Self-correcting without being chatty.

### Concurrent creation needs arbitration

An earlier draft of this note claimed concurrent creation *"converges rather than
conflicting"*. That is true only when both devices are creating **the same**
account. For two **distinct** accounts at one application — work and personal,
enrolled concurrently from devices restored to the same phrase — both scans see
`i = 0` free and both derive the same DID and stable alias.
[[SPEC-004-application-scoped-identity#CON-204]] *"SHALL reject an alias already
bound to another account or DID"*, so one creation fails, or the two accounts
share one identity, which [[SPEC-004-application-scoped-identity#REQ-216]]
forbids.

**Arbitration happens at provisioning, using machinery that already exists.**

```text
  wallet   scan → lowest free i → derive → sign grant → bundle
  app      CON-204 provisioning:
             alias already bound to a DIFFERENT account?
               yes → refuse: AccountIndexTaken
                     (CON-204 already revokes the grant on a provisioning failure)
               no  → provision, publish the JRD, then CON-206
  wallet   on AccountIndexTaken: i ← i+1, re-derive, re-sign, retry
```

The application is the arbiter because it is the only party that sees both
creations. It cannot *propose* an index — the index space is wallet-internal and
it has no view of it — but it can refuse one, which is all arbitration requires.

`CON-204` already specifies the failure path: *"SHALL return
`AccountProvisioningFailed`, SHALL NOT retry acceptance, and SHALL revoke the
exact grant ID"* — so a superseded grant does not linger. The retry is bounded
by the ceiling below.

## Footprint

A large diff, and a **smaller specification**. Most of it is deletion.

```text
  DELETED
  ├─ CON-211                    the account-scope contract
  ├─ most of REQ-217            allocation, immutability, carrier rules,
  │                             the publication prohibition, AccountScopeUnavailable
  ├─ "protected Selfsame        a carrier named in four normative clauses which
  │   recovery backup"          round 2 found is defined nowhere in this vault
  └─ the recovery apparatus     recovery is enumeration now

  AMENDED
  ├─ CON-202                    account_node takes U32BE(i)
  ├─ CON-219 / CON-214          one member swapped; offer_core reshapes; payloadVersion → 2
  ├─ REQ-215, REQ-216           rekey on (applicationId, home DID)
  ├─ ADR-210                    the child selector is a derived index
  ├─ CON-209, CON-201, NFR-203, CON-212   prohibitions that reference the scope
  └─ NFR-201, OQ-203            mention scopes

  NEW
  ├─ CON-227                    the recovery scan: window, both legs, partial-result rule
  ├─ REQ-233                    the ceiling N as a normative account limit, the
  │                             never-stop-at-first-miss rule, and the creation refusal
  └─ AccountIndexTaken          one closed error token on CON-204's existing failure path

  ADDED BY THE CROSS-MODEL REVIEW (see [[oq-208-review-disposition]])
  ├─ CON-204                    SHALL NOT withdraw a stable-alias JRD on account deletion
  ├─ CON-202                    LP broadened to octet strings
  └─ REQ-216                    "any number of accounts" → at most 16 per person
```

## Two things to amend deliberately, not argue around

**`REQ-216`**: *"The person SHALL NOT type, copy, scan, remember, or choose an
account scope **or derivation index**."* This design uses a derivation index. In
letter it is compatible — the prohibition is on *the person* choosing, and here
the wallet derives it and the person never sees it. But this is the second place
the specification rejects an index (`ADR-210` is the first), which says its real
intent is *no person-visible index*, an intent this honours. Amend it explicitly
or a reviewer lands there and is right to.

**`ADR-210`** rejects *"a user-selected index … because it requires configuration
and is not reliably recoverable."* Both objections are about a person supplying
and reproducing a value. Neither reaches a wallet-derived index. Say so in the
ADR rather than leaving the contradiction standing.

## Dependency this does not remove

`CON-204`'s second leg needs a conforming `stateResolvers` entry, and none is
deployed — the `G6` gap in [[selfsame-path-b-readiness-2026-08-10]]. Every design
considered for `OQ-208` inherits this, because anything that validates a derived
identity ends up resolving its DID.

## Standing

This is the **fourth** design for this problem in one working session. The three
before it each looked clean until reviewed, and two were withdrawn after landing
in a specification. Nothing here should be trusted on the strength of the
argument above.

**One cross-model round has been run** against `8e06ad7`, returning three P1 and
one P2 — all accepted, all repaired above, and dispositioned in
[[oq-208-review-disposition]]. Its finding was structural: every P1 was a
consequence of removing the coordinator, and the repairs buy back what a
coordinator supplies for free — arbitration, non-reuse, and an unbounded account
count, of which the last is now capped rather than bought. **What that round
assessed is therefore no longer what is here.**

Specifically not yet done: no further round against the repairs, and no
Anthropic-family pass since. The
carriage table is checked against `CON-204`, `CON-205`, `CON-206`, `CON-214` and
`CON-219`, but **not** against PROTO-002/003/004, which own the envelopes these
payloads travel inside — an `accountScopeId` consumer hiding in one of those
would change the table.

### The check that would have unwound this, run

The claim the whole design rests on is *the application never needs the scope*.
The place that would falsify it is the acceptance predicate, so it was traced
rather than assumed:

- **`CON-206` mentions the account scope zero times.** The thirteen-step verifier
  never sees it. Its step 9 checks the reciprocal binding using the `acct:` URI,
  which [[SPEC-004-application-scoped-identity#CON-203]] derives from the home
  DID — not from the scope.
- **`CON-205`'s single mention is a prohibition**, not a use: `grant_token` *"is
  never derived from a device key, account scope, timestamp, provider
  allocation, or recovery material."*
- **`REQ-217` already forbids the scope from the credential**: *"SHALL NOT appear
  in a DID, DID Document, `acct:` URI, VC, JWS header, WebFinger response …"*

So the scope is structurally excluded from every artefact a verifier handles.
The only application-side consumers are `REQ-216`'s internal indexing and
`CON-214`'s signature coverage, and the carriage table replaces both.

This strengthens the design rather than unwinding it — but it is one check by
the session that proposed the design, which is exactly the evidence
Constitutional Principle 12 says does not count.
