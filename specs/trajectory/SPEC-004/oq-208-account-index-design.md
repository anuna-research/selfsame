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
account_node = KDF(application_node, "account", U32BE(i), 64)      i = 0, 1, 2 …
```

`accountScopeId` is deleted. The index never leaves the wallet.

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

1. **Scan the whole window, never stop at the first miss.** Accounts can sit at
   `{0, 2}`. `N` is a **specification constant, 16** — not a profile value: it
   bounds wallet scan cost, not application policy, and a profile member would be
   a `profileVersion` bump for nothing.
2. **Fail closed on the whole scan.** If any index cannot be checked — a resolver
   down, a leg unreachable — return *incomplete* and **no list**. Never a partial
   list. A scan that silently omits an account whose resolver was down, and
   reports success, is the silent orphan this entire line of work exists to
   prevent.
3. **No gap bookkeeping.** The window scan is the only mechanism. A recorded gap
   is wallet-local state, and a restore destroys wallet-local state — the exact
   error the withdrawn `REQ-232` made.
4. **A wallet with local state trusts it, but re-scans on restore and on any
   refusal of a presented key.** Self-correcting without being chatty.

### Concurrent creation converges rather than conflicting

Two devices creating "a new account" both derive `i = 0` from the same phrase and
`applicationId`, so both produce the **same** home DID. That is idempotent, not a
collision, and the index negotiation an earlier draft of this note called for is
unnecessary.

A half-created account — DID published, application binding never written —
fails `CON-204`'s second leg and reads as not-live, so the next creation reuses
that index. The failure mode is self-healing.

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
  └─ REQ-233                    the ceiling N and the never-stop-at-first-miss rule
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

Specifically not yet done: no adversarial review, and no cross-model round. The
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
