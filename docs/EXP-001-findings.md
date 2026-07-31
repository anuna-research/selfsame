# EXP-001 — Findings

| Field | Value |
|---|---|
| id | EXP-001-findings |
| brief | [[EXP-001-spec-004-reference-implementation]] |
| conflict record | [[CONFLICT-001-spec-004-tier1-gate]] |
| status | complete — converged on the covered surface, blocked on the rest |
| date | 2026-07-31 |
| author | Claude Opus 5 (1M context), `claude-opus-5[1m]` |
| reviewer | **none** — see the Gate Evidence Record |

## Recommendation

The pure core of [[SPEC-004-application-scoped-identity]] is implementable from
the specification text. Fourteen of its twenty-six contracts are now implemented
and tested against the specification's own `TEST-2NN` criteria, with a published
conformance corpus. **Ten findings** are recorded below; two of them —
`FINDING-004` and `FINDING-005` — are defects in artefacts the specification
depends on rather than in the specification's prose, and one of those is a
security defect that the Tier-1 review should treat as blocking.

The specification is unusually implementable for its size. Where it was
ambiguous it was ambiguous in small, local ways, and in every case the
fail-closed reading was available. That is the substantive result: a 6,100-line
Tier-1 specification produced ten findings and no contradictions.

**Confidence:** high on the covered surface, and it is worth being precise about
why. Every obligation implemented here was read from the specification and
tested against the specification's own criteria, three hand-run mutants were
killed by the tests written for them, and the whole is 305 tests. But
Constitutional Principle 12 forbids this session from validating its own output,
so "high confidence" here means *the author believes it correct*, which the
protocol correctly treats as inadmissible evidence.

## What was implemented

| Contract | Module | Tests |
|---|---|---|
| `CON-201` application profile | `profile` | 35 (`TEST-203`) |
| `CON-202` key hierarchy | `hierarchy` | 14 (`TEST-201`, `TEST-202`, `TEST-222`) |
| `CON-203` account alias | `alias` | included below |
| `CON-204` reciprocal binding | `alias` | 24 (`TEST-204`–`206`, `TEST-225`) |
| `CON-205` device grant | `grant` | included below |
| `CON-206` acceptance predicate | `accept` | 28 (`TEST-207`–`212`) |
| `CON-207` device proof | `proof` | 15 (`TEST-209`, `TEST-210`) |
| `CON-208`/`209` selection and hint | `selection` | 7 (`TEST-214`, `TEST-215`) |
| `CON-210` revocation and projection | `revocation` | 16 (`TEST-213`, `TEST-240`) |
| `CON-211` account scope | `scope` | 8 (`TEST-223`) |
| `CON-212` human alias | `alias` | included above |
| `CON-214` enrollment evidence | `enrollment` | included below |
| `CON-215`/`219` ceremony payloads | `ceremony` | 25 (`TEST-228`, `231`, `236`) |
| `CON-220` profile discovery | `discovery` | 7 (`TEST-237`) |
| `CON-221` first-enrollment confirmation | `confirm` | 7 (`TEST-238`) |
| `CON-224` credential context | `context` | 8 (`TEST-241`) |
| `CON-225` identity succession | `succession` | 16 (`TEST-242`) |
| `CON-226` conformance corpus | `tests/con_226_corpus.rs` | 5 (`TEST-243`) |

Plus the shared primitives the contracts assume but do not name as contracts:
the one JSON recogniser and RFC 8785 canonicaliser, canonical base64url /
base32 / base58btc, the restricted HTTPS URI grammar, the `dateTimeStamp`
recogniser, the compact JWS layer, and `did:key`.

**305 tests, all passing. `cargo clippy --all-targets` clean. The purity gate
passes: no network-capable crate is in the dependency graph.**

## What was NOT implemented, and why

Stated plainly, because a completion report that omits this is the false
compliance [[PROTO-001-usdd-agent-protocol]] §Compliance Evidence measures.

| Not implemented | Why |
|---|---|
| `CON-213`, `CON-216`, `CON-217`, `CON-218` | Each is a *binding* to [[PROTO-003-selfsame-pairing-v1]] — SPAKE2, nameplates, role tokens, the `CON-409` record ladder. PROTO-003 is a separate specification with its own open Tier-1 gate and no implementation in this repository. Implementing the binding without the thing bound would produce a shape, not a contract. |
| `CON-222`, `CON-223` | Android and Apple platform adapters. These are native platform code — `PackageManager`, `PendingIntent` flags, `universalLinksOnly`, associated domains — and cannot be exercised meaningfully outside an integration harness with hostile sibling apps installed, which `TEST-239` correctly requires. |
| The effectful shell | HTTP profile fetch, WebFinger, provider probes, `did:crdt` state resolution and delta submission. Deliberately out of scope: the purity boundary is the point, and every one of these is injected as a parameter so the decision it feeds is tested without it. |
| `TEST-220`, `TEST-226`, `TEST-227`, `TEST-229`, `TEST-230`, `TEST-234`, `TEST-235`, `TEST-239` | Each requires two independently implemented provider stacks, a mobile integration harness, or an adversary with network control. They are gate items, not unit tests. |

The corpus's `CON-222`/`CON-223` groups are consequently absent rather than
stubbed. `CON-226` says cases outside group 3 "SHALL NOT be platform-conditional";
group 3 itself is platform-conditional by construction and is owed.

## Findings

### FINDING-001 — `CON-201`: "a non-empty absolute path" is not decidable as written

`applicationId` MUST "contain a non-empty absolute path". Whether
`https://photos.example/` satisfies that is not stated: the path is present and
absolute, and its single segment is empty.

**Taken as:** no. The path must contain at least one non-empty segment.
**Warrant:** `ADR-201` and `CON-220` both turn on one developer hosting several
security boundaries on one origin, and a bare `/` cannot distinguish them.
**Proposed resolution:** state it. "…a path of at least one non-empty segment."

### FINDING-002 — `CON-201`: empty path segments are unconstrained

Nothing forbids `https://photos.example/a//b` or a trailing `/`. Either gives one
application two spellings of its own identifier, which `REQ-202`'s exact-ASCII
comparison cannot survive.

**Taken as:** every `applicationId` segment must be non-empty. Provider URLs keep
the permissive rule, because `CON-201`'s own `credentialBaseUrl` example ends in
`/`.
**Proposed resolution:** add the rule to `applicationId`'s list, and say
explicitly that provider URLs are not subject to it.

### FINDING-003 — `dateTimeStamp` admits several spellings of one instant, and `CON-214` compares them as strings

`CON-205`, `CON-214`, `CON-219`, and `CON-225` all require XML Schema
`dateTimeStamp` normalised to UTC `Z`. XSD permits fractional seconds, so
`2026-07-30T10:00:00Z` and `2026-07-30T10:00:00.000Z` are both valid and denote
one instant. `CON-214` then requires each timestamp to be **exact-string equal**
to its counterpart in the offer.

An issuer emitting one form and a backend emitting the other would fail a check
meant to detect substitution.

**Taken as:** exactly one spelling — `YYYY-MM-DDTHH:MM:SSZ`, second resolution,
no fractional part.
**Proposed resolution:** fix the grammar in the specification. Comparing
timestamps semantically is the wrong fix: it would mean parsing before comparing,
at a trust boundary, ahead of the signature check.

### FINDING-004 — `CON-224` declares a `context_digest` for a file that was never published

`CON-224` states that the version 1 context is `contexts/device-grant-v1.jsonld`
in the `selfsame` repository, that it is **1,045 octets**, and that

```text
context_digest = 9dba4d065a9b7f54acbcfe8d75e1f2c8e7fe4ab8a4b87a4ad3f883c45a3d1183
```

That file did not exist in the repository. The digest is therefore unverifiable,
and no implementation can adopt it without asserting agreement with bytes nobody
can read.

**What was done:** the logical context `CON-205` prints was serialised in **RFC
8785 canonical form** — 794 octets, digest
`4f1eece1611f06657fca7d00c23e13e39431464c039861192e0ea1d05e5c1e20` — and shipped
as `contexts/device-grant-v1.jsonld`. Both digests are constants in `context.rs`
and a test asserts they still differ, so the day the real file arrives the test
fails loudly and in the right place.

**Proposed resolution:** publish the file, and **make it canonical**. Canonical
form is regenerable from the specification text alone, so a second implementation
can reproduce the octets and therefore the digest — which is what `NFR-202`
requires and what a pretty-printed file with an unstated indentation convention
can never provide. This is already a Tier-1 gate item; the recommendation is
about *which* bytes to publish.

### FINDING-005 — `CON-210`'s unauthenticated-write argument depends on a call the pinned method does not make by default

**This one is a security defect, and the review should treat it as blocking.**

`CON-210` permits an adopting application to accept `did:crdt` deltas at its own
endpoint, and argues it is safe because the operation is monotone: "A forged
delta fails the signature check, a replayed delta is idempotent, and the worst an
accepted delta can do is revoke."

At the pinned revision `adb5c7ac`, `Document::merge` **does not verify
signatures**. Its own documentation says so:

> Cryptographic signature verification is deferred to a later phase (see
> `core::validate`). Callers that operate in a trust boundary MUST call
> `validate::verify_signature` before calling this method.

`Document::merge_verified_delta` is the one that authenticates. So a replica
built on the obviously-named call admits a delta signed by **any** key, and
`CON-210`'s monotonicity argument silently stops holding — the worst an accepted
delta can do is no longer "revoke", because nothing established that the home
controller authored it.

This is demonstrated, not asserted:
`revocation::tests::the_non_verifying_merge_admits_a_forgery_that_the_verifying_one_refuses`
shows one forged delta admitted by `merge` and refused by `merge_verified_delta`.

**What was done:** `revocation::admit_revocation` wraps the verifying call, so the
correct one is the easy one, and the divergence is pinned as a test that will
fail when upstream closes it.

**Proposed resolution:** `CON-210` should name the **verifying entry point**, not
the operation. "A replica accepts the operation only after normal `did:crdt`
signature, authorization … checks" is true of the contract and not of the API a
reader will reach for. Consider also raising it upstream: an unauthenticated
`merge` beside an authenticated `merge_verified_delta` is a footgun whose safe
use depends on reading the doc comment.

### FINDING-006 — `CON-204` states no octet bound on the WebFinger response

Every other document in SPEC-004 has one: profiles at 65,536, grants at 65,536,
payloads at 69,607. A JRD is attacker-influenced input at a trust boundary and
has none.

**Taken as:** 65,536 octets, matching its neighbours.
**Proposed resolution:** state a bound in `CON-204`.

### FINDING-007 — percent-encoding canonicality is stated only for `applicationId`

`CON-201` requires RFC 3986 percent-encoding normalisation of `applicationId` —
unreserved characters decoded, hexadecimal upper-case — and says nothing about
provider URLs, permission URIs, or `kid` values, several of which are also
compared as exact strings or fed into digests.

**Taken as:** applied to every URL the recogniser accepts. No example anywhere in
SPEC-004 uses percent-encoding, so the stricter rule costs nothing today and
closes the same second-spelling hazard for descriptor digests.
**Proposed resolution:** hoist the rule to apply to every URL in the profile, or
say explicitly that it does not.

### FINDING-008 — one JWS recogniser cannot serve `CON-205` and `CON-214` without a parameter

`CON-206` step 3 requires "an absolute DID URL `kid`; reject remote key URLs". A
`CON-214` `kid` is an absolute **HTTPS** URI on the `applicationId` origin. Both
are correct — the two key sources differ — but an implementer sharing one
recogniser between them, which LangSec Principle 5 pushes toward, will find the
two rules contradict.

Neither is safe under the other's rule: accepting an HTTPS `kid` on a grant
reintroduces exactly the remote key URL step 3 forbids.

**Taken as:** a `KidRule` parameter on the shared policy, with a test asserting
neither shape is admitted under the other's rule.
**Proposed resolution:** note in `CON-214` that its `kid` shape deliberately
differs from `CON-205`'s, and why. A reader who spots only one of the two rules
will implement the wrong one.

### FINDING-009 — `enrollment.mobileBindings` optionality is unstated

`CON-201` requires `requestSigningKeys` to hold at least one entry and says of
`mobileBindings` only that "every entry has a unique `id`". `REQ-214` item 5
makes mobile bindings conditional on same-device support.

**Taken as:** optional; `enrollment` is closed at exactly those two members.
**Proposed resolution:** say so, since "an unknown member at any depth is a
rejection" makes the closed set load-bearing.

### FINDING-010 — `CON-206` step 10's resolver preference has no stated failure

Step 10 says the closure "SHALL be resolved from" a declared resolver at session
establishment "where any declared `stateResolvers` entry is reachable", and that
a verifier relying on the bundle "SHALL record that it did so". It does not say
what a verifier does when a resolver *was* reachable and it used the bundle
anyway — that is out of conformance, but no check fires.

**Taken as:** `Acceptance::used_bundle_closure` records it; acceptance is not
refused, because the core cannot know what the shell could have reached.
**Proposed resolution:** either make it an obligation on the shell with a named
observable (`OBS-###`), or state that the record is the whole control.

## Gate Evidence Record

Per [[PROTO-001-usdd-agent-protocol]] §Gate Evidence Record. `unverified` is a
legitimate value and is used honestly here.

```yaml
phase: 3
scope: EXP-001 governed prototype, not a Tier-1 gate closure
gates:
  - gate: "Tests derived from requirements (REQ → TEST)"
    mechanism: "cargo test -p selfsame-app-identity"
    result: pass
    evidence: "305 passed, 9 suites; every test file names the TEST-2NN it derives from"

  - gate: "Test-First / Red Gate"
    mechanism: "commit order for the json recogniser; mutation testing elsewhere"
    result: partial
    evidence: "tests/json_recogniser.rs was written and observed to fail before
      src/json.rs existed. For the rest, strict temporal enforcement was not
      practical in one session, so PROTO-001's named fallback applies: three
      hand-run mutants (freshness bound min→max, validity window >= → >,
      lifetime bound removed) were each killed by the test written for them.
      A full mutation run was NOT performed."

  - gate: "Purity: no I/O in the core"
    mechanism: "cargo test -p selfsame-app-identity --test purity"
    result: pass
    evidence: "4 tests: dependency-graph scan, source scan, no compiled-in
      Anuna/Selfsame endpoint, forbid(unsafe_code) present"

  - gate: "Architecture: no layer violations, arch-lint clean"
    mechanism: "cargo clippy -p selfsame-app-identity --all-targets"
    result: pass
    evidence: "no warnings"

  - gate: "Documentation: README exists; module docs cover every contract"
    mechanism: "crates/selfsame-app-identity/README.md; #![deny(missing_docs)]"
    result: pass
    evidence: "README present; the crate does not compile with an undocumented
      public item"

  - gate: "CON-226 corpus published and complete"
    mechanism: "cargo test -p selfsame-app-identity --test con_226_corpus"
    result: pass
    evidence: "test-vectors/spec-004-v1.json — 21,518 octets, 13 groups, 68
      cases, sha256 d407d2c3ff126e3f063011d3801a41ee0cda0f19f1a53b730ee4ca768d6d6941.
      The completeness rule is a test: every closed error token and each of
      CON-206's thirteen steps has a case."

  - gate: "Two independent implementations reproduce the normative vectors (NFR-202)"
    mechanism: "none available"
    result: unverified
    evidence: "this is the first implementation. The corpus exists so a second
      can be checked against it."
    owner: "the human owner"

  - gate: "Adversarial review (Constitutional Principle 12)"
    mechanism: "none run"
    result: unverified
    evidence: "no fresh-context review has seen this code. Principle 12 forbids
      the generating session from validating its own output, so every artefact
      here is unreviewed."
    owner: "the human owner"

  - gate: "Cross-model adversarial review (Tier 1)"
    mechanism: "none run"
    result: unverified
    evidence: "Tier-1 gate item, outstanding. SPEC-004 covers cryptography,
      authentication core, and privacy-sensitive transforms — all three
      PROTO-001 no-go areas."
    owner: "the human owner"

  - gate: "Human cryptography/security sign-off"
    mechanism: "none run"
    result: unverified
    evidence: "Tier-1 gate item, outstanding"
    owner: "the human owner"

  - gate: "Full contract coverage"
    mechanism: "inspection against SPEC-004 §Contracts"
    result: fail
    evidence: "CON-213, CON-216, CON-217, CON-218 depend on PROTO-003, which is
      unimplemented. CON-222, CON-223 are native platform adapters. See
      'What was NOT implemented' above."
    owner: "the human owner"
```

**No Tier-1 gate box was ticked by this work**, and
[[SPEC-004-application-scoped-identity]] remains `status: draft` with
`review-gate: not-approved`. This experiment produces evidence for the gate; it
is not a substitute for it.

## Process observations

Three, offered for Phase 4 rather than as findings against the specification.

- **Writing the recogniser first paid for itself repeatedly.** Six contracts
  declare closed languages with the same six obligations. Building one strict
  recogniser before any contract meant `CON-201`, `CON-205`, `CON-214`,
  `CON-215`, `CON-219`, and `CON-225` each cost a member list and a grammar
  rather than a parser.
- **The specification's habit of stating *why* a rule exists is what made it
  implementable.** `CON-219`'s explanation that `offerDigest` excludes two
  members because "a digest computed over an object containing itself has no
  fixed point" is the difference between transcribing a rule and knowing when a
  test is testing the right thing. Several findings above were only visible
  because the reasoning was on the page next to the rule.
- **Two findings came from reading dependencies rather than the specification.**
  `FINDING-004` and `FINDING-005` are both about artefacts SPEC-004 relies on —
  a file that was never published, and an API whose default is not the safe one.
  Neither is visible from the specification text alone, which is an argument for
  the Tier-1 gate's insistence on a reference implementation rather than review
  by inspection.
