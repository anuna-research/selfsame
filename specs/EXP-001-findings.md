# EXP-001 — Findings

| Field | Value |
|---|---|
| id | EXP-001-findings |
| brief | [[EXP-001-spec-004-reference-implementation]] |
| conflict record | [[CONFLICT-001-spec-004-tier1-gate]] |
| status | complete — all 26 contracts implemented; primitives and FFI remain |
| date | 2026-07-31 |
| author | Claude Opus 5 (1M context), `claude-opus-5[1m]` |
| reviewer | **none** — see the Gate Evidence Record |

## Recommendation

The pure core of [[SPEC-004-application-scoped-identity]] is implementable from
the specification text. **All twenty-six contracts** are now implemented and
tested against the specification's own `TEST-2NN` criteria, with a published
conformance corpus. **Fourteen findings** are recorded below. Three deserve a
reviewer's attention ahead of the rest: `FINDING-005` is a security defect in a
pinned dependency, `FINDING-004` is an unpublishable digest, and `FINDING-013` is
a contradiction between two contracts whose failure mode is that an implementer
manufactures the evidence one of them forbids. `FINDING-014` is the largest in
scope — the specification defines no observability signals at all — and
[[EXP-001-proposed-obs]] drafts the set it needs.

The specification is unusually implementable for its size. Where it was
ambiguous it was ambiguous in small, local ways, and in every case the
fail-closed reading was available. That is the substantive result: a 6,100-line
Tier-1 specification governing cryptography, authorization, and revocation
produced fourteen findings, of which exactly one — `FINDING-013` — is an
internal contradiction rather than an underspecification or an omission.

**Confidence:** high on the covered surface, and it is worth being precise about
why. Every obligation implemented here was read from the specification and
tested against the specification's own criteria, seven hand-run mutants were
killed by the tests written for them, and the whole is 386 tests. But
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
| `CON-213` protocol binding | `pairing` | included below |
| `CON-214` enrollment evidence | `enrollment` | included below |
| `CON-215`/`219` ceremony payloads | `ceremony` | 25 (`TEST-228`, `231`, `236`) |
| `CON-216` bootstrap obligations | `pairing` | included below |
| `CON-217` PAKE composition | `pairing` | included below |
| `CON-218` downgrade closure | `pairing` | 18 (`TEST-229`, `232`, `233`, `235`) |
| `CON-220` profile discovery | `discovery` | 7 (`TEST-237`) |
| `CON-221` first-enrollment confirmation | `confirm` | 7 (`TEST-238`) |
| `CON-222` Android binding | `platform` | included below |
| `CON-223` Apple binding | `platform` | 15 (`TEST-230`, `TEST-239`) |
| `CON-224` credential context | `context` | 8 (`TEST-241`) |
| `CON-225` identity succession | `succession` | 16 (`TEST-242`) |
| `CON-226` conformance corpus | `tests/con_226_corpus.rs` | 5 (`TEST-243`) |

Plus the shared primitives the contracts assume but do not name as contracts:
the one JSON recogniser and RFC 8785 canonicaliser, canonical base64url /
base32 / base58btc, the restricted HTTPS URI grammar, the `dateTimeStamp`
recogniser, the compact JWS layer, and `did:key`.

**395 tests in the core, 565 across the workspace, all passing. `cargo clippy --all-targets` clean. The purity gate
passes: no network-capable crate is in the dependency graph.**

Every `REQ-###`, `NFR-###`, and `CON-###` the specification defines is cited by
name in the implementation or its tests, and 41 of 43 `TEST-2NN` are covered at
least in part. The two that are not — `TEST-220`'s live third-party flow and
`TEST-234`'s many-application spoken routing — need provider stacks that do not
exist yet.

## What was NOT implemented, and why

Stated plainly, because a completion report that omits this is the false
compliance [[PROTO-001-usdd-agent-protocol]] §Compliance Evidence measures.

All twenty-six contracts now have an implementation. What remains unimplemented
is **primitives and FFI**, not contracts — and the distinction matters, because
every obligation the six late contracts state turns out to be about ordering,
binding, and closure rather than about the primitive underneath.

| Not implemented | Why |
|---|---|
| PROTO-003's SPAKE2 (`CON-403`–`CON-408`) | The password mapping, the two messages, the confirmation MACs, and the derivation of `mailbox_secret_16` from the PAKE key. A separate specification with its own open Tier-1 gate. `pairing` takes a [`Confirmation`] carrying the role it was made for and the `binding_hash` it covers, which is everything `CON-213`/`216`/`217`/`218` actually ask about — swapping in a real SPAKE2 changes what *produces* one, not what may be done once one exists. |
| PROTO-002's mailbox HTTP and PROTO-004's AEAD envelope | Likewise separate specifications. `CON-213`'s transport policy is implemented as a response predicate; the requests are the shell's. |
| Android and Apple **FFI** | `PackageManager`, `PendingIntent`, `UIApplication.open`, associated domains. `CON-222`/`CON-223`'s *policy* — binding grammars, caller-identity comparison, dispatch flags, the return-path origin rule, the API-30 floor — is implemented and tested; the native calls are not, and cannot be outside the harness `TEST-239` requires. |
| The effectful shell | HTTP profile fetch, WebFinger, provider probes, `did:crdt` state resolution and delta submission. Deliberately out of scope: the purity boundary is the point, and every one of these is injected as a parameter so the decision it feeds is tested without it. |
| `TEST-220`, `TEST-226`, `TEST-227`, `TEST-234`, `TEST-239` | Each requires two independently implemented provider stacks, a mobile integration harness, or an adversary with network control. They are gate items, not unit tests. `TEST-229`, `TEST-230`, `TEST-233` and `TEST-235` are now partly covered: their state-machine and closure obligations are tested, their network and platform halves are not. |

The corpus carries `CON-222`/`CON-223` as group 3, which `CON-226` permits to be
platform-conditional. Every other group is platform-neutral, as it requires.

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

### FINDING-011 — `REQ-229` bounds initiator confirmations but does not say what a second one does

> The wallet SHALL evaluate at most one initiator confirmation per minted
> ceremony.

The bound is clear; the consequence of exceeding it is not. Two readings are
available — ignore the second confirmation, or burn the ceremony — and they
differ materially. Ignoring it leaves the ceremony live for a peer that has just
demonstrated it will retry, which is an attacker with more than one guess at a
128-bit code delivered over a human channel.

**Taken as:** burn. `CON-218` says "Every condition enumerated by … `REQ-229`
moves the local ceremony directly to terminal `burned`", and a second initiator
confirmation is a condition `REQ-229` enumerates.
**Proposed resolution:** say so in `REQ-229`. The inference is available but it
requires reading two contracts together, and the fail-open reading is the one an
implementer reaches for first because it is less disruptive.

### FINDING-012 — `CON-222` compares a calling package to a `platformBindingId`, which is a different shape

> The wallet obtains the calling package … and compares it to the
> `platformBindingId` in the `CON-214` evidence.

A calling package is `com.example.photos`. A `platformBindingId` is
`android:com.example.photos:<cert-sha256>`. They are not comparable as written,
so a literal implementation either always fails or does an undeclared substring
match — and an undeclared substring match over an identifier that contains a
package name is exactly the kind of comparison that admits
`com.example.photos.evil`.

**Taken as:** compare against the binding's `packageName` member, having
resolved the binding from the authenticated profile by its `platformBindingId`.
**Proposed resolution:** state the comparison precisely. "…resolves the binding
named by `platformBindingId` in the authenticated profile and compares the
calling package to that binding's `packageName`, as exact ASCII."

### FINDING-013 — `CON-215` requires of every adapter something `CON-223` says Apple cannot provide

`CON-215` sets the bar for a future adapter:

> A future adapter must provide equivalent installed-target authentication,
> no-network-fallback behavior, one-shot delivery, and **a caller-binding signal
> for `CON-214`**.

`CON-223` then records that one of the two adapters the specification itself
defines cannot meet the last clause:

> Apple provides no general equivalent of Android's calling-package attribution
> for a Universal Link open.

So as literally written, the Apple adapter fails the equivalence bar the
specification sets for adapters. The intent is plainly that three properties are
universal and the fourth is provided where the platform can, with the residual
gap closed by the `CON-214` signature and `CON-221` confirmation — `CON-223` says
exactly that — but `CON-215` does not carry the qualification.

**Taken as:** the four universal properties are required of every adapter; the
caller-binding signal is required only where the platform provides one.
`AdapterConformance::is_conformant` is parameterised by platform for this reason,
and a test asserts that Apple's policy conforms on Apple and does **not** conform
on Android — because Android provides the signal, so omitting it there is a
choice rather than a platform limit.
**Proposed resolution:** qualify the clause in `CON-215`: "…and a caller-binding
signal for `CON-214` where the platform authenticates one, or an explicit record
that it does not, as `CON-223` gives for Apple."

This one is worth a reviewer's attention beyond the wording. The failure mode of
leaving it unqualified is not that an Apple adapter is rejected — it is that an
implementer reads "must provide a caller-binding signal", finds the platform
gives none, and **manufactures one** from a payload-supplied identifier. `CON-222`
already forbids exactly that: "A caller-supplied package name in the payload is
never evidence of anything."

### FINDING-014 — SPEC-004 defines no `OBS-###`, so Principle 7 is unsatisfiable as written

Constitutional Principle 7 requires that "every `REQ-###` carries at least one
`OBS-###` link post-release", and PROTO-001's traceability chain is
`REQ → CON → TEST → CODE → OBS`. SPEC-004 defines **zero** observability
artefacts, and its Traceability table has no OBS column, so the chain terminates
at TEST.

The consequence is not only bookkeeping. `NFR-207` states a numeric latency
threshold — 2 seconds at p95 — with no signal to evaluate it against, and
`OQ-201` asks the human owner to ratify four freshness values that nobody has
measured, because there is nothing measuring them.

**Taken as:** a spec-level gap this experiment cannot close. Amendment Channels
name chat instructions as a request rather than an amendment, so a draft is
supplied instead of an edit.

**Proposed resolution:** [[EXP-001-proposed-obs]] drafts fourteen signals,
`OBS-201` through `OBS-214`, each traced to the requirements it serves, with the
REQ → OBS mapping the Traceability table would gain and an explicit account of
the requirements that get **no** signal and why. Two carry temporal properties in
the notation PROTO-001 §Temporal Properties fixes, so `NFR-207` and `REQ-208`'s
propagation bound become monitorable rather than asserted.

The draft's shape is dictated by an interaction worth flagging to the reviewer:
the dimensions a designer reaches for first — account scope, home DID, grant ID,
device DID — are each forbidden by `REQ-217`, `NFR-201`, `NFR-203`, or `REQ-215`.
So every proposed signal is a counter or a latency distribution dimensioned only
by values already public to the party emitting them. A metric that let an
operator reconstruct which accounts a person holds would defeat `NFR-201` more
thoroughly than any protocol flaw, because it would do so quietly and at scale.

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
    evidence: "565 passed across the workspace, 12 suites in the core; every
      test file names the TEST-2NN it derives from. Artefact coverage: 31/31
      REQ, 8/8 NFR, 26/26 CON, 41/43 TEST cited by name."

  - gate: "Test-First / Red Gate"
    mechanism: "commit order for the json recogniser; mutation testing elsewhere"
    result: partial
    evidence: "tests/json_recogniser.rs was written and observed to fail before
      src/json.rs existed. For the rest, strict temporal enforcement was not
      practical in one session, so PROTO-001's named fallback applies: three
      hand-run mutants (freshness bound min→max, validity window >= → >,
      lifetime bound removed) were each killed by the test written for them.
      Four more were run against the pairing and platform contracts: dropping the
      authentication half of the consent gate, making burn() a no-op, permitting
      an implicit intent to carry ceremony material, and treating an
      unattributed caller as a mismatch. Each was killed by the test written for
      it. Three more against the provider hint — dropping the descriptor-digest
      check, the offer-digest check, and the account-scope prohibition — were
      likewise killed, which matters because that verifier had shipped untested.
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
    evidence: "test-vectors/spec-004-v1.json — 37,893 octets, 26 groups (one
      per contract), 127 cases, sha256
      09f16b91ecbfd54f0413a515e2bf942d2332b5fbfb0a4f54ba22a1c1491dddc4. The
      completeness rule is a test: every closed error token — including CON-218's
      nine version-1 downgrades — and each of CON-206's thirteen steps has a
      case. The seven contracts that had no group were found by the SPL theory,
      not by inspection; see the process observations."

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

  - gate: "Observability: every REQ links to an OBS post-release (Principle 7)"
    mechanism: "REQ → OBS traceability audit"
    result: fail
    evidence: "SPEC-004 defines zero OBS-### artefacts and its Traceability
      table has no OBS column, so the chain terminates at TEST. FINDING-014.
      docs/EXP-001-proposed-obs.md drafts OBS-201..OBS-214 with the mapping the
      table would gain; adopting it needs a Tier-1 amendment through the
      declared channel, which this experiment cannot perform."
    owner: "the human owner"

  - gate: "Phase 1 user profiles and happy paths exist"
    mechanism: "path existence: users/{person,developer,provider}/"
    result: pass
    evidence: "users/person/user.md, users/person/happy-paths.md,
      users/developer/user.md, users/developer/happy-paths.md,
      users/provider/user.md. The happy paths restate SPEC-004's inline prose in
      PROTO-001 Phase 1 form, which is what surfaced the failure modes the
      simulation then found."

  - gate: "Synthetic user simulation run and findings recorded"
    mechanism: "docs/EXP-001-synthetic-user-run.md"
    result: unverified
    evidence: "Eight findings recorded. But PROTO-001 requires the synthetic
      user to be a sub-agent working from the specification and profile only,
      and this run was performed by the session that wrote the implementation.
      That breaches the Principle 12 separation, so the findings stand and the
      gate does not."
    owner: "the human owner"

  - gate: "Vault hygiene: dead links authored or explicitly deferred"
    mechanism: "zetl check --dead-links -d specs"
    result: pass
    evidence: "65 dead links, of which 7 are this experiment's and all 7 point
      at PROTO-001-usdd-agent-protocol, which lives in the anuna-dev skill
      rather than the vault. Recorded as an explicit deferral with an owner in
      EXP-001, per PROTO-001's own rule that a dead link is visible debt to be
      authored or deferred, never deleted. The other 58 are pre-existing —
      SPEC-001, SCREEN-001/002, and concept pages the specs already carry.
      The USDD artefacts were moved from docs/ into specs/ so they join the
      vault the specs live in; before that move their links were unresolvable
      because they sat outside it."

  - gate: "Full contract coverage"
    mechanism: "inspection against SPEC-004 §Contracts"
    result: pass
    evidence: "all 26 contracts (CON-201 through CON-226) have an implementation
      and tests. What remains unimplemented is primitives and FFI — PROTO-002/3/4
      and the native platform calls — not contracts. See 'What was NOT
      implemented' above for the precise boundary."

  - gate: "Ceremony obligations exercised against a live PROTO-003 stack"
    mechanism: "none available"
    result: unverified
    evidence: "CON-213/216/217/218 are tested against an injected Confirmation
      rather than a real SPAKE2 exchange. The ordering, binding, and closure
      obligations are covered; the primitive is not implemented here."
    owner: "the human owner"

  - gate: "Platform adapters exercised on a real OS (TEST-239)"
    mechanism: "none available"
    result: unverified
    evidence: "CON-222/223 policy is implemented and tested; the FFI is not.
      TEST-239 requires hostile sibling apps and alternate link handlers
      installed, which needs an integration harness."
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
- **The SPL theory found a corpus gap that inspection had not.** Encoding
  "implemented and has a corpus case" as a defeasible rule and asking the theory
  which contracts were ready surfaced seven with no corpus group — including
  `CON-205` and `CON-207`, whose grant and proof vectors are exactly what
  `NFR-202` needs a second implementation to reproduce. The corpus had satisfied
  `CON-226`'s completeness rule, which is stated over *error tokens and steps*
  rather than over contracts, so nothing was failing. That is the argument for
  writing the plan as a theory rather than a checklist: a checklist confirms what
  its author thought to list.
- **"It depends on PROTO-003" was too quick an answer.** Four contracts were
  initially deferred on that ground and all four turned out to be implementable:
  their obligations are about ordering, binding, and closure, and none of them
  needs the SPAKE2 primitive to be decidable. `CON-218` needs no PROTO-003
  concept at all. The lesson for Phase 4 is that a contract naming a dependency
  is not the same as a contract *requiring* it, and the cheap test is to ask
  which of its clauses actually mention the primitive rather than the ceremony
  around it.
