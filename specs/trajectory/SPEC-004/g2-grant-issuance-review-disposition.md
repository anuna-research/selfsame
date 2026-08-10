# G2 grant issuance — cross-model review and its disposition

- **Artefact:** `authorise()` in `crates/selfsame-app-identity/src/authorise.rs` and
  the `app_grant_*` commands in `src-tauri/src/app_grant.rs`, at `a793724`
  (PR #19).
- **Reviewer:** a different model family (Codex), fresh context.
- **Returned:** five P1 and one P2.
- **Disposition:** all six accepted. **PR #19 does not merge.** Two are repaired
  as Group A; four are Group B and are the real remaining scope of G2.

## The verdict in one line

> *"The new issuance path omits required authentication, replay protection,
> first-enrollment confirmation, and issuer state publication. It also cannot
> authorize valid Android handoffs."*

## What was actually built

A signer, and almost nothing that makes a signature meaningful. The decision
recognised its inputs correctly and then acted as though recognition were the
whole contract.

The clearest evidence is a comment. The module doc asserts that *"the `kid`
resolves only in the authenticated profile"* — a real property of `CON-214`, and
one this code never establishes, because it accepts a profile from its caller
and only checks that the syntax parses. **A comment claiming a security property
the code does not provide is worse than no comment**: it tells the next reader
the question has been answered.

## Group A — `authorise` assumed inputs it should have required

### F1 — P1 — profiles are recognised, never authenticated

`ApplicationProfile::recognise` validates syntax. Neither command performs
`CON-220` origin-bound discovery, and neither binds the profile to the ceremony
record. An attacker supplies a canonical profile for a claimed application
carrying an enrollment key they hold, signs matching evidence with it, and the
wallet signs for an origin nobody authenticated.

`CON-214`'s entire value is that the `kid` resolves in an *authenticated*
document whose private half is a backend credential. Against a caller-supplied
profile it verifies that the caller signed their own statement with their own
key.

**Repair.** `authorise` takes the ceremony's `profileDigest` — the value
`PROTO-003`'s record binds and `CON-219`'s offer carries — and requires the
supplied profile to hash to it. The wallet then trusts the profile exactly as
far as the ceremony binding reaches, and no further. Where a wallet can perform
`CON-220` discovery itself it should; that is a fetch and belongs to the shell,
but it does not replace this check, because a fetched profile still has to be
the one *this ceremony* is about.

### F4 — P1 — Android handoffs always refuse

`platform_binding_id` is hard-coded `None`, and `enrollment::verify` rejects an
Android binding when it is absent — correctly, because `Observed`'s own
documentation says `None` means *"the OS said nothing"*, never *"any binding
will do"*. Every legitimate Android handoff is therefore refused, and the
required caller comparison never happens.

It fails closed, which is why it is a functional defect rather than a hole. It
is still a P1: the platform path cannot work at all.

**Repair.** The parameter is threaded through from the adapter that observed it.
`None` remains meaningful and remains correct on Apple, where `CON-223` records
that the platform gives no general caller attribution.

### F6 — P2 — the provider hint is never checked

`offerDigest` excludes `providerHint` deliberately, to avoid a digest over an
object containing itself. The consequence is that a malformed or mismatched hint
can sit beside otherwise valid signed evidence, and `authorise` never parses
`payload.provider_hint` or compares it to the provider actually observed.

**Repair.** Recognise the hint through `selection::ProviderHint` and require its
`providerId`, `descriptorDigest` and `offerDigest` to match what the wallet
observed and computed. `CON-209` exists to bind the ceremony to a provider; a
hint nobody reads binds nothing.

## Group B — steps that do not exist

These are not patches. Each is a capability the change assumed was already
there, and together they are the real remaining scope of G2.

### F2 — P1 — no replay protection

The successful path runs from verification straight to token generation and
signing without consulting or updating a `RequestLedger`, whose own
documentation calls it *"the sole permitted mutation once syntactically valid
evidence reaches step 5"*. Resubmitting the same still-valid offer — including
after a successful issuance — mints a second credential instead of returning
`EnrollmentReplay`.

**What it needs.** A durable consumed-`requestId` store in the shell, consulted
and updated **atomically before any key use**. The pure ledger type exists; what
does not exist is anywhere for it to live across process restarts.

### F3 — P1 — the issuer has no document

This is the largest, and the one that was assumed rather than skipped. The
command derives a home key and signs a credential with it, and never constructs
the `did:crdt` genesis or the `CON-203` `alsoKnownAs` update. The application
account's identity has no document by any route: `issuerClosure` is always
`None`, nothing is published to a `stateResolvers` entry, and a recipient
reaching `CON-206` step 4 finds no closure to acquire.

Note what `CON-206` actually says about the bundle path — it is *"a bootstrap
for a first ceremony on a degraded network, not a standing arrangement"*, and a
verifier may rely on it only when accepting a grant ID for the first time with
no declared resolver reachable. So the repair is not simply "put a closure in
the bundle": the wallet must **create and publish issuer state**, with the
bundled closure as the degraded-network bootstrap it is described as.

**What it needs.** Two-stage `CON-203` construction — genesis from the home
public key, then a root-signed document-data update setting `alsoKnownAs` — plus
publication to a declared resolver. That last part meets `G6` in
[[selfsame-path-b-readiness-2026-08-10]]: no conforming resolver is deployed.
This is identity *creation*, and it deserves its own change.

### F5 — P1 — first enrollment is indistinguishable from any other

For an account with no existing authority binding, the path derives and signs
immediately. It checks no authority state, exposes no pre-bundle fingerprint,
and records no confirmation, so it cannot tell a first enrolment from a
subsequent one and can mint a first grant without the `CON-221` comparison the
contract requires.

`CON-221` is cited in a doc comment on `GrantRequestView` in the same change,
and implemented nowhere.

**What it needs.** An authority-state check to establish which case this is, the
fingerprint surfaced before the bundle exists, and somewhere durable to record
that the person confirmed. `CON-221` also forbids re-entering the contract to
"re-confirm", so the recorded result is load-bearing rather than advisory.

## Why the tests did not catch any of this

Eight tests, all passing, none of which touched a single finding. They exercised
**the decision that was written** rather than the decision `CON-206` requires:
each verified that a check present in the code behaved correctly, and none asked
which checks the contract requires to be present at all.

That is a general lesson worth keeping, and it is the same one
[[spec-004-carriage-check]] records one layer up. There, a requirement was
written without asking which wire carried its values. Here, a signing path was
written without asking what the verifier at the other end must be able to do
with the result. Both are failures to read the contract from the *consumer's*
side.

## Both groups are now repaired

**Group A** — `69bf01c`. **Group B** — F2 in `c66883d` (PR #20), F3 and F5 in
`7017b52` and `9987dd0`.

Three things the repairs surfaced that the findings did not name:

- **F3 needed a delta constructor that did not exist.** `selfsame-core` gained
  `set_also_known_as`, beside `declare_profile`, because that module owns
  `did:crdt` delta construction and a second place building deltas would be a
  second answer to what a signed delta is. The closure itself is
  `did_crdt::core::recon::ClosureBundle` rather than a new type: the method
  defines the shape, and this crate's reader says it mirrors it, so producing
  the upstream type is what stops writer and reader drifting.
- **F5 needed an error the network crate could not express.** Every
  unsuccessful WebFinger status became `Refused`, so an implementation had to
  read every outage as first use — the substitution the comparison exists to
  catch — or refuse every genuine first enrolment. `NetError::NotFound` now
  distinguishes a 404, which is the authority answering, from the rest, which is
  the authority failing to answer.
- **F5 forced issuance into two commands.** The comparison is a person's, and a
  single command could only have asked them after the fact.

## What is still open, and is reported rather than hidden

`AuthorisedGrant::published` is always `false`. `CON-206` prefers a declared
`stateResolvers` entry and calls the bundled closure *"a bootstrap for a first
ceremony on a degraded network, not a standing arrangement"* — a verifier may
lean on it only at a grant's first acceptance with no resolver reachable, and
must record that it did.

Publication needs a conforming `did:crdt` resolver and none is deployed: `G6` of
[[selfsame-path-b-readiness-2026-08-10]]. The field exists so a caller can see it
is relying on the bootstrap instead of inferring it from silence.

## Round 2 — the repairs were reviewed, and four of five held

A second cross-model pass over Group B returned four P1 and one P2. All five
accepted and repaired. Their verdict on F3 is the one that matters:

> *"The generated issuer closure cannot authorize the key named by its grants, so
> the primary issuance path remains unverifiable."*

### R1 — P1 — the document was built and still cannot authorise a grant

F3 constructed a `did:crdt` document, and not the one `CON-206` needs. Genesis
creates `{did}#key-0`, an `Ed25519Signature2020` method in `Authentication`;
`grant::header` signs under `{did}#jwk-0`; step 6 requires that exact identifier
to name a **`JsonWebKey`** in `assertionMethod`. Every bundle the path could
produce fails step 6.

**It cannot be repaired in this repository.** `did_crdt`'s `SuiteType` has two
variants and neither is `JsonWebKey`, so no delta at the pinned revision creates
a method of the required type. `CON-203` says the same from the other side — the
projection *"MAY be a deterministic DID resolver representation of the existing
root key"*, and *"The corresponding `did:crdt` method change is a Tier-1-gated
dependency"* — which is an open box in this specification's own gate.

So the reviewer's second option was the only one available: **issuance is
gated.** `IssuerIdentity::authorises_grants` is `false`, and the shell refuses
with `IssuerKeyProjectionUnavailable` rather than emitting a bundle no verifier
can accept. A grant that fails at the recipient is worse than one never issued,
because the failure surfaces later, somewhere else, after a person believes they
linked a device.

Two tests pin it, including one that **fails when the upstream box closes** —
so opening the path is a decision someone takes rather than an edit someone
makes.

**F3 is therefore not closed.** The identity now exists and is correct as far as
it goes; what it cannot yet do is authorise the key its own grants are signed
under.

### R2 — P1 — a syntactic JRD suppressed the one-time comparison

`authority_state` treated any successful JRD with a non-empty `aliases` array as
`Bound`. A stale or cache-mixed response whose `subject` names another account
would therefore suppress `CON-221`'s prompt while proving nothing about *this*
account. Now `fetch_and_verify` requires `CON-204`'s reciprocal binding in both
directions, and a semantic mismatch is `Unknown` — which fails closed, because a
mismatch is precisely the substitution the comparison exists to catch.

### R3 — P1 — confirmation was not bound to what was displayed

`pending_issuance` was overwritten unconditionally and `app_grant_confirm` took
no identifier, so an overlapping preparation could replace the slot and
confirming the displayed request would release a different signed bundle. A
second live ceremony is now refused rather than allowed to displace the first,
and confirmation names the ceremony it is answering.

### R4 — P1 — `Response::TimedOut` was unreachable

No deadline was stored, so any later `confirmed = true` became `Confirmed`. A
preparation begun shortly before expiry — WebFinger takes time — or a prompt left
open could still yield a long-lived grant after the ceremony had timed out. The
offer's expiry now travels with the pending state and is compared at release.

### R5 — P2 — the screen could not draw what the contract requires

The response carried only the hex. The issuer DID stays private until
confirmation, so the shell cannot call `home_fingerprint`, and deriving a second
rendering in the frontend is the duplicate implementation this repository
refuses — leaving `CON-221`'s required LifeHash undrawable. The full `Fp` is now
returned.

### The pattern, again

R1 is the third instance of one error in this line of work: I verified what I
built rather than what the consumer needs. The F3 tests checked that the DID was
the one the key derives and that the alias update was causally ordered — both
true, and neither asks the question `CON-206` asks, which is whether the
document authorises the key the grant is signed under.

## Standing

The Group A and Group B repairs are unreviewed; round 2 assessed Group B only. Round 1 assessed `a793724`; everything since is new
code written in response to findings, which is the condition under which this
session has introduced defects before — twice in `authorise` alone, both caught
by tests written minutes later.

F3 and F5 are where a further error is most likely: both are new capability
rather than a corrected line, both touch crates outside the one under review,
and neither has been exercised end to end against a real application.

Nothing shipped: `GATE-01` is shut in cbcl-bus, so this code is dormant by
construction under `GATE-00`. That is a reason the defects cost nothing yet, not
a reason they were acceptable.
