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

## Standing

PR #19 is not merged and its description asserts properties F1 shows are false;
correcting it is part of this disposition. Group A is repaired against this
record. Group B is tracked as the remaining scope of G2, with F3 expected to
land as its own change because publishing issuer state reaches `did:crdt`
construction and the unresolved resolver question.

Nothing shipped: `GATE-01` is shut in cbcl-bus, so this code is dormant by
construction under `GATE-00`. That is a reason the defects cost nothing yet, not
a reason they were acceptable.
