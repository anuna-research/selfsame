# Happy paths: the infrastructure provider

Restated from [[SPEC-004-application-scoped-identity#REQ-219]] and
[[SPEC-004-application-scoped-identity#REQ-228]] in the
[[PROTO-001-usdd-agent-protocol]] Phase 1 form.

The provider's paths are short, and that is the design: `REQ-228` keeps them
holding as little as possible, so there is little for them to do and little for
them to lose.

## HP-P1: Become eligible

**Preconditions.** An operator wanting to serve Selfsame traffic. No
relationship with Anuna, and `REQ-219` forbids one being required — "Operator
identity, commercial relationship, co-location with a state resolver, or an
Anuna allowlist SHALL NOT substitute for protocol conformance."

**Steps.**

1. Implement [[PROTO-003-selfsame-pairing-v1]] `CON-401`–`CON-408`, or
   [[PROTO-002-selfsame-rendezvous-v1]] `CON-301`–`CON-308`, or both.
2. Serve a capability object at each service's declared path.
3. Pass both black-box conformance suites.
4. Ask an adopting developer to add a descriptor naming them.

**Postconditions.** Applications whose profiles name them can select them.
Nothing else changes; there is no registry to join.

**Failure modes.**

- **They implement only one of the two services.** `CON-213` step 5 requires
  both capability probes to pass, so a descriptor naming them is never eligible.
  The developer's profile is valid and the provider is never chosen, which is a
  silent outcome and worth an operator-facing diagnostic.
- **Their capability response is compressed, redirected, or sets a cookie.**
  `CON-213` refuses all three, and a CDN in front of the service will do at
  least one of them by default.

## HP-P2: Relay a pairing session

**Preconditions.** Selected by an initiator under `CON-208`.

**Steps.**

1. Allocate a nameplate on request.
2. Accept the immutable `pA` write and acknowledge it.
3. Relay SPAKE2 frames between two parties.
4. Relay confirmation MACs.
5. Serve mailbox slots.

**Postconditions.** Two parties completed a ceremony. The provider learns that
one happened, roughly when, and roughly how large — and nothing else.

**What they must not have learned.** `REQ-228` is a list, and it is exhaustive:
no word, word index, password-equivalent verifier, PAKE key, mailbox key,
offer or grant plaintext, DID, account scope, or authorization decision.

**Failure modes.**

- **They try to be a SPAKE2 endpoint.** `CON-218`'s `ProviderAsPakeEndpoint`
  downgrade. Both clients burn the ceremony.
- **They serve a peer's confirmation on their behalf.** `REQ-226` forbids a
  client accepting a provider-generated confirmation. Same outcome.
- **They go down mid-ceremony.** `CON-213` abandons and regenerates everything;
  the person sees a restart. Availability is the one thing a provider can
  genuinely cost, and the profile's second descriptor is the answer.

## HP-P3: Serve `did:crdt` state

**Preconditions.** Named in a profile's `stateResolvers`.

**Steps.**

1. Accept signed deltas, applying the method's own checks.
2. Serve resolved closures.

**Postconditions.** Verifiers can reach fresh issuer state, and revocations
propagate within `propagationSlaSeconds`.

**Failure modes.**

- **They withhold state.** Permitted in the sense that nothing stops them, and
  bounded in effect: `CON-210` requires submission to *every* declared resolver
  and `CON-201` recommends the application run its own, so withholding by one
  operator is survivable by design.
- **They accept a delta without verifying its signature.** The failure
  `FINDING-005` is about. The method's `merge` does not verify by default, and a
  replica built on it admits forged deltas — which is fail-safe only for
  grow-only operations, and only while every operation stays grow-only.
- **They try to un-revoke.** Not possible. The set is grow-only and merge is
  union; there is no operation to attempt.

## HP-P4: Publish a status projection

**Preconditions.** A profile with `revocation.projection` present.

**Steps.**

1. Allocate a random free `(credential, index)` at issuance.
2. Store the signed status list credential the home DID produced.
3. Serve it.

**Postconditions.** Generic W3C VC consumers can read a bounded-freshness
status. Selfsame verifiers are unaffected — `CON-206` step 10 never relies on a
projection.

**Failure modes.**

- **They allocate sequential indexes.** Permitted but discouraged: the list is
  public, so sequential allocation leaks issuance order and volume.
- **They serve a stale projection.** Handled by the format: the publisher was
  forbidden from signing a window longer than `maxAgeSeconds`, so a consumer
  applying only W3C validity rules already rejects it.
- **They try to sign one themselves.** The projection's issuer must be the
  application-account home DID, and they do not hold that key. `CON-210` is
  explicit that the publication host "possesses no home signing key and is not
  an authorization trust anchor".
