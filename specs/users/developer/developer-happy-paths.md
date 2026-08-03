# Happy paths: the adopting developer

Restated from [[SPEC-004-application-scoped-identity#REQ-214]] in the
[[PROTO-001-usdd-agent-protocol]] Phase 1 form.

## HP-D1: First integration

**Preconditions.** An application with its own accounts and its own backend. No
relationship with Anuna, and per `REQ-214` none is needed.

**Steps.**

1. Choose a canonical `applicationId` on an origin they control.
2. Author a profile and publish it **at that identifier**, served as
   `application/selfsame-profile+json` with no redirect.
3. Generate an Ed25519 enrollment key; the private half stays in the backend.
4. Add an `accountScopeId` column: 32 CSPRNG octets, allocated once per account,
   atomically on first use, never recycled.
5. Stand up an account authority answering WebFinger for `acct:ss-…` URIs.
6. Choose providers, or run their own.
7. Embed the method library in the backend they already run, and declare their
   own origin as a state resolver.
8. Integrate the SDK.

**Postconditions.** A person can enrol, link a device, and be revoked, with no
Anuna involvement at any point.

**Failure modes.**

- **The profile is not canonical.** `CON-201` step 5 refuses it and every
  ceremony fails at discovery. The error names the member, which is the only
  reason this is debuggable.
- **They serve the profile behind a redirect** — a CDN, a trailing-slash
  normalisation, an apex-to-www rule. `CON-220` step 2 rejects **every**
  redirect including same-origin. This will happen to someone on their first
  deploy and the message must say why.
- **They embed the enrollment key in the mobile app.** Nothing fails. Everything
  works. The `REQ-222` guarantee is silently gone, and no test they run will
  tell them. This is the most dangerous available mistake.

## HP-D2: Rotate an enrollment key

**Preconditions.** A published profile with one signing key.

**Steps.**

1. Generate the new key.
2. Publish a profile containing **both**.
3. Move signing to the new key.
4. Publish a profile containing only the new key.

**Postconditions.** Rotated with no ceremony interrupted.

**Failure modes.**

- **They skip step 2.** Wallets holding a cached profile — up to 3,600 seconds
  under `CON-220` — verify against the old key and refuse the new signature.
- **They expect revocation to be instant.** Removing a key from the profile
  bounds an attacker to the remaining cache lifetime, not to zero. `CON-220`
  states the composition with `CON-214`'s 120-second window; a developer under
  pressure will want faster and there is no faster.

## HP-D3: Verify a grant

**Preconditions.** A grant arrived from a ceremony.

**Steps.**

1. Recognise the profile.
2. Read `issuer` and recompute the expected alias.
3. Provision the account record and publish the reciprocal JRD.
4. Resolve the issuer's closure from a declared resolver.
5. Run all thirteen `CON-206` steps.
6. Issue a challenge and verify the device proof.

**Postconditions.** An authenticated session, or a refusal naming a step.

**Failure modes.**

- **They run step 5 before step 3.** Step 9 fails closed and the grant looks
  broken. The ordering is in `CON-204` and is easy to invert.
- **They cache a negative result from step 9.** `CON-204` forbids caching it "in
  a way that prevents acceptance once provisioning completes" — an obvious
  optimisation that breaks the remote-controller path permanently.
- **They rely on the bundle's closure because it is right there.** Permitted only
  on first acceptance with no resolver reachable, and must be recorded. The
  closure is the issuer's own account of its own revocations.

## HP-D4: Revoke a device

**Steps.**

1. Construct and sign the `RevokeCredential` delta on the current frontier.
2. Submit to every declared resolver, in parallel.
3. Report **pending**.
4. Re-resolve; report success only when a verified closure carries the ID.

**Failure modes.**

- **They report success on HTTP 200.** The natural implementation and the wrong
  one. `CON-210`: "A resolver's acknowledgement is not evidence of revocation."
- **They give up when one resolver fails.** Forbidden: the delta is retained and
  retried.
- **They build the replica on the non-verifying merge.** See `FINDING-005`.
  Nothing fails visibly; the endpoint simply accepts forged deltas.
