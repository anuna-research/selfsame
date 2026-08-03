# Happy paths: the person

Seven paths, drawn from [[SPEC-004-application-scoped-identity#Users and happy paths]]
and restated in the [[PROTO-001-usdd-agent-protocol]] Phase 1 form so each carries
explicit preconditions, postconditions, and **failure modes** — the third of which
the specification's inline prose mostly leaves implicit.

The failure modes are the point of restating them. A happy path with no failure
modes is a happy path nobody has walked.

## HP-1: Add a second application

**Preconditions.** The person already uses application A with Selfsame. They have
just installed application B on the same device, and signed into B's own account
by B's own means.

**Steps.**

1. Sign into B normally → B authenticates its account and holds an
   `accountScopeId` for it.
2. B asks Selfsame for this account's identity → no person-visible step.
3. Selfsame derives B's application and account nodes, constructs the home DID
   and `acct:` localpart → no person-visible step.
4. B provisions the alias at its account authority and publishes the reciprocal
   binding → no person-visible step.
5. B verifies the grant, status, account binding, and device proof → no
   person-visible step.

**Postconditions.** B works. Nothing from A was shown to B: no identifier, key,
alias, endpoint choice, or grant.

**What the person experiences.** Nothing. This is the path where the promise is
kept by there being no ceremony at all.

**Failure modes.**

- **The account authority is unreachable at step 4.** `CON-204` returns
  `AccountProvisioningFailed`, and `CON-206` step 9 then refuses the grant. The
  person sees B fail to finish signing in, with no obvious relationship to
  Selfsame. *What should the message say?* The specification does not.
- **B's profile has expired descriptors.** `CON-208` returns
  `NoEligibleRendezvous`. No ceremony is needed on this path, so this only bites
  if B links a second device later.

## HP-2: Switch between two accounts in one application

**Preconditions.** Application A has two signed-in accounts, A1 and A2, each
with a committed `accountScopeId`.

**Steps.**

1. Use A's existing account switcher to select A2 → the switcher A already had.
2. A supplies A2's scope to Selfsame → no person-visible step.
3. Selfsame selects A2's home DID, alias, device key, grant, and state → no
   person-visible step.

**Postconditions.** A2's identity is active. A1's grant, proof, and state confer
nothing while A2 is the authenticated context.

**What the person experiences.** The account switcher they already knew.
`REQ-216` is explicit that they are never asked for a derivation index, and this
is the path that promise is about.

**Failure modes.**

- **A cannot restore A2's scope** — the account record is corrupt, or A2 was
  restored from a backup that did not carry it. `REQ-217` requires
  `AccountScopeUnavailable` and forbids guessing or prompting. The person sees
  one account work and the other not, with no available action.

## HP-3: Set a human-readable username

**Preconditions.** Signed into A1. The mandatory opaque alias is provisioned.

**Steps.**

1. Open A's Selfsame identity settings and type `alice` → the only free text a
   person types anywhere in this specification.
2. The UI previews `acct:alice@accounts.photos.example` and warns that it is
   publicly discoverable and may correlate them if reused → they read it, or
   they do not.
3. The authority validates, reserves, publishes the reciprocal binding.
4. A1's home key signs a `SetDocumentData` update setting `alsoKnownAs` to both
   aliases.

**Postconditions.** The username is active. The DID, home key, account scope,
opaque alias, grants, revocation state, and projection allocations are all
unchanged — `CON-212` is emphatic that none of them move.

**Failure modes.**

- **`UsernameUnavailable`.** Someone has it, or it is reserved, or it is
  tombstoned from a previous holder. A asks for a different one; it never asks
  the person to edit a URI.
- **They pick the same handle they use everywhere else.** Not an error. It is
  the explicit privacy exception in `NFR-201`, and the warning at step 2 is the
  only control — "the protocol cannot make a voluntarily reused public name
  unlinkable".

## HP-4: Link another device

**Preconditions.** A wallet on the phone, an application on the laptop, both
online.

**Steps.**

1. The application selects a provider, allocates a nameplate, writes `pA`,
   publishes the `CON-409` record → no person-visible step.
2. One party generates the twelve-word code `C`.
3. The person carries `C` across: by scanning a QR, by reading twelve words
   aloud, by typing them, or by OS handoff on one device.
4. Both sides run SPAKE2 and verify confirmation MACs → no person-visible step.
5. The wallet shows consent naming the authenticated origin, the target device,
   and the exact permissions.
6. The person approves.
7. The application provisions the alias and publishes the reciprocal binding.
8. The joining device proves possession.

**Postconditions.** The laptop holds a grant scoped to that one application
account.

**Failure modes.**

- **A mistyped word.** BIP-39's checksum catches most transcription errors
  locally. But `REQ-229` burns the ceremony on *any* failure, and a retry needs
  a **new** code — so the person re-reads twelve fresh words rather than
  correcting one. See `SU-002` in the simulation log.
- **The provider dies mid-ceremony.** `CON-213` abandons and regenerates
  everything. The person sees a restart.
- **Step 7 has not completed when they look.** The grant exists and no verifier
  accepts it. `CON-204` is clear about the mechanism and silent about the
  screen.
- **This is the account's first enrollment.** `CON-221` inserts a fingerprint
  comparison between steps 6 and 7. See `HP-4a`.

## HP-4a: First enrollment of an account

**Preconditions.** As HP-4, and the account authority holds no binding for this
account.

**Steps.**

1. As HP-4 through consent.
2. The wallet displays the home DID's fingerprint — six bytes as hex, with a
   LifeHash beside it.
3. The application displays the same two values, computed from the grant's
   `issuer`.
4. The person compares **the hex**, on two screens at once.
5. They confirm.

**Postconditions.** The DID now bound to this account is the one their wallet
derived. Nothing is established about the wallet's provenance or integrity —
`CON-221` says so plainly.

**Failure modes.**

- **They cannot see both screens.** One device is across the room, or held by
  someone else. There is no "skip" and `REQ-230` forbids offering one.
- **They confirm without comparing.** The realistic case, and the one no
  protocol can prevent. `CON-221` shrinks the window to once per account ever,
  which is the most a design can do.
- **The fingerprints differ.** Either a bug or the attack this exists to catch.
  The application must not provision, must not accept, must burn the ceremony,
  and should revoke.

## HP-5: Authorise an application on the same phone

**Preconditions.** The developer application and a verified Selfsame wallet are
both installed on one mobile device, and the target of the grant is *this*
device.

**Steps.**

1. The application prepares the ordinary ceremony → no person-visible step.
2. It hands the bootstrap to the wallet through the platform adapter.
3. The person taps **Continue in Selfsame**.
4. They review consent naming the authenticated origin and exact permissions.
5. They return.

**Postconditions.** As HP-4. `REQ-221` requires this path to use the same offer,
evidence, provider selection, confirmation, slots, bundle, predicate, and proof —
only the bootstrap delivery differs.

**Failure modes.**

- **No wallet installed.** `WalletUnavailable`, and an install action carrying
  no ceremony material.
- **A hostile sibling app claims the link.** `UnverifiedWalletTarget` or
  `HandoffAmbiguous`; the ceremony burns.
- **The OS offers a browser.** `CON-223` makes that a terminal failure rather
  than a fallback. The person sees the flow stop, which is correct and will feel
  like a bug.

## HP-6: Remove a device from one account

**Preconditions.** Signed into A1. A1 has a grant on a laptop the person no
longer has.

**Steps.**

1. Select **Remove laptop**.
2. The UI names the account and the device and asks for confirmation.
3. The person confirms.
4. Selfsame signs a `RevokeCredential` delta and submits it to every declared
   resolver.
5. The application shows **pending**.
6. When a re-resolved verified closure contains the grant ID, it shows success.

**Postconditions.** The laptop is refused even holding a valid grant and its
device key. Every A2 grant, key, and session is untouched.

**Failure modes.**

- **No resolver answers.** The revocation stays pending, is retained, and is
  retried. `CON-210` forbids reporting success. The person sees "pending"
  indefinitely, which is honest and unsatisfying.
- **They expect it to be instant.** It is bounded by
  `propagationSlaSeconds + min(maxClosureAgeSeconds, propagationSlaSeconds)` —
  120 seconds at the defaults. For a stolen device, two minutes feels long.

## HP-7: Restore

**Preconditions.** A new device. The person has their twelve recovery words.

**Steps.**

1. Enter the recovery phrase.
2. Sign into application A by A's own means.
3. A supplies the account's `accountScopeId` from its authenticated record.
4. Selfsame reproduces the same account node, home seed, DID, and `acct:` URI.

**Postconditions.** The same identity, from the same words. Provider changes in
the interim changed nothing — `REQ-213`.

**Failure modes.**

- **They have the words but have not signed into A.** Step 3 has not happened,
  so there is no scope, so there is no identity. `REQ-217` requires
  `AccountScopeUnavailable`.

  This is the sharpest cliff in the specification and it is worth stating
  plainly: **the recovery phrase alone does not restore a Selfsame identity.**
  It restores the *hierarchy*; the account scope comes from the application. A
  person whose model is "my words are my backup" is wrong in a way the words
  themselves cannot tell them. See `SU-001`.

- **The application account itself is lost** — forgotten password, dead email.
  Then the scope is gone, and `REQ-217` forbids guessing or prompting. The
  identity is unrecoverable, and no amount of correct recovery phrase changes
  that.
