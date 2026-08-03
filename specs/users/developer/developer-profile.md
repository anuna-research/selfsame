# User: The adopting application developer

| Field | Value |
|---|---|
| group | `developer` |
| governs | [[SPEC-004-application-scoped-identity]] |
| status | draft — authored under [[EXP-001-spec-004-reference-implementation]] |

## Role

Builds an application that wants device authorization without running an
identity system. They are adopting Selfsame the way one adopts a library, and
their patience for ceremony is proportional to how much of their own problem it
solves.

`REQ-214` is the requirement written for them, and its first clause is the one
that matters: **"A conforming integration SHALL require no registration with
Anuna."**

## Goals

1. **Authorize devices without storing passwords or running an IdP.**
2. **Not be locked in.** They will read the profile's provider list and ask what
   happens when they want to move. `REQ-213`'s answer — identity does not depend
   on any provider — is the one that makes adoption safe.
3. **Ship in a sprint, not a quarter.** Nine obligations in `REQ-214` is a lot.
   Whether it is *too* much is the adoption question.
4. **Not be responsible for a breach they cannot reason about.** They will look
   for the trust boundary and want it small.

## Constraints

- **Backend and mobile competence: yes. Cryptography: no.** They can hold an
  Ed25519 key in a backend and sign a statement. They cannot evaluate whether
  `SPAKE2` composed with `HKDF` is sound, and should not have to.
- **They will not read 6,000 lines.** They will read the Orientation block, look
  at `CON-201`'s example profile, and start typing. Anything load-bearing that
  only appears at line 3,400 will be missed.
- **They deploy on their own schedule.** The 3,600-second profile cache bound in
  `CON-220` is a real operational constraint on key rotation, and they will
  discover it the first time they rotate.

## Daily workflow

1. Read the Orientation block; decide whether this is worth it.
2. Mint an `applicationId` and publish a profile at it.
3. Stand up an enrollment-signing key in the backend.
4. Implement the account-scope lifecycle in their account records.
5. Run or contract an account authority with WebFinger.
6. Choose providers, or run their own.
7. Integrate the SDK and verify grants.
8. Discover something in production that the specification bounded and they did
   not notice.

## The nine obligations, and which ones will hurt

`REQ-214` lists nine. Ranked by how much work each actually is, which is not the
order they are listed in:

| Obligation | Cost |
|---|---|
| A `did:crdt` node (item 7) | Highest — unless they take the specification's own advice and embed the method library in the backend they already run for item 4. That sentence is easy to miss and halves the integration. |
| An RFC 7565 account authority with WebFinger (item 3) | High. A new public endpoint with an availability obligation. |
| Origin-authenticated profile publication and a backend signing key (item 4) | Moderate, and the security-critical one. |
| The account-scope lifecycle (item 2) | Moderate. A column, a CSPRNG call, and an atomicity requirement on first use. |
| Mobile platform bindings (item 5) | Moderate, and only for same-device. |
| Providers conforming to two protocols (item 6) | Unknown until those protocols have implementations. |
| An immutable `applicationId` and profile (item 1) | Low, and irreversible. `REQ-202` means getting this wrong costs a `CON-225` succession or a fresh identity. |
| Permission URIs and verifier policy (item 8) | Low. |
| The SDK (item 9) | Low. |

## What they must never do

- Embed an enrollment private key in a native application. `CON-201` says so,
  and it is the single decision the whole `REQ-222` guarantee rests on — a
  hostile sibling app can copy everything else.
- Change `applicationId` casually. `REQ-202` makes it a new identity.
- Treat a resolver acknowledgement as a completed revocation. `CON-210` is
  explicit and the mistake is natural.
- Re-serve different octets at the credential context IRI. `CON-224` calls that
  a specification violation "regardless of who does it, the steward included".

## Related

- [[developer-happy-paths]]
- [[SPEC-004-application-scoped-identity#REQ-214]]
