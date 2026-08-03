# User: The person holding the recovery secret

| Field | Value |
|---|---|
| group | `person` |
| governs | [[SPEC-004-application-scoped-identity]] |
| status | draft — authored under [[EXP-001-spec-004-reference-implementation]] |

## Role

Someone who uses two or more unrelated applications that have adopted Selfsame.
They hold one BIP-39 recovery phrase and, on at least one device, the wallet that
controls their identities.

They are **not** a Selfsame user in their own mind. They are a Photos user and a
Pictura user who, at some point, saw a screen asking them to confirm something.
Nothing in their model of the world contains the words "home key", "account
scope", or "rendezvous provider", and `REQ-209`'s promise — that they are never
asked to choose an endpoint — exists precisely so it never has to.

## Goals

Ordered by how often they arise, which is not the order the specification
discusses them in.

1. **Sign in on a new device and have their things be there.** The dominant
   case, and the one every other goal is judged against.
2. **Add a second application without starting over.** They have a recovery
   phrase; they expect it to be worth something.
3. **Remove a device they no longer have.** Usually because it was lost or sold,
   sometimes urgently.
4. **Not be tracked between applications.** Held weakly and rarely articulated,
   but violated loudly if they discover it was violated.
5. **Occasionally, be findable by a name they chose.** A minority want this;
   `REQ-218` makes it optional for exactly that reason.

## Constraints

- **Technical proficiency: ordinary.** Can follow an on-screen instruction, scan
  a QR code, and read a phone. Cannot be asked to compare a 64-character hex
  string, edit a URI, or understand what a DID is.
- **Two devices, usually.** A phone and a laptop. Sometimes only a phone.
- **Accessibility: the fallback path must work.** Some cannot scan a QR — no
  camera, poor vision, a screen reader, or a laptop with no camera facing the
  phone. `ADR-406`'s twelve spoken words exist for them, and the whole
  `PROTO-003` code design turns on that path being usable rather than nominally
  present.
- **Environment: not always ideal.** Captive portals, one device offline, a
  phone at 4% battery, a shared living room where reading twelve words aloud is
  not private.
- **Attention: low, and interrupted.** They are trying to do something else. Any
  ceremony is an interruption to that something else.

## Daily workflow

Selfsame does not appear in it. That is the design working.

It appears at four moments:

1. **First enrollment in an application.** Once per application account, ever.
2. **Adding a device.** Rare — a new laptop, a replaced phone.
3. **Removing a device.** Rarer, and usually stressful.
4. **Restoring after losing a device.** Rarest, and always stressful.

Every one of those is a moment of elevated anxiety, and three of the four happen
when something has already gone wrong. A design tuned for the calm case is tuned
for the wrong case.

## What they must never be asked

Drawn from `REQ-209`, `REQ-216`, `REQ-217`, and `REQ-227`, and listed here
because a screen that violates one of these is a defect rather than a preference:

- to choose, type, paste, or scan a server endpoint;
- to type, copy, remember, or choose an account scope or derivation index;
- to say an HTTPS identity aloud, except at `CON-409` tier 3 after every other
  transport has failed;
- to import a second recovery phrase;
- to edit a URI, a domain, a DID document, or a configuration file.

## What they *are* asked, and why each is unavoidable

| Ask | Why it cannot be removed |
|---|---|
| Scan a QR, or read twelve words | The two devices share no channel yet. Something has to cross the gap, and a person is the only trustworthy carrier. |
| Compare a fingerprint, once per account ever | `CON-221`. Without it, whichever wallet answers the first ceremony becomes the account's identity permanently — `CON-206`'s expected-account check does not exist yet at that moment. |
| Approve a consent screen | The wallet is about to issue authority. `REQ-222` requires the application to have been authenticated first, but the decision is still the person's. |
| Confirm before removing a device | Irreversible. `CON-210`'s revocation set is grow-only. |

## Related

- [[person-happy-paths]]
- [[SPEC-004-application-scoped-identity#Users and happy paths]]
