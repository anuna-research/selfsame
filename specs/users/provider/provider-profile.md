# User: The infrastructure provider

| Field | Value |
|---|---|
| group | `provider` |
| governs | [[SPEC-004-application-scoped-identity]], [[PROTO-002-selfsame-rendezvous-v1]], [[PROTO-003-selfsame-pairing-v1]] |
| status | draft — authored under [[EXP-001-spec-004-reference-implementation]] |

## Role

Operates one or more of the rendezvous, pairing, state, account, or
status-projection functions. May be the adopting developer themselves,
a commercial operator, or Anuna — and `CON-201` is explicit that all three have
**identical standing**.

## Goals

1. Serve traffic without becoming liable for what it means.
2. Be replaceable, and be seen to be replaceable — that is what makes them
   adoptable.
3. Not hold anything whose loss would be a breach.

## Constraints

- **They are not a trust anchor, and the design keeps it that way.** `REQ-228`:
  the provider "SHALL receive no word, word index, password-equivalent verifier,
  PAKE key, mailbox key, offer/grant plaintext, DID, account scope, or
  authorization decision."
- **Co-location confers nothing.** Running both the pairing and mailbox services,
  or a state resolver beside a rendezvous, grants no application, account,
  DID-state, credential, or PAKE authority.
- **Conformance, not identity, makes them eligible.** `REQ-219`: "Operator
  identity, commercial relationship, co-location with a state resolver, or an
  Anuna allowlist SHALL NOT substitute for protocol conformance."

## What they can and cannot do

| Can | Cannot |
|---|---|
| Withhold or lag state | Forge, clear, or override a G-Set entry |
| Refuse a mailbox write | Read an offer or grant plaintext |
| See ceremony timing and volume | See which account or person a ceremony is for |
| Serve a `CON-409` record | Substitute one — records are self-authenticating |
| Publish a status projection | Un-revoke a grant, or authorize a device |

The asymmetry is deliberate: an operator can always deny service, and can never
grant authority. `CON-210`'s resolver diversity and `REQ-208`'s propagation
bound exist because denial is the residual threat once forgery is closed.

## What Anuna specifically may not become

The Infrastructure promise, and `REQ-210` enforcing it: an Anuna node a developer
*chooses and declares* is an ordinary declared resolver. The same node reached
because a profile failed to name one is exactly what the requirement forbids. An
implementation must not special-case any operator, and `tests/purity.rs` checks
that no such endpoint is compiled into the core at all.
