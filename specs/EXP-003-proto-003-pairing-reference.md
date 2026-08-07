---
id: EXP-003
title: PROTO-003 pairing reference and vector harness
status: active
tier: 3
audience: protocol implementer, cryptography reviewer, provider implementer
author: Anuna Research (prototype authorised 2026-08-07)
last-updated: 2026-08-07
owner-repo: selfsame
governs: PROTO-003 Selfsame Pairing Protocol v1
---

# EXP-003 — PROTO-003 pairing reference and vector harness

## Decision and hypothesis

The human owner confirmed on 2026-08-07 that PROTO-003 retains SPAKE2 with a
128-bit random `C`, rendered as twelve BIP-39 English words. `C` remains a
one-use bearer capability; SPAKE2 supplies the fresh mutually-confirmed key
which then derives the mailbox secret for the encrypted offer/grant exchange.

This experiment tests whether independent implementations can consume one
complete, byte-addressable vector shape without inventing field encodings or
transcript boundaries. It does **not** establish cryptographic correctness,
interoperability, or production readiness.

## Scope

- Define and validate the schema for candidate TEST-403 vectors.
- Build a pure harness that checks vector shape, fixed widths, and required
  fields without treating any fixture as normative cryptographic output.
- Record the API boundary needed by a future pairing provider: nameplate claim,
  opaque `pA`/`pB`/`cA`/`cB` relay, and terminal burn.

## Exclusions

- No production endpoint, provider deployment, relay, DHT, or record host.
- No claim that generated values implement SPAKE2 or satisfy CON-404.
- No Tier-1 gate box is checked and no protocol status changes.
- No replacement of required independent cryptography, privacy, operator, or
  security review.

## Exit criteria

The experiment converges only when the schema is canonical, its harness accepts
a labelled non-normative fixture and rejects each missing/wrong-width field, and
the reviewer packet names every still-unimplemented cryptographic and transport
obligation. A disagreement over encoding, M/N construction, transcript bytes,
or key schedule is an Error Response: record it and stop that surface rather
than inventing a normative answer.

## Evidence boundary

The eventual gate evidence remains PROTO-003 TEST-403: cryptographically
reviewed vectors reproduced byte-for-byte by two independent implementations.
This experiment only makes that future evidence package unambiguous.
