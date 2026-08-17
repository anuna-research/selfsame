---
title: cbcl-pairing
mode: reference
last-updated: 2026-08-17
---

# cbcl-pairing

`cbcl-pairing` is the sibling repository that supplies Selfsame's reusable pairing engine.

## SPEC-001

The normative source is `../cbcl-pairing/specs/SPEC-001-reusable-blind-pairing.md`.
Selfsame consumes the exact local revision recorded by [[SPEC-006-cbcl-pairing-integration#ADR-702]].

The crate owns invitation recognition, CPace, both Finished values, CBCL role projection,
secure channel framing, endpoint effects, blind mailbox transitions, and relay limits.

The crate remains experimental. Production invitation allocation is disabled pending its
human cryptography, adversarial, profile-integration, and owner-approval gates.
