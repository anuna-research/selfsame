---
id: EXP-003-reviewer-packet
title: EXP-003 reviewer packet — what PROTO-003 still owes before TEST-403
status: active
tier: 3
audience: cryptography reviewer, protocol implementer, provider implementer
last-updated: 2026-08-14
owner-repo: selfsame
governs: PROTO-003 Selfsame Pairing Protocol v1
---

# EXP-003 reviewer packet

[[EXP-003-proto-003-pairing-reference]] converges only when *"the reviewer packet
names every still-unimplemented cryptographic and transport obligation"*. This is
that packet. It is a list of what does **not** exist, written so a reviewer can
tell the difference between a gap and an oversight.

**Nothing here checks a cryptographic relation, and nothing here is evidence for
[[PROTO-003-selfsame-pairing-v1]]'s Tier-1 Gate.** The eventual gate evidence
remains TEST-403: reviewed vectors reproduced byte-for-byte by two independent
implementations. This experiment only makes that future package unambiguous.

## What EXP-003 has produced

| artefact | what it establishes |
|---|---|
| `test-vectors/proto-003-spake2-v1.schema.json` | the candidate TEST-403 vector shape, closed |
| `test-vectors/proto-003-spake2-v1.non-normative.json` | one fixture of that shape, labelled `non-normative` |
| `scripts/validate-proto003-vector.mjs` | a structural harness — widths, required members, closed shape |
| `scripts/validate-proto003-vector.test.mjs` | that the harness **refuses** each missing and each wrong-width field |

The last row is the one worth naming. An accept-only harness demonstrates that
one fixture passes and nothing about what is rejected; a validator never shown to
refuse is indistinguishable from one that returns true.

## Cryptographic obligations, unmet

1. **No conforming SPAKE2 implementation exists for this protocol.** The
   construction is specified — ristretto255, `M`/`N` from `FROM_UNIFORM_BYTES`
   over the `v1` hash strings, `w_bytes` via HKDF-SHA256 under the
   `selfsame-pairing-v2` domain — and nothing implements it.

2. **The nearest existing implementation is in the wrong process, and cannot
   simply be reused.** `cbcl-bus`'s `cbcl-crypto-spake2` is RFC 9382 framing on
   ristretto255 with the same `M`/`N` derivation and word-index packing, which
   PROTO-003 adopts deliberately. But its roles are *initiator (agent)* and
   *responder (router)* — the hub is one of the two PAKE endpoints there.
   [[SPEC-053-key-root-identity#REQ-018]] forbids exactly that here: the
   endpoints are the wallet and the browser, and the provider relays only.
   **The algorithm transfers; the deployment does not.**

3. **Neither device end has one.** The browser would need it through
   `selfsame-web-device` (wasm) and the wallet through the application. Neither
   has any SPAKE2 today.

4. **An off-the-shelf crate does not close this.** `spake2` on crates.io is
   Ed25519 following the earlier CFRG draft — different group, different `M`/`N`,
   different transcript and key schedule, so the same words yield a different
   key. PROTO-003 states its ciphersuite and domain constants are
   protocol-specific and *"MUST NOT be described as an RFC 9382 registered …
   ciphersuite"*. The reusable layer is the group primitive
   (`curve25519-dalek`'s `RistrettoPoint::from_uniform_bytes` is precisely
   `FROM_UNIFORM_BYTES`), not a SPAKE2 crate.

5. **No value in the fixture is a SPAKE2 output.** Every field is
   structurally shaped and cryptographically meaningless. `status:
   "non-normative"` is enforced by the harness so this cannot be forgotten
   downstream.

6. **TEST-403's two independent implementations do not exist.** Today there are
   zero conforming ones. The plausible pair is the LFE core re-instantiated under
   the `v2` domain and a Rust/wasm implementation for the device ends — two
   languages, two codebases, one specification.

## Transport obligations, unmet

7. **No provider is deployed or declared.** [[SPEC-053-key-root-identity#OQ-004]]
   now names the operator — the `cbcl-bus` deployment, separably — but no
   descriptor exists in any ratified profile, and
   `RATIFIED_PROFILE_BASE64URL` is `null`.

8. **Both hub surfaces are written and deliberately unrouted.**
   `cbcl-chat-selfsame-pair-gate:routed?/0` and
   `cbcl-chat-rendezvous-gate:routed?/0` each return `false` as a source
   constant. They are two enablement points for two blast radii, and neither is
   a configuration flag.

9. **The nameplate/claim/burn boundary is implemented but unexercised in the
   ceremony.** The relay accepts allocate, claim, `pA`/`pB`/`cA`/`cB` put/get,
   and rate-limits per peer, failing closed when the limiter is absent. What it
   does **not** do is burn on a wrong guess: a mismatched claim returns
   `conflict` and leaves the record intact. Guessing is defended by 128-bit
   addressing and rate limiting. **Burn-on-wrong-password is a SPAKE2
   confirmation property, and it is absent for the same reason as item 1.**
   A reviewer should decide whether the relay owes an attempt counter
   independently of the PAKE.

10. **The client cannot start a ceremony.** In `cbcl-bus`, `setCode` has no
    caller, no adapter is constructed, and the pairing transport is never
    supplied — so `canPair` is permanently false and the surface says so.

## Error Responses recorded, not resolved

EXP-003 directs that *"a disagreement over encoding, M/N construction,
transcript bytes, or key schedule is an Error Response: record it and stop that
surface rather than inventing a normative answer."*

- **`v1` hash strings inside a `v2` domain.** `M`/`N` derive from strings ending
  `Hash v1` while the KDF and confirmation labels are `selfsame-pairing-v2`.
  This reads as deliberate — the group constants are inherited from the existing
  primitive while the domain separation is new — but the mixed versioning is
  exactly the kind of thing two implementations read differently, and it is
  recorded here rather than normalised.

No other disagreement was found. Nothing in this packet resolves one.
