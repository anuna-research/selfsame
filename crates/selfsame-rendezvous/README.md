# selfsame-rendezvous

The three routes [SPEC-001](../../anuna-ssi/specs/SPEC-001-device-key-provisioning.md)
adds to the `did-crdt` service, as a reference implementation.

SPEC-001 §6.12 places the rendezvous mailbox, signed-closure resolution, and
state publication on *"the `did-crdt` service (existing)"*. They live here so the
contracts are executable now; the durable home is upstream.

## Quick start

```bash
cargo run -p selfsame-rendezvous                       # 127.0.0.1:8787
SELFSAME_BIND=0.0.0.0:9000 cargo run -p selfsame-rendezvous
```

The default bind is loopback on purpose: this is a development service, and a
rendezvous reachable from the network is one more thing to reason about than the
SPEC-001 threat model currently covers.

## Usage

```
PUT  /rendezvous/{slot}      201 | 409 | 400   single-write, ≤ 4 KiB
GET  /rendezvous/{slot}      200 | 404         read-once, 600 s lifetime
POST /dids/{did}/deltas      202 | 409 | 400   idempotent publication
GET  /dids/{did}/closure     200 | 404 | 410   signed deltas, not a document
GET  /healthz                200
```

`{slot}` is 26 characters of RFC 4648 lowercase base32 — `BLAKE3("anuna-ssi/v1/slot/" ‖ role ‖ s)[0..16]`.
Anything else is refused before it reaches the store.

## Architecture

**The one thing this server must not do is make a trust decision.**

- CON-002: *"it is a blind mailbox and MUST NOT inspect the ciphertext or hold
  any key."* It holds neither. What it can see is `H(s)` and ciphertext — enough
  to withhold, never enough to substitute, because it cannot derive `s` from
  `H(s)` and therefore cannot forge an AEAD tag.
- CON-005 post-condition 3: *"the server applies no profile and its opinion is
  not consumed."* `GET /dids/{did}/closure` returns the **signed delta set**, in
  the exact bytes the signer produced. Upstream's `GET /:did` returns a resolved
  W3C document, which carries no signatures — a verifier consuming that would be
  trusting this server's authorisation decisions instead of applying REQ-003 and
  REQ-008 itself (REQ-025).

The one check publication *does* perform is structural, not a judgement on
anyone's behalf: a genesis delta must derive the DID it is posted under
(REQ-003), so the store cannot be filled by anyone who knows a DID string.

Two post-conditions are worth naming because they are security properties rather
than tidiness:

- **Single-write.** A slot cannot be overwritten mid-exchange, by the operator or
  by anyone who guesses an address.
- **Read-once.** A leaked slot address is stale almost immediately. Not a control
  on its own — the AEAD is — but it bounds the window.

## Development

```bash
cargo test -p selfsame-rendezvous
```

`tests/end_to_end.rs` runs the real server on a loopback port and drives both
endpoints through it: the client writes an offer, the phone reads it, authorises,
replies and publishes, the client accepts, and a third party then resolves the
closure and verifies. It also walks HP-5: revoke, re-resolve, and confirm the
device has left the authorised set while its label survives so the revoke screen
can still name it.

## Upstreaming

Storage is in-memory with a request-time sweeper, annotated `// SIMPLIFY:` with
its replacement: the `did-crdt` service's SQLite persistence layer (SPEC-034
there). The route handlers themselves are written against `did_crdt::core` and
should move across close to unchanged. Tracked as
[IMPL-ADR-008](../../anuna-ssi/specs/IMPL-001-device-key-provisioning.md).
