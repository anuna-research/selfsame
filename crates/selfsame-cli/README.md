# selfsame

The device-client half of [SPEC-001](../../anuna-ssi/specs/SPEC-001-device-key-provisioning.md)
linking: mint the code, write the signed offer, apply the acceptance predicate,
report the identity joined.

This is the reference for `hark link` and the terminal form of
[SCREEN-002](../../anuna-ssi/specs/SCREEN-002-link-panel.md), which *"carries the same
three pieces of information in the same order"* as the browser panel.

## Quick start

```bash
cargo run -p selfsame-rendezvous &        # something to talk to

export SELFSAME_ENDPOINT=http://127.0.0.1:8787
cargo run -p selfsame -- link             # scan the QR with Selfsame
cargo run -p selfsame -- status
```

## Usage

```
selfsame link                 request linkage and report the identity joined
selfsame status               show whether this device is linked
selfsame verify DID KEY       is KEY authorised by DID right now?
selfsame unlink               forget the identity locally
```

### `link` — HP-2 and HP-3

Draws a fresh 128-bit secret, signs an offer over this device's own wire key,
writes it to the slot addressed by `H(s)`, and shows the code as **both** a QR
and a 41-character string. The typed form is not a fallback behind "having
trouble?" — REQ-011 makes it a first-class route, and a user without a camera
must not have to discover it.

On success it prints the DID and its fingerprint and asks one question: does this
match what your phone showed when you created your home key? That comparison is
the human backstop behind REQ-006 (trust assumption A6), and a confirmation the
user waves past is not a backstop.

On failure it prints one line — *"Couldn't link — the reply didn't match this
device."* — and nothing else. The `RejectReason` reaches the operator only under
`SELFSAME_DEBUG`, because a reason teaches the user nothing and leaks which
check failed.

### `verify` — HP-4

Fetches the **signed closure**, recomputes the DID from the genesis (REQ-003),
applies the single-controller profile locally (REQ-008), and answers from the
document it resolved itself (REQ-025). Exits non-zero if the key is not
authorised, so it composes into a script.

### `unlink` is local only

It forgets the identity on this machine. It does **not** revoke: revocation
needs the root key and a published delta, and it is done from Selfsame — which
works whether or not this machine is switched on. The command says so.

## Architecture

Effectful shell over `selfsame-core`. It owns the wire key, the network, the
terminal, and the clock; the core owns every decision.

| File | Role |
|---|---|
| `main.rs` | commands, the QR, the countdown, the compiled endpoint table |
| `store.rs` | `device.key` and `identity.json` under `~/.config/selfsame/` |

Two details in `store.rs` are requirements rather than housekeeping:

- **`device.key` is created `0600`, at creation** — not chmod'ed afterwards, so
  there is no window in which it is world-readable. REQ-004: the key is generated
  on the device that uses it and its private half never leaves.
- **`identity.json` is re-verified on load**, not trusted because we wrote it. A
  client that believed a tampered file would render attribution it never actually
  checked (REQ-009 fail-closed). It is written to a temporary file and renamed,
  so a crash cannot leave half an identity — REQ-017's atomicity one layer down.

ADR-004 in practice: the device key here is a file of the same shape as `hark`'s
`router-agent.key`. **Linking adds no new key material** — it adds a statement
about the key that already exists.

## Development

```bash
cargo build -p selfsame
SELFSAME_HOME=$(mktemp -d) cargo run -p selfsame -- status   # a clean device
SELFSAME_DEBUG=1 cargo run -p selfsame -- link               # show reject reasons
```

`SELFSAME_ENDPOINT` overrides the compiled endpoint table for local
development. It is an operator-controlled variable, not a value that reaches the
process from a scanned code — which is the thing REQ-026 forbids.
