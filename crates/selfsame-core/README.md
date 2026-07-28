# selfsame-core

Every security decision in [SPEC-001](../../anuna-ssi/specs/SPEC-001-device-key-provisioning.md),
written once, in one crate, with no I/O.

The phone, the browser, and `hark` all have to apply the *same* predicate to the
*same* wire records. Three implementations of one security predicate is the
parser-differential failure LangSec Principle 5 prohibits, so this crate is the
single machined part every runtime links.

## Quick start

```rust
use selfsame_core::{accept, record::{Application, Offer}, LinkContext};

// A device client mints an offer over its own wire key.
let offer = Offer::sign(Application::CbclChat, &signing_key, "Chrome on macOS", expiry);

// …writes it to the rendezvous, shows the code, and waits. When a reply
// arrives, one call decides everything.
match accept(&sealed, &LinkContext { secret, offer }, now) {
    Ok(identity) => println!("{} — {}", identity.did, identity.fingerprint.hex()),
    Err(_) => println!("Couldn't link — the reply didn't match this device."),
}
```

`accept` is pure and total. It reads no clock (`now` is a parameter), touches no
storage, and makes no network call — so a rejected bundle cannot leave partial
state behind, and the DID↔device-key binding is verifiable with the network
stack removed (NFR-006, REQ-017).

## Usage

### Verifying a bundle — the whole of CON-003

`accept` returns `Result<AcceptedIdentity, RejectReason>`, and `RejectReason` is
a closed enum with one variant per post-condition, so a failure attributes to a
single requirement:

| Conjunct | Requirement | Variant |
|---|---|---|
| `transcript_ok` | REQ-006 | `TranscriptMismatch` |
| `not_expired` | REQ-016 | `Expired` |
| `did_matches_genesis` | REQ-003 | `DidMismatch` |
| `profile_signer_ok` | REQ-008 | `ForeignSigner` |
| `own_key_authorised` | REQ-015 | `OwnKeyNotAuthorised` |
| `no_capabilities` | REQ-013 | — dropped, never a rejection |
| `atomic` | REQ-017 | — guaranteed by the signature |

**Do not show a `RejectReason` to a user.** SCREEN-002 S4 shows one line,
because a reason teaches the user nothing and leaks which check failed.

### Verifying someone else — REQ-025

```rust
let document = profile::resolve_closure(&deltas, &root_public_key)?;
let resolved = document.resolve()?.did_document.unwrap();
let authorised = resolved.verification_method.iter()
    .any(|vm| vm.public_key_multibase == mb::encode(&their_key));
```

Note what this is *not*: it is not `GET /:did`. Upstream's resolution endpoint
returns a resolved W3C document, which carries no signatures — so the
single-controller profile could not be applied to it and you would be trusting
the resolver's authorisation decisions rather than making your own.

### The two fingerprints — REQ-007

They are **distinct functions over distinct inputs** and are never compared
against each other:

- `fingerprint_key(&public_key)` — what the phone shows before authorising,
  compared against what the linking client shows for its own key.
- `fingerprint_did(&did)` — what the client shows after accepting, compared
  against what the phone showed at identity creation.

`Fingerprint::hex()` is the normative comparison rendering (48 bits, against
NFR-008's floor of 32). `Fingerprint::label()` is a list-row nickname carrying
≈ 18.6 bits and is **not** a comparison value.

## Architecture

This crate is the pure core of
[SPEC-001 §13](../../anuna-ssi/specs/SPEC-001-device-key-provisioning.md). Dependencies
point inward: shells import this, this imports nothing effectful.

```
  Selfsame · browser · hark          ← effectful shell
              │
              ▼
   mb  code  record  seal             ← recognisers and codecs
   profile  accept  fingerprint       ← the predicate
   derive  identity                   ← key and delta construction
              │
              ▼
  cbcl-core · cbcl-parser · did_crdt::core
```

| Module | Contract | Obligation |
|---|---|---|
| `mb` | CON-001, CON-002 | REQ-027 — one canonical binary spelling |
| `code` | CON-001 | REQ-005, REQ-011 — the Bech32m link code |
| `record` | CON-001, CON-002 | ADR-013 — the CBCL offer and grant |
| `seal` | CON-002 | REQ-006 — HKDF + AEAD, transcript-bound |
| `profile` | — | REQ-008 — the single-controller signer filter |
| `accept` | CON-003 | the acceptance predicate |
| `fingerprint` | CON-003 | REQ-007, NFR-008 |
| `derive` | CON-007 | REQ-001, REQ-002 |
| `identity` | — | REQ-003, REQ-010, REQ-020, REQ-021, ADR-010 |

Design decisions that are not obvious from the code are recorded in
[IMPL-001 §3](../../anuna-ssi/specs/IMPL-001-device-key-provisioning.md) — in particular
why the wire form and the signing form differ, and why the transcript commits to
the canonical encoding.

## Development

```bash
cargo test -p selfsame-core                              # 129 tests
cargo build -p selfsame-core --target wasm32-unknown-unknown
cargo test -p selfsame-core --test purity                # the §13 gate
cargo test -p selfsame-core --test hostile_rendezvous    # NFR-003
```

### The purity gate

`tests/purity.rs` fails if `tokio`, `reqwest`, `hyper`, `axum`, or a TLS stack
enters the normal dependency graph, and if any non-test source names `std::fs`,
`std::net`, `std::time`, `SystemTime`, `std::process`, or `std::env`. It is not
a style rule: a core that cannot reach a socket cannot make a network call, which
is how TEST-033's negative-output is discharged.

### Regenerating the test vectors

Don't, unless you mean it.

```bash
cargo test -p selfsame-core --test vectors -- --ignored regenerate
```

`test-vectors/spec-001-v1.json` is Tier-1 gate condition B. Regenerating it
after anything has shipped **re-derives every existing identity**. That is why
it is a separate, ignored, explicitly-named command rather than something the
checking test does when the file is missing.
