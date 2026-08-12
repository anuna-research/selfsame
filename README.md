# Selfsame

**Your browser, your CLI, and your phone are the selfsame person — and this
makes that checkable.**

Selfsame is a root-key custodian. You create one identity on your phone; every
other client you use gets authorised from it, and other people can verify that
those clients really are you rather than taking your word for it. Lose a laptop
and you revoke it from the phone, without needing the laptop back.

*The phone is the home key; every other client gets a copy cut from it, and the
phone can change the lock.*

> ## Not cleared for production
>
> This implements [SPEC-001][spec] as written. That specification is `draft`
> behind a **Tier-1 gate that has not been passed** — round-2 cross-model
> adversarial review and human security sign-off are outstanding, and three
> open questions are gate-blocking (key reuse across four contexts, verifiable
> resolver freshness, and frame authorship in plaintext channels).
>
> Mutation testing of the acceptance predicate — which the specification
> requires at a 100 % kill rate — **has not been run**. Do not put an identity
> you rely on into this.

## What it looks like

| The home key, and every client cut from it | Nothing is granted without you |
|---|---|
| ![Selfsame home screen: the home key rendered as a LifeHash picture above the fingerprint 2E 41 D0 88 6B 15, the petname garnet-plover-31, and the did:crdt identifier; below it a device list showing Chrome on macOS, hark on workstation-01 still publishing, and a revoked Firefox on the old laptop struck through](https://imagedelivery.net/O-SJhBv1S1zUZFvTxrBOhQ/a95f6456-6790-486b-8930-3d378776be00/public) | ![Selfsame consent screen asking "Let this application act for your account?", showing the origin that asked, the name it calls itself marked "its own words, unchecked", the account it is for, and the two capabilities it gains — one of them "not recognised by this wallet" — above Allow and No](https://imagedelivery.net/O-SJhBv1S1zUZFvTxrBOhQ/fd33d347-6639-47b9-2ee2-86b1e6e52c00/public) |
| Every key carries the same 48 bits three ways — hex, picture, petname — and each linked client shows its own. Revocation is a line through a row, done from the phone. | The origin that asked is the fact; the name beside it is that application's own claim, labelled as unchecked. A capability the wallet doesn't recognise says so rather than being quietly summarised. |

## Before you build

Selfsame depends on two sibling repositories by path. Clone them next to this
one or nothing compiles:

```
Code/
├── selfsame/     ← you are here
├── did-crdt/     git clone https://git.anuna.io/anuna-research/did-crdt
└── cbcl-rs/      git clone https://git.anuna.io/anuna-research/cbcl-rs
```

`did-crdt` is pinned at `9a53bff1ed3eb88680fe19db0366ffd13d6b240a` — its DID
derivation is adopted verbatim and a change to it is a breaking change to the
protocol. `crates/selfsame-core/tests/pinned_derivation.rs` fails if it drifts,
and `tests/vectors.rs` records the revision the test vectors were generated
against, which is the copy CI clones.

`cbcl-rs` is pinned by `cbcl-rs.sha` at the repository root — the same
convention `cbcl-bus` uses for the `cbcl-erl` NIF.

## Quick start

```bash
cargo test --workspace                  # 150 tests

# terminal 1 — the rendezvous and resolver
cargo run -p selfsame-rendezvous

# terminal 2 — the phone
SELFSAME_ENDPOINT=http://127.0.0.1:8787 cargo run -p selfsame

# terminal 3 — a device asking to be linked
SELFSAME_ENDPOINT=http://127.0.0.1:8787 cargo run -p selfsame-cli -- link
```

Create a home key in the app, write down the twelve words, confirm three of
them, then paste the code the CLI prints into *Link a device → Enter the code by
hand*. Full walkthrough: [docs/using-selfsame.md](docs/using-selfsame.md).

## What's here

| Path | What it is |
|---|---|
| `crates/selfsame-core` | the pure core — **every security decision in the system, written once** |
| `src-tauri`, `src` | the phone app: custody, consent, signing, revocation |
| `crates/selfsame-rendezvous` | the blind mailbox and resolver routes, destined for `did-crdt` |
| `crates/selfsame-cli` | the device client — the reference for `hark link` |

## How it works

`did:crdt` derives a DID from a BLAKE3 hash committing to your root key, so an
identity document is **self-certifying**: anyone holding the signed deltas can
check *"is this really this identity's document?"* with a hash and a signature —
no blockchain, no key-transparency log, no trusted registry.

Your phone holds that root key. A client shows a 41-character code carrying a
128-bit secret and leaves a *signed* offer — proving it holds the key it wants
authorised — in a mailbox addressed by `H(secret)`. The phone reads the code,
verifies the offer, shows you what it is about to authorise, and puts back a
credential bundle sealed to that exact offer.

```
   phone ──reads code (out of band)──▶ derives K=HKDF(s), verifies signed offer
     │                                              │
     │  writes bundle sealed with AEAD(K, ad=H(offer))
     ▼                                              ▼
   blind mailbox: sees only H(s) and ciphertext ──▶ browser / CLI
                                                     └ checks: our transcript,
                                                       DID↔genesis, one signer,
                                                       our own key
```

The mailbox operator sees `H(s)` and ciphertext and nothing else. It can
withhold; it cannot substitute. `crates/selfsame-core/tests/hostile_rendezvous.rs`
gives it every power that concession allows and asserts what still holds.

### The human backstop

The last check is a person, comparing a 48-bit fingerprint across two screens.
Every key Selfsame shows you — on the phone and in the CLI — is rendered three
ways from one digest:

| Rendering | Carries | Job |
|---|---|---|
| `C0 7A 1E 42 9B 33` | 48 bits | **the value you compare.** Every question a screen asks is about this |
| a [LifeHash] picture | the same 48 bits | recognition — you notice a change before you can read one |
| `copper-lynx-42` | ≈18.6 bits | names a row in a list; never compared |

The picture is [LifeHash] v2 — Conway's Game of Life seeded from the digest,
then coloured and mirrored. It is computed from the *fingerprint*, not from the
key, so the picture and the hex cannot disagree: same hex, same picture,
necessarily. It replaced three colour bars that consumed half the digest and
lived only on one screen of the phone app.

It is a recognition aid, not the comparison. Promoting it would move SPEC-001's
human backstop, which is gated behind that specification's outstanding Tier-1
review — see [SPEC-002] ADR-107.

[LifeHash]: https://lifehash.info/
[SPEC-002]: specs/SPEC-002-visual-key-fingerprint.md

## Architecture

Dependencies point inward. The pure core makes every decision; the shells do
I/O and presentation and nothing else.

```
  app (Tauri) · rendezvous · cli        ← effectful shell
              │
              ▼
   mb  code  record  seal               ← recognisers and codecs
   profile  accept  fingerprint         ← the predicate
   derive  identity                     ← key and delta construction
              │
              ▼
  cbcl-core · cbcl-parser · did_crdt::core
```

`crates/selfsame-core/tests/purity.rs` enforces that boundary: it fails if
`tokio`, `reqwest`, `hyper`, `axum`, or a TLS stack enters the core's dependency
graph, or if any core module reaches for a clock, a socket, or a disk. The core
compiles to `wasm32-unknown-unknown`.

The webview holds **no security logic**. It cannot reach the root key; it can
only ask the Rust side to use it, and every such call carries a user-presence
check.

### The name is the brand; `anuna-ssi/v1` is the protocol

You will see `anuna-ssi/v1/...` throughout the code — in HKDF info strings, AEAD
associated data, slot derivation, and the CBCL dialect name. **Those are wire
format**, fixed by SPEC-001 and pinned by `test-vectors/spec-001-v1.json`.
Renaming them would change every signature, every mailbox address, and every
DID. They are deliberately untouched by the rename to Selfsame.

## Development

```bash
cargo test --workspace
cargo clippy --workspace --all-targets
cargo build -p selfsame-core --target wasm32-unknown-unknown

npm install && npm run screens      # render all 17 screens headlessly
```

All four run on every push and pull request — `.forgejo/workflows/ci.yml`.

`tests/screens.mjs` walks every screen with a stubbed Tauri bridge and asserts
what Rust cannot see: one screen visible at a time, no horizontal overflow at
phone width, no console errors, and — after a bug that shipped a black
rectangle — that a *missing* bridge renders an explanation.

### Test vectors

`test-vectors/spec-001-v1.json` fixes the root-key derivation, the DID
derivation, link codes, slot addresses, and fingerprints, so a second runtime
can be checked against the same file. Regenerating it after anything ships
**re-derives every existing identity**, which is why it is a separate, ignored,
explicitly-named command:

```bash
cargo test -p selfsame-core --test vectors -- --ignored regenerate
```

## Specification

The original device-provisioning design lives in the
[`anuna-ssi`][spec] vault. This repository now also owns:

- [SPEC-004](specs/SPEC-004-application-scoped-identity.md), the
  application/account identity and grant profile;
- [PROTO-002](specs/PROTO-002-selfsame-rendezvous-v1.md), the blind encrypted
  offer/grant mailbox; and
- [PROTO-003](specs/PROTO-003-selfsame-pairing-v1.md), the routable
  `number-word-word` SPAKE2 pairing ceremony.

[spec]: ../anuna-ssi/specs/SPEC-001-device-key-provisioning.md

## Licence

Copyright 2026 Anuna Research Pty Ltd. Apache-2.0.
