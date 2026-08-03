# End-to-end linking harness

One [SPEC-001] linking ceremony between two genuinely separate clients, with an
assertion that both independently arrive at the same identity.

This is [EXP-002]'s apparatus. It is a **governed spike**, not a shipped test
suite: it gates nothing, runs on one developer machine, and exists to settle
three unknowns about driving the real application. Read the brief before
changing it — several things here look accidental and are not.

## Quick start

```bash
npm run e2e:preflight     # what is missing, and the command that supplies it
npm run e2e:wasm          # build the browser client's wasm package
npm run e2e               # run the ceremony (layer two)
```

`E2E_VERBOSE=1` prints every JSON line to and from `ar-crawl`, plus the
rendezvous log. It is the first thing to reach for when a run stalls.

## The three layers

Each layer swaps exactly **one** thing for its real counterpart. That ordering
is the whole design: by the time the emulator is involved, everything except the
emulator has been proven, so a red run means the wallet — not the wire, and not
the wasm.

| Layer | Device side | Phone side | Needs | Status |
|---|---|---|---|---|
| 1 | `Device` in Rust | scripted, in Rust | nothing | green |
| 2 | `Device` in wasm, in a browser | scripted, in Rust | a browser | green |
| 3 | `Device` in wasm, in a browser | the real application | an emulator | **unrun** |

Layer 1 is `crates/selfsame-web-device/tests/against_the_real_rendezvous.rs` and
runs under `cargo test`. Layers 2 and 3 are `driver.mjs`, selected with
`--wallet scripted` (the default) and `--wallet emulator`.

## What runs where

```
  ┌──────────────────────── host ─────────────────────────┐
  │  driver.mjs ─── stdin/JSON ───┐                        │
  │      │                        ▼                        │
  │      │              ar-crawl session (Chrome)          │
  │      │                        │ drives                 │
  │      │                        ▼                        │
  │      │              device page + wasm                 │
  │      │                        │ HTTP, same origin      │
  │      │                        ▼                        │
  │      │              page server ──proxy──▶ rendezvous  │
  │      │                                                 │
  │      └─ stdin/JSON ─▶ ar-crawl android session ──┐     │
  └─────────────────────────────────────────────────┼─────┘
                                                    ▼
                                        ┌─── emulator ────┐
                                        │  Selfsame APK   │
                                        └─────────────────┘
```

The proxy is not incidental — see FINDING-018 below.

## Things that look wrong and are deliberate

**The link code passes through the driver.** `ar-crawl` can record and replay a
session, and this is not one. The link secret is drawn fresh in the browser
every run, so the code does not exist until the run starts and no recording can
carry it. Replay stays useful for sub-flows and screenshot regression.

**The scripted phone is a Rust program, not JavaScript.** The harness's value is
that *one* implementation of the offer format, the slot derivation and the
acceptance predicate is exercised from both ends. A phone written in the driver
would be the parser differential `CON-205` exists to prevent — with both copies
in this repository, which is worse than having one elsewhere.

**Every cargo call passes `--locked`.** Without it, `cargo` and `wasm-pack`
silently rewrite `Cargo.lock` to match whichever sibling checkouts happen to be
present, the harness passes, and CI then fails on a lockfile the harness itself
changed. If the harness refuses to build, check `../cbcl-rs` and `../did-crdt`
against the pins in `cbcl-rs.sha` and `crates/selfsame-core/tests/vectors.rs`.

**The rendezvous is proxied through the page's own origin.** FINDING-018: the
dev rendezvous sends no CORS headers, so a browser device client cannot reach it
cross-origin at all. The proxy sidesteps that without changing the service — and
the cost is that this harness **does not** prove a browser can reach the service
cross-origin, which is precisely what the finding says it cannot.

**`--wallet emulator` refuses loudly rather than skipping.** A wallet stub that
passed would report success for a ceremony that never happened.

## Layer three is written and has never been run

There is no Android SDK on the machine this was authored on. Every line of
`emulatorWallet` is unverified, and it is built to **report** what it finds
rather than assume:

- **U1** — whether `ar-crawl android`'s `webviews` can reach the Tauri
  [WebView]'s DOM. If it can, the harness uses the same `data-action` selectors
  `tests/screens.mjs` uses. If it cannot, it falls back to native text
  selectors, says so, and then **fails** rather than passing — because without
  the DOM it cannot read the identity the wallet reached, and that is the one
  assertion the harness exists to make.
- **U2** — how the application is pointed at a loopback rendezvous. `adb
  reverse` handles the transport; telling the app is the hard half. The harness
  tries `setprop wrap.<package>`, which needs no source change. If that fails it
  stops and names EXP-002 Q1, the debug-only cargo feature, as the owner's
  decision — it does not quietly patch the application.
- **U3** — the biometric presence check, answered with `adb emu finger touch`.
  Best-effort: on a build using the typed passcode there is no prompt.

Running it is how these get answered. Expect the first run to fail somewhere
interesting; that is the point of a spike, and each failure is a finding for
EXP-002 rather than a bug in the harness.

[SPEC-001]: ../../specs/EXP-002-e2e-linking-harness.md
[EXP-002]: ../../specs/EXP-002-e2e-linking-harness.md
[WebView]: ../../specs/EXP-002-e2e-linking-harness.md
