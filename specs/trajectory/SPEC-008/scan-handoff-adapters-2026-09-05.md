---
id: scan-handoff-adapters-2026-09-05
title: Native and WASM scan adapter evidence
mode: reference
status: local source verified; exact pin integration pending
date: 2026-09-05
---

# Native and WASM scan adapter evidence

The complete-handoff Tauri entry delegates to the shared recognizer under
[[SPEC-008-production-pairing-claimant#CON-986]]. Its pure input boundary checks
canonical encoding, commitment, expiry and expected allocator key before profile
fetching. The explicit legacy path shares profile/relay policy handling. Both
entries use the preview worker's attempt identity and cancellation guard.
No scanned string enters error text. Native expiry and version errors are closed.

The WASM allocator exports only its retained core handoff. QR rendering first
recognizes that handoff, then uses the existing Q-level encoder. Capacity refusal
preserves the intact copy route. A separate public-carrier expiry export uses the
existing canonical decoder and preserves the u64, allowing the browser to enforce
both the relay and authenticated hub deadlines.

Independent reviewer `pairing_ux_review` approved the native input and attempt
boundaries and identified a stale legacy presence-code cache after terminal core
errors. Root added a real allocated-session regression: terminal closure exposed
no handoff but incorrectly retained the legacy export. The test executed and
failed before repair. Removing the redundant cache makes both accessors delegate
to core state, including errors that return before effect capture. Temporary
serialization text uses Zeroizing. The reviewer approved the repair. The existing
restoration test now checks absence before allocation and captures presence only
after allocation.

Development validation uses Rust 1.96.0, external target/tmp directories, debug
information and incremental compilation disabled, and the explicitly labelled
SELFSAME_ALLOW_UNPINNED_CBCL_PAIRING override. The override remains necessary for
unrelated user-edited cbcl-rs and did-crdt siblings. These results are not release
provenance evidence. The pairing pin now names ec260d3dbedfe38155c591c7ac50cced8c634d69.

- `cargo test --locked -p selfsame --lib scan_`: ten tests pass, covering pure
  recognition and the native preview/cancellation boundaries.
- `cargo test --locked -p selfsame-web-device --lib`: QR, lifetime and public
  expiry tests plus existing library regressions: forty tests pass. The final command is retained
  in `/tmp/spec077-wasm-integrated.log` alongside allocator-session tests.
- `cargo test --locked -p selfsame-web-device --test credential_v2_allocator_session`:
  three tests pass, including real CPace transitions and persisted restoration.
- The initial QR stub executed two failed positive/capacity assertions; malformed
  input already refused. The implemented recognizer/encoder passes those cases.

Root next owns a clean exact-pin build and the native/served-WASM local integration
required by cbcl-bus SPEC-077 TEST-008. Device camera hardware and platform custody
are not claimed by the controlled UI bridge or these native library tests.

Mechanical audit (`usdd-count.sh` on this evidence file):

```text
artefacts   CON=1 TEST=1 SPEC=2
gate rows   0  (pass=0 fail=0 unverified=0)
wikilinks   1  (anchored=1)
```
