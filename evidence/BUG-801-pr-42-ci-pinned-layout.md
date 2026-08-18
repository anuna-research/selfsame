# BUG-801 — PR #42 CI did not reach the pinned dependency layout

- **Ownership:** process and environment
- **Detected by:** Forgejo Actions runs 270 and 271 on PR #42
- **Requirement:** SPEC-007 TEST-820 development completion evidence
- **Status:** repaired locally; Forgejo confirmation pending

## Red evidence

Run 270 stopped both jobs before their first test because `cbcl-pairing` was
not anonymously cloneable. Forgejo's automatic workflow token is scoped to
`selfsame` and cannot authorise a sibling repository.

After `cbcl-pairing` became public, run 271 proved the screens job green and
reached Rust. Rust then refused `Cargo.lock` under `--locked`: the lockfile had
been generated while the developer's `../cbcl-rs` checkout was at
`febc6691e6dd2d5f7116b1a4d84c984b64717564`, not Selfsame's declared
`1c6fa8f581a69a7bcb88fb787fa37c81f5de4221` pin. Regenerating against the
declared pin removed the stale path-package `sha2` edge. The next exact CI
command exposed two large state-machine enum variants and a Clippy-only
constant-assertion diagnostic.

## Repair

- Keep `cbcl-pairing` anonymously cloneable at its reviewed pin.
- Regenerate `Cargo.lock` against all three declared sibling revisions.
- Box the large live-session endpoint/bootstrap states without changing their
  transitions or effects.
- Preserve TEST-810 as a runtime mutation gate by passing the production hold
  constant through `std::hint::black_box` before asserting it is false.

## Local verification

The checks ran in `/private/tmp` with fresh sibling clones detached at exactly:

- `did-crdt` `fbccfd5885cd0c0136218f809ea0e183bc7e49f3`
- `cbcl-rs` `1c6fa8f581a69a7bcb88fb787fa37c81f5de4221`
- `cbcl-pairing` `197d4cb3d1560ab5328df28fc984269799c510f9`

Passing commands:

```text
cargo check --workspace --all-targets --locked --offline
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo test --workspace --locked --offline
cargo build -p selfsame-core --target wasm32-unknown-unknown --locked --offline
```

TEST-810 was also re-run with `PRODUCTION_ALLOCATION_ENABLED` temporarily set
to `true`; it failed at the runtime assertion, and passed again after the
mutation was restored.

This repair does not enable production invitation allocation and is not
production-gate evidence.
