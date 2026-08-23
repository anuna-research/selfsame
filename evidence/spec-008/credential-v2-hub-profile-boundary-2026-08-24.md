# Credential/v2 hub profile boundary — 2026-08-24

Scope: local test-first implementation evidence. Release and deployment remain
prohibited pending a fresh cross-model PASS and separate owner approval.

## Red

After adding the two TEST-117 boundary cases, this command failed because the
credential/v2 authority module did not exist:

```text
cargo test -p selfsame-beam --test credential_v2
error[E0432]: unresolved import `cbcl_selfsame_erl::credential_v2`
```

## Green

```text
cargo test -p selfsame-beam --test credential_v2
2 passed; 0 failed

cargo clippy -p selfsame-beam --all-targets -- -D warnings
finished successfully
```

The unpinned debug NIF was rebuilt locally and called from BEAM against the
exact profile served by `cbcl-chat-selfsame-application-gate`. It returned the
expected application, account authority, relay, profile and descriptor
digests, one declared permission, canonical installation JWK, and raw 32-byte
installation key.

Negative cases independently changed the application, relay, permission set,
permission multiplicity, JWK member set, and canonical spelling. Every case
returned no typed projection.
