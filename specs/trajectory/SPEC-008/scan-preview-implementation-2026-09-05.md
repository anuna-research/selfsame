---
title: Native preview continuation and cancellation implementation evidence
date: 2026-09-05
doc_mode: explanation
status: local implementation; independent acceptance belongs to root
---

# Native preview continuation and cancellation

This isolated implementation addresses the native portion of
[[SPEC-077-selfsame-scan-pairing#TEST-004]] and
[[SPEC-077-selfsame-scan-pairing#CON-002]], implementing
[[SPEC-008-production-pairing-claimant#CON-986]] in the owner-authorized
0.5.18-draft revision. Root owns the UI render boundary, the Elephant task,
and independent integration acceptance. No Elephant changes were made.

The source contract was read from
`/Users/anuna-01/Code/cbcl-bus/specs/SPEC-077-selfsame-scan-pairing.md`
(version 0.1.1) and this checkout's SPEC-008. Base is
`ed6722f6f02a335e2cd5b455c72271b02ec3ff6a`; branch is
`circus/scan-native-preview/1`.

## Result and native boundary

`cbcl_v2_preliminary_decide(approve=true, passcode)` sends the original intent
decision and waits for its relay acknowledgement. It derives the local preview
once, retains the original decision and zeroizing DID, and returns:

```text
outcome: "preview"
finalReview:
  applicationId: authenticated application ID
  previewIssuerDid: locally derived DID
  previewFingerprint: existing Fp projection
  comparison: "waiting"
```

There is no preparation send or comparison wait in that command. Preliminary
decline retains the existing decision-send/declined-result behavior.

`cbcl_v2_compare()` has only the injected Session argument. It consumes the
preview-ready phase, sends preparation once using the held decision and DID,
and waits for the existing authenticated comparison/binding result. It returns
`CredentialV2FinalReviewView` with the existing
`no-binding-person-compared` or `bound-same-did` comparison value and saves the
comparison without replacing the held decision or preview. It performs no
custody call. Registration is added in `src-tauri/src/lib.rs`.

The same native phase guard protects preliminary consent, comparison, final
consent, and receipt continuation. Wrong-phase and duplicate calls fail before
preparation or grant authority is reached. Taking the socket also acquires the
single work lease, so concurrent invocations cannot reuse it.

## Cancellation mechanism

The [[Session]] retains an attempt token while an asynchronous command or
blocking worker owns its socket. The token uses shared Arc identity as the
attempt generation and an atomic cancellation bit. Cancellation invalidates it
under the Session mutex and drops idle relay/pairing state. A cancelled token
never becomes valid again. The Session generation check and state update occur
under the same mutex, so a stale result cannot replace a later attempt.

A weak work lease in Session bounds outstanding native work. A blocking
closure retains a strong lease even if its awaiting command is dropped.
Cancellation refuses a new attempt with `PairingAlreadyActive` until that work
has unwound; after the lease is released a new attempt can start. No task is
spawned by cancellation. This deliberately avoids accumulating workers behind
blocked sockets or custody prompts.

Checks bracket recognition/profile results, connection and relay-handshake
work, each explicit relay send, each relay read, preview derivation, comparison
return, final transaction boundaries, installation, and state reinsertion.
The final transaction's existing fault sink is wrapped so cancellation is
checked after an injected/blocking boundary as well as before it. Existing
pre-payload cleanup, exclusive offer-deadline checks, preview equality,
checkpoint sequencing, final effect assembly, authenticated receipts, and
installation predicates remain authoritative. Durable payload checkpoints keep
the existing sealed recovery path; cancellation does not delete those slots.

The placement uses standard-library Arc/atomic/weak references and the
existing transaction fault-sink boundary. It adds no dependency or protocol
primitive and changes no identity-core implementation.

## Behavioral red and green

The first tests were written against permissive extracted phase/cancellation
helpers before their checks were implemented. They executed and failed on
observable assertions; this was not an unresolved-symbol or compilation-only
red gate. Those helpers are now used by the production commands.

```text
cargo test -p selfsame --lib scan_preview -- --nocapture
RED: test result: FAILED. 0 passed; 4 failed; 0 ignored; 0 measured; 67 filtered out
GREEN (expanded suite): test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 67 filtered out
```

The focused test paths exercise:

| Test suffix after `scan_preview_` | Production path and observation |
|---|---|
| `returns_identity_before_continuation_and_derives_only_once` | `prepare_preview`, `review_projection`, and `continue_preview`: required return fields, waiting comparison, one derivation, no preparation until continuation, one continuation preparation |
| `continuation_is_single_use_and_wrong_phases_have_no_effects` | `CredentialV2Phase::require` used by `take_pending` and `continue_preview`: wrong phases and duplicate continuation refuse; preparation and grant counters remain zero on refusal |
| `cancel_blocked_continuation_refuses_send_and_return` | A channel-blocked `continue_preview` observes cancellation on release; its guarded send counter stays zero and the result is refused |
| `cancellation_during_derivation_or_comparison_erases_result` | Cancellation inside the production derivation/comparison helper callbacks prevents preview/final-review output |
| `cancelled_transport_sends_zero_frames` | Actual `send_binary` and `send_effects` on a loopback TCP/WebSocket; a cancelled token causes errors and the peer receives no bytes |
| `final_boundaries_refuse_cancellation_observed_after_wait` | `CancellationFaults` around each existing pre-payload boundary refuses when the inner boundary cancels the attempt |
| `blocking_wrapper_keeps_lease_after_command_is_dropped` | Actual `pairing_blocking` wrapper: abort the awaiting task, retain the blocked worker lease, refuse another attempt until it exits |
| `cancelled_generation_cannot_restore_or_replace_new_attempt` | Actual `Session::update_cbcl_v2_attempt` used for profile/pending reinsertion: stale updates refuse and a fresh attempt's state remains unchanged; a different live token also refuses |
| `profile_wait_and_aborted_worker_hold_one_attempt` | Actual attempt admission/lease helpers used before profile fetch and handshake: duplicate admission and replacement while an old worker remains active refuse |

After green, each mutation below was applied separately to the owned production
helper, tested with the same focused command, and restored. Each run compiled,
executed tests, and exited 101 with a behavioral failure:

| Removed guard | Observed test summary |
|---|---|
| Phase equality | FAILED: 7 passed; 2 failed |
| Cancellation-bit check | FAILED: 4 passed; 5 failed |
| Post-action cancellation check | FAILED: 8 passed; 1 failed |
| Session update generation validation | FAILED: 8 passed; 1 failed |
| Blocking worker's retained lease | FAILED: 8 passed; 1 failed |
| Post-boundary cancellation check in final continuation | FAILED: 8 passed; 1 failed |

## Commands and environment

All successful Cargo runs used this environment (equivalent to the inline
assignments in the transcript):

```sh
export SELFSAME_ALLOW_UNPINNED_CBCL_PAIRING=1
export CARGO_TARGET_DIR=/Volumes/anuna-03/codex-scan-native-preview-1/target
export TMPDIR=/Volumes/anuna-03/codex-scan-native-preview-1/tmp
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_INCREMENTAL=0
```

Toolchain: `rustc 1.96.0 (ac68faa20 2026-05-25)`;
`cargo 1.96.0 (30a34c682 2026-05-25)`.

```sh
cargo test -p selfsame --lib scan_preview -- --nocapture
cargo test -p selfsame
cargo test -p selfsame --lib cbcl_v2_completion::tests::test_1162_pre_payload_failure_and_person_abandonment_release_the_exact_slot -- --ignored --exact
cargo test -p selfsame-pairing --test credential_v2_offer
cargo check -p selfsame
rustfmt --edition 2021 --config skip_children=true src-tauri/src/cbcl_v2_commands.rs src-tauri/src/session.rs
rustfmt --check --edition 2021 --config skip_children=true src-tauri/src/cbcl_v2_commands.rs src-tauri/src/session.rs
git diff --check
```

Final native suite summaries: library `75 passed; 0 failed; 1 ignored`,
Android custody integration `2 passed`, closed-bundle integration `6 passed`.
The remaining native integration binaries retain their existing ignored
live-endpoint/platform-keychain tests. The isolated in-memory pre-payload
cleanup/recovery regression passed (`1 passed; 0 failed`), and the credential
protocol regression passed (`3 passed; 0 failed`). Cargo check, relevant-file
rustfmt check, and diff whitespace check exited 0. The native suite and checks
were run again after restoring the mutation guards.

Raw local logs are `/tmp/scan-native-preview-red.log`,
`/tmp/scan-native-preview-green.log`,
`/tmp/scan-native-preview-native-suite.log`,
`/tmp/scan-native-preview-recovery.log`,
`/tmp/scan-native-preview-credential-regression.log`,
`/tmp/scan-native-preview-check.log`, and
`/tmp/scan-native-preview-mutation-{phase,cancel-bit,post-action,session-update,worker-lease,final-boundary}.log`.
The summaries above are retained here because temporary logs are not durable
repository evidence.

The initial Cargo attempt using
`CARGO_TARGET_DIR=/Users/anuna-01/Code/selfsame/target` exhausted the system
volume before tests ran (`No space left on device`). It is an infrastructure
failure, not behavioral red evidence. Subsequent build output and compiler
temporary files used the attached volume. Source/dependency checkouts were not
moved or cleaned.

## Limits and acceptance handoff

These are local sibling-path results, not release-pin or end-to-end acceptance.
The build's explicit development override was necessary for this existing
sibling state:

| Sibling | Recorded pin | Observed HEAD and tracked state |
|---|---|---|
| cbcl-pairing | `62ef4a968b46b4836374fcee1d78c410f730a7a7` | `b703e31ea3d83a74e460fde90a9cf7f33cb6e0d0`, clean |
| cbcl-rs | `febc6691e6dd2d5f7116b1a4d84c984b64717564` | same HEAD, pre-existing tracked edits |
| did-crdt | `1f409a4229d07a62dd4cc6b2dce3b5a2e18e78a1` | `94db956d7d5d5edf0f42afad073ab42f265a1752`, pre-existing tracked edits |

No sibling, dependency pin, manifest, lockfile, WASM, UI, or Elephant edit is
part of this change. The shared handoff codec is not required by this native
preview implementation and handoff recognition remains independently owned.
Only the requested native files and this evidence file are committed.

The focused tests use production phase, generation, update, effect-boundary,
and blocking-work helpers. They do not drive a real wallet's custody prompt,
an authenticated remote relay handshake, or the full Tauri/UI invocation
chain. The native suite supplies existing transport and credential regression
coverage, but full Finished/grant/receipt integration and the actual rAF paint
boundary remain root's integration acceptance under
[[SPEC-077-selfsame-scan-pairing#TEST-003]],
[[SPEC-077-selfsame-scan-pairing#TEST-004]], and
[[SPEC-077-selfsame-scan-pairing#TEST-008]]. No live endpoint was contacted.

Cancellation is cooperative at the native boundaries. It cannot undo a send
or an atomic custody/network/storage operation already entered before the
worker observes the token. Existing transport I/O timeouts remain unchanged;
DNS/TLS connector internals and platform custody prompts are not redesigned or
claimed immediately interruptible. The work lease bounds outstanding work
while they unwind. Root should account for the temporary `PairingAlreadyActive`
response if a new scan arrives before that unwind completes. The UI epoch must
still suppress a result cancelled after its final native generation check.

The original exclusive deadline and final-effect guards were preserved rather
than redesigned. Independent acceptance of the full identity-effect/deadline
contract remains with root; these helper tests do not establish new claims
about identity-core internals. Root reviews the isolated integration commit
before accepting it. No push, deployment, or Circus acceptance/merge was done
by this worker.
