# SPEC-079 native SingleLink consent evidence

This evidence covers the bounded native-consent implementation at Selfsame base
`3c92cafc6b6d60659ed01f34cb7e770d2d4012dc`, with the exact clean
`cbcl-pairing` sibling `ffb348d2d840dcc43d6ead2681b5fbf9a886e363`.
It implements the default complete scan/paste SingleLink flow and preserves the
explicit legacy two-decision flow. Manual pairing UI belongs to the later
wallet-manual increment. Exact native/served-browser closure remains the root
integration task under SPEC-079 TEST-011.

## Implemented boundaries

- `cbcl_v2_begin_handoff` recognizes complete input and reserves a fresh native
  attempt before contact. `cbcl_v2_contact` performs live profile and exact
  relay authorization under the same tag. SingleLink never reads or writes the
  legacy exact-pair policy.
- `cbcl_v2_unlock_preview` performs one presence operation, derives only the
  local DID/fingerprint preview, clears the renderer passcode, and retains a
  zeroizing native root under an exclusive deadline. It creates no protocol
  decision, preparation, signature, identity effect, or durable pairing row.
- `cbcl_v2_preview_rendered` follows a real double animation-frame paint.
  `cbcl_v2_link` alone consumes the private native Link authority and releases
  `IntentApprove` plus preparation. A matching authenticated comparison must
  precede the distinct protocol `FinalApprove` in `cbcl_v2_continue_link`.
- The retained root is private, non-cloneable, non-serializable and single-use.
  Preview DID/fingerprint, attempt, root generation, ceremony, application,
  relay, request, offer, profile, intent, comparison predecessor and deadline
  remain bound to its consumption. Preview is recomputed before the first
  signature.
- Deadlines use suspend-inclusive native clocks and expire at the earliest of
  120 real elapsed seconds, offer expiry, or relay expiry. Equality is expired.
  Clock failure, rollback, conversion overflow, root replacement, background,
  cancellation and stale tags fail closed.
- Effect entry is registered atomically against revocation. A worker lease
  prevents a new attempt while cancelled in-flight work retains the socket or
  root. Every pause and effect boundary rechecks attempt, root and deadline.
- `PrePayloadPendingTransaction` compensates the exact owned row before durable
  `PayloadPrepared`. A storage write that commits `PayloadPrepared` and then
  reports failure retains the sealed recovery slot. Finish verifies the signed
  receipt and an independent live reciprocal resolver/WebFinger binding before
  installation. SingleLink recovery and unlink remain policy-free; explicit
  legacy retains exact policy snapshot/compare/delete behavior.
- New Tauri requests are nested `{request:{...}}` deny-unknown-fields objects.
  Mode checks precede phase and custody effects. The UI keeps explicit legacy
  controls and its two approvals while default complete input exposes one
  unlock and one Link.

After independent review, the UI's post-Link failure path now queries the
native installed and sealed-recovery projections. An ambiguous continuation
reports the retained recovery checkpoint; an error after installation reports
that a local installed record is present; an unavailable projection reports
completion as unresolved. None of these paths asserts that disclosure or
installation did not occur. Legacy `cbcl_v2_finish` checks mode and presence
before taking `PayloadSent`, so a missing passcode leaves the attempt available
for a corrected retry while SingleLink still refuses `PairingWrongMode` first.

The exact command/result interface and the later manual adapter seam are in
`/tmp/spec079-native-consent-api-handoff.md`. The test-only JSONL host documents
matching operations in `docs/spec077-native-host.md` and retains memory custody,
explicit local CA routing and redacted responses.

## TEST-001 through TEST-010 mapping

| Contract | Executed evidence |
|---|---|
| TEST-001 | `single_link_native_commands_render_mode_comparison_cancel_and_expiry` exercises exact application/relay candidate refusal and observes no policy or identity writes; `native_host_single_link_reserves_before_contact_and_refuses_profile_failure` proves reservation precedes contact and a profile failure creates no live pending protocol session. |
| TEST-002 | The native SingleLink command test checks zero writes, decisions and peer frames before Link, successful local preview, bad phases, root change and clock failure. UI tests check passcode clearing on unlock success and failure. |
| TEST-003 | Native tests reject Link before render and show render alone emits no peer frame. The real UI bridge test requires the double-frame acknowledgement and separate Link action; removing the render call is killed. |
| TEST-004 | The local authenticated peer test observes `IntentApprove`, preparation, matching comparison and distinct `FinalApprove`; it holds, declines, mismatches and alters comparison inputs, rejects duplicate Link/continuation, and checks pre-signature preview equality. |
| TEST-005 | Authenticated peer substitutions cover ceremony, predecessor, preview DID/fingerprint, authority status and result bindings. Four compile-fail cases prove external construction, cloning, serialization and reuse-after-move of Link authority are unavailable. |
| TEST-006 | Native clock tests cover equality, before/after bounds, wall-clock rollback, continuous-time advance, clock failure and overflow. The command test advances the continuous clock while ordinary task timing is idle and checks all pre-payload pause boundaries. Platform evidence is below. |
| TEST-007 | Native and UI tests cancel held comparison, foreground/navigation transitions and late reservations; they reject stale tags, clear custody, prevent stale reinsertion, prevent starting while a worker lease remains, and emit no later final decision. |
| TEST-008 | `single_link_transaction_faults_ambiguous_payload_and_policy_free_unlink` injects every transaction boundary, before/after-commit store failures, preserves ambiguous `PayloadPrepared`, and checks policy-free SingleLink unlink. UI regressions inject committed-then-error continuation and post-install finish failures, requiring sealed-recovery or completion-unknown guidance without an unverified negative claim. The existing isolated TEST-1162 regression remains green. Receipt/live-binding checks remain in the production finish path and are covered by the native library verification fixtures. |
| TEST-009 | Native tests call every legacy approval/comparison command from SingleLink and every SingleLink command from legacy, requiring `PairingWrongMode`; request grammar rejects extras/coercions/bad tags. `legacy_finish_missing_presence_keeps_the_attempt_retryable` checks presence before taking pending state and then reaches the unchanged phase check with a corrected value. Pairing shell and wallet UI regressions preserve explicit legacy carrier/PAIR1 and two decisions. |
| TEST-010 | `tests/spec-077-scan-pairing.mjs` drives the actual phone UI bridge through default scan: one unlock, cleared passcode, painted complete review, one Link, visible cancellation/status, no legacy final auto-call, verified installed-only success, and truthful failure states. Wallet legacy accessibility/recovery/reload/unlink tests remain green. Manual UI is intentionally owned by the next increment. |

## Green checks

All Cargo commands used the externally mounted build directories required by the
task and ran locked/offline with the accepted clean siblings.

| Check | Result |
|---|---|
| `cargo test --locked --offline -p selfsame --lib` | 83 passed, 0 failed, 7 ignored |
| `cargo test ... -p selfsame --lib single_link -- --ignored --nocapture --test-threads=1` | 3 passed: native host reservation/contact, native SingleLink commands, and transaction/ambiguous-payload/policy-free-unlink |
| `cargo test ... -p selfsame --lib single_link -- --nocapture` | 4 passed, including the legacy missing-presence retry regression; 3 isolated tests ignored as designed |
| isolated `test_1162_pre_payload_failure_and_person_abandonment_release_the_exact_slot` | 1 passed |
| isolated `native_host_memory_init_cancel_shutdown_regression` | 1 passed |
| isolated `native_host_explicit_relay_setter_routes_actual_connect_wss` | 1 passed |
| `PUPPETEER_SKIP_DOWNLOAD=1 npm run e2e:wallet-pairing` | 14 passed, 0 failed |
| `cargo test --locked --offline -p selfsame-pairing` | all unit, integration and doc tests passed; one helper process test remained intentionally ignored |
| `cargo clippy --locked --offline -p selfsame --lib -- -D warnings` | passed |
| scoped `rustfmt --check` over every changed Rust file | passed |
| `git diff --check` | passed |

The broader `cargo clippy -p selfsame --lib --tests -D warnings` reaches a
pre-existing test arrangement that includes
`crates/selfsame-app-identity/tests/common/mod.rs` through multiple test modules
and trips Clippy's `duplicate_mod` lint. The production library target above is
clean; no lint was suppressed or production source changed to hide that test
layout.

## Mutation and platform-clock evidence

`mutation-results.json` records 24/24 killed cases: 20 behavioral guard-removal
mutations and four compile-fail ownership mutations. They cover exact contact,
policy isolation, local-only unlock, render gating, comparison hold, preview
identity equality, deadline equality/enforcement, effect-entry and guarded-pause
fences, payload recovery, cross-mode/grammar checks, UI paint/passcode/install,
late-tag cancellation, and the four Link-authority type properties. Full logs
remain at `/Volumes/anuna-03/spec079-native-consent-mutations/`. The committed
runner can refresh all cases or a named subset while preserving the complete
result ledger.

This host is `aarch64-apple-darwin`; the full native library test executed the
Apple `mach_continuous_time` adapter and its checked timebase conversion.
`clock-targets.json` records compile/source checks of the actual clock module for
`aarch64-apple-darwin`, four Android ABIs using `CLOCK_BOOTTIME`, and
`x86_64-pc-windows-gnu` using `QueryInterruptTime`. All six compiled. Cross
targets were not executed, so this evidence makes no Android or Windows runtime
claim.

No production endpoint, real wallet, system keychain, deployment, push, source
pin, sibling checkout, reviewed specification, release WASM or generated browser
asset was changed. This is local implementation evidence, not production or
independent human approval.
