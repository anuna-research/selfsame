# Native integration host job and recovery seam evidence

This evidence covers only the test-host seam needed by
[[SPEC-078-selfsame-manual-pairing#TEST-008]] and
[[SPEC-079-selfsame-single-link-consent#TEST-011]]. It does not claim either
end-to-end integration test complete. Root owns the strict ceremony rig,
regenerated package, exact pin closure, and independent review.

The implementation base is Selfsame
`d84c984efc318b966840a449ec21e030a1895ae0`, with local clean sibling sources
`cbcl-rs febc6691e6dd2d5f7116b1a4d84c984b64717564`, `cbcl-pairing
6e56ef2f2db0a918888cbfe39315944db30f50a3`, and `did-crdt
1f409a4229d07a62dd4cc6b2dce3b5a2e18e78a1`. All commands used
`CARGO_TARGET_DIR=/Volumes/anuna-03/codex-native-host-jobs-target`,
`TMPDIR=/Volumes/anuna-03/codex-scan-native-preview-1/tmp`, debug information
and incremental compilation disabled, four build jobs, and `--locked
--offline`.

| Check | Result | External log and SHA-256 |
|---|---|---|
| Focused host grammar/job tests | 6 passed, 3 intentionally ignored | `/Volumes/anuna-03/codex-native-host-jobs/host-jobs-focused.log`, `24c87319a25da14598494ba2872fcb031cf2511a1059c951ad41d2e21d8c3953` |
| Memory custody, pending projections and recovery refusal dispatch | 1 passed | `/Volumes/anuna-03/codex-native-host-jobs/native-host-memory.log`, `2c3f84bcdce6ce511dfe7837cc9ec2640400c3a651d33c27edafa16665b451bf` |
| Real SingleLink reservation, native lease observation, actual continuation refusal and retained polling | 1 passed | `/Volumes/anuna-03/codex-native-host-jobs/native-host-single-link.log`, `856758b69c4d77ccf69d3119deb5bfda310155a4a5b6f50c7671e1e12eeb741e` |
| Selfsame library regression | 88 passed, 7 intentionally ignored | `/Volumes/anuna-03/codex-native-host-jobs/selfsame-lib.log`, `6d16083f20852f5a44a910315d3c91738a8cbc37588c5025b38953d0e9f6106e` |
| Normal non-test library check | pass | `cargo check --locked --offline -p selfsame --lib`; test-only host and lease accessor absent |
| Cancellation-result mutant | killed: executed assertion failure, exit 101 | `/Volumes/anuna-03/codex-native-host-jobs/cancellation-mutant-red.log`, `a2cd59d5cbeccebc313f570a82a0f43f1bc56ced3a146bf9ec1bb1df11f7b965` |
| Ready/disconnected-result lease-retention mutant | killed: both assertions executed and failed, exit 101 | `/Volumes/anuna-03/codex-native-host-jobs/lease-retention-mutant-red.log`, `28160574be1a83b8247f26bfb203b3d07419c10d579e7d97683044f8d72aaf7c` |

The killed mutant disabled the cancellation-fence branch after a retained
successful worker result. The test required the outer result to remain
`PairingCancelled` and therefore failed. The correct result also retains the
actual command outcome in a nested closed `command` projection. This lets the
strict integration test detect an erroneous native command success after the
fence; the host does not hide that result while preventing it from reviving
live authority.

The lease-retention mutant allowed polling to consume a ready result or a
disconnected result channel while the actual native worker lease remained
active. Both focused tests failed at the pending-state assertion. The correct
implementation retains the whole job until that independently observed lease
is idle, then drains the result exactly once.

The component does not shorten the real 900-second recovery gate, alter a
clock, export a checkpoint/root/recovery token, or prove cancellation during a
real pending comparison. Those are strict rig obligations owned by root.
