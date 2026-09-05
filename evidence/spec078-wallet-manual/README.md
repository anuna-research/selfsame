# Wallet Manual adapter receipt

This component adds explicit phone Manual entry to the accepted SingleLink
implementation. `cbcl_v2_begin_manual` takes the closed nested request
`{request:{bootstrap,words}}`, calls the shared Rust `recognise_pair` on both raw
inputs, and returns the existing opaque reservation before asynchronous contact.
It reserves no authority and contacts no origin on local recognition refusal.
The actual JSONL host exposes the same command as `begin-manual`.

The phone offers **Enter three words**, a manual invitation scan/paste field,
and a separate three-word field. A manual camera scan fills the invitation and
focuses the words; Start invokes shared recognition. Invalid local input stays
editable with a generic error. Successful reservation and disposal clear both
inputs. Explicit Full scan remains the default zero-code route. Later commands
reuse the existing tagged SingleLink path, without a manual flag, additional
approval, passcode prompt, or durable trust policy.

This source is based on Selfsame
`d84c984efc318b966840a449ec21e030a1895ae0`, which includes accepted native consent
and WASM closure inspection. `closure.json` records the unchanged clean sibling
heads: Pairing `6e56ef2f2db0a918888cbfe39315944db30f50a3`, CBCL
`febc6691e6dd2d5f7116b1a4d84c984b64717564`, and DID
`1f409a4229d07a62dd4cc6b2dce3b5a2e18e78a1`. The Selfsame status in that receipt
is the implementation's expected uncommitted state before this commit.

## Validation

`verification.json` contains exact commands, environment, final source hashes,
exit statuses, and extracted result lines. Corresponding logs are committed;
only trailing whitespace is normalized for the repository's diff check.

- Native library: **84 passed**, 11 deliberately ignored in the ordinary run.
- Each of the **10 isolated native regression tests** passed in a separate
  process. These include Full and Manual consent, real manual parsing and
  typed-entry consumption, a valid wrong phrase reaching one CPace share and
  failing Finished without restart, both host contact failures, exact relay
  routing, and existing transaction/recovery regressions.
- Phone UI: **30 passed**, including existing explicit legacy tests, both Full
  and Manual consent variants, late scans/reservations, correction, disposal,
  camera states, keyboard/focus checks, and an axe WCAG audit at 320px.
- Production native library Clippy with `-D warnings`, scoped rustfmt, JavaScript
  syntax, and `git diff --check` passed.

The receipt also records one harmless zero-input EOF invocation of the ignored
JSONL service. That invocation is not counted among the 10 regression tests or
as ceremony evidence. The verification runner now excludes it by terminal test
name. Its UI result extraction accepts Node's TAP and spec reporters.

Run `python3 tests/support/spec078_wallet_manual_verify.py` to reproduce the
bounded green suite with the documented local caches. No all-tests Clippy claim
is made: the accepted baseline has an unrelated `duplicate_mod` test-layout
failure recorded in `../spec079-native-consent/README.md`.

UI dependencies were reused through a local `node_modules` symlink to
`/Volumes/anuna-03/codex-successor-closure/selfsame-native-consent-1/node_modules`.
That environment-only symlink is excluded in this clone's `.git/info/exclude`;
no dependency installation or package manifest change was needed.

## Defensive mutations

`mutations.json` and the eight named logs record **8/8 behavioral failures**:
ignoring words, trimming the invitation, replacing recognized presence,
accepting extra request fields, starting from a manual scan before words,
accepting a late scan, retaining transferred inputs, and destroying correction
inputs. Every case compiled or loaded, reached the relevant assertion, and
failed. Original and restored production hashes match. These are disposable
local fixtures; assertion logs contain no real wallet values.

The first attempt at evidence collection misread Rust's multiline failure
report; its actual assertion failure was confirmed and the matcher repaired.
Earlier UI fixture corrections (manual camera prefix and native string error
shape) are not counted as behavioral red evidence. Run
`python3 tests/support/spec078_wallet_manual_mutations.py` only in an isolated
checkout; it restores each source after the corresponding local test.

## Contract trace and limits

The governing contracts are SPEC078 v0.1.1 and SPEC079 v0.1.1. The mapping below
states exercised properties without expanding the accepted fixture coverage.

| Contract tests | Evidence and practical boundary |
| --- | --- |
| SPEC078 TEST002 | Actual native manual command rejects malformed, oversize, noncanonical, expired, missing, and invalid-word pairs before reservation; checks every allowed ASCII separator and case normalization, fixed errors, zero writes/identity decisions, and no sensitive response members. Shared parsing owns the full grammar. |
| SPEC078 TEST006 | Closed native request shape, explicit Full/Manual parser rejection, Manual/legacy isolation, and actual Manual typed entry in the consent rig. No exporter or protocol schemas changed. |
| SPEC078 TEST007 | Recognized carrier/presence reaches the existing claimant, signed offer, CPace/Finished, preview, and tagged consent implementation. Existing transaction/recovery regressions execute separately. |
| SPEC079 TEST001 | Full and Manual real reservation commands; actual host contact failure before relay; ceremony provenance and unchanged policy/write counters in the local signed protocol rig. |
| SPEC079 TEST002–004 | Parameterized native and UI tests cover local preview, rendering prerequisite, no pre-Link decisions/identity effects, exactly one Link, separate IntentApprove/FinalApprove, held/declined/mismatched comparison, and duplicate Link/continuation refusal. |
| SPEC079 TEST005 | Both modes execute the inherited comparison-body substitutions and retained-preview mismatch. This does not establish every independent CON003 substitution after both preview and Link. Earlier ownership/type evidence remains separate. |
| SPEC079 TEST006–007 | Both modes execute inherited deadline/revocation cases; actual Manual entry also refuses background/root-change reservations. UI late reservation/scan and successor fencing run for both. The direct guarded-boundary fault loop is not a real executor paused at every boundary. |
| SPEC079 TEST008 | Both UI modes cover invalid finish, ambiguous continuation, and installed-then-error projections without false success or false absence. Existing isolated transaction/recovery tests cover exact compensation, retained ambiguous payload, and policy-free install/unlink fixtures. They are not a completed Manual command-to-installed ceremony. |
| SPEC079 TEST009 | Both native consent modes refuse legacy commands and closed-request violations; Manual admission refuses an existing legacy attempt and a second active attempt. Existing explicit legacy UI tests remain green. |
| SPEC079 TEST010 | Real HTML/JS under Chrome with a controlled native bridge runs one unlock/Link for each mode, preserves request/preview, clears passcodes and transferred inputs, and checks keyboard/focus/status/accessibility behavior. No hardware-camera, mobile assistive-technology, or actual Tauri bridge claim is made. |

The native consent rig consumes the real entry returned by the actual Manual
command; it supplies a test authenticated profile and local protocol transport
instead of external HTTPS. Its positive execution reaches distinct final
approval and stops before issuer construction. The separate host test executes
actual contact against a refusing local proxy. Wrong-word evidence uses the
real shared Manual allocator and claimant protocol state machines, with local
wire messages; it does not simulate relay crashes or browser ownership recovery.

The native test executes this Apple host's clock adapter. Accepted non-Apple
compile/source receipts and all mobile/runtime limitations remain unchanged.
The inherited legacy missing-passcode test has no populated PayloadSent object;
its actual pending nonconsumption claim remains source-order evidence.

Root owns independent review, the separately authored asynchronous host helper,
serial merge, exact native/served-WASM integration, real expiry recovery, and
production holds. SPEC078 TEST008 and SPEC079 TEST011 depth are not claimed by
this component. No approved specification, dependency pin, sibling source,
schema, bundle, generated package, real wallet, or production endpoint changed.
