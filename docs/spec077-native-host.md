---
title: Native scan integration host protocol and evidence
mode: reference
---

# Native scan integration host protocol and evidence

This test adapter drives the actual native commands for [[SPEC-077-selfsame-scan-pairing#TEST-008]].
It does not establish completion of that integration test.
Root owns the signed ceremony, browser, local authority, clean pin closure, and independent review.

The implementation composes the existing [[Tauri]] mock builder, managed `AppSession`, native commands, and completion recognizer.
Only custody storage and transport routing differ in the host process.
Normal identity verification remains authoritative. Default complete-input consent follows
[[SPEC-079-selfsame-single-link-consent#CON-001]] through [[SPEC-079-selfsame-single-link-consent#CON-004]].
Explicit legacy entry retains its separate relay, preliminary and final decisions.

## Invocation and isolation

```sh
CARGO_TARGET_DIR=/Volumes/anuna-03/codex-scan-clean-native-target \
TMPDIR=/Volumes/anuna-03/codex-scan-native-preview-1/tmp \
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=4 \
cargo test --locked --offline -p selfsame --lib scan_integration_native_host -- --ignored --nocapture --test-threads=1
```

The host runs alone because the keyring builder and explicit network configuration are process-global.
The host installs and checks the extracted shared memory backend before any storage or application setup.
`Session::default()` has no wallet directory or persistence path.
Init calls `Custody::restore` directly, avoiding the publication and discovery effects of UI creation/restoration commands.
It runs the actual storage probe and checks sealed hierarchy unlocking and backup state using memory only.
Shutdown and EOF cancel the native attempt and erase process-local storage.
If a background continuation exists, teardown first revokes its actual native
attempt, then boundedly drains or aborts the wrapper and observes the actual
worker lease. A drain failure returns `HostJobDrainFailed` and leaves custody
untouched until process exit rather than clearing storage under live work.
The host does not reset a wallet or address operating-system credentials.

The non-default `selfsame-app-identity-net/native-test-support` feature is enabled by a native dev dependency.
Tauri's `test` feature, JSON raw-value parsing, and zeroizing deserialization are also dev dependencies.
The host module is absent from normal, mobile, and WASM builds.
Relay configuration exists only under `cfg(test)`.
No ambient environment variable enables a trust override.

## Private JSON-lines protocol

Every request is a UTF-8 JSON object:

```json
{"id":1,"op":"cancel","args":{}}
```

`id` is an unsigned 64-bit integer. `op` is one of the names below. `args` is the corresponding object.
The host's raw JSON `serde` recognizers reject unknown fields, missing required fields, duplicate fields, and wrong types.
The production Tauri commands receive nested normalized objects: `{request: args}` for the new operations below.
They deny unknown members and wrong types; they cannot reject duplicate keys already lost in Tauri's transport parsing.
The input limit is 65,536 bytes per line, including its newline.
An oversized line produces `HostRequestOversize` with `id:null`, then closes the host.
Malformed envelopes produce `HostRequestRefused` with `id:null`; malformed arguments retain the recognized request ID.
The response error is an allowlisted native command token or a closed host category.
Other `UiError` messages become `HostCommandRefused`; backend details never cross this boundary.
Host initialization categories are `HostAlreadyInitialized`, `HostAlreadyConfigured`, `HostRootRefused`, `HostProxyRefused`, `HostRelayAddressRefused`, `HostMnemonicRefused`, `HostPasscodeRefused`, and `HostCustodyRefused`.
Premature operations return `HostNotInitialized`; a missing installed record after finish returns `HostInstalledRecordMissing`.
Background ownership adds only `HostJobOccupied`, `HostJobMissing`,
`HostJobRefused`, and `HostJobDrainFailed`.

Each response is one flushed line:

```text
SPEC077_HOST {"id":1,"ok":true,"result":null}
SPEC077_HOST {"id":2,"ok":false,"error":"PairingNotStarted"}
```

Cargo and libtest diagnostics coexist on stdout/stderr.
The host terminates libtest's pending diagnostic line before its response stream starts.
Every response line starts with `SPEC077_HOST `, including the first response. There is no startup response.
No request data, handoff, mnemonic, seed, passcode, raw grant, or signed receipt is logged.
Secret request buffers and decoded custody/handoff fields are zeroized on drop.
Synthetic ceremony material belongs exclusively to private IPC.

Requests execute sequentially except for the one explicitly started
`continue-link` job. Its actual native command runs in the Tauri runtime so a
later exact-tag `cancel-link` can revoke it while relay I/O is pending. The host
retains at most one active or completed-undrained job. While occupied it refuses
all ceremony mutations except exact-tag cancellation; read-only installed and
pending projections, matching polling, and shutdown remain available. A wrong
attempt tag or random job ID cannot poll, consume, replace, or cancel the job.

## Operations

Field names in this table are exact. Optional passcodes accept omission or `null`; approval still requires presence in the actual command.
`cancel` and `shutdown` are available before initialization. Other ceremony operations require successful initialization.

| Operation | `args` | `result` |
|---|---|---|
| `initialize` | `{mnemonic:string,passcode:string,rootPem:string,proxyUrl:string,relayAddress:string}` | `{outcome:"initialized",custody:"memory",backupConfirmed:true,installedLinks:[]}` |
| `begin-handoff` | `{handoff:string}` | `{attemptTag,phase:"reserved",applicationId,relayOrigin}`; local recognition only |
| `contact` | `{attemptTag}` | `{phase:"authenticated-request",intent:Intent}` |
| `unlock-preview` | `{attemptTag,passcode:string}` | `{phase:"preview-unpainted",review:Review}`; no protocol decision or disclosure |
| `preview-rendered` | `{attemptTag}` | `{phase:"review-ready"}`; renderer acknowledgement grants no disclosure |
| `link` | `{attemptTag}` | `{phase:"comparing"}`; consumes person Link and sends intent approval/preparation |
| `continue-link` | `{attemptTag}` | `{phase:"await-receipt"}`; authenticated matching comparison precedes distinct final approval/payload |
| `start-continue-link` | `{attemptTag}` | `{state:"started",jobId}`; starts the actual native continuation without waiting |
| `poll-continue-link` | `{attemptTag,jobId}` | `{state:"pending",workActive:boolean}` or `{state:"finished",ok:true,result}` or `{state:"finished",ok:false,error}`; after confirmed cancellation the latter also carries `{cancellation:"confirmed",command:{ok,result|error}}` |
| `finish-link` | `{attemptTag}` | `{outcome:"installed",installedLinks:[InstalledEvidence]}`; verifies receipt/live binding with retained bounded custody |
| `cancel-link` | `{attemptTag}` | `null`; wrong tag refuses without cancelling a newer attempt |
| `recognise-legacy` | `{invitation:string,presenceCode:string}` | `{applicationId,relayOrigin,requiresApproval}` from explicit carrier/PAIR1 entry |
| `recognise-handoff` | `{handoff:string}` | obsolete default entry refuses `PairingWrongMode` |
| `relay-decide` | `{approve:boolean}` | `{outcome:"declined"|"intent",intent:null|Intent}` |
| `preliminary-decide` | `{approve:boolean,passcode?:string|null}` | `{outcome:"declined"|"preview",finalReview:null|Review}` |
| `compare` | `{}` | `Review`, after authenticated comparison |
| `final-decide` | `{approve:boolean,passcode?:string|null}` | `{outcome:"declined"|"payload-sent"}` |
| `finish` | `{passcode?:string|null}` | `{outcome:"installed",installedLinks:[InstalledEvidence]}` |
| `pending-recoveries` | `{}` | application IDs from the actual sealed pending-record index |
| `pending-links` | `{}` | redacted pending-link summaries from the actual sealed index |
| `recover` | `{applicationId,passcode,approveRotation:boolean}` | `{recovery:RecoveryView,installedLinks:[InstalledEvidence]}` |
| `installed-links` | `{}` | `[InstalledEvidence]` |
| `metrics` | `{}` | `{identityEffects,custodyWrites,policyOperations}` from existing test-only counters; read-only, including while a continuation job is retained |
| `cancel` | `{}` | `null` after native session revocation in either mode |
| `shutdown` | `{}` | `null` after cancel; process exits |

`Intent` is the existing authenticated command projection:

```text
{applicationId, httpsOrigin, relayOrigin, permissions: string[], deviceDid,
 accountPrincipalDigest, tofuState,
 transition: {kind, legacyHandle: string|null, migrationRooms: string[]}}
```

`tofuState` is `"ceremony-gesture"` for SingleLink, `"new-pair"` or `"trusted-pair"` for explicit legacy, or the command's defensive `"unknown"` value.
`transition.kind` is `"none"` or `"path-a-to-b"`.

`Review` is the existing preview/comparison projection:

```text
{applicationId, previewIssuerDid,
 previewFingerprint: {hex, label, lifehash}, comparison}
```

Default unlock returns `comparison:"waiting"`. The real UI acknowledges after paint and calls `link` only for the person's Link gesture.
The host exposes these same separate operations for orchestration; it does not synthesize gestures.
`jobId` is 16 fresh random bytes rendered as exactly 32 lowercase hexadecimal
characters. It is an opaque test-host correlation value, not protocol or native
authority. `workActive:true` comes from the exact tagged native worker lease,
not from task creation. A finished result remains retained until both tags poll
it once.
After a successful tagged cancellation, the outer finished result is
`PairingCancelled`, so an earlier continuation success cannot restore live
authority. Its nested `command` member still preserves the actual command's
success or closed error. The integration oracle can therefore detect and fail
an erroneous native success after the cancellation fence rather than having the
host hide it.
Default finish has no passcode argument. Custody expires exclusively at the earliest of 120 suspend-inclusive seconds from unlock, offer expiry, and relay expiry.
Expired post-payload recovery uses the existing wallet recovery API with fresh
explicit presence. The host forwards its exact application ID, passcode and
rotation decision; it adds no recovery authority and exposes no checkpoint or
recovery token. The real 900-second relay gate remains unchanged.
For explicit legacy, preliminary approval returns `comparison:"waiting"` before preparation disclosure;
`compare` returns `"no-binding-person-compared"` or `"bound-same-did"`, and final approval remains a separate request.
Wrong phases, duplicate continuation, decline, and cancellation retain the commands' existing refusal behavior.

`InstalledEvidence` contains only these fields:

```text
{applicationId, account, relayOrigin, issuerDid, grantId, grantDigest,
 credentialId, installationDeviceDid, accountPrincipalDigest, profileDigest,
 offerCoreDigest, carrierCeremonyId, requestId, payloadDigest,
 finalStatusDigest, finalizedAt}
```

The IDs and digests retain their stored encodings; binary IDs and digests use canonical unpadded base64url.
`credentialId` retains the grant's identifier. `finalizedAt` is the signed finalization time in seconds.
`installed-links` first calls `cbcl_v2_installed_links`, then reloads each record through `cbcl_v2_completion::load_installed`.
The loader recognizes and validates the installed slot; the host also checks the current custody root generation.
`finish` additionally requires an installed record for the actual pending application's identifier.
An absent or pending record cannot yield installed success. Grants and recovery material are excluded from the projection.

## Local TLS configuration

`rootPem` is exactly one per-run certificate in PEM form. Both HTTP and relay configuration reject unusable roots before custody initialization.
`proxyUrl` is an HTTP origin with a numeric loopback IP and explicit nonzero port, with an optional trailing slash.
Examples: `http://127.0.0.1:41001` and `http://[::1]:41001`.
Credentials, paths, query strings, fragments, hostnames, and nonloopback addresses refuse.
`relayAddress` is a numeric loopback `SocketAddr` with a nonzero port, for example `127.0.0.1:41002`.
Configuration installs once per process. A new run uses a new process.

All identity HTTP clients, including WebFinger's separate builders, use the explicitly installed CONNECT proxy.
The canonical HTTPS URL, host header, and TLS server name remain unchanged.
The proxy tunnels each canonical host/port to the orchestrator's isolated TLS service.
Account-authority names keep their normal port-free form, with CONNECT targeting port 443.
Explicit configuration disables ambient proxy discovery and refuses redirects, including WebFinger redirects in this host.
No cookie jar is compiled into the client.
Without explicit configuration, WebFinger retains its existing bounded redirect policy and the normal clients retain their original trust setup.

The relay connector routes TCP directly to `relayAddress` without DNS resolution.
It retains the carrier-derived `wss://host[:port]/relay` URL and validates the certificate for the original host.
The ordinary WebPKI roots remain installed; the per-run root is additive only in explicitly configured tests.
HTTPS, SNI, hostname validation, response recognizers, signatures, Finished, and grant verification remain active.

## Evidence and limits

Base: Selfsame `729dd0f`, pairing pin `ec260d3`.
Development commands used `SELFSAME_ALLOW_UNPINNED_CBCL_PAIRING=1` because the owner's sibling checkouts differ from the pinned closure.
These runs are **invalid release evidence**. No sibling checkout, pin, served WASM, generated asset, or specification contract changed.
No deployment, push, external message, production probe, real keychain write, or real wallet reset occurred.

Logs are under `/Volumes/anuna-03/codex-scan-native-preview-1/`.
All cargo invocations use the target, temporary directory, and debug/incremental settings shown above.

| Check | Result | Command after `cargo` | Evidence log |
|---|---|---|---|
| Behavioral red before HTTP plumbing | pass: executed failure observed | `test -p selfsame-app-identity-net --features native-test-support --lib native_host_root_and_connect_proxy -- --nocapture` | `native-host-red.log`: executed test failed with the route unwired |
| Deliberate guard removal | pass: executed failure observed | `test -p selfsame-app-identity-net --features native-test-support --lib native_host_config_rejects_nonloopback_proxy_and_invalid_root -- --nocapture` | `native-host-mutant.log`: removing `!ip.is_loopback()` caused an executed assertion failure; guard restored |
| HTTP configuration and refusal regression | pass | `test -p selfsame-app-identity-net --features native-test-support --lib` | `native-host-net-green.log` |
| Normal HTTP trust, feature disabled | pass | `test -p selfsame-app-identity-net --no-default-features --lib` | `native-host-default-net.log` |
| Actual shared-client setter | pass | `test -p selfsame-app-identity-net --features native-test-support --lib native_host_explicit_setter_routes_actual_client -- --ignored --nocapture --test-threads=1` | `native-host-http-setter-green.log` |
| Canonical WebFinger authority and redirect refusal | pass | `test -p selfsame-app-identity-net --features native-test-support --lib native_host_webfinger_setter_routes_canonical_account_authority -- --ignored --nocapture --test-threads=1` | `native-host-webfinger-green.log` |
| Native relay/default TLS | pass | `test -p selfsame --lib cbcl_transport -- --nocapture` | `native-host-transport-green.log` |
| Actual relay setter | pass | `test -p selfsame --lib native_host_explicit_relay_setter_routes_actual_connect_wss -- --ignored --nocapture --test-threads=1` | `native-host-relay-setter-green.log` |
| Scan/preview/phase/cancellation | pass | `test -p selfsame --lib scan -- --nocapture` | `native-host-scan-regression.log` |
| Completion validation | pass | `test -p selfsame --lib cbcl_v2_completion -- --nocapture` | `native-host-completion-regression.log` |
| Extracted keyring, including injected write failures | pass | `test -p selfsame --lib test_1162_pre_payload_failure_and_person_abandonment_release_the_exact_slot -- --ignored --nocapture --test-threads=1` | `native-host-keyring-regression.log` |
| Memory custody lifecycle | pass | `test -p selfsame --lib native_host_memory_init_cancel_shutdown_regression -- --ignored --nocapture --test-threads=1` | `native-host-memory-green.log` |
| Actual stdin host process | pass | Exact invocation above, with generated private synthetic init IPC, installed-links, cancel, shutdown | `native-host-ipc-green.log`: init rejected invalid root, then succeeded; stdout/stderr contained no mnemonic/passcode |
| Normal native compilation | pass | `check -p selfsame --lib` | `native-host-normal-check.log` |
| Normal/WASM feature isolation | pass | `tree -p selfsame --edges normal,build,features`; same for `selfsame-web-device --target wasm32-unknown-unknown` | `native-host-normal-feature-tree.log`, `native-host-wasm-feature-tree.log`: no test-support, Tauri test, or cookie feature |
| Existing boundaries/rollback/hold | boundaries/rollback/hold pass; shell baseline fails | `test -p selfsame-pairing --test shell_cutover --test spec008_hold_invariance --test rollback_hold --test boundaries`; separate `test -p selfsame-pairing --test spec008_hold_invariance` after the baseline failure | `native-host-default-guards.log`, `native-host-production-hold.log` |

At the earlier SPEC-077 base, `shell_cutover` was red on an obsolete legacy UI source assertion, `ui.contains("{ invitation, presenceCode }")`; `native-host-shell-cutover-baseline.log` preserves that historical receipt. The SPEC-079 successor updates the assertion for default nested complete-handoff entry and explicit nested legacy carrier/PAIR1 entry. The current full `selfsame-pairing` suite passes; see `evidence/spec079-native-consent/README.md` for the bounded successor receipt. Normal trust guards remain green.

The complete signed browser/native ceremony and successful installation are unexecuted here.
The completion fixture regression is storage/verification evidence only, not a browser/native installation ceremony.
[[SPEC-077-selfsame-scan-pairing#TEST-008]] and fresh independent review remain unverified, owned by root and its reviewer.
Concept-link resolution in the spec vault remains root-owned; this evidence document does not amend the vault.

## Explicit manual phone entry

The test-only JSONL operation `begin-manual` takes exactly
`{"bootstrap":"SSPAIR-M1:…","words":"word word word"}`. It calls the actual
`cbcl_v2_begin_manual` command: shared complete pair recognition precedes the
same opaque reservation used by `begin-handoff`. The response is the existing
`{attemptTag,phase:"reserved",applicationId,relayOrigin}`. Pass that tag through
`contact`, `unlock-preview`, `preview-rendered`, `link`, `continue-link`,
`finish-link` and `cancel-link` unchanged. Neither a prefix nor a failed grammar
selects a fallback mode. Manual recognition errors are `RecognitionFailed` and
contain no raw inputs. The host's request line remains zeroizing and its output
contains no bootstrap or phrase.

Trace: [[SPEC-078-selfsame-manual-pairing#TEST-002]],
[[SPEC-079-selfsame-single-link-consent#TEST-001]]. A parameterized host test runs
both real Full and Manual reservations against an explicit local proxy that
refuses the profile before any relay connection. This is a contact-failure
receipt, not final native/served integration acceptance.
