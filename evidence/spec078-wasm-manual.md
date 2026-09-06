# wasm-manual bounded adapter evidence

Owner: Circus `wasm-manual/1`, isolated Selfsame worktree at `/Volumes/anuna-03/codex-successor-closure/selfsame-wasm-manual-1`. Integration base: `3c92cafc6b6d60659ed01f34cb7e770d2d4012dc`. Consumer: root's fresh independent review, Circus acceptance and serial merge; browser-manual consumes the reviewed API next. This record reports worker execution, not independent acceptance.

The actual `CredentialV2BrowserAllocatorSession` now selects shared Full/Manual mode explicitly. Existing construction retains the Full positional ABI and independent C16/T16; `new_manual` accepts four entropy bytes in the presence position and delegates the mapping to shared `CredentialV2ManualWords`. Restore appends mandatory exact mode and fresh scalar bytes, including for established checkpoints. Live bootstrap mode and private manual JSON are derived on demand from the core. Manual QR first invokes the shared authenticated recognizer and then the existing complete-text Q encoder.

The exact signatures, optional return behavior, JSON fields, error shapes, JS type expectations and browser responsibilities are recorded in `evidence/spec078-wasm-manual/api-handoff.md`, also published at `/tmp/spec078-wasm-manual-api-handoff.md`. The shared implementation was independently accepted before this task; no new cryptographic codec or mode inference was added here.

## Executed verification

Commands below used `CARGO_NET_OFFLINE=true`, the locked dependency graph, `CARGO_TARGET_DIR=/Volumes/anuna-03/codex-successor-wasm-native-target`, `TMPDIR=/Volumes/anuna-03/codex-scan-native-preview-1/tmp`, `CARGO_PROFILE_DEV_DEBUG=0`, `CARGO_PROFILE_TEST_DEBUG=0`, and `CARGO_INCREMENTAL=0`.

| Command | Observed result | Raw evidence |
|---|---|---|
| `cargo test --locked -p selfsame-web-device --lib` | 51 passed; no failures | `evidence/spec078-wasm-manual/lib.log` |
| `cargo test --locked -p selfsame-web-device --test credential_v2_allocator_session` | 3 passed; no failures | `evidence/spec078-wasm-manual/credential-v2-allocator-session.log` |
| `cargo test --locked -p selfsame-web-device --test cbcl_allocator_session` | 2 passed; no failures | `evidence/spec078-wasm-manual/cbcl-allocator-session.log` |
| `python3 crates/selfsame-web-device/tests/support/spec078_wasm_manual_vectors.py` | Byte-identical reproduction of checked-in fixtures | `evidence/spec078-wasm-manual/verification.json` |
| `python3 crates/selfsame-web-device/tests/support/spec078_wasm_manual_mutations.py` | 15 executed behavioral mutants killed; source restored byte-for-byte | `evidence/spec078-wasm-manual/mutations.json` and per-mutant logs |

The exact commands, observed test summaries, environment, source SHA-256 values and clean sibling revisions are retained in `verification.json`. The final green commands ran after the last mutation restoration. All fixtures and log values are synthetic local test material. No real wallets, production scripts or remote services were used; the existing legacy integration regression uses its local relay.

## Contract-to-behavior evidence

| Contract / test | Adapter behavior exercised |
|---|---|
| [[SPEC-078-selfsame-manual-pairing#CON-001]], [[SPEC-078-selfsame-manual-pairing#CON-002]], [[SPEC-078-selfsame-manual-pairing#TEST-001]] | Actual exported manual constructor against independent word vectors, including n endpoints, checksum branches and every masked high-bit combination. Exact carrier and bootstrap text come from an independent Python CBOR fixture. Pair recognition yields the independent expected C. Returned JSON contains exactly bootstrap and words. |
| [[SPEC-078-selfsame-manual-pairing#TEST-002]] | Pure implementations beneath exports reject constructor/restore byte-length errors, unknown or normalized mode strings, malformed checkpoints/carriers and expiry. Manual QR rejects cross-format input, malformed/noncanonical encoding, incorrect domain/token, extra/trailing/nested CBOR, missing allocator key, oversized input and exclusive expiry before QR. Missing-key input is separately checked to reach the shared AllocatorKeyRequired category. |
| [[SPEC-078-selfsame-manual-pairing#CON-003]], [[SPEC-078-selfsame-manual-pairing#TEST-003]] | Actual restore in both modes uses independently varied caller scalars and changes the expected allocator share. Before checkpoint acknowledgement, only the checkpoint effect is returned; wrong generation and reentrant input refuse. A valid wrong phrase pins the first share. Bound restores replay the exact cached share and later Finished despite different supplied fresh scalars. Different shares terminate; cached or correct replay cannot revive the attempt. Crash before persistence releases no response, while the durable bound snapshot covers the Ack/reply boundaries. |
| [[SPEC-078-selfsame-manual-pairing#CON-005]], [[SPEC-078-selfsame-manual-pairing#TEST-006]] | Full C16/T16 remain exact and independent, including Full C with the manual prefix and with an out-of-mapping suffix. Full/manual checkpoints reject the opposite mode. An independently sealed old inner-v2 fixture with a manual-prefix C restores as Full only. Full/legacy exporters refuse Manual; manual export refuses Full. Manual public effects and decoded wire/carrier fields contain no manual transfer text, C or T. Caller-owned string changes cannot alter a later private export. |
| [[SPEC-078-selfsame-manual-pairing#TEST-007]] | Manual admission completes both Finished values through the unchanged protocol; a checksum-valid wrong phrase fails authentication and establishes no channel. Established restores require syntactically valid mode/scalar but expose no bootstrap mode or transfer and preserve the exact receipt-recovery commitment. Full/Manual public carrier and context bytes match for identical inputs. Relay allocation remains 900 seconds. Cancellation, terminal relay input, parser failure, consumption and exclusive expiry clear private export. Existing library and both allocator-session regressions pass. |

The adapter tests live in `crates/selfsame-web-device/src/credential_v2_manual_tests.rs` so they can exercise private pure implementations. Successful constructors, restore, manual output, QR and checkpoint acknowledgement also run through their actual exported Rust methods. Native refusal tests call the exact inner function that the export maps to `JsError`; they do not construct `JsError`, catch an abort, or treat a missing-method/compile failure as red. The existing scan terminal test now exercises this adapter boundary too.

The fixture generator reads the accepted independent pairing word/bootstrap corpus and existing independently digested application-profile fixture. It independently encodes the allocated carrier and old Full checkpoint using Python CBOR/HKDF/AES-GCM, with no Rust output as an oracle input. Python cryptography is needed only to regenerate the old fixture; it adds no manifest dependency.

## Behavioral red and source restoration

The mutation runner patches only the owned adapter file, requires each selected test to compile and execute, requires a normal assertion-based test failure, and restores the original bytes in a `finally` block. Compile errors and native aborts are explicitly excluded from its success condition. The final source SHA-256 equals the recorded pre-mutation SHA-256.

The killed behaviors are byte-order drift in manual construction, C/T swapping, mode inference from a C prefix, constant restore scalar, case-folded mode fallback, oversized-byte truncation, swapped private JSON fields, private transfer in public effects, premature peer checkpoint acknowledgement, cancellation retaining the core, established mode capability, omitted QR recognition, omitted QR expiry, weakened QR correction level, and truncated QR input. Each case has its executed failing assertion in a named `.log`; `mutations.json` records its exact command and exit status.

## Scope and review boundary

No concrete conflict with the supplied adapter contracts was found. No specifications or Elephant state were amended. No dependency pins, manifests, lockfile, src-tauri, phone UI or generated/release files were edited. The sibling pairing/rust/DID checkouts are clean at their exact pinned revisions recorded in `verification.json`; no unpinned build override was used. No push or deployment was performed.

The browser owns the CSPRNG draws, owner/fence discipline, checkpoint and hub commits before private display, clearing at the earlier authenticated hub/relay deadline, and closure proof before replacement. The adapter does not infer clock authority or reopen expired checkpoints. Existing Full effect shapes remain compatible; Manual pending-allocation presenceCode is null.

This bounded task does not claim the browser IndexedDB/closure gate, native identity-effect and 600-second hub gates, final generated JS/WASM ABI execution, or final served bundle acceptance. Those remain with their assigned workers and root's [[SPEC-078-selfsame-manual-pairing#TEST-008]] / [[SPEC-079-selfsame-single-link-consent#TEST-011]] integration review. Root still performs fresh independent review, Circus acceptance and serial merge of these owned changes.
