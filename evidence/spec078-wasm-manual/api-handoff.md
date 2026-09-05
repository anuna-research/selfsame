# wasm-manual API handoff

Consumer: browser-manual worker and root. Source worktree: `/Volumes/anuna-03/codex-successor-closure/selfsame-wasm-manual-1`, base `3c92caf`, accepted pairing pin `ffb348d2d840dcc43d6ead2681b5fbf9a886e363`. Bounded implementation and adapter execution evidence are complete: library and both allocator-session regressions pass, and executed behavioral mutations fail as required. See `evidence/spec078-wasm-manual.md` and `evidence/spec078-wasm-manual/verification.json` in the worktree. Root independently reviews and accepts before consumer integration. No generated JS/WASM or release bytes are produced here.

Trace: [[SPEC-078-selfsame-manual-pairing#CON-001]], [[SPEC-078-selfsame-manual-pairing#CON-002]], [[SPEC-078-selfsame-manual-pairing#CON-003]], [[SPEC-078-selfsame-manual-pairing#CON-005]].

```rust
cbcl_allocator_api_version() -> u32 // exactly 2, required for Full as well

CredentialV2BrowserAllocatorSession::new(
    profile: &[u8], relay_origin: String,
    mailbox_id: &[u8], carrier_ceremony_id: &[u8], carrier_nonce: &[u8],
    cpace_secret: &[u8], claim_token: &[u8], cpace_scalar: &[u8],
    request_id: &[u8], intent_nonce: &[u8], expected_allocator_key: &[u8],
    installation_seed: &[u8],
) -> Result<CredentialV2BrowserAllocatorSession, JsError>;
// Existing 12-position JS constructor. Full; C and T are independent 16-byte
// CSPRNG draws. All other byte positions except profile are exactly 32 bytes.

CredentialV2BrowserAllocatorSession::new_manual(
    profile: &[u8], relay_origin: String,
    mailbox_id: &[u8], carrier_ceremony_id: &[u8], carrier_nonce: &[u8],
    manual_word_randomness: &[u8], claim_token: &[u8], cpace_scalar: &[u8],
    request_id: &[u8], intent_nonce: &[u8], expected_allocator_key: &[u8],
    installation_seed: &[u8],
) -> Result<CredentialV2BrowserAllocatorSession, JsError>;
// Static JS new_manual, same positions. Position 6 is exactly FOUR CSPRNG
// bytes; only shared CredentialV2ManualWords maps them to C. T stays 16 bytes.

CredentialV2BrowserAllocatorSession::restore(
    profile: &[u8], carrier: &[u8], checkpoint: &[u8], generation: u64,
    request_id: &[u8], intent_nonce: &[u8], expected_allocator_key: &[u8],
    installation_seed: &[u8], now: u64,
    mode: String, fresh_cpace_scalar: &[u8],
) -> Result<CredentialV2BrowserAllocatorSession, JsError>;
// Static JS restore; same name, append exact "full" | "manual" and a fresh
// 32-byte CSPRNG draw after existing now. Every call requires both, including
// established restores. No old ABI/scalar fallback. Authenticated bootstrap
// mode must match; old inner v2 is Full only. Peer-bound restores discard new
// scalar and retain exact authenticated cached response. Expiry is unchanged.

session.bootstrap_mode() -> Option<String>; // "full" | "manual" from LIVE core
session.manual_transfer_text() -> Result<Option<String>, JsError>;
// Private JSON text exactly {"bootstrap":"SSPAIR-M1:...","words":"... ... ..."}.
// No stored JS/native string cache. Caller parses only for private callbacks.
// Allocated Full refuses; Manual succeeds while T live. Before allocation,
// consumed/established/terminal/cancelled return None. Established has no mode.
session.handoff_text() -> Result<Option<String>, JsError>; // Full SSPAIR1 only
session.restored_presence_code() -> Option<String>; // Full legacy PAIR1 only
// Full handoff refuses Manual; legacy returns None for Manual. No mode fallback.

cbcl_manual_bootstrap_qr_modules_json(text: &str, now: u64)
    -> Result<String, JsError>;
// Shared ManualBootstrap recognizes whole input and exclusive expiry BEFORE QR.
// Q-level QR over exact original text. JSON {"size": integer, "dark": [0|1,...]}
// Row-major dark.length == size*size. Capacity error:
// "the pairing invitation does not fit a QR symbol"; keep complete private text
// for paste fallback. Recognition error: "the pairing invitation was refused".
```

For wasm-bindgen JS, Rust byte slices take Uint8Array and u64 arguments/results use bigint. Optional strings are string or undefined. Result errors throw redacted JS Error. These are source ABI declarations; root's actual generated/served-WASM depth gate verifies final glue and implementation bytes.

The existing closed effect list stays unchanged. Manual pending-allocation `presenceCode` is null; neither private text, C nor T is added to effects. Sealed checkpoint bytes and public carrier remain existing recovery bindings. Bootstrap mode is available only from allocated/live core bootstrap, including consumed bootstrap; it is absent before allocation and after establishment/terminal/cancel.

Browser shell still owns durable allocation/hub commits before display, private callback clearing at earlier authenticated hub/relay expiry, owner/fence checks and closure before replacement. Adapter exporters have no clock input and create no replacement authority. Existing receive/checkpoint_persisted gate all Ack/Put output. Expired checkpoints remain refused: closure-only recovery is root/browser-ownership scope.
