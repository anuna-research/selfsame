# WASM closure inspection API handoff

Implementation ready for independent review in `/Volumes/anuna-03/codex-closure-inspection/selfsame`, branch `wasm-closure-inspection`, base `9f3f1b6511a44e9e46a023d4c291ac4a99e1e1fb`. Shared inspection dependency: pairing `6e56ef2f2db0a918888cbfe39315944db30f50a3`. Root owns independent review, generated package, browser bridge, and integration acceptance.

```rust
CredentialV2BrowserAllocatorSession::restore_for_closure(
    profile: &[u8], carrier: &[u8], checkpoint: &[u8], generation: u64,
    request_id: &[u8], intent_nonce: &[u8], expected_allocator_key: &[u8],
    installation_seed: &[u8], now: u64, mode: String,
) -> Result<CredentialV2BrowserAllocatorClosureInspection, JsError>;

impl CredentialV2BrowserAllocatorClosureInspection {
    restored_phase(&self) -> String;
    restored_mode(&self) -> Option<String>;
    restore_offer_context(
        &mut self, raw_carrier: &[u8], offer_core: &[u8],
        offer_core_digest: &[u8], pending_expires_at: u64,
        signed_offer: &[u8], authority_response: &[u8],
        authority_digest: &[u8], now: u64,
    ) -> Result<(), JsError>;
    verify_final_status(
        &self, final_status: &[u8], final_status_digest: &[u8],
        finalized_at: u64,
    ) -> Result<(), JsError>;
    cancel(&mut self) -> String; // exactly "[]"; disables this inspector
}
```

The static method takes the existing nine restore prefix arguments plus exact `"full" | "manual"`. It takes no CPace scalar. Byte slices map to Uint8Array and u64 values to bigint. The returned type is distinct and has no start, receive, transfer export, preparation, issuance, checkpoint, or live-session conversion. Generic teardown may call `cancel()` or wasm-bindgen `free()`; active operations must fail when their methods are absent.

`restored_mode()` reports only authenticated bootstrap mode. Established checkpoints return undefined; browser metadata cannot create a mode, missing profile/request/intent binding, or finality. `restored_phase()` uses the existing live phase spellings. Inspection uses the real supplied clock and may authenticate an expired checkpoint; ordinary live restore and offer-context expiry checks remain unchanged.

Offer context must match the exact decoded carrier, signed offer, profile, request/intent, allocator, deadline and signed authority facts, including retained body bindings where present. Bootstrap and Begin context grants no final-status authority without retained Payload or terminal Receipt evidence. PayloadSent verification uses restored authenticated body facts. Terminal Receipt verification reconstructs the canonical candidate receipt, matches its sealed intent/content hashes, and verifies the actual signed final status and all retained bindings. Neither expiry nor inspection authorizes deletion: the browser still obtains exact authenticated hub closure and performs its ownership CAS.

Source implementation evidence is in `evidence/spec078-wasm-closure-inspection/verification.json` and `mutations.json`. Generated package execution and browser integration remain root-owned acceptance gates. No schema, pin, bundle, or production enablement change is included.

## Disposable generated-WASM fixture

`/tmp/spec078-closure-wasm-fixtures.json` is exported by the real signed checkpoint builder in `crates/selfsame-web-device/src/credential_v2_closure_tests.rs`; regenerate with `SPEC078_CLOSURE_FIXTURES_OUT=/tmp/spec078-closure-wasm-fixtures.json` and the focused `closure_real_payload_and_terminal_receipt_verify_after_expiry` lib test. Its fixed keys/seeds are disposable public test values. The fixture profile and carrier are local `.example` values, with relay deadline `1760000900` (2025), so use Chrome's actual `BigInt(Math.floor(Date.now()/1000))`.

Schema `spec078-wasm-closure-fixtures/v1` has `cases`: `payload-sent`, `terminal-receipt`, and `terminal-receipt-invalid-signature`. Each case provides:

- `restore`: `profileB64u`, `carrierB64u`, `checkpointB64u`, `generation`, `requestIdB64u`, `intentNonceB64u`, `expectedAllocatorKeyB64u`, `installationSeedB64u`, `mode`, and diagnostic `relayExpiresAt`. Pass the first eight fields in API order, then actual current time, then mode.
- `offerContext`: `carrierB64u`, `offerCoreB64u`, `offerCoreDigestB64u`, `pendingExpiresAt`, `signedOfferB64u`, `authorityResponseB64u`, `authorityDigestB64u`. These are the first seven arguments in order; eighth is the actual current time.
- `finalStatus`: UTF-8 `jws`, `digestB64u`, `finalizedAt`, and `expectedVerified`. Pass UTF-8 JWS bytes, decoded digest, and bigint finalizedAt.
- `expectedPhase` and `expectedMode` (`null` means the exported Option should return undefined).

Decode every `B64u` field as unpadded base64url to Uint8Array; convert numeric u64 arguments to bigint. The invalid-signature case seals the exact Receipt containing the altered signature: it passes the canonical receipt/hash binding but must fail actual final-status signature verification. Native export reruns its own actual closure verification on the same bytes and asserts all three expected results. The Payload body uses a syntactic grant fixture and does not claim application credential acceptance.

## Source verification handoff

The final source passes web-device lib (63), allocator integration (3 and 2), relevant shared pairing offer/receipt (3 and 1), and no-live compile-fail docs (3). Strict production Clippy passes. Strict all-tests Clippy encounters two unchanged base warnings (`manual_range_contains` and `useless_vec`); allowing only those categories passes, with exact receipts in the evidence directory. No baseline code was edited to clear them. Six deliberate guard mutations produced named behavioral test failures (no compilation-error kills), and the mutated production source hashes equal the restored final source hashes. The final lib suite adds a valid-signature/exact-receipt-hash grammar refusal test after that mutation capture.

The source and API are ready for root's independent review and generated-WASM browser verification; this producer handoff is not independent acceptance or production approval.
