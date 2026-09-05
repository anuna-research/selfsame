---
id: scan-wallet-ui-implementation-2026-09-05
title: Scan wallet UI implementation evidence
status: independently reviewed; local UI checks passed
last-updated: 2026-09-05
---

# Scan wallet UI implementation evidence

This implements the UI part of cbcl-bus SPEC-077 TEST-004 and TEST-007 under
[[SPEC-008-production-pairing-claimant#CON-986]]. Native command and exact-WASM
integration evidence remain separate.

The default scanner and paste entry call the shared-handoff native command with
unaltered input. Legacy input requires opening the older-invitation control.
The page clears input after capture. The preview stage places the fingerprint
before request details, awaits two animation-frame callbacks, and only then
calls the comparison continuation. Approval stays disabled during comparison.
An attempt epoch rejects delayed recognition, comparison, and completion after
cancellation. Wait screens retain an accessible Cancel control.

The final review retains the authenticated intent and adds the local preview.
The unlock field moves into the consent screen so a scan can precede unlocking.
Hidden field CSS now excludes that input from relay-consent keyboard traversal.

Validation commands:

- `npm run e2e:wallet-pairing`: 9 tests pass, including mobile 320-pixel width,
  keyboard/WCAG checks and recovery/installed-state regression tests.
- Initial `node --test tests/spec-077-scan-pairing.mjs`: behavioral failure
  because scan never invoked complete-handoff recognition.
- Remove `await previewRendered()` and run the preview test: failure because
  native comparison starts before the controlled render callbacks.
- Remove the epoch check after `cbcl_v2_compare` and run the cancellation test:
  failure because the old completion reopens final review after cancellation.
- Both mutations restored before the final passing run.

The tests use the actual rendered wallet and a controlled native bridge. They
prove UI order and cancellation handling, not native crypto or installation.
The complete `CI=true npm run screens` command passes with the new native
handoff and comparison command registrations.

Independent reviewer `pairing_ux_review` identified a pending-cancellation gap:
the final screen remained actionable until the native cancellation returned.
The candidate now enters a cancelling phase and disables decisions before that
await. A controlled delayed-cancel regression requires zero final-decision calls.
The reviewer confirmed the render barrier, epoch guard and preserved fields.
Their separate viewport run was blocked by their sandbox; the root mobile
viewport/WCAG tests above executed successfully.

The cancellation repair was also deliberately removed: its delayed-native-cancel
test failed. Restoring the cancelling phase restores the passing UI suite.
