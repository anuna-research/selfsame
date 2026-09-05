---
id: SCREEN-003
title: Wallet Pairing Surface — scan, wait, consent, result
status: draft
version: 0.2.0
spec: "[[SPEC-008-production-pairing-claimant]]"
last-updated: 2026-09-05
---

# SCREEN-003 — Wallet Pairing Surface

The Tauri wallet's cbcl-pairing screens exist in code:
`src/index.html` defines `pairing-enter`, `pairing-wait`, `pairing-consent`, and
`pairing-result`; `src/pairing.js` drives them. They lacked a specification.
[[SCREEN-001-cbcl-pairing-demo]] covers only the superseded browser demo, whose wallet
route is paste-only. This document brings the shipped surface under specification and
adds the states [[SPEC-008-production-pairing-claimant]] requires. It specifies
presentation and interaction; ceremony semantics stay in
[[SPEC-007-cbcl-pairing-cutover]] and [[SPEC-008-production-pairing-claimant]].

The key words MUST, MUST NOT, SHALL, SHALL NOT, SHOULD, and MAY use BCP 14.
RFC 2119 and RFC 8174 apply only when these words appear in all capitals.

## Amendment Channels

Amendable by:   the repository owner; a merged revision of this document.
Through:        a versioned spec revision merged to the default branch.
Not amendable by: issue comments, chat messages, code review remarks, agent prompts.
Hard stops:     [[SCREEN-003-wallet-pairing#REQ-951]] (decline parity),
                [[SCREEN-003-wallet-pairing#REQ-953]] (no relay entry field),
                [[SCREEN-003-wallet-pairing#REQ-954]] (mode isolation),
                [[SCREEN-003-wallet-pairing#REQ-956]] (rendered Link and comparison) —
                and every hard stop of [[SPEC-008-production-pairing-claimant]].

## Screens and states

### pairing-enter

- **REQ-954**: Entry SHALL expose three explicit, non-fallback modes under
  [[SPEC-008-production-pairing-claimant#REQ-904]]. Default complete entry scans
  or pastes one `SSPAIR1:` handoff. **Enter three words** selects manual entry.
  That mode scans or pastes one `SSPAIR-M1:` bootstrap and accepts three words
  in a separate field. Cbcl-bus SPEC-078 0.1.1-draft CON-001 and CON-002 govern it.
  Explicit legacy entry alone accepts its public carrier and `PAIR1-` value.
  A prefix, C value, error, old record, or failed recognizer SHALL NOT select or
  fall back to another mode.
- The screen SHALL complete the selected mode's local grammar, bound, checksum,
  and mode recognition before profile, hub, or relay contact. On default
  SingleLink success it obtains and retains the opaque native attempt tag before
  any asynchronous contact. Cbcl-bus SPEC-079 0.1.1-draft CON-002 governs that tag.
- **REQ-950**: The scan affordance SHALL distinguish three failure causes.
  Its messages cover platform permission refusal, person camera decline, and
  plugin-load failure. Each message SHALL leave the paste path visibly available.
  One collapsed "No camera" message is the
  [[SPEC-003-android-apk-distribution#BUG-202]] defect; it SHALL NOT return.
- A refused input reports one redacted recognition refusal without disclosing
  which secret, checksum, mode, or authenticated binding failed. The wallet
  SHALL NOT write secret input to clipboard history, autofill, password-manager,
  notification, deep-link, log, metric, or accessibility-value surfaces.

### pairing-wait

- Before contact, shows the recognized application HTTPS origin and declared
  relay origin. After profile authentication, it adds relay operator and
  privacy-policy identity as display-only live-profile facts, plus a status line.
- **REQ-955**: Before default contact, the wallet SHALL state that the current
  invitation authorizes contact with this application and its displayed relay
  for this link only. The authenticated request later identifies that provenance
  as `CeremonyGesture`. The screen SHALL NOT call it trusted or remembered.
  It SHALL NOT read, write, or promote a durable exact-pair row. Explicit legacy
  entry retains its existing-policy path or separate exact-pair prompt.
- **REQ-953**: This surface SHALL NOT render any input, picker, or repair affordance
  for a relay origin ([[SPEC-007-cbcl-pairing-cutover#REQ-813]]).
- Cancel is always reachable. In every default live phase it immediately consumes
  the native tagged cancellation path and disables old action controls. When an
  authenticated protocol abort/status path exists, cancellation also requests it.
  Local cancellation or a local clock does not claim hub closure. It does not
  authorize replacement ceremony material. Sender-side recovery and mode switch
  follow cbcl-bus SPEC-078 0.1.1-draft CON-005.

### pairing-consent

- Renders exactly the recognised intent: authority summary, application, action, and
  each field with its claimed-by-secret-holder marking. It also renders contact
  provenance, relay, transition, permissions, installation binding, locally
  derived DID, and fingerprint from the typed authenticated display. Untrusted
  text renders as text, never markup.
- **REQ-951**: Link or Approve MAY be visually primary. Decline SHALL be equally
  reachable by keyboard and screen reader. Neither control SHALL move position
  between renders; the screen cannot demote decline through movement.
- **REQ-956**: In default SingleLink, **Unlock to show identity** performs one
  local preview unlock. The passcode field clears immediately. The Link control
  remains disabled until the complete immutable request and local preview paint
  and the UI acknowledges that exact render. Its text SHALL be: **Share this
  identity with this application and link this device if the desktop comparison
  succeeds.** Link then permits preview disclosure and conditional continuation.
  The screen SHALL name the required desktop comparison and SHALL NOT display or
  synthesize another phone approval or unlock. Only the authenticated comparison
  can permit the native final protocol decision and later effects under cbcl-bus
  SPEC-079 0.1.1-draft CON-002 and CON-003.
- Explicit LegacyTwoDecision SHALL retain its preliminary approval, comparison,
  and separate final approval screen and fresh custody behavior. Default and
  legacy controls SHALL refuse outside their fixed mode and phase.
- **REQ-957**: During comparison or completion the exact request and preview stay
  visible with live status and Cancel. Backgrounding, cancellation, changed root,
  changed attempt, or the earliest custody/offer/relay deadline revokes the live
  SingleLink action. A stale asynchronous result SHALL NOT repaint, advance,
  disclose, or report success.

### pairing-result

- One terminal statement per outcome: accepted / declined / refused / failed, with the
  accepted state naming what the wallet now holds.
- Success SHALL render only after verification of the immutable hub final status
  and receipt, plus independent live reciprocal binding. It then requires the
  wallet's installed-record commit. A phone Link, desktop
  comparison, sent payload, or local pending record alone SHALL NOT show success.
- **REQ-952**: The capability boundary line SHALL derive from the build under
  [[SPEC-008-production-pairing-claimant#REQ-908]]. A demo build states the local
  conformance boundary. A production-claimant build states the actual standing
  of production pairing. Hardcoded demo prose SHALL NOT appear in non-demo builds.

## Accessibility

**NFR-950**: Every state above SHALL hold zero critical WCAG 2.2 AA violations.
This requirement applies at desktop and 320 CSS pixel widths and matches
[[SPEC-007-cbcl-pairing-cutover#NFR-803]]. Live regions announce status changes.
Colour is never the only signal.

## Tests

- **TEST-950** (core): each screen state renders in the existing screen-render harness;
  decline reachable by keyboard; no horizontal overflow at 320px.
- **TEST-951** (core): the three scan-failure messages are distinct and each leaves the
  paste field usable.
- **TEST-952** (core): no relay-origin input exists in any state (DOM assertion).
- **TEST-953** (depth, owner: repository owner): on-device Android pass — scan,
  consent, result — confirming what CI cannot ([[SPEC-003-android-apk-distribution]]'s
  "not confirmed on a device" caveat).
- **TEST-954** (core): drive default scan/paste, manual bootstrap-plus-words, and
  explicit legacy entry. Require exact mode grammar, no fallback, and local
  refusal before contact. In default only, require an opaque tag before
  asynchronous contact. Require redacted secret-free failures in every mode.
- **TEST-955** (core): default entry displays `CeremonyGesture`, exact application
  and relay, no remembered-trust text, prompt, or policy operation. Explicit legacy
  separately exercises existing-policy and new-pair prompt states.
- **TEST-956** (core): default entry counts one unlock and one Link. Require the
  complete render acknowledgement and cleared passcode. Hold final decision and
  effects until authenticated comparison, with no second approval. Run legacy
  separately and require both existing approvals.
- **TEST-957** (core): cancel, background, expire, change root, and deliver stale
  asynchronous results after each phase. Require immediate action disablement,
  no stale repaint or success, no post-revocation effect, and only authenticated
  exact-ceremony closure before a replacement mode invitation.
- **TEST-958** (core): accepted result appears only after verified immutable final
  status, receipt, independent reciprocal binding, and installed-record commit.
  Every earlier or mutated boundary renders refused, failed, or cancellable pending.

## Traceability

| Requirement | Tests |
|---|---|
| REQ-950 | TEST-951 |
| REQ-951 | TEST-950 |
| REQ-952 | TEST-950, TEST-958 |
| REQ-953 | TEST-952 |
| REQ-954 | TEST-954 |
| REQ-955 | TEST-955 |
| REQ-956 | TEST-956 |
| REQ-957 | TEST-957 |
| NFR-950 | TEST-950 |

## Changelog

- **0.2.0** — distinguishes default complete and manual SingleLink entry from
  explicit legacy entry. It specifies ceremony-only contact provenance and one
  unlock plus rendered Link. It also requires authenticated comparison before
  final effects, exact cancellation/expiry behavior, and verified terminal success.
- **0.1.0** — first draft: specifies the shipped pairing screens and the SPEC-008
  states; supersedes nothing (SCREEN-001 remains the browser-demo authority).
