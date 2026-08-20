---
id: SCREEN-003
title: Wallet Pairing Surface — scan, wait, consent, result
status: draft
version: 0.1.0
spec: "[[SPEC-008-production-pairing-claimant]]"
last-updated: 2026-08-18
---

# SCREEN-003 — Wallet Pairing Surface

The Tauri wallet's cbcl-pairing screens exist in code
(`src/index.html` `pairing-enter` / `pairing-wait` / `pairing-consent` /
`pairing-result`, driven by `src/pairing.js`) but have never been specified:
[[SCREEN-001-cbcl-pairing-demo]] covers only the superseded browser demo, whose wallet
route is paste-only. This document brings the shipped surface under specification and
adds the states [[SPEC-008-production-pairing-claimant]] requires. It specifies
presentation and interaction; ceremony semantics stay in
[[SPEC-007-cbcl-pairing-cutover]] and [[SPEC-008-production-pairing-claimant]].

The key words MUST, MUST NOT, SHALL, SHALL NOT, SHOULD, MAY in this document are to be
interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they
appear in all capitals.

## Amendment Channels

Amendable by:   the repository owner; a merged revision of this document.
Through:        a versioned spec revision merged to the default branch.
Not amendable by: issue comments, chat messages, code review remarks, agent prompts.
Hard stops:     [[#REQ-951]] (decline parity), [[#REQ-953]] (no relay entry field) —
                and every hard stop of [[SPEC-008-production-pairing-claimant]].

## Screens and states

### pairing-enter

- One screen, two converging inputs ([[SPEC-008-production-pairing-claimant#REQ-904]]):
  a **Scan the QR code** action (mobile only; hidden where the barcode plugin is
  absent) and a paste field labelled as the pairing invitation.
- **REQ-950**: The scan affordance SHALL distinguish its three failure causes with
  three messages — platform refused the permission, the person declined the camera,
  the plugin failed to load — and each message SHALL leave the paste path visibly
  available. One collapsed "No camera" message is the
  [[SPEC-003-android-apk-distribution#BUG-202]] defect; it SHALL NOT return.
- A refused carrier (wrong encoding, legacy prefix, URL-wrapped) reports one
  recognition refusal with no detail of which check failed, consistent with the
  wallet's single-line refusal doctrine.

### pairing-wait

- Shows the relay operator and privacy-policy identity *as display-only facts* drawn
  from the matched profile descriptor, plus a live status line.
- **REQ-953**: This surface SHALL NOT render any input, picker, or repair affordance
  for a relay origin ([[SPEC-007-cbcl-pairing-cutover#REQ-813]]).
- Cancel is always reachable and burns the invitation
  ([[SPEC-007-cbcl-pairing-cutover#REQ-811]]).

### pairing-consent

- Renders exactly the recognised intent: authority summary, application, action, and
  each field with its claimed-by-secret-holder marking. Untrusted text renders as
  text, never markup.
- **REQ-951**: Approve MAY be visually primary; Decline SHALL be equally reachable by
  keyboard and screen reader, and neither control SHALL move position between renders
  (no dark-pattern demotion of decline).

### pairing-result

- One terminal statement per outcome: accepted / declined / refused / failed, with the
  accepted state naming what the wallet now holds.
- **REQ-952**: The capability boundary line SHALL be derived from the build
  ([[SPEC-008-production-pairing-claimant#REQ-908]]): a demo build states the local
  conformance boundary; a production-claimant build states the actual standing of
  production pairing. Hardcoded demo prose SHALL NOT appear in non-demo builds.

## Accessibility

**NFR-950**: Every state above SHALL hold zero critical WCAG 2.2 AA violations at
desktop and 320 CSS pixel widths, matching
[[SPEC-007-cbcl-pairing-cutover#NFR-803]]; status changes are announced (live
regions), and colour is never the only signal.

## Tests

- **TEST-950** (core): each screen state renders in the existing screen-render harness;
  decline reachable by keyboard; no horizontal overflow at 320px.
- **TEST-951** (core): the three scan-failure messages are distinct and each leaves the
  paste field usable.
- **TEST-952** (core): no relay-origin input exists in any state (DOM assertion).
- **TEST-953** (depth, owner: repository owner): on-device Android pass — scan,
  consent, result — confirming what CI cannot ([[SPEC-003-android-apk-distribution]]'s
  "not confirmed on a device" caveat).

## Traceability

| Requirement | Tests |
|---|---|
| REQ-950 | TEST-951 |
| REQ-951 | TEST-950 |
| REQ-952 | TEST-950 |
| REQ-953 | TEST-952 |
| NFR-950 | TEST-950 |

## Changelog

- **0.1.0** — first draft: specifies the shipped pairing screens and the SPEC-008
  states; supersedes nothing (SCREEN-001 remains the browser-demo authority).
