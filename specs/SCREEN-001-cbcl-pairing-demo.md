---
id: SCREEN-001
title: cbcl-pairing Selfsame Demo
status: implemented
version: 0.2.0
last-updated: 2026-08-17
spec: SPEC-006
---

# SCREEN-001 — cbcl-pairing Selfsame Demo

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL are interpreted as described in BCP 14. Their
special meaning applies only when they appear in all capitals.

## Orientation

**Intent.** The page makes a complete [[Selfsame Credential Transfer]] visible
without suggesting that the relay understands the exchange.

**Structure.**

```text
+-------------------- page --------------------+
| title · experimental badge · reset           |
|                                              |
| application  <== opaque relay ==> Selfsame   |
| invitation       safe counters     consent   |
|                                              |
| ceremony gates · endpoint timeline           |
| terminal accepted / declined / failed result |
+----------------------------------------------+
```

**Load-bearing.** [[SPEC-006-cbcl-pairing-integration#REQ-702]] defines the complete ceremony.
[[SPEC-006-cbcl-pairing-integration#REQ-704]] defines relay opacity.
[[SPEC-006-cbcl-pairing-integration#REQ-706]] defines the consent gate.

**Controls.** [[SPEC-006-cbcl-pairing-integration#REQ-715]] requires an experimental label.
[[SPEC-006-cbcl-pairing-integration#NFR-703]] requires the WCAG baseline.

**Open.** Production product styling is excluded. Owner: Selfsame product owner.

## Primary user journey

1. Open the application page and select **Create invitation**.
2. Open the wallet page in another browser context.
3. Copy the complete invitation into the wallet page.
4. Select **Join ceremony**.
5. Review application, origin, account scope, recipient, and requested authority.
6. Select **Approve once** or **Decline**.
7. Read both terminal results and the verifier evidence summary.

Each endpoint SHALL remain on its own route. A state transition changes visible
controls without moving that endpoint to another page.

## Regions

### Header

The header identifies Selfsame, `cbcl-pairing`, and the not-production-approved boundary.
It includes a persistent **Reset** action.

### Application endpoint

The application route shows the direct invitation carrier and credential request.
It SHALL NOT show pairing keys, credential bytes, proof values, or private identifiers.

### Blind relay

Both routes show only opaque frame count, aggregate byte count, and closed visibility statements.

Endpoint instrumentation labels the timeline. The page SHALL NOT attribute those labels to relay state.

### Selfsame endpoint

The wallet route accepts the complete carrier. After secure-session activation,
it shows one recognised intent and the two decision controls.

The approval action is visually primary. The decline action remains adjacent and equally reachable by keyboard.

### Ceremony rail

The rail shows invitation, CPace, Finished, roles, intent, consent, credential,
and Selfsame acceptance in order.

Each item has text status. Color SHALL NOT be the only status signal.

### Result

The result states one of: accepted, declined, invitation mismatch, verifier refusal, or protocol failure.

An accepted result names the completed Selfsame acceptance predicate. It SHALL NOT expose the credential.

## Responsive layout

At widths of at least 960 CSS pixels, each route uses a two-column content layout.

Below 960 CSS pixels, the panels stack in ceremony order. The page SHALL have no horizontal overflow at 320 CSS pixels.

## Interaction states

- `idle`: create invitation is enabled.
- `invitation-created`: claimant entry is enabled and intent remains hidden.
- `awaiting-decision`: recognised intent and decision controls are visible.
- `accepted`: all controls except reset are disabled.
- `declined`: all controls except reset are disabled.
- `failed`: a safe error and fresh-start guidance are visible.

Every user action immediately sets a visible pending status and disables conflicting controls.

## Accessibility

- Every control SHALL have a programmatic label.
- Pending and terminal messages SHALL use a polite live region.
- Keyboard focus SHALL move to newly revealed consent or result content.
- Touch targets SHALL be at least 44 by 44 CSS pixels.
- Adjacent touch targets SHALL have at least 8 CSS pixels of clear spacing.
- Text and meaningful UI boundaries SHALL meet WCAG 2.2 AA contrast.
- Motion SHALL respect `prefers-reduced-motion`.

## Applied UX Heuristics

| Law | Application |
|---|---|
| [[UX Heuristics#Jakob's Law|Jakob's Law]] | Buttons, forms, focus, and status use browser conventions. |
| [[UX Heuristics#Doherty Threshold|Doherty Threshold]] | [[SPEC-006-cbcl-pairing-integration#NFR-701]] requires pending feedback within 100 ms. |
| [[UX Heuristics#Fitts's Law|Fitts's Law]] | Interactive targets meet the 44 by 44 CSS pixel baseline. |
| [[UX Heuristics#Hick's Law|Hick's Law]] | Each state presents at most three primary choices. |
| [[UX Heuristics#Miller's Law|Miller's Law]] | The ceremony rail groups eight steps into invitation, secure channel, consent, and acceptance regions. |
| [[UX Heuristics#Von Restorff Effect|Von Restorff Effect]] | The approval action is distinct without hiding decline. |
| [[UX Heuristics#Goal-Gradient Effect|Goal-Gradient Effect]] | The ceremony rail exposes current and remaining work. |
| [[UX Heuristics#Peak-End Rule|Peak-End Rule]] | Accepted, declined, and failed endings receive dedicated result treatments. |
| [[UX Heuristics#Aesthetic-Usability Effect|Aesthetic-Usability Effect]] | Automated tests exercise decisions and refusals rather than judging surface polish. |

## Test specification

### TEST-713: Interaction feedback and layout

**Validates:** [[SPEC-006-cbcl-pairing-integration#NFR-701]].

Drive every action at desktop and 320 CSS pixel widths. Verify pending feedback
appears within 100 ms and no horizontal overflow occurs.

Verify both routes persistently state **Experimental** and **Not production-approved**.

### TEST-714: Accessibility scan

**Validates:** [[SPEC-006-cbcl-pairing-integration#NFR-703]].

Run automated WCAG checks in every state. Verify zero critical violations,
logical focus order, text status, target size, and keyboard completion.

### TEST-715: Consent presentation

**Validates:** [[SPEC-006-cbcl-pairing-integration#REQ-706]].

Verify intent fields stay hidden before both Finished values and role projection.
Verify approval and decline become reachable only after recognised intent.
Drive decline in the wallet context. Verify both contexts become terminal,
the invitation cannot rejoin, and only **Reset** remains enabled.

### TEST-716: Secret and relay-label prohibition

**Validates:** [[SPEC-006-cbcl-pairing-integration#REQ-709]].

Inspect every state in both routes. Verify no invitation secret, credential bytes,
key material, proof, or verifier evidence appears in relay-labelled content.

## Amendment Channels

Amendable by: the Selfsame product owner and [[SPEC-006-cbcl-pairing-integration]] owner.

Through: a reviewed revision that updates affected tests and accessibility evidence.

Not amendable by: screenshots, demo output, implementation behavior, or visual preference alone.

Hard stops: consent remains explicit, secrets remain hidden, relay opacity remains accurate,
and the WCAG 2.2 AA baseline remains mandatory.
