---
id: SPEC-006
title: cbcl-pairing Integration and End-to-End Web Demo
status: superseded
tier: 1
version: 0.5.0
last-updated: 2026-08-17
owner-repo: selfsame
prototype-authorised: 2026-08-17 by the repository owner through the explicit integration goal
review-gate: superseded-by-SPEC-007; demo-evidence-only; production-not-approved
superseded-by: SPEC-007
depends-on: cbcl-pairing SPEC-001; SPEC-004; PROTO-004; SCREEN-001
---

# SPEC-006 — cbcl-pairing Integration and End-to-End Web Demo

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL are interpreted as described in BCP 14. Their
special meaning applies only when they appear in all capitals.

## Supersession disposition

[[SPEC-007-cbcl-pairing-cutover]] supersedes this prototype specification.
These artifacts remain historical demo evidence:

- REQ-701 through REQ-716 and NFR-701 through NFR-703;
- ADR-701 through ADR-704;
- CON-701 through CON-705; and
- TEST-701 through TEST-722.

They do not authorize a two-endpoint in-process production shell.
Vectors: the existing demo corpus remains evidence; this disposition changes no shared wire octet.

Evidence: [[SPEC-007-cbcl-pairing-cutover#TEST-819]].
Owner: Selfsame human repository owner.
Approved: 2026-08-17.
Production approval: not granted.

## Orientation

**Intent.** Selfsame adopts [[cbcl-pairing]] as the protocol authority for this
prototype integration. Two isolated endpoint sessions in ordinary same-browser tabs demonstrate one complete
[[Selfsame Credential Transfer]] through the real adapter and blind relay.

**Metaphor.** Selfsame supplies the sealed credential. `cbcl-pairing` supplies the guarded courier route.

**Terms.** The `CredentialGrant` is the pairing envelope. Its credential field
contains the complete PROTO-004 Selfsame grant bundle. A payload effect is a
protocol delivery signal, not an accepted Selfsame credential.

**Decline outcome.** The claimant sends one sealed decline after recognising the intent.
Both endpoints then close the session, erase session secrets, and mark the invitation spent.
Neither endpoint sends a credential payload or calls the Selfsame verifier.
The browser enters the terminal `declined` state and offers only **Reset**.

**Structure.**

```text
  browser shell              Selfsame integration                 blind relay
+----------------+      +--------------------------+      +-------------------+
| SCREEN-001     |----->| CON-701 adapter          |<====>| CON-702 mailbox   |
| invite/consent |typed | cbcl EndpointReducer     |opaque| bounded frames    |
+----------------+      +------------+-------------+      +-------------------+
                                  |
                    approved payload only
                                  v
                       +-----------------------+
                       | CON-703 verifier      |
                       | SPEC-004 accept_grant |
                       +-----------------------+
```

**Decisions.** [[SPEC-006-cbcl-pairing-integration#ADR-701]] adopts the dependency instead of copying its protocol.
[[SPEC-006-cbcl-pairing-integration#ADR-702]] pins the sibling baseline.
[[SPEC-006-cbcl-pairing-integration#ADR-703]] uses the credential profile.
[[SPEC-006-cbcl-pairing-integration#ADR-704]] keeps the demo loopback-only.

**Load-bearing.** [[SPEC-006-cbcl-pairing-integration#REQ-701]] selects one pairing engine.
[[SPEC-006-cbcl-pairing-integration#REQ-702]] requires the complete browser ceremony.
[[SPEC-006-cbcl-pairing-integration#REQ-703]] preserves Selfsame authorization.
[[SPEC-006-cbcl-pairing-integration#REQ-704]] preserves the blind-relay boundary.

**Controls.**

- [[SPEC-006-cbcl-pairing-integration#REQ-705]] forbids production invitation allocation.
- [[SPEC-006-cbcl-pairing-integration#REQ-706]] forbids grant release before explicit approval.
- [[SPEC-006-cbcl-pairing-integration#REQ-707]] forbids legacy cryptography inside the new adapter.
- [[SPEC-006-cbcl-pairing-integration#NFR-702]] binds the demo to loopback.
- [[SPEC-006-cbcl-pairing-integration#NFR-703]] requires zero critical accessibility violations.

**Open.** The production Tauri cutover requires human cryptography review and new migration vectors.
Owner: Selfsame security owner.

**Detail.** Reviewer: [[SPEC-006-cbcl-pairing-integration#Architecture decisions]] and
[[SPEC-006-cbcl-pairing-integration#Production boundary]]. Implementer:
[[SPEC-006-cbcl-pairing-integration#Contracts]] to [[SPEC-006-cbcl-pairing-integration#Test specification]].
Stakeholder: [[SPEC-006-cbcl-pairing-integration#Requirements]] to
[[users/person/person-happy-paths]].

## Failure mode

Selfsame currently owns a separate SPAKE2 ceremony, relay API, mailbox derivation,
and browser binding. This duplicates the reusable protocol now present in [[cbcl-pairing]].

### BUG-601: ordinary application and wallet tabs shared one session cookie

**Severity:** S2
**Priority:** P1
**Status:** verified
**Reported by:** user
**Assigned to:** Codex

**Specification reference:** This bug violates [[SPEC-006-cbcl-pairing-integration#REQ-702]]
and [[SPEC-006-cbcl-pairing-integration#CON-704]].
[[SPEC-006-cbcl-pairing-integration#TEST-704]] provides the regression path.

**Environment:** Chromium loaded `/application` and `/wallet` as ordinary tabs in one browser context.

**Reproduction:** Load the application tab. Load the wallet tab. Select **Create Invitation** in the application tab.

**Expected behavior:** Both endpoint sessions coexist. The application creates one invitation.

**Actual behavior:** The wallet page replaced the application session cookie. The start request returned HTTP 401.

**Root cause:** The implementation used one cookie name for both endpoint roles.
The browser test hid the defect by creating one isolated browser context per endpoint.

**Resolution:** The server issues distinct application and wallet cookies.
Every request carries an exact role header. [[SPEC-006-cbcl-pairing-integration#TEST-704]] now runs both endpoints as ordinary tabs.

**Evidence:** `cargo test -p selfsame-pairing --locked --no-fail-fast` passes 19 integration tests and one compile-fail test.
`npm run e2e:pairing` passes both browser tests across the complete state set.

**AI detection context:** Codex GPT-5 reproduced the user report with loopback HTTP and Chromium.
Confidence is high because the failure and regression path both ran directly.

The duplicate path creates two authorities for pairing order, transcript binding,
consent, burn behavior, and relay limits. A fix in one implementation does not protect the other.

The requested remedy fits the failure. Composition removes the second protocol authority
while Selfsame retains its application-specific credential acceptance predicate.

## Intent source and user outcome

The repository owner requested that Selfsame integrate `../cbcl-pairing` and ship
an end-to-end demo web application from a clean branch based on `main`.

The dominant user is the person in [[users/person/person-profile]]. The person
creates an invitation, transfers it, reviews exact authority, approves once, and sees an accepted device grant.

The developer in [[users/developer/developer-profile]] needs one command that starts
the demo and one automated test that proves the approved and declined branches.

## Scope

This version includes:

- evidence that the branch started at the exact `main` revision;
- a pinned workspace dependency on `../cbcl-pairing`;
- a Selfsame-owned adapter around the dependency's credential profile;
- two isolated loopback browser clients using the adapter;
- a real in-memory `cbcl-pairing` relay between both endpoints;
- authoritative Selfsame grant acceptance after pairing approval;
- integration, negative, scope-invariant, accessibility, and browser tests;
- migration documentation that identifies the legacy path.

This version excludes production relay operation, public binding, TLS termination,
mobile deployment, and production activation of the legacy Tauri replacement.

The legacy Tauri path is rollback-only for this prototype. It SHALL NOT be
reachable from the demo, imported by the adapter, or described as the selected protocol.

## Requirements

### REQ-701: One pairing engine

The prototype Selfsame credential-pairing surface SHALL use `cbcl-pairing` for invitation,
CPace, Finished, CBCL session, channel, and endpoint state.

Trace:
- [[SPEC-006-cbcl-pairing-integration#CON-701]]
- [[SPEC-006-cbcl-pairing-integration#TEST-701]]
- [[SPEC-006-cbcl-pairing-integration#TEST-702]]
- [[SPEC-006-cbcl-pairing-integration#OBS-701]]

### REQ-702: Complete browser ceremony

The demo SHALL create an invitation, establish the secure session, display recognised
intent, record one decision, and reach one terminal result.

The approval result SHALL contain one transferred Selfsame credential accepted by
the [[SPEC-004-application-scoped-identity#CON-206]] predicate.

Trace:
- [[SPEC-006-cbcl-pairing-integration#CON-701]]
- [[SPEC-006-cbcl-pairing-integration#CON-704]]
- [[SPEC-006-cbcl-pairing-integration#TEST-703]]
- [[SPEC-006-cbcl-pairing-integration#TEST-704]]
- [[SPEC-006-cbcl-pairing-integration#OBS-701]]

### REQ-703: Selfsame remains the authorization authority

The integration SHALL apply `selfsame_app_identity::accept::accept_grant` before it
reports a credential as accepted.

Trace:
- [[SPEC-006-cbcl-pairing-integration#CON-703]]
- [[SPEC-006-cbcl-pairing-integration#TEST-705]]
- [[SPEC-006-cbcl-pairing-integration#TEST-706]]
- [[SPEC-006-cbcl-pairing-integration#OBS-702]]

### REQ-704: Blind relay boundary

The relay SHALL transport only recognised opaque protocol messages and bounded mailbox state.

Trace:
- [[SPEC-006-cbcl-pairing-integration#CON-702]]
- [[SPEC-006-cbcl-pairing-integration#TEST-707]]
- [[SPEC-006-cbcl-pairing-integration#TEST-708]]
- [[SPEC-006-cbcl-pairing-integration#OBS-703]]

### REQ-705: Production hold

The integration SHALL NOT enable production invitation allocation or public network binding.

Trace:
- [[SPEC-006-cbcl-pairing-integration#CON-704]]
- [[SPEC-006-cbcl-pairing-integration#TEST-709]]
- [[SPEC-006-cbcl-pairing-integration#OBS-701]]

### REQ-706: Consent before payload

The allocator SHALL NOT send a credential payload before one exact recognised intent receives explicit approval.

Trace:
- [[SPEC-006-cbcl-pairing-integration#CON-701]]
- [[SPEC-006-cbcl-pairing-integration#TEST-710]]
- [[SPEC-006-cbcl-pairing-integration#TEST-711]]
- [[SPEC-006-cbcl-pairing-integration#OBS-701]]

### REQ-707: Legacy isolation

The new adapter SHALL NOT import `selfsame_core::spake2`, `PairingSession`,
`PairingCarrier`, or the `PROTO-003` relay client.

Trace:
- [[SPEC-006-cbcl-pairing-integration#CON-701]]
- [[SPEC-006-cbcl-pairing-integration#TEST-702]]
- [[SPEC-006-cbcl-pairing-integration#OBS-701]]

### REQ-708: Protocol success is not authorization

CPace, Finished, CBCL validity, carrier possession, and approval SHALL NOT
constitute an accepted Selfsame credential.

Trace:
- [[SPEC-006-cbcl-pairing-integration#CON-703]]
- [[SPEC-006-cbcl-pairing-integration#TEST-706]]
- [[SPEC-006-cbcl-pairing-integration#TEST-716]]

### REQ-709: Relay opacity

The relay SHALL NOT receive invitation secrets, plaintext intent, approval meaning,
credential plaintext, or Selfsame verifier evidence.

Trace:
- [[SPEC-006-cbcl-pairing-integration#CON-702]]
- [[SPEC-006-cbcl-pairing-integration#TEST-707]]
- [[SPEC-006-cbcl-pairing-integration#TEST-717]]

### REQ-710: Decline is terminal

After decline, both endpoints SHALL close, erase session secrets, and mark the invitation spent.
The claimant SHALL display `declined` with only **Reset** enabled.

Trace:
- [[SPEC-006-cbcl-pairing-integration#CON-701]]
- [[SPEC-006-cbcl-pairing-integration#TEST-710]]
- [[SCREEN-001-cbcl-pairing-demo#TEST-715]]

### REQ-711: Failure cannot authorize

Mismatch, protocol failure, cancellation, or expiry SHALL produce no accepted credential.

Trace:
- [[SPEC-006-cbcl-pairing-integration#CON-701]]
- [[SPEC-006-cbcl-pairing-integration#TEST-711]]
- [[SPEC-006-cbcl-pairing-integration#TEST-718]]

### REQ-712: Branch provenance

The implementation branch SHALL differ from `main` and record its exact `main` merge base.

Trace:
- [[SPEC-006-cbcl-pairing-integration#TEST-719]]

### REQ-713: Loopback request authority

Every mutating demo request SHALL carry the exact origin, JSON media type,
ceremony identifier, browser-session identifier, and unguessable endpoint capability.

Trace:
- [[SPEC-006-cbcl-pairing-integration#CON-704]]
- [[SPEC-006-cbcl-pairing-integration#TEST-720]]
- [[SPEC-006-cbcl-pairing-integration#TEST-721]]

### REQ-714: One-command developer outcome

`cargo run -p selfsame-pairing --example web-demo` SHALL start the loopback demo.

Trace:
- [[SPEC-006-cbcl-pairing-integration#CON-705]]
- [[SPEC-006-cbcl-pairing-integration#TEST-722]]

### REQ-715: Experimental boundary

Every demo page SHALL identify the integration as experimental and not production-approved.

Trace:
- [[SCREEN-001-cbcl-pairing-demo#TEST-713]]

### REQ-716: Approval-bound acceptance value

Only the adapter's reducer-effect handler SHALL construct the opaque value
accepted by the Selfsame verification function.

Trace:
- [[SPEC-006-cbcl-pairing-integration#CON-703]]
- [[SPEC-006-cbcl-pairing-integration#TEST-716]]

## Non-functional requirements

### NFR-701: Interactive feedback

The browser SHALL display pending feedback within 100 ms of each user action under loopback demo conditions.

Trace:
- [[SCREEN-001-cbcl-pairing-demo#TEST-713]]
- [[SPEC-006-cbcl-pairing-integration#OBS-701]]

### NFR-702: Loopback confinement

The demo server SHALL reject every non-loopback bind address before opening a listener.

Trace:
- [[SPEC-006-cbcl-pairing-integration#TEST-709]]
- [[SPEC-006-cbcl-pairing-integration#OBS-701]]

### NFR-703: Accessibility baseline

The demo SHALL have zero critical WCAG 2.2 AA violations in its automated browser scan.

Trace:
- [[SCREEN-001-cbcl-pairing-demo#TEST-714]]
- [[SPEC-006-cbcl-pairing-integration#OBS-701]]

## Architecture decisions

### ADR-701: Compose the existing pairing engine

**Status:** accepted for the prototype.

Selfsame uses the sibling crate at Simplicity Ladder rung 4. Reimplementing
CPace, CBCL monitors, secure channels, mailbox state, or relay controls is rejected.

This placement gives every Selfsame shell one shared adapter and keeps application
credential rules in `selfsame-app-identity`.

### ADR-702: Pin the inspected sibling baseline

**Status:** accepted for the prototype.

The integration records the exact `cbcl-pairing` Git revision in a root pin file.
Cargo uses the sibling path for local development.

The reviewed revision is `197d4cb3d1560ab5328df28fc984269799c510f9`.

The pin detects unreviewed dependency drift. CI clones the recorded revision beside Selfsame.

### ADR-703: Select the credential profile

**Status:** accepted for the prototype.

The integration uses `CredentialProfile`, `CredentialIntentClaims`, and `CredentialGrant`.
The profile already binds application identifier, HTTPS origin, scope, recipient, and credential bytes.

Selfsame runs its full acceptance predicate after the pairing layer releases the recognised payload.
No pairing verdict becomes a Selfsame authorization result.

### ADR-704: Keep the demonstration in one loopback process

**Status:** accepted for the prototype.

One Axum process serves two isolated endpoint sessions.
The sessions coexist in one browser context.
The process composes two real endpoint reducers with a real in-memory `RelayService` boundary.

This arrangement exercises the protocol core end to end. It does not claim independent deployment, TLS, or production readiness.

## Contracts

### CON-701: Selfsame pairing adapter

**Interface:** `selfsame_pairing::DemoCeremony` and its testable native API.

**Preconditions:**

- The shell supplies CSPRNG bytes for every secret and ephemeral.
- The invitation uses the `anuna.io/credential/v1` application identifier.
- The invitation uses a direct mailbox locator and a 16-octet secret.
- The shell persists or retains the invitation consumption record before online processing.

**Postconditions:**

- Both endpoint reducers reach the projected session only after both Finished values verify.
- Exactly one recognised intent reaches the decision surface.
- Approval permits exactly one payload attempt.
- Decline permits one sealed refusal and zero payload attempts.
- Every terminal result erases endpoint secrets and consumes the invitation.
- Relay delivery encodes and recognises each `ChannelFrame` before endpoint input.

**Error model:** one closed `IntegrationError` enumeration maps recognition,
pairing, profile, Selfsame acceptance, state, and I/O failures.

**Implements:**
- [[SPEC-006-cbcl-pairing-integration#REQ-701]]
- [[SPEC-006-cbcl-pairing-integration#REQ-702]]
- [[SPEC-006-cbcl-pairing-integration#REQ-706]]
- [[SPEC-006-cbcl-pairing-integration#REQ-707]]

**Verified by:**
- [[SPEC-006-cbcl-pairing-integration#TEST-701]]
- [[SPEC-006-cbcl-pairing-integration#TEST-702]]
- [[SPEC-006-cbcl-pairing-integration#TEST-703]]
- [[SPEC-006-cbcl-pairing-integration#TEST-710]]

### CON-702: Relay adapter

**Interface:** the `cbcl_pairing::relay::RelayService` in-memory composition.

**Input grammar:** one canonical CBOR `ClientMessage` from `pairing-v1.cddl` per transport unit.

**Recognition:** `cbcl_pairing::wire::decode_client_message` performs full recognition before relay state changes.

**Postconditions:** only opaque bodies, membership state, sequence state, acknowledgements, expiry, and privacy-safe counters exist at the relay boundary.

**Error model:** malformed, crowded, expired, oversized, out-of-order, and unauthorized inputs return closed protocol errors without application effects.

**Implements:**
- [[SPEC-006-cbcl-pairing-integration#REQ-704]]

**Verified by:**
- [[SPEC-006-cbcl-pairing-integration#TEST-707]]
- [[SPEC-006-cbcl-pairing-integration#TEST-708]]

### CON-703: Selfsame credential acceptance boundary

**Interface:** `ApprovedCredential` is opaque outside the adapter. The private
`accept_transferred_credential` function consumes that value and explicit verifier context.

**Construction:** only the reducer-effect handler constructs `ApprovedCredential`.
It matches the `DeliverGrant` body to the exact encoded `CredentialGrant` for the ceremony.

**Postconditions:** success contains `selfsame_app_identity::accept::Acceptance`.
No other success type represents an accepted Selfsame credential.

**Error model:** every [[SPEC-004-application-scoped-identity#CON-206]] failure remains a refusal with its numbered step.

**Implements:**
- [[SPEC-006-cbcl-pairing-integration#REQ-703]]
- [[SPEC-006-cbcl-pairing-integration#REQ-708]]
- [[SPEC-006-cbcl-pairing-integration#REQ-716]]

**Verified by:**
- [[SPEC-006-cbcl-pairing-integration#TEST-705]]
- [[SPEC-006-cbcl-pairing-integration#TEST-706]]
- [[SPEC-006-cbcl-pairing-integration#TEST-716]]

### CON-704: Loopback demo HTTP boundary

**Placement:** Axum and Hyper recognise HTTP at Simplicity Ladder rung 4.
Serde request structures use `deny_unknown_fields` and reject duplicate members.

**Interface:** `GET /application`, `GET /wallet`, and static assets are public.
The typed API is `POST /api/start|claim|approve|decline|reset` and `GET /api/state`.

Each endpoint page response creates one 256-bit browser-session identifier in
an HttpOnly, SameSite-Strict, path-bound cookie. It embeds a separate 256-bit
bootstrap capability in a role-specific HTML meta element.

The application cookie is `selfsame_demo_application_session=` and the wallet
cookie is `selfsame_demo_wallet_session=`, each followed by 43 canonical
base64url characters. Both cookies MAY coexist in one browser context.
Duplicate cookies for the selected role are invalid. Other cookie names carry no authority.

`start` requires the application bootstrap capability and session cookie.
It returns the new ceremony identifier and rotated application capability.
`claim` requires the wallet bootstrap capability, session cookie, and invitation.
It returns the matched ceremony identifier and rotated wallet capability.

The authorization matrix is closed:

| Route | Required role | Result |
|---|---|---|
| `start` | application bootstrap | create one invitation |
| `claim` | wallet bootstrap | join one matching invitation |
| `approve` | wallet ceremony | commit claimant approval once |
| `decline` | wallet ceremony | commit claimant decline once |
| `state` | matching application or wallet ceremony | return that endpoint view |
| `reset` | matching application or wallet ceremony | cancel both endpoints and rotate both capabilities |

No other role and route pairing is authorized. A wrong-role request causes no
transition, payload effect, verifier call, capability rotation, or response detail.

**Input contract:** request heads are at most 16 KiB. Bodies are at most 4 KiB.
Mutations require `application/json`, an exact loopback `Host`, an exact `Origin`,
the role-specific session cookie, `X-Selfsame-Role`, and `X-Selfsame-Capability`.
Post-bootstrap mutations also require `X-Selfsame-Ceremony`.

`start` accepts an empty object. `claim` accepts only an encoded invitation.
`approve`, `decline`, and `reset` accept only the current state version.

The invitation recogniser accepts the complete decoded carrier before ceremony action.
Each capability contains 256 CSPRNG bits and is bound to one endpoint and browser session.
Bootstrap capabilities are single-use and rotate before a response is returned.
The server serialises transitions per ceremony and rejects stale or concurrent versions.

**Postconditions:** every response includes `Cache-Control: no-store`,
`X-Content-Type-Options: nosniff`, and a self-only Content Security Policy.

**Error model:** invalid, cross-origin, stale, replayed, or unauthorized input
returns one safe error token and causes no ceremony state change.

**Implements:**
- [[SPEC-006-cbcl-pairing-integration#REQ-702]]
- [[SPEC-006-cbcl-pairing-integration#REQ-705]]
- [[SPEC-006-cbcl-pairing-integration#REQ-713]]

**Verified by:**
- [[SPEC-006-cbcl-pairing-integration#TEST-704]]
- [[SPEC-006-cbcl-pairing-integration#TEST-709]]
- [[SPEC-006-cbcl-pairing-integration#TEST-712]]
- [[SPEC-006-cbcl-pairing-integration#TEST-720]]
- [[SPEC-006-cbcl-pairing-integration#TEST-721]]

### CON-705: Developer launch contract

**Interface:** `cargo run -p selfsame-pairing --example web-demo`.

**Postconditions:** the process binds only `127.0.0.1`, prints the selected URL,
serves both clients, and exits non-zero for a non-loopback bind request.

**Verified by:**
- [[SPEC-006-cbcl-pairing-integration#TEST-709]]
- [[SPEC-006-cbcl-pairing-integration#TEST-722]]

## Purity Boundary Map

### Pure core

- `cbcl-pairing`: recognition, CPace, channel, CBCL monitors, endpoint reducer, mailbox transitions.
- `selfsame-app-identity`: grant construction, recognition, and acceptance predicate.

### Effectful shell

- `selfsame-pairing-demo`: randomness, Axum HTTP, clock, browser assets, and in-memory orchestration.

### Boundary values

- `Invitation`, `ChannelFrame`, `EndpointEffect`, `CredentialGrant`, and `Acceptance`.

### Dependency rule

Dependencies point from the demo shell through the adapter toward both pure cores.
Neither pure core imports the demo shell.

### Enforcement

[[SPEC-006-cbcl-pairing-integration#TEST-702]] inspects the adapter dependency and source boundary.

## Test specification

### Core

#### TEST-701: Dependency integration

**Validates:** [[SPEC-006-cbcl-pairing-integration#REQ-701]].

Build the adapter through the pinned sibling path. Verify the CBCL dialect hashes
match the dependency's published constants. Verify sibling `HEAD` equals the pin
and refuse tracked-file drift or a mismatched sibling revision.

#### TEST-702: Legacy isolation

**Validates:** [[SPEC-006-cbcl-pairing-integration#REQ-701]], [[SPEC-006-cbcl-pairing-integration#REQ-707]].

Inspect the adapter dependency tree and source. Refuse any legacy SPAKE2 or `PROTO-003` pairing import.

#### TEST-703: Approved ceremony

**Validates:** [[SPEC-006-cbcl-pairing-integration#REQ-702]].

Run both real endpoint reducers through CPace, both Finished values, role projection,
intent, approval, payload, and one Selfsame acceptance.

#### TEST-704: Browser end to end

**Validates:** [[SPEC-006-cbcl-pairing-integration#REQ-702]].

Start the loopback server. Drive application and wallet tabs in one browser
context through
invitation, relay frames, approval, `accept_grant`, and the accepted result.

#### TEST-705: Selfsame verifier positive

**Validates:** [[SPEC-006-cbcl-pairing-integration#REQ-703]].

Transfer one valid application-account grant. Verify `accept_grant` succeeds at every numbered step.

#### TEST-706: Selfsame verifier negative output

**Validates:** [[SPEC-006-cbcl-pairing-integration#REQ-703]].

Mutate the transferred grant signature. Verify pairing can transport the bytes but Selfsame refuses authorization.

#### TEST-707: Relay opacity

**Validates:** [[SPEC-006-cbcl-pairing-integration#REQ-704]].

Inspect relay state and logs after a complete ceremony. Verify no secret, intent field, credential, or verifier evidence appears.

#### TEST-708: Relay scope invariant

**Validates:** [[SPEC-006-cbcl-pairing-integration#REQ-704]].

Compare relay state before and after one ceremony. Verify only the selected mailbox and bounded counters change.

#### TEST-709: Production prohibition

**Validates:** [[SPEC-006-cbcl-pairing-integration#REQ-705]], [[SPEC-006-cbcl-pairing-integration#NFR-702]].

Attempt a non-loopback bind. Verify no listener opens and no production allocation switch exists.

#### TEST-710: Decline prohibits payload

**Validates:** [[SPEC-006-cbcl-pairing-integration#REQ-706]].

Decline the recognised intent. Verify zero payload effects, zero Selfsame verifier calls, and erased endpoint secrets.

#### TEST-711: Wrong invitation prohibits intent

**Validates:** [[SPEC-006-cbcl-pairing-integration#REQ-706]].

Exercise a different invitation secret, protocol failure, cancellation, and expiry.
Verify zero accepted results and terminal secret erasure in every case.

#### TEST-712: HTTP negative input

**Validates:** [[SPEC-006-cbcl-pairing-integration#REQ-702]].

Submit malformed JSON, unknown members, non-canonical invitation data, and oversized bodies.
Verify every input is refused before a ceremony transition.

#### TEST-716: Acceptance provenance

**Validates:** [[SPEC-006-cbcl-pairing-integration#REQ-708]],
[[SPEC-006-cbcl-pairing-integration#REQ-716]].

Compile-fail an external attempt to construct `ApprovedCredential` or invoke
the private acceptance function. Verify approval alone reports no accepted credential.

#### TEST-717: Relay recogniser and opacity

**Validates:** [[SPEC-006-cbcl-pairing-integration#REQ-704]],
[[SPEC-006-cbcl-pairing-integration#REQ-709]].

Round-trip every relayed client message through canonical CBOR recognition.
Reject malformed, trailing, and non-canonical inputs before relay state changes.

#### TEST-718: Terminal and replay matrix

**Validates:** [[SPEC-006-cbcl-pairing-integration#REQ-711]].

Exercise cancellation, expiry, decision replay, payload replay, simultaneous claims,
and invitation reuse. Verify closed results, spent invitations, and zero extra effects.

#### TEST-719: Branch baseline

**Validates:** [[SPEC-006-cbcl-pairing-integration#REQ-712]].

Verify the branch is `feature/cbcl-pairing-demo`, differs from `main`, and has
merge base `22801e77dc0c7c493b6e811f79cb17c7cd9352ab`.

#### TEST-720: HTTP recognition and authority

**Validates:** [[SPEC-006-cbcl-pairing-integration#REQ-713]].

Reject wrong Host, Origin, media type, ceremony, browser session, capability,
unknown member, duplicate member, oversized body, stale version, and replay.
Verify each page issues distinct bootstrap authority and each successful bootstrap rotates it once.
Use each valid same-ceremony capability on every wrong-role route. Verify zero state change,
payload effects, verifier calls, and capability rotations.

#### TEST-721: Concurrent browser isolation

**Validates:** [[SPEC-006-cbcl-pairing-integration#REQ-713]].

Open two application pages and two wallet pages. Verify capabilities cannot cross
ceremonies and concurrent decisions produce exactly one terminal transition.

#### TEST-722: Clean launch smoke test

**Validates:** [[SPEC-006-cbcl-pairing-integration#REQ-714]].

Start the documented command on a clean build output, discover its loopback URL,
load both pages, complete approval and decline flows, then stop it cleanly.

### Depth

Run the pinned `cbcl-pairing` wire and relay fuzz corpus before completion.
The upstream curated mutation suite remains a production depth test.
Owner: `cbcl-pairing` security owner.

The production Tauri cutover, mobile carriers, independent relay deployment,
and cross-runtime vectors remain depth tests. Owner: Selfsame security owner.

## Mutation gate

Before completion, remove the explicit-approval check in a temporary mutation.
[[SPEC-006-cbcl-pairing-integration#TEST-710]] SHALL fail.

Before completion, bypass `accept_grant` in a temporary mutation.
[[SPEC-006-cbcl-pairing-integration#TEST-705]] or [[SPEC-006-cbcl-pairing-integration#TEST-706]] SHALL fail.

## Observability

### OBS-701: Ceremony state

The demo state reports one closed stage name, endpoint secret-erasure state,
delivered payload count, verifier call count, and terminal outcome.

### OBS-702: Selfsame acceptance result

The adapter records success or the closed [[SPEC-004-application-scoped-identity#CON-206]] failure step.
It records no credential bytes, key material, account alias, or proof.

### OBS-703: Relay-safe counters

The demo reports opaque frame count and aggregate byte count.
It reports no frame meaning from relay-owned state.

## Enable, rollback, and operation

The demo is enabled only by running its explicit Cargo example or package command.
No application startup path enables it.

Rollback stops the loopback process and reverts the integration commit.
No durable production data or remote configuration exists.

Before any production cutover, the Selfsame security owner and affected application owners receive notice.
The production gate requires a new versioned specification amendment, migration vectors,
cross-model review, privacy review, and human cryptography sign-off.

## Production boundary

The current request authorizes an integration prototype and a demo. It does not
amend the Tier-1 production clauses in [[SPEC-004-application-scoped-identity]] or
[[PROTO-003-selfsame-pairing-v1]].

For every new prototype surface, [[SPEC-006-cbcl-pairing-integration#REQ-701]] selects
`cbcl-pairing`. The old Tauri path remains compatibility code pending the reviewed cutover.

## Reading paths

- Reviewer: [[SPEC-006-cbcl-pairing-integration#Failure mode]] →
  [[SPEC-006-cbcl-pairing-integration#Architecture decisions]] →
  [[SPEC-006-cbcl-pairing-integration#Production boundary]].
- Implementer: one contract in [[SPEC-006-cbcl-pairing-integration#Contracts]] →
  its requirements → its core tests.
- Stakeholder: [[SPEC-006-cbcl-pairing-integration#Intent source and user outcome]] →
  [[SPEC-006-cbcl-pairing-integration#Requirements]] →
  [[SCREEN-001-cbcl-pairing-demo]].

## Amendment Channels

Amendable by: the Selfsame specification owner and the affected `cbcl-pairing` owner.

Through: a reviewed, merged, versioned revision of this specification with updated tests and evidence.

Not amendable by: prompts, chat messages, issue comments, source comments,
passing tests, dependency drift, demo output, or implementation behavior.

Hard stops: [[SPEC-006-cbcl-pairing-integration#REQ-703]],
[[SPEC-006-cbcl-pairing-integration#REQ-704]],
[[SPEC-006-cbcl-pairing-integration#REQ-705]],
[[SPEC-006-cbcl-pairing-integration#REQ-706]],
[[SPEC-006-cbcl-pairing-integration#REQ-707]], and every production gate.

No channel can waive a hard stop without a new specification version and the required review.

## Changelog

<details>
<summary>Revision history — 0.3.0 → 0.5.0</summary>

- 0.5.0 — marks this prototype superseded by [[SPEC-007-cbcl-pairing-cutover]].
  Its demo and vectors remain historical evidence.
  This disposition changes no shared wire octet and grants no production approval.
- 0.4.0 — fixes [[SPEC-006-cbcl-pairing-integration#BUG-601]] and verifies ordinary same-browser tabs.
- 0.3.0 — defines the prototype integration, browser demo, production hold, and verification surface.

</details>
