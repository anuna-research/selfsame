---
id: SPEC-004
title: Application- and Account-Scoped Identity — deterministic home keys, acct aliases, portable device grants, and provider discovery
status: draft
tier: 1
version: 0.5.0
audience: agent, human, application developer, infrastructure provider
author: Anuna Research (drafted with Codex, 2026-07-30)
last-updated: 2026-07-30
owner-repo: selfsame
affects-repos: selfsame, anuna-ssi, did-crdt, adopting applications
review-gate: not-approved — Tier-1; all ADRs are PROPOSED; cross-model adversarial review, independent KDF vectors, privacy review, and human security sign-off are outstanding
depends-on: did:crdt Method Specification; PROTO-002 Selfsame Rendezvous Protocol v1; W3C VC Data Model 2.0; W3C VC JOSE/COSE; W3C DID Core 1.0; optional W3C Bitstring Status List 1.0 projection; RFC 7565; RFC 7033; RFC 3986; RFC 4648; RFC 5234; RFC 5869; RFC 7515; RFC 8032; RFC 8785
---

# SPEC-004 — Application- and Account-Scoped Identity

## Orientation

**Intent.** One Selfsame recovery secret SHALL work across unrelated developer
applications without making those applications share a public identity, a home
key, or an infrastructure operator. Each account within an application receives
a deterministic, unlinkable home DID below that application's private
hierarchy. That DID names the application account with an RFC 7565 `acct:` URI
and issues a W3C Verifiable Credential that grants a particular device narrowly
scoped access to that account in that application.

**User promise.** A person who uses Selfsame in application A and application B
SHALL scan, consent, and continue. They SHALL NOT select a rendezvous server,
copy endpoints, import a second recovery phrase, or edit a configuration file.
Application A and application B SHALL nevertheless see different home keys,
different DIDs, different account aliases, different grants, and independently
operated providers. If one application supports two signed-in accounts, its
ordinary account switcher SHALL select the corresponding Selfsame identity
without asking the person for a derivation index or Selfsame setting. The
person MAY separately opt into one public, human-readable username for an
account; it is never required to link, restore, or authorize a device.

**Infrastructure promise.** The Selfsame project defines protocols, ships
client libraries, supplies a reference server, and maintains conformance tests.
It does not become the mandatory rendezvous, account, state, or projection host.
Each adopting application chooses one or more operators in its embedded
application profile. Anuna MAY operate one such provider, but no conforming
production application may depend on an undeclared Anuna fallback.

**Metaphor.** *One key ring, a different front-door key for every building.*
Each flat within a building also has its own key. The key ring is recoverable
once. A landlord cannot use the key for one building to recognise the tenant at
another, one flat key does not open another flat, and the locksmith need not
own either building.

**Structure.**

```text
                         one private recovery secret
                                      |
                    application/account hierarchy (CON-202)
                         /                            \
            application A node                 application B node
              /             \                          |
       account A1 node  account A2 node          account B1 node
              |             |                          |
        A1 home DID     A2 home DID                B1 home DID
              |             |                          |
       acct:ss-…@A      acct:ss-…@A               acct:ss-…@B
              |             |                          |
       A1 device VC     A2 device VC               B1 device VC

  Application nodes and account-scope identifiers are private. No public
  identifier or provider selection crosses an application or account boundary.
  The recovery secret never leaves the user's devices.
```

**Decisions.**
[[SPEC-004-application-scoped-identity#ADR-201]] namespace the deterministic
hierarchy by immutable application ID ·
[[SPEC-004-application-scoped-identity#ADR-202]] make the
application-account home DID, not a global DID, the VC issuer ·
[[SPEC-004-application-scoped-identity#ADR-203]] use RFC 7565 `acct:` URIs in
`alsoKnownAs` ·
[[SPEC-004-application-scoped-identity#ADR-204]] secure the grant as
`application/vc+jwt` with EdDSA ·
[[SPEC-004-application-scoped-identity#ADR-205]] bind the device with `cnf` and
a fresh challenge ·
[[SPEC-004-application-scoped-identity#ADR-206]] let the application profile
select providers ·
[[SPEC-004-application-scoped-identity#ADR-207]] carry the initiator's provider
choice through the link ceremony ·
[[SPEC-004-application-scoped-identity#ADR-208]] make the signed, grow-only
`did:crdt` credential-revocation set authoritative and permit standards-facing
status projections ·
[[SPEC-004-application-scoped-identity#ADR-209]] pin the JSON-LD context and
forbid verification-time context fetching ·
[[SPEC-004-application-scoped-identity#ADR-210]] derive one home DID per
application account ·
[[SPEC-004-application-scoped-identity#ADR-211]] keep a user-chosen public
username separate from the stable opaque account alias ·
[[SPEC-004-application-scoped-identity#ADR-212]] make a versioned,
operator-neutral mailbox protocol the rendezvous compatibility boundary ·
[[SPEC-004-application-scoped-identity#ADR-213]] make same-device mobile
authorization reuse the existing ceremony, with OS handoff replacing only the
scan ·
[[SPEC-004-application-scoped-identity#ADR-214]] require layered application
authentication before the wallet uses an application-account branch.

**Load-bearing.**
[[SPEC-004-application-scoped-identity#REQ-201]] one secret produces a different
home key per application account ·
[[SPEC-004-application-scoped-identity#REQ-205]] the device grant is a
conforming W3C VC ·
[[SPEC-004-application-scoped-identity#REQ-207]] the VC is interpreted only
through the Selfsame authorization profile ·
[[SPEC-004-application-scoped-identity#REQ-209]] provider choice requires no
user configuration ·
[[SPEC-004-application-scoped-identity#REQ-216]] accounts in one application
remain independent ·
[[SPEC-004-application-scoped-identity#REQ-217]] account scope is stable,
opaque, and recoverable without user configuration ·
[[SPEC-004-application-scoped-identity#REQ-218]] a person may set a
human-readable account alias without changing identity or authorization ·
[[SPEC-004-application-scoped-identity#REQ-219]] protocol conformance, not
operator identity, determines rendezvous eligibility ·
[[SPEC-004-application-scoped-identity#REQ-220]] same-device mobile
authorization requires no self-scan or typed code ·
[[SPEC-004-application-scoped-identity#REQ-222]] no caller can use a public
profile alone to obtain an application-account grant ·
[[SPEC-004-application-scoped-identity#NFR-201]] application identities are
pairwise unlinkable from their public data ·
[[SPEC-004-application-scoped-identity#NFR-205]] all authorization checks fail
closed.

**Blocking before implementation.**
[[SPEC-004-application-scoped-identity#OQ-201]] authorization-state freshness ·
[[SPEC-004-application-scoped-identity#OQ-202]] durable vocabulary ownership ·
[[SPEC-004-application-scoped-identity#OQ-204]] application-ID migration ·
[[SPEC-004-application-scoped-identity#OQ-206]] legacy identity migration ·
[[SPEC-004-application-scoped-identity#OQ-207]] requesting-application
authentication ·
the Tier-1 gate in
[[SPEC-004-application-scoped-identity#Tier-1 Gate]].

**Controls digest.**

- Tier-1 status prohibits implementation and shipment until the gate closes.
- `applicationId` values are immutable; clients do not silently migrate them.
- Unknown authorization inputs fail closed and no undeclared provider fallback
  is permitted.
- A device key is never reused across either application or account scope.
- An `accountScopeId` is never PII, guessed, user-entered, or reassigned.
- A human-readable alias is public, optional, never a KDF or authorization
  input, and never silently reassigned.
- Credential revocation is an irreversible `did:crdt` operation; a status-list
  projection can aid generic VC consumers but never overrides CRDT state.
- Compact grants are at most 64 KiB and use only the EdDSA profile.
- Proof nonces are single-use and expire within 120 seconds.
- Rendezvous probes have a per-endpoint deadline of at most 1500 ms.
- Only providers passing
  [[PROTO-002-selfsame-rendezvous-v1#CON-301]] are eligible; all mailbox use
  then follows that protocol's bounded, blind, immutable contract.
- A same-device ceremony secret is delivered only to an installed,
  platform-verified Selfsame wallet target; no browser or unverified custom
  scheme receives it.
- Selfsame does not disclose branch existence, derive an existing branch, sign,
  publish, or write a grant until application enrollment evidence, the offer
  transcript, and available platform identity all agree.
- A mobile completion callback is advisory and contains no grant, DID, account
  scope, key, link code, provider secret, or verifier acceptance decision.
- Ambiguous or failed delivery of ceremony material permanently abandons that
  ceremony; retry starts with a fresh secret, offer, slots, and ciphertext.

---

## Conformance and status

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in BCP 14 (RFC 2119 and RFC 8174) when, and only when, they appear in
all capitals.

This is a **Tier-1 draft** because it defines authentication, authorization,
key derivation, identity correlation boundaries, and revocation. Every
`ADR-2##` is PROPOSED. This document is suitable for requirements review and
prototype planning only. It does not authorize implementation or shipment
until the gate in [[SPEC-004-application-scoped-identity#Tier-1 Gate]] closes.

This specification is the second-application trigger anticipated by
[[SPEC-001-device-key-provisioning]] ADR-011 and ADR-012. It proposes the
application-neutral profile that the earlier CBCL-specific design deferred.
It does **not** silently amend that document. In particular, the statement in
SPEC-001 ADR-001 that "`did:crdt` deltas are the credential" remains the legacy
CBCL profile until SPEC-001 is explicitly amended to carry the VC defined here.

Artefacts in this document use the `2##` number band so they cannot collide
with SPEC-002's `1##` band or the identifiers currently observed in SPEC-001.

## Context

Selfsame currently proves that a phone-held root authorized a device key. The
prototype is shaped around one consuming application and one compiled
rendezvous endpoint. That is sufficient for a vertical slice but creates five
problems as soon as a second developer adopts it or one application supports a
second signed-in account:

1. a single public home DID correlates a person across applications;
2. a single rendezvous host makes Anuna the default operator for every adopter;
3. a CBCL-shaped grant is not portable to non-CBCL applications; and
4. endpoint, application, or account-branch choices leak into Selfsame user
   configuration; and
5. a developer app and Selfsame wallet on one phone cannot safely ask the
   person to scan the same display, while an unauthenticated deep link lets a
   malicious local app claim another developer's public profile.

The new boundary is an **application profile**. It is developer-supplied,
embedded in every release of that application, and passed to the Selfsame SDK.
It fixes the application's immutable identifier, account authority, allowed
permissions, and eligible providers. The user's recovery secret is combined
with that identifier to derive a private application node. An opaque,
application-issued `accountScopeId` then selects a private child node and the
home key for exactly one signed-in account. Nothing in the derivation depends
on which rendezvous provider happens to be healthy today, and the person does
not manage either derivation input.

### Identity roles

The terms below are normative:

| Role | Identifier | Responsibility |
|---|---|---|
| Recovery principal | no public identifier | Holds the mnemonic-derived secret from which application nodes are derived. |
| Application | canonical HTTPS `applicationId` | Defines one developer and provider-policy boundary. |
| Account scope | private `accountScopeId` | Selects one stable account child below an application node; it is never a public identity. |
| Application-account home | account-specific `did:crdt` DID | Controls one account identity within one application, issues its grants, and authorizes permanent credential-revocation deltas. |
| Stable account alias | opaque RFC 7565 `acct:ss-…` URI | Mandatory provider-hosted authorization identifier that refers to the same subject as the application-account home DID. |
| Human-readable account alias | optional user-chosen RFC 7565 `acct:` URI | Public discovery name for the same home DID; mutable display metadata, never an authorization or derivation input. |
| Device | `did:key` plus the same Ed25519 public key in `cnf.jwk` | Subject and holder of one device grant. |
| Verifier | application backend or peer | Applies VC verification and the additional Selfsame authorization predicate. |
| Provider | profile-named operator | Supplies one or more rendezvous, state, account, or optional status-projection functions. |

The recovery principal is deliberately absent from every wire representation.
There is no global public "Selfsame user DID" in this profile.

## Scope

### In scope

- deterministic, domain-separated application and account nodes and home keys;
- an immutable application identifier and embedded application profile;
- an opaque, stable, application-issued account-scope lifecycle;
- one account-specific `did:crdt` home DID per application account;
- RFC 7565 `acct:` values in DID Core `alsoKnownAs`;
- an optional human-readable RFC 7565 account username;
- reciprocal `acct:` → DID binding using RFC 7033 WebFinger;
- W3C VC Data Model 2.0 device grants secured with W3C VC JOSE/COSE;
- device proof of possession and an explicit authorization predicate;
- `did:crdt` credential revocation, expiry, and fail-closed verification;
- optional W3C Bitstring Status List projection for generic VC consumers;
- automatic selection among application-approved rendezvous providers;
- origin-authenticated application enrollment evidence;
- MITM-resistant same-device mobile handoff without self-scanning;
- developer and provider conformance responsibilities;
- coexistence of unrelated Selfsame-enabled applications on one device; and
- coexistence and ordinary switching of multiple accounts in one application.

### Out of scope

- a universal human identifier shared between applications;
- a global username namespace or guaranteed availability of the same username
  at different account authorities;
- discovery of all applications used by a recovery principal;
- transfer of an identity between two different `applicationId` values;
- deriving an account branch from email, user name, display name, or a
  user-entered ordinal;
- anonymous credentials, selective disclosure, or zero-knowledge proofs;
- delegation from one device to another without the application-account home
  key;
- semantic interoperability of application-defined permissions;
- payment, commercial provider selection, or an Anuna-hosted public utility;
- changes to BIP-39 backup UX; and
- implementation work in any affected repository.

## Users and happy paths

### Existing user adds a second application

1. Application B supplies its embedded profile to the Selfsame SDK.
2. After authenticating the signed-in account, application B supplies that
   account's stable `accountScopeId` without user interaction.
3. Selfsame validates both inputs, derives B's application and account nodes,
   and constructs the account's home DID and opaque `acct:` localpart.
4. Application B provisions that `acct:` value at its declared account
   authority and publishes the reciprocal WebFinger binding.
5. Selfsame issues a B-scoped device grant to the device.
6. Application B verifies the VC, status, account binding, and device proof.

No identifier, key, account alias, endpoint choice, or grant from application A
is presented to application B.

### User switches between two accounts in one application

1. The person uses the application's existing account switcher to select A2.
2. The authenticated A2 account record supplies its stable `accountScopeId` to
   the Selfsame SDK; the person enters no Selfsame identifier or setting.
3. Selfsame derives the A2 node and selects A2's home DID, alias, device key,
   grant, CRDT state, and optional projection records.
4. The application and verifier reject any A1 grant or proof presented while
   the authenticated context expects A2.

Switching back supplies A1's scope and deterministically selects A1. Neither
account learns the other's scope, key, DID, alias, grant, or provider state.

### User sets a human-readable username

1. While signed into A1, the person opens the application's Selfsame identity
   settings and requests the lower-case handle `alice`.
2. The UI previews the public URI
   `acct:alice@accounts.photos.example` and warns that it is publicly
   discoverable and may correlate the person if reused elsewhere.
3. The account authority validates and reserves the handle for A1's home DID,
   publishes its reciprocal WebFinger binding, and returns confirmation.
4. A1's home key signs a DID document-data update whose `alsoKnownAs` contains
   the mandatory opaque alias and the optional username alias.
5. The person's DID, home key, account scope, opaque authorization alias,
   existing grants, revocation state, and projection allocations do not change.

Renaming or removing the username follows CON-212. The application may ask for
a different available handle after `UsernameUnavailable`; it never asks the
person to edit a URI, domain, DID document, or provider configuration.

### User links another device

1. The initiating application supplies the active authenticated account scope,
   creates the target device key and offer, then filters and probes the
   providers in its embedded profile.
2. It selects a healthy rendezvous endpoint, obtains CON-214 enrollment
   evidence bound to the exact account, key, permission, provider, and offer,
   and places that choice in the authenticated link-ceremony provider hint.
3. The joining device scans the link code and follows the selected provider; it
   does not run its own independent election.
4. The phone verifies the application enrollment evidence and offer, shows
   authenticated-origin consent, creates a random grant ID, and issues the
   device grant.
5. The existing encrypted ceremony carries the VC as opaque
   `application/vc+jwt` bytes.
6. The joining device proves possession of the `cnf` private key to the
   application verifier.

### User authorizes an application on the same phone

This is the path where the developer application receiving the grant and the
Selfsame wallet holding the home controller are separate apps on one mobile
device. It is not selected merely because Selfsame is installed: authorizing a
laptop or other remote target continues to use the cross-device path above.

1. The developer application authenticates its active account, creates a fresh
   application-account-scoped device key, selects a conforming rendezvous,
   constructs the ordinary offer, obtains the application enrollment evidence
   in CON-214 bound to that provider and offer, writes the encrypted offer, and
   begins polling the ordinary bundle slot.
2. Instead of displaying that offer as a QR code, its Selfsame SDK passes the
   existing one-time link code to the installed Selfsame wallet through the
   platform adapter in CON-215. The adapter either reaches the verified wallet
   app or returns `WalletUnavailable`; it never sends ceremony material to a
   browser, clipboard, generic intent, unverified URL-scheme handler, install
   page, analytics event, or notification.
3. Selfsame reads and authenticates the same encrypted offer used by the
   cross-device flow. Before showing consent, it verifies the application
   origin and enrollment evidence, the active application/account/device/offer
   bindings, expiry and one-time nonce, and every platform identity signal the
   adapter can securely provide.
4. The consent screen names the authenticated application origin and account
   operation, the target device, and the exact requested permissions. A label
   supplied only by the calling app is never presented as verified identity.
5. On approval, Selfsame derives or selects the application-account home,
   issues the device VC, publishes signed `did:crdt` state through the
   separately selected state service, and writes the encrypted grant to the
   existing rendezvous bundle slot. No DID delta is written to a rendezvous
   mailbox slot.
6. The developer application receives and verifies the bundle through its
   already-running mailbox poll and then proves possession of the device key.
   An optional OS callback merely foregrounds that pending application
   session; it carries no credential or authority and cannot make a failed
   bundle pass.
7. If secure wallet invocation is unavailable, ambiguous, intercepted, or
   falls back toward the web, both apps abandon the ceremony. An install/help
   action contains no ceremony material, and a later retry creates a fresh
   secret, offer, slots, ciphertext, enrollment nonce, and evidence.

The person taps **Continue in Selfsame**, reviews consent, and returns. They do
not scan their own screen, type a code, choose a server, or grant a mobile link
handler authority over the resulting credential.

### User revokes a device from one account

Suppose the person is signed into Photos account A1 and selects **Remove
laptop**:

1. The authenticated A1 context supplies its private `accountScopeId`;
   Selfsame selects A1's home key, stable opaque `acct:` URI, and the laptop's
   exact grant ID. A human-readable alias, if present, is display metadata and
   is not used for authorization.
2. The UI identifies the application account and laptop and obtains explicit
   confirmation. It does not expose or ask for the account scope, DID frontier,
   state-resolver URL, or provider endpoint.
3. Selfsame constructs the method-defined
   `RevokeCredential { credential_id: "<exact VC id>" }` operation with the
   current A1 frontier as its parents and signs the resulting `did:crdt` delta
   with a currently authorized A1 controller key.
4. The SDK submits the delta to the application-profile state resolvers and
   any directly connected peers. Valid concurrent deltas merge by set union;
   the credential ID can never be removed from the revocation G-Set.
5. The application marks the operation **pending** until it resolves and
   verifies a signed closure containing the exact credential ID. Submission
   alone is not success, and an undeclared fallback is forbidden.
6. A Selfsame verifier resolving a sufficiently fresh closure calls
   `is_revoked(grant.id)` or performs the equivalent method check and rejects
   the laptop even if it retains both its validly signed VC and device private
   key. The application SHOULD terminate any locally controlled active session
   for that grant immediately.
7. An operator MAY project the verified CRDT revocation set into a W3C
   Bitstring Status List Credential for generic VC software. The projection is
   a cache: it cannot un-revoke a grant, authorize a device, or supersede a
   newer verified CRDT closure.

Every A2 grant, key, revocation set, and session remains unchanged. The outer
availability bound is CRDT-delta propagation plus the verifier's closure
freshness policy; OQ-201 must fix those bounds before production.

### User restores

Given the same recovery words, the same BIP-39 passphrase policy, and the same
canonical `applicationId`, a restored Selfsame installation first derives the
same private application node. To recover a particular account home, it also
requires that account's exact `accountScopeId`, restored automatically from the
authenticated application account record or protected Selfsame backup as
specified by [[SPEC-004-application-scoped-identity#REQ-217]]. Those inputs
reproduce the same account node, home seed, DID, and `acct:` URI. Provider
endpoint changes do not change identity.

## Requirements

### REQ-201: One secret, a different home key per application account

The system SHALL derive an independent private application node FOR each
canonical `applicationId`, then an independent account node and home signing
key FOR each `(applicationId, accountScopeId)` pair, using
[[SPEC-004-application-scoped-identity#CON-202]].

Two different canonical application IDs SHALL yield different home signing
seeds, public keys, and DIDs, even if their account-scope byte strings happen to
match. Two distinct scopes below one application SHALL also yield different
account nodes, home signing seeds, public keys, and DIDs. The same canonical
application ID, account scope, and recovery secret SHALL reproduce
byte-identical results on every conforming platform.

No application SHALL receive the recovery secret, another application's node,
another account's node or home seed, or a derivation path that permits
computing any sibling.

Trace: [[SPEC-004-application-scoped-identity#TEST-201]],
[[SPEC-004-application-scoped-identity#TEST-202]]

### REQ-202: The application ID is immutable and canonical

Every adopting application SHALL declare exactly one canonical
`applicationId` conforming to [[SPEC-004-application-scoped-identity#CON-201]].
The ID SHALL identify the authorization and correlation boundary, not a
particular build, endpoint, deployment region, or provider.

The application SHALL embed the exact canonical string in each client that is
intended to share the same Selfsame identity. A verifier SHALL compare it as
exact ASCII after validating canonical form. It SHALL NOT repair, redirect, or
guess a different identifier.

Changing `applicationId` creates a new application identity. Silent migration
is prohibited.

Trace: [[SPEC-004-application-scoped-identity#TEST-203]]

### REQ-203: The home DID uses RFC 7565 `acct:` in `alsoKnownAs`

The resolved application-account home DID Document SHALL contain exactly one
stable Selfsame authorization alias in `alsoKnownAs`, constructed by
[[SPEC-004-application-scoped-identity#CON-203]]. It MAY additionally contain
exactly one human-readable alias governed by
[[SPEC-004-application-scoped-identity#REQ-218]]:

```json
{
  "id": "did:crdt:<application-account-home>",
  "alsoKnownAs": [
    "acct:ss-<base32-sha256-of-home-did>@accounts.example",
    "acct:alice@accounts.example"
  ]
}
```

Each alias SHALL conform to RFC 7565 and refer to the same account and home DID
at the named service provider. Neither is an email address or transport
endpoint. The stable alias is not a global Selfsame handle; the optional alias
is a public username only within its named account authority.

The SDK SHALL compute the complete stable alias from the derived home DID and
the profile's `accountAuthority`. The person SHALL NOT choose, type, copy, or
edit that localpart, authority, or URI. The person MAY choose only the optional
username localpart through the application workflow in REQ-218; the SDK and
authority construct and publish the complete URI.

Trace: [[SPEC-004-application-scoped-identity#TEST-204]],
[[SPEC-004-application-scoped-identity#TEST-205]]

### REQ-204: Every `acct:` alias names a real, reciprocally bound account

An application SHALL provision each exact `acct:` account at its declared
account authority before the DID publishes that alias. It SHALL NOT fabricate
an `acct:` URI merely by combining a user name or public key with a developer
domain.

The account authority SHALL answer the RFC 7033 WebFinger query for that
`acct:` URI over HTTPS. The JRD `subject` SHALL equal the normalized account
URI and its `aliases` set SHALL contain the exact application-account home DID.

The mandatory authorization account record SHALL use an opaque Selfsame
localpart and SHALL NOT reveal an email address, display name, phone number, or
cross-application account ID. The optional public username record is the sole
exception and remains subject to REQ-218 and CON-212.

Trace: [[SPEC-004-application-scoped-identity#TEST-205]],
[[SPEC-004-application-scoped-identity#TEST-206]]

### REQ-205: A device grant is a conforming W3C Verifiable Credential

Every portable Selfsame device grant SHALL be a credential conforming to the
W3C Verifiable Credentials Data Model 2.0 and SHALL use the
`SelfsameDeviceGrantCredential` profile in
[[SPEC-004-application-scoped-identity#CON-205]].

The mandatory secured representation SHALL be a compact JWS with media type
`application/vc+jwt`, produced and verified according to the W3C
"Securing Verifiable Credentials using JOSE and COSE" Recommendation.

The grant SHALL NOT be wrapped in a legacy JWT `vc` claim. The unsecured VC
document itself SHALL be the JWS payload.

Trace: [[SPEC-004-application-scoped-identity#TEST-207]],
[[SPEC-004-application-scoped-identity#TEST-208]]

### REQ-206: The grant is cryptographically bound to one device

The credential subject SHALL be the device DID. The JWS payload SHALL contain
a `cnf.jwk` Ed25519 public key whose public bytes equal the key identified by
the device DID.

Before accepting the grant for an authenticated session, the verifier SHALL
require the device to sign a fresh, application-and-account-bound challenge
according to
[[SPEC-004-application-scoped-identity#CON-207]]. Possession of the VC without
the corresponding device private key SHALL confer no access.

Trace: [[SPEC-004-application-scoped-identity#TEST-209]],
[[SPEC-004-application-scoped-identity#TEST-210]]

### REQ-207: VC verification is necessary but not sufficient

A verifier SHALL apply the complete acceptance predicate in
[[SPEC-004-application-scoped-identity#CON-206]]. A valid JWS and a conforming
VC alone SHALL NOT authorize the device.

The authorization decision SHALL additionally bind:

- the expected `applicationId`;
- the expected RFC 7565 application account;
- an explicitly recognized permission set;
- current grant validity and status;
- a verified, sufficiently fresh issuer closure whose revocation G-Set does not
  contain the grant ID; and
- fresh proof of possession by the device.

Unknown permissions, contexts, algorithms, issuers, status mechanisms, or
application identifiers SHALL be rejected, not ignored.

Rationale: VC Data Model 2.0 explicitly does not define a complete RBAC or ABAC
authorization system. This contract is the accompanying Selfsame authorization
framework.

Trace: [[SPEC-004-application-scoped-identity#TEST-211]]

### REQ-208: Every grant is bounded and revocable

Every grant SHALL contain a globally unique `id`, `validFrom`, `validUntil`,
and one `SelfsameDidCrdtStatusEntry` whose `statusPurpose` is `revocation` and
whose `credentialId` exactly equals the grant `id`.

Unlinking a device SHALL create a signed `did:crdt`
`RevokeCredential { credential_id }` delta, where `credential_id` is the exact
grant `id`. The revocation G-Set in the verified issuer state is the normative
source of truth. Because it is grow-only, no operation, provider response,
projection, key rotation, or concurrent merge may make a revoked grant valid
again.

The application SHALL define maximum acceptable issuer-closure age and
revocation propagation bounds. A Selfsame verifier SHALL fail closed when it
cannot obtain sufficiently fresh, causally valid issuer state. It SHALL reject
the grant when `Document::is_revoked(grant.id)` or the method-equivalent check
returns true.

A profile MAY enable an additional W3C Bitstring Status List projection for
generic VC consumers. Such a projection SHALL be derived from verified
`did:crdt` state and signed by the application-account home DID or a currently
authorized key of that DID; the projection host is not a trust anchor. A
Selfsame verifier MAY use a set bit for early rejection, but an unset,
unavailable, or stale projection SHALL never override the CRDT revocation set
or replace the mandatory CRDT-state check.

Trace: [[SPEC-004-application-scoped-identity#TEST-212]],
[[SPEC-004-application-scoped-identity#TEST-213]]

### REQ-209: Provider selection requires no user configuration

Every production application SHALL embed an application profile with at least
two eligible rendezvous descriptors unless it documents a single-provider
availability exception.

The initiating client SHALL select a provider using
[[SPEC-004-application-scoped-identity#CON-208]]. A descriptor becomes eligible
only by passing the capability contract in
[[PROTO-002-selfsame-rendezvous-v1#CON-301]]. The person SHALL NOT be asked to
type, paste, scan, or choose an endpoint during the normal path.

The UI MAY show the selected operator and privacy policy and MAY expose an
advanced administrator policy. Such visibility SHALL NOT turn an
application-supplied interoperability value into a required user setting.

Trace: [[SPEC-004-application-scoped-identity#TEST-214]],
[[SPEC-004-application-scoped-identity#TEST-215]],
[[SPEC-004-application-scoped-identity#TEST-226]]

### REQ-210: There is no undeclared global fallback

The SDK SHALL NOT contain a production Anuna rendezvous, account, state, or
status-projection endpoint that is consulted when the application profile is
missing or unhealthy.

When no declared provider is usable, the operation SHALL stop with an
actionable application error. It SHALL NOT silently route through infrastructure
operated by Selfsame, Anuna, or a prior application.

A loopback development profile MAY be supplied by developer tooling, but it
MUST be rejected by release builds.

Trace: [[SPEC-004-application-scoped-identity#TEST-216]],
[[SPEC-004-application-scoped-identity#TEST-226]]

### REQ-211: The VC remains opaque inside the link transport

The link ceremony SHALL carry the compact JWS bytes together with the exact
media type `application/vc+jwt` inside its existing transcript-bound encrypted
bundle.

The outer CBCL or other application transport SHALL NOT translate the VC
properties, reserialize its JWS components, replace its signature, or call an
outer signature "VC conformance." The same bytes SHALL be independently
verifiable after extraction by a non-CBCL application.

Trace: [[SPEC-004-application-scoped-identity#TEST-217]]

### REQ-212: The provider choice follows the ceremony

The initiating client SHALL place the selected provider ID and descriptor
digest in the authenticated provider hint defined by
[[SPEC-004-application-scoped-identity#CON-209]].

The joining client SHALL follow that choice for the in-progress ceremony. It
SHALL NOT independently select a different rendezvous. If the selected
provider becomes unavailable, the initiator SHALL abandon that ceremony and
create a fresh secret, slots, offer, ciphertext, and authenticated hint before
either party moves, as required by
[[PROTO-002-selfsame-rendezvous-v1#REQ-307]].

Trace: [[SPEC-004-application-scoped-identity#TEST-218]],
[[SPEC-004-application-scoped-identity#TEST-226]]

### REQ-213: Derivation does not depend on an infrastructure provider

Application-account home key derivation SHALL depend only on recovery input,
the KDF version, canonical `applicationId`, and canonical `accountScopeId`. It
SHALL NOT depend on account authority, rendezvous, state, or status-projection
provider ID, endpoint URL, region, projection index, device key, or a provider
health response.

Changing providers therefore SHALL NOT rotate the home DID or `acct:`
localpart. The application is responsible for preserving or republishing the
account and state records when it changes operators. Restoring the account
scope itself follows [[SPEC-004-application-scoped-identity#REQ-217]].

Trace: [[SPEC-004-application-scoped-identity#TEST-219]]

### REQ-214: Any developer can adopt the profile

A conforming integration SHALL require no registration with Anuna. A developer
needs only:

1. one immutable application ID and embedded profile;
2. an account-record integration implementing the scope lifecycle in REQ-217;
3. an RFC 7565 account authority with the WebFinger binding in CON-204;
4. for a production wallet-exposed integration, origin-authenticated profile
   publication and a backend enrollment-signing key conforming to CON-214;
5. for same-device mobile, the Android and/or Apple application bindings in
   CON-201 and CON-215;
6. one or more providers conforming to
   [[PROTO-002-selfsame-rendezvous-v1]];
7. one or more state resolvers or peer paths that exchange complete,
   causally valid `did:crdt` signed closures and revocation deltas;
8. application permission URIs and verifier policy; and
9. the Selfsame issuer/holder SDK or an independent conforming implementation.

A developer MAY additionally deploy a W3C Bitstring Status List projection
host. That optional service does not participate in core issuance, linking,
revocation authority, or Selfsame authorization.

The reference implementation SHALL expose the black-box PROTO-002 conformance
suite and the end-to-end profile suite so either can run without contacting
Anuna infrastructure.

Trace: [[SPEC-004-application-scoped-identity#TEST-220]],
[[SPEC-004-application-scoped-identity#TEST-226]],
[[SPEC-004-application-scoped-identity#TEST-227]],
[[SPEC-004-application-scoped-identity#TEST-228]]

### REQ-215: Device keys are application-account-scoped

A device SHALL generate or provision a distinct Ed25519 key FOR each
`(applicationId, accountScopeId, device installation)` tuple. It SHALL NOT
reuse a device key, device DID, `cnf.jwk`, or proof nonce namespace between
applications or between accounts in one application.

Device keys SHOULD be generated by the device CSPRNG and remain local to that
installation. They SHALL NOT be derived from the recovery secret or application
home signing seed.

Rationale: pairwise home DIDs do not provide pairwise privacy if two
credentials expose the same device DID.

Trace: [[SPEC-004-application-scoped-identity#TEST-221]]

### REQ-216: Multiple accounts in one application remain independent

An application MAY bind any number of authenticated application accounts to
one `applicationId`. It SHALL assign each account a distinct scope and index
all Selfsame home keys, DIDs, aliases, device keys, grants, state, revocation
entries, and projections by the complete `(applicationId, accountScopeId)`
tuple.

The application's ordinary authenticated-account context SHALL supply the
active scope automatically. The person SHALL NOT type, copy, scan, remember,
or choose an account scope or derivation index. Account switching SHALL select
the matching Selfsame branch without changing the application profile.

A verifier handling account A2 SHALL expect A2's `acct:` alias and issuer
closure. A grant, proof, device key, revocation entry, status projection, or
home signature belonging to A1 SHALL confer no authority in A2, even though
both accounts share an `applicationId`.

Trace: [[SPEC-004-application-scoped-identity#TEST-222]]

### REQ-217: Account scope is opaque, stable, and recoverable

When Selfsame is first enabled for an authenticated application account, the
application SHALL allocate 32 bytes from a CSPRNG, encode them as the canonical
`accountScopeId` in
[[SPEC-004-application-scoped-identity#CON-211]], and bind that value
immutably to the account record. It SHALL return the same value after normal
authentication and account recovery. A deleted-and-recreated account SHALL
receive a new value; a value SHALL never be reassigned to another account.

The application SHALL supply the scope to the SDK from authenticated account
state without displaying it as a user setting. The SDK SHALL store it in
platform-protected local storage and include it in any encrypted Selfsame
recovery backup that supports application metadata. The scope is sensitive
correlation metadata but is not a password or source of cryptographic entropy.
It SHALL NOT be derived from or replaced by email, user name, display name,
phone number, a sequential database identifier, or other PII.

The mnemonic and `applicationId` alone cannot identify one of several account
children. If neither the authenticated account record nor a protected backup
can restore the exact scope, the SDK SHALL fail with
`AccountScopeUnavailable`. It SHALL NOT guess a scope, ask the person to enter
one, or silently create a replacement identity.

The raw or encoded scope SHALL NOT appear in a DID, DID Document, `acct:` URI,
VC, JWS header, WebFinger response, provider hint, status entry, log, analytics
event, or other public protocol artifact.

Trace: [[SPEC-004-application-scoped-identity#TEST-223]]

### REQ-218: A person may choose one human-readable account alias

After the mandatory opaque alias is provisioned, an authenticated application
account MAY request one available human-readable localpart at the same
`accountAuthority`. The person chooses only the localpart; the application
constructs and previews the complete RFC 7565 URI. The authority and home DID
SHALL complete the authenticated, reciprocal lifecycle in
[[SPEC-004-application-scoped-identity#CON-212]] before the alias is shown as
active.

The human-readable alias is public discovery and display metadata. It SHALL
NOT replace the stable opaque alias in a VC `account` claim, KDF input,
`accountScopeId`, authorization predicate, proof input, grant ID, revocation
operation, state namespace, or provider-selection input. Setting, renaming, or
removing it SHALL NOT rotate the home DID, keys, grants, or revocation state.

The UI SHALL warn before publication that a reused username can correlate the
person across services. A person who declines or cannot obtain a username
retains the complete linking, authorization, revocation, and recovery
functionality of Selfsame.

Trace: [[SPEC-004-application-scoped-identity#TEST-225]]

### REQ-219: Protocol conformance determines rendezvous eligibility

A rendezvous descriptor naming `selfsame-rendezvous-v1` SHALL be eligible only
when its URL is canonical and its bounded capability probe passes
[[PROTO-002-selfsame-rendezvous-v1#CON-301]]. After selection, both clients and
the operator SHALL use
[[PROTO-002-selfsame-rendezvous-v1#CON-302]] through
[[PROTO-002-selfsame-rendezvous-v1#CON-308]] for every mailbox operation.
Operator identity, commercial relationship, co-location with a state resolver,
or an Anuna allowlist SHALL NOT substitute for protocol conformance.

Changing providers after any slot request has been sent or a hint has been
published SHALL abandon the prior ceremony and create a fresh secret, slots,
offer, ciphertext, and authenticated hint as required by
[[PROTO-002-selfsame-rendezvous-v1#REQ-307]]. It SHALL NOT rotate or alter the
application-account identity.

Trace: [[SPEC-004-application-scoped-identity#TEST-214]],
[[SPEC-004-application-scoped-identity#TEST-226]]

### REQ-220: Same-device mobile initiation requires no self-scan

When the target developer application and a verified Selfsame wallet are
installed on the same mobile device, the SDK SHALL initiate the same-device
path in [[SPEC-004-application-scoped-identity#CON-215]] without requiring the
person to scan their own display or copy, type, or paste ceremony material.

This path is selected for the target app instance, not merely because a wallet
is installed. A person authorizing a different device continues to receive the
cross-device QR and typed-code paths.

Trace: [[SPEC-004-application-scoped-identity#TEST-227]]

### REQ-221: Same-device handoff reuses one authorization ceremony

The same-device path SHALL use the same fresh offer, application evidence,
provider selection, rendezvous slots, encrypted grant bundle, acceptance
predicate, device proof, and state-publication path as the cross-device
ceremony; only delivery of the existing one-time link code to Selfsame and an
optional non-authoritative UI return differ.

This prevents a platform adapter from becoming a second grant protocol with a
different security state machine.

Trace: [[SPEC-004-application-scoped-identity#TEST-227]],
[[SPEC-004-application-scoped-identity#TEST-231]]

### REQ-222: The wallet authenticates the requesting application

Selfsame SHALL NOT disclose whether an application branch exists, derive or
select an existing application-account home, sign or publish an authorization
delta, issue a device grant, or write a grant bundle unless the enrollment
evidence in [[SPEC-004-application-scoped-identity#CON-214]] authenticates the
application origin and binds the exact profile, account scope, device key,
requested permissions, offer digest, time window, and one-time request ID
observed in the current ceremony.

A public application profile, display name, icon, bundle/package name, deep
link, callback URI, or TLS connection is insufficient by itself.

Trace: [[SPEC-004-application-scoped-identity#TEST-228]],
[[SPEC-004-application-scoped-identity#TEST-229]]

### REQ-223: Ceremony secrets do not cross an unverified mobile channel

The invoking SDK SHALL NOT deliver a link code, ceremony secret, offer
plaintext, account scope, device private key, grant, or decryption key through
a generic/implicit intent, unverified custom URL scheme, browser or install-page
fallback, clipboard, pasteboard, notification payload, analytics event, crash
report, or application log.

The platform adapter may carry the link code only after it has constrained
delivery to the installed wallet target as defined by
[[SPEC-004-application-scoped-identity#CON-215]].

Trace: [[SPEC-004-application-scoped-identity#TEST-229]],
[[SPEC-004-application-scoped-identity#TEST-230]]

### REQ-224: The completion callback carries no authorization

The target application SHALL determine authorization success only from the
ordinary, transcript-authenticated grant bundle and
[[SPEC-004-application-scoped-identity#CON-206]] acceptance predicate, never
from an OS callback, foreground event, URL parameter, success screen, or wallet
process exit.

The optional callback is a usability hint with the closed field set in
[[SPEC-004-application-scoped-identity#CON-215]]. Interception, replay,
mutation, or loss of that hint cannot disclose a credential or turn rejection
into acceptance.

Trace: [[SPEC-004-application-scoped-identity#TEST-231]]

### REQ-225: Ambiguous mobile dispatch burns the ceremony

When the platform cannot prove delivery to the intended installed wallet, a
browser or alternate handler is offered, the wallet reports a caller-binding
mismatch, or the dispatch result is ambiguous, the SDK SHALL permanently
abandon that ceremony and retry only with a fresh secret, offer, slots,
ciphertext, request ID, enrollment evidence, and provider hint.

An install or help link is a separate action containing no ceremony data.

Trace: [[SPEC-004-application-scoped-identity#TEST-230]]

## Non-functional requirements

### NFR-201: Pairwise application-account unlinkability

Given public artifacts from two application accounts—whether in different
applications or the same application—an observer without the recovery secret
and private account scopes SHALL gain no cryptographic equality test showing
that the two home DIDs share a recovery principal.

The two profiles SHALL share no derived public key, DID, `acct:` URI,
credential ID, revocation entry, projection index, rendezvous route key, or
device key by default.

Choosing the same human-readable localpart at multiple authorities is an
explicit privacy exception. The UI warning in REQ-218 is mandatory because the
protocol cannot make a voluntarily reused public name unlinkable.

An application may still correlate a person through non-Selfsame data such as
email, payment, IP address, or browser fingerprinting. This requirement makes
no claim about those channels.

### NFR-202: Deterministic portability

At least two independent implementations SHALL reproduce every normative KDF,
application ID, account-scope validation, opaque alias, username grammar,
grant-ID, JWK, JWS, revocation-delta, challenge, and provider-selection test
vector, plus every application-enrollment and mobile-handoff vector,
byte-for-byte before the Tier-1 gate closes. PROTO-002's capability, slot,
HTTP, expiry, and retry vectors are part of this portability gate.

### NFR-203: Data minimization

The VC SHALL contain only its random ID, the application ID, opaque account
URI, device identifier and public key, permission URIs, validity, and status
reference required by this profile. It SHALL NOT contain recovery metadata,
the optional human-readable alias, another application's identifier, a display
name, email address, mnemonic fingerprint, `accountScopeId`, or
provider-selection history.

### NFR-204: No verification-time code or context loading

VC verification SHALL perform no arbitrary remote JSON-LD context fetch, schema
code execution, dynamic algorithm loading, or plugin discovery.

The exact base and Selfsame contexts SHALL be pinned by digest in the SDK.
Unknown context entries SHALL be rejected before signature-dependent
authorization decisions are made.

### NFR-205: Fail closed

Malformed profiles, aliases, DID closures, revocation state, JWKs, VCs, JWS
headers, enrollment statements, platform bindings, mobile handoffs, callbacks,
status projections, permission sets, challenges, provider hints, rendezvous
capabilities, or mailbox responses SHALL produce a typed failure and no
authenticated session.

There SHALL be no TOFU path for issuer keys, projection issuers, account
authorities, or provider descriptors.

### NFR-206: Provider diversity

The protocol SHALL permit the account, rendezvous, state, and optional
status-projection roles to be operated by different organizations. No wire
identifier SHALL assume they share a DNS origin or deployment stack.

### NFR-207: Selection latency

With at least one healthy declared provider, provider selection SHOULD complete
within 2 seconds at the 95th percentile on an ordinary residential connection,
excluding captive portals and complete network loss.

Health probes SHALL be bounded and parallel. A slow high-priority provider
SHALL NOT serially block all fallbacks.

### NFR-208: Algorithm confinement

Version 1 SHALL use Ed25519/EdDSA only for the application-account home JWS,
developer enrollment JWS, and device proof. Algorithm agility SHALL occur by a
new profile version and explicit migration, never by accepting an algorithm
named by untrusted input.

## Architecture decisions

### ADR-201: Namespace the hierarchy by immutable application ID

**Status:** PROPOSED.

The recovery secret feeds a private application node, that node feeds one
private child per account scope, and each account node feeds its home signing
seed. The application ID and account scope are length-prefixed and placed in
separate HKDF invocations, not reduced to the current one-byte application code
or a 32-bit persona index.

Reasons:

- a collision-resistant identifier is required before unrelated developers can
  safely share one hierarchy;
- provider and endpoint changes must not rotate identity;
- a child application or account key must not expose or enable sibling
  derivation; and
- the same hierarchy can later add application-local encryption and recovery
  children without reusing signing material.

Rejected:

- one global home DID — correlates applications;
- sequential application indices chosen by the person — require configuration
  and do not reproduce independently on restore;
- account email, user name, database sequence, or person-chosen account index —
  creates correlation, reassignment, enumeration, or restore ambiguity;
- DNS host alone — fails when one developer hosts multiple security
  boundaries; and
- the existing one-byte `Application` code — closed, centrally allocated, and
  collision-prone at ecosystem scale.

### ADR-202: The application-account home DID is the VC issuer

**Status:** PROPOSED.

The per-application-account home DID is both the controller of that account's
application identity and the issuer of its device grants. The recovery
principal and private application node have no public DID.

This keeps the authorization root pairwise across both applications and
accounts in one application. It also lets a verifier validate a
self-certifying signed closure without trusting Anuna, while allowing the
application to choose where that closure is transported and cached.

### ADR-203: Use RFC 7565 `acct:` URIs in DID `alsoKnownAs`

**Status:** PROPOSED.

The DID Document always uses one stable opaque alias and may use one public
human-readable alias:

```json
"alsoKnownAs": [
  "acct:ss-…@account-authority.example",
  "acct:alice@account-authority.example"
]
```

RFC 7565 exists specifically to identify an account at a service provider
without choosing an interaction protocol. DID Core permits any RFC 3986 URI in
`alsoKnownAs`, so the two specifications compose directly.

The assertion is not proof of equivalence. DID Core recommends reciprocal or
independent verification. This profile therefore requires a WebFinger JRD whose
`subject` is the account URI and whose `aliases` contains the DID.

The stable localpart is derived from the application-account home DID and then
actually provisioned. It is not the user's existing email or display handle.
This avoids creating a default cross-application correlator and satisfies RFC
7565's requirement that the URI identify an account at the named provider.
The optional human-readable alias is an explicit public discovery choice
governed by ADR-211 and never carries authorization.

### ADR-204: Secure the VC as `application/vc+jwt` with EdDSA

**Status:** PROPOSED.

Version 1 adopts the W3C VC JOSE/COSE JWS envelope:

- compact JWS;
- `typ: "vc+jwt"`;
- `cty: "vc"`;
- `alg: "EdDSA"`;
- an absolute DID URL in `kid`; and
- the VC Data Model document as the direct payload.

This choice avoids RDF canonicalization, uses the project's existing Ed25519
key material, has a registered VC media type, and provides the registered
`cnf` holder-binding mechanism.

Data Integrity `eddsa-jcs-2022` remains a possible future secured
representation. It is not accepted in version 1 because accepting two proof
systems doubles the verification surface before interoperability is proven.

### ADR-205: The device is subject and holder; `cnf` plus challenge proves it

**Status:** PROPOSED.

The home DID issues a claim about one device DID. The same Ed25519 public key is
present as `cnf.jwk`. The application then challenges that key before creating
an authenticated session.

A bearer VC is insufficient for device authorization. Conversely, a challenge
signature without the VC proves possession of a key but not authorization by
the application-account home.

### ADR-206: The application profile, not a global registry, names providers

**Status:** PROPOSED.

The developer embeds the profile and therefore supplies the trust anchor and
eligible provider set. The SDK performs compatibility, policy, health,
priority, and weight selection within that set.

This avoids a globally writable endpoint directory and avoids turning Anuna
into the mandatory operator. Provider marketplaces and enterprise policy can
produce profiles, but they are upstream of this trust boundary.

### ADR-207: The initiator's provider choice follows the ceremony

**Status:** PROPOSED.

Only the initiator elects a rendezvous. Its authenticated provider hint is
bound to the offer transcript. The joining client follows that hint.

Independent election is rejected because health, region, profile revision, and
timing can differ between devices, causing a correct pair to wait at different
servers.

### ADR-208: Make `did:crdt` revocation authoritative

**Status:** PROPOSED.

Every device-grant ID is revocable by the existing signed
`RevokeCredential` operation in the issuer's `did:crdt` state. Its G-Set merge
is union, so revocation is permanent, idempotent, and convergent under
concurrent updates. The controller's signed state—not a provider database—is
the authorization source of truth.

The VC carries a Selfsame status entry so a verifier knows to query that state.
An optional Bitstring Status List Credential may project the same state for
generic VC consumers, but it is home-authorized and cannot supersede CRDT
state. This preserves standards-facing interoperability without making the
projection operator a trust anchor.

Rejected:

- provider-operated status as the normative state — adds a mutable third-party
  authorization root and can diverge from controller state;
- key rotation as implicit grant revocation — would revoke unrelated grants
  and makes historical signature validity ambiguous; and
- deletion from a revocation set — breaks convergence and permits accidental
  or malicious resurrection.

Neither mechanism solves distribution freshness. OQ-201 remains blocking.

### ADR-209: Pin contexts; do not dereference them while verifying

**Status:** PROPOSED.

The credential includes the W3C v2 context and the versioned Selfsame context.
The SDK ships exact, digest-pinned copies. A verifier recognizes those
identifiers but does not fetch executable interpretation from the network.

This preserves VC semantics without allowing a compromised context host to
change an authorization decision.

### ADR-210: Derive one home DID per application account

**Status:** PROPOSED.

One `applicationId` may contain multiple private account children. Every child
has a distinct home DID, RFC 7565 alias, issuer closure, device key, VC grant,
state namespace, revocation set, and optional projection allocation. The
application allocates an opaque
random scope once and retrieves it from its authenticated account record; its
ordinary account switcher thereby selects the branch without new Selfsame UX.

Putting several accounts beneath one public home DID is rejected because a
shared issuer would correlate the accounts and make authorization, revocation,
and recovery boundaries ambiguous. Deriving from a visible user identifier is
rejected because it leaks PII and permits offline guessing. A user-selected
index is rejected because it requires configuration and is not reliably
recoverable. Two application IDs for one application are rejected because they
split provider policy and misuse the developer boundary to represent account
state.

The random scope is not intended to strengthen the recovery secret. Its
purpose is stable, opaque child selection. Because multiple children cannot be
selected from the mnemonic and application ID alone, the authenticated
application account record and protected Selfsame backup are the recovery
carriers defined by REQ-217.

### ADR-211: Separate a public username from the stable account alias

**Status:** PROPOSED.

The mandatory `acct:ss-…` alias remains opaque, immutable, automatically
provisioned, and the only alias used in grants and authorization. A person may
add one lower-case human-readable `acct:` localpart at the same account
authority for public discovery and display. Both aliases reciprocally name the
same home DID.

Making the chosen username the account scope, KDF input, stable alias, or VC
account claim is rejected: availability and renaming would then change
identity, reused names would create default cross-application correlation, and
reassignment could transfer apparent authority. A global Selfsame username
registry is also rejected; each application authority owns availability in its
own namespace.

Usernames are therefore mutable DID document data with conservative
tombstoning. Setting, renaming, or removing one changes no key, DID, grant, or
revocation entry.

### ADR-212: Use a versioned, operator-neutral rendezvous protocol

**Status:** PROPOSED.

The profile token `selfsame-rendezvous-v1` names
[[PROTO-002-selfsame-rendezvous-v1]], not the current reference server or an
Anuna deployment. The protocol fixes the HTTPS capability response, existing
role-separated slot derivation, opaque record size and TTL, immutable
idempotent writes, repeatable reads, errors, CORS, cache behavior, failover,
and operator data boundary. Eligibility and interoperability are decided by
black-box behavior.

The mailbox remains independent of `did:crdt` state transport. An operator may
offer both services, but selection of its rendezvous grants no state authority
and never implies the state endpoints exist at that origin.

Leaving `selfsame-rendezvous-v1` as an undocumented label is rejected because
it makes the reference implementation the accidental standard and prevents a
third party from knowing what to implement. Requiring every adopter to
configure protocol details is rejected because it breaks the no-configuration
user promise. Destructive reads are rejected because a dropped response would
consume the only correct copy; PROTO-002 instead makes replay rejection an
end-to-end ceremony property.

### ADR-213: Same-device mobile reuses the rendezvous ceremony

**Status:** PROPOSED.

When the target developer app and Selfsame wallet are on one phone, the
platform handoff replaces only the physical act of scanning or typing the link
code. The developer app still writes the offer and polls for the encrypted
grant under [[PROTO-002-selfsame-rendezvous-v1]], while Selfsame still reads the
offer, obtains consent, and writes the bundle. Signed `did:crdt` deltas continue
through the separate state-publication role.

This settles at the composition rung of the Simplicity Ladder: one ceremony,
one acceptance predicate, one loss/retry model, and one adversarial test corpus
serve both cross-device and same-device paths. It also keeps a compact,
security-insensitive completion callback from becoming a second credential
transport.

Returning a grant directly in a deep link, custom URL scheme, clipboard,
pasteboard, notification, or application callback is rejected. Those channels
have inconsistent caller authentication, interception and size behavior across
mobile platforms, and would expose a second implementation of transcript,
retry, timeout, and replay semantics. A future origin-authenticated platform
credential API may define a direct-local transport in a new profile version,
but it must reproduce the same security properties and cannot silently
downgrade version 1.

### ADR-214: Authenticate the application in layers before consent

**Status:** PROPOSED.

Selfsame treats the calling app, all link parameters, the public application
profile, display metadata, and a completion callback as attacker-controlled.
Before it touches an existing application-account branch, it requires:

1. a short-lived, one-time enrollment statement authenticated by a developer
   backend key anchored to the HTTPS `applicationId` origin;
2. an exact binding from that statement to the profile digest, account scope,
   device key, requested permissions, offer digest, and current time window;
3. the strongest caller/target identity signal exposed by the conforming
   platform adapter; and
4. explicit consent naming only the developer origin and operation established
   by those verified values.

No one layer substitutes for another. Origin authentication prevents a
malicious app from replaying another developer's public profile. Platform
binding reduces local app impersonation and link interception. Transcript
binding prevents a network, rendezvous, or local relay from swapping the
account, key, permission, provider, or response between concurrent ceremonies.
Consent addresses accurately authenticated but surprising requests.

An app-embedded shared secret is rejected because a public native client cannot
keep one. A custom scheme or package/bundle label alone is rejected because it
does not establish control of the application origin. Consent based on
caller-supplied name or icon is rejected because it authenticates presentation,
not authority. CON-214 fixes the logical statement and acceptance invariants;
OQ-207 remains blocking for the exact cross-platform key-discovery, wire, and
platform-evidence profiles.

## Contracts

### CON-201: Canonical application profile

The application supplies an immutable profile document with this logical
shape:

```json
{
  "profileVersion": 1,
  "applicationId": "https://photos.example/selfsame/application",
  "accountAuthority": "accounts.photos.example",
  "verifierAudience": "https://photos.example/selfsame/application",
  "allowedPermissions": [
    "https://photos.example/selfsame/application#device"
  ],
  "enrollment": {
    "requestSigningKeys": [
      {
        "kid":
          "https://photos.example/selfsame/application#enrollment-2026-01",
        "publicKeyJwk": {
          "kty": "OKP",
          "crv": "Ed25519",
          "x": "<base64url 32-byte Ed25519 public key>"
        }
      }
    ],
    "mobileBindings": [
      {
        "id": "android:com.example.photos:<cert-sha256>",
        "platform": "android",
        "packageName": "com.example.photos",
        "signingCertificateSha256": ["<base64url SHA-256 digest>"]
      },
      {
        "id": "apple:TEAM123456:com.example.photos:https://photos.example",
        "platform": "apple",
        "teamId": "TEAM123456",
        "bundleId": "com.example.photos",
        "returnUri":
          "https://photos.example/.well-known/selfsame/return"
      }
    ]
  },
  "rendezvous": [
    {
      "id": "au-primary",
      "url": "https://rendezvous-au.provider.example",
      "protocol": "selfsame-rendezvous-v1",
      "priority": 10,
      "weight": 80,
      "validUntil": "2027-07-30T00:00:00Z"
    },
    {
      "id": "global-secondary",
      "url": "https://rendezvous.example.net",
      "protocol": "selfsame-rendezvous-v1",
      "priority": 20,
      "weight": 20,
      "validUntil": "2027-07-30T00:00:00Z"
    }
  ],
  "stateResolvers": [
    {
      "id": "state-1",
      "url": "https://state.provider.example",
      "protocol": "did-crdt-signed-closure-v1"
    }
  ],
  "revocation": {
    "method": "did-crdt-revocations-v1",
    "maxClosureAgeSeconds": 900,
    "propagationSlaSeconds": 60,
    "projection": {
      "type": "BitstringStatusList",
      "allocationUrl":
        "https://status-cache.provider.example/selfsame/v1/slots",
      "credentialBaseUrl":
        "https://status-cache.provider.example/selfsame/v1/lists/",
      "maxAgeSeconds": 900
    }
  }
}
```

The physical encoding and remote update mechanism are deliberately outside
version 1. The application MUST embed an authenticated copy; it MAY update the
profile through its own authenticated release/configuration channel.

`accountScopeId` is authenticated per-account runtime input, not an application
profile property. A profile containing an account scope MUST be rejected; doing
so would give every account the same branch and publish private correlation
metadata in release configuration. Runtime scopes MUST conform to CON-211.

`applicationId` and `verifierAudience` MUST be identical in version 1.
`applicationId` MUST:

- be an absolute HTTPS URI;
- contain no user information, query, or fragment;
- use a lower-case ASCII IDNA A-label host;
- omit default port `443`;
- contain a non-empty absolute path;
- contain no `.` or `..` path segment; and
- use RFC 3986 percent-encoding normalization: unreserved characters decoded
  and hexadecimal digits upper-case.

The canonical string is the exact ASCII serialization satisfying those rules.
Clients MUST reject non-canonical input rather than normalize it silently.

`accountAuthority` MUST be a lower-case ASCII IDNA A-label DNS name without
port or trailing dot.

`enrollment.requestSigningKeys` MUST contain at least one unique key. Each
`kid` MUST be an absolute HTTPS URI on the `applicationId` origin with a
non-empty fragment, and each `publicKeyJwk` MUST use exactly `kty: OKP`,
`crv: Ed25519`, and one canonical 32-byte base64url `x` value. The private keys
are backend credentials and MUST NOT be embedded in a native application.

Every `enrollment.mobileBindings` entry has a unique `id`. Android package
names and signing-certificate rotation sets use the platform's canonical
spellings. Apple entries bind an exact Team ID and bundle ID to a claimed HTTPS
return URI on the `applicationId` origin. The wallet accepts a binding only
after the OQ-207 profile-origin mechanism and the platform-specific
verification in CON-215 authenticate it; field presence is not proof.

Every provider ID MUST match `[a-z0-9][a-z0-9-]{0,62}` and be unique within its
role. Every provider URL MUST be HTTPS, contain an authority, and contain no
user information or fragment. A rendezvous `validUntil` value MUST be a UTC
XML Schema `dateTimeStamp`; an expired descriptor is ineligible.
Rendezvous URLs have the stricter canonical-origin grammar in
[[PROTO-002-selfsame-rendezvous-v1#CON-301]] and MUST conform to it.

`revocation.method` MUST equal `did-crdt-revocations-v1` in profile version 1.
The `projection` member is OPTIONAL. Its absence disables Bitstring projection
without disabling issuance or revocation. If present, its URLs identify only
allocation and publication hosts: the application-account home DID remains the
status-list credential issuer and authority under CON-210.

For hashing in CON-209, the canonical descriptor bytes are the RFC 8785 JSON
Canonicalization Scheme serialization of the complete rendezvous descriptor.

### CON-202: Application and account key hierarchy

Definitions:

```text
UTF8(s)      = UTF-8 encoding of Unicode string s
U32BE(n)     = four-byte unsigned big-endian encoding of n
LP(s)        = U32BE(len(UTF8(s))) || UTF8(s)
SALT         = SHA-512(UTF8("selfsame/application-account-key-hierarchy/v1"))

KDF(ikm, label, context, length) =
  HKDF-SHA-512(
    IKM  = ikm,
    salt = SALT,
    info = LP(label) || LP(context),
    L    = length
  )
```

The recovery input is the 64-byte BIP-39 seed:

```text
recovery_seed = PBKDF2-HMAC-SHA512(
  password   = NFKD(mnemonic sentence),
  salt       = UTF8("mnemonic") || UTF8(NFKD(passphrase)),
  iterations = 2048,
  L          = 64
)
```

Version 1 uses the empty BIP-39 passphrase unless a future backup specification
explicitly records and restores another value.

After validating `canonical_account_scope_id` with CON-211, the hierarchy is:

```text
application_node =
  KDF(recovery_seed, "application", canonical_application_id, 64)

account_node =
  KDF(application_node, "account", canonical_account_scope_id, 64)

home_signing_seed =
  KDF(account_node, "home-signing-key", "", 32)
```

`home_signing_seed` is interpreted as an RFC 8032 Ed25519 private seed. It SHALL
be used only for the application-account home DID's assertion and control
operations. It SHALL NOT be used as a device key, encryption key, route key,
account token, or status-provider credential. `application_node` and
`account_node` are private KDF material; neither is a DID, signing key, wire
identifier, log field, or application-visible secret.

The home DID is the `did:crdt` identifier produced by a genesis document
controlled by the resulting Ed25519 public key. Exact DID construction remains
owned by the pinned `did:crdt` method specification.

The Tier-1 gate requires normative vectors for:

- two application IDs under one mnemonic;
- two account scopes below one application;
- the same account-scope bytes below two applications;
- the same application and account scope under two mnemonics;
- the same application ID under two mnemonics;
- a one-byte application-ID change;
- a one-byte account-scope change;
- Unicode mnemonic normalization; and
- rejection of non-canonical application IDs and account scopes.

### CON-203: DID Document and RFC 7565 account alias

Let:

```text
home_did  = the canonical application-account home DID string
digest    = SHA-256(UTF8(home_did))
localpart = "ss-" || BASE32LOWER-NOPAD(digest)
acct_uri  = "acct:" || localpart || "@" || accountAuthority
```

`BASE32LOWER-NOPAD` is RFC 4648 base32 with alphabet
`abcdefghijklmnopqrstuvwxyz234567`, lower-case output, and no `=` padding. A
SHA-256 digest therefore produces 52 characters and the complete localpart is
55 ASCII characters.

Because this generated localpart uses only unreserved characters and the
authority is already an A-label, the canonical profile URI uses no
percent-encoding.

The resolved DID Document SHALL include:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/jwk/v1"
  ],
  "id": "did:crdt:<application-account-home>",
  "alsoKnownAs": [
    "acct:ss-<52-lower-base32-characters>@accounts.photos.example"
  ],
  "verificationMethod": [
    {
      "id": "did:crdt:<application-account-home>#jwk-0",
      "type": "JsonWebKey",
      "controller": "did:crdt:<application-account-home>",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "x": "<base64url-no-padding raw 32-byte public key>"
      }
    }
  ],
  "assertionMethod": [
    "did:crdt:<application-account-home>#jwk-0"
  ]
}
```

Construction is deliberately two-stage:

1. create the `did:crdt` genesis and compute `home_did` from the root public key
   using the pinned method; then
2. provision `acct_uri` and apply a root-signed DID document-data update that
   sets `alsoKnownAs` to that URI.

The alias SHALL NOT be an input to DID genesis or DID identifier derivation.
This ordering prevents a circular definition in which the alias hashes the DID
while the DID hashes the alias. A resolver accepts `alsoKnownAs` only when that
document-data update is present in the verified signed closure.

The `JsonWebKey` projection is required by the W3C VC JOSE/COSE controlled
identifier profile. It MAY be a deterministic DID resolver representation of
the existing root key; it MUST NOT alter the bytes used to compute an existing
`did:crdt` identifier. The corresponding `did:crdt` method change is a
Tier-1-gated dependency.

For generated aliases, comparison is exact ASCII after validation. A general
`acct:` parser MUST follow RFC 7565 and RFC 3986 case and percent-encoding
normalization and MUST NOT assume that arbitrary userparts are case-insensitive.

### CON-204: Account provisioning and reciprocal binding

Before publishing `acct_uri`, the application account authority SHALL create an
account record keyed by its full normalized value and bind it to `home_did`.
That record MAY map internally to an existing application account, but the
mapping is private provider data and SHALL NOT appear in the DID or VC.

Provisioning occurs through the application's authenticated active-account
channel and is automatic from the person's perspective. The authority SHALL
recompute the expected localpart from `home_did`, require the supplied URI to
match it and the profile authority, and atomically create or return the
idempotent binding for that application account. It SHALL reject an alias
already bound to another account or DID.

Only after provisioning and reciprocal WebFinger publication succeed may the
home key sign the `SetDocumentData` update that publishes `alsoKnownAs` or
issue a device grant. On failure, the SDK SHALL leave the alias unpublished,
issue no grant, and return a typed integration error; it SHALL NOT ask the
person to repair the alias.

The reciprocal query is:

```http
GET /.well-known/webfinger?resource=<RFC3986-percent-encoded acct_uri> HTTP/1.1
Host: <accountAuthority>
Accept: application/jrd+json
```

A successful response contains:

```json
{
  "subject": "acct:ss-<opaque>@accounts.photos.example",
  "aliases": [
    "did:crdt:<application-account-home>"
  ]
}
```

Verification succeeds only when:

1. HTTPS certificate validation succeeds;
2. redirects, if any, remain HTTPS and are permitted by RFC 7033;
3. normalized JRD `subject` equals normalized `acct_uri`;
4. `aliases` contains an exact string equal to `home_did`; and
5. the DID Document's `alsoKnownAs` contains the same normalized `acct_uri`.

The response proves the account authority's reciprocal assertion. It does not
prove that the provider's internal mapping to a human is correct, and no
Selfsame verifier may infer such a claim.

### CON-205: Selfsame Device Grant Credential

The provisional immutable context identifier is:

```text
https://selfsame.dev/credentials/device-grant/v1
```

Domain ownership, publication, content digest, and long-term governance are
blocking in OQ-202. Once version 1 ships, the context at this identifier MUST
be immutable. The logical context defines:

```json
{
  "@protected": true,
  "SelfsameDeviceGrantCredential":
    "https://selfsame.dev/vocab/device-grant/v1#SelfsameDeviceGrantCredential",
  "application": {
    "@id": "https://selfsame.dev/vocab/device-grant/v1#application",
    "@type": "@id"
  },
  "account": {
    "@id": "https://selfsame.dev/vocab/device-grant/v1#account",
    "@type": "@id"
  },
  "permissions": {
    "@id": "https://selfsame.dev/vocab/device-grant/v1#permissions",
    "@type": "@id",
    "@container": "@set"
  },
  "SelfsameDidCrdtStatusEntry":
    "https://selfsame.dev/vocab/device-grant/v1#SelfsameDidCrdtStatusEntry",
  "credentialId": {
    "@id": "https://selfsame.dev/vocab/device-grant/v1#credentialId",
    "@type": "@id"
  }
}
```

At issuance, generate 32 CSPRNG bytes and encode them as canonical base64url
without padding:

```text
grant_token = BASE64URL-NOPAD(random_32_bytes)
grant_id    = home_did || "#grant-" || grant_token
status_id   = home_did || "#status-" || grant_token
```

`grant_token` is 43 characters and MUST pass the same decode/re-encode
canonicality checks as CON-211. It is independent for every grant and is never
derived from a device key, account scope, timestamp, provider allocation, or
recovery material.

A grant payload has this shape:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://selfsame.dev/credentials/device-grant/v1"
  ],
  "type": [
    "VerifiableCredential",
    "SelfsameDeviceGrantCredential"
  ],
  "id": "did:crdt:<application-account-home>#grant-<43-char-token>",
  "issuer": "did:crdt:<application-account-home>",
  "validFrom": "2026-07-30T06:00:00Z",
  "validUntil": "2026-08-29T06:00:00Z",
  "credentialSubject": {
    "id": "did:key:<device>",
    "application": "https://photos.example/selfsame/application",
    "account": "acct:ss-<opaque>@accounts.photos.example",
    "permissions": [
      "https://photos.example/selfsame/application#device"
    ]
  },
  "credentialStatus": {
    "id": "did:crdt:<application-account-home>#status-<43-char-token>",
    "type": "SelfsameDidCrdtStatusEntry",
    "statusPurpose": "revocation",
    "credentialId":
      "did:crdt:<application-account-home>#grant-<43-char-token>"
  },
  "aud": "https://photos.example/selfsame/application",
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "alg": "EdDSA",
      "x": "<base64url-no-padding raw 32-byte device public key>"
    }
  }
}
```

The example values are illustrative; the member names and validation rules are
normative.

The protected JWS header SHALL be:

```json
{
  "alg": "EdDSA",
  "kid": "did:crdt:<application-account-home>#jwk-0",
  "typ": "vc+jwt",
  "cty": "vc"
}
```

The JWS SHALL use the compact serialization from RFC 7515. Its payload SHALL be
the UTF-8 JSON VC document, not a JSON string and not a nested `vc` property.
JSON objects SHALL contain no duplicate member names.

The header SHALL contain no `jku`, `x5u`, `x5c`, embedded `jwk`, or unprotected
algorithm/key-discovery parameter. A verifier SHALL accept only the exact
`EdDSA` algorithm allowlist and SHALL reject `none` and every other algorithm.

The credential:

- MUST contain the two contexts in the stated order and no unknown context;
- MUST contain both stated types;
- MUST contain a unique `id` constructed above;
- MUST use the expected application-account home DID as `issuer`;
- MUST use the offered device DID as `credentialSubject.id`;
- MUST set `application` and `aud` to the expected canonical application ID;
- MUST set `account` to the issuer DID's verified stable opaque RFC 7565 alias,
  never the optional human-readable alias;
- MUST contain a non-empty set of permission URIs declared by the profile;
- MUST contain exactly one `SelfsameDidCrdtStatusEntry`, with matching
  `status_id`, `credentialId`, issuer DID, and grant token;
- MAY additionally contain exactly one `BitstringStatusListEntry` when the
  profile enables the CON-210 projection; in that case `credentialStatus` is
  an array with the Selfsame entry first and Bitstring entry second;
- MUST use XML Schema `dateTimeStamp` values normalized to UTC `Z`; and
- MUST make the `cnf.jwk` key equal the Ed25519 key encoded by the device DID.

### CON-206: Grant acceptance predicate

Given `grant_bytes`, an embedded `application_profile`, the exact RFC 7565
account expected by the current authenticated application-account context, an
offered device key, and current time, a verifier SHALL perform these steps in
order:

1. Reject input larger than 64 KiB.
2. Parse compact JWS strictly; reject invalid base64url, duplicate JSON member
   names, extra compact segments, or non-object header/payload.
3. Require exactly `alg=EdDSA`, `typ=vc+jwt`, `cty=vc`, and an absolute DID URL
   `kid`; reject remote key URLs and forbidden header parameters.
4. Obtain the issuer's signed `did:crdt` closure from the encrypted bundle,
   local cache, or a profile-declared state resolver.
5. Recompute the self-certifying DID, verify every required delta and
   authorization rule, and resolve the current DID Document.
6. Require `kid` to identify a `JsonWebKey` in the issuer document's
   `assertionMethod`; require an OKP/Ed25519 public JWK with no private `d`.
7. Verify the JWS over the original compact protected-header and payload bytes.
8. Validate every VC field and cross-field equality in CON-205 using the pinned
   contexts; require `credentialSubject.account` to equal the expected account;
   perform no remote context retrieval.
9. Verify the reciprocal RFC 7565 account binding in CON-204 or a fresh
   authenticated cache of that exact binding.
10. Enforce `revocation.maxClosureAgeSeconds` on the causally valid closure and
    require its revocation G-Set not to contain the exact VC `id`, using
    `Document::is_revoked` or the pinned method-equivalent check. If an
    optional Bitstring projection is present, a valid set bit also rejects the
    grant; an unset, stale, invalid, or unavailable projection never bypasses
    the CRDT check.
11. Require current time to be within `[validFrom, validUntil)`, allowing only
    the application's explicitly configured clock-skew bound.
12. Require every permission to be declared by the embedded profile and by the
    local operation being attempted.
13. Run the device proof-of-possession challenge in CON-207.

Authorization succeeds only if every step succeeds. Diagnostic detail MAY be
logged locally but externally visible errors SHOULD collapse to a small stable
set so that attackers do not gain a credential oracle.

### CON-207: Device proof of possession

The verifier generates a uniformly random 32-byte nonce, records it as unused,
and sends it to the device. The nonce expires after at most 120 seconds.

Define:

```text
grant_hash = SHA-256(grant_bytes)

proof_input =
  UTF8("selfsame/device-possession/v1") ||
  0x00 ||
  LP(canonical_application_id) ||
  LP(canonical_acct_uri) ||
  nonce_32 ||
  grant_hash
```

Here `LP` is the function in CON-202. The device returns an RFC 8032 Ed25519
signature over `proof_input`. The verifier validates it with `cnf.jwk`.

The verifier SHALL atomically mark the nonce used whether verification succeeds
or fails. It SHALL reject a nonce issued for another application, account,
grant, verifier session, or time window.

### CON-208: Rendezvous provider selection

For one link attempt, the initiator:

1. reads the authenticated embedded profile;
2. rejects expired, malformed, non-HTTPS, unsupported-protocol, or
   locally-forbidden descriptors;
3. groups remaining descriptors by ascending numeric `priority`;
4. probes all descriptors in the lowest-priority group concurrently with a
   per-probe deadline of at most 1500 ms;
5. forms the eligible set only from endpoints whose base URL and complete
   capability response pass
   [[PROTO-002-selfsame-rendezvous-v1#CON-301]];
6. selects one eligible descriptor by cryptographically random weighted choice,
   where zero weight means ineligible;
7. if none are eligible, repeats steps 4–6 with the next priority group; and
8. if every group fails, returns `NoEligibleRendezvous`.

Health responses are hints, not trust anchors. All ceremony confidentiality and
authenticity remain end-to-end.

Selection MUST NOT use a stable user identifier, home DID, `acct:` URI, device
key, or recovery-derived value as the random input. Doing so would create
provider-visible cohorts.

### CON-209: Authenticated provider hint

The link ceremony SHALL bind this logical value:

```json
{
  "applicationId": "https://photos.example/selfsame/application",
  "profileVersion": 1,
  "providerId": "au-primary",
  "descriptorDigest": "<base64url SHA-256 of canonical descriptor>",
  "offerDigest": "<base64url transcript offer digest>"
}
```

The provider hint MUST be confidential until the joining device has the
out-of-band link secret and MUST be authenticated as part of the same
transcript that protects the offer and grant bundle.

The hint SHALL NOT contain `accountScopeId`. The transcript-bound offer digest
and encrypted grant bind the ceremony to the expected RFC 7565 account without
disclosing the private derivation selector to the rendezvous provider.

The concrete carrier MAY be the secret-derived discovery record already
proposed by SPEC-001 ADR-014 or a future ceremony version with room in the
out-of-band code. Whichever carrier is selected by the ceremony specification
MUST preserve the logical fields and acceptance rules above.

The joiner verifies:

- exact application ID;
- a supported profile version;
- provider ID present in its embedded profile;
- descriptor digest equal to its local descriptor;
- offer digest equal to the offer it is processing; and
- transcript authentication before first use of the endpoint.

### CON-210: CRDT revocation and optional status projection

Core issuance requires no provider allocation. The exact `grant_id` constructed
in CON-205 is the credential identifier stored in revocation state.

To revoke it, a controller:

1. resolves and verifies the issuer's current causally complete `did:crdt`
   state and frontier;
2. constructs the pinned method's
   `RevokeCredential { credential_id: grant_id }` operation;
3. sets the current frontier as the delta's parents and creates the
   method-defined HLC timestamp;
4. signs the method-defined canonical delta input with a known, non-revoked
   verification method authorized in the operation's causal past; and
5. submits the complete signed delta to every reachable profile-declared state
   resolver and directly connected peer.

This specification does not redefine `SignedDelta`, its proof, canonical
signing bytes, causal-admission rules, or hash. Implementations SHALL use the
exact versions pinned by the `did:crdt` method specification. A standalone
HTTP "revoke" signature or provider database update does not revoke a
Selfsame grant.

A replica accepts the operation only after normal `did:crdt` signature,
authorization, DID, parent-closure, deactivation, and causal checks. Applying
the operation inserts the exact string into the issuer document's revocation
G-Set. Merge is set union and therefore commutative, associative, idempotent,
and irreversible. Duplicate revocations succeed idempotently; concurrent
revocations of different grants retain every ID. Key rotation neither revokes
nor restores a credential.

The initiating application reports **pending** until a newly resolved,
cryptographically verified closure includes `grant_id`. It reports success
only then. A resolver's acknowledgement is not evidence of revocation. A
resolver MAY withhold or lag state, but cannot forge, clear, or override a
valid G-Set entry. Resolver diversity and
`revocation.propagationSlaSeconds` bound availability; OQ-201 must approve the
final values.

If `revocation.projection` is present, issuance MAY additionally obtain a
random free `(statusListCredential, statusListIndex)` allocation and include a
conforming `BitstringStatusListEntry` after the mandatory Selfsame entry.
`statusListIndex` MUST be a canonical base-10 integer with no leading zeroes;
indexes SHOULD be assigned randomly as recommended by W3C Bitstring Status
List 1.0.

The projection SHALL satisfy all of these invariants:

- it conforms to W3C Bitstring Status List 1.0 and its uncompressed bitstring
  contains at least 131,072 entries;
- its `issuer` is the same application-account home DID as the projected
  grants, and its proof is made by that DID's current `assertionMethod`;
- its publication host only stores signed bytes and allocation metadata; the
  host possesses no home signing key and is not an authorization trust anchor;
- a bit may be set only after a verified CRDT closure contains the exact grant
  ID mapped to that index, and no later projection may clear a previously set
  bit; and
- its validity and cache lifetime do not exceed
  `revocation.projection.maxAgeSeconds`.

An implementation can therefore create and sign the projection beside the
revocation delta, then publish it through an untrusted cache or CDN. Failure to
publish the projection does not undo the CRDT revocation. Selfsame verifiers
always apply CON-206 to fresh CRDT state. Generic VC consumers may process the
Bitstring entry according to that W3C standard and inherit its bounded
freshness tradeoff.

Status credentials SHOULD be stapled where practical. Fetchers SHOULD use
privacy-preserving caches or proxies rather than reveal individual
authorization events to the publication host.

### CON-211: Account-scope identifier and lifecycle

The canonical textual form is base64url without padding of exactly 32 random
bytes. Its ABNF is:

```abnf
b64url-char  = ALPHA / DIGIT / "-" / "_"
b64url-final = %x41 / %x45 / %x49 / %x4D / %x51 / %x55 / %x59
             / %x63 / %x67 / %x6B / %x6F / %x73 / %x77
             / %x30 / %x34 / %x38
account-scope-id = 42b64url-char b64url-final
```

`ALPHA` and `DIGIT` are the RFC 5234 core rules. The restricted final
character encodes the required zero pad bits for a canonical 32-byte value.
A parser MUST additionally:

1. reject `=`, whitespace, non-ASCII input, and any length other than 43;
2. decode with the RFC 4648 URL- and filename-safe alphabet;
3. require exactly 32 decoded bytes; and
4. re-encode those bytes without padding and require byte-for-byte equality
   with the input.

For a new authenticated application account, the application generates the
32-byte value with a CSPRNG and commits it to the account record before
requesting derivation. Concurrent first-use requests MUST resolve atomically to
one committed value. The value is immutable for the lifetime of that account
and MUST NOT be recycled after deletion.

The application passes the canonical string through an authenticated,
in-process SDK boundary. Selfsame uses it only as KDF context and private
storage namespace. Providers and public protocols receive the resulting DID,
alias, or credential identifiers, never the scope itself.

### CON-212: Human-readable alias grammar and lifecycle

The chosen localpart MUST be 1–32 lower-case ASCII characters and match:

```text
[a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9])?
```

The `ss-` prefix and an authority-maintained list of operational or abusive
names are reserved. Input containing upper-case, non-ASCII, percent-encoding,
leading or trailing punctuation, or any other form SHALL be rejected rather
than silently normalized. The complete alias is:

```text
human_acct_uri =
  "acct:" || chosen_localpart || "@" || accountAuthority
```

Because all components are ASCII URI characters, the canonical form contains
no percent-encoding. Availability is exact-string availability within the
profile's `accountAuthority`; Selfsame defines no global namespace.

To set the alias, the authority SHALL:

1. authenticate the active application account and obtain its already-bound
   `home_did` and stable opaque alias;
2. validate the localpart, check reservations, and atomically reserve the
   complete URI for that same account and DID;
3. publish a CON-204 WebFinger JRD whose `subject` is `human_acct_uri` and
   whose `aliases` contains `home_did`;
4. return an authenticated confirmation to the SDK; and
5. have a current home controller sign a `SetDocumentData` update setting
   `alsoKnownAs` to `[stable_acct_uri, human_acct_uri]`.

The alias becomes active only after a verified DID closure exposes that exact
array and both reciprocal WebFinger checks pass. An unavailable or reserved
name returns `UsernameUnavailable`; other failures leave the previous DID
aliases and account binding unchanged.

Rename first reserves and publishes the new URI, then replaces the old
human-readable value in one DID update, verifies the new closure, and finally
tombstones the old URI. Removal updates `alsoKnownAs` to contain only the
stable alias, verifies the closure, and then tombstones the removed URI. A
tombstoned human-readable URI SHALL NOT be assigned to another account or DID
in version 1. This conservative rule prevents stale links and caches from
appearing to transfer identity.

No set, rename, removal, reservation, or tombstone operation changes
`accountScopeId`, the home DID, any key, the stable alias, existing grant IDs,
VCs, device proofs, revocation G-Set entries, or provider selection.

### CON-213: Rendezvous protocol binding

For profile version 1, a rendezvous descriptor is recognized only when:

1. `protocol` is exactly `selfsame-rendezvous-v1`;
2. `url` is a canonical base URL under
   [[PROTO-002-selfsame-rendezvous-v1#CON-301]];
3. the descriptor passes expiry, local policy, priority, and weight checks in
   [[SPEC-004-application-scoped-identity#CON-208]]; and
4. a bounded `GET /healthz` returns a capability object accepted by
   [[PROTO-002-selfsame-rendezvous-v1#CON-301]].

The selected descriptor's exact base URL is the only rendezvous origin for
that ceremony. The clients derive fresh offer and bundle slots and perform all
mailbox requests under
[[PROTO-002-selfsame-rendezvous-v1#CON-302]] through
[[PROTO-002-selfsame-rendezvous-v1#CON-308]]. They reject redirects,
credentials, cookies, content encoding, oversized responses, unrecognized
statuses, destructive-read semantics, and any attempt by the server to choose
another endpoint or protocol.

The authenticated hint in
[[SPEC-004-application-scoped-identity#CON-209]] binds the exact descriptor
digest, so a joiner never accepts a health response or redirect as a provider
substitution. If the selected provider fails after any slot request or hint
publication, both parties abandon its ceremony state. A newly selected provider
receives a new secret, slots, offer, ciphertext, and hint; no mailbox record is
copied.

A rendezvous descriptor supplies no DID-state, account-authority, or
status-projection endpoint. Those roles require their own profile descriptors
and protocols even when one operator or DNS origin implements several roles.

Implements: REQ-209, REQ-210, REQ-212, REQ-214, REQ-219.

Verified by: TEST-214, TEST-215, TEST-216, TEST-218, TEST-220, TEST-226.

### CON-214: Application enrollment evidence

Before either mobile path may use an application-account branch, the
developer backend authenticates this closed logical statement:

```json
{
  "evidenceVersion": 1,
  "requestId": "<base64url 32 random bytes>",
  "ceremonyId": "<base64url 32 random bytes>",
  "applicationId": "https://photos.example/selfsame/application",
  "profileVersion": 1,
  "profileDigest": "<base64url SHA-256 of the RFC 8785 profile>",
  "accountScopeId": "<canonical private account scope>",
  "deviceKeyDigest": "<base64url SHA-256 of the canonical cnf.jwk>",
  "requestedPermissions": [
    "https://photos.example/selfsame/application#device"
  ],
  "providerId": "au-primary",
  "descriptorDigest": "<base64url SHA-256 of the canonical descriptor>",
  "offerDigest": "<base64url transcript offer digest>",
  "platformBindingId": "android:com.example.photos:<cert-sha256>",
  "returnUri": "https://photos.example/.well-known/selfsame/return",
  "issuedAt": "2026-07-30T10:00:00Z",
  "expiresAt": "2026-07-30T10:02:00Z"
}
```

The physical evidence is a compact JWS over the exact UTF-8 RFC 8785
serialization of that object. Its protected header has the closed field set
`alg`, `typ`, and `kid`; `alg` is exactly `EdDSA`, `typ` is exactly
`selfsame-enrollment+jws`, and `kid` identifies an Ed25519 enrollment-signing
key in the authenticated application profile. No unprotected header is
permitted. The developer backend, not the public native app, holds the private
key.

The JSON recognizer rejects duplicate members, unknown members, non-canonical
base64url, arrays with duplicates or non-profile permissions, timestamps with
offsets other than `Z`, and any value outside the inherited CON-201, CON-205,
CON-209, and CON-211 grammars. `requestedPermissions` is sorted by Unicode code
point and is an exact subset of `allowedPermissions`. `expiresAt` is later than
`issuedAt` by at most 120 seconds. Both random identifiers decode to exactly 32
bytes.

`platformBindingId` selects one binding from the authenticated profile:

- Android uses `android:` followed by the exact package name and a SHA-256
  signing-certificate digest, including an explicitly declared certificate
  rotation set.
- Apple platforms use `apple:` followed by the Team ID, bundle ID, and the
  origin of an associated HTTPS return URI.

The exact profile-discovery and platform-evidence encodings remain the blocking
part of OQ-207. This contract fixes the values they must authenticate. A
production wallet cannot treat a profile and key delivered only by the caller
as authenticated.

The compact JWS appears only inside the encrypted ceremony offer. The
`accountScopeId`, evidence JWS, and its private claims never appear in the OS
handoff, rendezvous plaintext, callback, URL, log, analytics, or consent label.

Before showing consent, Selfsame:

1. obtains the application profile through the authenticated
   `applicationId`-origin mechanism selected by OQ-207 and verifies the profile
   digest;
2. verifies the compact JWS and resolves `kid` only from that authenticated
   profile;
3. compares every statement field to the active offer, provider descriptor,
   device JWK, requested permission set, and OS-observed platform binding;
4. checks the 120-second window against its local clock;
5. atomically records `requestId` as consumed before any home-key signature,
   delta publication, or grant-bundle write, whether the request is approved or
   rejected; and
6. renders consent from the authenticated origin and bound operation rather
   than caller-supplied presentation metadata.

Any mismatch returns one closed error:
`UnverifiedApplication`, `EnrollmentMalformed`, `EnrollmentBadSignature`,
`EnrollmentExpired`, `EnrollmentReplay`, `ProfileMismatch`,
`AccountBindingMismatch`, `DeviceBindingMismatch`, `PermissionMismatch`,
`ProviderMismatch`, `OfferMismatch`, or `PlatformBindingMismatch`.

Every error leaves home state, grant state, DID state, provider state, active
sessions, and the bundle slot unchanged. The consumed-ID record is the sole
permitted mutation after syntactically valid evidence reaches step 5.

Implements: REQ-205, REQ-206, REQ-207, REQ-208, REQ-215, REQ-216, REQ-217,
REQ-222, REQ-223.

Verified by: TEST-207, TEST-209, TEST-211, TEST-221, TEST-222, TEST-228,
TEST-229.

### CON-215: Same-device mobile handoff

The developer app creates the ordinary ceremony through CON-208, CON-209,
CON-213, and CON-214 before invoking Selfsame. The closed logical handoff is:

```json
{
  "handoffVersion": 1,
  "mode": "same-device",
  "ceremonyId": "<same 32-byte identifier as CON-214>",
  "applicationId": "https://photos.example/selfsame/application",
  "profileDigest": "<same digest as CON-214>",
  "offerDigest": "<same digest as CON-214>",
  "linkCode": "<existing one-time Selfsame link code>",
  "returnUri": "https://photos.example/.well-known/selfsame/return"
}
```

The recognizer accepts exactly the first six members and the optional seventh
`returnUri` member, in the shown order, after the platform adapter has
delivered a typed value. It does not extract fields with regular expressions
or act on a partial parse. The inherited application ID, base64url,
offer-digest, link-code, and HTTPS URI grammars apply. When present,
`returnUri` is exact-string equal to the URI in CON-214, has no user
information or fragment, and is declared by the authenticated platform
binding.

The SDK chooses the same-device path only after the adapter positively
identifies an installed wallet conformance target:

- An Android adapter uses an explicit package/component dispatch, verifies the
  installed wallet signing identity, requests caller-identity sharing where the
  platform supports it, and uses an immutable one-shot result capability. It
  never uses a generic implicit intent for ceremony material.
- An Apple adapter opens a Selfsame HTTPS Universal Link only with the
  platform's `universalLinksOnly` requirement. Failure to reach an associated
  installed app is failure, not permission to open Safari, an embedded web
  view, an install page, or a custom URL scheme.
- A future adapter must provide equivalent installed-target authentication,
  no-network-fallback behavior, one-shot delivery, and a caller-binding signal
  for CON-214. Declaring itself equivalent is insufficient; its conformance
  suite and threat analysis must land in a new spec revision.

After dispatch, the developer app keeps polling the existing bundle slot.
Selfsame uses `linkCode` to enter the ordinary offer/grant ceremony, applies
CON-214 before consent, and returns the grant only through the encrypted
rendezvous bundle. State deltas are submitted through the profile's state
resolver role, never through a `/rendezvous/{slot}` record.

An optional platform return contains exactly:

```json
{
  "handoffVersion": 1,
  "ceremonyId": "<same identifier>",
  "outcome": "completed"
}
```

`outcome` is one of `completed`, `cancelled`, or `failed`. This object contains
no link code, secret, provider, profile digest, offer digest, account scope,
DID, alias, key, credential, ciphertext, permission, or error detail. It is
accepted only to foreground a locally pending ceremony with the same
`ceremonyId`; it does not stop polling, supply grant data, or alter the
acceptance result.

Dispatch returns one of `WalletUnavailable`, `UnverifiedWalletTarget`,
`HandoffMalformed`, `HandoffAmbiguous`, `PlatformBindingMismatch`,
`UserDenied`, or `Dispatched`. Every result except `Dispatched`, and every
ambiguous post-dispatch condition, abandons the ceremony under REQ-225.
Installation/help UI is then offered separately with no ceremony value.

Implements: REQ-209, REQ-211, REQ-212, REQ-220, REQ-221, REQ-222, REQ-223,
REQ-224, REQ-225.

Verified by: TEST-218, TEST-227, TEST-228, TEST-229, TEST-230, TEST-231.

## Test specifications

### TEST-201: Application separation

For one fixed recovery seed, one fixed canonical account scope, and 10,000
distinct canonical application IDs, derive 10,000 unique application nodes,
account nodes, home seeds, public keys, and DIDs. No pair is equal.

### TEST-202: Deterministic restore

Two independent implementations derive byte-identical application nodes,
account nodes, and home seeds from every normative vector.

### TEST-203: Application ID canonicality

Accept the normative canonical URI corpus. Reject variants with upper-case
host, default port, user information, query, fragment, dot segment, Unicode
host, lower-case percent hex, or percent-encoded unreserved character.

### TEST-204: `acct:` construction

For every home DID vector, reproduce the exact lower-case unpadded base32
localpart and complete RFC 7565 URI.

### TEST-205: Reciprocal alias

Accept only when DID `alsoKnownAs`, WebFinger `subject`, WebFinger `aliases`,
the application profile authority, and VC account all match. Break each edge
individually and require rejection.

### TEST-206: Account privacy

Generated DID, account, WebFinger, VC, status, and provider-hint fixtures
contain none of the fixture user's email, display name, phone number, global
account ID, `accountScopeId`, sibling scope, or application-A identifier.

### TEST-207: W3C VC positive vectors

Validate all W3C VC Data Model 2.0 and VC JOSE/COSE requirements exercised by
the profile, then verify the normative Selfsame grant vectors.

### TEST-208: JWS negative corpus

Reject `alg:none`, algorithm substitution, missing/relative/wrong `kid`,
unprotected algorithm parameters, embedded remote keys, duplicate JSON names,
legacy `vc` wrapper claims, malformed compact serialization, altered payload,
and non-canonical base64url.

### TEST-209: Holder binding

Accept a valid challenge signature from the `cnf` key. Reject a signature by
the issuer, another device, another application device, another account's
device, or a key whose public bytes differ from the subject DID.

### TEST-210: Challenge replay

Reject reuse after success, reuse after failure, use after 120 seconds, use
with another grant, another application ID, or another RFC 7565 account.

### TEST-211: Authorization predicate

Mutate each of CON-206's thirteen checks independently. No mutation may leave
the result authorized.

### TEST-212: Grant validity and status

Test before `validFrom`, at `validFrom`, immediately before `validUntil`, at
`validUntil`, present and absent grant IDs in a valid revocation G-Set, stale
closure, incomplete causal closure, invalid delta signature, unauthorized
signer, and deactivated issuer.

With projection enabled, test valid set and unset bits, invalid proof, wrong
issuer, cleared-bit rollback, stale projection, and unavailable projection. A
set bit rejects early; no other projection condition may bypass the CRDT check.

### TEST-213: Revocation convergence and propagation

Submit a valid signed `RevokeCredential` delta and observe the exact grant ID
in a newly resolved verified closure within `propagationSlaSeconds`. Reject
tampered, wrong-DID, missing-parent, cross-application, cross-account,
deactivated, revoked-signer, and unknown-signer deltas.

Apply the same delta repeatedly and require idempotence. Concurrently revoke
different grants on three replicas, merge in every order, and require identical
sets containing every ID. Attempt to clear or overwrite an ID and require that
no method operation or merge can make `is_revoked(id)` false.

### TEST-214: Provider selection

Exercise priority, weight, bounded parallel probes, incompatible protocol,
timeouts, unhealthy endpoints, malformed descriptors, and total failure.
Against the PROTO-002 capability oracle, reject a plain `ok` body, unknown or
duplicate JSON members, wrong semantics, a 4 KiB maximum, redirects,
compression, wrong media type, oversized response, and a response arriving
after 1500 ms. No rejected descriptor may enter the weighted choice.

### TEST-215: One initiator, one selection

Give two devices different health observations and profile revisions. Confirm
that the joiner follows only a valid initiator hint and never starts a second
election for the same ceremony.

### TEST-216: No global fallback

Build a release client with an empty or wholly unhealthy profile. Assert that
no DNS lookup or connection targets an Anuna/Selfsame endpoint and that the
operation ends as `NoEligibleRendezvous`.

### TEST-217: Opaque transport

Issue one compact JWS, transport it through every supported ceremony encoding,
extract it, and require byte identity and successful verification by an
independent non-CBCL verifier.

### TEST-218: Provider-hint integrity

Alter application ID, profile version, provider ID, descriptor digest, offer
digest, ciphertext, and authentication tag separately. Every alteration is
rejected before grant retrieval.

### TEST-219: Provider-independent recovery

Change every provider and account endpoint in the profile without changing
`applicationId` or `accountScopeId`; confirm that the application node, account
node, and home key do not change.

### TEST-220: Independent developer conformance

Run a complete issue-link-verify-revoke flow using only third-party account,
rendezvous, and state services. The rendezvous first passes the independent
PROTO-002 black-box suite. Exercise two accounts in the same application,
disable Bitstring projection, block all Anuna domains, and require both flows
to pass. Repeat with a third-party projection host and require identical
Selfsame authorization results.

### TEST-221: Device-key separation

On one installation, enroll the same recovery principal into 100 distinct
application IDs with 100 account scopes each. No device public key or DID may
repeat. Deliberately reuse one device key across applications and then across
two accounts in one application; require the second enrollment to be rejected
in both cases.

### TEST-222: Multiple-account isolation and switching

For one fixed recovery seed and application ID, derive 10,000 distinct valid
account scopes. Require unique account nodes, home seeds, public keys, DIDs,
aliases, device keys, credential IDs, state namespaces, and status entries.

Switch the application's authenticated account context between A1 and A2
without changing its profile. Require the SDK to select the matching branch
without Selfsame user input. Present each account's issuer closure, grant,
device proof, status entry, revocation delta, and optional projection to the
other account in turn; every cross-account presentation must fail.

### TEST-223: Account-scope lifecycle and recovery

Accept canonical 43-character encodings that decode to exactly 32 bytes.
Reject wrong length, padding, whitespace, non-ASCII, invalid alphabet,
non-canonical pad bits, and decode/re-encode mismatch.

For one account, race concurrent first-use requests and require one committed
scope. Require repeated authentication and account recovery to return it,
protected local or backup restore to reproduce the same identity, account
deletion and recreation to allocate a different scope, and attempted scope
reuse for another account to fail. With every valid carrier removed, require
`AccountScopeUnavailable`, no new identity, and no prompt for the scope.
Inspect public artifacts, logs, analytics, and rendezvous traffic and require
the raw and encoded scope to be absent.

### TEST-224: `did:crdt` method-boundary compatibility

Use two account-derived Ed25519 public keys to create two ordinary independent
`did:crdt` genesis documents. Apply a root-signed `SetDocumentData` update for
`alsoKnownAs` to each and require resolution to expose the exact RFC 7565 URI
at the DID Document top level.

Require the issuer key to resolve at `#jwk-0` as `type: JsonWebKey` with
`publicKeyJwk` and membership in `assertionMethod`. Confirm that adding this
resolver representation does not change the genesis bytes or DID identifier
computed by the pinned method.

Issue a grant ID, apply a valid `RevokeCredential` delta, merge concurrent
revocations in different orders, and require the existing
`Document::is_revoked` interface to return the same permanent result. This
operation is already part of the inspected method and requires no new
`did:crdt` amendment.

### TEST-225: Human-readable alias lifecycle

Accept boundary-length and representative valid localparts. Reject empty,
overlength, upper-case, Unicode, percent-encoded, reserved `ss-`, leading or
trailing punctuation, and authority-mismatched values.

Set, rename, and remove a username through CON-212. At each committed state,
require the exact DID/WebFinger reciprocal binding and stable opaque alias.
Race two accounts for one name and permit exactly one reservation. Require the
loser to receive `UsernameUnavailable`; tombstone the old name after rename or
removal and reject later reassignment. Confirm byte identity of all home keys,
DIDs, stable aliases, grants, proofs, and revocation entries before and after
each username operation.

### TEST-226: Rendezvous protocol integration and failover

**Validates:** REQ-209, REQ-210, REQ-212, REQ-214, REQ-219, CON-208,
CON-209, CON-213.

Run [[PROTO-002-selfsame-rendezvous-v1#TEST-301]] through
[[PROTO-002-selfsame-rendezvous-v1#TEST-310]] against two independently
implemented providers, then complete the same application-account ceremony
through each. Confirm selection uses only a conforming capability response and
all traffic remains on the descriptor origin.

Make the first provider unavailable once after an unacknowledged initial slot
request and once after publishing its authenticated provider hint, then select
the second. In both cases require a new secret, offer slot, bundle slot, offer,
ciphertext, descriptor digest, and hint. Require no shared slot or ciphertext
across the two operators and no change to the application-account node, home
key, DID, stable alias, account scope, grant semantics, or `did:crdt` state.

Deploy a state resolver beside the first rendezvous and at a separate origin in
turn. Neither arrangement may change mailbox traffic or make the selected
rendezvous an implicit resolver. Block every Anuna domain throughout and
require identical results.

### TEST-227: Same-device mobile ceremony

**Validates:** REQ-220, REQ-221, ADR-213, CON-214, CON-215.

Install the developer app and a conforming Selfsame wallet in the Android and
Apple integration harnesses. Authorize the developer app's current device
through a tap-to-Selfsame handoff, with the target app holding the device
private key and polling the selected rendezvous throughout.

The positive test requires no QR render, camera permission, typed/pasted code,
endpoint chooser, or credential-sized OS callback. The wallet reads the
ordinary offer, shows the authenticated application/account/device/permission
consent, writes the ordinary encrypted bundle, and publishes signed DID state
only to the separately selected state service. The app accepts through CON-206
and proves the device key through CON-207.

Repeat as a cross-device ceremony with fresh randomness. The platform traces
differ only at link-code delivery and optional foreground return; provider
selection, mailbox routes, accepted grant semantics, device proof, state
publication, and failure decisions are otherwise equivalent.

### TEST-228: Enrollment evidence acceptance and replay

**Validates:** REQ-222, ADR-214, CON-201, CON-214.

Verify a positive compact-JWS vector independently. Exercise both timestamp
boundaries, every permitted enrollment-key rotation entry, the exact
application/account/device/permission/provider/offer bindings, and a valid
platform binding. Approval consumes `requestId` before the first home-key side
effect.

Retry the byte-identical evidence before and after expiry, after approval,
after denial, and after a post-consumption process crash. Every retry returns
`EnrollmentReplay`. The prohibited-action assertion requires no second
signature, grant ID, delta, mailbox write, session, or consent decision. The
scope-invariant assertion permits only one consumed-ID record and leaves every
other application and account unchanged.

### TEST-229: MITM, local-app substitution, and ceremony mix-up

**Validates:** REQ-205, REQ-206, REQ-207, REQ-222, REQ-223, CON-206, CON-209,
CON-214, CON-215.

Place an adversary on every network path and give it control of the rendezvous,
one state resolver, a second installed mobile app, all callback/link parameters,
and caller-supplied name/icon metadata. It does not control the OS, recovery
secret, developer enrollment-signing key, or target device private key.

Mutate application ID, profile digest, account scope, device key digest,
permission set, provider ID, descriptor digest, offer digest, request ID,
ceremony ID, platform binding, return URI, issue/expiry time, JWS protected
header, offer ciphertext, provider hint, grant ciphertext, VC audience, and
device proof one at a time. Then splice each valid value from application A,
account A1, and ceremony C1 into B, A2, and C2 in every pairwise direction.

Every mutation or splice is rejected before a home-key signature, delta
publication, grant-bundle write, branch-existence disclosure, or verified
consent label. Copying the complete public profile, package/bundle label,
display metadata, handoff, or callback into the malicious app never grants it
the developer backend signature or target device proof. Exact-count assertions
require zero new grants, deltas, sessions, bundle records, aliases, or provider
requests outside the single accepted control ceremony.

### TEST-230: Verified wallet dispatch and fail-closed fallback

**Validates:** REQ-220, REQ-223, REQ-225, CON-215.

On Android, install a competing implicit-intent handler, an app using the
expected package name under the wrong signing certificate, and a mutable or
replayable result capability. On Apple platforms, remove or corrupt the
associated-domain binding, offer Safari and a custom-scheme handler, and make
the Universal Link open result ambiguous. Also test the wallet-absent case on
both platforms.

The adapter never supplies ceremony material to any alternate target, web
request, clipboard/pasteboard, notification, log, crash report, or analytics
sink. It returns the closed CON-215 error, abandons the offer and both slots,
and displays only a ceremony-free install/help action. A successful later
attempt uses a different secret, request ID, ceremony ID, offer, slots,
ciphertext, enrollment evidence, and hint. No abandoned value is reused.

### TEST-231: Completion callback is non-authoritative

**Validates:** REQ-221, REQ-224, CON-215.

Capture, drop, delay, replay, reorder, and mutate all three callback outcomes
and ceremony IDs. Send `completed` before consent, after denial, for a different
application/account/ceremony, and with no pending local session. The app may
foreground only the exactly matching pending session and otherwise ignores the
object.

In every case, authorization follows only the independently retrieved bundle,
CON-206, and CON-207. A valid callback with a missing or rejected bundle never
authorizes; a lost callback with a valid bundle does not invalidate the grant.
The serialized callback has exactly three fields and contains none of the
secret or identity values prohibited by CON-215.

## Security and threat model

The threat model is normative. A happy path that succeeds outside these
boundaries is a specification defect even if its signatures verify.

### Protected assets

1. the recovery mnemonic, recovery-derived secret, application/account child
   keys, and application-account home controller;
2. the privacy boundary between applications and between accounts in one
   application, including the private `accountScopeId`;
3. the binding between the authenticated developer origin, active application
   account, target device key, requested permissions, and resulting grant;
4. the ceremony secret, offer/grant plaintexts, enrollment evidence, provider
   hint, transcript, and one-time identifiers;
5. device private keys and the authorization value of issued VCs;
6. the completeness and freshness of signed `did:crdt` authorization and
   revocation state; and
7. the integrity of consent—what authenticated application/account/device
   operation the person believes they approved.

### Trust boundaries and anchors

This profile relies on:

- platform-protected storage keeping the recovery secret and device private
  keys confidential;
- BIP-39, HKDF-SHA-512, SHA-256, Ed25519, JWS, the selected AEAD, and their
  domain separation remaining secure for their stated uses;
- the HTTPS `applicationId` origin and a backend enrollment-signing key
  authenticated through the mechanism that will close OQ-207;
- the mobile OS correctly enforcing application sandboxing, installed-app
  signing identity, explicit/verified dispatch, associated-domain routing, and
  one-shot result capabilities used by CON-215;
- the application authenticating its active account and preserving that
  account's immutable scope across normal account recovery;
- TLS authenticating the account authority and selected service endpoint, while
  end-to-end signatures and AEAD—not TLS—establish grant and DID-state truth;
- the account authority truthfully reporting the account↔DID mapping in its own
  namespace; and
- verifiers enforcing closure freshness and the complete CON-206 and CON-207
  predicates.

A production wallet does **not** trust a public profile merely because a caller
supplied it. Until OQ-207 authenticates profile discovery and platform evidence,
the embedded-profile assumption is limited to an in-process prototype and this
specification's Tier-1 gate remains closed.

The following are explicitly untrusted:

- the rendezvous operator, any state resolver, status-projection host, network
  path, browser, URL handler, and completion-callback recipient;
- every caller-supplied application name, icon, package/bundle string, link
  parameter, profile, callback value, and error description; and
- other applications and application accounts, including ones colluding with
  each other or with an infrastructure operator.

### Adversary capabilities

The adversary may:

- intercept, delay, drop, replay, reorder, duplicate, redirect, and mutate
  network messages, and may operate a selected rendezvous or state service;
- install a malicious app on the same device, register competing custom
  schemes and implicit intents, launch Selfsame with arbitrary bytes, replay a
  copied public profile, and intercept any callback the OS does not bind;
- start concurrent ceremonies and splice otherwise valid application, account,
  key, permission, provider, offer, evidence, callback, VC, proof, status, and
  DID-state values between them;
- read all public DIDs, VCs disclosed to verifiers, `acct:`/WebFinger records,
  status projections, and bounded service metadata;
- steal a VC without its device key, or steal a device key without controlling
  the home controller; and
- collude across applications, accounts, providers, and observers.

The model does not grant the adversary the ability to break the accepted
cryptography, defeat TLS endpoint authentication without a compromised trust
anchor, read another app's correctly enforced sandbox, or subvert the mobile OS
dispatch decision. Those conditions are covered as exclusions below.

### Authorization chain and MITM invariant

An accepted authorization has one unbroken, locally verified chain:

```text
authenticated application origin
          |
          | signs CON-214: app + account + device key + permission
          |                + provider + offer + nonce + expiry
          v
encrypted, transcript-bound offer
          |
          | OS handoff transports only the one-time link capability
          | rendezvous transports only opaque immutable ciphertext
          v
application-account home controller
          |
          | signs VC and did:crdt deltas
          v
encrypted, transcript-bound grant bundle
          |
          | target proves the bound device private key
          v
verifier applies CON-206 + CON-207 + fresh signed closure

completion callback ───── usability only; outside the authorization chain
```

The application ID, profile digest, account scope, device key, requested
permissions, provider descriptor, offer digest, request/ceremony IDs, expiry,
VC issuer/subject/audience/account/permissions/grant ID, DID closure, and device
challenge are each signed, encrypted-and-authenticated, or checked against a
signed value before acceptance. A man in the middle can deny service or replay
already observed bytes, but cannot change one of those values, move a result to
another application/account/device/ceremony, or make a callback authorize
without causing a named verification failure.

The invariant is two-sided: rejection occurs before the first unauthorized home
signature, delta publication, bundle write, branch-existence disclosure, or
session creation. TEST-229's exact-count scope assertions are the enforcement
mechanism.

### Security goals

- **Application/account authenticity:** a grant is issued only for the
  developer origin and active account authenticated by CON-214.
- **Device and holder binding:** only the target device key named by the
  request and VC can satisfy CON-207.
- **Ceremony integrity and anti-replay:** every request is fresh, one-time,
  transcript-bound, and unusable across application, account, provider, offer,
  or callback contexts.
- **Confidentiality:** the rendezvous, URL handlers, callbacks, and unrelated
  apps learn no offer/grant plaintext, account scope, or private key.
- **Authorization-state integrity:** only causally valid controller-signed
  deltas affect state; revocation is grow-only and stale/incomplete closure
  fails closed.
- **Pairwise privacy:** public protocol artifacts contain no default equality
  test across application accounts.
- **Consent integrity:** verified origin/account/device/permission values, not
  caller presentation metadata, determine what the person sees.
- **Fail-closed scope:** a failed check grants no authority and changes only
  the explicitly permitted replay/hold record.

### Explicit exclusions and residual risks

- A rooted/jailbroken or malicious OS, broken application sandbox, compromised
  secure storage, screen-overlay attack outside platform protections, or
  extracted recovery/home/device key is outside the v1 remote-attacker claim.
- Compromise of the developer backend, enrollment-signing key, or application
  account-authentication system lets the attacker mint apparently legitimate
  enrollment evidence for that application. The home key is still not
  derivable, and visible consent still applies, but backend recovery and key
  rotation require a separate incident specification.
- Compromise of the recovery secret compromises every derived application
  branch. Recovery-secret rotation is outside v1 and must be specified before
  production.
- A ceremony secret is a short-lived bearer capability. Disclosure may reveal
  offer/grant plaintext and enable delivery interference even though the VC
  still requires the target device key. Suspected disclosure always burns the
  ceremony under REQ-225.
- A malicious rendezvous, resolver, account authority, or network can deny
  service. This profile bounds and detects withholding; it cannot guarantee
  availability against every selected operator colluding.
- Pairwise derivation cannot prevent correlation through email, payment, IP
  address, device fingerprinting, a deliberately reused public username,
  application telemetry, or global traffic analysis.
- A malicious account authority can lie about or suppress mappings in its own
  RFC 7565 namespace, but cannot sign as the home DID or device.
- Correctly authenticated but misleading application content and a person's
  decision to approve an accurately identified request remain social/UX risks;
  the consent requirements reduce but do not eliminate them.

### Threat-to-control analysis

| Threat | Required response |
|---|---|
| Network man in the middle | TLS authenticates endpoints; CON-214 signatures, ceremony AEAD, provider/offer transcript binding, home signatures, VC audience, and device proof detect every substitution. TEST-229 mutates each field and asserts zero unauthorized side effects. |
| Malicious same-device app copies another developer's public profile | A public profile supplies no authority. The attacker lacks the origin-anchored enrollment signature and matching platform binding; CON-214 rejects before branch lookup or consent. |
| Link-handler or custom-scheme interception | CON-215 permits only verified installed-wallet dispatch and forbids browser/custom-scheme fallback. Any ambiguity burns every ceremony value under REQ-225. |
| Callback interception or forged `completed` result | Callback carries no secret or credential and is outside the authorization chain. Only a verified rendezvous bundle plus CON-206/CON-207 authorizes. |
| Concurrent application/account/ceremony mix-up | Enrollment evidence and the encrypted transcript bind exact application, profile, account scope, device key, permission, provider, offer, request ID, and ceremony ID. Cross-splices fail TEST-229. |
| Application A colludes with application B | Their public Selfsame artifacts provide no equality test; other shared account data remains outside scope. |
| Account A1 is confused with A2 in one application | The authenticated account context selects the scope and expected `acct:` alias; issuer, grant, proof, status, and state checks reject every cross-account artifact. |
| Application reuses or replaces an account scope | Atomic uniqueness and immutability checks reject reuse; missing scope fails as `AccountScopeUnavailable` rather than creating a new identity. |
| Account scope is disclosed | It may correlate that application's private account storage but cannot derive a home key without the recovery secret; rotate only through explicit identity migration. |
| Malicious rendezvous | It may withhold, replay, retain, or reorder ciphertext and observe bounded metadata; end-to-end AEAD, immutable transcript binding, expiry, and one-ceremony checks prevent forgery or authorization. |
| Malicious or withholding state resolver | It cannot forge an accepted signed closure or remove a G-Set entry; stale or incomplete state fails closed and resolver/peer diversity limits withholding. |
| Compromised application profile distribution | Production verification requires the OQ-207 origin-authenticated profile mechanism. Caller-delivered fields alone fail CON-214. |
| Stolen VC | It cannot pass CON-207 without the device private key. |
| Stolen device key | The grant remains usable until its ID appears in fresh verified CRDT state or it expires; the home controller revokes the exact grant ID. |
| Username squatting or reassignment | Authenticated atomic reservation prevents races; version 1 tombstones released names permanently. |
| Reused public username | UI warns that voluntary reuse can correlate accounts; authorization continues to use only the opaque alias. |
| Stale authorization state | Authorization fails after `maxClosureAgeSeconds`; the precise availability tradeoff blocks the gate. |
| Context host compromise | It has no verification-time effect because contexts are pinned and not fetched. |
| Algorithm confusion | Exact EdDSA allowlists, protected headers, and key-type checks reject input-selected algorithms. |
| Identifier normalization attack | Restrictive canonical application IDs and generated ASCII `acct:` localparts remove equivalent spellings; general comparison follows RFC 3986/RFC 7565. |
| Status-projection correlation | Projection is optional; random indexes, aggregation, stapling, caching, and proxying reduce but do not eliminate observation. |

## `did:crdt` compatibility boundary

At a high level this hierarchy conforms to the current `did:crdt` method. The
application and account nodes exist wholly above the DID method. For each
account, CON-202 supplies one ordinary Ed25519 public key to `did:crdt`
genesis; the method sees neither `applicationId` nor `accountScopeId`. Distinct
account keys therefore create ordinary independent DIDs, while the method's
self-certifying identifier and signed-closure rules remain unchanged.

The implementation inspected at `did-crdt` commit `adb5c7a` supports the other
structural requirements. A root-authorized `SetDocumentData` operation can
store `alsoKnownAs`, and its resolver flattens document data into the top-level
DID Document. It also implements
`DeltaOp::RevokeCredential { credential_id: String }`, stores credential IDs
in a grow-only set, merges that set by union, and exposes
`Document::is_revoked`. CON-203's two-stage alias construction and CON-210's
authoritative revocation path therefore fit the existing state model without
changing DID derivation or adding a new method operation.

The present implementation does **not** yet satisfy the VC-JOSE issuer-key
profile in this specification:

1. its default genesis relationship is `authentication`, while CON-203 and
   CON-205 require the issuer key in `assertionMethod`; and
2. its resolver emits `Ed25519VerificationKey2020` with
   `publicKeyMultibase`, while the VC JOSE/COSE controlled-identifier profile
   used here requires `type: JsonWebKey` with `publicKeyJwk`.

Before implementation, the pinned `did:crdt` method and resolver MUST define a
deterministic `#jwk-0` representation of the same Ed25519 root key and a
normative way to place that key in `assertionMethod`. The change MUST NOT
reinterpret or recompute existing DID identifiers: the present method commits
to the exact serialized genesis tuple, including its existing public-key
encoding. A representation-only resolver projection or an explicitly
versioned/authorized relationship operation is acceptable if it preserves that
invariant and passes TEST-224.

Consequently, the application/account derivation model is compatible at the
DID-method boundary and credential revocation needs no method amendment. The
complete VC grant profile is not conforming until the small upstream
relationship/resolver amendment above lands.

## Tier-1 Gate

No implementation task may be marked ready until all boxes are checked:

- [ ] A fresh-context cross-model adversarial review covers KDF separation,
      DID/VC key representation, holder binding, alias equivalence, provider
      selection, revocation, application authentication, network MITM,
      same-device app substitution, ceremony mix-up, callback hijack,
      normalization, and privacy.
- [ ] A second review verifies the revised document and closes every blocking
      finding from the first.
- [ ] A human cryptography/security reviewer approves CON-202, CON-205,
      CON-206, CON-207, CON-210, CON-211, CON-212, and CON-213.
- [ ] Mobile platform security reviewers approve CON-214 and CON-215, including
      the exact Android and Apple target/caller identity checks and the
      fail-without-web-fallback behavior.
- [ ] Two independent implementations reproduce the normative KDF and wire
      vectors required by NFR-202.
- [ ] The `did:crdt` method explicitly defines the `JsonWebKey` projection and
      `assertionMethod` relationship without changing existing DID derivation.
- [ ] The Selfsame JSON-LD context has an owned durable URL, immutable content,
      published digest, and archival policy.
- [ ] A privacy review covers `acct:` harvesting, WebFinger, state lookups,
      optional username reuse, CRDT revocation enumeration, projection
      retrieval, account-scope storage, provider and browser-Origin metadata,
      mobile handoff/callback metadata, and cross-application and cross-account
      correlation.
- [ ] OQ-201, OQ-202, and OQ-204 through OQ-207 are either resolved
      normatively or explicitly accepted by the human owner with bounded
      consequences. OQ-203 is resolved by ADR-210.
- [ ] SPEC-001 is explicitly amended or profiles this document without
      contradictory credential and derivation claims.
- [ ] PROTO-002 passes its own Tier-1 gate and two independent providers pass
      both its black-box suite and TEST-226 without Anuna infrastructure.
- [ ] TEST-227 through TEST-231 pass against real Android and Apple platform
      adapters with hostile sibling apps and alternate link handlers installed.
- [ ] Human security sign-off records an approval version and commit.

## Open questions

### OQ-201: How stale may authorization state be? — blocking

The profile names `maxClosureAgeSeconds`, `propagationSlaSeconds`, and optional
projection `maxAgeSeconds`, but no values have been approved. Short windows
improve revocation and harm offline availability; long windows do the reverse.
The decision must define when a closure is causally complete enough for
authorization, how long resolvers may lag a submitted revocation, and what
generic consumers may infer from a projection. Selfsame authorization always
fails closed beyond the closure bound.

Owner: HOC + application security owner.

### OQ-202: Who owns the durable VC vocabulary? — blocking

`https://selfsame.dev/credentials/device-grant/v1` is provisional. Before use,
the project must prove control of a durable origin, publish the exact context,
pin its digest, and define what happens if the project or domain changes hands.

Owner: Anuna Research.

### OQ-203: Multiple accounts in one application — RESOLVED by ADR-210

Version 1 derives a private child below the application node from a random,
stable `accountScopeId` bound to the authenticated application account. Each
child has an independent home DID and all dependent artifacts. The
application's ordinary account context supplies the scope; there is no
Selfsame account-selection setting.

REQ-216, REQ-217, CON-202, CON-211, TEST-222, and TEST-223 define the
separation, lifecycle, grammar, recovery, and failure behavior. The accepted
tradeoff is fundamental: the mnemonic and application ID alone cannot select
one of several children, so normal application-account recovery or protected
Selfsame metadata backup must restore the opaque scope. Missing scope fails
closed instead of guessing or silently creating another identity.

Owner: application-profile working group.

### OQ-204: Application ID migration — blocking for mutable deployments

Domain loss, acquisition, or application merger may require a new
`applicationId`. Version 1 correctly treats that as a new identity. A future
migration must be explicit, signed by each affected old and new
application-account home and the developer trust roots, visible to the person,
and resistant to silent cross-application correlation.

Owner: application-profile working group.

### OQ-205: Exact discovery carrier

CON-209 fixes the provider hint's authenticated semantics but leaves its
carrier to the link-ceremony specification. SPEC-001 ADR-014's secret-derived
discovery record is the current candidate. Its public-DHT metadata and
anti-abuse properties require review before it becomes this profile's mandatory
carrier.

PROTO-002 does not resolve this bootstrapping question: it begins once a client
has the authenticated descriptor and ceremony secret, then completely defines
how that client uses the selected mailbox.

Owner: SPEC-001 maintainer.

### OQ-206: Migration of the existing SPEC-001 identity — blocking for existing users

CON-202 intentionally does not reproduce SPEC-001's current
`anuna-ssi/v1/root-key/<persona>` derivation. An existing CBCL identity therefore
cannot silently become the new application-account-scoped home DID.

The migration needs a separately reviewed transition in which the incumbent
SPEC-001 DID authorizes each new CBCL application-account home DID, verifiers
accept a bounded overlap, and no other application learns the legacy global
DID. Until that transition exists, this profile is suitable only for new
application identities or explicit test migrations.

Owner: SPEC-001 maintainer + HOC.

### OQ-207: Exact profile-origin and mobile-platform evidence — blocking

CON-214 and CON-215 now fix the security shape: an origin-authenticated,
backend-signed, short-lived enrollment statement; exact
application/account/device/permission/provider/offer binding; platform
caller/target evidence; and verified-origin consent. A copied public profile,
custom scheme, display label, callback, or TLS session alone is explicitly
insufficient.

The remaining work is deliberately narrow but still blocks production:

1. specify the HTTPS `applicationId`-origin profile discovery, media type,
   cache, signature, key rotation/revocation, redirect, and offline rules so the
   wallet never trusts a key obtained only from its caller;
2. fix the Android minimum API and exact checks for explicit wallet targeting,
   calling package/UID sharing, signing-certificate rotation, verified App
   Links, and immutable one-shot return capabilities;
3. fix the Apple Team-ID/bundle-ID and associated-domain validation, the
   Selfsame Universal Link invocation origin, `universalLinksOnly` failure
   behavior, and the claimed HTTPS return path;
4. decide how multiple independently implemented conforming wallet apps are
   discovered and selected without a user-managed endpoint or an Anuna-only
   package allowlist; and
5. publish cross-platform canonical JWS, profile, handoff, MITM, replay,
   application-substitution, and callback-hijack vectors.

The Android candidate is an explicit component/result flow whose installed
signing identity is checked against the authenticated profile; Android verified
App Links may carry a non-secret return. The Apple candidate is a Universal
Link opened only when an associated installed Selfsame app can handle it, with
an associated HTTPS return to the developer app. On both platforms the
backend-signed CON-214 evidence remains mandatory: link routing authenticates a
target or return association, not the whole application-account request.

Private-use/custom schemes, clipboard/pasteboard transfer, generic intents,
embedded browser fallbacks, and a credential in a callback are not candidates.
Until all five items are normative and TEST-227 through TEST-231 pass on real
platforms, the profile-authenticity assumption is limited to an in-process
prototype and a wallet service must not accept arbitrary application requests.

Owner: Selfsame wallet + application-profile working group + mobile platform
reviewers.

## Traceability

| User outcome | Requirements | Contracts | Tests |
|---|---|---|---|
| Different home identity per application account | REQ-201, REQ-202, REQ-213 | CON-201, CON-202, CON-211 | TEST-201–203, TEST-219, TEST-222, TEST-223 |
| Multiple accounts switch without Selfsame configuration | REQ-216, REQ-217 | CON-202, CON-211 | TEST-222, TEST-223 |
| RFC 7565 stable alias and optional username | REQ-203, REQ-204, REQ-218 | CON-203, CON-204, CON-212 | TEST-204–206, TEST-225 |
| Portable VC device grant | REQ-205–208, REQ-211 | CON-205–210 | TEST-207–213, TEST-217 |
| Controller-owned convergent revocation | REQ-207, REQ-208 | CON-205, CON-206, CON-210 | TEST-211–213, TEST-224 |
| No user endpoint configuration | REQ-209, REQ-212, REQ-219 | CON-208, CON-209, CON-213 | TEST-214, TEST-215, TEST-218, TEST-226 |
| No mandatory Anuna infrastructure | REQ-210, REQ-214, REQ-219 | CON-201, CON-208, CON-213 | TEST-216, TEST-220, TEST-226 |
| Replaceable, loss-tolerant blind rendezvous | REQ-209, REQ-212, REQ-219; PROTO-002 REQ-301–308 | CON-208, CON-209, CON-213; PROTO-002 CON-301–308 | TEST-214–216, TEST-218, TEST-220, TEST-226; PROTO-002 TEST-301–310 |
| MITM-resistant same-device mobile authorization without self-scan | REQ-220–225 | CON-206, CON-207, CON-209, CON-214, CON-215 | TEST-227–231 |
| Cross-application and cross-account privacy | REQ-201, REQ-203, REQ-213, REQ-215–218 | CON-202–205, CON-211, CON-212 | TEST-201, TEST-204–206, TEST-219, TEST-221–223, TEST-225 |
| Compatibility with the `did:crdt` method boundary | REQ-201, REQ-203, REQ-205, REQ-208 | CON-202, CON-203, CON-210 | TEST-207, TEST-213, TEST-224 |

## Amendment Channels

This specification may be amended only by a versioned change to this file that:

1. identifies affected REQ/NFR/ADR/CON/TEST artefacts;
2. updates traceability and the changelog;
3. records the reason and evidence;
4. receives the reviews required by the risk tier; and
5. is approved by the human owner.

Chat instructions, implementation drift, passing tests, issue comments, and
provider behavior are evidence or amendment requests; none changes this
contract by itself.

Any change to application-ID or account-scope canonicalization, account-scope
lifecycle, key derivation, DID construction, JWK representation, accepted
algorithms, signed bytes, holder proof, closure/projection freshness,
revocation semantics, alias comparison, rendezvous eligibility, provider-hint
binding, application enrollment evidence, mobile caller/wallet identity,
same-device dispatch, callback authority, threat-model boundary, or the
PROTO-002 version is a Tier-1 normative amendment and requires new vectors plus
renewed security sign-off.

## Normative and informative sources

Normative internal protocol:

- [[PROTO-002-selfsame-rendezvous-v1]] defines the wire and operator contract
  named by `selfsame-rendezvous-v1`.

Normative external specifications:

- W3C, [Verifiable Credentials Data Model
  2.0](https://www.w3.org/TR/vc-data-model-2.0/), Recommendation,
  15 May 2025.
- W3C, [Securing Verifiable Credentials using JOSE and
  COSE](https://www.w3.org/TR/vc-jose-cose/), Recommendation,
  15 May 2025.
- W3C, [Decentralized Identifiers (DIDs)
  v1.0](https://www.w3.org/TR/did-core/), especially `alsoKnownAs`.
- W3C, [Bitstring Status List
  v1.0](https://www.w3.org/TR/vc-bitstring-status-list/), normative only when
  the optional projection is enabled.
- IETF, [RFC 7565 — The `acct` URI
  Scheme](https://datatracker.ietf.org/doc/html/rfc7565).
- IETF, [RFC 7033 — WebFinger](https://datatracker.ietf.org/doc/html/rfc7033).
- IETF, RFC 3986, RFC 4648, RFC 5234, RFC 5869, RFC 7515, RFC 8032,
  RFC 8785, and BIP-39.

Informative mobile security and interoperability sources:

- IETF, [RFC 8252 — OAuth 2.0 for Native
  Apps](https://datatracker.ietf.org/doc/html/rfc8252), especially claimed
  HTTPS redirects, exact redirect matching, public-client secrets, and
  inter-app interception.
- Android Developers, [About Android App
  Links](https://developer.android.com/training/app-links/about),
  [Pending intents security](https://developer.android.com/privacy-and-security/risks/pending-intent),
  and
  [AppAuthenticator](https://developer.android.com/reference/androidx/security/app/authenticator/AppAuthenticator).
- Apple Developer, [Supporting associated
  domains](https://developer.apple.com/documentation/Xcode/supporting-associated-domains),
  [Allowing apps and websites to link to your
  content](https://developer.apple.com/documentation/xcode/allowing-apps-and-websites-to-link-to-your-content/),
  and
  [`universalLinksOnly`](https://developer.apple.com/documentation/uikit/uiapplication/openexternalurloptionskey/universallinksonly).
- OpenID Foundation, [OpenID for Verifiable Presentations
  1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html),
  used only as an informative precedent for same-device invocation,
  nonce/audience binding, replay, and session-mix-up analysis. SPEC-004 does
  not claim OpenID4VP conformance.

Standards constraints that are easy to miss:

- RFC 7565 identifies an account at a provider; it does not define how to
  interact with or dereference that account.
- RFC 7565 comparison uses RFC 3986 case and percent-encoding normalization.
- DID Core `alsoKnownAs` is an assertion, not proof of equivalence; reciprocal
  or independent verification is recommended.
- VC Data Model 2.0 is not a complete authorization framework; CON-206 and
  CON-207 supply the missing application policy and holder proof.
- VC JOSE/COSE requires `kid` when a key is expressed as a DID URL and requires
  `JsonWebKey`/`publicKeyJwk` for controlled identifier documents.
- Bitstring Status List requires at least 131,072 bits and can itself create
  correlation through status identifiers and retrieval behavior; in this
  profile it is a derivative projection, never the Selfsame source of truth.
- Android App Links and Apple Universal Links bind an HTTPS origin to an
  installed app/route; neither authenticates the complete application-account
  enrollment statement, so CON-214 remains independently required.
- An immutable Android `PendingIntent` prevents field injection and a one-shot
  capability prevents replay; an implicit or mutable capability is not
  equivalent.
- Apple's `universalLinksOnly` option makes absence of an associated installed
  app a dispatch failure. Opening the same URL with ordinary web fallback would
  disclose the link capability outside the permitted handoff boundary.
- RFC 8252 warns that public native clients cannot keep distributed secrets and
  that private-use schemes can be claimed by another app. SPEC-004 therefore
  uses no app-embedded authenticator and gives a custom scheme no authority.

The informative
[functional prior-art survey](../docs/selfsame-functional-prior-art.md)
compares CardSpace, SLIP-0013, OIDC pairwise subjects, passkeys, Fission ODD,
re:claimID, peer DIDs/DIDComm, UCAN, DWNs, and AnonCreds. It found substantial
component precedents but no surveyed system with the complete Selfsame
combination; that is an engineering conclusion, not a legal novelty claim.

## Changelog

- **0.5.0 — 2026-07-30 — draft, normative.** Adds the same-device mobile path
  for a developer app and Selfsame wallet installed on one phone. The OS
  handoff replaces self-scanning but deliberately reuses the existing
  transcript, rendezvous offer/bundle, verifier predicate, and separate
  `did:crdt` state-publication path. Defines layered, origin-signed application
  enrollment evidence; verified wallet dispatch; a non-authoritative callback;
  fresh-ceremony failure semantics; and Android/Apple conformance boundaries.
  Replaces the former threat table with an explicit protected-asset,
  trust-boundary, adversary-capability, authorization-chain, MITM-invariant,
  security-goal, exclusion, residual-risk, and threat-to-control model. Adds
  REQ-220–225, ADR-213–214, CON-214–215, and TEST-227–231; narrows OQ-207 to
  the exact profile-origin/platform evidence; and updates CON-201, the
  Orientation controls, happy paths, Tier-1 gate, traceability, amendment
  channels, and sources.
- **0.4.1 — 2026-07-30 — documentation-only.** Renumbers this document as
  [[SPEC-004-application-scoped-identity]] after
  [[SPEC-003-android-apk-distribution]] was allocated on `main`, and retargets
  its inbound and self-links. No normative behavior changed.
- **0.4.0 — 2026-07-30 — draft.** Binds every
  `selfsame-rendezvous-v1` descriptor to the independent PROTO-002 mailbox
  contract. Makes capability conformance—not operator identity—the eligibility
  boundary; requires fresh ceremony material on provider failover; separates
  mailbox and `did:crdt` state roles; adds black-box third-party and failover
  tests; and records that the current 4 KiB, destructive-read reference server
  is not yet conforming. Adds REQ-219, ADR-212, CON-213, and TEST-226; affects
  REQ-209, REQ-210, REQ-212, REQ-214, NFR-202, NFR-205, CON-201, CON-208,
  CON-209, TEST-214, TEST-220, the trust boundary, Tier-1 gate, traceability,
  and OQ-205.
- **0.3.0 — 2026-07-30 — draft.** Makes the existing signed `did:crdt`
  `RevokeCredential` G-Set the authoritative grant-revocation state and moves
  W3C Bitstring Status List to an optional, home-signed projection. Adds random
  DID-URL grant IDs, causal/freshness acceptance rules, convergence and
  propagation tests, and records that no new method revocation operation is
  required. Specifies one optional RFC 7565 human-readable username per
  application account, including grammar, reciprocal publication, rename,
  removal, permanent tombstoning, privacy warning, and strict separation from
  derivation and authorization. Affects REQ-203, REQ-204, REQ-207, REQ-208,
  REQ-210, REQ-213, REQ-214, REQ-216–218, NFR-201, NFR-203, NFR-205,
  NFR-206, ADR-203, ADR-208, ADR-211, CON-201, CON-205, CON-206, CON-210,
  CON-212, and TEST-205, TEST-206, TEST-211–213, TEST-220, TEST-222,
  TEST-224, TEST-225.
- **0.2.0 — 2026-07-30 — draft.** Resolves OQ-203 with one private random
  account-scope child and one home DID per application account. Specifies
  automatic selection through the application's authenticated account context,
  scope grammar and recovery, cross-account key/grant isolation, new
  conformance tests, and the high-level `did:crdt` compatibility boundary.
  Records the remaining upstream requirements for `assertionMethod` and the
  VC-JOSE `JsonWebKey` resolver representation. Affects REQ-201, REQ-203–208,
  REQ-213–217, NFR-201–203, ADR-201–203, ADR-205, ADR-210, CON-201–211, and
  TEST-201–224.
- **0.1.0 — 2026-07-30 — draft.** First application-neutral specification.
  Defines per-application deterministic home keys, RFC 7565 `acct:` aliases
  with reciprocal WebFinger binding, W3C VC 2.0 JOSE device grants, explicit
  holder proof and authorization validation, provider-profile rendezvous
  selection, portable status, developer requirements, and a Tier-1 no-go gate.
