---
id: SPEC-004
title: Application- and Account-Scoped Identity — deterministic home keys, acct aliases, portable device grants, and provider discovery
status: draft
tier: 1
version: 0.16.0-draft
audience: agent, human, application developer, infrastructure provider
author: Anuna Research (drafted with Codex, 2026-07-30; amended with Claude, 2026-07-31; hierarchy re-rooted with Claude, 2026-08-10)
last-updated: 2026-08-21
owner-repo: selfsame
affects-repos: selfsame, anuna-ssi, did-crdt, adopting applications
prototype-authorised: 2026-08-10 by the repository owner for hierarchy version 2; widened 2026-08-13 to cover the contracts SPEC-053 adopts — see Tier-1 Gate
review-gate: not-approved — Tier-1; all unsuperseded ADRs are PROPOSED; cross-model adversarial review, independent KDF and cbcl-pairing vectors, privacy review, and human cryptography/security sign-off are outstanding. **0.15.0 remains `-draft` because it does not yet satisfy this document's production gate.** It is a proposal for review, not an accepted production version, and the accepted version does not advance until those gates land
depends-on: did:crdt Method Specification; SPEC-007 cbcl-pairing Protocol Cutover for Selfsame credential pairing; cbcl-pairing SPEC-001; PROTO-002 Selfsame Rendezvous Protocol v1 for non-cutover uses; PROTO-003 Selfsame Pairing Protocol v1 as a legacy rejection source; PROTO-004 Selfsame Ceremony Envelope v1 for non-cutover uses; W3C VC Data Model 2.0; W3C VC JOSE/COSE; W3C DID Core 1.0; optional W3C Bitstring Status List 1.0 projection; RFC 7565; RFC 7033; RFC 3986; RFC 4648; RFC 5234; RFC 5869; RFC 7515; RFC 8032; RFC 8439; RFC 8785; RFC 9382; RFC 9496
---

# SPEC-004 — Application- and Account-Scoped Identity

## SPEC-007 pairing cutover disposition

For Selfsame credential pairing, [[SPEC-007-cbcl-pairing-cutover]] supersedes
the following artifacts only to the extent listed in its Amendment disposition table:

- REQ-209 through REQ-212, REQ-219, and REQ-226 through REQ-229;
- ADR-215 through ADR-218;
- CON-216 through CON-219; and
- TEST-226 and TEST-232 through TEST-235.

CON-206 remains the credential-acceptance authority.
CON-219 retains its member sets and narrows its cbcl payload bound to 62,000 octets.
Unrelated identity, credential, revocation, recovery, and protocol duties remain unchanged.
All 25 Tier-1 production rows remain open through the exact SPEC-007 disposition.
Vectors: TEST-818 covers the new cbcl payload bound; unrelated identity vectors are unchanged.

Evidence: [[SPEC-007-cbcl-pairing-cutover#TEST-819]] and the
[[SPEC-007-cbcl-pairing-cutover#Inherited SPEC-004 Tier-1 gate ledger]].
Owner: Selfsame human repository owner.
Approved for development: 2026-08-17.
Production approval: not granted.

## Orientation

**Intent.** One Selfsame recovery secret SHALL work across unrelated developer
applications without making those applications share a public identity, a home
key, or an infrastructure operator. Each account within an application receives
a deterministic, unlinkable home DID below that application's private
hierarchy. That DID names the application account with an RFC 7565 `acct:` URI
and issues a W3C Verifiable Credential that grants a particular device narrowly
scoped access to that account in that application.

**User promise.** A person who uses Selfsame in application A and application B
SHALL scan, consent, and continue. The cross-device fallback is the
application's authenticated identity plus a short
twelve-word code; the same-device path requires no scan or typing.
They SHALL NOT select a rendezvous server, copy endpoints, import a second
recovery phrase, or edit a configuration file. Application A and application B
SHALL nevertheless see different home keys, different DIDs, different account
aliases, different grants, independently operated providers, and
application-bound pairing transcripts. If one application supports two
signed-in accounts, its ordinary account switcher SHALL select the
corresponding Selfsame identity without asking the person for a derivation
index or Selfsame setting. The person MAY separately opt into one public,
human-readable username for an account; it is never required to link, restore,
or authorize a device.

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
         hierarchy_root (ADR-223)  ← sealed; what a wallet holds
              a sibling of SPEC-001's persona root, not its child
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
authentication before the wallet uses an application-account branch ·
[[SPEC-004-application-scoped-identity#ADR-215]] replace the long direct-secret
manual code with SPAKE2, superseded by
[[PROTO-003-selfsame-pairing-v1#ADR-406]] ·
[[SPEC-004-application-scoped-identity#ADR-216]] separate application/provider
routing from the human PAKE password, partially superseded by
[[PROTO-003-selfsame-pairing-v1#ADR-407]] ·
[[SPEC-004-application-scoped-identity#ADR-217]] compose the confirmed PAKE key
with the existing blind mailbox ·
[[SPEC-004-application-scoped-identity#ADR-219]] bind state transport to
`did:crdt` and let the application be its own replica ·
[[SPEC-004-application-scoped-identity#ADR-218]] own the ceremony envelope in a
protocol and its payload here ·
[[SPEC-004-application-scoped-identity#ADR-220]] confirm the issuer at first
enrollment rather than authenticate the wallet ·
[[SPEC-004-application-scoped-identity#ADR-221]] name the credential vocabulary
from a controlled origin and make its digest the authority ·
[[SPEC-004-application-scoped-identity#ADR-222]] succeed an application
identifier with a doubly signed, unpublished statement ·
[[SPEC-004-application-scoped-identity#ADR-223]] root the hierarchy at its own
sibling of the SPEC-001 persona root, so a wallet that seals only that root can
derive without the recovery phrase ·
[[SPEC-004-application-scoped-identity#ADR-224]] let a web-only application
declare the manual cross-device path as its platform binding instead of
renting an unverifiable native one.

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
[[SPEC-004-application-scoped-identity#REQ-226]] every human code uses
SPAKE2 with mutual confirmation ·
[[SPEC-004-application-scoped-identity#REQ-227]] many applications and
providers route without a global directory or user endpoint configuration ·
[[SPEC-004-application-scoped-identity#REQ-228]] the pairing provider remains a
blind relay, not a PAKE endpoint ·
[[SPEC-004-application-scoped-identity#REQ-229]] one failed pairing attempt
burns the complete ceremony ·
[[SPEC-004-application-scoped-identity#REQ-230]] an account's first issuer is
confirmed, not trusted ·
[[SPEC-004-application-scoped-identity#REQ-231]] identity succession is
explicit, bounded, and confirmed ·
[[SPEC-004-application-scoped-identity#NFR-201]] application identities are
pairwise unlinkable from their public data ·
[[SPEC-004-application-scoped-identity#NFR-205]] all authorization checks fail
closed.

**Blocking before implementation.** Every open question now has a normative
resolution; what blocks is review, ratification, and evidence, all of it in the
Tier-1 gate in [[SPEC-004-application-scoped-identity#Tier-1 Gate]]. The
outstanding items are human ratification of the
[[SPEC-004-application-scoped-identity#OQ-201]] freshness values; the
operational duties on the
[[SPEC-004-application-scoped-identity#OQ-202]] context origin; mobile platform
review of [[SPEC-004-application-scoped-identity#CON-220]] through
[[SPEC-004-application-scoped-identity#CON-223]]; security review of
[[SPEC-004-application-scoped-identity#CON-221]] and
[[SPEC-004-application-scoped-identity#CON-225]]; publication of the
[[SPEC-004-application-scoped-identity#CON-226]] corpus with two independent
stacks agreeing on it; two upstream `did:crdt` items — the `JsonWebKey`
projection and whether verification relationships gate delta authorization;
and reconciling SPEC-001 with this document.

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
  projection can aid generic VC consumers but never overrides CRDT state. A set
  projection bit is true at any age; an unset one past `validUntil` means
  unavailable, never not-revoked.
- Closure freshness has two tiers: establishing a session uses
  `min(maxClosureAgeSeconds, propagationSlaSeconds)` and prefers an
  independently resolved closure; continuing one uses `maxClosureAgeSeconds`.
- The credential context is authoritative as bytes and a digest. Nothing
  dereferences its IRI, and the naming origin is not a trust anchor.
- An account's home DID changes only through an explicit, doubly signed,
  person-confirmed, expiring succession that is never published.
- Compact grants are at most 64 KiB and use only the EdDSA profile.
- Proof nonces are single-use and expire within 120 seconds.
- Rendezvous probes have a per-endpoint deadline of at most 1500 ms.
- Only providers passing
  [[PROTO-003-selfsame-pairing-v1#CON-401]] and
  [[PROTO-002-selfsame-rendezvous-v1#CON-301]] are eligible; the PAKE relay and
  encrypted mailbox then follow their separate bounded contracts.
- Every ceremony record is sealed by
  [[PROTO-004-selfsame-ceremony-envelope-v1#CON-502]] under a role-separated
  key that seals exactly one plaintext. The payload member sets are closed and
  live in [[SPEC-004-application-scoped-identity#CON-219]].
- `offerDigest` is computed over `offer_core` — the offer payload without the
  enrollment evidence and provider hint that carry it — so nothing commits to
  a digest of itself.
- A stable `acct:` alias is named deterministically by the home controller and
  becomes usable only once its authority record and reciprocal JRD exist; the
  gate is verification, not issuance order.
- The canonical human code is twelve BIP-39 English words rendering a 128-bit
  value `C`, used only by end-to-end SPAKE2 with explicit confirmation and as
  the seed for the [[PROTO-003-selfsame-pairing-v1#CON-409]] meeting-point
  address.
- Application context is resolved from a signed, ephemeral record at that
  address, not carried by the code. A code that resolves no record is never
  broadcast to candidate applications or providers.
- A person is asked for the application's origin only as CON-409 tier 3, after
  every other transport has failed. It is a lookup key, never an authorization
  input: the canonical `applicationId` still comes from the fetched profile.
- Records resolve through a three-tier ladder — relays already authenticated
  from a profile, a public distributed hash table, then the person supplying the
  application's origin. Selfsame ships no relay and Anuna operates none.
- `did:crdt` deltas are published to every declared state resolver, including
  the application's own node where it declares one. Delivery is best-effort and
  never evidence; only a re-resolved verified closure confirms a revocation.
- Either party may generate and display the code; the application always
  selects the provider, publishes the record, and is SPAKE2 role A.
- A same-device pairing bootstrap is delivered only to an installed,
  platform-verified Selfsame wallet target; no browser or unverified custom
  scheme receives it.
- Selfsame does not disclose branch existence, derive an existing branch, sign,
  publish, or write a grant until application enrollment evidence, the offer
  transcript, and available platform identity all agree.
  [[SPEC-004-application-scoped-identity#CON-214]] owns that agreement — its
  statement's `platformBindingId` must select a binding the authenticated
  profile declares, and the OS-observed caller must satisfy that binding's own
  contract ([[SPEC-004-application-scoped-identity#CON-222]] Android,
  [[SPEC-004-application-scoped-identity#CON-223]] Apple,
  [[SPEC-004-application-scoped-identity#CON-227]] web manual); any
  disagreement — including an OS-attributed caller against a web binding — is
  `PlatformBindingMismatch`.
- A mobile completion callback is advisory and contains no grant, DID, account
  scope, key, pairing bootstrap/code, provider secret, or verifier acceptance
  decision.
- Ambiguous or failed delivery, peer claim, SPAKE2 frame, or confirmation
  permanently abandons that ceremony; retry starts with a fresh code,
  meeting-point address, nameplate, role tokens, ephemerals, derived mailbox
  secret, offer, slots, and ciphertext.

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

[[SPEC-001-device-key-provisioning]] is deliberately an unresolved link. That
document is not present in this vault, and per the dead-link discipline it is
recorded here as visible debt rather than deleted to quiet the report: it is
required by the Tier-1 gate item covering SPEC-001 amendment and by
[[PROTO-004-selfsame-ceremony-envelope-v1#OQ-501]]. Locating or reconstructing
it is owned by the SPEC-001 maintainer and blocks those items, not this
document's other content.

It is no longer required by
[[SPEC-004-application-scoped-identity#OQ-206]], which is withdrawn: no person
holds a SPEC-001 identity, so no migration exists to specify. What remains is
reconciling two documents that describe the same codebase, not rescuing a
population.

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
- the ceremony offer and grant bundle payloads carried by the sealed envelope;
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
   authority and publishes the reciprocal WebFinger binding. Because the SDK is
   in process here, this happens before issuance — the preferred order in
   [[SPEC-004-application-scoped-identity#CON-204]].
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
   creates the target device key, offer, and CON-214 evidence, then filters and
   probes the pairing-capable rendezvous providers in its embedded profile.
2. Either party generates the sixteen-octet code `C`; if the wallet generated
   it, the person carries it to the application first. The application selects
   one descriptor, asks its PROTO-003 service for a provider-local nameplate,
   computes a fresh SPAKE2 role-A ephemeral, writes `pA`, and publishes the
   [[PROTO-003-selfsame-pairing-v1#CON-409]] record naming its application ID,
   profile digest, provider, and nameplate.
3. The other party receives `C` by QR, by twelve spoken or typed words, or by
   OS handoff. The wallet derives the meeting-point address from `C`, resolves
   and verifies the record, fetches the profile from its claimed canonical
   origin, and requires the profile digest to match. It displays that claimed
   target/origin and requires explicit pairing-target approval before claiming
   a nameplate or running SPAKE2 as role B through the selected blind relay.
   This approval authenticates neither the application nor an account and never
   grants authority. The wallet never runs an independent provider election. On
   the normal path it is never asked for an application identity; only if every
   [[PROTO-003-selfsame-pairing-v1#CON-409]] transport tier fails does it fall
   back to asking the person for the application's origin.
4. After both sides verify explicit confirmation MACs, they derive the
   128-bit PROTO-002 mailbox secret from the PAKE key. The application writes
   the encrypted offer and the wallet reads it.
5. The wallet verifies the application enrollment evidence and offer, shows
   authenticated-origin consent, creates a random grant ID, and issues the
   device grant naming the deterministic `acct:` alias.
6. The ceremony carries the VC as opaque `application/vc+jwt` bytes in the
   sealed bundle payload defined by
   [[SPEC-004-application-scoped-identity#CON-219]].
7. The application recomputes the expected alias from the grant's `issuer`,
   provisions it at its account authority, and publishes the reciprocal
   WebFinger binding. This is the remote-controller order in
   [[SPEC-004-application-scoped-identity#CON-204]]; until it completes, the
   grant exists but no verifier accepts it.
8. The joining device proves possession of the `cnf` private key to the
   application verifier.

### User authorizes an application on the same phone

This is the path where the developer application receiving the grant and the
Selfsame wallet holding the home controller are separate apps on one mobile
device. It is not selected merely because Selfsame is installed: authorizing a
laptop or other remote target continues to use the cross-device path above.

1. The developer application authenticates its active account, creates a fresh
   application-account-scoped device key, selects a pairing-capable
   rendezvous descriptor, constructs the ordinary offer and application
   enrollment evidence in CON-214, allocates the PROTO-003 nameplate, and
   writes its SPAKE2 `pA`.
2. Instead of displaying the QR, its Selfsame SDK passes the logical PROTO-003
   bootstrap to the installed Selfsame wallet through the platform adapter in
   CON-215. The adapter either reaches the verified wallet app or returns
   `WalletUnavailable`; it never sends ceremony material to a browser,
   clipboard, generic intent, unverified URL-scheme handler, install page,
   analytics event, or notification.
3. The two apps run the same end-to-end SPAKE2 exchange used cross-device,
   through the selected provider. The provider is not a SPAKE2 endpoint.
   After mutual confirmation, both derive the ordinary mailbox secret; the
   developer app writes the encrypted offer and begins polling the bundle.
4. Selfsame reads and authenticates the same encrypted offer used by the
   cross-device flow. Before showing consent, it verifies the application
   origin and enrollment evidence, the active application/account/device/offer
   bindings, expiry and one-time nonce, and every platform identity signal the
   adapter can securely provide.
5. The consent screen names the authenticated application origin and account
   operation, the target device, and the exact requested permissions. A label
   supplied only by the calling app is never presented as verified identity.
6. On approval, Selfsame derives or selects the application-account home,
   issues the device VC, publishes signed `did:crdt` state through the
   separately selected state service, and writes the encrypted grant to the
   existing rendezvous bundle slot. No DID delta is written to a rendezvous
   mailbox slot.
7. The developer application receives the bundle through its already-running
   mailbox poll, recognizes it under
   [[PROTO-004-selfsame-ceremony-envelope-v1#CON-503]], provisions the
   recomputed `acct:` alias under
   [[SPEC-004-application-scoped-identity#CON-204]], verifies the grant, and
   then proves possession of the device key. An optional OS callback merely
   foregrounds that pending application session; it carries no credential or
   authority and cannot make a failed bundle pass.
8. If secure wallet invocation is unavailable, ambiguous, intercepted, or
   falls back toward the web, both apps abandon the ceremony. An install/help
   action contains no ceremony material, and a later retry creates fresh
   code, address, nameplate, tokens, SPAKE2 ephemerals, mailbox secret, offer,
   slots,
   ciphertext, enrollment nonce, and evidence.

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

A restored installation holds the twelve recovery words and nothing else. From
them it re-derives the hierarchy root
([[SPEC-004-application-scoped-identity#CON-202]]), which is what the custodian
seals and what version 1 of this hierarchy could not reach — see
[[SPEC-004-application-scoped-identity#ADR-223]]. With the same canonical
`applicationId` it reaches the same private application node.

To recover a particular account home it also requires that account's exact
`accountScopeId`, restored automatically from the authenticated application
account record or protected Selfsame backup as specified by
[[SPEC-004-application-scoped-identity#REQ-217]]. Those inputs reproduce the
same account node, home seed, DID, and `acct:` URI. Provider endpoint changes do
not change identity.

**An application whose only account credential is the Selfsame identity cannot
authenticate that request**, because a wallet that has just restored holds no
key yet. Version 1 does not solve that case: `REQ-217`'s carrier is the
authenticated account record, and an application without an independent login
has no way to authenticate the caller. Such an application is out of scope for
this version, and closing the gap needs a contracted lookup rather than a
relaxation of `REQ-217` — see [[SPEC-004-application-scoped-identity#OQ-208]].

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
account authority, and that authority SHALL publish the reciprocal binding,
before any verifier accepts a grant naming that alias. It SHALL NOT fabricate
an `acct:` URI merely by combining a user name or public key with a developer
domain.

The obligation is anchored at acceptance, not at issuance. The stable alias is
a deterministic function of the home DID under
[[SPEC-004-application-scoped-identity#CON-203]], so the home controller can
name it before any authority has heard of it — and a name asserted by the
controller alone proves nothing, exactly as DID Core says of `alsoKnownAs`. The
provisioned account record and its reciprocal JRD are what convert that
assertion into a binding, and
[[SPEC-004-application-scoped-identity#CON-206]] step 9 is where a verifier
requires it. Placing the obligation at issuance instead would make the first
enrollment of an account impossible whenever the home controller is a wallet on
another device: the authority cannot recompute a localpart from a home DID that
has not been derived yet, and the wallet does not hold the application's
authenticated account channel.

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

`validUntil` SHALL be later than `validFrom` by no more than the profile's
`maxGrantLifetimeSeconds`, which SHALL NOT exceed 2,592,000 seconds — thirty
days. An issuer SHALL NOT mint a longer grant and a verifier SHALL reject one
under [[SPEC-004-application-scoped-identity#CON-206]] step 11, whatever the
current time.

This bound is load-bearing rather than hygienic. Revocation depends on a
verifier obtaining fresh issuer state, and
[[SPEC-004-application-scoped-identity#CON-204]] permits an application that
cannot reach the home controller to rely on expiry alone when provisioning
fails. Grant lifetime is therefore the outer bound on how long a revoked or
unprovisionable device keeps working, and an unbounded `validUntil` would make
revocation cosmetic in exactly the cases where it matters most. Choosing the
final ceiling alongside `maxClosureAgeSeconds` and `propagationSlaSeconds` is
[[SPEC-004-application-scoped-identity#OQ-201]]; the thirty-day value above is
a normative default that OQ-201 may lower but SHALL NOT raise without a Tier-1
amendment.

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
only by passing both capability contracts in
[[PROTO-003-selfsame-pairing-v1#CON-401]] and
[[PROTO-002-selfsame-rendezvous-v1#CON-301]]. The person SHALL NOT be asked to
type, paste, scan, or choose an endpoint during the normal path. Scanning a QR
or entering the twelve-word pairing code is ceremony bootstrap, not endpoint
selection. The person is never asked for an application identity.

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

[[PROTO-003-selfsame-pairing-v1#CON-409]] record resolution conforms to this
requirement rather than excepting it. Its tier-1 relays arrive only inside
profiles the resolving party authenticated, its tier-3 path is the application's
own origin — already required for the profile fetch — and its tier-2 distributed
hash table has no operator. No Selfsame or Anuna endpoint is consulted when a
profile is missing or unhealthy.

Trace: [[SPEC-004-application-scoped-identity#TEST-216]],
[[SPEC-004-application-scoped-identity#TEST-226]]

### REQ-211: The VC remains opaque inside the link transport

The link ceremony SHALL carry the compact JWS bytes together with the exact
media type `application/vc+jwt` in the `grant` and `grantMediaType` members of
the bundle payload defined by
[[SPEC-004-application-scoped-identity#CON-219]], sealed by
[[PROTO-004-selfsame-ceremony-envelope-v1#CON-502]].

The outer CBCL or other application transport SHALL NOT translate the VC
properties, reserialize its JWS components, replace its signature, or call an
outer signature "VC conformance." The ceremony envelope SHALL NOT be described
as securing the credential: it protects the transport, and the credential's own
JWS is the only signature a verifier accepts. The same bytes SHALL be
independently verifiable after extraction by a non-CBCL application.

Trace: [[SPEC-004-application-scoped-identity#TEST-217]],
[[SPEC-004-application-scoped-identity#TEST-236]]

### REQ-212: The provider choice follows the ceremony

The initiating client SHALL place the selected provider ID and descriptor
digest in the authenticated provider hint defined by
[[SPEC-004-application-scoped-identity#CON-209]].

The joining client SHALL follow that choice for the in-progress ceremony. It
SHALL NOT independently select a different rendezvous. If the selected
provider becomes unavailable, the initiator SHALL abandon that ceremony and
create fresh material before either party moves. Fresh material includes the
code `C`, meeting-point address, nameplate, role tokens, SPAKE2 ephemerals and
confirmations, derived mailbox secret, offer, slots, ciphertext, and
authenticated hint, as required by
[[PROTO-003-selfsame-pairing-v1#REQ-406]] and
[[PROTO-002-selfsame-rendezvous-v1#REQ-307]].

Trace: [[SPEC-004-application-scoped-identity#TEST-218]],
[[SPEC-004-application-scoped-identity#TEST-226]]

### REQ-213: Derivation does not depend on an infrastructure provider

Application-account home key derivation SHALL depend only on recovery input,
the hierarchy version, canonical `applicationId`, and canonical
`accountScopeId`. It SHALL NOT depend on account authority, rendezvous, state,
or status-projection provider ID, endpoint URL, region, projection index,
device key, or a provider health response.

The hierarchy version was already named here before 0.14.0 and remains a
property of this specification rather than of any account: exactly one version
is live at a time, and a wallet derives under the version its own code
implements because there is no other. The empty BIP-39 passphrase and
`persona = 0` are constants of that version
([[SPEC-004-application-scoped-identity#CON-202]]), not inputs a caller varies,
so nothing outside this document selects a derivation tree.

Changing providers therefore SHALL NOT rotate the home DID or `acct:`
localpart. The application is responsible for preserving or republishing the
account and state records when it changes operators. Restoring the account
scope itself follows [[SPEC-004-application-scoped-identity#REQ-217]].

Trace: [[SPEC-004-application-scoped-identity#TEST-219]],
[[SPEC-004-application-scoped-identity#TEST-244]]

### REQ-214: Any developer can adopt the profile

A conforming integration SHALL require no registration with Anuna. A developer
needs only:

1. one immutable application ID and embedded profile;
2. an account-record integration implementing the scope lifecycle in REQ-217;
3. an RFC 7565 account authority with the WebFinger binding in CON-204;
4. for a production wallet-exposed integration, origin-authenticated profile
   publication and a backend enrollment-signing key conforming to CON-214;
5. for same-device mobile, the Android and/or Apple application bindings in
   CON-201 and CON-215; for a web-only application, the web manual binding in
   [[SPEC-004-application-scoped-identity#CON-227]];
6. one or more providers conforming to both
   [[PROTO-003-selfsame-pairing-v1]] and
   [[PROTO-002-selfsame-rendezvous-v1]];
7. one or more `did:crdt` service nodes or peer paths conforming to that
   method's `CON-003` and `CON-004`, which the application MAY satisfy by
   embedding the method library in the backend it already runs for CON-214
   rather than by contracting a third party;
8. application permission URIs and verifier policy; and
9. the Selfsame issuer/holder SDK or an independent conforming implementation.

A developer MAY additionally deploy a W3C Bitstring Status List projection
host. That optional service does not participate in core issuance, linking,
revocation authority, or Selfsame authorization.

The reference implementation SHALL expose the black-box PROTO-002 and
PROTO-003 conformance suites and the end-to-end profile suite so each can run
without contacting Anuna infrastructure.

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

### REQ-219: Protocol conformance determines pairing and rendezvous eligibility

A rendezvous descriptor naming `selfsame-rendezvous-v1` SHALL be eligible only
when its mailbox URL is canonical, its pairing fields conform to
[[PROTO-003-selfsame-pairing-v1#CON-401]], and both bounded capability probes
pass. After selection, both clients and the operator SHALL use
[[PROTO-003-selfsame-pairing-v1#CON-402]] through
[[PROTO-003-selfsame-pairing-v1#CON-408]] for pairing and
[[PROTO-002-selfsame-rendezvous-v1#CON-302]] through
[[PROTO-002-selfsame-rendezvous-v1#CON-308]] for every mailbox operation.
Operator identity, commercial relationship, co-location with a state resolver,
or an Anuna allowlist SHALL NOT substitute for protocol conformance.

Changing providers after a PROTO-003 session is allocated, any pairing frame
or mailbox request has been sent, or a bootstrap/hint has been published SHALL
abandon the prior ceremony and create a fresh code, address, nameplate, tokens,
ephemerals, derived secret, slots, offer, ciphertext, and authenticated hint as
required by
[[PROTO-003-selfsame-pairing-v1#REQ-406]] and
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
provider selection, SPAKE2 roles and confirmation, derived rendezvous slots,
encrypted grant bundle, acceptance predicate, device proof, and
state-publication path as the cross-device ceremony; only delivery of the
logical pairing bootstrap to Selfsame and an optional non-authoritative UI
return differ.

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

The invoking SDK SHALL NOT deliver a pairing code or bootstrap, word secret,
role token, PAKE key, mailbox secret, offer plaintext, account scope, device
private key, grant, or decryption key through a generic/implicit intent,
unverified custom URL scheme, browser or install-page fallback, clipboard,
pasteboard, notification payload, analytics event, crash report, or
application log.

The platform adapter may carry the pairing bootstrap only after it has
constrained delivery to the installed wallet target as defined by
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
abandon that ceremony and retry only with a fresh code, address, nameplate,
role tokens,
SPAKE2 ephemerals, derived mailbox secret, offer, slots, ciphertext, request
ID, enrollment evidence, and provider hint.

An install or help link is a separate action containing no ceremony data.

Trace: [[SPEC-004-application-scoped-identity#TEST-230]]

### REQ-226: Every short human code uses SPAKE2

The canonical human pairing code SHALL be the twelve-word rendering of the
128-bit value `C` defined by
[[PROTO-003-selfsame-pairing-v1#CON-402]]. `C` SHALL be used only as the
password input to the end-to-end SPAKE2 construction in
[[PROTO-003-selfsame-pairing-v1#CON-403]] and
[[PROTO-003-selfsame-pairing-v1#CON-404]], and as the meeting-point address
seed in [[PROTO-003-selfsame-pairing-v1#CON-409]].

Both clients SHALL require explicit role-separated confirmation. No client
SHALL treat the short code as a bearer key, feed it to the former direct-secret
HKDF, omit SPAKE2, or accept a provider-generated peer confirmation.

Trace: [[SPEC-004-application-scoped-identity#TEST-232]],
[[SPEC-004-application-scoped-identity#TEST-233]]

### REQ-227: Application context makes the short code routable

Every carrier SHALL convey the logical bootstrap in
[[PROTO-003-selfsame-pairing-v1#CON-402]]. Machine carriers convey the sixteen
octets of `C` directly; a person conveys its twelve-word rendering. No carrier
conveys a canonical `applicationId`, profile digest, route, or nameplate.

On the normal path no person is asked to say an HTTPS identity. The single
exception is tier 3 of [[PROTO-003-selfsame-pairing-v1#CON-409]], reached only
after every other transport has failed, where the person supplies the
application's origin as a lookup key. That path exists because no
non-user-supplied discovery transport can be guaranteed on every network, and
because the resolving party must fetch the profile from that origin regardless —
so it introduces no new dependency and no new trust. It SHALL NOT be offered
before the other tiers are attempted.

Application context SHALL be resolved from the signed record in
[[PROTO-003-selfsame-pairing-v1#CON-409]], whose contents re-enter the
[[PROTO-003-selfsame-pairing-v1#CON-403]] binding and therefore fail
confirmation if substituted. A code SHALL NOT be interpreted globally,
broadcast, resolved by an operator registry, or tried against
historic/undeclared providers. A code resolving no record fails as
`PairingRecordUnavailable`.

Trace: [[SPEC-004-application-scoped-identity#TEST-234]],
[[SPEC-004-application-scoped-identity#TEST-235]],
[[PROTO-003-selfsame-pairing-v1#TEST-413]]

### REQ-228: The pairing provider is not a trust anchor

The application and wallet SHALL be the two SPAKE2 endpoints. The selected
provider SHALL conform to the blind relay boundary in
[[PROTO-003-selfsame-pairing-v1#REQ-404]] and SHALL receive no word, word
index, password-equivalent verifier, PAKE key, mailbox key, offer/grant
plaintext, DID, account scope, or authorization decision.

A provider may operate both pairing and PROTO-002 services, but co-location
confers no application, account, DID-state, credential, or PAKE authority.

Trace: [[SPEC-004-application-scoped-identity#TEST-233]],
[[SPEC-004-application-scoped-identity#TEST-235]]

### REQ-229: One failed pairing attempt burns every dependent value

The application and wallet SHALL each lock one peer under
[[PROTO-003-selfsame-pairing-v1#CON-407]]. A wrong code, conflicting claim,
invalid point, confirmation mismatch, frame fork, timeout, carrier mismatch,
ambiguous post-display request, or provider change SHALL permanently abandon
the complete pairing and grant ceremony.

A retry SHALL generate a new code `C`, meeting-point address, provider session,
role tokens,
SPAKE2 ephemerals, derived mailbox secret, offer, slots, ciphertext, request
ID, ceremony ID, enrollment evidence, and provider hint. The wallet SHALL
evaluate at most one initiator confirmation per minted ceremony.

Trace: [[SPEC-004-application-scoped-identity#TEST-233]],
[[SPEC-004-application-scoped-identity#TEST-235]]

### REQ-230: An account's first issuer is confirmed, not trusted

At the first enrollment of an authenticated application account, the person
SHALL confirm the home DID fingerprint across the wallet and application screens
defined by [[SPEC-004-application-scoped-identity#CON-221]] before the alias is provisioned or the grant is
accepted.

An application SHALL NOT accept a first grant without that confirmation, SHALL
NOT offer an affordance to skip or suppress it, and SHALL fail closed when it
cannot determine whether the account authority already holds a binding.

At every subsequent enrollment the authority's existing binding is
authoritative: a grant naming a different issuer SHALL be rejected under
[[SPEC-004-application-scoped-identity#CON-204]], and the confirmation SHALL NOT be shown again.

Rationale: without this, whichever wallet answers a first ceremony becomes the
account's identity permanently, because [[SPEC-004-application-scoped-identity#CON-206]]'s expected-account
input does not yet exist and the check degrades to self-consistency. See
[[SPEC-004-application-scoped-identity#ADR-220]].

Trace: [[SPEC-004-application-scoped-identity#TEST-238]]

### REQ-231: Identity succession is explicit, bounded, and confirmed

When an application account's home DID must be replaced because the developer's
canonical `applicationId` changed, the replacement SHALL occur only through
[[SPEC-004-application-scoped-identity#CON-225]]. Version 1 defines no other
succession, and in particular no migration from an earlier derivation scheme.

It SHALL be requested by the application, authorized by signatures from **both**
the outgoing and the incoming home key, confirmed by the person comparing both
fingerprints under [[SPEC-004-application-scoped-identity#CON-221]]'s display
rules, bounded by an explicit expiry no longer than the incoming profile's
`revocation.maxGrantLifetimeSeconds`, and invisible to every other application.

Silent migration, wallet-initiated migration, unbounded overlap, a one-sided
statement, a succession chain, and publication of the statement in any
resolvable document are prohibited. An application that cannot complete CON-225
SHALL enroll a fresh identity rather than approximate a migration.

Rationale: [[SPEC-004-application-scoped-identity#REQ-202]] already declares
that changing `applicationId` creates a new identity. This requirement does not
weaken that — it defines the one audited path by which a person may carry an
account across the boundary, and keeps every other path closed. See
[[SPEC-004-application-scoped-identity#ADR-222]].

Trace: [[SPEC-004-application-scoped-identity#TEST-242]]

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

Trace: [[SPEC-004-application-scoped-identity#TEST-201]], [[SPEC-004-application-scoped-identity#TEST-206]], [[SPEC-004-application-scoped-identity#TEST-221]], [[SPEC-004-application-scoped-identity#TEST-222]]

### NFR-202: Deterministic portability

At least two independent implementations SHALL reproduce every normative KDF,
application ID, account-scope validation, opaque alias, username grammar,
grant-ID, JWK, JWS, revocation-delta, challenge, and provider-selection test
vector, plus every application-enrollment and mobile-handoff vector,
byte-for-byte before the Tier-1 gate closes. PROTO-003's code packing,
binding, SPAKE2 messages, confirmations, relay, and mailbox-secret vectors,
PROTO-002's capability, slot, HTTP, expiry, and retry vectors, and PROTO-004's
envelope key schedule, sealed record, and rejection vectors are part of this
portability gate. The `offerDigest` and payload vectors in
[[SPEC-004-application-scoped-identity#CON-219]] are included.

Trace: [[SPEC-004-application-scoped-identity#TEST-202]], [[SPEC-004-application-scoped-identity#TEST-207]], [[SPEC-004-application-scoped-identity#TEST-226]], [[SPEC-004-application-scoped-identity#TEST-236]]

### NFR-203: Data minimization

The VC SHALL contain only its random ID, the application ID, opaque account
URI, device identifier and public key, permission URIs, validity, and status
reference required by this profile. It SHALL NOT contain recovery metadata,
the optional human-readable alias, another application's identifier, a display
name, email address, mnemonic fingerprint, `accountScopeId`, or
provider-selection history.

Trace: [[SPEC-004-application-scoped-identity#TEST-206]]

### NFR-204: No verification-time code or context loading

VC verification SHALL perform no arbitrary remote JSON-LD context fetch, schema
code execution, dynamic algorithm loading, or plugin discovery.

The exact base and Selfsame contexts SHALL be pinned by digest in the SDK.
Unknown context entries SHALL be rejected before signature-dependent
authorization decisions are made.

Trace: [[SPEC-004-application-scoped-identity#TEST-207]], [[SPEC-004-application-scoped-identity#TEST-208]], [[SPEC-004-application-scoped-identity#TEST-211]]

### NFR-205: Fail closed

Malformed profiles, aliases, DID closures, revocation state, JWKs, VCs, JWS
headers, enrollment statements, platform bindings, mobile handoffs, callbacks,
status projections, permission sets, challenges, provider hints, rendezvous
capabilities, pairing bootstraps, short codes, routes, nameplates, SPAKE2
points, confirmations, role tokens, relay responses, mailbox responses, sealed
ceremony records, or ceremony payloads SHALL produce a typed failure and no
authenticated session.

There SHALL be no TOFU path for projection issuers, account authorities, or
provider descriptors.

An account's **first** issuer key is the single case where no prior binding can
exist, and it is closed by human confirmation rather than by prior trust:
[[SPEC-004-application-scoped-identity#CON-221]] requires the person to compare the home DID fingerprint
before the alias is provisioned, and [[SPEC-004-application-scoped-identity#REQ-230]] forbids skipping it.
Every enrollment after the first is pinned by the account authority's binding,
so there is no first-use trust remaining. An implementation that accepts a first
grant without that confirmation **is** a TOFU path and does not conform.

Trace: [[SPEC-004-application-scoped-identity#TEST-208]], [[SPEC-004-application-scoped-identity#TEST-211]], [[SPEC-004-application-scoped-identity#TEST-229]]

### NFR-206: Provider diversity

The protocol SHALL permit the account, pairing, rendezvous, state, and optional
status-projection roles to be operated by different organizations. A selected
descriptor may bind separate pairing and mailbox origins, but no wire
identifier SHALL assume any other roles share a DNS origin or deployment stack.

Trace: [[SPEC-004-application-scoped-identity#TEST-220]], [[SPEC-004-application-scoped-identity#TEST-226]]

### NFR-207: Selection latency

With at least one healthy declared provider, provider selection SHOULD complete
within 2 seconds at the 95th percentile on an ordinary residential connection,
excluding captive portals and complete network loss.

Health probes SHALL be bounded and parallel. A slow high-priority provider
SHALL NOT serially block all fallbacks.

Trace: [[SPEC-004-application-scoped-identity#TEST-214]]

### NFR-208: Algorithm confinement

Version 1 SHALL use Ed25519/EdDSA only for the application-account home JWS,
developer enrollment JWS, and device proof.

The ceremony envelope SHALL use only the HKDF-SHA-256 key schedule and RFC 8439
ChaCha20-Poly1305 AEAD fixed by
[[PROTO-004-selfsame-ceremony-envelope-v1#NFR-502]]. No algorithm identifier
appears in a sealed record, so there is nothing for untrusted input to select.

Algorithm agility SHALL occur by a new profile version and explicit migration,
never by accepting an algorithm named by untrusted input.

Trace: [[SPEC-004-application-scoped-identity#TEST-208]], [[SPEC-004-application-scoped-identity#TEST-236]]

## Architecture decisions

### ADR-201: Namespace the hierarchy by immutable application ID

**Status:** PROPOSED.

The recovery secret feeds the hierarchy root
([[SPEC-004-application-scoped-identity#ADR-223]]), that root feeds a private
application node, that node feeds one private child per account scope, and each
account node feeds its home signing seed. The application ID and account scope
are length-prefixed and placed in separate HKDF invocations, **not reduced to
the current one-byte application code or to any small integer index**.

That rejection is about how *applications and accounts* are namespaced, and it
stands. It is not a rejection of the persona index, which
[[SPEC-004-application-scoped-identity#ADR-223]] admits into the root
derivation: a persona selects which of the person's own identity trees is in
use, it is chosen by the wallet and never by an application or a person typing
a number, and it namespaces nothing below the root. Version 0.14.0 amended this
paragraph, which previously named the persona index among the rejected
encodings and would otherwise contradict CON-202.

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

That the assertion proves nothing is exactly why
[[SPEC-004-application-scoped-identity#CON-204]] anchors the provisioning
obligation at acceptance rather than at publication or issuance. A controller
may name its own deterministic alias at any time; only the authority's record
and reciprocal JRD make it usable, and only a verifier checks for them.

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

Neither mechanism solves distribution freshness. That is bounded rather than
solved, by the CON-206 freshness tiers and the CON-210 projection rules
recorded under [[SPEC-004-application-scoped-identity#OQ-201]].

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
platform handoff replaces only the physical act of scanning or typing the
PROTO-003 bootstrap. The developer app and wallet still run the same
application-to-wallet SPAKE2 exchange through the blind relay, derive the same
PROTO-002 mailbox secret, exchange the encrypted offer/grant, and apply the
same acceptance predicate. Signed `did:crdt` deltas continue through the
separate state-publication role.

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
[[SPEC-004-application-scoped-identity#CON-220]] fixes key discovery and the
wire, and [[SPEC-004-application-scoped-identity#CON-222]] and
[[SPEC-004-application-scoped-identity#CON-223]] fix the platform-evidence
profiles.

### ADR-215: Use two-word SPAKE2 for the human pairing code

**Status:** SUPERSEDED by
[[PROTO-003-selfsame-pairing-v1#ADR-406]] and
[[PROTO-003-selfsame-pairing-v1#ADR-409]].

The decision below reduced the code from 128 bits to 22 because the previous
form "made the accessibility fallback impractical." That diagnosis was of the
41-character Bech32m **encoding**, not of the entropy. ADR-406 keeps 128 bits and
changes the encoding to twelve BIP-39 words, which costs two spoken tokens
against the code described here and returns 80 bits. SPAKE2 and mutual
confirmation are retained; only the password width and its rendering change. The
reasoning below is preserved for the record.

The human code is the
`<two-digit route><six-digit nameplate>-<BIP-39 word>-<BIP-39 word>` value in
[[PROTO-003-selfsame-pairing-v1]]. The two words provide 22 bits and are used
only by end-to-end SPAKE2 with explicit role-separated confirmation and an
N=1 burn-on-first-failure rule.

The former 41-character Bech32m code correctly carried 128 random bits, but it
made the accessibility fallback impractical. A two-word value cannot safely
replace that secret inside the former direct HKDF: PAKE is mandatory whenever
the short form is accepted. Conversely, maintaining separate high-entropy QR
and low-entropy manual cryptographic ceremonies is rejected because it creates
a downgrade boundary and duplicates the security state machine. QR, manual,
and same-device paths therefore carry one logical SPAKE2 bootstrap.

The existing Hark/cbcl-bus composition is reused at the primitive and UX
levels. Its hub-as-SPAKE2-responder trust model is not reused.

### ADR-216: Route within an authenticated application profile

**Status:** PARTIALLY SUPERSEDED by
[[PROTO-003-selfsame-pairing-v1#ADR-407]] and
[[PROTO-003-selfsame-pairing-v1#ADR-409]].

The conclusion below — that a short code cannot identify an arbitrary HTTPS
endpoint, and that separate application context is therefore a normative
bootstrap requirement — remains correct. What changed is where that context comes
from. ADR-407 obtains it by resolving a signed record at an address derived from
the code, rather than by requiring a person to convey an HTTPS identity aloud.
The cross-application separation this ADR establishes is untouched: route,
nameplate, and descriptor digest remain members of the
[[PROTO-003-selfsame-pairing-v1#CON-403]] binding object, reconstructed from the
resolved record instead of parsed from the human code.

A bare Hark-style numeric nameplate works only when both peers already know one
hub. Selfsame must support unrelated applications whose profiles name
different providers. Version 1 therefore scopes the numeric component:

```text
number = two-digit profile route || six-digit provider nameplate
```

The QR and verified same-device carrier include the canonical application ID
and profile digest. A manual path supplies the application identity beside the
short code unless the wallet already has that authenticated context. The route
then selects one descriptor only within that profile. Other applications may
reuse every route and nameplate without collision because the PAKE transcript
binds the application, profile, and complete descriptor.

A global Selfsame provider directory, centrally allocated numeric prefixes,
and code broadcast are rejected. They would make shared infrastructure or
privacy-leaking fan-out necessary. A short code cannot by itself identify an
arbitrary HTTPS endpoint; the separate application context is therefore a
normative bootstrap requirement, not optional UX decoration.

### ADR-217: Pair end to end, then reuse the blind mailbox

**Status:** PROPOSED.

The developer application is SPAKE2 role A and the Selfsame wallet is role B.
The selected provider is only the bounded four-frame relay defined by
[[PROTO-003-selfsame-pairing-v1]]. It stores no password-equivalent verifier
and cannot impersonate a client merely by compromising provider storage.

After mutual confirmation, both endpoints derive the existing 16-byte
PROTO-002 mailbox secret from the PAKE key and bound transcript. That secret,
with `binding_hash`, is also the sole input to the
[[PROTO-004-selfsame-ceremony-envelope-v1#CON-501]] envelope keys.
Application enrollment evidence, consent, home signatures, VC validation,
holder proof, and `did:crdt` state remain independent controls. Successful PAKE
proves shared knowledge of the OOB words; it does not authenticate a developer
origin or authorize a device by itself.

### ADR-218: Own the ceremony envelope in a protocol, its payload here

**Status:** PROPOSED.

The sealed record that carries every offer and every grant is defined by
[[PROTO-004-selfsame-ceremony-envelope-v1]]. Its payload member sets are
defined by [[SPEC-004-application-scoped-identity#CON-219]].

Until version 0.7.0 neither existed. PROTO-002 placed "offer, grant, VC, AEAD,
transcript, or pairing-code formats" out of scope; PROTO-003 placed "the
encrypted offer/bundle mailbox wire contract" out of scope and delegated it to
PROTO-002. Each document reasonably declined a concern outside its
responsibility, and the concern fell between them: this specification's threat
model named "the ceremony AEAD" and "the selected AEAD" without any document
having selected one, and CON-206 read an issuer closure "from the encrypted
bundle" without any document defining a bundle.

The split follows the boundary the two existing protocols already draw. A
mailbox slot and the octets inside it are separate concerns in PROTO-002;
one layer up, the sealed envelope and the payload inside it are separate in the
same way. Cryptographic properties — suite, key schedule, nonce discipline,
transcript binding, recognition order — belong in a protocol that two
independent clients implement identically and that a cryptography reviewer signs
off once. Application-account content — account scope, device key, permissions,
enrollment evidence, grant — belongs here, where a new permission shape is an
ordinary profile amendment rather than a Tier-1 cryptographic one.

Rejected:

- defining the envelope in this document — a 3,600-line application profile is
  the wrong home for a keystream-reuse argument, and every payload change would
  then require renewed cryptography sign-off;
- extending PROTO-002 to cover it — PROTO-002 is deliberately blind and must
  stay implementable by an operator who knows nothing about credentials;
- extending PROTO-003 to cover it — pairing ends at mutual confirmation, and
  loading transport encryption onto it would merge two independent burn and
  retry state machines; and
- leaving it undefined and inheriting SPEC-001's CBCL envelope — that document
  is not in this vault, this specification explicitly declines to amend it, and
  an unstated inheritance is how the gap arose.

### ADR-219: Bind state transport to `did:crdt`, and let the application be its own replica

**Status:** PROPOSED.

`stateResolvers` entries name nodes conforming to the `did:crdt` method's own
`CON-003` HTTP Resolution API and `CON-004` Sync Protocol. An adopting
application SHOULD list its own origin among them.

Through version 0.10.0 this profile declared the token
`did-crdt-signed-closure-v1` and defined it nowhere — the exact defect
[[SPEC-004-application-scoped-identity#ADR-212]] rejected for the rendezvous,
where an undocumented label "makes the reference implementation the accidental
standard and prevents a third party from knowing what to implement." The remedy
there was to write PROTO-002. Here no new document is needed, because the
upstream method already specifies both a service API and a sync protocol with
their own conformance tests. Naming them is strictly better than restating them.

`CON-004` carries a property this profile depends on and should cite rather than
re-derive: only signed deltas cross the wire, and there is deliberately no
message shipping a materialised document, because state-based convergence is a
local primitive not reachable from the untrusted network. That is what lets
[[SPEC-004-application-scoped-identity#CON-206]] step 5 recompute and verify
everything locally.

The second half — the application as its own replica — follows from noticing
that the application **is** the verifier. Publishing the revocation directly to
the party that enforces it is the strongest available answer to a withholding
resolver, because that party stops depending on a third party choosing to tell
it. It costs nothing: `CON-214` already obliges every adopting application to run
a backend, and the method ships as a library with a service feature, so this is
an embedded dependency rather than a fourth piece of infrastructure to procure.

It is safe because revocation is **monotone**. The set is grow-only, deltas are
signed by the home key, and no operation clears an entry — so a forged delta
fails verification, a replayed one is idempotent, and an accepted one can only
reduce authority. Delivery to an application node therefore adds no way to
grant, only ways to revoke.

Rejected:

- **writing a Selfsame state-transport protocol** — it would duplicate `CON-003`
  and `CON-004` and immediately risk diverging from the method it profiles;
- **making the application's node authoritative** — `CON-210` is explicit that
  the controller's signed state, not a provider database, decides; an
  application node is a replica that verifies like any other;
- **delivering only to the application's node** — a grant may be verified by a
  peer or another device, so the other declared resolvers still receive the
  delta; and
- **treating a delivery acknowledgement as success** — unchanged from CON-210:
  only a re-resolved verified closure containing the exact grant ID confirms a
  revocation.

### ADR-220: Confirm the issuer at first enrollment rather than authenticate the wallet

**Status:** PROPOSED.

At an account's first enrollment the person confirms the new home DID's
fingerprint across the two screens in
[[SPEC-004-application-scoped-identity#CON-221]]. The application does not try
to authenticate which wallet answered.

`CON-206` takes as input "the exact RFC 7565 account expected by the current
authenticated application-account context." At first enrollment that value does
not exist: the application has never seen this person's home DID, so
`CON-204`'s remote-controller ordering has it derive the expectation from the
grant's own `issuer`. That is a self-consistency check, not an identity check —
whichever wallet answers becomes the account's identity, permanently. It is
trust-on-first-use of an issuer key, which
[[SPEC-004-application-scoped-identity#NFR-205]] prohibits outright.

The exposure is concentrated on the same-device path, where the SDK rather than
the person selects the target. A malicious local wallet that receives the
bootstrap holds `C`, so it completes SPAKE2, reads the offer, and can issue a
grant from its own recovery secret. `CON-215` asks the adapter to verify "the
installed wallet signing identity" — but an Anuna-only package allowlist is
ruled out, so there is nothing to verify against.

Authenticating the wallet cannot work without such a list, and a list would
block independent implementations, which is the property
[[SPEC-004-application-scoped-identity#REQ-214]] exists to protect. Confirming
the *issuer* sidesteps that: the person already knows which wallet holds their
recovery secret, so the question worth asking is not "is this a genuine wallet"
but "is this the identity your wallet just derived." One comparison, on first
enrollment only, converts trust-on-first-use into verified first use without
any registry.

Subsequent enrollments need no confirmation. Once the account authority holds a
binding under `CON-204`, a grant naming a different issuer is rejected outright,
so the ceremony is pinned by state the application already keeps.

The compared value is the hex fingerprint, with the
[[SPEC-002-visual-key-fingerprint]] LifeHash beside it as a recognition aid.
That ordering is required rather than chosen:
[[SPEC-002-visual-key-fingerprint#REQ-103]] states the hex "remains the
normative comparison value" and SHALL NOT be replaced by pictures, and
[[SPEC-002-visual-key-fingerprint#ADR-107]] defers promoting the image pending
human-discrimination evidence. Asking for an image comparison here would move
that backstop from a downstream document — the specification drift ADR-107
names.

Rejected:

- **platform attestation of the wallet** — strongest binding, but needs a
  registry of acceptable wallet builds, which
  [[SPEC-004-application-scoped-identity#REQ-214]] rules out and which would
  foreclose independent wallets;
- **authority-side pinning alone** — correct for every enrollment after the
  first and useless for the first, which is the only unprotected one;
- **narrowing `NFR-205` to permit first-use trust** — cheapest, but it spends a
  stated security property to avoid one comparison the person is well placed to
  make; and
- **comparing LifeHash images instead of hex** — contradicts
  [[SPEC-002-visual-key-fingerprint#REQ-103]].

### ADR-221: Name the vocabulary from a controlled origin, and make its digest the authority

**Status:** PROPOSED.

The credential context and vocabulary are named from
`https://anuna.io/selfsame/…`, and the normative artifact is the exact context
octets and their SHA-256 rather than whatever that URL serves.
[[SPEC-004-application-scoped-identity#CON-224]] carries the rules.

Through version 0.12.0 the identifier was `https://selfsame.dev/…`, described
here as provisional pending proof of domain control. It resolved no NS records:
the specification named a domain the project did not hold. That is worse than
an unowned identifier looks, because the string is baked into every signed
credential — an unregistered name in a credential is a name an adversary can
register and then serve a context of their choosing from. `anuna.io` is under
project control today, which settles the "prove control of a durable origin"
half of OQ-202 by inspection rather than by a purchase order.

The apparent tension with the Infrastructure promise is not real, and it is
worth stating why rather than leaving a reader to wonder. Naming is not
hosting. [[SPEC-004-application-scoped-identity#REQ-210]] forbids an Anuna
endpoint *consulted at runtime* when a profile is missing or unhealthy;
[[SPEC-004-application-scoped-identity#ADR-209]] forbids consulting this one at
all. A conforming verifier never contacts `anuna.io`, so no adopting
application acquires an operational dependency on Anuna by using the
vocabulary. The name appears in bytes, not in traffic.

Making the digest the authority is what reduces the origin to a name. Nothing
fetches during verification, a party that fetches for another reason must
compare, and the octets are archived independently — so hostile acquisition of
the domain, or loss of it, changes no verification result. It also means a
future stewardship change is a documentation event rather than a re-issuance
event, provided the IRIs never move.

Rejected:

- **keep `selfsame.dev` unregistered** — cheapest, and it leaves a signed
  identifier pointing at a name anyone may take;
- **register `selfsame.dev`** — a better name for the project, and a purchase
  is not a resolution: the gate item would still be open on the day the
  decision was needed, and the registration becomes a permanent lapse risk that
  the digest rule makes unnecessary;
- **a content-addressed identifier such as
  `urn:selfsame:credentials:device-grant:v1`** — immune to domain loss by
  construction and the most honest expression of ADR-209, but
  [[SPEC-004-application-scoped-identity#REQ-205]] claims W3C VC Data Model 2.0
  conformance and that model expects context values to be URLs; buying immunity
  the digest rule already provides at the cost of the conformance claim is the
  wrong trade; and
- **serving the context from each adopting application's origin** — removes the
  single name entirely, and creates as many divergent vocabularies as there are
  adopters.

### ADR-222: Succeed an application identifier with a doubly signed, unpublished statement

**Status:** PROPOSED.

[[SPEC-004-application-scoped-identity#OQ-204]] is answered by
[[SPEC-004-application-scoped-identity#CON-225]]: when a developer's canonical
`applicationId` changes, an existing home key hands one application account to a
key derived under the new identifier, with no third party able to make that
claim and no other application learning that it happened.

The pinned-key rule is the decision inside the decision. The obvious design has
the wallet fetch the outgoing origin's succession pointer and check it against
that origin's currently published enrollment keys — which makes succession
exactly as strong as a domain registration, and a lapsed registration acquired
by someone else is the case OQ-204 exists for. Checking instead against the key
set the wallet recorded at that account's last successful enrollment uses state
the wallet already holds and converts a DNS-strength control into a
key-strength one. The cost is that a developer who rotates every enrollment key
between a person's last enrollment and the migration loses that person's
succession — which fails closed to fresh enrollment, and is the right direction
to fail.

Both signatures are required for a reason that is easy to lose: the outgoing
key alone, if it leaked, could nominate an attacker's DID as successor, and the
incoming key alone could claim any predecessor's history. Requiring both means
the only party who can produce a statement is the party holding the recovery
secret from which both keys descend.

The mechanism is deliberately a signed statement rather than a `did:crdt`
operation, which is worth defending because
[[SPEC-004-application-scoped-identity#CON-210]] insists that a standalone
signature revokes nothing. Revocation and succession fail in opposite
directions: a withheld revocation leaves a dead grant working, so its state
must be convergent and unsuppressable, whereas a withheld succession simply
means an old grant is not accepted, which is already the safe outcome.
Convergent public state is mandatory where unavailability *grants* authority
and merely convenient where it *withholds* authority. Publishing the statement
as a delta would additionally announce the successor to everyone who resolves
the outgoing DID, which is the same objection that rules out `alsoKnownAs`
below.

Rejected:

- **rotating the key in place** — `did:crdt` has `AddVerificationMethod` and
  `RevokeVerificationMethod`, so the outgoing DID could simply adopt the key
  derived under the new `applicationId` and keep its identifier. No succession
  statement, no overlap, no alias tombstoning. It is also exactly wrong twice
  over. The retained DID was derived under the *old* application node, so the
  new application's identity would descend from the old application's
  namespace, collapsing the correlation boundary
  [[SPEC-004-application-scoped-identity#ADR-201]] exists to draw; and
  [[SPEC-004-application-scoped-identity#NFR-202]] requires the home DID to be
  reproducible from mnemonic, `applicationId`, and `accountScopeId` alone,
  which a retained predecessor identifier is not. It would buy convenience with
  the two properties the hierarchy exists for;
- **a succession Verifiable Credential** — portable and standards-shaped, and
  it would add terms to the context [[SPEC-004-application-scoped-identity#CON-224]]
  has just frozen. Portability is worthless here: nothing outside the
  developer's own two origins consumes it, and publishing it as a credential is
  precisely what would leak the link;
- **`alsoKnownAs` on the incoming DID naming the outgoing DID** — the
  DID-native move, and exactly wrong, because `alsoKnownAs` is resolvable
  public data and would publish the cross-application link
  [[SPEC-004-application-scoped-identity#NFR-201]] exists to prevent;
- **trusting the outgoing origin's currently served keys** — see above;
- **permitting succession chains** — A→B→C lets a compromised intermediate
  launder an account into a third identity; version 1 permits one hop and
  re-enrollment for anything longer;
- **one developer-signed migration covering every account** — a single artifact
  is operationally attractive, and it links a population and hands an origin
  acquirer one lever; and
- **a new profile member for the overlap window** — CON-201's recognized
  language is closed at any depth, so a new member is a new `profileVersion`.
  Bounding the statement by the incoming profile's existing
  `maxGrantLifetimeSeconds` obtains the same bound for nothing.

### ADR-223: Root the hierarchy at its own sibling of the SPEC-001 persona root

**Status:** PROPOSED.

**Context.** Hierarchy version 1 rooted
[[SPEC-004-application-scoped-identity#CON-202]] at the 64-byte BIP-39 seed.
[[SPEC-001-device-key-provisioning]]'s custody seals `root_seed(mnemonic,
persona)` — an HKDF-SHA-512 output over that seed — and stores the phrase
nowhere, deliberately. The two specifications therefore rooted at different
points of one secret, and a wallet that had completed SPEC-001 onboarding held
only the derivative. It could not derive a SPEC-004 home DID for any
application, at any time, without the person re-entering their recovery phrase.
Neither specification was wrong locally; neither stated where they meet. The gap
was found while planning the person-facing surface and is recorded as
`FINDING-016` in [[EXP-001-findings]].

**Decision.** Hierarchy version 2 roots at `hierarchy_root`, a 64-octet
HKDF-SHA-512 output over `bip39_seed` under this project's own label
`selfsame/v2/hierarchy-root/`. It is a **sibling** of SPEC-001's persona root,
not its child: both descend from the seed, neither derives the other. A
custodian seals it alongside whatever else it seals. Everything below
`application_node` is unchanged — the salt construction, the length-prefixed
`info` encoding and its injectivity argument, the labels, the node widths, and
the Ed25519 interpretation of `home_signing_seed`.

**Rationale.** Four alternatives were considered.

*Seal the BIP-39 seed in custody.* `FINDING-016`'s first proposed resolution. It
works, and it widens a custody compromise from one persona's root key to the
entire recovery hierarchy — every persona, every application, permanently. The
persona separation SPEC-001 defines would become decorative.

*Derive at unlock time from a re-entered phrase.* `FINDING-016`'s second
resolution. It changes no storage but breaks
[[SPEC-004-application-scoped-identity#REQ-213]]'s user promise and `HP-7`
(*Restore*) in [[person-happy-paths]], whose precondition is twelve words and a
new device and nothing else. It also requires the threat boundary to state where
a recovery secret lives during a session and for how long.

*Root at SPEC-001's persona root itself.* Drafted and rejected. It reaches the
same usability using material a custodian already holds, and it costs four
things this decision declines to pay: the persona root would be simultaneously
an RFC 8032 Ed25519 private seed and HKDF input keying material, requiring a
joint-security argument in the random-oracle model plus a dual-PRF assumption on
HMAC-SHA-512 with the secret in the message position; SPEC-001 REQ-024 requires
user presence for *every* use of that seed, so every application derivation
would either prompt or hold the root across a session — the very question this
list rejects alternative 2 for; SPEC-004 would acquire a normative dependency on
an external Tier-1 draft that is itself unapproved; and the root would have to
cross into `selfsame-app-identity`, a crate that also compiles to wasm, putting
the SPEC-001 root signing seed behind any disclosure bug there. A sibling root
buys the identical capability with none of them.

*A sibling root — chosen.* One extra HKDF call at create or restore, and 64 more
sealed octets. In exchange the root is HKDF input keying material and nothing
else, so there is no key-separation question to review, no cross-specification
dependency to pin, and no SPEC-001 secret in the derivation crate. Sixty-four
octets is the same width as every interior node of the tree, so
`application_node`, `account_node` and the recovery type keep their shapes.

**Consequences.**

1. **A custody format change, and it widens what a custody compromise yields.**
   This is the cost and it is stated first because
   [[SPEC-004-application-scoped-identity#ADR-223]] is what a reviewer reads to
   decide. *Before* version 2, compromising the passcode-sealed custody blob
   yielded one persona's Ed25519 root signing key and **no SPEC-004 material at
   all** — precisely because the hierarchy rooted at a seed custody did not
   hold. *After* version 2 the same compromise additionally yields
   `hierarchy_root`, and with it every `application_node` under that persona,
   for every application, past and future, unrevocably. The blast radius did
   **not** already exist; it is created here. `EXP-001-findings` says the same
   thing about every resolution of `FINDING-016`: *"the choice widens what a
   passcode compromise yields, so it wants the security sign-off the Tier-1 gate
   already requires."* Recorded in the threat model rather than only here.

   **Counted conservatively, that is every account key as well.** Reaching an
   `account_node` from an `application_node` additionally requires that
   account's `accountScopeId`, so an attacker holding only the sealed root
   cannot *immediately* derive account keys for accounts whose scopes it has
   not obtained. That gap SHALL NOT be counted as a mitigation. The scope is
   held by the application and returned to the person's own authenticated
   session ([[SPEC-004-application-scoped-identity#REQ-217]]); an attacker who
   has already taken the custody blob is well placed to take it too, and no
   requirement here claims the scope's confidentiality as a control. The honest
   statement of the radius is the full one: **a compromised `hierarchy_root` is
   a compromised identity.** An earlier draft asserted the full radius without
   noticing the scope was missing from the derivation; it is stated
   deliberately now rather than by omission.

2. **What it still does not yield.** Neither the mnemonic nor `bip39_seed` is
   retained, so a custody compromise does not produce a recovery phrase, and
   `hierarchy_root` is not derivable from the persona root or vice versa.
   Compromise of the SPEC-001 root *signing key* yields `SHA-512(seed)` rather
   than the seed, so it reaches no part of this hierarchy.
3. **Hierarchy-version-1 vectors are void.** The salt moves to `/v2`, so every
   derived value changes. [[SPEC-004-application-scoped-identity#CON-226]]'s
   corpus is regenerated and its new SHA-256 recorded in the changelog.
4. **No migration path is defined**, and
   [[SPEC-004-application-scoped-identity#REQ-231]] is deliberately not amended:
   *"Version 1 defines no other succession, and in particular no migration from
   an earlier derivation scheme."* Nothing has derived a production identity —
   the wallet stubs derivation and the reference CLI is a declared prototype —
   so there is nothing to migrate and no user to protect.
5. **The persona index becomes a derivation input**, which
   [[SPEC-004-application-scoped-identity#ADR-201]] previously listed among the
   things this hierarchy does not reduce identifiers to. That ADR is amended
   rather than left to contradict this one; its objection was to *namespacing
   applications* by index, which remains rejected.

**Future hierarchy versions.** This decision does not make version 3 free, and
this document deliberately buys no option on one. Exactly one hierarchy version
is live at a time; [[SPEC-004-application-scoped-identity#REQ-231]] states that
version 1 defines no migration from an earlier derivation scheme, and a bump is
therefore a re-enrolment for every account.

An earlier draft of this amendment added a per-account record of the version and
persona, on the argument that a later migration would need it. That requirement
was withdrawn: it demanded a value that no defined wire could carry
([[SPEC-004-application-scoped-identity#CON-219]] and
[[SPEC-004-application-scoped-identity#CON-214]] are closed member sets), and it
bought optionality on a migration this specification has declined to support. A
bump under the present design fails closed — an account derived under an
obsolete version yields a home DID the authority's binding refuses — which is
the required posture, not a silent orphan.

If a migration is ever wanted, [[SPEC-004-application-scoped-identity#CON-225]]
is the mechanism to generalise, and the version record is one of the things that
work would have to add. Adding it now, ahead of the wire that would carry it,
was the error.

**What no design avoids.** Peers pin key-to-account bindings at first enrolment
([[SPEC-004-application-scoped-identity#CON-221]]). A hierarchy bump is a
re-pinning event for every peer whatever else is true, and CON-221 confirms only
*first* enrolments — so a wrong derivation on any later enrolment is refused at
[[SPEC-004-application-scoped-identity#CON-204]] without a person ever being
shown a fingerprint. Fail-closed rejection, not human comparison, is the control
that operates here.

### ADR-224: Web-only applications enrol through a declared web manual binding

**Status:** PROPOSED (2026-08-21).

**Context.** This document contradicts itself about platform bindings, and the
contradiction makes a whole class of conforming applications unable to enrol.
The adoption checklist scopes bindings to one path — *"for same-device mobile,
the Android and/or Apple application bindings"* — while
[[SPEC-004-application-scoped-identity#CON-214]]'s closed statement grammar
requires `platformBindingId` unconditionally and requires it to select a
binding from the authenticated profile. A **web-only application** — one with
no native app on any platform, whose ceremony reaches the wallet by the
cross-device path (the person scans the application's displayed QR from
another device, or pastes the code) — has no honest binding to declare:
an `apple:` entry requires a real Team ID bound by an
`apple-app-site-association` file that can never exist without a notarised
build, and an `android:` entry names a package whose calling-package
comparison ([[SPEC-004-application-scoped-identity#CON-222]]) refuses the
unattributed manual handoff by design.

The conflict is not hypothetical. The first adopting application,
[[cbcl-bus|cbcl-chat]] at `chat.anuna.io`, is web-only; its operator holds no
Apple Developer team (owner-confirmed 2026-08-21). Because no CON-214
statement can be constructed for it, no enrolment completes, no
[[IMPL-008-production-pairing-claimant#ADR-912]] pairing-trust record is ever
written, and every [[SPEC-008-production-pairing-claimant]] production pairing
attempt refuses at the origin gate. The failure a person sees is a pairing
refusal; the mechanism is an enrolment grammar that cannot be satisfied
honestly.

**Decision.** Add a third `enrollment.mobileBindings` form,
`platform: "web"`, defined by
[[SPEC-004-application-scoped-identity#CON-227]]: a profile-declared statement
that this application's ceremonies reach the wallet with no OS-mediated
handoff at all. The CON-214 statement grammar is **unchanged** —
`platformBindingId` remains required and still selects one declared binding.
The wallet accepts unattributed caller evidence against a web binding and
refuses any attributed caller against it.

**Rationale — alternatives considered.**

*Make `platformBindingId` conditional on the handoff mode.* Rejected. It
splits one closed statement shape into two at a trust boundary
(Constitutional Principle 14 argues for one recognised language), and absence
cannot be distinguished from a constructor that forgot the member — an
explicit declaration can be checked, an omission can only be excused.

*A sentinel value not anchored in the profile* (for example
`none:cross-device`). Rejected. It breaks the one uniform rule doing the
authenticating — that the statement selects a binding the
[[SPEC-004-application-scoped-identity#CON-220]]-authenticated profile
declares — leaving nothing for profile authentication to bite on.

*Declare an `apple:` binding with a placeholder team.* Rejected outright. It
publishes a fabricated authenticated fact; an iOS wallet would attempt a
Universal-Link association that can never verify, and the profile generator's
own refusal discipline exists to prevent exactly this artefact.

*Require the operator to obtain an Apple team first.* Rejected as the general
rule (any operator MAY still do it): it makes a US$99 external enrolment a
protocol precondition for a web application that ships no Apple binary, and
the binding it buys authenticates nothing on the paths such an application
actually uses — the unattributed carve-out in
[[SPEC-004-application-scoped-identity#CON-223]] is what would do the work,
and CON-227 states that same carve-out honestly instead of renting it from a
platform the application is absent from.

**Why this amends profile version 1 rather than minting version 2.** CON-201's
recognised language is closed, so an unamended recogniser refuses a profile
carrying a `web` binding — fail-closed, never misinterpreted. A version bump
exists to protect deployed recognisers from deployed documents, and there are
none of either: this specification was `0.15.0-draft` at the time of this
decision, its review gate is not-approved, and no ratified production profile
has ever been published by any origin. The recogniser and the first ratified profile ship together from
pinned builds in this repository and [[cbcl-bus]]. Amending version 1 before
first ratification is therefore a draft correction with zero compatibility
surface; minting version 2 would carry the conflict forward as permanent
dead grammar.

**Consequences.** The security delta is confined to what CON-227 states: a
web binding provides strictly less caller evidence than
[[SPEC-004-application-scoped-identity#CON-222]] and exactly as much as
[[SPEC-004-application-scoped-identity#CON-223]]'s unattributed case, and the
residual is closed by the same three controls that close it there — the
CON-214 backend signature, [[SPEC-004-application-scoped-identity#CON-221]]
first-enrollment confirmation, and the sealed offer under the PAKE. New
vectors are owed ([[SPEC-004-application-scoped-identity#TEST-246]], corpus
group 3), and this is a Tier-1 normative amendment under
[[SPEC-004-application-scoped-identity#Amendment Channels]]: it does not take
effect until the required reviews and the human owner's approval land.

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
      },
      {
        "id": "web:https://photos.example",
        "platform": "web",
        "origin": "https://photos.example"
      }
    ]
  },
  "rendezvous": [
    {
      "id": "au-primary",
      "url": "https://rendezvous-au.provider.example",
      "protocol": "selfsame-rendezvous-v1",
      "pairingUrl": "https://pairing-au.provider.example",
      "pairingProtocol": "selfsame-pairing-v1",
      "pairingRoute": "03",
      "priority": 10,
      "weight": 80,
      "validUntil": "2027-07-30T00:00:00Z"
    },
    {
      "id": "global-secondary",
      "url": "https://rendezvous.example.net",
      "protocol": "selfsame-rendezvous-v1",
      "pairingUrl": "https://pairing.example.net",
      "pairingProtocol": "selfsame-pairing-v1",
      "pairingRoute": "17",
      "priority": 20,
      "weight": 20,
      "validUntil": "2027-07-30T00:00:00Z"
    }
  ],
  "pairingRecordRelays": [
    "https://records-au.provider.example",
    "https://records.example.net"
  ],
  "stateResolvers": [
    {
      "id": "app-own",
      "url": "https://api.photos.example",
      "protocol": "did-crdt-service-v1"
    },
    {
      "id": "state-1",
      "url": "https://state.provider.example",
      "protocol": "did-crdt-service-v1"
    },
    {
      "id": "anuna-public",
      "url": "https://state.anuna.io",
      "protocol": "did-crdt-service-v1"
    }
  ],
  "revocation": {
    "method": "did-crdt-revocations-v1",
    "maxGrantLifetimeSeconds": 2592000,
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

#### Encoding and recognition

The physical encoding is **UTF-8 JSON**, and this is normative rather than a
convenience. Later contracts sign and compare `SHA-256(RFC8785(profile))` —
[[SPEC-004-application-scoped-identity#CON-214]] binds it,
[[PROTO-003-selfsame-pairing-v1#CON-403]] puts it in the PAKE transcript, and
[[PROTO-003-selfsame-pairing-v1#CON-409]] requires a resolving party to
recompute it — none of which is well-defined without fixing the serialization.
Earlier drafts placed the encoding outside version 1 while relying on that
digest, which let two conforming recognizers disagree about which profiles are
valid even when they computed the same digest.

The profile is therefore a closed recognized language:

1. the document is valid UTF-8 with no byte-order mark and at most 65,536
   octets;
2. it parses as JSON with no duplicate member names, no trailing content, and a
   nesting depth of at most 8;
3. the top-level value is an object whose member set is exactly the ten names
   below — `profileVersion`, `applicationId`, `accountAuthority`,
   `verifierAudience`, `allowedPermissions`, `enrollment`, `rendezvous`,
   `stateResolvers`, `revocation`, and the OPTIONAL `pairingRecordRelays`;
4. every member value satisfies its grammar in this contract; and
5. re-serializing the recognized object with RFC 8785 reproduces the input
   byte-for-byte.

**An unknown member at any depth is a rejection, not an extension point.** There
is no forward-compatibility affordance inside a profile; a new field is a new
`profileVersion`. A party SHALL complete all five steps before any semantic
action, and SHALL NOT extract a field by regular expression or act on a partial
parse.

`profileVersion` is exactly the integer `1`. `allowedPermissions` is a non-empty
array of at most 64 absolute HTTPS URIs, each on the `applicationId` origin with
a non-empty fragment, sorted by Unicode code point, without duplicates, and
compared as exact ASCII after the same canonicalization `applicationId` uses —
[[SPEC-004-application-scoped-identity#CON-206]] step 12 and
[[SPEC-004-application-scoped-identity#CON-214]] both compare against this array,
so an unnormalized permission would otherwise be a comparison hazard.
`rendezvous` and `stateResolvers` are non-empty arrays of at most 64 entries;
`pairingRecordRelays` at most 16.

The remote update mechanism remains outside version 1. The application MUST
embed an authenticated copy; it MAY update the profile through its own
authenticated release/configuration channel.

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
return URI on the `applicationId` origin. Web entries carry exactly `id`,
`platform`, and `origin`; `origin` MUST equal the `applicationId` origin
byte for byte, and `id` is exactly `web:` followed by that origin
([[SPEC-004-application-scoped-identity#CON-227]]). The wallet accepts a
binding only after [[SPEC-004-application-scoped-identity#CON-220]]
authenticates the profile and the platform-specific verification in
[[SPEC-004-application-scoped-identity#CON-222]],
[[SPEC-004-application-scoped-identity#CON-223]], or
[[SPEC-004-application-scoped-identity#CON-227]] authenticates the binding;
field presence is not proof.

Every provider ID MUST match `[a-z0-9][a-z0-9-]{0,62}` and be unique within its
role. Every provider URL MUST be HTTPS, contain an authority, and contain no
user information or fragment.

`priority` and `weight` MUST each be integers in `[0, 65535]`. `priority`
groups descriptors in ascending order under
[[SPEC-004-application-scoped-identity#CON-208]] step 3; `weight` is the
selection weight in step 6, where zero means ineligible. At least one descriptor
in the lowest-priority group MUST have a non-zero weight, or that group can
never be selected from. A rendezvous `validUntil` value MUST be a UTC
XML Schema `dateTimeStamp`; an expired descriptor is ineligible. Rendezvous
`url` values have the stricter canonical-origin grammar in
[[PROTO-002-selfsame-rendezvous-v1#CON-301]] and MUST conform to it.

Every rendezvous descriptor additionally MUST contain `pairingUrl`,
`pairingProtocol`, and `pairingRoute` as defined by
[[PROTO-003-selfsame-pairing-v1#CON-401]], which is the sole grammar for all
three. In particular `pairingUrl` is **not** origin-only: it uses that
contract's `pairing-base-url` and MAY carry one absolute, slash-prefixed path
prefix, which is what lets one operated service expose the blind mailbox at its
origin and the pairing relay below a prefix without colliding with another
protocol already served at `/pair/v1`. Pairing routes are exactly two ASCII
digits and unique within the profile; their numeric value has no global meaning.
`pairingUrl` and `url` MAY have different origins and MAY be operated by
different organizations.

`stateResolvers` entries name nodes conforming to the `did:crdt` method's own
service contract — `CON-003` HTTP Resolution API and, where the node
participates in peer sync, `CON-004` Sync Protocol — at the version pinned by
this profile. `protocol` is exactly `did-crdt-service-v1`. This replaces the
`did-crdt-signed-closure-v1` token used through version 0.10.0, which named no
contract and made the reference implementation the accidental standard —
precisely the defect [[SPEC-004-application-scoped-identity#ADR-212]] rejected
for the rendezvous.

An adopting application MAY list **its own origin** as a resolver, and doing so
is RECOMMENDED. See [[SPEC-004-application-scoped-identity#ADR-219]].

The example lists three entries to show that the roster is heterogeneous by
design: the application's own node, an unrelated commercial operator, and
`anuna-public`, a `did:crdt` node Anuna Research intends to operate as a public
good for developers who want no operational burden. All three are ordinary
declared resolvers with identical standing. `anuna-public` receives no special
trust, is not required, is not a default, and an application that omits it is
fully conforming.

That distinction is normative rather than editorial.
[[SPEC-004-application-scoped-identity#REQ-210]] names `state` explicitly among
the roles for which the SDK SHALL NOT carry an Anuna endpoint "consulted when
the application profile is missing or unhealthy." An Anuna node a developer
*chooses and declares* is permitted by the Infrastructure promise; the same node
reached because a profile failed to name one is exactly what that requirement
forbids. Implementations SHALL NOT special-case this or any other operator, and
SHALL NOT substitute it when a declared resolver is unreachable.

Listing several resolvers costs nothing beyond the requests themselves.
`CON-210` submission is parallel and best-effort, and `did:crdt` merge is
commutative, associative, and idempotent, so the same delta arriving at one node
by several paths converges to the same state. Redundant delivery is the intended
behaviour, not an overhead to minimise.

`pairingRecordRelays` is an OPTIONAL array of canonical HTTPS origins serving
[[PROTO-003-selfsame-pairing-v1#CON-409]] records. Each entry uses the canonical
origin grammar in [[PROTO-002-selfsame-rendezvous-v1#CON-301]] and MUST be
unique. A production application SHOULD declare at least two independently
operated entries.

These are tier-1 and tier-3 transports under
[[PROTO-003-selfsame-pairing-v1#ADR-410]], not trust anchors: a relay serves
self-authenticating signed records, so it can withhold one but never substitute
one, and CON-409's checks do not weaken when a record arrives from any of them.
A resolving party MAY cache these origins across ceremonies and query the
accumulated set on a later first encounter with an unrelated application. Their
absence does not disable pairing — the ladder degrades to the distributed hash
table and then to the person supplying this application's origin, which is
already required for the profile fetch.

`revocation.maxGrantLifetimeSeconds` is REQUIRED, is a positive integer, and
MUST NOT exceed 2,592,000. It bounds `validUntil - validFrom` under
[[SPEC-004-application-scoped-identity#REQ-208]] and is enforced at CON-206 step 11.

`revocation.propagationSlaSeconds` is REQUIRED, a positive integer, and MUST NOT
exceed 300. `revocation.maxClosureAgeSeconds` is REQUIRED, a positive integer,
and MUST NOT exceed 3,600. When `revocation.projection` is present its
`maxAgeSeconds` is REQUIRED, a positive integer, and MUST NOT exceed 3,600. A
verifier SHALL reject a profile exceeding any ceiling. Defaults and the composed
revocation-latency bound they produce are recorded in [[SPEC-004-application-scoped-identity#OQ-201]].

`revocation.method` MUST equal `did-crdt-revocations-v1` in profile version 1.
The `projection` member is OPTIONAL. Its absence disables Bitstring projection
without disabling issuance or revocation. If present, its URLs identify only
allocation and publication hosts: the application-account home DID remains the
status-list credential issuer and authority under CON-210.

For hashing in CON-209 and PROTO-003, the canonical descriptor bytes are the
RFC 8785 JSON Canonicalization Scheme serialization of the complete rendezvous
descriptor, including all three pairing fields.

Implements: [[SPEC-004-application-scoped-identity#REQ-202]], [[SPEC-004-application-scoped-identity#REQ-209]], [[SPEC-004-application-scoped-identity#REQ-210]], [[SPEC-004-application-scoped-identity#REQ-214]].

Verified by: [[SPEC-004-application-scoped-identity#TEST-203]], [[SPEC-004-application-scoped-identity#TEST-214]], [[SPEC-004-application-scoped-identity#TEST-216]], [[SPEC-004-application-scoped-identity#TEST-220]].

### CON-202: Application and account key hierarchy

Definitions:

```text
UTF8(s)      = UTF-8 encoding of Unicode string s
U32BE(n)     = four-byte unsigned big-endian encoding of n
LP(s)        = U32BE(len(UTF8(s))) || UTF8(s)
SALT         = SHA-512(UTF8("selfsame/application-account-key-hierarchy/v2"))

KDF(ikm, label, context, length) =
  HKDF-SHA-512(
    IKM  = ikm,
    salt = SALT,
    info = LP(label) || LP(context),
    L    = length
  )
```

**Hierarchy version 2.** The salt names the hierarchy version, so a change to
the version makes every derived key unrelated to every key of the previous
version. This is deliberate: it removes any possibility of a partial version
bump, in which some nodes move and others do not. A version is adopted or it is
not; there is no intermediate state a defect could produce.

*Read "hierarchy version" as a distinct counter from this document's version.*
Elsewhere "version 1" names the **specification**; here and in
[[SPEC-004-application-scoped-identity#ADR-223]] and
[[SPEC-004-application-scoped-identity#TEST-244]] it names the **derivation
tree**, which moved to 2 in specification version 0.14.0 while the
specification itself remains version 1. The two counters are independent and a
future specification version will not move the hierarchy unless it says so in
this contract.

The recovery input is the **hierarchy root**, a value derived for this
hierarchy and used for nothing else:

```text
bip39_seed = PBKDF2-HMAC-SHA512(
  password   = NFKD(mnemonic sentence),
  salt       = UTF8("mnemonic") || UTF8(NFKD(passphrase)),
  iterations = 2048,
  L          = 64
)

hierarchy_root = HKDF-SHA-512(
  IKM  = bip39_seed,
  salt = "",                                          ; zero-length, RFC 5869 §2.2
  info = UTF8("selfsame/v2/hierarchy-root/") || U32BE(persona),
  L    = 64
)
```

The salt is a zero-length string. RFC 5869 §2.2 sets the salt to
`HashLen` zero octets when it is absent, so "absent" and "zero-length" name one
value; implementations differ in which spelling their API exposes, and this
contract fixes the spelling so two of them cannot disagree.

**Both remaining inputs are constants of the hierarchy version, not parameters.**
Hierarchy version 2 uses the empty BIP-39 passphrase and `persona = 0`.
Admitting another value for either is a hierarchy version bump, for the reason
given above: the derived tree changes wholesale, so a version that admitted two
personas would be two trees under one name.

`persona = 0` is fixed here rather than carried because a wallet restored from a
recovery phrase holds no per-account state from which to learn one, and asking
the person for a number is exactly the configuration
[[SPEC-004-application-scoped-identity#REQ-217]] and
[[SPEC-004-application-scoped-identity#ADR-210]] refuse. It appears in the
`info` as `U32BE(0)` so that a later version admitting a second persona is a
change of value in an encoding that already exists, rather than a change of
shape. Until such a version exists, no party stores, transmits, or selects a
persona index, and neither the passphrase nor the persona is a recorded
per-account value.

**`hierarchy_root` is a sibling of the SPEC-001 persona root, not its child.**
Both descend from `bip39_seed` by HKDF-SHA-512 under different `info` labels,
and neither is derivable from the other. This hierarchy therefore consumes no
SPEC-001 construction, defines no shared secret with it, and imposes no
key-separation obligation: `hierarchy_root` is HKDF input keying material and
nothing else, in this contract and in every other.

Hierarchy version 1 rooted at `bip39_seed` directly.
[[SPEC-004-application-scoped-identity#ADR-223]] records why that changed, what
it costs, and why no migration path from version 1 is defined.

**What a custodian must hold.** A conforming custodian SHALL retain
`hierarchy_root` — sealed under whatever protection it applies to other
long-lived secrets — and SHALL NOT be required to retain the mnemonic or
`bip39_seed` in order to derive. `hierarchy_root` is a one-way function of the
seed, so a custodian holding it can derive every account below it and cannot
recover the phrase, the seed, or any sibling root. This is the property the
version-2 root exists to provide and it is normative: a wallet that can derive
only while the person is re-entering their recovery phrase does not conform.

After validating `canonical_account_scope_id` with CON-211, the hierarchy is:

```text
application_node =
  KDF(hierarchy_root, "application", canonical_application_id, 64)

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
- Unicode mnemonic normalization;
- rejection of non-canonical application IDs and account scopes;
- the intermediate `hierarchy_root` for each vector mnemonic, so a second
  implementation can locate a divergence above or below the root rather than
  only observing that the home DID differs; and
- the same mnemonic and application under two persona indices, which SHALL
  produce unrelated home DIDs. This vector exercises the `info` encoding, not a
  deployable configuration: `persona = 0` is the only index
  [[SPEC-001-device-key-provisioning]] defines, and a vector is the one place a
  second implementation can check the encoding before another index exists.

Implements: [[SPEC-004-application-scoped-identity#REQ-201]], [[SPEC-004-application-scoped-identity#REQ-213]], [[SPEC-004-application-scoped-identity#REQ-216]].

Verified by: [[SPEC-004-application-scoped-identity#TEST-201]], [[SPEC-004-application-scoped-identity#TEST-202]], [[SPEC-004-application-scoped-identity#TEST-219]], [[SPEC-004-application-scoped-identity#TEST-222]], [[SPEC-004-application-scoped-identity#TEST-244]].

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
2. compute `acct_uri` from `home_did` and apply a root-signed DID
   document-data update that sets `alsoKnownAs` to that URI.

Provisioning `acct_uri` at the account authority is a third, independent step
owned by [[SPEC-004-application-scoped-identity#CON-204]]. It may precede or
follow step 2, because step 2 is a controller assertion and provisioning is
what a verifier actually checks.

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

Implements: [[SPEC-004-application-scoped-identity#REQ-203]].

Verified by: [[SPEC-004-application-scoped-identity#TEST-204]], [[SPEC-004-application-scoped-identity#TEST-205]], [[SPEC-004-application-scoped-identity#TEST-224]].

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

Ordering depends on where the home controller sits.

**When the SDK is in process with the application** — the second-application
and account-switch paths — the SDK derives the home DID, hands it to the
application, and the application provisions before either the
`SetDocumentData` update or the first grant is signed. This is the preferred
order because it never produces a grant that no verifier can accept.

**When the home controller is a remote or same-device wallet** — every
[[PROTO-003-selfsame-pairing-v1]] ceremony — the wallet MAY sign the
`SetDocumentData` update publishing the deterministic alias and MAY issue a
device grant naming it before the authority holds a record. The application
then, on opening the CON-219 bundle and before attempting acceptance:

1. reads `issuer` from the grant and recomputes the expected localpart under
   [[SPEC-004-application-scoped-identity#CON-203]];
2. requires the grant's `credentialSubject.account` to equal that recomputed
   URI exactly, rejecting the grant outright on any mismatch;
3. provisions the account record and publishes the reciprocal JRD; and
4. only then runs [[SPEC-004-application-scoped-identity#CON-206]].

No authority is conferred by the earlier ordering. Between issuance and
provisioning the grant exists but is unusable, because CON-206 step 9 fails
closed on the missing binding. A verifier SHALL NOT relax step 9 on the grounds
that the grant is newly issued, and SHALL NOT cache a negative result in a way
that prevents acceptance once provisioning completes.

If provisioning or reciprocal publication cannot complete, the application
SHALL return `AccountProvisioningFailed`, SHALL NOT retry acceptance, and
SHALL revoke the exact grant ID under
[[SPEC-004-application-scoped-identity#CON-210]] or, when it cannot reach the
home controller to do so, SHALL record the grant ID as never-accepted and rely
on `validUntil`. It SHALL NOT ask the person to repair the alias, and SHALL NOT
present an unprovisioned alias as an active identity.

On any failure the SDK leaves the account scope, home key, DID keys, other
grants, and revocation state unchanged.

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

Implements: [[SPEC-004-application-scoped-identity#REQ-203]], [[SPEC-004-application-scoped-identity#REQ-204]].

Verified by: [[SPEC-004-application-scoped-identity#TEST-205]], [[SPEC-004-application-scoped-identity#TEST-206]].

### CON-205: Selfsame Device Grant Credential

The immutable context identifier is:

```text
https://anuna.io/selfsame/credentials/device-grant/v1
```

Ownership, publication, the pinned content digest, and succession are fixed by
[[SPEC-004-application-scoped-identity#CON-224]], which also states why the
digest rather than the origin is the authority. The context at this identifier
is immutable. The logical context defines:

```json
{
  "@protected": true,
  "SelfsameDeviceGrantCredential":
    "https://anuna.io/selfsame/vocab/device-grant/v1#SelfsameDeviceGrantCredential",
  "application": {
    "@id": "https://anuna.io/selfsame/vocab/device-grant/v1#application",
    "@type": "@id"
  },
  "account": {
    "@id": "https://anuna.io/selfsame/vocab/device-grant/v1#account",
    "@type": "@id"
  },
  "permissions": {
    "@id": "https://anuna.io/selfsame/vocab/device-grant/v1#permissions",
    "@type": "@id",
    "@container": "@set"
  },
  "SelfsameDidCrdtStatusEntry": {
    "@id":
      "https://anuna.io/selfsame/vocab/device-grant/v1#SelfsameDidCrdtStatusEntry",
    "@context": {
      "@protected": true,
      "id": "@id",
      "type": "@type",
      "statusPurpose":
        "https://www.w3.org/ns/credentials/status#statusPurpose",
      "credentialId": {
        "@id": "https://anuna.io/selfsame/vocab/device-grant/v1#credentialId",
        "@type": "@id"
      }
    }
  }
}
```

`statusPurpose` and `credentialId` are scoped inside
`SelfsameDidCrdtStatusEntry` rather than declared at the top level. The scoping
is required, not stylistic: the W3C v2 context defines `statusPurpose` only
inside `BitstringStatusListEntry` and `BitstringStatusList`, so a
`SelfsameDidCrdtStatusEntry` carrying that member would otherwise use an
undefined term and fail the conformance REQ-205 asserts and the unknown-entry
rejection NFR-204 requires. `statusPurpose` deliberately reuses the W3C status
IRI so the two entry types agree on what the term means.

`aud` and `cnf` need no declaration here. Both are defined at the top level of
`https://www.w3.org/ns/credentials/v2`, `cnf` with its own scoped context
covering `kid` and `jwk`, so the payload members in CON-205 are already
context-defined by the base context this credential includes first.

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
    "https://anuna.io/selfsame/credentials/device-grant/v1"
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
- MUST set `account` to the stable opaque RFC 7565 alias computed from the
  issuer DID under [[SPEC-004-application-scoped-identity#CON-203]], never the
  optional human-readable alias; the issuer computes this value deterministically
  and a verifier requires it to be reciprocally bound at CON-206 step 9, not at
  issuance time;
- MUST contain a non-empty set of permission URIs declared by the profile;
- MUST contain exactly one `SelfsameDidCrdtStatusEntry`, with matching
  `status_id`, `credentialId`, issuer DID, and grant token;
- MAY additionally contain exactly one `BitstringStatusListEntry` when the
  profile enables the CON-210 projection; in that case `credentialStatus` is
  an array with the Selfsame entry first and Bitstring entry second;
- MUST use XML Schema `dateTimeStamp` values normalized to UTC `Z`; and
- MUST make the `cnf.jwk` key equal the Ed25519 key encoded by the device DID.

Implements: [[SPEC-004-application-scoped-identity#REQ-205]], [[SPEC-004-application-scoped-identity#REQ-206]], [[SPEC-004-application-scoped-identity#REQ-208]].

Verified by: [[SPEC-004-application-scoped-identity#TEST-207]], [[SPEC-004-application-scoped-identity#TEST-208]], [[SPEC-004-application-scoped-identity#TEST-212]].

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
   authenticated cache of that exact binding. This step is the sole gate on
   alias provisioning: a deterministically named but unprovisioned alias fails
   closed here, whatever order issuance and provisioning happened to take.
10. Enforce `revocation.maxClosureAgeSeconds` on the causally valid closure and
    require its revocation G-Set not to contain the exact VC `id`, using
    `Document::is_revoked` or the pinned method-equivalent check. If an
    optional Bitstring projection is present, a valid set bit also rejects the
    grant; an unset, stale, invalid, or unavailable projection never bypasses
    the CRDT check.
11. Require current time to be within `[validFrom, validUntil)`, allowing only
    the application's explicitly configured clock-skew bound, and independently
    require `validUntil - validFrom` not to exceed the profile's
    `maxGrantLifetimeSeconds`. A grant whose lifetime exceeds the bound is
    rejected even while it is otherwise within its validity window.
12. Require every permission to be declared by the embedded profile and by the
    local operation being attempted.
13. Run the device proof-of-possession challenge in CON-207.

Authorization succeeds only if every step succeeds. Diagnostic detail MAY be
logged locally but externally visible errors SHOULD collapse to a small stable
set so that attackers do not gain a credential oracle.

#### Freshness tiers at step 10

Step 10's bound is not one number, because the two things a verifier does with
a grant carry different costs when the answer is stale:

- **Session establishment** — the first acceptance of a given grant ID by this
  verifier, and any acceptance that begins a new authenticated session — uses
  `min(maxClosureAgeSeconds, propagationSlaSeconds)`. Where any declared
  `stateResolvers` entry is reachable, the closure SHALL be resolved from one
  rather than taken from the CON-219 bundle or a cache.
- **Continuation** — re-verification inside a session this verifier already
  established — uses `maxClosureAgeSeconds`.
- A verifier that cannot determine which case applies SHALL use the
  session-establishment bound. A verifier whose record of an accepted grant ID
  is lost or unreadable SHALL treat the next acceptance as establishment.

Both bounds are derived from members `CON-201` already defines, so this
resolves [[SPEC-004-application-scoped-identity#OQ-201]]'s first narrow
question without adding a profile member, changing `profileVersion`, or
invalidating a published vector.

The split is where the cost sits. Session establishment is interactive and
online by construction — a ceremony just completed or the person just signed
in — so strictness is nearly free there, and it is exactly the moment a stolen
device whose grant was revoked minutes ago tries to obtain new authority. A
revoked device therefore cannot start a new session more than
`propagationSlaSeconds + min(maxClosureAgeSeconds, propagationSlaSeconds)`
after the revocation was submitted: 120 seconds at the defaults, 600 at the
ceilings. Continuation is where a fifteen-minute resolver outage would
otherwise sever every live session, and where the marginal security of a
tighter bound is small because the session was already authorized against
fresh state.

The resolver preference is a separate point and load-bearing. A closure taken
from the bundle is the **issuer's own account of its own revocations**, and the
issuer is precisely the party a revocation constrains; an issuer that omits its
own `RevokeCredential` deltas produces a closure that is internally valid and
materially incomplete. A verifier MAY rely on the bundle-supplied closure only
when it is accepting a grant ID for the first time and no declared resolver is
reachable, and SHALL record that it did so. It is a bootstrap for a first
ceremony on a degraded network, not a standing arrangement.

Implements: [[SPEC-004-application-scoped-identity#REQ-205]], [[SPEC-004-application-scoped-identity#REQ-207]], [[SPEC-004-application-scoped-identity#REQ-208]].

Verified by: [[SPEC-004-application-scoped-identity#TEST-211]], [[SPEC-004-application-scoped-identity#TEST-212]], [[SPEC-004-application-scoped-identity#TEST-240]].

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

Implements: [[SPEC-004-application-scoped-identity#REQ-206]].

Verified by: [[SPEC-004-application-scoped-identity#TEST-209]], [[SPEC-004-application-scoped-identity#TEST-210]].

### CON-208: Pairing-capable rendezvous provider selection

For one link attempt, the initiator:

1. reads the authenticated embedded profile;
2. rejects expired, malformed, non-HTTPS, unsupported-protocol, or
   locally-forbidden descriptors;
3. groups remaining descriptors by ascending numeric `priority`;
4. probes both pairing and mailbox capabilities for all descriptors in the
   lowest-priority group concurrently with a per-probe deadline of at most
   1500 ms;
5. forms the eligible set only from descriptors whose pairing fields and
   response pass [[PROTO-003-selfsame-pairing-v1#CON-401]] and whose mailbox
   base URL and response pass
   [[PROTO-002-selfsame-rendezvous-v1#CON-301]];
6. selects one eligible descriptor by cryptographically random weighted choice,
   where zero weight means ineligible;
7. if none are eligible, repeats steps 4–6 with the next priority group; and
8. if every group fails, returns `NoEligibleRendezvous`.

Health responses are hints, not trust anchors. A descriptor supplies one
profile-local route covering its bound pairing and mailbox services; the two
URLs may have different operators. All ceremony confidentiality and
authenticity remain end-to-end.

Selection MUST NOT use a stable user identifier, home DID, `acct:` URI, device
key, or recovery-derived value as the random input. Doing so would create
provider-visible cohorts.

Implements: [[SPEC-004-application-scoped-identity#REQ-209]], [[SPEC-004-application-scoped-identity#REQ-219]].

Verified by: [[SPEC-004-application-scoped-identity#TEST-214]], [[SPEC-004-application-scoped-identity#TEST-215]], [[SPEC-004-application-scoped-identity#TEST-226]].

### CON-209: Authenticated provider hint

The link ceremony SHALL bind this logical value:

```json
{
  "applicationId": "https://photos.example/selfsame/application",
  "profileVersion": 1,
  "providerId": "au-primary",
  "descriptorDigest": "<base64url SHA-256 of canonical descriptor>",
  "offerDigest": "<the CON-219 offerDigest>"
}
```

`offerDigest` is exactly the value defined by
[[SPEC-004-application-scoped-identity#CON-219]]. Because the hint is one of
the two members CON-219 excludes from `offer_core`, placing the digest here
creates no cycle: the hint commits to the offer, and the offer does not commit
to the hint.

The provider hint MUST be confidential inside the sealed offer defined by
[[SPEC-004-application-scoped-identity#CON-219]] and
[[PROTO-004-selfsame-ceremony-envelope-v1#CON-502]], and is authenticated by
that envelope's tag over additional authenticated data containing the PROTO-003
`binding_hash`. Before that offer exists, the PROTO-003 binding already commits
both clients to the application ID, profile digest, provider ID, complete
descriptor digest, route, and nameplate.

The hint SHALL NOT contain `accountScopeId`. The transcript-bound offer digest
and encrypted grant bind the ceremony to the expected RFC 7565 account without
disclosing the private derivation selector to the rendezvous provider.

The provider hint's concrete carrier is the sealed offer opened under the
confirmed PAKE-derived envelope key. Provider discovery itself uses the
logical bootstrap and profile-local route in
[[SPEC-004-application-scoped-identity#CON-216]]. A global provider directory
and an endpoint inside the human words are not carriers.

The rejection of a **secret-derived discovery record** recorded here was correct
for a 22-bit code, where the address would be enumerable and a payload encrypted
under the code would be recoverable offline. It is reopened by
[[PROTO-003-selfsame-pairing-v1#ADR-407]], which derives the address from a
128-bit code and therefore does not have either property.
[[PROTO-003-selfsame-pairing-v1#CON-409]] is the carrier.

The joiner verifies:

- exact application ID;
- a supported profile version;
- provider ID selected by the route in its origin-authenticated profile;
- descriptor digest equal to its local descriptor;
- offer digest equal to the offer it is processing; and
- PROTO-003 binding and confirmation before deriving or using a mailbox slot.

Implements: [[SPEC-004-application-scoped-identity#REQ-212]].

Verified by: [[SPEC-004-application-scoped-identity#TEST-218]], [[SPEC-004-application-scoped-identity#TEST-226]].

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
   resolver — including the application's own node where it declares one — and
   to every directly connected peer.

Submission is best-effort and parallel. A failed or unacknowledged submission to
any one resolver SHALL NOT abandon the revocation, discard the delta, or cause
the controller to report success; the delta is retained and retried until a
verified closure confirms it. A controller SHALL NOT treat delivery to the
application's own node as a substitute for submission to the other declared
resolvers, because a grant may be verified by a peer or by another device.

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
valid G-Set entry.

Where the application declares its own node, submission delivers the delta
directly to the party that enforces it, which is the strongest available answer
to withholding: the verifier no longer depends on a third party choosing to
tell it. This does not make that node authoritative — the controller's signed
state remains the source of truth, and the node admits the delta only after the
same `did:crdt` checks any replica performs.

Accepting deltas at an application endpoint is safe because the operation is
**monotone**: the revocation set is grow-only, deltas are signed by the home
key, and no method operation can clear an entry. A forged delta fails the
signature check, a replayed delta is idempotent, and the worst an accepted
delta can do is revoke — which reduces authority and therefore fails safe. This
is one of the few endpoints in the profile where an unauthenticated write is
tolerable, and the reasoning SHOULD be re-checked against any future method
operation that is not grow-only.

Resolver diversity, direct application delivery, and
`revocation.propagationSlaSeconds` bound availability. `CON-201` fixes the
ceilings, [[SPEC-004-application-scoped-identity#OQ-201]] records the defaults
and the composed latency they produce, and human ratification of those defaults
is a Tier-1 gate item rather than an open design question.

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
- it carries both `validFrom` and `validUntil`, and `validUntil - validFrom`
  does not exceed `revocation.projection.maxAgeSeconds`, so its cache lifetime
  cannot exceed that bound either.

The `validUntil` invariant is what makes the freshness bound enforceable by the
parties it constrains. A generic consumer applying nothing but W3C VC validity
rules already rejects an over-age projection, because the publisher was
forbidden from signing one whose window exceeds `maxAgeSeconds`. Expressing the
bound as Selfsame-specific policy instead would have made it advisory to
exactly the consumers it exists for.

**What a generic consumer may infer.** The revocation set is grow-only and no
method operation clears an entry, so the two bit values are not symmetric and
must not be read as though they were:

- a **set** bit is permanently true. No later state can unset it, so age never
  makes it wrong and a consumer MAY act on it whatever the projection's age.
- an **unset** bit is a claim about the world at `validFrom`, and it decays.
  Past `validUntil` a consumer SHALL treat the projection as **unavailable**,
  never as evidence of non-revocation.

There is no third reading for a projection whose age falls between
`revocation.projection.maxAgeSeconds` and `revocation.maxClosureAgeSeconds`,
because the two bounds do not govern the same party. `maxAgeSeconds` bounds
what a generic consumer may rely on; `maxClosureAgeSeconds` bounds a Selfsame
verifier, which under CON-206 step 10 never relies on the projection at all. A
consumer that wants the CRDT bound has to resolve CRDT state and become a
Selfsame verifier. No projection, at any age, can deliver it. This resolves
[[SPEC-004-application-scoped-identity#OQ-201]]'s second narrow question.

An implementation can therefore create and sign the projection beside the
revocation delta, then publish it through an untrusted cache or CDN. Failure to
publish the projection does not undo the CRDT revocation. Selfsame verifiers
always apply CON-206 to fresh CRDT state. Generic VC consumers may process the
Bitstring entry according to that W3C standard and inherit its bounded
freshness tradeoff.

Status credentials SHOULD be stapled where practical. Fetchers SHOULD use
privacy-preserving caches or proxies rather than reveal individual
authorization events to the publication host.

Implements: [[SPEC-004-application-scoped-identity#REQ-208]].

Verified by: [[SPEC-004-application-scoped-identity#TEST-212]], [[SPEC-004-application-scoped-identity#TEST-213]], [[SPEC-004-application-scoped-identity#TEST-224]], [[SPEC-004-application-scoped-identity#TEST-240]].

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

Implements: [[SPEC-004-application-scoped-identity#REQ-216]], [[SPEC-004-application-scoped-identity#REQ-217]].

Verified by: [[SPEC-004-application-scoped-identity#TEST-222]], [[SPEC-004-application-scoped-identity#TEST-223]].

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

Implements: [[SPEC-004-application-scoped-identity#REQ-218]].

Verified by: [[SPEC-004-application-scoped-identity#TEST-225]].

### CON-213: Pairing and rendezvous protocol binding

For profile version 1, a rendezvous descriptor is recognized only when:

1. `protocol` is exactly `selfsame-rendezvous-v1`;
2. `url` is a canonical base URL under
   [[PROTO-002-selfsame-rendezvous-v1#CON-301]];
3. `pairingProtocol`, `pairingUrl`, and `pairingRoute` pass
   [[PROTO-003-selfsame-pairing-v1#CON-401]];
4. the descriptor passes expiry, local policy, priority, and weight checks in
   [[SPEC-004-application-scoped-identity#CON-208]]; and
5. bounded pairing and mailbox probes return capability objects accepted by
   [[PROTO-003-selfsame-pairing-v1#CON-401]] and
   [[PROTO-002-selfsame-rendezvous-v1#CON-301]].

The selected descriptor's exact `pairingUrl` is the only PAKE relay origin and
its exact `url` is the only mailbox origin for that ceremony. Clients perform
pairing under [[PROTO-003-selfsame-pairing-v1#CON-402]] through
[[PROTO-003-selfsame-pairing-v1#CON-408]], derive fresh offer and bundle slots
only after mutual confirmation, and perform all mailbox requests under
[[PROTO-002-selfsame-rendezvous-v1#CON-302]] through
[[PROTO-002-selfsame-rendezvous-v1#CON-308]]. They reject redirects,
credentials, cookies, content encoding, oversized responses, unrecognized
statuses, destructive-read semantics, and any attempt by the server to choose
another endpoint or protocol.

The authenticated hint in
[[SPEC-004-application-scoped-identity#CON-209]] binds the exact descriptor
digest, so a joiner never accepts a health response or redirect as a provider
substitution. If the selected provider fails after a pairing session is
allocated, a bootstrap is displayed, or any frame/slot request is sent, both
parties abandon its ceremony state. A newly selected descriptor receives new
words, number, session, role tokens, SPAKE2 ephemerals, mailbox secret, slots,
offer, ciphertext, and hint; no frame or mailbox record is copied.

A pairing/rendezvous descriptor supplies no DID-state, account-authority, or
status-projection endpoint. Those roles require their own profile descriptors
and protocols even when one operator or DNS origin implements several roles.

Implements: REQ-209, REQ-210, REQ-212, REQ-214, REQ-219, REQ-226, REQ-228,
REQ-229.

Verified by: TEST-214, TEST-215, TEST-216, TEST-218, TEST-220, TEST-226,
TEST-232, TEST-233, TEST-235.

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
  "offerDigest": "<the CON-219 offerDigest>",
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
CON-209, CON-211, and CON-219 grammars. `requestedPermissions` is sorted by
Unicode code point and is an exact subset of `allowedPermissions`. `expiresAt`
is later than `issuedAt` by at most 120 seconds. Both random identifiers decode
to exactly 32 bytes.

`offerDigest` is the value defined by
[[SPEC-004-application-scoped-identity#CON-219]], computed over `offer_core`
only. The backend therefore signs a digest of the offer's semantic content
before the offer is assembled and sealed, and this statement is one of the two
members CON-219 excludes from that digest. A statement whose `offerDigest`
covered the statement itself would be unsatisfiable; an implementation that
computes the digest over the complete offer payload MUST be rejected as
non-conforming rather than accommodated.

Every other member of this statement that also appears in `offer_core` —
`requestId`, `ceremonyId`, `applicationId`, `profileVersion`, `profileDigest`,
`accountScopeId`, `requestedPermissions`, `issuedAt`, and `expiresAt` — SHALL
be exact-string equal to its counterpart there, and `deviceKeyDigest` SHALL
equal the SHA-256 of the canonical `deviceKeyJwk` in `offer_core`.

`platformBindingId` selects one binding from the authenticated profile:

- Android uses `android:` followed by the exact package name and a SHA-256
  signing-certificate digest, including an explicitly declared certificate
  rotation set.
- Apple platforms use `apple:` followed by the Team ID, bundle ID, and the
  origin of an associated HTTPS return URI.
- Web-only applications use `web:` followed by the `applicationId` origin,
  declaring the manual cross-device path defined by
  [[SPEC-004-application-scoped-identity#CON-227]].

This contract fixes the values that must be authenticated;
[[SPEC-004-application-scoped-identity#CON-220]] fixes how the profile and its
signing key are obtained, and
[[SPEC-004-application-scoped-identity#CON-222]],
[[SPEC-004-application-scoped-identity#CON-223]], and
[[SPEC-004-application-scoped-identity#CON-227]] fix the platform evidence. A
production wallet cannot treat a profile and key delivered only by the caller
as authenticated.

The compact JWS appears only inside the sealed ceremony offer defined by
[[SPEC-004-application-scoped-identity#CON-219]]. The `accountScopeId`,
evidence JWS, and its private claims never appear in the OS handoff,
rendezvous plaintext, callback, URL, log, analytics, or consent label.

Before showing consent, Selfsame:

1. obtains the application profile through
   [[SPEC-004-application-scoped-identity#CON-220]] and verifies the profile
   digest;
2. verifies the compact JWS and resolves `kid` only from that authenticated
   profile, and records the profile's complete
   `enrollment.requestSigningKeys` set against this application account for the
   purposes of [[SPEC-004-application-scoped-identity#CON-225]];
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
  "offerDigest": "<same digest as CON-214>",
  "pairingBootstrap": {
    "version": 2,
    "c": "<base64url of the 16 octets of C>"
  },
  "returnUri": "https://photos.example/.well-known/selfsame/return"
}
```

The recognizer accepts exactly the first five members and the optional sixth
`returnUri` member, in the shown order, after the platform adapter has
delivered a typed value. It does not extract fields with regular expressions
or act on a partial parse. `pairingBootstrap` passes
[[PROTO-003-selfsame-pairing-v1#CON-402]]: it carries `c`, the sixteen octets of
the code, and never the word rendering. Application identity and provider
selection are not carried here and are resolved from
[[PROTO-003-selfsame-pairing-v1#CON-409]] like every other carrier, so the
handoff cannot become a second routing path. The inherited base64url,
offer-digest, and HTTPS URI grammars apply. When present, `returnUri` is exact-string equal to the URI in
CON-214, has no user information or fragment, and is declared by the
authenticated platform binding.

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

After dispatch, both apps run PROTO-003 through the selected `pairingUrl`.
Only after mutual confirmation do they derive the PROTO-002 mailbox slots.
The developer app then writes the encrypted offer and polls the bundle.
Selfsame applies CON-214 before consent and returns the grant only through the
encrypted rendezvous bundle. State deltas are submitted through the profile's
state resolver role, never through a pairing frame or `/rendezvous/{slot}`
record.

An optional platform return contains exactly:

```json
{
  "handoffVersion": 1,
  "ceremonyId": "<same identifier>",
  "outcome": "completed"
}
```

`outcome` is one of `completed`, `cancelled`, or `failed`. This object contains
no pairing code/bootstrap, word, token, PAKE/mailbox key, provider, profile
digest, offer digest, account scope, DID, alias, key, credential, ciphertext,
permission, or error detail. It is
accepted only to foreground a locally pending ceremony with the same
`ceremonyId`; it does not stop polling, supply grant data, or alter the
acceptance result.

Dispatch returns one of `WalletUnavailable`, `UnverifiedWalletTarget`,
`HandoffMalformed`, `HandoffAmbiguous`, `PlatformBindingMismatch`,
`UserDenied`, or `Dispatched`. Every result except `Dispatched`, and every
ambiguous post-dispatch condition, abandons the ceremony under REQ-225.
Installation/help UI is then offered separately with no ceremony value.

Implements: REQ-209, REQ-211, REQ-212, REQ-220, REQ-221, REQ-222, REQ-223,
REQ-224, REQ-225, REQ-226, REQ-227, REQ-229.

Verified by: TEST-218, TEST-227, TEST-228, TEST-229, TEST-230, TEST-231,
TEST-232, TEST-235.

### CON-216: Application obligations around the pairing bootstrap

Routing itself is owned by
[[PROTO-003-selfsame-pairing-v1#CON-409]], which is the single path for every
carrier and both initiation directions. This contract states only what an
adopting application owes around it.

**Before the code may be displayed by either party**, the application:

1. selects one descriptor under CON-208, with both capability probes passing;
2. obtains that provider's nameplate;
3. constructs the complete PROTO-003 binding from its authenticated profile and
   the selected descriptor;
4. obtains acknowledgement of the immutable `pA` write; and
5. publishes the CON-409 record naming its canonical `applicationId`, profile
   digest, `providerId`, and nameplate.

The application SHALL NOT render, or ask a person to convey, a pairing URL, a
mailbox URL, a route, a nameplate, or any value other than the twelve-word
rendering of `C`.

There is exactly one exception, and it is a last resort rather than a mode. When
every [[PROTO-003-selfsame-pairing-v1#CON-409]] transport tier has failed, the
resolving party MAY ask the person for the application's origin as tier 3, and
the application MAY display that origin to support it. A party SHALL attempt
tiers 1 and 2 first and SHALL NOT offer origin entry as an alternative to
resolution, a shortcut past it, or a default. Origin entry supplies only a
lookup key: the canonical `applicationId` still comes from the profile fetched
at that origin, and every CON-409 check applies unchanged.

Where the application displays the code,
it SHOULD also show its own authenticated origin as context for the person —
that display is a courtesy to the reader, never a protocol input, and the
resolving party ignores it.

**Where the wallet generates and displays the code** under
[[PROTO-003-selfsame-pairing-v1#ADR-408]], steps 1–5 happen after the person
carries `C` to the application, and the wallet polls the CON-409 address until
the record appears or the code expires. The wallet SHALL show the claimed
canonical `applicationId` and HTTPS origin, and obtain explicit pairing-target
approval before a nameplate claim or PAKE frame, because a wallet-generated code
carries none of the person's own session context. This approval is distinct from
downstream CON-214 application authentication and application-account consent.

**On resolution**, the resolving party performs
[[PROTO-003-selfsame-pairing-v1#CON-409]]'s ordered checks, obtaining the
profile through the origin-authenticated `applicationId` mechanism required by
[[SPEC-004-application-scoped-identity#OQ-207]] and requiring its RFC 8785
SHA-256 digest to equal the record's `profileDigest`.

A `providerId` matching zero or several descriptors, an unresolvable address, a
changed profile digest, descriptor, nameplate, or protocol, and a record that
fails signature or expiry each return a fresh-ceremony failure under CON-409's
error set. The resolving party never repairs, guesses, broadcasts, or falls
back, and never searches for a matching nameplate.

Implements: REQ-209, REQ-210, REQ-212, REQ-219, REQ-226, REQ-227.

Verified by: TEST-214, TEST-216, TEST-218, TEST-226, TEST-232, TEST-234,
TEST-235; [[PROTO-003-selfsame-pairing-v1#TEST-413]].

### CON-217: SPAKE2-to-mailbox composition

The application is PROTO-003 role A and Selfsame is role B. They execute the
closed state machine in
[[PROTO-003-selfsame-pairing-v1#CON-403]] through
[[PROTO-003-selfsame-pairing-v1#CON-407]]. Neither may display consent, derive
an application branch, request a mailbox slot, or send an offer/grant before
the confirmation required for its role succeeds.

After mutual confirmation, both derive `mailbox_secret_16` under
[[PROTO-003-selfsame-pairing-v1#CON-408]]. That value becomes the only
`secret_16` for PROTO-002 slot derivation and the only input, with
`binding_hash`, to the envelope keys in
[[PROTO-004-selfsame-ceremony-envelope-v1#CON-501]]. The application then seals
and writes the offer payload defined by
[[SPEC-004-application-scoped-identity#CON-219]]; the wallet reads it,
recognizes it under
[[PROTO-004-selfsame-ceremony-envelope-v1#CON-503]], applies CON-214, obtains
consent, and seals and writes the grant bundle.

The sealed transcript binds `binding_hash` as additional authenticated data,
and its payload binds the provider hint in CON-209, the `offerDigest` in
CON-219, ceremony/request IDs, application/account, device key, permission set,
and enrollment evidence. A valid PAKE confirmation is necessary transport
authentication but is never sufficient application authentication or
authorization.

Implements: REQ-211, REQ-212, REQ-219, REQ-221, REQ-222, REQ-226, REQ-228.

Verified by: TEST-217, TEST-218, TEST-226, TEST-227, TEST-228, TEST-229,
TEST-233, TEST-235.

### CON-218: Pairing failure and downgrade closure

Every condition enumerated by
[[PROTO-003-selfsame-pairing-v1#REQ-406]] or REQ-225/REQ-229 moves the local
ceremony directly to terminal `burned`. A burned ceremony accepts no new
frame, confirmation, profile, provider, carrier, callback, mailbox record, or
application evidence.

The following modes are not version-1 alternatives and return
`PairingDowngrade`:

- deriving an AEAD or mailbox secret directly from `C`, `wib`, or any rendering
  of the human code, bypassing SPAKE2;
- carrying a route, nameplate, provider, or application identifier inside the
  human code, or asking a person to convey an application identity;
- transporting the word rendering through a machine carrier instead of `C`;
- omitting either confirmation MAC;
- making the provider a SPAKE2 responder or password-verifier holder;
- using Hark/cbcl-bus transcript labels without Selfsame binding;
- treating the QR as an authoritative browser/custom-scheme URL;
- accepting a code by searching providers rather than resolving its
  [[PROTO-003-selfsame-pairing-v1#CON-409]] record; or
- changing provider or carrier while retaining any ceremony value.

The only retry transition is `burned -> new ceremony`, with every value listed
in REQ-229 regenerated.

Implements: REQ-223, REQ-225, REQ-226, REQ-227, REQ-228, REQ-229.

Verified by: TEST-229, TEST-230, TEST-232, TEST-233, TEST-234, TEST-235.

### CON-219: Ceremony offer and grant bundle payloads

Both ceremony records are sealed by
[[PROTO-004-selfsame-ceremony-envelope-v1#CON-502]] and recognized by
[[PROTO-004-selfsame-ceremony-envelope-v1#CON-503]]. This contract declares the
two payload member sets that PROTO-004 leaves to the enclosing profile, and the
digest rule that lets a developer backend commit to an offer it does not yet
hold.

For both roles, the declared nesting bound is 8 and the declared payload bound
is 69,607 octets. Every base64url value is canonical and unpadded; every
timestamp is an XML Schema `dateTimeStamp` normalized to UTC `Z`; every
inherited value obeys the grammar of the contract that defines it.

#### The offer payload

The application seals this object under `K_offer`:

```json
{
  "payloadVersion": 1,
  "role": "offer",
  "ceremonyId": "<base64url 32 random octets>",
  "requestId": "<base64url 32 random octets>",
  "applicationId": "https://photos.example/selfsame/application",
  "profileVersion": 1,
  "profileDigest": "<base64url SHA-256 of the RFC 8785 profile>",
  "accountScopeId": "<canonical private account scope>",
  "deviceDid": "did:key:<device>",
  "deviceKeyJwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "alg": "EdDSA",
    "x": "<base64url-no-padding raw 32-octet device public key>"
  },
  "requestedPermissions": [
    "https://photos.example/selfsame/application#device"
  ],
  "issuedAt": "2026-07-30T10:00:00Z",
  "expiresAt": "2026-07-30T10:02:00Z",
  "enrollmentEvidence": "<compact JWS defined by CON-214>",
  "providerHint": { "…": "the CON-209 object" }
}
```

The member set is exactly those fifteen names. `accountScopeId` conforms to
[[SPEC-004-application-scoped-identity#CON-211]]; `deviceKeyJwk` is the exact
key that CON-205 requires in `cnf.jwk`, and `deviceDid` encodes the same key;
`requestedPermissions` is a non-empty set, sorted by Unicode code point, that is
an exact subset of the profile's `allowedPermissions`; `expiresAt` is later than
`issuedAt` by at most 120 seconds.

#### `offer_core` and `offerDigest`

```text
offer_core  = the offer payload object with the members
              "enrollmentEvidence" and "providerHint" removed

offerDigest = BASE64URL-NOPAD(SHA-256(RFC8785(offer_core)))
```

`offer_core` is therefore the thirteen members from `payloadVersion` through
`expiresAt`. `offerDigest` is the digest defined by
[[PROTO-004-selfsame-ceremony-envelope-v1#CON-503]] over that named subset.

The two excluded members are exactly the two that carry `offerDigest`
themselves — the CON-214 enrollment evidence and the CON-209 provider hint.
Excluding them is what makes the digest well-defined: a digest computed over an
object containing itself has no fixed point, and version 1 does not attempt one.

The construction order is consequently fixed:

1. the application assembles `offer_core`;
2. it computes `offerDigest`;
3. its backend signs the CON-214 statement carrying that `offerDigest`;
4. the application builds the CON-209 hint carrying the same `offerDigest`;
5. the application assembles the complete offer payload and seals it.

On receipt, the wallet recomputes `offerDigest` from the `offer_core` members of
the payload it actually opened, and requires it to equal both the `offerDigest`
inside the verified enrollment evidence and the `offerDigest` inside the
provider hint. A mismatch in either returns `OfferMismatch` under
[[SPEC-004-application-scoped-identity#CON-214]].

The excluded members are not thereby unauthenticated: the PROTO-004 tag covers
the complete payload, and the CON-214 signature independently covers every
security-relevant `offer_core` value. `offerDigest` exists only so that a
backend which never sees the sealed record can still bind its signature to the
exact request that will be sealed.

#### The bundle payload

The wallet seals this object under `K_bundle`:

```json
{
  "payloadVersion": 1,
  "role": "bundle",
  "ceremonyId": "<the exact ceremonyId from the offer>",
  "requestId": "<the exact requestId from the offer>",
  "grantMediaType": "application/vc+jwt",
  "grant": "<the compact JWS verbatim, as an ASCII string>",
  "issuerClosure": "<base64url of a signed did:crdt closure, OPTIONAL>"
}
```

The member set is exactly those seven names, of which `issuerClosure` is the
only OPTIONAL one. `grantMediaType` is exactly `application/vc+jwt`.

`grant` carries the compact JWS **verbatim**, as the ASCII string it already is,
at most 65,536 characters. It is not re-encoded. A compact JWS under RFC 7515 is
three base64url segments separated by `.`, so every character is already
JSON-string-safe and requires no escaping; base64url-encoding it a second time
would expand 65,536 octets to 87,382 and exceed the payload bound by 17,771 —
which is why this contract says verbatim rather than encoded. That also
satisfies [[SPEC-004-application-scoped-identity#REQ-211]] more directly: the
bytes a verifier extracts are byte-identical to the bytes the issuer signed,
with no transformation in between.

The size budget is therefore:

```text
payload bound (PROTO-004 CON-502)                        69,607
  grant, at the CON-206 step 1 maximum                  -65,536
  fixed members and JSON syntax                    approx  -250
                                                   ─────────────
  remaining for issuerClosure                      approx 3,821
```

`issuerClosure`, when present, is the closure
[[SPEC-004-application-scoped-identity#CON-206]] step 4 may consume without a
state-resolver round trip. It is OPTIONAL precisely because that remainder is
small: an implementation whose closure does not fit SHALL omit it and let the
verifier resolve one, and SHALL NOT truncate either value. A payload exceeding
the bound is a `PayloadTooLarge` failure under
[[PROTO-004-selfsame-ceremony-envelope-v1#CON-504]], never a silent truncation.

The 65,536-character ceiling is a defensive bound inherited from CON-206 step 1,
not an expected size; a conforming grant is on the order of one to two kilobytes,
so both members fit comfortably in practice.

Bundle length is **not** observable metadata.
[[PROTO-004-selfsame-ceremony-envelope-v1#CON-502]] pads every sealed record to
exactly 69,632 octets, so whether this bundle inlines a closure — and how large
that closure is — is invisible to the rendezvous operator. That matters here
because closure size tracks a DID's delta history and would otherwise be a
per-account fingerprint. The four octets missing from the budget above relative
to the PROTO-002 record bound are the frame's length prefix.

A bundle SHALL NOT contain the account scope, the home key, a DID document, an
alias, a provider secret, an acceptance decision, or an error description.

#### Acceptance

The wallet SHALL NOT interpret an offer payload before
[[PROTO-004-selfsame-ceremony-envelope-v1#CON-503]] recognition succeeds, and
SHALL apply [[SPEC-004-application-scoped-identity#CON-214]] to the recognized
value before consent. The application SHALL NOT treat a bundle as an
authorization before recognition succeeds and
[[SPEC-004-application-scoped-identity#CON-206]] and
[[SPEC-004-application-scoped-identity#CON-207]] both pass. A `ceremonyId` or
`requestId` in a bundle that does not exactly equal the one this application
sealed into its offer is a rejection, not a new ceremony.

Implements: REQ-205, REQ-206, REQ-207, REQ-211, REQ-217, REQ-221, REQ-222,
REQ-223.

Verified by: TEST-217, TEST-228, TEST-229, TEST-231, TEST-236.

### CON-220: Application profile discovery

This contract closes OQ-207 item 1. It defines how a resolving party obtains an
application profile and binds it to the `applicationId` origin, so that the
enrollment-signing key in `CON-214` is never one the caller supplied.

**The identifier is the locator.** The profile is retrieved by dereferencing the
canonical `applicationId` itself:

```http
GET /selfsame/application HTTP/1.1
Host: photos.example
Accept: application/selfsame-profile+json
Accept-Encoding: identity
```

Using the identifier rather than a fixed well-known path is required by
[[SPEC-004-application-scoped-identity#ADR-201]], which contemplates one
developer hosting several security boundaries: a single well-known path would
permit only one application per origin.

A successful response is `200`, `Content-Type:
application/selfsame-profile+json`, and a body recognized under
[[SPEC-004-application-scoped-identity#CON-201]] as a closed language. The
resolving party SHALL:

1. require HTTPS with successful certificate validation;
2. **reject every redirect**, including same-origin — the `applicationId` is
   canonical, so a redirect means the identifier is wrong, not that the profile
   moved;
3. reject content encoding, a media type other than the one above, and a body
   over 65,536 octets;
4. run the complete CON-201 recognition before any semantic action;
5. require the profile's own `applicationId` member to equal the URI it
   dereferenced, exact ASCII; and
6. require its RFC 8785 SHA-256 digest to equal the `profileDigest` in the
   [[PROTO-003-selfsame-pairing-v1#CON-409]] record for this ceremony.

Step 6 is what makes the fetch trustworthy rather than merely encrypted. TLS
authenticates the origin; the record digest — asserted by a party holding `C` —
pins *which* profile that origin served. A host that serves a substituted
profile fails step 6. The two together are why no key ever comes from the
caller.

**Ordering under CON-409 tier 3.** When the person supplies an origin because
every transport tier failed, the profile is fetched before any record exists, so
step 6 cannot run yet. The resolving party SHALL fetch under steps 1–5, use only
`pairingRecordRelays` from it, resolve the record, and then apply step 6 against
the profile it already holds. A mismatch is a fresh-ceremony failure. The
profile is never used for anything else until step 6 passes.

**Origin enumeration, tier 3 only.** A typed origin is not an `applicationId`.
To map one to the other:

```http
GET /.well-known/selfsame/applications HTTP/1.1
```

returning `{"version": 1, "applications": ["https://photos.example/selfsame/application"]}`
— exactly two members, at most 32 entries, every entry an absolute HTTPS URI on
the queried origin and canonical under CON-201. A party SHALL use this endpoint
only for tier-3 recovery, SHALL present the resulting choice to the person when
more than one entry is returned, and SHALL NOT consult it on any other path.

**Cache and rotation.** A profile MAY be cached for at most 3,600 seconds and
SHALL be revalidated after that. `enrollment.requestSigningKeys` is an array, so
rotation is publication of a profile containing the new key, and revocation is
publication of one without the old key. The cache bound is therefore the window
in which a removed key remains usable, and it composes with `CON-214`'s
120-second evidence window: an attacker holding a revoked enrollment key has at
most the remaining cache lifetime, never indefinite use. A party SHALL evict a
cached profile immediately on any digest mismatch and SHALL NOT serve one whose
`validUntil`-bearing descriptors have all expired.

**Offline.** A cached profile within its bound MAY be used with no network
request. Beyond it, and with no network, the operation fails closed as
`UnverifiedApplication`; there is no stale-profile grace period, because the
enrollment key is exactly what staleness would put at risk.

Implements: [[SPEC-004-application-scoped-identity#REQ-222]],
[[SPEC-004-application-scoped-identity#REQ-227]].

Verified by: [[SPEC-004-application-scoped-identity#TEST-237]].

### CON-221: First-enrollment issuer confirmation

This contract closes OQ-207 item 4 and the
[[SPEC-004-application-scoped-identity#NFR-205]] contradiction identified in
[[SPEC-004-application-scoped-identity#ADR-220]].

**When it applies.** Exactly when the account authority holds no binding for the
authenticated application account — that account's first enrollment. The
application SHALL determine this from authority state, not from local cache, and
SHALL treat an unreachable authority as "unknown" and fail closed rather than
assume first use.

**What each side displays.** Let `fp = fingerprint_did(home_did)` under
[[SPEC-002-visual-key-fingerprint]]. The wallet, after deriving the home DID and
before writing the grant bundle, displays `Fingerprint::hex` of `fp` together
with its LifeHash. The application, after opening the bundle and before
provisioning the alias, displays the same two values computed from the grant's
`issuer`.

The person is asked to compare **the hex**. The LifeHash is a recognition aid
shown beside it and SHALL NOT be presented as the thing being compared:
[[SPEC-002-visual-key-fingerprint#REQ-103]] makes the hex the normative
comparison value, [[SPEC-002-visual-key-fingerprint#REQ-105]] forbids a picture
being alone on screen, and
[[SPEC-002-visual-key-fingerprint#ADR-107]] defers promoting the image pending
evidence about human discrimination.

**What follows.** On confirmation the application provisions the alias under
`CON-204` and proceeds to `CON-206`. On rejection, or on any timeout, it
SHALL NOT provision the alias, SHALL NOT accept the grant, SHALL create no
session, SHALL burn the ceremony under
[[SPEC-004-application-scoped-identity#REQ-229]], and SHOULD revoke the grant ID
under `CON-210` if it can reach a controller. Neither side SHALL offer a
"remember this" or "skip" affordance: the confirmation happens once per account
ever, and an affordance to skip it is an affordance to reinstate the
trust-on-first-use this contract removes.

**Subsequent enrollments.** No confirmation. The authority's binding is
authoritative, and a grant naming a different issuer is rejected under `CON-204`
before `CON-206` runs. An application SHALL NOT re-enter this contract to
"re-confirm" an account, because a prompt that can appear twice can be induced
to appear at an attacker's chosen moment.

**What it does and does not establish.** It establishes that the DID now bound
to this account is the one the person's wallet derived. It establishes nothing
about the wallet's provenance, build, or integrity, and it is not an
authentication of the wallet — see ADR-220 for why that is unavailable without
a registry.

Implements: [[SPEC-004-application-scoped-identity#REQ-222]],
[[SPEC-004-application-scoped-identity#REQ-230]].

Verified by: [[SPEC-004-application-scoped-identity#TEST-238]].

### CON-222: Android platform binding

This contract closes OQ-207 item 2. It is the Android instance of the adapter
[[SPEC-004-application-scoped-identity#CON-215]] requires, and it inherits every
prohibition there.

Minimum API level 30. Level 30 is the floor because package visibility filtering
and the maturity of verified App Links below it make both wallet discovery and
the return path unreliable in ways an application cannot detect.

**Discovering wallets.** The developer application declares a `<queries>` entry
for the wallet capability action and resolves it with `PackageManager` to obtain
the set of installed candidates. That query carries **no ceremony material** —
it names a capability and returns package names, nothing more. Where more than
one candidate exists the person selects; where none does, the result is
`WalletUnavailable` and an install action containing no ceremony value.

**Dispatch.** Delivery uses an **explicit** component intent to the selected
package. An implicit intent SHALL NOT carry ceremony material under any
circumstance, including when exactly one candidate resolves. Before dispatch the
adapter reads the target's signing identity with
`GET_SIGNING_CERTIFICATES` and records it; `hasSigningCertificate` with
`CERT_INPUT_SHA256` accommodates rotation. That identity is recorded for the
person's benefit and for post-hoc audit — it is **not** checked against a
registry, because none exists, which is precisely why
[[SPEC-004-application-scoped-identity#CON-221]] confirmation is required at
first enrollment.

**Caller identity.** The wallet obtains the calling package through the
`PendingIntent` creator, or `getCallingPackage()` where the invocation form
provides it, and compares it to the `platformBindingId` in the `CON-214`
evidence. A mismatch is `PlatformBindingMismatch`. A caller-supplied package
name in the payload is never evidence of anything.

**Return capability.** Any `PendingIntent` handed to the wallet SHALL be
`FLAG_IMMUTABLE` and `FLAG_ONE_SHOT`. Mutability would let the wallet inject
fields into the return; multi-use would let it replay one. Neither is permitted
even though `CON-215`'s return object carries no authority — defence in depth
costs nothing here.

**Return path.** A non-secret return MAY use a verified App Link on the
`applicationId` origin, with `android:autoVerify` and a
`/.well-known/assetlinks.json` entry. Failure to verify is failure: the adapter
SHALL NOT fall back to a browser, a custom scheme, or an unverified link.

Implements: [[SPEC-004-application-scoped-identity#REQ-220]],
[[SPEC-004-application-scoped-identity#REQ-223]],
[[SPEC-004-application-scoped-identity#REQ-225]].

Verified by: [[SPEC-004-application-scoped-identity#TEST-239]].

### CON-223: Apple platform binding

This contract closes OQ-207 item 3, and likewise inherits every `CON-215`
prohibition.

**Dispatch.** Delivery opens a Selfsame HTTPS Universal Link with
`UIApplication.OpenExternalURLOptionsKey.universalLinksOnly` set to `true`. When
no associated installed application can handle it, the completion handler
receives `false` and **that is the terminal result**. The adapter SHALL NOT then
open Safari, an embedded web view, an install page, or a custom URL scheme; per
Apple's own semantics the option exists so that absence is a dispatch failure
rather than a web navigation, and treating it otherwise would disclose the link
outside the permitted boundary.

**Association.** The wallet's associated-domain entry and its
`/.well-known/apple-app-site-association` file bind the Team ID and bundle ID in
`enrollment.mobileBindings`. The developer application's claimed HTTPS return
path is validated the same way on its own `applicationId` origin.

**Caller identity is weaker here, and the contract says so.** Apple provides no
general equivalent of Android's calling-package attribution for a Universal
Link open. The wallet therefore compares only what the platform genuinely
authenticates — the association between the return URI's origin and the
declared binding — and SHALL NOT treat any payload-supplied identifier as
caller evidence. The residual gap is closed by the `CON-214` backend signature
and by `CON-221` confirmation, not by the platform.

**Return path.** The optional return uses the claimed HTTPS path on the
`applicationId` origin, declared in the platform binding, and carries only the
closed three-member object in `CON-215`.

Implements: [[SPEC-004-application-scoped-identity#REQ-220]],
[[SPEC-004-application-scoped-identity#REQ-223]],
[[SPEC-004-application-scoped-identity#REQ-225]].

Verified by: [[SPEC-004-application-scoped-identity#TEST-239]].

### CON-224: Credential vocabulary and context governance

This contract closes [[SPEC-004-application-scoped-identity#OQ-202]]. It fixes
who owns the Selfsame credential vocabulary, what the normative artifact
actually is, and what happens when the naming origin changes hands.

**Identifiers.** For profile version 1 these two strings are fixed and appear
verbatim in every issued grant:

```text
context IRI     https://anuna.io/selfsame/credentials/device-grant/v1
vocabulary base https://anuna.io/selfsame/vocab/device-grant/v1#
```

**The normative artifact is the bytes, not the URL.** The context is the exact
octet sequence of `contexts/device-grant-v1.jsonld` in the `selfsame`
repository: UTF-8, no byte-order mark, LF line endings, at most 8,192 octets.
Define `context_digest = SHA-256(those octets)`. For version 1 the file is
1,045 octets and:

```text
context_digest =
  9dba4d065a9b7f54acbcfe8d75e1f2c8e7fe4ab8a4b87a4ad3f883c45a3d1183
```

That value is also recorded in the
[[SPEC-004-application-scoped-identity#CON-226]] corpus and in the changelog
entry of every amendment that changes it, which for version 1 means never. The
JSON-LD document wraps the logical context shown in
[[SPEC-004-application-scoped-identity#CON-205]] in a single `@context` member;
CON-205 shows the value, this file is the document.

**Nothing dereferences it during verification.**
[[SPEC-004-application-scoped-identity#ADR-209]] and
[[SPEC-004-application-scoped-identity#NFR-204]] already forbid
verification-time context loading, and this contract adds no exception. A party
that fetches the IRI for any other purpose SHALL compare the retrieved octets
to `context_digest` and, on mismatch, SHALL fail closed as `UnknownContext`. It
SHALL NOT use the retrieved bytes, prefer them to the pinned copy, or repair
the difference. An implementer who adds a fetch "for robustness" has added an
attack surface and removed none.

**Immutability.** The octets served at that IRI SHALL NEVER change. A change of
meaning is a new IRI ending `/v2` and a new `profileVersion`. Re-serving
different bytes at `/v1` is a specification violation regardless of who does
it, the steward included, because the term IRIs inside already-signed
credentials would silently acquire new definitions.

**Term IRIs are names, not locations.** A value under the vocabulary base
identifies a term. It need not resolve, and a party SHALL NOT dereference one
during verification.

**Stewardship.** The steward is Anuna Research. Transfer of stewardship is a
Tier-1 amendment recording the new steward, the effective date, and the
archival location. It SHALL NOT change any IRI: changing an IRI changes what
already-signed credentials mean, which is the one thing a stewardship transfer
must not do.

**Loss of the origin.** Because the digest is the authority and the octets are
archived in the repository and in at least one immutable public archive whose
content identifier is recorded at the gate, loss of `anuna.io` invalidates no
issued credential and changes no verification result. It removes a convenience
mirror. A successor MAY publish byte-identical octets elsewhere and record the
new mirror; it SHALL NOT mint a second IRI for the same terms.

**Hostile acquisition of the origin.** An acquirer can serve different octets.
That has no verification-time effect, because nothing fetches, and it is
detected by the digest comparison for any party that does. This is the whole
reason the digest rather than the domain is the authority, and it is why the
choice of origin is a durability and naming question rather than a security
one.

**Why this origin.** The identifier used through version 0.12.0 pointed at
`selfsame.dev`, a domain that resolved no NS records — the specification named
a domain the project did not hold, which is precisely what a durable identifier
must not be, since an unregistered name in a signed credential is a name
someone else can register. `anuna.io` is under project control today, so the
"prove control of a durable origin" half of OQ-202 is satisfied by inspection.
See [[SPEC-004-application-scoped-identity#ADR-221]] for why naming a
vocabulary after Anuna does not breach the Infrastructure promise.

**Operational duties**, all Tier-1 gate items rather than runtime requirements:
a registration of at least five years with expiry monitoring, DNSSEC, a CAA
record, an immutable public archival copy with a recorded content identifier,
and publication as `application/ld+json` with `Cache-Control: immutable`.

Implements: [[SPEC-004-application-scoped-identity#REQ-205]],
[[SPEC-004-application-scoped-identity#REQ-207]].

Verified by: [[SPEC-004-application-scoped-identity#TEST-241]].

### CON-225: Application identifier succession

This contract closes [[SPEC-004-application-scoped-identity#OQ-204]]. It
defines the only permitted way for an application account's home DID to be
replaced when the developer's canonical `applicationId` changes — through
domain loss, acquisition, or application merger.
[[SPEC-004-application-scoped-identity#ADR-222]] records the reasoning,
including why the succession is a bearer statement rather than a `did:crdt`
delta.

Version 1 defines no migration from any earlier derivation scheme; see
[[SPEC-004-application-scoped-identity#OQ-206]].

**The developer succession pointer.** The **outgoing** origin serves:

```http
GET /.well-known/selfsame/succession HTTP/1.1
Host: photos.example
Accept: application/jose
```

The body is a compact JWS over the exact RFC 8785 serialization of:

```json
{
  "successionVersion": 1,
  "from": "https://photos.example/selfsame/application",
  "to": "https://pictura.example/selfsame/application",
  "issuedAt": "2026-07-30T10:00:00Z",
  "expiresAt": "2026-10-28T10:00:00Z"
}
```

Closed protected header `alg`, `typ`, `kid`; `alg` is exactly `EdDSA` and `typ`
is exactly `selfsame-application-succession+jws`. `expiresAt - issuedAt` SHALL
NOT exceed 7,776,000 seconds — ninety days.

`kid` SHALL resolve in the `enrollment.requestSigningKeys` set **the wallet
recorded at this account's most recent successful enrollment** under CON-214
step 2, not in a set served now by any origin. This is the load-bearing rule.
Checking a currently-served key would make succession exactly as strong as a
domain registration, and a lapsed registration acquired by someone else is the
case OQ-204 was opened for. Checking a key the wallet pinned before the lapse
turns a DNS-strength control into a key-strength control using state the wallet
already holds. If the developer has rotated away every key the wallet pinned,
succession fails closed and the person enrolls a fresh identity: an
availability cost, never an authority one.

**The per-account succession statement.** A closed object, recognized exactly
as CON-201 recognizes a profile — unknown members at any depth are rejections,
not extension points:

```json
{
  "successionVersion": 1,
  "outgoing": "did:crdt:<outgoing application-account home>",
  "incoming": "did:crdt:<incoming application-account home>",
  "outgoingApplication": "https://photos.example/selfsame/application",
  "incomingApplication": "https://pictura.example/selfsame/application",
  "accountScopeId": "<canonical private account scope>",
  "issuedAt": "2026-07-30T10:00:00Z",
  "expiresAt": "2026-08-06T10:00:00Z"
}
```

The physical statement is **two** compact JWS values over byte-identical RFC
8785 payloads:

- the outgoing signature, `typ` exactly `selfsame-succession+jws`, `kid` the
  outgoing home DID's `assertionMethod`; and
- the incoming signature, `typ` exactly `selfsame-succession-countersign+jws`,
  `kid` the incoming home DID's `assertionMethod`.

Both are REQUIRED. A one-sided statement is rejected: the outgoing key alone,
if it leaked, could nominate an attacker's DID as successor, and the incoming
key alone could claim any predecessor's history. A person holding the recovery
secret can produce both and nobody else can produce either.

`expiresAt - issuedAt` SHALL NOT exceed the **incoming** profile's
`revocation.maxGrantLifetimeSeconds`. The overlap window is therefore bounded
by a member CON-201 already defines; version 1 adds no profile member and does
not change `profileVersion`.

**Order of operations.**

1. The application requests succession and supplies the developer pointer. A
   wallet SHALL NOT initiate succession.
2. The wallet verifies the pointer against its pinned key set. On failure it
   returns `SuccessionRejected` and discloses nothing — in particular, not
   whether it holds an outgoing identity for that application.
3. The wallet derives the incoming node and home key by an ordinary CON-202
   derivation, carrying the `accountScopeId` across unchanged. Only the
   application node differs, because only the `applicationId` changed.
4. The wallet displays the outgoing and incoming fingerprints under the
   [[SPEC-004-application-scoped-identity#CON-221]] display rules — the hex is
   what is compared, the LifeHash sits beside it — and the person confirms.
   Rejection or timeout ends the operation with nothing changed.
5. The wallet produces both signatures.
6. Ordinary enrollment proceeds for the incoming DID: alias publication,
   CON-204 provisioning, CON-206 acceptance.

**What a verifier does with it.** During `[issuedAt, expiresAt)` the
application MAY accept a grant whose `issuer` is `outgoing`, provided that:

1. both JWS verify over byte-identical payloads, with each `kid` resolving in
   its DID's `assertionMethod` from a closure meeting the CON-206 step 10
   session-establishment bound;
2. `incoming` equals the home DID the authority is being asked to bind, and
   `outgoing` equals the DID the authority currently binds for this account;
3. the developer pointer verifies as above and its `from`/`to` equal
   `outgoingApplication`/`incomingApplication`, with the incoming profile's own
   `applicationId` equal to `to`;
4. the person confirmed at step 4; and
5. `CON-206` then runs **unchanged** against the outgoing expectation — the
   grant's `credentialSubject.account` is the outgoing alias and its
   `application` and `aud` are the outgoing `applicationId`.

CON-206 is deliberately not amended. Succession changes which expectation a
verifier feeds the predicate, not the predicate.

**Alias handling.** An account holds exactly one stable alias, and succession
is the only operation that replaces it. The outgoing alias is tombstoned under
[[SPEC-004-application-scoped-identity#CON-212]]'s rule and SHALL NOT be
assigned to another account or DID. An optional human-readable alias MAY move
to the incoming DID by ordinary CON-212 rename.

**After the window.** The application SHALL accept only the incoming issuer.
The outgoing controller SHOULD revoke each old grant under CON-210 as its
device re-enrolls.

**Deactivation is last, and the order is normative.** The outgoing home DID
SHOULD be deactivated once succession is complete, but a controller SHALL NOT
deactivate it until every grant it issued has been revoked or has passed its
`validUntil`. The `did:crdt` deactivation latch is irreversible and rejects
**all** subsequent mutations, `RevokeCredential` among them, so deactivating
early strands any still-live grant in a state where it can never be revoked —
leaving expiry as the only remaining control, which is precisely the degraded
case [[SPEC-004-application-scoped-identity#REQ-208]] bounds rather than
accepts. A controller that cannot enumerate its outstanding grants SHALL NOT
deactivate.

**Prohibitions.**

- No chains. A statement whose `outgoing` is the `incoming` of another
  unexpired statement is rejected. Version 1 permits one hop; anything longer
  is re-enrollment. Chaining would let a compromised intermediate launder an
  account into a third identity.
- No publication. The statement SHALL NOT appear in `alsoKnownAs`, a WebFinger
  JRD, a status projection, a state-resolver record, a callback, a log, or
  analytics. It travels in the CON-219 bundle or the application's
  authenticated account channel and nowhere else. Publishing it is what would
  create the cross-application link [[SPEC-004-application-scoped-identity#NFR-201]]
  exists to prevent.
- No second source. A verifier SHALL NOT accept a statement received from any
  party other than the wallet or its own account authority.
- No silent migration, per [[SPEC-004-application-scoped-identity#REQ-202]],
  and no succession without the CON-221-shaped confirmation.

**Why this is a signed statement and not a `did:crdt` delta.**
[[SPEC-004-application-scoped-identity#CON-210]] says plainly that a standalone
signature does not revoke a grant, and a reader is right to ask why succession
gets to be one. The answer is that the two operations fail in opposite
directions:

- a **withheld revocation** means a dead grant keeps working. Withholding is
  the threat, so the state must be convergent and unsuppressable — hence the
  G-Set, the resolver diversity, and the freshness bound.
- a **withheld succession** means an old grant is simply not accepted. That is
  the fail-closed outcome, so no convergence is required to make it safe.

Convergent public state is mandatory where unavailability grants authority, and
merely convenient where unavailability withholds it. Publishing succession as a
delta would also defeat its privacy property: `SetDocumentData` lands in the
resolvable document, so the outgoing DID would announce its successor to every
party that resolves it — the same objection that rules out `alsoKnownAs` in
[[SPEC-004-application-scoped-identity#ADR-222]].

Succession still depends on `did:crdt` for the part that matters: each `kid`
must resolve in its DID's `assertionMethod` from a verified closure, so the
method decides which key may speak for either identity.

Every failure returns `SuccessionRejected` and leaves the outgoing identity,
its alias, its grants, its revocation state, the account scope, and every
session unchanged.

Implements: [[SPEC-004-application-scoped-identity#REQ-202]],
[[SPEC-004-application-scoped-identity#REQ-231]].

Verified by: [[SPEC-004-application-scoped-identity#TEST-242]].

### CON-226: Conformance vector corpus

This contract closes [[SPEC-004-application-scoped-identity#OQ-207]] item 5. It
converts "publish vectors" from an open question into a defined artifact with a
completeness rule that can fail.

**Location and shape.** The corpus is `test-vectors/spec-004-v1.json`, beside
the existing `test-vectors/spec-001-v1.json` and `test-vectors/lifehash-v2.json`
and following their convention: top-level `spec` and `did_crdt_revision`
members, then one member per contract named `con_2NN_<slug>` whose value is an
array of cases.

The filename's `v1` names the **corpus profile**, not the hierarchy version, and
since 0.14.0 the two differ: this file carries hierarchy-version-2 vectors. The
corpus SHALL therefore also carry a top-level `hierarchy_version` member, so a
consuming stack reads the tree it is being checked against rather than inferring
it from a filename. Values from a superseded hierarchy version SHALL be
**deleted** rather than retained beside the current ones — a void vector left in
the file is one an implementation eventually passes against.

Each case is:

```json
{
  "id": "con_206_step10_stale_closure",
  "description": "closure older than the session-establishment bound",
  "input": { },
  "expect": { "reject": "con_206_step_10" }
}
```

`expect` is either `{"accept": <value>}` or `{"reject": "<reason>"}`. A reason
is either the exact closed error token the relevant contract defines — such as
`EnrollmentReplay` from CON-214 or `SuccessionRejected` from CON-225 — or,
where the contract defines steps rather than tokens, the identifier
`con_<nnn>_step_<n>`. Requiring the reason, not merely a failure, is the point:
two stacks must agree on **which** check fired, or they have not implemented
the same predicate. CON-206 deliberately collapses its externally visible
errors so that an attacker gains no credential oracle; the corpus is an
internal conformance artifact and names the step regardless.

**Canonical form.** UTF-8, no byte-order mark, LF, and RFC 8785 canonical — a
conforming re-serialization reproduces the file byte for byte. Binary is
base64url without padding. Numbers are integers; no floats appear.

**Completeness rule.** For every closed error token defined by CON-204,
CON-211, CON-212, CON-214, CON-215, CON-219, CON-220, CON-221, CON-222,
CON-223, and CON-225, and for each of CON-206's thirteen numbered steps, the
corpus SHALL contain at least one case whose `expect.reject` names it. A token
or step with no case is a gate failure, not a documentation gap.

**Required groups.** One corpus, not two: it carries both the groups the Tier-1
gate already named — KDF, alias, VC, holder binding, revocation, account scope,
username — and the seven OQ-207 item 5 groups:

1. canonical JWS, positive and the TEST-208 negative corpus;
2. profile recognition under CON-201 and discovery under CON-220;
3. handoff traces, labelled per platform for CON-222 and CON-223, and
   `web-manual` traces for CON-227 — the web-manual traces are cross-device
   by construction, filed here for the caller-evidence dimension they share
   with the platform traces; web profile-recognition negatives belong to
   group 2, not here;
4. MITM substitution at each layer of the authorization chain;
5. replay of every one-time value;
6. application substitution, including a hostile sibling and a copied public
   profile; and
7. callback hijack and forged completion.

Cases outside group 3 SHALL NOT be platform-conditional.

**The corpus is normative.** Where the corpus and this document's prose
disagree, that is a defect resolved by amendment. The corpus SHALL NOT be
edited to match an implementation, and a case SHALL NOT be deleted or marked
skipped to make a suite pass. The file's SHA-256 is recorded in the changelog
entry of every Tier-1 amendment that changes it.

Implements: [[SPEC-004-application-scoped-identity#REQ-222]],
[[SPEC-004-application-scoped-identity#REQ-227]].

Verified by: [[SPEC-004-application-scoped-identity#TEST-243]].

### CON-227: Web manual binding

This contract closes the conflict named by
[[SPEC-004-application-scoped-identity#ADR-224]]. It is the third instance of
the platform-evidence family beside
[[SPEC-004-application-scoped-identity#CON-222]] and
[[SPEC-004-application-scoped-identity#CON-223]], for applications with no
native app on the enrolling person's platform.

**Declaration.** A web binding is the closed three-member object shown in
[[SPEC-004-application-scoped-identity#CON-201]]: `id`, `platform: "web"`, and
`origin`. `origin` MUST equal the profile's `applicationId` origin byte for
byte, and `id` MUST be exactly `web:` followed by that origin. A web binding
whose origin names anything else is a recognition failure of the whole
profile, not a skipped entry. At most one web binding may appear in a profile,
because a second could differ only by violating the origin rule.

**What it declares.** The ceremony reaches the wallet with **no OS-mediated
handoff at all**: the person scans the application's displayed QR from
another device or manually enters the code — the cross-device path this
document already defines. The binding is a profile-authenticated admission
that no platform will attribute a caller, made checkable instead of left
implicit.

**Caller identity is absent here, and the contract says so.** The wallet
accepts exactly unattributed caller evidence against a web binding, and SHALL
NOT treat any payload-supplied identifier as caller evidence. **Any**
platform-attributed caller — a calling package, an associated origin —
presented against a web binding is `PlatformBindingMismatch`: an OS-mediated
handoff claiming a manual binding is a contradiction, and refusing it keeps
every same-device dispatch on the strictly stronger
[[SPEC-004-application-scoped-identity#CON-222]] and
[[SPEC-004-application-scoped-identity#CON-223]] forms.

**The CON-215 adapter never selects a web binding.** Same-device handoff
requires an installed, verified wallet target; a web binding names none. An
adapter that can resolve only a web binding reports `WalletUnavailable`
exactly as it does when no binding resolves. Consequently
[[SPEC-004-application-scoped-identity#REQ-220]]'s no-self-scan promise is
scoped to applications that declare a native binding for the person's
platform; a web-only application's ceremonies are cross-device by
construction.

**The residual gap, and what closes it.** A web binding authenticates
strictly less than CON-222 and exactly as much as CON-223's unattributed
case: nothing about the carrier of the code. What closes the gap is what
closes it there — the [[SPEC-004-application-scoped-identity#CON-214]]
backend signature proves which application backend constructed the ceremony;
[[SPEC-004-application-scoped-identity#CON-221]] first-enrollment
confirmation puts a human comparison between a relayed code and an issued
grant; and the [[SPEC-004-application-scoped-identity#CON-219]] sealed offer
under the PAKE denies the code's carrier every ceremony secret. A deployment
whose threat model requires platform attribution declares native bindings and
omits the web form; the wallet enforces whatever the authenticated profile
declares.

**Delivery prohibitions are unchanged.**
[[SPEC-004-application-scoped-identity#REQ-223]] binds the manual path in
full: displaying the QR and accepting a paste introduce no new channel, and
nothing in this contract licenses clipboard, notification, log, or analytics
carriage of ceremony material.

**`returnUri` under a web binding.** The
[[SPEC-004-application-scoped-identity#CON-214]] statement's `returnUri`
member remains required, and this contract fixes its meaning here: it MUST be
an HTTPS URI on the `applicationId` origin, the wallet MUST NOT dispatch,
dereference, or navigate to it, and it carries no authority — there is no
OS return path on a manual ceremony, so the member exists only to keep the
statement grammar closed and to bind the origin one more time. A web-binding
statement whose `returnUri` names any other origin is
`EnrollmentMalformed`.

Implements: [[SPEC-004-application-scoped-identity#REQ-222]],
[[SPEC-004-application-scoped-identity#REQ-223]],
[[SPEC-004-application-scoped-identity#REQ-225]].

Verified by: [[SPEC-004-application-scoped-identity#TEST-246]].

## Test specifications

### TEST-201: Application separation

**Validates:** [[SPEC-004-application-scoped-identity#REQ-201]].

For one fixed recovery seed, one fixed canonical account scope, and 10,000
distinct canonical application IDs, derive 10,000 unique application nodes,
account nodes, home seeds, public keys, and DIDs. No pair is equal.

### TEST-202: Deterministic restore

**Validates:** [[SPEC-004-application-scoped-identity#REQ-201]].

Two independent implementations derive byte-identical application nodes,
account nodes, and home seeds from every normative vector.

### TEST-203: Application ID and profile canonicality

**Validates:** [[SPEC-004-application-scoped-identity#REQ-202]],
[[SPEC-004-application-scoped-identity#REQ-209]].

Accept the normative canonical URI corpus. Reject variants with upper-case
host, default port, user information, query, fragment, dot segment, Unicode
host, lower-case percent hex, or percent-encoded unreserved character.

Exercise the CON-201 profile recognizer as a closed language. Accept the
normative profile corpus and require `SHA-256(RFC8785(profile))` to agree across
two independent implementations. Reject: an unknown member at top level and at
each nested depth, a missing required member, a duplicate member name, a
byte-order mark, invalid UTF-8, a document over 65,536 octets, nesting past
depth 8, `profileVersion` other than `1`, an empty or over-length
`allowedPermissions`, a permission that is unsorted, duplicated, off-origin, or
lacking a fragment, `priority` or `weight` outside `[0, 65535]`, a
lowest-priority group whose weights are all zero, and any input that does not
re-serialize byte-for-byte. Assert zero semantic action on every rejection —
no probe, no derivation, no network request.

### TEST-204: `acct:` construction

**Validates:** [[SPEC-004-application-scoped-identity#REQ-203]].

For every home DID vector, reproduce the exact lower-case unpadded base32
localpart and complete RFC 7565 URI.

### TEST-205: Reciprocal alias

**Validates:** [[SPEC-004-application-scoped-identity#REQ-203]], [[SPEC-004-application-scoped-identity#REQ-204]].

Accept only when DID `alsoKnownAs`, WebFinger `subject`, WebFinger `aliases`,
the application profile authority, and VC account all match. Break each edge
individually and require rejection.

Exercise both CON-204 orderings for a first-ever enrollment of one account.
In the in-process order, provision before issuance and require acceptance. In
the remote-controller order, issue through a complete
[[PROTO-003-selfsame-pairing-v1]] ceremony first and assert that the grant is
**rejected** at CON-206 step 9 while the alias is unprovisioned, then
provision, then require the same unmodified grant bytes to be accepted. Require
no re-issuance, no new grant ID, no key change, and no DID change between the
two attempts.

Substitute an alias that is well-formed but not the CON-203 function of the
grant's `issuer` and require rejection before provisioning is attempted. Make
provisioning fail permanently and require `AccountProvisioningFailed`, a
revocation of the exact grant ID, no accepted session, and no retry of
acceptance.

### TEST-206: Account privacy

**Validates:** [[SPEC-004-application-scoped-identity#REQ-204]].

Generated DID, account, WebFinger, VC, status, and provider-hint fixtures
contain none of the fixture user's email, display name, phone number, global
account ID, `accountScopeId`, sibling scope, or application-A identifier.

### TEST-207: W3C VC positive vectors

**Validates:** [[SPEC-004-application-scoped-identity#REQ-205]].

Validate all W3C VC Data Model 2.0 and VC JOSE/COSE requirements exercised by
the profile, then verify the normative Selfsame grant vectors.

### TEST-208: JWS negative corpus

**Validates:** [[SPEC-004-application-scoped-identity#REQ-205]].

Reject `alg:none`, algorithm substitution, missing/relative/wrong `kid`,
unprotected algorithm parameters, embedded remote keys, duplicate JSON names,
legacy `vc` wrapper claims, malformed compact serialization, altered payload,
and non-canonical base64url.

### TEST-209: Holder binding

**Validates:** [[SPEC-004-application-scoped-identity#REQ-206]].

Accept a valid challenge signature from the `cnf` key. Reject a signature by
the issuer, another device, another application device, another account's
device, or a key whose public bytes differ from the subject DID.

### TEST-210: Challenge replay

**Validates:** [[SPEC-004-application-scoped-identity#REQ-206]].

Reject reuse after success, reuse after failure, use after 120 seconds, use
with another grant, another application ID, or another RFC 7565 account.

### TEST-211: Authorization predicate

**Validates:** [[SPEC-004-application-scoped-identity#REQ-207]].

Mutate each of CON-206's thirteen checks independently. No mutation may leave
the result authorized.

### TEST-212: Grant validity and status

**Validates:** REQ-207, REQ-208, CON-205, CON-206, CON-210.

Test before `validFrom`, at `validFrom`, immediately before `validUntil`, at
`validUntil`, present and absent grant IDs in a valid revocation G-Set, stale
closure, incomplete causal closure, invalid delta signature, unauthorized
signer, and deactivated issuer.

Test the lifetime bound independently of the validity window: accept a grant
whose `validUntil - validFrom` equals `maxGrantLifetimeSeconds` exactly, and
reject one exceeding it by a single second **while the current time sits inside
its window**, proving the check is on the interval rather than on the instant.
Reject a profile declaring `maxGrantLifetimeSeconds` above 2,592,000, absent, or
non-positive.

With projection enabled, test valid set and unset bits, invalid proof, wrong
issuer, cleared-bit rollback, stale projection, and unavailable projection. A
set bit rejects early; no other projection condition may bypass the CRDT check.

### TEST-213: Revocation convergence and propagation

**Validates:** [[SPEC-004-application-scoped-identity#REQ-208]].

Submit a valid signed `RevokeCredential` delta and observe the exact grant ID
in a newly resolved verified closure within `propagationSlaSeconds`. Reject
tampered, wrong-DID, missing-parent, cross-application, cross-account,
deactivated, revoked-signer, and unknown-signer deltas.

Apply the same delta repeatedly and require idempotence. Concurrently revoke
different grants on three replicas, merge in every order, and require identical
sets containing every ID. Attempt to clear or overwrite an ID and require that
no method operation or merge can make `is_revoked(id)` false.

### TEST-214: Provider selection

**Validates:** [[SPEC-004-application-scoped-identity#REQ-209]], [[SPEC-004-application-scoped-identity#REQ-219]], [[SPEC-004-application-scoped-identity#NFR-207]].

Exercise priority, weight, bounded parallel probes, incompatible protocol,
timeouts, unhealthy endpoints, malformed descriptors, and total failure.
Require selection to complete within the NFR-207 latency bound with at least
one healthy declared provider, and require a slow high-priority provider not to
serially block its fallbacks.
Against both PROTO-003 and PROTO-002 capability oracles, reject a plain `ok`
body, unknown or duplicate JSON members, wrong fixed semantics, a 4 KiB
mailbox maximum, invalid/duplicate pairing routes, redirects, compression,
wrong media type, oversized response, and a response arriving after 1500 ms.
No descriptor failing either service may enter the weighted choice.

### TEST-215: One initiator, one selection

**Validates:** [[SPEC-004-application-scoped-identity#REQ-209]].

Give two devices different health observations and profile revisions. Confirm
that the joiner follows only the route and descriptor bound by the valid
initiator bootstrap/hint and never starts a second election for the same
ceremony.

### TEST-216: No global fallback

**Validates:** [[SPEC-004-application-scoped-identity#REQ-210]].

Build a release client with an empty or wholly unhealthy profile. Assert that
no DNS lookup or connection targets an Anuna/Selfsame endpoint and that the
operation ends as `NoEligibleRendezvous`. Give a wallet a bare
twelve-word code whose address resolves nothing, and likewise require zero
network fan-out.

### TEST-217: Opaque transport

**Validates:** [[SPEC-004-application-scoped-identity#REQ-211]].

Issue one compact JWS, transport it through every supported ceremony encoding,
extract it, and require byte identity and successful verification by an
independent non-CBCL verifier.

### TEST-218: Provider-hint integrity

**Validates:** [[SPEC-004-application-scoped-identity#REQ-212]].

Alter application ID, profile version/digest, provider ID, pairing route,
nameplate, descriptor digest, offer digest, SPAKE2 binding/confirmation,
ciphertext, and authentication tag separately. Every alteration is rejected
before grant retrieval.

### TEST-219: Provider-independent recovery

**Validates:** [[SPEC-004-application-scoped-identity#REQ-213]].

Change every provider and account endpoint in the profile without changing
`applicationId` or `accountScopeId`; confirm that the application node, account
node, and home key do not change.

### TEST-220: Independent developer conformance

**Validates:** [[SPEC-004-application-scoped-identity#REQ-214]].

Run a complete issue-link-verify-revoke flow using only third-party account,
pairing, rendezvous, and state services. The pairing/rendezvous pair first
passes the independent PROTO-003 and PROTO-002 black-box suites. Exercise two
accounts in the same application, disable Bitstring projection, block all
Anuna domains, and require both flows to pass. Repeat with a third-party
projection host and require identical Selfsame authorization results.

### TEST-221: Device-key separation

**Validates:** [[SPEC-004-application-scoped-identity#REQ-215]].

On one installation, enroll the same recovery principal into 100 distinct
application IDs with 100 account scopes each. No device public key or DID may
repeat. Deliberately reuse one device key across applications and then across
two accounts in one application; require the second enrollment to be rejected
in both cases.

### TEST-222: Multiple-account isolation and switching

**Validates:** [[SPEC-004-application-scoped-identity#REQ-216]].

For one fixed recovery seed and application ID, derive 10,000 distinct valid
account scopes. Require unique account nodes, home seeds, public keys, DIDs,
aliases, device keys, credential IDs, state namespaces, and status entries.

Switch the application's authenticated account context between A1 and A2
without changing its profile. Require the SDK to select the matching branch
without Selfsame user input. Present each account's issuer closure, grant,
device proof, status entry, revocation delta, and optional projection to the
other account in turn; every cross-account presentation must fail.

### TEST-223: Account-scope lifecycle and recovery

**Validates:** [[SPEC-004-application-scoped-identity#REQ-217]].

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

**Validates:** [[SPEC-004-application-scoped-identity#REQ-201]], [[SPEC-004-application-scoped-identity#REQ-203]], [[SPEC-004-application-scoped-identity#REQ-205]], [[SPEC-004-application-scoped-identity#REQ-208]].

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

**Validates:** [[SPEC-004-application-scoped-identity#REQ-218]].

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

### TEST-226: Pairing and rendezvous protocol integration and failover

**Validates:** REQ-209, REQ-210, REQ-212, REQ-214, REQ-219, REQ-226–229,
CON-208, CON-209, CON-213, CON-216–218.

Run [[PROTO-003-selfsame-pairing-v1#TEST-401]] through
[[PROTO-003-selfsame-pairing-v1#TEST-412]] and
[[PROTO-002-selfsame-rendezvous-v1#TEST-301]] through
[[PROTO-002-selfsame-rendezvous-v1#TEST-310]] against two independently
implemented provider pairs, then complete the same application-account
ceremony through each. Confirm selection requires both capability responses,
SPAKE2 stays end to end, and pairing/mailbox traffic remains on the two exact
descriptor origins.

Make the first provider unavailable after allocation, after `pA`, after `pB`,
after each confirmation, after an unacknowledged initial slot request, and
after publishing its authenticated provider hint, then select the second. In
every post-allocation case require a new code, meeting-point address,
nameplate, role tokens,
SPAKE2 ephemerals/frames, derived secret, offer slot, bundle slot, offer,
ciphertext, descriptor digest, and hint. Require no shared frame, slot, or
ciphertext across operators and no change to the application-account node,
home key, DID, stable alias, account scope, grant semantics, or `did:crdt`
state.

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
endpoint chooser, or credential-sized OS callback. The apps complete
PROTO-003 with mutual confirmation, derive the same mailbox secret, exchange
the ordinary encrypted offer/bundle, show authenticated
application/account/device/permission consent, and publish signed DID state
only to the separately selected state service. The app accepts through CON-206
and proves the device key through CON-207.

Repeat as a cross-device ceremony with fresh randomness. The platform traces
differ only at bootstrap delivery and optional foreground return; provider
selection, SPAKE2 transcript, mailbox derivation, accepted grant semantics,
device proof, state publication, and failure decisions are otherwise
equivalent.

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

**Validates:** REQ-205, REQ-206, REQ-207, REQ-222, REQ-223, REQ-226–229,
CON-206, CON-209, CON-214 through CON-218.

Place an adversary on every network path and give it control of the pairing
relay, rendezvous, one state resolver, a second installed mobile app, all
callback/bootstrap parameters, and caller-supplied name/icon metadata. It does
not control the OS, recovery secret, developer enrollment-signing key, human
code before use, or target device private key.

Mutate application ID, profile digest, account scope, device key digest,
permission set, provider ID, descriptor digest, offer digest, request ID,
ceremony ID, pairing route, nameplate, the code, either SPAKE2 point or
confirmation, role label, platform binding, return URI, issue/expiry time, JWS
protected header, offer ciphertext, provider hint, grant ciphertext, VC
audience, and device proof one at a time. Then splice each valid value from
application A, account A1, and ceremony C1 into B, A2, and C2 in every pairwise
direction.

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
sink. It returns the closed CON-215 error, burns the PROTO-003 session and
dependent offer/slots, and displays only a ceremony-free install/help action.
A successful later attempt uses a different code, address, nameplate, tokens,
SPAKE2 ephemerals/frames, derived secret, request ID, ceremony ID, offer,
slots, ciphertext, enrollment evidence, and hint. No abandoned value is
reused.

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

### TEST-232: Code grammar, routing, and bootstrap

**Validates:** REQ-226, REQ-227, CON-201, CON-216, CON-218; PROTO-003 ADR-406,
ADR-407, ADR-409.

Run [[PROTO-003-selfsame-pairing-v1#TEST-402]],
[[PROTO-003-selfsame-pairing-v1#TEST-408]],
[[PROTO-003-selfsame-pairing-v1#TEST-409]], and
[[PROTO-003-selfsame-pairing-v1#TEST-413]]. Require a twelve-word code to
resolve exactly one CON-409 record and, through it, exactly one descriptor in
the authenticated application profile.

Give the wallet a well-formed code whose address resolves nothing and require
`PairingRecordUnavailable` after exactly one resolution attempt and zero
further DNS or HTTP requests — in particular no profile fetch, no capability
probe, and no peer claim.

Publish records for two applications naming the same `providerId` and
nameplate, and require different bindings, PAKE keys, and mailbox slots.
Require a code carrying any route, nameplate, provider, or application
identifier to be rejected under CON-218, along with global interpretation,
provider broadcast, and an undeclared fallback.

### TEST-233: SPAKE2 confirmation, blind relay, and burn

**Validates:** REQ-226, REQ-228, REQ-229, ADR-217, CON-217, CON-218;
PROTO-003 ADR-406.

Run [[PROTO-003-selfsame-pairing-v1#TEST-403]] through
[[PROTO-003-selfsame-pairing-v1#TEST-407]],
[[PROTO-003-selfsame-pairing-v1#TEST-410]], and
[[PROTO-003-selfsame-pairing-v1#TEST-411]]. The correct code produces mutual
confirmation and one shared mailbox secret. Any wrong word, invalid point,
changed binding, missing/wrong MAC, provider fork, reflection, race, retry, or
downgrade produces no mailbox request or application-account side effect.

Instrument the wallet to prove it evaluates at most one `cA` for a minted
ceremony. Inspect provider state to prove it contains no password-equivalent
verifier, PAKE/mailbox key, application/account identifier, offer, or grant.

### TEST-234: Many-application spoken routing

**Validates:** REQ-227, CON-216, CON-218; PROTO-003 ADR-407, ADR-409, CON-409.

Create three unrelated application IDs, each with at least two providers and
overlapping routes and nameplates. For each, deliver **only** the twelve words,
with no QR and no application identity. Require the wallet to reach the
record-named claimed target and descriptor purely by resolving the CON-409
record, to fetch its profile from that claimed origin and require its digest to
match the record, and to complete pairing without user endpoint selection or
Anuna infrastructure.

Run each application in both initiation directions and require identical
results.

Substitute a validly signed record naming another application's `applicationId`,
`profileDigest`, `providerId`, or nameplate. Require the wallet to disclose the
claimed canonical application origin and require an explicit pairing-target
approval before a nameplate claim or PAKE frame. Declining burns the ceremony
with zero claim, frame, or grant. On approval, require the substituted values to
enter the binding, but do not claim that PAKE confirmation detects the
substitution: a holder of the bearer code can create a self-consistent record.
Require the downstream CON-214 application-authentication and account-consent
checks before any grant, and assert the wallet never searches another
application, profile, or provider.

Then exercise the CON-409 tier-3 fallback explicitly. With every tier-1 relay
removed and the tier-2 transport unreachable, require the wallet to attempt both
before offering origin entry, to reach the same descriptor and the same binding
once the person supplies the origin, and to complete pairing identically. Require
that origin entry is never offered while a tier remains untried. If a mistyped
origin resolves a different application, require claimed-target disclosure and
explicit pairing-target approval before PAKE; if approved, PAKE may confirm but
no grant may issue without the later CON-214 application-authentication and
separate application-account-consent checks. Require that the canonical
`applicationId` used in the binding comes from the fetched profile and not from
what the person typed.

### TEST-235: Carrier equivalence and full authorization chain

**Validates:** REQ-226–229, ADR-217, ADR-218, CON-214–219;
PROTO-003 ADR-406–409.

Deliver equivalent fresh bootstraps by QR, by twelve spoken or typed words, and
by verified same-device handoff — each in both initiation directions, giving six
traces. Every trace runs the same PROTO-003 roles and confirmation, resolves the
same CON-409 record, derives a PROTO-002 mailbox secret, processes the same
logical offer/grant fields, and requires the complete CON-206/CON-207 predicate.
Require the machine carriers to transport `c` and never the word rendering.

Then capture a complete correct code and successfully complete SPAKE2 while
omitting or mutating developer enrollment evidence, consent, home signature,
VC audience, holder key, device proof, or fresh `did:crdt` state. Require zero
accepted grants. This distinguishes PAKE password knowledge from application
or credential authority.

### TEST-236: Ceremony payloads, offer digest, and envelope integration

**Validates:** REQ-205, REQ-211, REQ-222, ADR-218, CON-214, CON-217, CON-219;
PROTO-004 CON-501 through CON-504.

Run [[PROTO-004-selfsame-ceremony-envelope-v1#TEST-501]] through
[[PROTO-004-selfsame-ceremony-envelope-v1#TEST-506]] against two independently
implemented clients, then complete an application-account ceremony through
each.

Accept the normative offer and bundle payload vectors. For each role, reject a
payload with an unknown member, a missing required member, a member whose value
violates its inherited grammar, a `requestedPermissions` array that is empty,
unsorted, duplicated, or not a subset of `allowedPermissions`, a `grant`
exceeding 65,536 characters, a `grantMediaType` other than `application/vc+jwt`,
and a bundle whose `ceremonyId` or `requestId` differs from the offer's.

Assert the grant encoding and the size budget directly. A bundle carrying a
65,536-character grant verbatim, with `issuerClosure` omitted, MUST seal inside
the PROTO-004 payload bound. A bundle whose `grant` has been base64url-encoded
rather than carried verbatim MUST be rejected — as `PayloadTooLarge` at the
maximum size, and as a malformed compact JWS at any size. Extract `grant` from a
completed bundle and require byte identity with the issued JWS with no decode
step between.

Compute `offerDigest` over `offer_core` for every vector and require two
independent implementations to agree byte-for-byte. Assert the exclusion rule
directly: adding, removing, or mutating `enrollmentEvidence` or `providerHint`
does not change `offerDigest`, and mutating any of the thirteen `offer_core`
members does. Present an offer whose enrollment-evidence `offerDigest` was
computed over the complete payload rather than `offer_core` and require
`OfferMismatch`, not acceptance.

Splice a valid offer from ceremony C1 into C2 and require
`EnvelopeAuthFailed` before payload recognition, proving that the envelope tag
rather than a payload field is the first line of defence. Present a bundle
whose grant is valid but whose payload fails CON-503 canonicality and require
zero acceptance, zero session, and zero device-proof challenge.

Extract the `grant` octets from a completed bundle and require byte identity
with the issued compact JWS and successful verification by an independent
non-CBCL verifier, confirming that the envelope secured transport only.

### TEST-237: Profile discovery and origin binding

**Validates:** [[SPEC-004-application-scoped-identity#REQ-222]], [[SPEC-004-application-scoped-identity#REQ-227]], [[SPEC-004-application-scoped-identity#CON-201]], [[SPEC-004-application-scoped-identity#CON-220]].

Dereference a canonical `applicationId` and require the CON-201 recognizer to
accept only a conforming profile whose own `applicationId` equals the URI
fetched. Reject, individually and with zero semantic action each time: any
redirect including same-origin, a wrong media type, content encoding, a body
over 65,536 octets, a profile whose `applicationId` differs from the fetched
URI, and a profile whose RFC 8785 digest differs from the CON-409 record's
`profileDigest`.

Serve a substituted profile carrying an attacker's enrollment key from an
otherwise valid TLS origin and require rejection at the digest step, proving TLS
alone is not the control. Supply the same profile to the wallet directly from
the caller and require it never to be used.

Exercise the tier-3 ordering: fetch under steps 1–5, use only
`pairingRecordRelays`, resolve the record, then apply step 6 — and require a
digest mismatch discovered at that point to abandon the ceremony with no
provisioning and no session.

Exercise cache and rotation: accept a cached profile inside 3,600 seconds with
no network request; require revalidation past it; publish a profile with a
removed enrollment key and require evidence signed by that key to fail once the
cache expires; require immediate eviction on any digest mismatch; and require
`UnverifiedApplication` when the cache is stale and the network is unavailable.

Exercise `/.well-known/selfsame/applications`: accept the closed two-member
object, reject unknown members, over 32 entries, and any entry off the queried
origin, and require the endpoint to be consulted on no path other than tier-3
recovery.

### TEST-238: First-enrollment confirmation and wallet substitution

**Validates:** [[SPEC-004-application-scoped-identity#REQ-222]], [[SPEC-004-application-scoped-identity#REQ-230]], [[SPEC-004-application-scoped-identity#ADR-220]], [[SPEC-004-application-scoped-identity#CON-221]].

For an account with no authority binding, complete a ceremony and require both
screens to display `Fingerprint::hex` of `fingerprint_did(home_did)` with its
LifeHash beside it, and require the values to match. Confirm, and require the
alias to be provisioned and the grant accepted.

Reject the comparison and require: no alias provisioned, no grant accepted, no
session, the ceremony burned, and a revocation attempted where a controller is
reachable. Time the prompt out and require the same. Assert no affordance exists
to skip, suppress, or remember the confirmation.

**Substitution.** Introduce a second wallet holding a different recovery secret
and give it the bootstrap. Require it to complete SPAKE2 and produce a
structurally valid grant — it can, since it holds `C` — and require the
confirmation step to be the control that stops it: the fingerprints differ, the
person rejects, and no alias is bound. Then repeat with the confirmation
disabled and require the enrollment to succeed, demonstrating that this contract
and not some other check is what closes the gap.

For an account the authority already binds, present a grant from a different
issuer and require rejection under CON-204 **before** CON-206 runs, with no
confirmation prompt shown. Require that no code path can re-enter the
confirmation for an already-bound account.

### TEST-239: Platform binding conformance

**Validates:** [[SPEC-004-application-scoped-identity#REQ-220]], [[SPEC-004-application-scoped-identity#REQ-223]], [[SPEC-004-application-scoped-identity#REQ-225]], [[SPEC-004-application-scoped-identity#CON-222]], [[SPEC-004-application-scoped-identity#CON-223]].

On Android at API 30 and above: require wallet discovery to carry no ceremony
material and to return only package names; require dispatch to be an explicit
component intent even when exactly one candidate resolves; require any
`PendingIntent` to be immutable and one-shot, and reject a mutable or replayable
one; require the wallet to compare the creator package against the CON-214
`platformBindingId` and return `PlatformBindingMismatch` otherwise; and require
signing-certificate rotation to be tolerated via `hasSigningCertificate`.

On Apple platforms: require dispatch with `universalLinksOnly` true, and require
a `false` completion to be terminal — assert no Safari open, no web view, no
install page, no custom scheme. Corrupt the associated-domain binding and
require failure. Assert that no payload-supplied identifier is treated as caller
evidence.

On both: install a hostile sibling registering the same capability and require
that it receives no ceremony material unless the person explicitly selects it,
and that selecting it still fails at [[SPEC-004-application-scoped-identity#CON-221]] confirmation.

### TEST-240: Freshness tiers and projection inference

**Validates:** [[SPEC-004-application-scoped-identity#REQ-207]], [[SPEC-004-application-scoped-identity#REQ-208]], [[SPEC-004-application-scoped-identity#CON-206]], [[SPEC-004-application-scoped-identity#CON-210]].

**Tiers.** With a profile at the defaults, accept a grant at session
establishment against a closure younger than
`min(maxClosureAgeSeconds, propagationSlaSeconds)` and reject one older,
including a closure that would pass the continuation bound. Then, inside the
established session, accept re-verification against a closure between the two
bounds. Lose the verifier's record of the accepted grant ID and require the
next acceptance to be treated as establishment. Present a grant whose case is
indeterminable and require the establishment bound.

**Composed latency.** Submit a revocation, then require that no new session can
be established with that grant more than
`propagationSlaSeconds + min(maxClosureAgeSeconds, propagationSlaSeconds)`
after submission — 120 seconds at the defaults — while an already-established
session may continue until `maxClosureAgeSeconds`.

**Resolver preference.** With a declared `stateResolvers` entry reachable,
require the establishment closure to be resolved from it and not taken from the
CON-219 bundle or a cache. Serve a bundle closure that omits a
`RevokeCredential` delta the resolver holds and require the grant to be
rejected. Make every declared resolver unreachable and require the
bundle-supplied closure to be used only for a first acceptance, and only with a
record that it was.

**Ceilings.** Reject a profile whose `propagationSlaSeconds` exceeds 300, whose
`maxClosureAgeSeconds` exceeds 3,600, whose `projection.maxAgeSeconds` exceeds
3,600, or whose `maxGrantLifetimeSeconds` exceeds 2,592,000, each individually
and with zero semantic action.

**Projection inference.** Publish a projection whose
`validUntil - validFrom` exceeds `maxAgeSeconds` and require the publisher path
to refuse to sign it. Age a valid projection past `validUntil` and require: a
set bit still rejects the grant, and an unset bit yields *unavailable* rather
than *not revoked*. Require a Selfsame verifier to reach the same decision with
the projection removed entirely, proving CON-206 step 10 never relied on it.

### TEST-241: Context digest and non-dereference

**Validates:** [[SPEC-004-application-scoped-identity#REQ-205]], [[SPEC-004-application-scoped-identity#NFR-204]], [[SPEC-004-application-scoped-identity#CON-224]].

Require `SHA-256` of `contexts/device-grant-v1.jsonld` to equal the
`context_digest` recorded in CON-224 and in the CON-226 corpus, and require the
file to be UTF-8 with no byte-order mark, LF endings, and at most 8,192 octets.
Require the document's single `@context` value to be structurally identical to
the logical context in CON-205, so the two cannot drift.

Verify a grant with all network egress blocked and require success, proving no
verification path dereferences the context or vocabulary IRIs. Instrument the
resolver and assert zero requests to the `anuna.io` origin across the complete
CON-206 predicate.

Serve altered octets at the context IRI and require any party that fetches to
fail closed as `UnknownContext` — specifically requiring that it does not use
the retrieved bytes, prefer them to the pinned copy, or merge the difference.
Serve the correct octets with a different media type or transfer encoding and
require the digest comparison to be what decides.

Require a credential carrying an unknown context IRI, a `/v2` IRI, or the two
contexts in the wrong order to be rejected at CON-206 step 8.

### TEST-242: Identity succession

**Validates:** [[SPEC-004-application-scoped-identity#REQ-202]], [[SPEC-004-application-scoped-identity#REQ-231]], [[SPEC-004-application-scoped-identity#ADR-222]], [[SPEC-004-application-scoped-identity#CON-225]].

**Positive.** Complete a succession with a valid developer pointer, both
signatures, and a confirmed fingerprint comparison; require the incoming alias
provisioned, the outgoing alias tombstoned, the `accountScopeId` carried across
unchanged, and grants from both issuers accepted until `expiresAt`.

**Negatives**, each individually and with the outgoing identity, its alias, its
grants, its revocation state, the account scope, and every session unchanged:
a one-sided statement with only the outgoing signature; only the countersign;
two signatures over payloads differing by one byte; a developer pointer signed
by a key present in the currently served profile but **absent from the set the
wallet pinned at the last successful enrollment**; a pointer whose
`expiresAt - issuedAt` exceeds ninety days; a statement past `expiresAt`; a
statement whose `expiresAt - issuedAt` exceeds the incoming profile's
`maxGrantLifetimeSeconds`; a statement whose `outgoing` is not the DID the
authority currently binds; a chained statement whose `outgoing` is another
unexpired statement's `incoming`; a statement carrying an unknown member at any
depth; and a wallet-initiated succession.

**Deactivation ordering.** Complete a succession while one grant issued by the
outgoing DID remains unexpired, and require a deactivation attempt to be
refused. Then deactivate after every outstanding grant is revoked or expired
and require it to succeed. Separately, deactivate the outgoing DID directly
through the method and require a subsequent `RevokeCredential` to be rejected —
demonstrating that the ordering rule is what prevents an unrevokable grant, not
a courtesy.

**Lapsed-origin simulation.** Transfer the outgoing origin to an adversary who
serves a well-formed pointer under a freshly generated enrollment key. Require
rejection at the pinned-key check, and require the wallet to disclose nothing —
including whether it holds an outgoing identity for that application. Then
rotate every pinned key legitimately and require succession to fail closed to
fresh enrollment rather than fall back to the served set.

**Confirmation.** Reject the fingerprint comparison and require nothing
provisioned, no session, and no signature produced. Time it out and require the
same. Assert both fingerprints are displayed as `Fingerprint::hex` with the
LifeHash beside, never instead.

**Publication.** After a successful succession, assert the statement appears in
no `alsoKnownAs`, WebFinger JRD, status projection, state-resolver record,
callback, log, or analytics payload. Require a verifier to reject a statement
offered by any party other than the wallet or its own account authority.

**After the window.** Past `expiresAt`, require only the incoming issuer
accepted and the outgoing rejected under CON-206 with
`credentialSubject.account` equal to the outgoing alias. Require the tombstoned
outgoing alias to be unassignable to another account or DID.

**Isolation.** Require a third application to be unable to obtain either
statement, and require its own home DID for the same person to be unchanged by
the succession. Require the incoming home DID to be reproducible from mnemonic,
the incoming `applicationId`, and the carried `accountScopeId` alone, so that
succession produces an ordinary CON-202 identity and not a retained one.

### TEST-243: Corpus completeness and independence

**Validates:** [[SPEC-004-application-scoped-identity#REQ-222]], [[SPEC-004-application-scoped-identity#REQ-227]], [[SPEC-004-application-scoped-identity#CON-226]].

Enumerate every closed error token defined by CON-204, CON-211, CON-212,
CON-214, CON-215, CON-219, CON-220, CON-221, CON-222, CON-223, and CON-225, and
each of CON-206's thirteen numbered steps, and require at least one corpus case
whose `expect.reject` names it. A token or step with no case fails this test —
it is not reported as a warning.

Require all seven OQ-207 item 5 groups and the KDF, alias, VC, holder-binding,
revocation, account-scope, and username groups to be present in the one file.
Require every case outside the handoff group to be platform-independent.

Require RFC 8785 re-serialization of `test-vectors/spec-004-v1.json` to
reproduce the file byte for byte, all binary to be canonical base64url without
padding, and every number to be an integer.

Run two independently implemented stacks over the corpus and require identical
accept/reject reasons for every case — not merely identical pass/fail. Require
a case that a stack cannot execute to be reported as a failure rather than
skipped, and assert that no case is marked skipped, pending, or expected-fail.

### TEST-244: Hierarchy root, version and persona separation

**Validates:** [[SPEC-004-application-scoped-identity#REQ-213]],
[[SPEC-004-application-scoped-identity#CON-202]],
[[SPEC-004-application-scoped-identity#ADR-223]].

*Positive.* Compute `hierarchy_root` from each corpus mnemonic using an
HKDF-SHA-512 implementation **other than the one under test**, driven only by
CON-202's published definition — IKM, zero-length salt, `info`, and length — and
require it to equal the corpus value byte for byte. Then require the home DID
derived from it to equal the corpus value. Comparing home DIDs alone would pass
while two implementations shared one wrong root; the recorded intermediate is
what localises a divergence above or below the root.

*Negative — the root is a sibling, not a child.* Expand SPEC-001's persona-root
label to 64 octets — `HKDF-SHA-512(IKM = bip39_seed, salt = "", info =
UTF8("anuna-ssi/v1/root-key/") || U32BE(0), L = 64)` — and require
`hierarchy_root` to differ from it, and neither to be a prefix, suffix or
truncation of the other. **Comparing against the 32-octet persona root would
be a check that cannot fail**, since a 64-octet value can never equal a
32-octet one; expanding to equal width is what makes the label separation the
subject of the test rather than the length.

Take the SPEC-001 construction from that specification's published vectors
rather than from a formula restated here. SPEC-001 is not present in this vault
([[SPEC-004-application-scoped-identity#Conformance and status]]), so a
hard-coded restatement would assert an unverifiable external fact and pass
against a fixture rather than against the thing it excludes.

Require that no vector in the corpus contains a SPEC-001 persona root at all: a
corpus that carried one would invite an implementation to derive from it.

*Negative — persona separation.* Derive the same mnemonic, `applicationId` and
`accountScopeId` under two persona indices and require unrelated
`hierarchy_root`, `application_node`, home DID and `acct:` alias. Require no
derived value under one persona to be a prefix, suffix, or truncation of the
corresponding value under the other.

*Negative — version separation, against the real version 1.* Compute the
**actual** hierarchy-version-1 value — `KDF` under the salt
`selfsame/application-account-key-hierarchy/v1` rooted at `bip39_seed` — and the
version-2 value — `KDF` under the `/v2` salt rooted at `hierarchy_root` — from
one mnemonic, `applicationId` and `accountScopeId`, and require unrelated output
at every node.

Both the salt **and the root** must differ, because both did. Varying only the
salt while feeding `hierarchy_root` to each computes a hybrid that never existed
in either version: it would satisfy the stated separation claim while leaving
the real v1 tree untested, which is the failure mode this clause exists to
avoid. The v1 salt and the seed-rooted derivation appear here as test fixtures
only; CON-202 no longer defines that hierarchy.

*Structural — the seed is not reachable.* Assert that the entry point producing
`application_node` accepts `hierarchy_root` as a **distinct nominal type** that
no mnemonic and no BIP-39 seed can inhabit, and that no public constructor of
that type takes either.

A parameter typed merely as 64 octets cannot exclude a 64-octet BIP-39 seed —
they are the same shape, which is the point of
[[SPEC-004-application-scoped-identity#ADR-223]]'s width argument and the reason
this clause must be about the type rather than the width. A behavioural check
("run it with the seed absent and require success") is weaker still: a function
that never takes the seed succeeds without it by construction, so it cannot
fail.

### TEST-246: Web manual binding conformance

**Validates:** [[SPEC-004-application-scoped-identity#REQ-220]],
[[SPEC-004-application-scoped-identity#REQ-222]],
[[SPEC-004-application-scoped-identity#REQ-223]],
[[SPEC-004-application-scoped-identity#CON-214]],
[[SPEC-004-application-scoped-identity#CON-215]],
[[SPEC-004-application-scoped-identity#CON-227]].

**Core** (writable in one sitting, no rig):

- *Positive.* A profile declaring one web binding recognises; a CON-214
  statement whose `platformBindingId` names it, observed with unattributed
  caller evidence, reaches consent.
- *Negative input.* A web binding whose `origin` differs from the
  `applicationId` origin — scheme, host, port, or a single trailing character —
  refuses the **whole profile** at
  [[SPEC-004-application-scoped-identity#CON-201]] recognition. A web binding
  with an extra member, a missing member, or an `id` not equal to `web:` plus
  the origin likewise refuses. A profile declaring two web bindings refuses.
- *Attributed caller refused.* The same statement observed with a calling
  package, and again with an associated origin, returns
  `PlatformBindingMismatch`; home state, grant state, and the bundle slot are
  unchanged.
- *Undeclared binding refused.* A statement naming a web binding the profile
  does not declare returns `PlatformBindingMismatch`.
- *Foreign `returnUri` refused.* A web-binding statement whose `returnUri`
  names any origin other than the `applicationId` origin returns
  `EnrollmentMalformed` ([[SPEC-004-application-scoped-identity#CON-227]]'s
  `returnUri` rule).
- *Mixed-profile downgrade refused.* A profile declaring **both** an android
  binding and a web binding; the statement names the web binding; the caller
  is attributed as **exactly the declared android package**. The result is
  `PlatformBindingMismatch` — matching *a* declared binding is not matching
  *the named* binding, and this is the one row where a lazy implementation
  silently reopens the route around
  [[SPEC-004-application-scoped-identity#CON-222]].
- *Mutation gate.* Make the verifier accept an attributed caller against a
  web binding and require a red test; make the recogniser accept a
  foreign-origin web binding and require a red test; make the verifier match
  the caller against any declared binding instead of the named one and
  require the mixed-profile row to go red.

**Depth** (needs a platform rig; owner: wallet maintainer, before Tier-1
production sign-off):

- A CON-215 adapter resolving only a web binding reports `WalletUnavailable`
  and dispatches nothing, on each platform.

**Corpus.** [[SPEC-004-application-scoped-identity#CON-226]] group 3 gains
`web-manual`-labelled cases covering each core row above; the corpus SHA-256
moves with this amendment's changelog entry when the cases land.

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
4. the human words, role tokens, SPAKE2 ephemerals/key, derived mailbox secret,
   offer/grant plaintexts, enrollment evidence, provider hint, transcripts,
   and one-time identifiers;
5. device private keys and the authorization value of issued VCs;
6. the completeness and freshness of signed `did:crdt` authorization and
   revocation state; and
7. the integrity of consent—what authenticated application/account/device
   operation the person believes they approved.

### Trust boundaries and anchors

This profile relies on:

- platform-protected storage keeping the recovery secret and device private
  keys confidential — including, since 0.14.0, the **custodian's sealed
  `hierarchy_root`**, which is a distinct at-rest asset from the mnemonic and
  is named here because it is now the sole compromise path to every application
  key below it ([[SPEC-004-application-scoped-identity#ADR-223]]). Where that
  seal is a passcode-derived key, the passcode's entropy — not the hierarchy's
  128 bits — is the binding number for an at-rest attacker;
- BIP-39, ristretto255, SPAKE2, HKDF-SHA-256/HKDF-SHA-512,
  HMAC-SHA-256, SHA-256/SHA-512, BLAKE3, Ed25519, JWS, the RFC 8439
  ChaCha20-Poly1305 AEAD fixed by
  [[PROTO-004-selfsame-ceremony-envelope-v1#CON-502]], and their domain
  separation remaining secure for their stated uses;
- conforming clients honouring
  [[PROTO-004-selfsame-ceremony-envelope-v1#REQ-502]], since a reused envelope
  key repeats a keystream and the constant nonce depends on that invariant;
- the HTTPS `applicationId` origin and a backend enrollment-signing key,
  obtained through [[SPEC-004-application-scoped-identity#CON-220]] and pinned
  per account for [[SPEC-004-application-scoped-identity#CON-225]];
- the mobile OS correctly enforcing application sandboxing, installed-app
  signing identity, explicit/verified dispatch, associated-domain routing, and
  one-shot result capabilities used by CON-215;
- the application authenticating its active account and preserving that
  account's immutable scope across normal account recovery;
- TLS authenticating the account authority and selected service endpoints,
  while end-to-end SPAKE2, signatures, and AEAD—not TLS—establish pairing,
  grant, and DID-state truth;
- the account authority truthfully reporting the account↔DID mapping in its own
  namespace; and
- verifiers enforcing closure freshness and the complete CON-206 and CON-207
  predicates.

A production wallet does **not** trust a public profile merely because a caller
supplied it. CON-220 through CON-223 now define profile discovery and platform
evidence, but until mobile platform reviewers approve them and TEST-237 through
TEST-239 pass on real devices, the embedded-profile assumption is limited to an
in-process prototype and this specification's Tier-1 gate remains closed.

A conforming verifier trusts the pinned credential context and **nothing about
the origin that names it**: CON-224 makes the context digest the authority, so
`anuna.io` appears in this list nowhere.

The following are explicitly untrusted:

- the pairing and rendezvous operators, any state resolver,
  status-projection host, network path, browser, URL handler, and
  completion-callback recipient;
- every caller-supplied application name, icon, package/bundle string, link
  parameter, profile, callback value, and error description; and
- other applications and application accounts, including ones colluding with
  each other or with an infrastructure operator.

### Adversary capabilities

The adversary may:

- intercept, delay, drop, replay, reorder, duplicate, redirect, fork, and
  mutate network messages, and may operate a selected pairing, rendezvous, or
  state service;
- enumerate or pre-claim public pairing nameplates, make one online guess
  against each locked endpoint, and retain every PAKE relay frame;
- install a malicious app on the same device, register competing custom
  schemes and implicit intents, launch Selfsame with arbitrary bytes, replay a
  copied public profile/bootstrap, and intercept any callback the OS does not
  bind;
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
claimed application/profile routing context resolved from the C-derived record
          |
          | visible target disclosure + pairing-target approval
          | app and wallet run mutually confirmed SPAKE2
          | pairing provider relays only opaque pA,pB,cA,cB
          v
confirmed PAKE key -> derived PROTO-002 mailbox secret
          |
          | encrypted, transcript-bound offer
          | rendezvous transports only opaque immutable ciphertext
          v
authenticated application origin (CON-214)
          |
          | signs app + account + device key + permission
          |       + provider + offer + nonce + expiry
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

The application ID, profile digest, provider descriptor/route/nameplate,
SPAKE2 roles and transcript, account scope, device key, requested permissions,
offer digest, request/ceremony IDs, expiry, VC
issuer/subject/audience/account/permissions/grant ID, DID closure, and device
challenge are each mutually confirmed, signed, encrypted-and-authenticated, or
checked against a signed value before acceptance. A man in the middle can deny
service, claim a nameplate it has resolved, or replay
already observed bytes, but cannot silently change one of those values, move a
result to another application/account/device/ceremony, derive the accepted
mailbox key without the words, or make a callback authorize without causing a
named verification failure.

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
- **Pairing authentication:** a passive provider transcript enables no offline
  word test; each endpoint requires the peer's role-separated confirmation and
  the wallet evaluates at most one active guess per ceremony.
- **Confidentiality:** the pairing relay, rendezvous, URL handlers, callbacks,
  and unrelated apps learn no PAKE/mailbox key, offer/grant plaintext, account
  scope, or private key.
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
- **Compromise of a custodian's sealed `hierarchy_root` compromises every
  application branch under that persona** — every `application_node` directly,
  and every `account_node` and `home_signing_seed` once the holder obtains the
  corresponding `accountScopeId` from the application. The scope's
  confidentiality is **not** claimed as a control and SHALL NOT be relied upon
  as one — [[SPEC-004-application-scoped-identity#REQ-217]] states it is neither
  a password nor a source of cryptographic entropy. For every application the holder can name, past and
  future, unrevocably. Hierarchy version 1 had no such asset:
  the hierarchy rooted at a seed no custodian retained, so a custody compromise
  reached no SPEC-004 material at all. Version 2 creates this asset in order to
  make derivation possible without the recovery phrase, and
  [[SPEC-004-application-scoped-identity#ADR-223]] records that trade as the
  cost of the decision. It does **not** yield the mnemonic, the BIP-39 seed, or
  any sibling root, so it does not compromise other personas or SPEC-001's root
  signing key.
- The code provides 128 bits under
  [[PROTO-003-selfsame-pairing-v1#ADR-406]], so guessing is infeasible; SPAKE2
  is retained for transcript binding and forward secrecy. Disclosure of the code
  before use remains the live risk, bounded by N=1 burn and a short lifetime.
- The complete application context and code are a short-lived OOB capability.
  Disclosure before use lets an attacker race pairing and may reveal
  offer/grant plaintext or enable delivery interference even though CON-214,
  consent, home signatures, and the target device key still gate
  authorization. Suspected disclosure always burns the ceremony under
  REQ-229.
- A malicious pairing provider can pre-claim, fork, or withhold frames; a
  malicious rendezvous, resolver, account authority, or network can deny
  service. This profile bounds and detects these actions but cannot guarantee
  availability against every selected operator colluding.
- Pairwise derivation cannot prevent correlation through email, payment, IP
  address, device fingerprinting, a deliberately reused public username,
  application telemetry, or global traffic analysis.
- A malicious account authority can lie about or suppress mappings in its own
  RFC 7565 namespace, but cannot sign as the home DID or device.
- Correctly authenticated but misleading application content and a person's
  decision to approve an accurately identified request remain social/UX risks;
  the consent requirements reduce but do not eliminate them.
- CON-221 substitutes a person's one-time hex comparison for wallet
  attestation, because a registry of acceptable wallet builds is unavailable
  by design. A person who confirms without comparing reinstates the
  trust-on-first-use the contract removes, and no protocol control detects it.
- A CON-225 succession discloses to the incoming application that the outgoing
  account belongs to the same person. That is inherent to migration, confined
  to one developer's two identifiers, and never published; no third application
  learns it. A developer who rotates every pinned enrollment key between a
  person's last enrollment and a migration loses that person's succession, and
  the fallback is fresh enrollment.
- An adversary acquiring a lapsed `applicationId` origin cannot mint a
  succession, because CON-225 checks the pointer against wallet-pinned keys.
  They can still stand up an ordinary application at that origin and enroll new
  identities, which is what registering any domain permits; they gain no access
  to the previous developer's accounts or to any home key.
- Loss or hostile acquisition of the `anuna.io` origin changes no verification
  result, since CON-224 pins the context by digest and nothing dereferences it.
  It removes a convenience mirror for generic consumers that choose to fetch.

### Threat-to-control analysis

| Threat | Required response |
|---|---|
| Network man in the middle | TLS authenticates endpoints; PROTO-003 binds both PAKE endpoints to the claimed application/profile/descriptor/route/nameplate and requires both confirmation MACs. An attacker without `C` cannot silently mutate that binding; a code holder can make a self-consistent claimed target and is controlled by visible target approval, CON-214 signatures, ceremony AEAD, home signatures, VC audience, and device proof. TEST-229 and TEST-233 mutate each layer and assert zero unauthorized side effects. |
| Passive provider attempts an offline word dictionary | SPAKE2 frames and confirmation do not expose a password verifier. TEST-233 captures complete provider state and requires no offline guess predicate. |
| Active nameplate guess or pre-claim | The nameplate provides no security and is no longer public: it lives in a record at a 128-bit address, so live ceremonies cannot be enumerated. Atomic single claim, client peer locking, 600-second expiry, rate limiting, and permanent burn bound the residual and make interference a visible restart. |
| Malicious pairing provider terminates SPAKE2 | CON-217 requires the application and wallet as roles A/B and CON-218 rejects provider-generated frames or a password-verifier mode. Provider compromise yields no password equivalent or accepted key. |
| A code is tried across applications/providers | A code names no application, so there is nothing to try: routing comes from the signed record at its own 128-bit address, and PROTO-003 CON-409 forbids searching profiles, provider lists, or endpoints for a match. An unresolvable address makes one attempt per available tier and then fails. |
| Malicious same-device app copies another developer's public profile | A public profile supplies no authority. The attacker lacks the origin-anchored enrollment signature and matching platform binding; CON-214 rejects before branch lookup or consent, and CON-220 means the signing key never comes from the caller. |
| Link-handler or custom-scheme interception | CON-215 permits only verified installed-wallet dispatch and forbids browser/custom-scheme fallback. Any ambiguity burns every ceremony value under REQ-225. |
| Callback interception or forged `completed` result | Callback carries no secret or credential and is outside the authorization chain. Only a verified rendezvous bundle plus CON-206/CON-207 authorizes. |
| Concurrent application/account/ceremony mix-up | The PAKE binding first commits both endpoints to the claimed application/profile/descriptor/route/nameplate; enrollment evidence and the encrypted transcript then bind account scope, device key, permission, offer, request ID, and ceremony ID. Cross-splices after an honest binding fail TEST-229 and TEST-234; a self-consistent code-holder target still requires visible approval and the downstream authorization chain. |
| Application A colludes with application B | Their public Selfsame artifacts provide no equality test; other shared account data remains outside scope. |
| Account A1 is confused with A2 in one application | The authenticated account context selects the scope and expected `acct:` alias; issuer, grant, proof, status, and state checks reject every cross-account artifact. |
| Application reuses or replaces an account scope | Atomic uniqueness and immutability checks reject reuse; missing scope fails as `AccountScopeUnavailable` rather than creating a new identity. |
| Account scope is disclosed | It may correlate that application's private account storage but cannot derive a home key without the recovery secret; rotate only through explicit identity migration. |
| Malicious rendezvous | It may withhold, replay, retain, or reorder ciphertext and observe bounded metadata; the confirmed PAKE-derived slot secret, end-to-end AEAD, immutable transcript binding, expiry, and one-ceremony checks prevent forgery or authorization. |
| Sealed record spliced between ceremonies, roles, or applications | PROTO-004 additional authenticated data covers the role octet and PROTO-003 `binding_hash`, so a spliced record fails the tag check before payload recognition. TEST-236 and PROTO-004 TEST-504 assert rejection with zero side effects. |
| Envelope key reused across two plaintexts | PROTO-004 REQ-502 makes each role key single-use; PROTO-002 slot immutability and PROTO-003 burn semantics enforce it from two independent directions, and PROTO-004 TEST-503 asserts at most one ciphertext per key per ceremony. |
| Grant issued before its alias is provisioned | It confers nothing: CON-206 step 9 fails closed on the missing reciprocal binding, and CON-204 requires the application to provision or return `AccountProvisioningFailed` and revoke the grant ID. |
| Malicious or withholding state resolver | It cannot forge an accepted signed closure or remove a G-Set entry; stale or incomplete state fails closed, and resolver/peer diversity limits withholding. An application that declares its own node receives revocations directly and stops depending on a third party choosing to relay them. |
| Unauthenticated write to an application's delta endpoint | Revocation is monotone: the set is grow-only, deltas are signed by the home key, and no operation clears an entry. Forgery fails verification, replay is idempotent, and an accepted delta can only reduce authority. |
| Compromised application profile distribution | CON-220 dereferences the canonical `applicationId` itself, rejects every redirect, and requires the RFC 8785 digest to equal the CON-409 record's `profileDigest`. TLS authenticates the origin; the record digest pins which profile it served. Caller-delivered fields alone fail CON-214. |
| Stolen VC | It cannot pass CON-207 without the device private key. |
| Stolen device key | The grant remains usable until its ID appears in fresh verified CRDT state or it expires; the home controller revokes the exact grant ID. |
| Username squatting or reassignment | Authenticated atomic reservation prevents races; version 1 tombstones released names permanently. |
| Reused public username | UI warns that voluntary reuse can correlate accounts; authorization continues to use only the opaque alias. |
| Stale authorization state | Two tiers under CON-206: session establishment uses `min(maxClosureAgeSeconds, propagationSlaSeconds)` and prefers an independently resolved closure; continuation uses `maxClosureAgeSeconds`. A revoked device cannot start a new session more than 120 s after submission at the defaults. TEST-240 asserts both bounds and the composed latency. |
| Issuer supplies a closure omitting its own revocations | The bundle closure is the issuer's own account of what it revoked. CON-206 requires an independently resolved closure at session establishment wherever a declared resolver is reachable, and permits the bundle only for a first acceptance on a degraded network, with a record that it happened. |
| Generic consumer over-reads a stale projection | CON-210 requires `validUntil` inside `maxAgeSeconds`, so ordinary W3C validity rules expire it. A set bit stays true at any age because the G-Set is grow-only; an unset bit past `validUntil` means *unavailable*, never *not revoked*. |
| Context host compromise | It has no verification-time effect because contexts are pinned and not fetched. CON-224 makes the digest the authority, so an acquirer of the naming origin cannot change any credential's meaning, and a party that does fetch must compare and fail closed. |
| Whichever wallet answers a first ceremony becomes the account | CON-221 requires the person to compare the home DID fingerprint before the alias is provisioned, with no skip affordance. Every later enrollment is pinned by the authority's binding under CON-204. TEST-238 demonstrates that disabling the confirmation is what lets a substituted wallet succeed. |
| Adversary acquires a lapsed `applicationId` origin and claims succession | CON-225 checks the succession pointer against enrollment keys the wallet pinned at the account's last successful enrollment, not against keys the origin serves now. A freshly minted key fails; the wallet discloses not even whether it holds an identity for that application. |
| Succession is used to launder an account | Exactly one hop is permitted: a statement whose `outgoing` is another unexpired statement's `incoming` is rejected. Both home keys must sign, so no single leaked key nominates a successor. |
| Succession statement leaks a cross-application link | It is never published — not in `alsoKnownAs`, a JRD, a projection, a resolver record, a callback, or a log — and a verifier accepts it only from the wallet or its own authority. Succession is one hop, per account, and confined to one developer's two identifiers. |
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

### Prototype authorisation — hierarchy version 2 only

**Recorded 2026-08-10 on the instruction of the repository owner (HOC).** This
document's §Scope puts *"implementation work in any affected repository"* out of
scope, and `review-gate` is `not-approved`. This entry is the exception the
owner is entitled to make, in the form
[[SPEC-053-key-root-identity#GATE-01]] names — *"or its owner records a
prototype authorisation covering this adoption"* — and in the form already used
for [[EXP-003-proto-003-pairing-reference]] on 2026-08-07.

**Authorised:** implementing hierarchy version 2 —
[[SPEC-004-application-scoped-identity#CON-202]]'s re-rooted derivation,
[[SPEC-004-application-scoped-identity#ADR-223]]'s sealed `hierarchy_root`, the
custody format change that retains it, and the
[[SPEC-004-application-scoped-identity#CON-226]] vectors that pin it. This
closes `FINDING-016`, which made the person-facing surface unbuildable.

**Not authorised**, and stated because an authorisation that does not say what it
excludes is read as covering everything:

- **Deployment or shipment.** This is a prototype. Every remaining box below is
  open, and nothing here permits an identity anyone relies on.
- **The rest of this specification.** The grant, acceptance, ceremony, pairing,
  revocation and platform contracts are untouched by this authorisation.
- **The withdrawn 0.14.0 cluster.** `REQ-232`, the `named` lookup and
  `accountScopeLookup` are removed from this document and are not to be
  implemented from any earlier draft.
- **[[SPEC-004-application-scoped-identity#OQ-208]]'s successor design.** The
  derived account index is a design note under review and is not part of this
  authorisation.

### Prototype authorisation — widened to the adoption SPEC-053 builds against

**Recorded 2026-08-13 on the instruction of the repository owner (HOC).** The
2026-08-10 entry above is scoped to hierarchy version 2 and says in as many
words that *"the grant, acceptance, ceremony, pairing, revocation and platform
contracts are untouched by this authorisation"*. Those are precisely the
contracts [[SPEC-053-key-root-identity]] adopts, so that entry named
`GATE-01`'s second branch without satisfying it. This one does.

**Authorised:** implementing, in the adopting application's repositories, the
contracts [[SPEC-053-key-root-identity]] declares it adopts —
[[SPEC-004-application-scoped-identity#CON-201]],
[[SPEC-004-application-scoped-identity#CON-203]],
[[SPEC-004-application-scoped-identity#CON-204]],
[[SPEC-004-application-scoped-identity#CON-205]],
[[SPEC-004-application-scoped-identity#CON-206]],
[[SPEC-004-application-scoped-identity#CON-207]],
[[SPEC-004-application-scoped-identity#CON-208]],
[[SPEC-004-application-scoped-identity#CON-214]],
[[SPEC-004-application-scoped-identity#CON-220]] and
[[SPEC-004-application-scoped-identity#CON-225]] — together with the
`selfsame-app-identity`, `selfsame-beam` and `selfsame-web-device` surfaces that
expose them.

**Not authorised**, on the same principle as above:

- **Deployment or shipment.** Unchanged, and it is not this authorisation's to
  give: the Tier-1 Gate forbids every Path-B requirement from shipping while any
  box below is open, and [[SPEC-053-key-root-identity#GATE-00]] independently
  holds the adopting code unreachable — no route, no allocation, no durable
  write. An authorisation that permitted shipping would contradict two gates.
- **Contracts outside that list.** `CON-202`'s hierarchy is covered by the
  2026-08-10 entry and by nothing here; the platform-binding and mobile
  contracts are covered by neither.
- **The withdrawn 0.14.0 cluster** and
  [[SPEC-004-application-scoped-identity#OQ-208]]'s successor design, excluded
  by the entry above and excluded again here.

**Why this is smaller than it sounds, and worth recording anyway.** It
authorises *building against a draft*, which is what the adopting repository has
been doing since before either entry existed. Its value is that the practice
becomes a stated one: a reader can now tell which upstream contracts an
adoption was permitted to implement, and a future divergence has a dated
baseline to be measured against. It changes nothing about what may be relied on.

**What this does not discharge.** Every box below stands, unchanged and
unweakened — the cross-model adversarial review, the independent KDF, SPAKE2 and
AEAD vectors, the privacy review, and the human cryptography and security
sign-off. This document remains `not-approved`, and `0.14.0` remains `-draft`
for the reason its `review-gate` gives: a key-derivation change requires new
vectors and renewed sign-off *for the amendment*, and neither exists. An
authorisation permits building; it asserts nothing about correctness, and the
implementation it covers has been reviewed by nobody.

**What this does not discharge.** A prototype authorisation permits building; it
asserts nothing about correctness. The implementation it covers has been
reviewed by nobody, and the boxes below stand unchanged — in particular the
0.14.0 box accepting the widened at-rest asset, which is a question about
consequences rather than about code.

- [ ] A fresh-context cross-model adversarial review covers KDF separation,
      DID/VC key representation, holder binding, alias equivalence, provider
      selection, revocation, application authentication, network MITM,
      same-device app substitution, ceremony mix-up, callback hijack,
      SPAKE2 password mapping/transcript/confirmation, provider routing,
      N=1 burn, downgrade, normalization, and privacy.
- [ ] A second review verifies the revised document and closes every blocking
      finding from the first.
- [ ] A human cryptography/security reviewer approves CON-202, CON-205,
      CON-206, CON-207, CON-210, CON-211, CON-212, CON-213, CON-216,
      CON-217, and CON-218.
- [ ] Mobile platform security reviewers approve CON-214, CON-215, CON-220,
      CON-222, and CON-223, including the exact Android and Apple target/caller
      identity checks and the fail-without-web-fallback behavior.
- [ ] A human security reviewer approves CON-221 and ADR-220 — specifically
      that a person's one-time issuer comparison is an acceptable substitute
      for wallet attestation, given that a registry is unavailable.
- [ ] A human security reviewer approves CON-225 and ADR-222, including the
      pinned-enrollment-key rule and the decision to permit exactly one
      succession hop.
- [ ] The human owner ratifies or lowers the four OQ-201 values, and records
      whether the session-establishment and continuation tiers are accepted as
      derived rather than declared.
- [ ] Two independent implementations reproduce the normative KDF and wire
      vectors required by NFR-202.
- [ ] **0.14.0 — the widened at-rest asset is accepted on the record.** The
      human owner, and a human security reviewer, accept that a custodian's
      sealed `hierarchy_root` now yields every application key under its
      persona where hierarchy version 1 yielded none, and record the entropy of
      the seal that protects it — which for a passcode-derived seal is the
      binding number for an at-rest attacker, not the hierarchy's 128 bits. See
      [[SPEC-004-application-scoped-identity#ADR-223]] consequence 1. This box
      does **not** ask whether the root derivation is sound; it asks whether the
      asset it creates is acceptable, which is a different question and the one
      version 1 never had to answer.
- [ ] **0.14.0 — the corpus is regenerated at the version-2 salt**, its new
      SHA-256 is recorded in the changelog entry, and
      [[SPEC-004-application-scoped-identity#TEST-244]] is green. Version-1
      vectors are **deleted, not retained**: the salt moved, so every value in
      them is unrelated to the current hierarchy, and a void corpus left on
      disk is a corpus something eventually passes against.
- [ ] The `did:crdt` method explicitly defines the `JsonWebKey` projection
      without changing existing DID derivation. As of the pinned revision
      `adb5c7ac`, `resolve()` emits `publicKeyMultibase` and the crate contains
      no `publicKeyJwk`, so the CON-203 document shape and the CON-206 step 6
      check are **not producible today**. The `assertionMethod` half of this
      item is already satisfied: verification-method relationships render into
      the resolved document.
- [ ] The `did:crdt` method enforces verification relationships in delta
      authorization, or this profile records that it does not. At the pinned
      revision `check_authorisation` requires only a known, non-revoked
      verification method, and never consults the `relationships` field it
      stores — so any authorized key may sign `RevokeCredential`, whatever
      relationship it holds. This is inert while an account has exactly one
      verification method and becomes live the moment it has two.
- [ ] `did:crdt` SPEC-035 (Causal Commitment Levels) leaves `stub` status with a
      chosen level and normative clauses. CON-206 steps 5 and 10 require a
      "causally valid" and "causally complete" closure, and that definition is
      currently deferred upstream — the most security-critical check in this
      profile rests on it.
- [ ] The pinned `did:crdt` version for `did-crdt-service-v1` is recorded, with
      its CON-003 and CON-004 conformance suites passing against a node the
      adopting application operates and a node it does not.
- [ ] The Selfsame JSON-LD context is published at the CON-224 IRI with
      immutable content, its `context_digest` recorded here and in the corpus,
      and an archival copy whose content identifier is recorded. The `anuna.io`
      registration runs at least five years with DNSSEC, a CAA record, and
      monitored expiry.
- [ ] A privacy review covers `acct:` harvesting, WebFinger, state lookups,
      optional username reuse, CRDT revocation enumeration, projection
      retrieval, account-scope storage, provider and browser-Origin metadata,
      pairing nameplates/frames/tokens, mobile handoff/callback metadata, and
      cross-application and cross-account correlation.
- [ ] Every open question is resolved normatively or explicitly accepted by the
      human owner with bounded consequences. OQ-203 is resolved by ADR-210,
      OQ-205 by PROTO-003 ADR-407 and ADR-409, OQ-202 by ADR-221 and CON-224,
      OQ-204 by ADR-222 and CON-225, and OQ-207 by CON-220 through CON-223 and
      CON-226. OQ-201's shape is settled and its four values await ratification
      above. OQ-206 is withdrawn on the owner's finding that no production
      SPEC-001 identity exists; that finding is re-confirmed at sign-off, and
      the question reopens if it ever becomes false.
- [ ] SPEC-001 is explicitly amended or profiles this document without
      contradictory credential and derivation claims.
- [ ] PROTO-002, PROTO-003, and PROTO-004 pass their own Tier-1 gates and two
      independent provider/client stacks pass their black-box suites and
      TEST-226 without Anuna infrastructure.
- [ ] A human cryptography reviewer approves
      [[PROTO-004-selfsame-ceremony-envelope-v1#CON-501]] and
      [[PROTO-004-selfsame-ceremony-envelope-v1#CON-502]], and explicitly
      accepts or rejects the constant-nonce construction.
- [ ] Every production profile declares `pairingRecordRelays` per CON-201, or
      documents why it relies on the
      [[PROTO-003-selfsame-pairing-v1#ADR-410]] tier-2 and tier-3 path alone.
- [ ] TEST-201 through TEST-226 pass against the reference implementation, with
      the normative KDF, alias, VC, holder-binding, revocation, account-scope,
      and username vectors published.
- [ ] TEST-227 through TEST-239 pass, including real Android and Apple platform
      adapters with hostile sibling apps and alternate link handlers installed.
- [ ] TEST-240 through TEST-243 pass, and the CON-226 corpus is published with
      its SHA-256 recorded, satisfying the completeness rule, with two
      independent stacks agreeing on every case's accept/reject reason.
- [ ] Human security sign-off records an approval version and commit.

## Open questions

### OQ-201: How stale may authorization state be? — defaults set, ratification outstanding

Version 1 now carries normative defaults and ceilings rather than named
parameters with no values. The remaining decision is whether to ratify or lower
them, not what shape they take.

| Parameter | Default | Ceiling |
|---|---:|---:|
| `revocation.propagationSlaSeconds` | 60 | 300 |
| `revocation.maxClosureAgeSeconds` | 900 | 3,600 |
| `revocation.projection.maxAgeSeconds` | 900 | 3,600 |
| `revocation.maxGrantLifetimeSeconds` | 2,592,000 | 2,592,000 |

A profile MAY lower any value and SHALL NOT exceed a ceiling. A verifier SHALL
reject a profile that does.

These are one question in three costumes, so the useful statement is the
composed bound — **how long a revoked device keeps working**:

```text
verifier that can resolve fresh state
    propagationSlaSeconds + maxClosureAgeSeconds
    = 960 s at the defaults, 3,900 s at the ceilings

verifier relying on expiry alone, per CON-204
    maxGrantLifetimeSeconds
    = 30 days
```

The second line is the one that matters, and it is why
[[SPEC-004-application-scoped-identity#REQ-208]] bounds grant lifetime at all: `CON-204` permits an
application that cannot reach a controller to rely on expiry, so an unbounded
`validUntil` would make revocation cosmetic in exactly that case. Sixteen
minutes online is a deliberate trade — short enough that a stolen device is
contained, long enough that a resolver outage does not sever every session.

Both narrower questions are now answered normatively.

**Does the closure bound differ for a first authorization?** Yes, and the split
is by what the acceptance creates rather than by how new the grant is. CON-206
now defines two tiers: session establishment uses
`min(maxClosureAgeSeconds, propagationSlaSeconds)` and prefers an independently
resolved closure over the bundle-supplied one; continuation inside an
established session uses `maxClosureAgeSeconds`. Strictness is nearly free at
establishment — the person is present and online — and that is where a stolen,
recently revoked device tries to obtain new authority. The composed bound
becomes 120 s at the defaults for a new session and 960 s for an existing one.

**What may a generic consumer infer from an over-age projection?** Nothing
about non-revocation, and everything about revocation. CON-210 now records the
asymmetry the grow-only G-Set implies: a set bit is permanently true and may be
acted on at any age; an unset bit decays, and past `validUntil` the projection
is *unavailable*, not *not revoked*. There is no intermediate reading between
`maxAgeSeconds` and the CRDT bound, because they govern different parties — a
Selfsame verifier never relies on the projection at all. The projection is also
now required to carry a `validUntil` inside `maxAgeSeconds`, so ordinary W3C
validity rules enforce the bound on the consumers it exists for.

Neither answer adds a profile member or changes `profileVersion`, so no
published vector is invalidated.

What remains is human ratification of the four values above, which is a Tier-1
gate item rather than a design question. Selfsame authorization always fails
closed beyond the closure bound.

Owner: HOC + application security owner.

### OQ-202: Who owns the durable VC vocabulary? — RESOLVED by ADR-221 and CON-224

The identifier moves to `https://anuna.io/selfsame/credentials/device-grant/v1`,
and the normative artifact becomes the exact context octets and their SHA-256
rather than whatever the URL serves.

The identifier used through version 0.12.0, `https://selfsame.dev/…`, resolved
no NS records — the specification named a domain the project did not hold, and
an unregistered name inside a signed credential is a name an adversary may
register. `anuna.io` is under project control, which settles the durable-origin
half of this question by inspection.

Making the digest the authority settles the rest. CON-224 fixes immutability,
term-IRI semantics, stewardship transfer, behaviour on loss of the origin, and
behaviour on hostile acquisition; because ADR-209 already forbids
verification-time dereferencing, none of those events changes a verification
result. Naming the vocabulary from an Anuna origin creates no runtime
dependency on Anuna — a conforming verifier never contacts it — and ADR-221
records why that is not a breach of the Infrastructure promise.

The residual items are operational and sit in the Tier-1 gate: registration
term, DNSSEC, CAA, expiry monitoring, and an immutable archival copy with a
recorded content identifier.

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

### OQ-204: Application ID migration — RESOLVED by ADR-222 and CON-225

Domain loss, acquisition, or application merger may require a new
`applicationId`, and version 1 still treats that as a new identity by default.
CON-225's `application-id` profile is the one audited path across the boundary:
a developer succession pointer served by the outgoing origin, a per-account
statement signed by **both** the outgoing and incoming home keys, a
fingerprint comparison the person makes, an expiry bounded by the incoming
profile's `maxGrantLifetimeSeconds`, and a prohibition on publishing the
statement anywhere resolvable.

The decision that carries the security is the pinned-key rule: the pointer is
checked against the enrollment keys the wallet recorded at that account's last
successful enrollment, not against keys an origin serves today. An adversary
who acquires a lapsed `applicationId` origin therefore cannot mint a
succession, which was the case this question was opened for. A developer who
has rotated every pinned key since the person last enrolled loses that person's
succession and falls back to fresh enrollment — an availability cost, not an
authority one.

Correlation is bounded by construction: one statement per account rather than
one per population, delivered only through the CON-219 bundle or the
application's own authenticated channel, and never in `alsoKnownAs`, a JRD, a
projection, or a resolver record. No third application learns that a succession
occurred. The residual — that the incoming application learns the outgoing
account belongs to the same person — is inherent, confined to one developer's
two identifiers, and recorded in the residual-risk list.

Owner: application-profile working group.

### OQ-205: Exact discovery carrier — RESOLVED by PROTO-003 ADR-407 and ADR-409

Every carrier conveys `C` and nothing else — machine carriers as sixteen octets,
a person as twelve words. Routing is resolved afterwards from the signed
ephemeral record at the `C`-derived address defined by
[[PROTO-003-selfsame-pairing-v1#CON-409]], which supplies the canonical
`applicationId`, profile digest, provider, and nameplate. Record transports
follow the [[PROTO-003-selfsame-pairing-v1#ADR-410]] ladder.

This supersedes the resolution originally recorded here, which had QR and
same-device carriers carry application context while a manual path required a
person to convey an HTTPS identity, and which split an eight-digit number into a
two-digit profile route and a six-digit provider nameplate. No carrier now
conveys a route, a nameplate, or an application identifier.

The provider hint still travels inside the sealed offer under CON-209. A global
provider directory, code broadcast, and an endpoint embedded in the code itself
remain rejected. A **secret-derived discovery record is no longer rejected**:
that rejection was correct for a 22-bit code and does not hold at 128 bits,
where the derived address is unenumerable. The exact profile-origin retrieval
mechanism remains the narrower blocking item in OQ-207.

Owner: application-profile working group.

### OQ-206: Migration of the existing SPEC-001 identity — WITHDRAWN; there is no legacy population

This question assumed a population of existing CBCL identities that would need
carrying into the new derivation. There is none: no person holds a SPEC-001
identity in production, so there is nothing to migrate and no migration is
specified.

Version 1 therefore defines **no** transition from
`anuna-ssi/v1/root-key/<persona>` to
[[SPEC-004-application-scoped-identity#CON-202]].
[[SPEC-004-application-scoped-identity#CON-225]] covers `applicationId`
succession only, and an application adopting this profile enrolls fresh
identities. The prohibition in
[[SPEC-004-application-scoped-identity#REQ-202]] stands unqualified: an
identity derived under a different scheme is a different identity.

This is a scope decision by the human owner rather than a technical resolution,
and it is cheap to reverse in one direction only. **It reopens the moment a
single production SPEC-001 identity exists** — after which withdrawing it again
would mean stranding that person. A conforming implementation SHALL NOT
approximate a legacy migration in the meantime, because an unreviewed bridge
built under time pressure is exactly what this question existed to prevent.

What does **not** go away is document reconciliation: SPEC-001 ADR-001's claim
that "`did:crdt` deltas are the credential" and this profile's VC cannot both
describe the same identity, and the codebase currently implements the former.
That remains a Tier-1 gate item, unaffected by the absence of users.

[[PROTO-004-selfsame-ceremony-envelope-v1#OQ-501]] rests on the same assumption
and can likely be withdrawn on the same basis; it is a separate document and
has not been touched here.

Owner: HOC.

### OQ-207: Exact profile-origin and mobile-platform evidence — RESOLVED normatively; verification outstanding

CON-214 and CON-215 fixed the security shape: an origin-authenticated,
backend-signed, short-lived enrollment statement; exact
application/account/device/permission/provider/offer binding; platform
caller/target evidence; and verified-origin consent. A copied public profile,
custom scheme, display label, callback, or TLS session alone remains explicitly
insufficient. All five items now have contracts:

| Item | Closed by |
|---|---|
| 1. HTTPS profile discovery, media type, cache, rotation, redirect, offline | [[SPEC-004-application-scoped-identity#CON-220]] |
| 2. Android targeting, caller identity, certificate rotation, return capability | [[SPEC-004-application-scoped-identity#CON-222]] |
| 3. Apple association, `universalLinksOnly`, claimed HTTPS return | [[SPEC-004-application-scoped-identity#CON-223]] |
| 4. Selecting among independent wallets with no allowlist | [[SPEC-004-application-scoped-identity#CON-221]] and [[SPEC-004-application-scoped-identity#ADR-220]] |
| 5. Cross-platform vectors | [[SPEC-004-application-scoped-identity#CON-226]] |

Item 4 is the one that changed shape rather than being filled in. Authenticating
*which wallet* answered cannot be done without a registry of acceptable builds,
and a registry forecloses the independent implementations
[[SPEC-004-application-scoped-identity#REQ-214]] exists to protect. ADR-220
replaces the question with one the person can answer: confirm at an account's
first enrollment that the **issuer** is the identity their own wallet just
derived. CON-222 accordingly records the target's signing identity for audit
and explicitly does not check it against anything.

Item 5 likewise stopped being a question and became an artifact. CON-226 fixes
the corpus location, case format, canonical form, and — the part that can fail
— a completeness rule requiring a case for every closed error token and every
CON-206 step.

What remains is verification rather than design, and it sits in the Tier-1
gate: mobile platform reviewers must approve CON-220 through CON-223, the
corpus must be published, TEST-237 through TEST-239 and TEST-243 must pass on
real Android and Apple devices with hostile siblings and alternate link
handlers installed, and two independent stacks must agree on every case.

Private-use/custom schemes, clipboard/pasteboard transfer, generic intents,
embedded browser fallbacks, and a credential in a callback remain rejected.
Until those gate items close, the profile-authenticity assumption is still
limited to an in-process prototype and a wallet service must not accept
arbitrary application requests.

Owner: Selfsame wallet + application-profile working group + mobile platform
reviewers.

### OQ-209: is a first-approval distinct at consent, or does a lookalike origin look identical to a familiar one?

`CON-214` step 6 requires consent rendered *"from the authenticated origin and
bound operation rather than caller-supplied presentation metadata"*, and the
wallet honours it — `toConsent` renders `application_id` from the authenticated
profile and falls back to `"(no name given)"` rather than to anything the
caller supplied. That defeats an application claiming to be another one.

**It does not defeat an application that truthfully claims to be itself, when
the person cannot tell that self apart from a familiar one.** A homograph or
near-miss origin — `chat-anuna.io` beside `chat.anuna.io` — authenticates
perfectly, as itself. Every check passes. The prompt is truthful. And it is
rendered identically to the one the person has approved a dozen times, because
nothing on the surface marks it as an origin this wallet has **never seen
before**.

That contrast is the signal a person would actually act on, and first approval
is the only moment it exists. `T6`'s residue is not authentication — `REQ-018`
covers possession and `REQ-019` covers the display — it is that truth without
contrast is what a homograph attack is for.

**The state to answer it is already persisted.** `CON-214` step 2 records the
profile's complete `enrollment.requestSigningKeys` set *against this application
account*, and `CON-225` depends on that history existing. The wallet therefore
already knows whether it has enrolled with an origin before; it simply does not
say so at consent time.

**Not the same control as `REQ-230`.** That confirms an account's first issuer
by fingerprint comparison, with no skip. It establishes *this is my home key*,
and says nothing about *this is a counterparty I have dealt with before*.

Open, because the answer is a design decision rather than a mechanism:

- Does a first approval get a distinct treatment, or a distinct step?
- Is "seen before" keyed on `applicationId`, on the recorded key set, or on
  both — and what does a legitimate `CON-225` succession look like under it, so
  that a rotation does not read as a stranger?
- Does a *near-miss* against a known origin deserve more than mere novelty —
  and if so, is that comparison the wallet's to make, given that a false
  "similar to" is its own hazard?

Raised by the adopting application (`cbcl-bus`, [[SPEC-053-key-root-identity]])
while dispositioning `T6` of [[SPEC-001-device-key-provisioning]]'s attack
table. The adopter's whole defence against impersonation is that an attacker
must use their **own** authenticated origin; this is the signal that makes a
person notice they have.

### OQ-208: how does an application with no independent login return an account scope?

[[SPEC-004-application-scoped-identity#REQ-217]] makes the authenticated account
record the carrier of the `accountScopeId`. That works for an application with
its own login and fails for one whose **only** account credential is the
Selfsame identity: a wallet restoring from a recovery phrase holds no key yet,
so there is nothing to authenticate it with, and the scope stays unreachable
exactly when it is needed.

0.14.0 attempted an unauthenticated `named` lookup keyed on the account's
human-readable alias and **withdrew it** on adversarial review. It published the
scope, which [[SPEC-004-application-scoped-identity#CON-211]] forbids over a
public protocol; it made mandatory the username that
[[SPEC-004-application-scoped-identity#REQ-218]] guarantees is optional and that
[[SPEC-004-application-scoped-identity#NFR-201]] calls an explicit privacy
exception; it rested recovery on a selector
[[SPEC-004-application-scoped-identity#CON-212]] permits a person to rename or
remove; and it defined no wire, in a document where every other cross-party
operation is specified byte-exactly.

**The shape a resolution probably takes**, recorded so the next attempt does not
restart from the same dead end: the selector should be a value only a holder of
the recovery secret can produce, and `application_node` is derivable from the
phrase and the `applicationId` **without** the scope. A commitment to it — a
digest, or better a MAC over a responder challenge to defeat replay — identifies
the person at that application without naming them publicly, is unguessable
rather than enumerable, and returns the *set* of that person's accounts there,
which is what [[SPEC-004-application-scoped-identity#ADR-210]]'s ordinary
account switcher already consumes.

That is a sketch, not a decision. It needs its own contract — endpoint, request
and response grammars, transport security, replay binding, closed error tokens
and a rate bound — and it is deliberately **not** part of a key-derivation
amendment. **Owner: HOC.**

## Traceability

| User outcome | Requirements | Contracts | Tests |
|---|---|---|---|
| Different home identity per application account | [[SPEC-004-application-scoped-identity#REQ-201]], [[SPEC-004-application-scoped-identity#REQ-202]], [[SPEC-004-application-scoped-identity#REQ-213]] | [[SPEC-004-application-scoped-identity#CON-201]], [[SPEC-004-application-scoped-identity#CON-202]], [[SPEC-004-application-scoped-identity#CON-211]] | TEST-201–203, [[SPEC-004-application-scoped-identity#TEST-219]], [[SPEC-004-application-scoped-identity#TEST-222]], [[SPEC-004-application-scoped-identity#TEST-223]] |
| A custodian that seals only the hierarchy root can derive without the recovery phrase | [[SPEC-004-application-scoped-identity#REQ-201]], [[SPEC-004-application-scoped-identity#REQ-213]] | [[SPEC-004-application-scoped-identity#CON-202]]; [[SPEC-004-application-scoped-identity#ADR-223]] | [[SPEC-004-application-scoped-identity#TEST-244]] |
| Multiple accounts switch without Selfsame configuration | [[SPEC-004-application-scoped-identity#REQ-216]], [[SPEC-004-application-scoped-identity#REQ-217]] | [[SPEC-004-application-scoped-identity#CON-202]], [[SPEC-004-application-scoped-identity#CON-211]] | [[SPEC-004-application-scoped-identity#TEST-222]], [[SPEC-004-application-scoped-identity#TEST-223]] |
| RFC 7565 stable alias and optional username | [[SPEC-004-application-scoped-identity#REQ-203]], [[SPEC-004-application-scoped-identity#REQ-204]], [[SPEC-004-application-scoped-identity#REQ-218]] | [[SPEC-004-application-scoped-identity#CON-203]], [[SPEC-004-application-scoped-identity#CON-204]], [[SPEC-004-application-scoped-identity#CON-212]] | TEST-204–206, [[SPEC-004-application-scoped-identity#TEST-225]] |
| Portable VC device grant | REQ-205–208, [[SPEC-004-application-scoped-identity#REQ-211]] | CON-205–210, [[SPEC-004-application-scoped-identity#CON-219]] | TEST-207–213, [[SPEC-004-application-scoped-identity#TEST-217]], [[SPEC-004-application-scoped-identity#TEST-236]] |
| A defined, sealed ceremony envelope and payload | [[SPEC-004-application-scoped-identity#REQ-205]], [[SPEC-004-application-scoped-identity#REQ-211]], [[SPEC-004-application-scoped-identity#REQ-222]], [[SPEC-004-application-scoped-identity#REQ-223]] | [[SPEC-004-application-scoped-identity#ADR-218]], [[SPEC-004-application-scoped-identity#CON-217]], [[SPEC-004-application-scoped-identity#CON-219]]; PROTO-004 CON-501–504 | [[SPEC-004-application-scoped-identity#TEST-236]]; PROTO-004 TEST-501–506 |
| An alias usable only once reciprocally bound | [[SPEC-004-application-scoped-identity#REQ-203]], [[SPEC-004-application-scoped-identity#REQ-204]] | [[SPEC-004-application-scoped-identity#CON-203]], [[SPEC-004-application-scoped-identity#CON-204]], [[SPEC-004-application-scoped-identity#CON-206]] | [[SPEC-004-application-scoped-identity#TEST-205]], [[SPEC-004-application-scoped-identity#TEST-206]] |
| Controller-owned convergent revocation | [[SPEC-004-application-scoped-identity#REQ-207]], [[SPEC-004-application-scoped-identity#REQ-208]] | [[SPEC-004-application-scoped-identity#CON-205]], [[SPEC-004-application-scoped-identity#CON-206]], [[SPEC-004-application-scoped-identity#CON-210]] | TEST-211–213, [[SPEC-004-application-scoped-identity#TEST-224]] |
| No user endpoint configuration | [[SPEC-004-application-scoped-identity#REQ-209]], [[SPEC-004-application-scoped-identity#REQ-212]], [[SPEC-004-application-scoped-identity#REQ-219]], [[SPEC-004-application-scoped-identity#REQ-227]] | [[SPEC-004-application-scoped-identity#CON-208]], [[SPEC-004-application-scoped-identity#CON-209]], [[SPEC-004-application-scoped-identity#CON-213]], [[SPEC-004-application-scoped-identity#CON-216]] | [[SPEC-004-application-scoped-identity#TEST-214]], [[SPEC-004-application-scoped-identity#TEST-215]], [[SPEC-004-application-scoped-identity#TEST-218]], [[SPEC-004-application-scoped-identity#TEST-226]], [[SPEC-004-application-scoped-identity#TEST-232]], [[SPEC-004-application-scoped-identity#TEST-234]] |
| No mandatory Anuna infrastructure | [[SPEC-004-application-scoped-identity#REQ-210]], [[SPEC-004-application-scoped-identity#REQ-214]], [[SPEC-004-application-scoped-identity#REQ-219]], [[SPEC-004-application-scoped-identity#REQ-227]] | [[SPEC-004-application-scoped-identity#CON-201]], [[SPEC-004-application-scoped-identity#CON-208]], [[SPEC-004-application-scoped-identity#CON-213]], [[SPEC-004-application-scoped-identity#CON-216]] | [[SPEC-004-application-scoped-identity#TEST-216]], [[SPEC-004-application-scoped-identity#TEST-220]], [[SPEC-004-application-scoped-identity#TEST-226]], [[SPEC-004-application-scoped-identity#TEST-234]] |
| Human twelve-word pairing code with SPAKE2 | [[SPEC-004-application-scoped-identity#REQ-226]], [[SPEC-004-application-scoped-identity#REQ-229]]; PROTO-003 REQ-401–409 | [[SPEC-004-application-scoped-identity#CON-217]], [[SPEC-004-application-scoped-identity#CON-218]]; PROTO-003 CON-401–409 | [[SPEC-004-application-scoped-identity#TEST-232]], [[SPEC-004-application-scoped-identity#TEST-233]], [[SPEC-004-application-scoped-identity#TEST-235]]; PROTO-003 TEST-401–413 |
| Many applications and providers route without a global directory | [[SPEC-004-application-scoped-identity#REQ-209]], [[SPEC-004-application-scoped-identity#REQ-210]], [[SPEC-004-application-scoped-identity#REQ-212]], [[SPEC-004-application-scoped-identity#REQ-227]] | [[SPEC-004-application-scoped-identity#CON-201]], [[SPEC-004-application-scoped-identity#CON-208]], [[SPEC-004-application-scoped-identity#CON-213]], [[SPEC-004-application-scoped-identity#CON-216]]; PROTO-003 [[SPEC-004-application-scoped-identity#CON-409]] | TEST-214–216, [[SPEC-004-application-scoped-identity#TEST-218]], [[SPEC-004-application-scoped-identity#TEST-226]], [[SPEC-004-application-scoped-identity#TEST-232]], [[SPEC-004-application-scoped-identity#TEST-234]]; PROTO-003 [[SPEC-004-application-scoped-identity#TEST-413]] |
| Replaceable blind pairing and rendezvous | [[SPEC-004-application-scoped-identity#REQ-209]], [[SPEC-004-application-scoped-identity#REQ-212]], [[SPEC-004-application-scoped-identity#REQ-219]], [[SPEC-004-application-scoped-identity#REQ-228]]; PROTO-002 REQ-301–308; PROTO-003 REQ-401–409 | [[SPEC-004-application-scoped-identity#CON-208]], [[SPEC-004-application-scoped-identity#CON-209]], [[SPEC-004-application-scoped-identity#CON-213]], CON-216–218; PROTO-002 CON-301–308; PROTO-003 CON-401–409 | TEST-214–216, [[SPEC-004-application-scoped-identity#TEST-218]], [[SPEC-004-application-scoped-identity#TEST-220]], [[SPEC-004-application-scoped-identity#TEST-226]], [[SPEC-004-application-scoped-identity#TEST-233]]; PROTO-002 TEST-301–310; PROTO-003 TEST-401–413 |
| MITM-resistant same-device mobile authorization without self-scan | REQ-220–229 | [[SPEC-004-application-scoped-identity#CON-206]], [[SPEC-004-application-scoped-identity#CON-207]], [[SPEC-004-application-scoped-identity#CON-209]], CON-214–219 | TEST-227–236 |
| Either party may start a pairing | [[SPEC-004-application-scoped-identity#REQ-226]], [[SPEC-004-application-scoped-identity#REQ-227]]; PROTO-003 [[SPEC-004-application-scoped-identity#REQ-409]] | [[SPEC-004-application-scoped-identity#CON-216]]; PROTO-003 [[SPEC-004-application-scoped-identity#CON-402]], [[SPEC-004-application-scoped-identity#CON-409]] | [[SPEC-004-application-scoped-identity#TEST-232]], [[SPEC-004-application-scoped-identity#TEST-234]], [[SPEC-004-application-scoped-identity#TEST-235]]; PROTO-003 [[SPEC-004-application-scoped-identity#TEST-413]] |
| Cross-application and cross-account privacy | [[SPEC-004-application-scoped-identity#REQ-201]], [[SPEC-004-application-scoped-identity#REQ-203]], [[SPEC-004-application-scoped-identity#REQ-213]], REQ-215–218 | CON-202–205, [[SPEC-004-application-scoped-identity#CON-211]], [[SPEC-004-application-scoped-identity#CON-212]] | [[SPEC-004-application-scoped-identity#TEST-201]], TEST-204–206, [[SPEC-004-application-scoped-identity#TEST-219]], TEST-221–223, [[SPEC-004-application-scoped-identity#TEST-225]] |
| Compatibility with the `did:crdt` method boundary | [[SPEC-004-application-scoped-identity#REQ-201]], [[SPEC-004-application-scoped-identity#REQ-203]], [[SPEC-004-application-scoped-identity#REQ-205]], [[SPEC-004-application-scoped-identity#REQ-208]] | [[SPEC-004-application-scoped-identity#CON-202]], [[SPEC-004-application-scoped-identity#CON-203]], [[SPEC-004-application-scoped-identity#CON-210]] | [[SPEC-004-application-scoped-identity#TEST-207]], [[SPEC-004-application-scoped-identity#TEST-213]], [[SPEC-004-application-scoped-identity#TEST-224]] |
| An authenticated profile whose key never comes from the caller | [[SPEC-004-application-scoped-identity#REQ-222]], [[SPEC-004-application-scoped-identity#REQ-227]] | [[SPEC-004-application-scoped-identity#CON-201]], [[SPEC-004-application-scoped-identity#CON-214]], [[SPEC-004-application-scoped-identity#CON-220]] | [[SPEC-004-application-scoped-identity#TEST-237]], [[SPEC-004-application-scoped-identity#TEST-243]] |
| A first issuer confirmed rather than trusted | [[SPEC-004-application-scoped-identity#REQ-222]], [[SPEC-004-application-scoped-identity#REQ-230]] | [[SPEC-004-application-scoped-identity#CON-204]], [[SPEC-004-application-scoped-identity#CON-221]]; [[SPEC-004-application-scoped-identity#ADR-220]] | [[SPEC-004-application-scoped-identity#TEST-238]], [[SPEC-004-application-scoped-identity#TEST-239]] |
| Platform dispatch that fails rather than falls back | [[SPEC-004-application-scoped-identity#REQ-220]], [[SPEC-004-application-scoped-identity#REQ-223]], [[SPEC-004-application-scoped-identity#REQ-225]] | [[SPEC-004-application-scoped-identity#CON-215]], [[SPEC-004-application-scoped-identity#CON-222]], [[SPEC-004-application-scoped-identity#CON-223]] | [[SPEC-004-application-scoped-identity#TEST-230]], [[SPEC-004-application-scoped-identity#TEST-239]] |
| Bounded revocation latency without severing offline sessions | [[SPEC-004-application-scoped-identity#REQ-207]], [[SPEC-004-application-scoped-identity#REQ-208]] | [[SPEC-004-application-scoped-identity#CON-201]], [[SPEC-004-application-scoped-identity#CON-206]], [[SPEC-004-application-scoped-identity#CON-210]] | [[SPEC-004-application-scoped-identity#TEST-213]], [[SPEC-004-application-scoped-identity#TEST-240]] |
| A vocabulary that survives losing its domain | [[SPEC-004-application-scoped-identity#REQ-205]], [[SPEC-004-application-scoped-identity#REQ-207]] | [[SPEC-004-application-scoped-identity#CON-205]], [[SPEC-004-application-scoped-identity#CON-224]]; [[SPEC-004-application-scoped-identity#ADR-209]], [[SPEC-004-application-scoped-identity#ADR-221]] | [[SPEC-004-application-scoped-identity#TEST-241]] |
| Carrying an account across an `applicationId` change, once and visibly | [[SPEC-004-application-scoped-identity#REQ-202]], [[SPEC-004-application-scoped-identity#REQ-231]] | [[SPEC-004-application-scoped-identity#CON-212]], [[SPEC-004-application-scoped-identity#CON-221]], [[SPEC-004-application-scoped-identity#CON-225]]; [[SPEC-004-application-scoped-identity#ADR-222]] | [[SPEC-004-application-scoped-identity#TEST-242]] |
| One conformance corpus two stacks must agree on | [[SPEC-004-application-scoped-identity#REQ-222]], [[SPEC-004-application-scoped-identity#REQ-227]] | [[SPEC-004-application-scoped-identity#CON-226]] | [[SPEC-004-application-scoped-identity#TEST-243]] |

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
binding, application enrollment evidence, profile discovery, first-enrollment
confirmation, mobile caller/wallet identity, same-device dispatch, pairing
grammar/entropy/routing, SPAKE2 suite/transcript, confirmation/burn behavior,
callback authority, credential context IRI or digest, identity succession,
threat-model boundary, or the PROTO-002/PROTO-003 version is a Tier-1 normative
amendment and requires new vectors plus renewed security sign-off.

A change to the [[SPEC-004-application-scoped-identity#CON-226]] corpus is such
an amendment, and its new SHA-256 is recorded in the changelog entry. The
corpus is never edited to match an implementation.

## Normative and informative sources

Normative internal protocols:

- [[PROTO-002-selfsame-rendezvous-v1]] defines the wire and operator contract
  named by `selfsame-rendezvous-v1` after PAKE confirmation.
- [[PROTO-003-selfsame-pairing-v1]] defines the routable human code,
  application-to-wallet SPAKE2, blind relay, confirmation/burn rules, and
  mailbox-secret derivation named by `selfsame-pairing-v1`.
- [[PROTO-004-selfsame-ceremony-envelope-v1]] defines the envelope key
  schedule, AEAD, sealed record, and payload recognition rules that carry the
  [[SPEC-004-application-scoped-identity#CON-219]] offer and bundle.

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
- IETF/IRTF, RFC 3986, RFC 4648, RFC 5234, RFC 5869, RFC 7515, RFC 8032,
  [RFC 8439 — ChaCha20 and Poly1305 for IETF
  Protocols](https://datatracker.ietf.org/doc/html/rfc8439),
  RFC 8785, [RFC 9382 — SPAKE2](https://datatracker.ietf.org/doc/html/rfc9382),
  [RFC 9496 — ristretto255 and
  decaf448](https://datatracker.ietf.org/doc/html/rfc9496), and BIP-39.

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
- RFC 9382 requires explicit key confirmation and warns that SPAKE2 is not
  augmented. Selfsame makes the application and wallet the PAKE endpoints so
  a provider stores no password-equivalent verifier.
- Twelve BIP-39 English words are a transcription-resistant rendering of 128
  bits, not a wallet mnemonic and never a bearer secret. The words are never
  the protocol value; `C` is.
- A provider-local numeric nameplate cannot identify an arbitrary service.
  [[PROTO-003-selfsame-pairing-v1#CON-409]] supplies the missing
  many-application/many-provider context by resolving a signed record at an
  address derived from the code, rather than by putting context in the code or
  in a person's mouth.
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

- **0.16.0-draft — 2026-08-21 — web manual binding (Tier-1 amendment, PROPOSED).**
  Repairs the internal conflict named by
  [[SPEC-004-application-scoped-identity#ADR-224]]: the adoption checklist
  scoped platform bindings to same-device mobile while
  [[SPEC-004-application-scoped-identity#CON-214]] required one
  unconditionally, leaving a web-only application unable to construct any
  enrolment statement honestly. Adds the `platform: "web"` binding form to
  [[SPEC-004-application-scoped-identity#CON-201]], the contract
  [[SPEC-004-application-scoped-identity#CON-227]], and
  [[SPEC-004-application-scoped-identity#TEST-246]]; extends the CON-214
  binding-form list and the [[SPEC-004-application-scoped-identity#CON-226]]
  group-3 corpus obligation. The CON-214 statement grammar is unchanged.
  Amends profile version 1 in place: no ratified profile and no deployed
  recogniser exist outside this repository's pinned builds (rationale in
  ADR-224). **Affected downstream artefacts** (Amendment Channels step 1,
  beyond this document's own): cbcl-bus `SPEC-053` CON-002's mobileBindings
  row — *"empty is a statement… a browser cannot claim a platform binding"* —
  mandates the opposite disposition and owes a follow-up amendment, and
  cbcl-bus `scripts/gen-production-profile.mjs` makes the Apple blanks
  mandatory and owes the web-binding form. The TEST-246 corpus cases have
  landed: `con_227_web_binding` (seven `web-manual` traces in group 3) and
  three group-2 recognition negatives in `con_201_application_profile`;
  the corpus SHA-256 is
  `723f75b9296e55f988f21f9d11451111910eda1c8a6b2082cdc29376befe7853`.
  Owner approval SHALL NOT be recorded in this entry before the reviews
  required by the risk tier are — Amendment Channels made the vectors part
  of the amendment, and they now are. This is a Tier-1 normative amendment (enrollment evidence,
  mobile caller identity): it grants nothing until cross-model adversarial
  review and the human owner's approval are recorded here.
  Fresh-context adversarial review 2026-08-21: APPROVE-WITH-CHANGES, all
  findings folded — record at
  `specs/trajectory/SPEC-004/adr-224-adversarial-review-2026-08-21.md`.

- **0.15.0-draft — 2026-08-17 — pairing cutover disposition.**
  Records the owner-approved [[SPEC-007-cbcl-pairing-cutover]] development cutover.
  Affected artifacts are named in the cutover disposition above.
  TEST-818 owns the new payload-bound vectors.
  CON-206 remains authoritative and every unrelated Tier-1 duty remains open.
  This revision grants no production approval.

- **0.14.0-draft — 2026-08-10 — PROPOSAL, not an accepted version.**
  Re-roots [[SPEC-004-application-scoped-identity#CON-202]] at a new
  `hierarchy_root` — a 64-octet HKDF-SHA-512 output over `bip39_seed` under the
  label `selfsame/v2/hierarchy-root/`, a **sibling** of
  [[SPEC-001-device-key-provisioning]]'s persona root rather than the BIP-39
  seed — and bumps the hierarchy salt to
  `selfsame/application-account-key-hierarchy/v2`.

  *Status.* Marked `-draft`, and the version number does not advance, because a
  key-derivation change must arrive with new vectors and renewed security
  sign-off **for the amendment**; both are instead Tier-1 gate boxes below,
  which is not what the Amendment Channels ask for.

  *Reason.* `FINDING-016` in [[EXP-001-findings]]: SPEC-001 custody seals
  `root_seed(mnemonic, persona)` and stores the phrase nowhere, while hierarchy
  version 1 rooted at the BIP-39 seed. The two rooted at different points of one
  secret, so a wallet that had completed onboarding could not derive a home DID
  for any application without the person re-entering twelve words — which
  [[SPEC-004-application-scoped-identity#REQ-213]] and `HP-7` (*Restore*) in
  [[person-happy-paths]] both promise is unnecessary. Evidence:
  `app_identity_derive` in the reference wallet returns a fixture and documents
  why.

  *Why a sibling root.* Rooting at SPEC-001's persona root was drafted and
  rejected on review: it would have made one secret both an Ed25519 private seed
  and HKDF input keying material, collided with SPEC-001 `REQ-024`'s per-use
  presence rule, added a normative dependency on an unapproved external Tier-1
  draft, and carried the root signing seed into a crate that compiles to wasm.
  [[SPEC-004-application-scoped-identity#ADR-223]] records all four alternatives.

  *Affected artefacts.* `CON-202` (re-rooted; salt bumped; salt spelling fixed
  with the RFC 5869 equivalence stated; the empty passphrase and `persona = 0`
  stated as constants of the hierarchy version; vector list extended;
  `Verified by` corrected); `REQ-213` (the hierarchy version named as a property
  of this specification rather than of an account); `ADR-201` (amended — its
  rejection of a "32-bit persona index" contradicted `CON-202`); `ADR-223`
  (new); `TEST-244` (new); the *User restores* narrative; `OQ-208` (new); Trust
  boundaries and Explicit exclusions in the threat model; two Tier-1 gate boxes;
  one traceability row.

  *Not amended.* `REQ-217`, `CON-201`, `CON-211`, `CON-212`, `REQ-218`,
  `NFR-201`, `CON-206`, `CON-219`, `CON-214`, `REQ-231` and every credential,
  wire and ceremony format. Protected assets and the Orientation's privacy
  statements needed no change: the `accountScopeId` remains private and
  authenticated-only, as it was in 0.13.1.

  *Withdrawn before proposal, and why it is recorded.* A first draft of this
  amendment added `REQ-232` — a per-account record of the hierarchy version and
  persona — plus an `accountScopeLookup` profile member with an unauthenticated
  `named` lookup mode, and `TEST-245`. Four adversarial passes, one cross-model
  and three fresh-context, found the cluster unsound and it is **removed
  entirely**:

  - `REQ-232` mandated a value no defined wire could carry.
    [[SPEC-004-application-scoped-identity#CON-219]]'s offer payload and
    [[SPEC-004-application-scoped-identity#CON-214]]'s enrollment evidence are
    closed member sets that reject unknown members, so no ceremony could deliver
    a hierarchy version and every derivation would have failed closed — not only
    restores. The changelog of that draft stated *"every credential, wire and
    ceremony format are untouched"* as a reassurance; it was the defect.
  - `named` published the scope, which
    [[SPEC-004-application-scoped-identity#CON-211]] forbids over a public
    protocol; made mandatory the username
    [[SPEC-004-application-scoped-identity#REQ-218]] guarantees is optional;
    rested recovery on a selector
    [[SPEC-004-application-scoped-identity#CON-212]] lets a person rename or
    remove; and defined no wire at all.
  - The per-account version bought optionality on a migration
    [[SPEC-004-application-scoped-identity#REQ-231]] has declined to support.
    With one hierarchy version live at a time, a bump is a re-enrolment, and an
    account derived under an obsolete version yields a home DID the authority's
    binding refuses — fail-closed, which is the required posture.

  The genuine problem `named` was reaching for — an application whose only
  account credential is the Selfsame identity cannot authenticate a
  just-restored wallet — is unsolved and recorded as
  [[SPEC-004-application-scoped-identity#OQ-208]], with the shape a resolution
  probably takes. It needs its own contract and does not belong in a
  key-derivation amendment.

  *Cost, stated plainly.* Hierarchy-version-1 vectors are void, not deprecated.
  A custodian must seal 64 more octets, in a format change with no migration
  because there is no population. And a custody compromise now yields every
  application key under that persona where version 1 yielded none — the asset is
  created here, it is recorded in Explicit exclusions, and it is a gate box
  rather than an assurance.

  *Corpus.* `test-vectors/spec-004-v1.json` regenerated at the version-2 salt;
  the version-1 values are gone rather than retained beside the new ones. Its
  SHA-256 is
  `b0be85945b4b0f9ca0b9f6ff4e01dc0e69cfd4a2753f0b6ab0cf93f6bce30803`. The
  filename's `v1` names the corpus profile, not the hierarchy version, and the
  two now differ.

  Every Tier-1 gate box remains open, and two were added.

- **0.13.1 — 2026-08-07 — draft, normative.** Follows PROTO-003 0.5.1's
  correction to the CON-409 bearer-code model. A record signature and PAKE
  confirmation bind peers to a claimed target but cannot establish that target
  as the person's intended application when a code holder can make a
  self-consistent record. The linking flow, CON-216, TEST-234, authorization
  diagram, and threat analysis therefore require visible target disclosure and
  explicit pairing-target approval before a nameplate claim or PAKE frame; that
  approval neither authenticates an application nor issues a grant. CON-214 and
  separate application-account consent remain mandatory. No key hierarchy,
  credential format, wire format, or cryptographic construction changes. Every
  Tier-1 gate box remains open.

- **0.13.0 — 2026-07-31 — draft, normative.** Closes the remaining open
  questions. Every OQ now has a normative resolution; what blocks the gate is
  review, ratification, and evidence rather than design.

  *OQ-207 items 1–4 were already answered in the working tree by CON-220
  through CON-223, ADR-220, REQ-230, and TEST-237 through TEST-239.* This
  version finishes item 5 with [[SPEC-004-application-scoped-identity#CON-226]],
  which turns "publish vectors" into `test-vectors/spec-004-v1.json` with a
  case format, a canonical form, and a completeness rule that can fail: a case
  for every closed error token and every CON-206 step, or the gate does not
  close. TEST-243 asserts it and requires two stacks to agree on the *reason*,
  not merely the outcome. The OQ-207 entry is rewritten as a five-row table
  from item to contract, and the stale "blocking OQ-207" references in CON-201,
  CON-214, and the trust-boundary list are retired.

  *OQ-201 was three parameters and two unanswered questions.* Both are now
  answered without a profile member, so `profileVersion` is unchanged and no
  published vector is invalidated. CON-206 gains freshness tiers: establishing
  a session uses `min(maxClosureAgeSeconds, propagationSlaSeconds)` and prefers
  an independently resolved closure over the bundle-supplied one; continuing an
  established session uses `maxClosureAgeSeconds`. A revoked device therefore
  cannot start a new session more than 120 s after submission at the defaults,
  while a resolver outage does not sever live sessions for fifteen minutes. The
  resolver preference matters on its own: a bundle closure is the issuer's own
  account of its own revocations. CON-210 records the grow-only asymmetry a
  generic consumer may rely on — a set bit is true at any age, an unset one
  past `validUntil` means unavailable — and now requires the projection to
  carry a `validUntil` inside `maxAgeSeconds` so ordinary W3C validity rules
  enforce the bound on the consumers it exists for.

  *OQ-202's provisional origin did not resolve.* `selfsame.dev` had no NS
  records, so the document named a domain the project did not hold, and an
  unregistered name inside a signed credential is one an adversary may
  register. The context and vocabulary IRIs move to `anuna.io`, an origin under
  project control, and ADR-221 plus CON-224 make the SHA-256 of the context
  octets the authority so the origin is a name and a mirror rather than a
  dependency. Nothing dereferences it — ADR-209 already forbade that — so loss
  or hostile acquisition of the domain changes no verification result. Naming a
  vocabulary is not hosting infrastructure, and TEST-241 verifies a grant with
  all network egress blocked.

  *OQ-204 gets ADR-222, CON-225, REQ-231, and TEST-242.* When a developer's
  canonical `applicationId` changes, one audited path carries an account
  across: a pointer served by the outgoing origin, a per-account statement
  signed by both the outgoing and incoming home keys, a fingerprint comparison
  the person makes, a bounded expiry, and no publication anywhere resolvable.
  Two signatures are required, so no single leaked key nominates a successor.
  One hop is permitted, so a compromised intermediate cannot launder an
  account.

  The load-bearing decision is the pinned-key rule. A succession pointer is
  checked against the enrollment keys the wallet recorded at that account's
  last successful enrollment, not against keys the outgoing origin serves now,
  which converts a DNS-strength control into a key-strength one and closes the
  lapsed-domain case OQ-204 was opened for. CON-214 step 2 accordingly gains
  the duty to record that key set.

  *OQ-206 is withdrawn rather than resolved.* No person holds a SPEC-001
  identity, so there is no population to migrate and version 1 specifies no
  transition from the legacy derivation. This is a scope decision by the human
  owner, reversible in one direction only: it reopens the moment a single
  production legacy identity exists. Reconciling SPEC-001 with this document
  remains a gate item, since the codebase still implements it.

  ADR-222 records why succession is a signed statement rather than a `did:crdt`
  delta — revocation fails unsafe when withheld and so needs convergent state,
  while succession fails closed and does not — and rejects rotating the key in
  place, which would descend the new application's identity from the old
  application's node and break NFR-202's reproducibility. CON-225 also fixes an
  ordering that would otherwise strand grants: `Deactivate` is an irreversible
  latch that rejects every later mutation including `RevokeCredential`, so the
  outgoing DID is deactivated only after its grants are revoked or expired.

  Two upstream `did:crdt` findings are recorded at the gate, both verified
  against the pinned revision `adb5c7ac`. `publicKeyJwk` does not exist in the
  crate — `resolve()` emits `publicKeyMultibase` — so the CON-203 document
  shape and the CON-206 step 6 check are not producible today, though the
  `assertionMethod` half of that item is already satisfied. And
  `check_authorisation` never consults the `relationships` field it stores, so
  any authorized verification method may sign `RevokeCredential`; that is inert
  at one key per account and live at two.

  Also: CON-222 and CON-223 gain the Implements/Verified-by footers the
  bidirectional traceability discipline requires; TEST-214 now validates
  NFR-207 and asserts its latency bound, so no artefact is left unreferenced by
  every other; the gate goes from eighteen items to twenty-three and loses
  none; the threat table gains nine rows; and the residual-risk list
  records what CON-221 and CON-225 do not cover — including that a person who
  confirms without comparing reinstates the trust-on-first-use CON-221 removes,
  and no protocol control detects it.

  No key hierarchy, DID construction, VC payload shape, revocation semantics,
  pairing grammar, SPAKE2 suite, envelope, or acceptance predicate changed. The
  credential context IRI did change, which is a Tier-1 amendment requiring new
  vectors.

  Versions 0.8.0 and 0.10.0 through 0.12.0 bumped the frontmatter without
  changelog entries; that gap is recorded here rather than reconstructed, and
  the commits `1c092b3`, `2cc3b42`, `4852541`, and `4bec117` carry those
  descriptions in full.
- **0.9.0 — 2026-07-31 — draft, normative.** Follows
  [[PROTO-003-selfsame-pairing-v1]] 0.3.0, which replaces the human pairing code
  and its routing. The code becomes twelve BIP-39 words rendering a 128-bit `C`;
  route and nameplate leave the code and are resolved from a signed ephemeral
  record at a `C`-derived address; either party may initiate, with the
  application always SPAKE2 role A.

  Amends the Orientation controls digest, REQ-226, and REQ-227. Marks ADR-215
  SUPERSEDED, ADR-216 PARTIALLY SUPERSEDED, and CON-216 SUPERSEDED, and reopens
  CON-209's rejection of a secret-derived discovery record — a rejection that was
  correct at 22 bits and does not hold at 128.

  Completes the reconciliation. CON-216 is rewritten from a withdrawn
  route-in-the-code bootstrap into the application's obligations around
  PROTO-003 CON-409, including the wallet-initiated ordering. CON-215's handoff
  carries `c` rather than a word rendering and no longer duplicates application
  context. TEST-232, TEST-234, and TEST-235 are rewritten to test resolution
  rather than route parsing, and TEST-235 now covers six carrier/direction
  traces. REQ-209, REQ-226, REQ-227, REQ-229, CON-218, the Orientation controls
  digest, the MITM invariant, the threat table, the standards notes, and
  traceability all follow.

  ADR-215 and ADR-216 keep their original reasoning under supersession headers,
  which is the correct treatment for a decision log: an ADR records what was
  decided and why, and is superseded rather than edited.

  The Tier-1 gate item that tracked this reconciliation is replaced by one
  tracking PROTO-003 OQ-401 — no transport for the CON-409 record is yet
  permitted by REQ-210, so no conforming production client can route a
  first-encounter pairing. No key hierarchy, DID construction, VC profile,
  revocation semantics, envelope, or acceptance predicate changed.
- **0.7.0 — 2026-07-31 — draft, normative.** Closes three review findings, each
  a gap between documents rather than a defect inside one.

  *The ceremony envelope had no owner.* PROTO-002 placed offer/grant/AEAD
  formats out of scope while PROTO-003 delegated that same contract to
  PROTO-002, so the layer carrying every device grant was unspecified. Adds
  [[PROTO-004-selfsame-ceremony-envelope-v1]] owning the key schedule, AEAD,
  sealed record, and recognition rules, and CON-219 owning the offer and
  bundle payload member sets. Adds ADR-218 and TEST-236; affects REQ-211,
  NFR-202, NFR-208, CON-209, CON-214, CON-215, CON-217, and the trust-boundary
  list.

  *`offerDigest` was undefined and circular.* It was referenced thirteen times
  and defined nowhere, and its two carriers — the CON-214 enrollment evidence
  and the CON-209 provider hint — both sat inside the offer they digested.
  CON-219 defines it over `offer_core`, the offer payload with exactly those
  two members removed, and fixes the construction order so a developer backend
  can sign before the offer is sealed. Affects CON-209 and CON-214.

  *First-time enrollment through a pairing ceremony was impossible.* CON-204
  forbade issuing a grant before the alias was provisioned, but in every
  PROTO-003 ceremony the wallet derives the home DID that the authority needs
  to recompute the localpart, so no ordering satisfied both. Moves the
  obligation from issuance to acceptance: a controller may name its own
  deterministic alias, and CON-206 step 9 remains the sole gate. Adds
  `AccountProvisioningFailed` and a revoke duty. Affects REQ-204, ADR-203,
  CON-203, CON-204, CON-205, CON-206, TEST-205, and two happy paths.

  Also extends the Tier-1 gate, which previously required TEST-226 through
  TEST-235 but never required the KDF, alias, VC, holder-binding, revocation,
  account-scope, or username tests to pass. No key hierarchy, DID construction,
  VC profile, revocation semantics, pairing grammar, or SPAKE2 change.
- **0.6.0 — 2026-07-30 — draft, normative.** Replaces the long
  high-entropy human fallback with the Hark/cbcl-bus-style
  `<number>-<word>-<word>` pattern and makes SPAKE2 mandatory for every short
  code. Separates routing from authentication: the QR/OS bootstrap carries the
  application context, the first two digits select a descriptor inside that
  authenticated profile, and the remaining six identify one provider-local
  session. Makes the application and wallet the SPAKE2 endpoints, keeps the
  provider a blind four-frame relay, requires mutual confirmation and N=1
  burn, and derives the existing PROTO-002 mailbox secret only from the
  confirmed PAKE key. Adds [[PROTO-003-selfsame-pairing-v1]], REQ-226–229,
  ADR-215–217, CON-216–218, and TEST-232–235; resolves OQ-205; and updates
  provider selection, profile descriptors, mobile flow, threat model, Tier-1
  gate, traceability, and sources. No VC, home-key hierarchy, `did:crdt`
  publication, or revocation semantics change.
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
