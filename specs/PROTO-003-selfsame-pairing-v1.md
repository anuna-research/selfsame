---
id: PROTO-003
title: Selfsame Pairing Protocol v1 — routable num-word-word SPAKE2
status: draft
tier: 1
version: 0.3.0
audience: application developer, SDK implementer, wallet implementer, infrastructure operator, security reviewer
author: Anuna Research (drafted with Codex, 2026-07-30; amended with Claude, 2026-07-31)
last-updated: 2026-07-31
owner-repo: selfsame
affects-repos: selfsame, hark, cbcl-bus, adopting applications, independent pairing implementations
review-gate: not-approved — Tier-1; independent cryptographic vectors, cross-model adversarial review, privacy review, production-operator review, and human cryptography sign-off are outstanding
depends-on: SPEC-004; PROTO-002; PROTO-004; RFC 2104; RFC 2119; RFC 3986; RFC 4648; RFC 5234; RFC 5869; RFC 6234; RFC 8174; RFC 8785; RFC 9110; RFC 9382; RFC 9496; BIP-39
---

# PROTO-003 — Selfsame Pairing Protocol v1

## Orientation

**Intent.** Define an independently implementable pairing ceremony carried by
one human-sayable value:

```text
C — sixteen octets, rendered for people as twelve BIP-39 words
```

The same ceremony SHALL work across unrelated applications and independently
operated rendezvous services without a user-managed server setting, a spoken
HTTPS identity, or a mandatory Selfsame directory.

**User promise.** Either side may start. The person carries one code — scanned,
spoken, typed, or handed over by the OS — and never says a domain, types a
route, or picks an endpoint. Whichever device has the better keyboard does the
typing.

**Security promise.** `C` is a 128-bit password used only by SPAKE2, never as a
bearer key and never passed directly to the mailbox HKDF. The application and
wallet perform SPAKE2 end to end with explicit key confirmation. The pairing
operator relays four opaque 32-byte values and never receives `C`, a password
verifier, the agreed key, an offer, a grant, a DID, or an account identifier.

**Routing promise.** A code is still not a global endpoint name. It is the
address of a short-lived signed record the application publishes, naming the
application and the exact session it chose from its own profile. Because the
address is a 128-bit function of `C`, no observer can enumerate live ceremonies;
because the record is signed and its contents re-enter the PAKE transcript, no
host can redirect one. No client broadcasts a code to candidate services.

**Structure.**

```text
        C  ── rendered as twelve words ──▶ person ──▶ other device
        │
        ├──▶ meet_addr = Ed25519(HKDF(C))        application publishes:
        │                                          applicationId, profileDigest
        │        ┌──────────────────────┐          providerId, nameplate
        │        │  signed record       │◀── unenumerable · ephemeral
        │        │  hint, not authority │─── resolved by the other party
        │        └──────────────────────┘
        │                  │
        │                  ▼
        └──▶ SPAKE2 password        application (role A) ◀──▶ wallet (role B)
                                          opaque relay: pA, pB, cA, cB
                                    ───── mutual confirmation ─────
                             |
                    32-byte ceremony key
                             |
                    derive 16-byte mailbox secret
                             |
                 [[PROTO-002-selfsame-rendezvous-v1]] slots
                 [[PROTO-004-selfsame-ceremony-envelope-v1]] sealed offer/grant
```

**Decisions.**
[[PROTO-003-selfsame-pairing-v1#ADR-401]] separate application/provider routing
from the PAKE password ·
[[PROTO-003-selfsame-pairing-v1#ADR-402]] use a profile-local two-digit route
and provider-local six-digit nameplate ·
[[PROTO-003-selfsame-pairing-v1#ADR-403]] put SPAKE2 between the application
and wallet, not between a client and provider ·
[[PROTO-003-selfsame-pairing-v1#ADR-404]] burn on the first peer claim or
failed confirmation ·
[[PROTO-003-selfsame-pairing-v1#ADR-405]] derive the existing blind mailbox
secret from the confirmed PAKE key ·
[[PROTO-003-selfsame-pairing-v1#ADR-406]] carry 128 bits as twelve BIP-39
words ·
[[PROTO-003-selfsame-pairing-v1#ADR-407]] resolve routing through a
code-derived meeting point ·
[[PROTO-003-selfsame-pairing-v1#ADR-408]] let either party initiate, with the
application always role A ·
[[PROTO-003-selfsame-pairing-v1#ADR-409]] take routing out of the human code.

**Load-bearing.**
[[PROTO-003-selfsame-pairing-v1#REQ-401]] any independent provider and two
independent clients can interoperate ·
[[PROTO-003-selfsame-pairing-v1#REQ-402]] the code has one closed grammar and
one meaning ·
[[PROTO-003-selfsame-pairing-v1#REQ-403]] many applications and providers
require no global directory ·
[[PROTO-003-selfsame-pairing-v1#REQ-404]] the provider is a blind relay, never
a SPAKE2 endpoint ·
[[PROTO-003-selfsame-pairing-v1#REQ-405]] mutual key confirmation is mandatory ·
[[PROTO-003-selfsame-pairing-v1#REQ-406]] one failed attempt burns the ceremony ·
[[PROTO-003-selfsame-pairing-v1#REQ-407]] only a confirmed PAKE key enters the
mailbox derivation ·
[[PROTO-003-selfsame-pairing-v1#REQ-408]] QR, spoken, and same-device carriers
cannot create a downgrade ·
[[PROTO-003-selfsame-pairing-v1#REQ-409]] either party may initiate.

**Controls digest.**

- The protocol value is `C`, sixteen octets. Twelve BIP-39 English words and the
  base64url bootstrap are renderings of it; no rendering is the value.
- `C` carries 128 bits and is used only as the SPAKE2 password and as the
  meeting-point address seed. It is never a bearer key, a mailbox secret, or an
  AEAD key.
- The human code contains no route, nameplate, provider, endpoint, or
  application identifier. Machine carriers transport `C` directly and never
  words.
- Routing is one signed, ephemeral record at an address derived from `C`. It is
  an unauthenticated hint: its contents re-enter the PAKE transcript, so a host
  can withhold but cannot redirect.
- The address space is 128 bits, so live ceremonies cannot be enumerated. The
  record is signed, not encrypted, and its `applicationId` is visible to anyone
  already holding `C`.
- Either party may generate and display the code. The application always selects
  the provider, allocates the nameplate, publishes the record, and is SPAKE2
  role A; the wallet is always role B.
- A wallet-generated code has no intended recipient. Its lifetime is bounded and
  the resolved origin is shown before consent.
- The pairing provider stores no password-equivalent verifier and performs no
  group operation, MAC verification, grant decision, or application lookup.
- The PAKE transcript binds the application, complete provider descriptor,
  profile, route, nameplate, protocol version, and roles — reconstructed from the
  record rather than parsed from the code.
- Only after mutual confirmation do clients derive the 16-byte secret used by
  [[PROTO-002-selfsame-rendezvous-v1]] and
  [[PROTO-004-selfsame-ceremony-envelope-v1]].
- Every retry after ambiguity, collision, wrong input, invalid point, failed
  MAC, timeout, provider change, record failure, or carrier mismatch creates a
  fresh code, address, nameplate, SPAKE2 ephemerals, mailbox secret, and offer.

---

## Conformance and status

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in BCP 14 (RFC 2119 and RFC 8174) when, and only when, they appear in
all capitals.

This is a **Tier-1 draft** because it defines a low-entropy authentication
ceremony and an unauthenticated public relay used before device authorization.
It is suitable for review, vector construction, and conformance-suite design
only. It does not authorize implementation or production deployment until the
gate in [[PROTO-003-selfsame-pairing-v1#Tier-1 Gate]] closes.

The construction follows the two-round SPAKE2 shape and explicit confirmation
requirements of RFC 9382, but its ristretto255 ciphersuite and domain constants
are protocol-specific. It MUST NOT be described as an RFC 9382 registered or
IETF Standards Track ciphersuite. RFC 9382 and RFC 9496 are Informational
IRTF/CFRG publications; the exact construction below remains subject to this
document's independent cryptographic review.

An implementation conforms to `selfsame-pairing-v1` only when it passes every
mandatory test in this document. Reusing code from Hark, cbcl-bus, or a
Selfsame reference implementation is evidence, not conformance by itself.

## Context

The existing Hark/cbcl-bus ceremony established the useful human pattern:
a public pairing locator followed by two BIP-39 words, with SPAKE2 and a
burn-on-first-failure rule. Selfsame reuses that composition and word-index
encoding, but changes one trust boundary. In Hark, the hub is the SPAKE2
responder and stores password-equivalent material. In this protocol the
developer application and Selfsame wallet are the two SPAKE2 endpoints. The
provider only relays frames, so compromise of provider storage does not reveal
a verifier that can impersonate either endpoint.

[[SPEC-004-application-scoped-identity]] also permits many unrelated
applications to choose different providers. A Hark-style numeric nameplate is
only meaningful at a known hub. This protocol therefore separates:

1. **application context**, which selects an origin-authenticated profile;
2. **route**, which selects one pairing-capable rendezvous descriptor in that
   profile;
3. **nameplate**, which locates one active provider session; and
4. **the code `C`**, which authenticates the end-to-end PAKE and, via
   [[PROTO-003-selfsame-pairing-v1#CON-409]], addresses the record that
   supplies the first three.

That separation is necessary: a short code cannot encode and authenticate an
arbitrary HTTPS endpoint without either more human input or a shared global
directory. Version 1 chooses application-origin discovery and profile-local
routing, not a mandatory Selfsame directory.

## Scope

### In scope

- the canonical twelve-word grammar and its 128-bit rendering;
- routing resolved from a code-derived record rather than carried by the code;
- initiation from either party;
- profile-local routing across many applications and providers;
- the QR/bootstrap logical value and carrier-independent acceptance rules;
- an exact SPAKE2 ristretto255 construction and role assignment;
- provider capability discovery and a bounded four-frame relay;
- role capability tokens, one-claim semantics, TTL, retry, and errors;
- explicit key confirmation and client-authoritative burn behavior;
- derivation of the existing high-entropy mailbox secret from the PAKE key;
- downgrade, replay, active-guess, MITM, provider-compromise, and privacy
  controls; and
- black-box and cross-implementation tests.

### Out of scope

- application-account key derivation, VC issuance, consent, holder proof, and
  `did:crdt` revocation, owned by
  [[SPEC-004-application-scoped-identity]];
- the sealed offer/bundle record, its key schedule, and its AEAD, owned by
  [[PROTO-004-selfsame-ceremony-envelope-v1]], which consumes the
  `mailbox_secret_16` and `binding_hash` this protocol produces;
- the mailbox slot, HTTP transport, immutability, and expiry contract, owned by
  [[PROTO-002-selfsame-rendezvous-v1]];
- the exact platform-specific verified-wallet invocation mechanism;
- a global application or provider registry;
- recovering an application identity from a bare pairing code;
- provider payment, commercial authentication, availability SLOs, or abuse
  policy beyond the mandatory protocol bounds; and
- claiming that knowledge of the PAKE password authenticates the developer
  origin. The signed application enrollment evidence remains mandatory.

## Happy path

1. The developer application authenticates its active account, constructs the
   ordinary offer and enrollment evidence, and reads its authenticated
   application profile.
2. It filters and probes descriptors supporting both
   `selfsame-pairing-v1` and `selfsame-rendezvous-v1`, then selects one without
   user input.
3. Either party generates `C` — sixteen CSPRNG octets — and renders it as
   twelve BIP-39 English words. If the wallet generated it, the person carries
   it to the application before step 2. The selected pairing provider allocates
   a six-digit nameplate and returns an initiator capability token.
4. The application computes `pA` from `C`, stores it, and only then publishes
   the [[PROTO-003-selfsame-pairing-v1#CON-409]] record naming its
   `applicationId`, profile digest, provider, and nameplate.
5. The other party derives the meeting-point address from the same `C`,
   resolves and verifies the record, fetches the profile named by it, requires
   the profile digest to match, selects the exact descriptor, and claims the
   nameplate once.
6. The clients exchange `pA`, `pB`, `cA`, and `cB` through the provider. Each
   client locks the first peer frame it processes and requires the opposite
   confirmation MAC.
7. After mutual confirmation, both derive the same 16-byte mailbox secret from
   the 32-byte PAKE key and transcript binding.
8. They use that secret with
   [[PROTO-002-selfsame-rendezvous-v1]] for the encrypted offer and grant.
   Application enrollment evidence, user consent, the home signature, VC
   validation, holder proof, and `did:crdt` publication remain unchanged.

The pairing provider never sees the words or a password-derived verifier. The
rendezvous sees only secret-derived mailbox slots and ciphertext.

## Requirements

### REQ-401: Independent implementations interoperate

A conforming pairing provider SHALL implement the exact capability, session,
frame, token, TTL, HTTP, and error contracts in
[[PROTO-003-selfsame-pairing-v1#CON-401]] and
[[PROTO-003-selfsame-pairing-v1#CON-405]] through
[[PROTO-003-selfsame-pairing-v1#CON-406]].

Two clients implemented independently SHALL derive byte-identical `pA`, `pB`,
transcript hash, confirmation MACs, PAKE key, and mailbox secret from the same
normative vector using only this specification.

Trace:
[[PROTO-003-selfsame-pairing-v1#TEST-401]],
[[PROTO-003-selfsame-pairing-v1#TEST-404]]

### REQ-402: The short code has one closed meaning

Every human pairing code SHALL conform to
[[PROTO-003-selfsame-pairing-v1#CON-402]]: exactly twelve BIP-39 English words
encoding 128 bits of entropy and a four-bit checksum, and nothing else. Those
words SHALL encode the SPAKE2 password according to
[[PROTO-003-selfsame-pairing-v1#CON-403]].

No word SHALL encode a route, nameplate, provider, endpoint URL, application
identifier, application account, DID, device key, permission, or derivation
index. Every one of those values SHALL be obtained by resolving
[[PROTO-003-selfsame-pairing-v1#CON-409]].

A recogniser SHALL reject a failing checksum before any network request or key
derivation.

Trace:
[[PROTO-003-selfsame-pairing-v1#TEST-402]]

### REQ-403: Routing scales across applications and providers

An application profile MAY declare up to 100 pairing-capable rendezvous
descriptors with distinct routes `00` through `99`. Routes are scoped to the
exact application ID and profile digest and MAY be reused by every other
application.

The application SHALL select the descriptor, in both initiation directions, from
its own authenticated profile. The wallet SHALL adopt that selection by
resolving [[PROTO-003-selfsame-pairing-v1#CON-409]] and SHALL NOT substitute a
descriptor, apply its own operator preference, interpret a route outside the
resolved profile, use an operator allowlist as a substitute for the profile,
query unrelated profiles, broadcast a code, or consult an undeclared
Selfsame/Anuna fallback.

Routes and nameplates no longer appear in the human code, but they remain
members of the [[PROTO-003-selfsame-pairing-v1#CON-403]] binding object. Two
applications reusing one route and nameplate therefore still produce different
transcripts, keys, and confirmation MACs.

Trace:
[[PROTO-003-selfsame-pairing-v1#TEST-408]]

### REQ-404: The provider is a blind relay, not a PAKE endpoint

The developer application SHALL be SPAKE2 role A and the Selfsame wallet SHALL
be role B. A pairing provider SHALL only allocate a nameplate, bind ephemeral
role capability tokens, and relay opaque `pA`, `pB`, `cA`, and `cB` values.

The provider SHALL NOT receive or store either word, either word index,
`wib`, `w`, `w_bytes`, a password-equivalent verifier, either SPAKE2 scalar,
the transcript hash, the agreed key, or the derived mailbox secret. It SHALL
NOT generate a peer frame, verify a confirmation MAC, terminate SPAKE2, or
release an application record under a provider-held PAKE key.

Trace:
[[PROTO-003-selfsame-pairing-v1#TEST-405]],
[[PROTO-003-selfsame-pairing-v1#TEST-407]]

### REQ-405: Mutual confirmation is mandatory

Both clients SHALL implement
[[PROTO-003-selfsame-pairing-v1#CON-404]] and the state machine in
[[PROTO-003-selfsame-pairing-v1#CON-407]]. Role B SHALL NOT accept or release
application data before validating `cA`. Role A SHALL NOT accept the PAKE or
mailbox output before validating `cB`.

Point decoding, transcript comparison, and MAC comparison SHALL fail closed.
An absent, repeated, reordered, malformed, reflected, role-swapped, or
cross-session frame SHALL never produce an accepted key.

Trace:
[[PROTO-003-selfsame-pairing-v1#TEST-403]],
[[PROTO-003-selfsame-pairing-v1#TEST-406]]

### REQ-406: One failed attempt burns the ceremony

Each client SHALL process at most one peer claim and one value for each peer
frame in a ceremony. Any wrong word, invalid point, mismatched binding,
confirmation failure, peer-claim conflict, timeout, ambiguous write, provider
fork, carrier mismatch, or unexpected state transition SHALL permanently burn
that local ceremony.

The client SHALL NOT retry a password guess, reset its SPAKE2 state, accept a
second peer, or reuse the code. A new attempt generates both new words, a new
nameplate, new role tokens, new ephemerals, a new mailbox secret, and new
application ceremony identifiers.

The provider SHALL enforce one active responder claim atomically and SHOULD
rate-limit allocation and claim attempts. Client burn is authoritative even if
a malicious or partitioned provider violates its own state.

Trace:
[[PROTO-003-selfsame-pairing-v1#TEST-406]],
[[PROTO-003-selfsame-pairing-v1#TEST-411]]

### REQ-407: Only the confirmed PAKE key enters the mailbox

Clients SHALL derive the mailbox secret exactly as
[[PROTO-003-selfsame-pairing-v1#CON-408]] specifies and SHALL supply it to
[[PROTO-002-selfsame-rendezvous-v1]] only after mutual confirmation.

No conforming path SHALL pass the two words, `wib`, `w`, or any truncation,
hash, or HKDF of those values directly to the offer/grant AEAD or mailbox slot
function. A short code used through the former 128-bit direct-secret path is a
critical downgrade and MUST be rejected.

Trace:
[[PROTO-003-selfsame-pairing-v1#TEST-410]]

### REQ-408: Every carrier converges on one ceremony

QR, spoken or typed, and same-device carriers SHALL deliver the same logical
bootstrap defined by [[PROTO-003-selfsame-pairing-v1#CON-402]], in either
initiation direction. They may differ only in physical transport, which party
displays the code, and whether the person types it.

No carrier and no direction may change the SPAKE2 roles, ciphersuite, transcript
binding, routing resolution, provider selection, confirmation rules, mailbox
derivation, sealed offer/grant, application evidence, consent, or acceptance
predicate. A carrier or peer that claims a direct-secret, no-confirmation,
provider-terminated, route-in-the-code, or unknown mode causes a fresh-ceremony
failure; there is no version negotiation inside a session.

Trace:
[[PROTO-003-selfsame-pairing-v1#TEST-409]],
[[PROTO-003-selfsame-pairing-v1#TEST-410]]

### REQ-409: Either party may initiate

The application or the Selfsame wallet MAY generate and display the pairing
code. A conforming implementation SHALL support both directions and SHALL apply
[[PROTO-003-selfsame-pairing-v1#CON-402]] identically to each.

Whichever party displays the code, the application SHALL select the provider,
allocate the nameplate, write `pA`, publish the
[[PROTO-003-selfsame-pairing-v1#CON-409]] record, and act as SPAKE2 role A; the
wallet SHALL act as role B. Initiation direction SHALL NOT change role
assignment, transcript identities, frame order, or any derived key.

A wallet-generated code has no intended recipient and is therefore a bearer
capability. A wallet SHALL bound its lifetime to at most 600 seconds, SHALL
evaluate at most one resolved record per code, and SHALL display the
authenticated `applicationId` resolved under CON-409 before the person is asked
to approve anything. An application-generated code carries the person's own
session context; a wallet-generated one does not, and consent is its only
signal.

Trace:
[[PROTO-003-selfsame-pairing-v1#TEST-409]],
[[PROTO-003-selfsame-pairing-v1#TEST-413]]

## Non-functional requirements

### NFR-401: Human entry remains bounded

The canonical code contains twelve BIP-39 English words and eleven hyphens.
It is case-insensitive at the presentation parser but always canonicalized to
lower-case ASCII with hyphens before use. A UI SHALL display all twelve words
in full and MAY group them visually without adding a parsed character.

The application identity shown beside a manual code is ceremony context, not a
rendezvous configuration field. The UI SHALL show the authenticated
application origin and SHALL NOT expose or request the selected provider URL.

### NFR-402: Parsing and allocation are bounded

Clients SHALL parse at most 2,048 bytes for a QR bootstrap, 2,048 bytes for a
capability response, and 1,024 bytes for a session response. Frame bodies are
exactly 32 bytes. Unknown fields, duplicate JSON names, invalid UTF-8,
non-canonical base64url, and integers outside their defined ranges are rejected
before cryptographic or storage allocation.

### NFR-403: Pairing metadata is ephemeral

The provider SHALL expire every session, frame, token hash, network retry
record, and rate-limit correlation record as soon as operationally possible
and no later than the bounded periods in
[[PROTO-003-selfsame-pairing-v1#CON-405]]. It SHALL NOT log raw nameplates,
tokens, frame bodies, or full client IP addresses.

## Architecture decisions

### ADR-401: Separate routing context from the PAKE password

**Status:** PROPOSED.

The application ID and authenticated profile answer *which application and
which candidate providers*. The numeric route answers *which descriptor in
that profile*. The nameplate answers *which active session*. The words answer
*whether the two endpoints share the out-of-band password*.

Making one short number globally identify an arbitrary provider is rejected.
It would require a mandatory directory, a centrally allocated provider prefix,
an impractically long endpoint encoding, or broadcast discovery. Putting a
provider URL in the words is also rejected because it destroys their
authentication entropy.

### ADR-402: Use a two-digit route and six-digit nameplate

**Status:** PARTIALLY SUPERSEDED by
[[PROTO-003-selfsame-pairing-v1#ADR-409]]. Routes and nameplates retain exactly
the roles and widths below, and remain members of the
[[PROTO-003-selfsame-pairing-v1#CON-403]] binding object. What changed is that
they are resolved from the CON-409 record rather than parsed from the human
code, so their widths are now chosen for allocation headroom alone and carry no
usability cost.

The eight-digit numeric component is `route || nameplate`. Two digits allow
100 independently operated descriptors per application profile. Six digits
allow one million active provider-local names. Neither value contributes
security; collisions are prevented by the provider's active-session allocator
and every cryptographic identity includes the complete binding.

A small provider-local integer alone, as used by a single known Hark/cbcl-bus
hub, is rejected because Selfsame must span many applications and providers.
A global route allocation is rejected because it makes registry continuity a
pairing dependency. Application-scoped routes deliberately may collide.

### ADR-403: Run SPAKE2 between the application and wallet

**Status:** PROPOSED.

The application is role A and the wallet is role B. The provider never holds a
password-equivalent verifier. This preserves the provider's status as an
untrusted transport and avoids the server-compromise property of symmetric
SPAKE2 when the server itself is a participant.

The design reuses the proven composition and BIP-39 packing from Hark/cbcl-bus,
but uses Selfsame-specific domain labels and binds an application profile and
provider descriptor. Reusing Hark's provider-as-responder trust model is
rejected because it would turn every selected provider into an impersonation
target.

### ADR-404: Burn on first claim or failed confirmation

**Status:** PROPOSED.

Two BIP-39 words provide `2048² = 2²²` possibilities. SPAKE2 prevents a passive
relay transcript from becoming an offline dictionary oracle; it does not
remove online guessing. Each endpoint therefore locks one peer and permanently
burns after the first failed confirmation. The authorization-critical wallet
offers at most one active guess per minted ceremony.

The tradeoff is deliberate: a mistyped word or attacker who claims a
nameplate first causes a visible restart. Allowing retries would silently
multiply the online success probability. Provider rate limiting reduces blind
enumeration and burn denial-of-service but is not counted as the cryptographic
guess bound.

### ADR-405: Compose SPAKE2 with the existing mailbox

**Status:** PROPOSED.

After confirmation, both endpoints derive a fresh 16-byte mailbox secret from
the 32-byte PAKE key and binding hash. Existing role-separated mailbox slots,
offer/grant AEAD, retry behavior, and adversarial tests then apply unchanged.

Replacing the entire offer/grant protocol with PAKE relay frames is rejected
because PAKE authenticates a key exchange, not the application enrollment
statement, consent, VC, holder key, or grant acceptance predicate. Feeding the
two-word password into the old direct-secret HKDF is rejected because 22 bits
cannot satisfy the old 128-bit secret assumption.

### ADR-406: Carry 128 bits as twelve BIP-39 words

**Status:** PROPOSED.

The human code is twelve BIP-39 English words encoding 128 bits of entropy plus
a four-bit checksum. It contains no digits.

[[SPEC-004-application-scoped-identity#ADR-215]] reduced the code from 128 bits
to 22 because the previous form "made the accessibility fallback impractical."
That diagnosis was of the **encoding**, not the entropy — the rejected artefact
was 41 Bech32m characters. Changing the encoding fixes the accessibility defect
without paying the entropy:

```text
41 Bech32m characters      41 spoken tokens    128 bits
03482715-account-clinic    10 spoken tokens     48 bits
twelve BIP-39 words        12 spoken tokens    128 bits
```

Twelve words costs two spoken tokens against the current code and returns 80
bits. It is also the only one of the three that self-checks: BIP-39 words are
unique in their first four letters and the mnemonic carries a checksum, so most
transcription errors fail locally instead of surfacing as an indistinguishable
`cA` failure after a network round trip.

The entropy is load-bearing beyond usability. At 22 bits no discovery record can
be confidential — an address derived from the code is enumerable, and a payload
encrypted under the code is recoverable offline, which would hand an attacker
the SPAKE2 password itself rather than merely the record.
[[PROTO-003-selfsame-pairing-v1#ADR-407]] depends on this decision.

Rejected:

- the former 41-character Bech32m code — correct entropy, unsayable;
- `<8 digits>-<word>-<word>` — its 22-bit password forces routing into the human
  code and makes every discovery shape either enumerable or impossible;
- a memory-hard KDF over 22 bits — buys time against offline attack but replaces
  a structural guarantee with an economic one that moves with hardware; and
- more words for routing plus two for the password — a split that only exists to
  work around a small password, and disappears once the password is large.

### ADR-407: Resolve routing through a code-derived meeting point

**Status:** PROPOSED.

The application publishes a short-lived signed record at an address derived from
the code. The wallet, which generated or received the same code, computes the
same address and resolves it. The record names the application and the exact
pairing session; see
[[PROTO-003-selfsame-pairing-v1#CON-409]].

The problem this solves is first-encounter routing. The wallet needs the
canonical `applicationId` before SPAKE2, because
[[PROTO-003-selfsame-pairing-v1#CON-403]] binds it into the transcript — but on
a first encounter the wallet has never heard of the application, and version
0.2.0 could close that gap only by having the person say an HTTPS URI aloud
beside the code.

A code-derived address is not a directory. It holds no list, cannot be queried
for what exists, and stores one ephemeral write per ceremony at a location only
the two parties can compute. Because [[PROTO-003-selfsame-pairing-v1#ADR-406]]
makes the code 128 bits, the address space is unenumerable: an observer cannot
sweep it to build an index of live pairings, which is the attack that makes the
same construction unacceptable at 22 bits. Because the record is signed, a host
can withhold it but cannot substitute it — and a substituted `applicationId`
would in any case diverge `binding_hash` and fail confirmation.

Rejected:

- the person says the canonical `applicationId` — the identity is the larger half
  of what a human must convey, and nothing bounds its length;
- domain entry plus a `.well-known` lookup — smaller, but still puts an origin in
  the person's mouth and makes discovery depend on DNS and the CA system for
  authenticity, where a code-derived address is self-certifying;
- a published global provider table — it routes to a provider but cannot carry
  the `applicationId`, so it does not close the gap, and it requires a central
  allocator that [[SPEC-004-application-scoped-identity#REQ-214]] promises
  developers they never need; and
- a low-entropy record as rejected by
  [[SPEC-004-application-scoped-identity#CON-209]] — that rejection was correct
  for a 22-bit code and is reopened only because ADR-406 changes its premise.

Two consequences are recorded as open rather than resolved:
[[PROTO-003-selfsame-pairing-v1#OQ-401]] on shared infrastructure and
[[PROTO-003-selfsame-pairing-v1#OQ-402]] on observer aggregation.

### ADR-408: Either party may initiate; the application is always role A

**Status:** PROPOSED.

The code may be generated and displayed by the application or by the wallet.
Whichever displays it, the **application** selects the provider from its own
profile, allocates the nameplate, writes `pA`, publishes the
[[PROTO-003-selfsame-pairing-v1#CON-409]] record, and is SPAKE2 role A. The
wallet is always role B.

Once the code is high-entropy and routing is resolved through a code-derived
address, the direction of the code stops being a protocol property. Trace both
directions and only three lines differ — who generates the code, who displays
it, and who types it. Provider selection, nameplate allocation, record
publication, frame order, and role assignment are identical, so this is a fourth
bootstrap carrier under the pattern
[[PROTO-003-selfsame-pairing-v1#REQ-408]] already establishes, not a second
state machine.

The gain is ergonomic and mostly accessible: the typing lands on whichever
device has the better input method rather than always on the wallet.

```text
application on a TV or console   application displays, person types into phone
application on a laptop          wallet displays, person types into laptop
both on one phone                OS handoff, nobody types
camera available                 QR, nobody types
```

Fixing the application as role A regardless of who initiated is deliberate. Role
A and role B are not symmetric — they use different group elements and different
transcript identities — so letting the role follow the initiator would fork the
transcript, double the vector set, and create a downgrade surface between two
otherwise identical ceremonies.

The residual risk is asymmetric and is recorded here rather than mitigated away.
An application-displayed code is scoped by the session the person is looking at.
A **wallet-displayed code has no intended recipient** and is therefore a bearer
capability a person can be talked into reading aloud. An attacker who obtains it
can complete SPAKE2, because the code is the password. What they cannot do is
forge [[SPEC-004-application-scoped-identity#CON-214]] enrollment evidence for
another developer's application, so they can only present themselves as their
own application and obtain a grant in that application's own branch. The harm
ceiling is enrolling in an application the person did not intend, and consent is
the entire defence. Because that consent screen is the only signal — where an
application-initiated flow also has the person's own context to confirm against —
a wallet-issued code SHOULD carry a shorter lifetime and the wallet SHOULD name
the resolved, authenticated origin before the person commits.

Rejected: making the initiator role A. It forks the transcript for no protocol
gain. Rejected: letting the wallet select the provider when it initiates. It
would override the application's operator policy, which
[[SPEC-004-application-scoped-identity#REQ-212]] and
[[SPEC-004-application-scoped-identity#ADR-207]] make authoritative.

### ADR-409: Routing leaves the human code

**Status:** PROPOSED.

The two-digit route and six-digit nameplate are removed from the human code.
They travel in the [[PROTO-003-selfsame-pairing-v1#CON-409]] record. The human
code is the twelve words and nothing else.

The binding object in [[PROTO-003-selfsame-pairing-v1#CON-403]] keeps every
member it has today. `route`, `nameplate`, `number`, `providerId`, and
`descriptorDigest` are reconstructed by the wallet from the resolved record and
the authenticated profile rather than parsed out of what the person said. The
cross-application separation argued in
[[PROTO-003-selfsame-pairing-v1#ADR-401]] and
[[PROTO-003-selfsame-pairing-v1#ADR-402]] therefore survives unchanged —
different applications reusing one route and nameplate still produce different
transcripts, keys, and confirmation MACs — while the eight digits stop being
something a person has to say.

This also unbinds nameplate width from usability. Nameplate size can now be
chosen purely for allocation headroom and claim-contention resistance, which is
the only thing it was ever really sized against.

Rejected: keeping the route in the human code as redundancy against a failed
resolution. Two sources for one routing decision is a parser-differential
invitation, and a resolution failure should be a typed error and a fresh
ceremony, not a fallback path with different security properties.

## Contracts

### CON-401: Pairing-capable provider descriptor and probe

A pairing-capable rendezvous descriptor contains these additional fields:

```json
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
}
```

`pairingUrl` uses the canonical HTTPS-origin `base-url` grammar in
[[PROTO-002-selfsame-rendezvous-v1#CON-301]]. `pairingProtocol` is exactly
`selfsame-pairing-v1`. `pairingRoute` is exactly two ASCII digits and is unique
among every rendezvous descriptor in one profile. The complete descriptor,
including all three pairing fields, is covered by its RFC 8785 descriptor
digest.

The pairing capability endpoint is:

```text
pairingUrl || "/pair/v1/healthz"
```

A successful response is:

```json
{
  "protocol": "selfsame-pairing-v1",
  "status": "ok",
  "nameplateDigits": 6,
  "sessionTtlSeconds": 600,
  "frameBytes": 32,
  "claimSemantics": "single-responder",
  "relaySemantics": "opaque-four-frame",
  "providerPakeRole": "none"
}
```

The JSON object has exactly those eight members and values. Unknown or missing
members, duplicate names, redirects, content encoding, a media type other than
`application/json`, a body over 2,048 bytes, or a non-`200` response makes the
descriptor ineligible. The response uses `Cache-Control: no-store`.

The selected descriptor is eligible only when this probe and the
[[PROTO-002-selfsame-rendezvous-v1#CON-301]] probe both succeed within the
application's bounded selection window. A probe establishes current
compatibility, not operator honesty.

### CON-402: Pairing code, its encodings, and the bootstrap

The protocol value is **`C`: sixteen octets of entropy**. Everything else in
this contract is a rendering of `C`, and no rendering is the value.

```text
            C  (16 octets)          ← the protocol value
            │
   ┌────────┼────────┐
   ▼        ▼        ▼
 twelve   base64url  future
 BIP-39   in the     renderings
 words    bootstrap
 (human)  (machine)
```

This separation is normative and load-bearing. Every derivation in this
protocol — the SPAKE2 password in
[[PROTO-003-selfsame-pairing-v1#CON-404]], the meeting-point address in
[[PROTO-003-selfsame-pairing-v1#CON-409]] — consumes `C` directly and never a
spelling of it. A rendering that cannot round-trip to the exact octets of `C` is
invalid, and two renderings of one `C` are the same code.

The consequence worth stating: the wordlist is a **presentation choice, not a
protocol constant**. Version 2 fixes the BIP-39 English list as the interoperable
default, and every conforming implementation MUST accept it. An implementation
MAY additionally offer another rendering — a localised BIP-39 wordlist, or a
different alphabet — provided it renders the same `C`, round-trips exactly, and
never becomes the only form the implementation accepts. Accessibility and
localisation therefore live at the presentation layer and require no amendment
to this protocol.

Normative ABNF for the English rendering:

```abnf
lower         = %x61-7A
word-token    = 3*8lower
pairing-code  = 11(word-token "-") word-token
```

The code is exactly twelve word tokens separated by single hyphens. Each
`word-token` MUST be an exact member of the 2,048-word BIP-39 English word
list. Tokens MAY repeat.

The twelve words encode 128 bits of entropy plus a four-bit checksum, exactly as
BIP-39 specifies for a 128-bit mnemonic. A recogniser MUST verify that checksum
and reject a failing code before any network request or key derivation. Define:

```text
C = the 16 octets of entropy recovered from the twelve words
```

`C` is the only secret the human carries. It encodes no route, nameplate,
provider, endpoint, application account, DID, device key, permission, or
derivation index. It is not a BIP-39 wallet seed and is never used as one.

The canonical code uses lower-case ASCII and hyphens. A presentation parser MAY
accept ASCII upper-case letters and one or more ASCII spaces around or in place
of a hyphen, but it MUST reject non-ASCII confusables, extra or missing tokens,
words absent from the list, and every value that cannot be re-encoded to one
canonical code.

Abbreviated entry — accepting a four-character prefix per word, which the BIP-39
English list makes unambiguous — is deliberately **not** specified. It would add
a second accepted input form, and therefore a second way for two recognisers to
disagree, in exchange for shortening only the typed path. The machine carriers
already transport `C` directly, so nothing else benefits. One value, one
recogniser, one accepted spelling.

#### Bootstrap

The logical bootstrap carries the entropy, not its spelling:

```json
{
  "version": 2,
  "c": "<base64url of the 16 octets of C>"
}
```

The object has exactly those two members. `c` is canonical unpadded RFC 4648
base64url decoding to exactly 16 octets, and MUST pass the same decode and
re-encode canonicality check applied elsewhere in this profile.

Machine carriers — the QR payload and the same-device handoff — carry this
object and never carry words. Twelve words are a **human presentation** of `C`,
so encoding them into a machine carrier would ship roughly seventy characters
where twenty-two suffice, and would put a second parser for the same value on
the wire. A carrier that transports words instead of `c` MUST be rejected.

`applicationId` and `profileDigest` are no longer carried by any bootstrap. A
resolving party obtains them from
[[PROTO-003-selfsame-pairing-v1#CON-409]], which is the single routing path for
every carrier. This removes the former asymmetry in which a QR could carry
application context that a spoken code could not, and with it the requirement
that a person convey an HTTPS identity aloud.

The canonical QR payload is:

```text
ASCII("selfsame-pairing-v2:")
|| BASE64URL-NOPAD(RFC8785(logical_bootstrap))
```

It is data consumed inside a conforming Selfsame wallet or application, not an
OS navigation URL. It MUST NOT be opened by a browser, emitted as an HTTP query,
placed in a referrer, or registered as an authoritative private-use URL scheme.

Under [[PROTO-003-selfsame-pairing-v1#ADR-408]] either party may generate and
display the code, and every carrier — QR, spoken or typed words, and verified
same-device handoff — delivers exactly this bootstrap in either direction.

A code that resolves no record returns `PairingRecordUnavailable`. A resolving
party SHALL NOT search installed applications, historic profiles, provider
lists, DNS guesses, or any other endpoint for a match, and SHALL NOT retry with
a mutated code.

### CON-403: Word-index and transcript binding inputs

The password input is the 16-octet value `C` recovered in
[[PROTO-003-selfsame-pairing-v1#CON-402]]:

```text
wib = C          ; exactly 16 octets, 128 bits
```

The name `wib` is retained so that
[[PROTO-003-selfsame-pairing-v1#CON-404]] reads unchanged, but it is no longer a
packed word-index pair. The former three-octet 22-bit encoding is withdrawn by
[[PROTO-003-selfsame-pairing-v1#ADR-406]]; an implementation offering it MUST be
rejected as a downgrade under
[[PROTO-003-selfsame-pairing-v1#REQ-407]].

`route`, `nameplate`, `number`, `providerId`, and `descriptor_digest` are no
longer parsed from the human code. Under
[[PROTO-003-selfsame-pairing-v1#ADR-409]] the application takes them from its
own profile and selection, and the wallet reconstructs them from the resolved
[[PROTO-003-selfsame-pairing-v1#CON-409]] record together with the profile it
fetches and pins by `profileDigest`. `number` is `route || nameplate` as before.

Both parties MUST hold every member below before either processes a peer frame.
Let `profile_digest` and `descriptor_digest` be canonical unpadded base64url
SHA-256 values. Both clients construct this exact logical object:

```json
{
  "applicationId": "https://photos.example/selfsame/application",
  "descriptorDigest": "<selected complete descriptor digest>",
  "nameplate": "482715",
  "number": "03482715",
  "profileDigest": "<authenticated application profile digest>",
  "protocol": "selfsame-pairing-v1",
  "providerId": "au-primary",
  "route": "03",
  "version": 1
}
```

The binding object has exactly those nine members and is serialized with RFC
8785. Define:

```text
binding_hash = SHA256(RFC8785(binding_object))
idA = ASCII("selfsame-pairing-v2/application/") || binding_hash
idB = ASCII("selfsame-pairing-v2/wallet/") || binding_hash
```

The identity labels name the **party**, not who started the ceremony. Under
[[PROTO-003-selfsame-pairing-v1#ADR-408]] either party may initiate, so the
former `initiator` label was a misnomer for a role that is always the
application. The label change alters every transcript hash, key, and
confirmation MAC and therefore invalidates every previously published vector;
this is why it is made now rather than after
[[PROTO-003-selfsame-pairing-v1#TEST-403]] publishes.

The code, `C`, and `wib` never appear in the binding object. Two applications
may use the same route, provider ID, number, and code; their different canonical
application IDs or profile/descriptor digests still produce different
identities, transcript hashes, keys, and confirmation MACs.

### CON-404: SPAKE2 ristretto255 ciphersuite

All octet-string labels below are exact ASCII. `SHA256`, `SHA512`,
`HKDF-SHA256`, and `HMAC-SHA256` are as specified by RFC 6234, RFC 5869, and
RFC 2104. `LV(x) = U64LE(len(x)) || x`. Integer lengths count octets.

The group is `ristretto255` from RFC 9496, with its canonical generator `B`,
canonical 32-byte element encoding, element decoding, uniform-byte element
derivation, scalar field, and constant-time operations. Define:

```text
M = FROM_UNIFORM_BYTES(SHA512(
      ASCII("SPAKE2 M Ristretto Curve25519 SHA-512 Hash v1")))
N = FROM_UNIFORM_BYTES(SHA512(
      ASCII("SPAKE2 N Ristretto Curve25519 SHA-512 Hash v1")))

w_bytes = HKDF-SHA256(
  ikm  = wib,
  salt = ASCII("selfsame-pairing-v2"),
  info = ASCII("selfsame-pairing-password-v2"),
  L    = 64)
w = REDUCE_SCALAR_LE(w_bytes)
```

Every domain-separation label in this contract carries `v2` because
[[PROTO-003-selfsame-pairing-v1#ADR-406]] changes `wib` from three octets to
sixteen. A version-1 and a version-2 implementation therefore cannot derive a
common `w`, `K`, or confirmation MAC from the same input, and a downgrade
attempt fails as a mismatch rather than succeeding weakly.

`REDUCE_SCALAR_LE` interprets 64 octets as an unsigned little-endian integer
and reduces it modulo the ristretto255 scalar order. Each role draws 64 fresh
uniform CSPRNG octets and reduces them in the same way to scalar `x` or `y`,
redrawing if the result is zero. Ephemeral octets and scalars are never reused.

Role A computes and sends:

```text
pA = ENCODE(x*B + w*M)
```

Role B decodes `pA`, rejecting a non-canonical or invalid element, then
computes and sends:

```text
pB = ENCODE(y*B + w*N)
ZA = x * (DECODE(pB) - w*N)
ZB = y * (DECODE(pA) - w*M)
```

Role A rejects an invalid `pB`. Both roles reject the identity element for a
received peer value or derived `Z`. Honest endpoints obtain `ZA = ZB`.

Each role computes:

```text
tt_hash = SHA256(
    LV(idA)
 || LV(idB)
 || LV(pA)
 || LV(pB)
 || LV(ENCODE(Z))
 || LV(w_bytes))

K = HKDF-SHA256(
  ikm  = tt_hash,
  salt = empty,
  info = ASCII("selfsame-pairing-session-key-v2"),
  L    = 32)

cA = HMAC-SHA256(
  K, ASCII("selfsame-pairing-application-confirm-v2") || tt_hash)
cB = HMAC-SHA256(
  K, ASCII("selfsame-pairing-wallet-confirm-v2") || tt_hash)
```

Every `pA`, `pB`, `cA`, and `cB` wire value is exactly 32 bytes. MAC comparison
is constant-time. `K` is internal key material and is released to
[[PROTO-003-selfsame-pairing-v1#CON-408]] only after the state machine's mutual
confirmation rule.

This construction deliberately uses the same M/N derivation and word-index
packing implemented by the existing Hark/cbcl-bus primitive, with distinct
Selfsame KDF and confirmation labels plus the binding identities in
[[PROTO-003-selfsame-pairing-v1#CON-403]]. Normative byte vectors remain
blocking in [[PROTO-003-selfsame-pairing-v1#Tier-1 Gate]].

### CON-405: Provider session and four-frame relay

The pairing base URL is `pairingUrl || "/pair/v1"`. All requests use HTTPS,
`Cache-Control: no-store`, `Pragma: no-cache`, no cookies, no redirects, no
content encoding, no client TLS certificate, and no ambient application
credential. Role tokens are ephemeral relay capabilities, not application or
user authentication.

#### Allocate

Role A sends:

```http
POST /pair/v1/sessions HTTP/1.1
Content-Length: 0
```

The provider allocates an unused uniformly random six-digit nameplate for 600
seconds and returns:

```json
{
  "version": 1,
  "nameplate": "482715",
  "expiresInSeconds": 600,
  "initiatorToken": "<base64url 32 CSPRNG bytes>"
}
```

The response is `201 Created`, `Content-Type: application/json`, and
`Cache-Control: no-store`. The object has exactly those four members.
`initiatorToken` is canonical unpadded base64url decoding to 32 bytes. The
provider stores only a cryptographic hash of a role token. If allocation
succeeds but the response is lost or invalid, role A abandons it; it never
displays a code for an unconfirmed allocation.

#### Store `pA`

After computing the binding and `pA`, role A sends exactly 32 octets:

```http
PUT /pair/v1/sessions/482715/pA HTTP/1.1
Authorization: Bearer <initiatorToken>
Content-Type: application/octet-stream
Content-Length: 32
```

The first valid write returns `201 Created`. An identical retry with the same
token and body returns `200 OK`; a different body returns `409 Conflict`.
Role A does not disclose the code until this write is acknowledged.

#### Claim role B

Role B generates an independent 32-byte `responderToken` and sends:

```http
POST /pair/v1/sessions/482715/claim HTTP/1.1
Authorization: Bearer <responderToken>
Content-Length: 0
```

The first claim after `pA` exists returns `201 Created`. An identical retry
using the same token returns `200 OK`. Every different token returns
`409 Conflict`. The provider stores only a cryptographic hash of the token.

#### Exchange frames

The remaining endpoints are:

```text
GET  /pair/v1/sessions/{nameplate}/pA   role B token
PUT  /pair/v1/sessions/{nameplate}/pB   role B token
GET  /pair/v1/sessions/{nameplate}/pB   role A token
PUT  /pair/v1/sessions/{nameplate}/cA   role A token
GET  /pair/v1/sessions/{nameplate}/cA   role B token
PUT  /pair/v1/sessions/{nameplate}/cB   role B token
GET  /pair/v1/sessions/{nameplate}/cB   role A token
```

Every successful GET returns exactly 32 octets with
`Content-Type: application/octet-stream`. Every PUT has the immutable retry
semantics defined for `pA`. A frame cannot be written before every preceding
frame in `pA, pB, cA, cB` exists. A GET before its frame exists returns `404
Not Found` with `Retry-After: 1`; it does not consume or extend the session.

The provider expires the complete session exactly 600 seconds after
allocation. It returns `410 Gone` for a known expired nameplate only while a
short non-enumerable tombstone is required to make a client's in-flight retry
unambiguous, for at most 60 additional seconds; otherwise it returns `404`.
Expiry is not extended by a claim, frame, read, retry, or health probe.

The provider never offers list, search, prefix, transcript, reset, retry-count,
password-verifier, application-ID, DID, account, grant, or mailbox-key
endpoints. It does not copy a session to another origin.

### CON-406: HTTP errors, tokens, CORS, and retry

`nameplate` path input is exactly six ASCII digits. A role token is accepted
only from an `Authorization: Bearer` value whose token is canonical unpadded
base64url decoding to exactly 32 bytes. Missing, malformed, or wrong tokens
return `404`, not an oracle distinguishing session existence or role.

The closed status set is:

| Status | Meaning |
|---|---|
| `200` | Identical authenticated retry, or successful frame read. |
| `201` | Allocation, claim, or first immutable frame write succeeded. |
| `400` | Malformed path, headers, media type, or body length. |
| `404` | Session/frame absent, or role token not accepted. |
| `409` | Conflicting claim, frame, or state transition. |
| `410` | Bounded recently-expired tombstone. |
| `413` | Body exceeded the applicable parse bound. |
| `429` | Rate limit; retrying the same ceremony is not automatically safe. |
| `503` | Service cannot honor the contract. |

All other statuses fail the ceremony. Error bodies are empty. Every response
uses `Cache-Control: no-store`; no response sets a cookie. Clients reject
redirects and use credentials only for the explicit role bearer token.

Browser implementations use `credentials: "omit"` and an explicit
`Authorization` header. A provider supporting browsers allows only `GET`,
`POST`, `PUT`, and `OPTIONS`; request headers `authorization`,
`content-type`, `cache-control`, and `pragma`; and origins without
credentials. It returns `Vary: Origin`, never persists `Origin` or `Referer`,
and never treats origin as authority. Native clients send no `Origin`.

An ambiguous allocation before code display may be abandoned. Any ambiguous
claim or frame write after code display burns the ceremony under
[[PROTO-003-selfsame-pairing-v1#CON-407]]. Retrying is permitted only when the
client can prove it is byte-identical, uses the same role token, and has not
processed a conflicting peer value.

### CON-407: Client state, confirmation, and burn

The closed state sequence is:

```text
A: allocate -> pA stored -> pB locked -> cA stored -> cB verified -> confirmed
B: claim    -> pA locked -> pB stored -> cA verified -> cB stored -> confirmed
```

Each client records the exact application/profile/descriptor binding, code,
role token, peer frame hashes, and terminal state in process-private memory.
It accepts only the next state. Duplicate byte-identical reads are harmless;
a different value, second peer, state regression, or skipped state burns.

Role B verifies `cA` before storing `cB`. A failed `cA` is the one
authorization-critical online password guess and burns locally even if the
provider offers another frame. Role A verifies `cB` before treating the PAKE
as complete. Neither client displays consent, decrypts an offer, derives a
mailbox slot, or exposes `K` before its required confirmation succeeds.

After a terminal success or failure, the code, words, `wib`, ephemerals, `K`,
tokens, and derived mailbox secret are zeroized when the platform permits.
Persistent storage may retain only a non-secret, expiring hash sufficient to
reject local code reuse. A UI reports that the code expired or pairing failed;
it does not distinguish a wrong word from an active attack.

### CON-408: Confirmed key to mailbox composition

After the confirmation rules in
[[PROTO-003-selfsame-pairing-v1#CON-407]] succeed, each endpoint derives:

```text
mailbox_secret_16 = HKDF-SHA256(
  ikm  = K,
  salt = binding_hash,
  info = ASCII("selfsame-rendezvous-secret-v1"),
  L    = 16)
```

The output is a fresh 128-bit pseudorandom secret. It becomes `secret_16` in
[[PROTO-002-selfsame-rendezvous-v1#CON-302]] for slot derivation, and — with
`binding_hash` — the sole input to the envelope keys in
[[PROTO-004-selfsame-ceremony-envelope-v1#CON-501]]. Those are separate
functions with separate outputs: a slot name is public and a key is not.

The selected descriptor's `url` is the only mailbox origin. Offer and bundle
encryption follows
[[PROTO-004-selfsame-ceremony-envelope-v1#CON-502]]; size, immutable writes,
repeatable reads, CORS, expiry, and retry follow
[[PROTO-002-selfsame-rendezvous-v1#CON-302]] through
[[PROTO-002-selfsame-rendezvous-v1#CON-308]] without alteration.

The encrypted application transcript additionally binds the exact
`binding_hash`, offer digest, ceremony ID, request ID, application/account
scope, device key, permission set, and application enrollment evidence as
required by [[SPEC-004-application-scoped-identity]]. SPAKE2 establishes
shared knowledge of the OOB password; it does not replace application-origin
authentication, consent, the home signature, VC verification, or holder proof.

### CON-409: Code-derived meeting point

This contract is the single routing path for every carrier and every initiation
direction. It replaces the application context that
[[PROTO-003-selfsame-pairing-v1#CON-402]] formerly required a QR to carry or a
person to speak.

#### Address

```text
meet_seed = HKDF-SHA256(
  ikm  = C,
  salt = ASCII("selfsame-pairing-v2"),
  info = ASCII("selfsame-pairing-meeting-point-v2"),
  L    = 32)

meet_key  = the Ed25519 keypair whose RFC 8032 private seed is meet_seed
meet_addr = the public key of meet_key
```

Both parties derive `meet_key` independently from `C`. The application holds the
private half only to sign its record; the address is the public half. Because
`C` carries 128 bits, `meet_addr` is not enumerable: an observer cannot sweep
the space to build an index of live ceremonies, which is the property that makes
this construction acceptable here and unacceptable under a 22-bit code.

`meet_seed` SHALL NOT be used as a SPAKE2 password, an AEAD key, a mailbox
secret, a slot input, or any other key. `C` reaches those uses only through
[[PROTO-003-selfsame-pairing-v1#CON-404]] and
[[PROTO-003-selfsame-pairing-v1#CON-408]].

#### Record

The application publishes exactly this object, RFC 8785 serialized and signed by
`meet_key`:

```json
{
  "version": 2,
  "applicationId": "https://photos.example/selfsame/application",
  "profileDigest": "<base64url SHA-256 of the RFC 8785 profile>",
  "providerId": "au-primary",
  "nameplate": "482715",
  "expiresAt": "2026-07-31T10:10:00Z"
}
```

The member set is exactly those six names. `applicationId` is canonical under
[[SPEC-004-application-scoped-identity#CON-201]]. `profileDigest` is canonical
unpadded base64url decoding to exactly 32 octets. `providerId` matches
`[a-z0-9][a-z0-9-]{0,62}`. `nameplate` is exactly six ASCII digits. `expiresAt`
is an XML Schema `dateTimeStamp` normalized to UTC `Z`, at most 600 seconds
after publication, and never later than the provider session it names.

`providerId` is REQUIRED alongside the profile digest because `pairingUrl` alone
is ambiguous when one profile declares two descriptors at one origin. Together
they select exactly one descriptor.

The record SHALL NOT contain an account scope, DID, alias, device key,
permission, offer digest, enrollment evidence, ceremony or request identifier,
person-identifying value, or any part of `C`.

The record is **signed, not encrypted**. No key exists at this point in the
ceremony that could confidentially seal it: a key derived from `C` directly
would let anyone resolving the address brute-force `C` itself and thereby
recover the SPAKE2 password, and the SPAKE2 output does not yet exist. The
disclosure this accepts is bounded by
[[PROTO-003-selfsame-pairing-v1#OQ-402]].

#### Publication and resolution

The publishing party MUST be the application, in both initiation directions. It
publishes only after it has selected a descriptor from its own authenticated
profile, obtained the nameplate, and acknowledged its `pA` write.

The resolving party MUST, in order:

1. recover `C` and verify the BIP-39 checksum under
   [[PROTO-003-selfsame-pairing-v1#CON-402]];
2. derive `meet_addr` and resolve the record;
3. verify the record signature against `meet_addr` and reject on failure;
4. reject an expired record, and reject a second record at the same address;
5. recognize the closed member set above before any semantic action;
6. fetch the application profile from the canonical `applicationId` origin and
   require its RFC 8785 SHA-256 digest to equal `profileDigest`;
7. select the unique descriptor matching `providerId` and re-run both bounded
   capability probes in [[PROTO-003-selfsame-pairing-v1#CON-401]]; and
8. construct the [[PROTO-003-selfsame-pairing-v1#CON-403]] binding before
   claiming the nameplate.

A resolved record is an **unauthenticated hint**. Its signature proves only that
whoever holds `C` wrote it; it establishes no application authority. A
substituted `applicationId`, `profileDigest`, `providerId`, or `nameplate`
produces a different `binding_hash` and fails confirmation, so a hostile host
can withhold but cannot redirect. Application authenticity comes from
[[SPEC-004-application-scoped-identity#CON-214]] after the mailbox opens, never
from this record.

#### Transport

A conforming implementation MAY resolve through any transport that returns the
signed record intact — a signed-record relay over HTTPS, a distributed hash
table, or both raced concurrently. Racing is safe precisely because the record
is self-authenticating: no trust decision depends on which transport answered,
so latency is the faster arm and availability is the more resilient one.

A transport SHALL NOT be treated as a trust anchor, SHALL NOT be permitted to
substitute a record, and SHALL NOT be consulted for anything other than the
exact derived address. Errors are `PairingRecordUnavailable`,
`PairingRecordMalformed`, `PairingRecordBadSignature`, `PairingRecordExpired`,
or `PairingRecordConflict`; every one abandons the ceremony under
[[PROTO-003-selfsame-pairing-v1#REQ-406]].

Which transports a conforming client ships, and who operates them, is
[[PROTO-003-selfsame-pairing-v1#OQ-401]] and is unresolved.

Implements: REQ-402, REQ-403, REQ-408, REQ-409.

Verified by: TEST-402, TEST-408, TEST-409, TEST-413.

## Test specifications

### TEST-401: Capability and descriptor recognition

**Validates:** REQ-401, CON-401.

Accept the exact capability response and descriptor grammar. Reject every
unknown/missing member, duplicate route, invalid route width, non-canonical
URL, wrong protocol, wrong fixed limit, expired descriptor, redirect, content
encoding, oversized body, and pairing-only provider lacking PROTO-002.

### TEST-402: Code grammar and rendering

**Validates:** REQ-402, CON-402, CON-403.

Accept and re-encode canonical twelve-word codes, recovering `wib = C` as
exactly sixteen octets. Cover all-zero entropy, all-ones entropy, repeated
words, and codes whose first and last words are the first and last list
entries.

Require the twelve-word rendering and the `c` bootstrap to round-trip to
identical octets, and require every derivation to consume `C` rather than a
spelling — render one `C` two ways and require identical `w_bytes` and
`binding_hash`.

Reject a failing BIP-39 checksum, an abbreviated word, a word absent from the
list, eleven or thirteen tokens, empty tokens, non-ASCII digits, Unicode
hyphens and confusables, overlong input, a machine carrier transporting words
rather than `c`, and any presentation form that does not converge on one
canonical output. Assert that a checksum failure produces no network request
and no key derivation.

Reject the withdrawn version-1 forms explicitly: an eight-digit-plus-two-word
code, and a three-octet `wib`.

### TEST-403: Normative SPAKE2 vectors

**Validates:** REQ-405, CON-403, CON-404.

Publish fixed vectors containing the complete binding object, RFC 8785 bytes,
binding hash, the twelve words, `C`, `wib`, role ephemerals, M/N encodings,
`w_bytes`, `pA`, `pB`, encoded shared element, transcript hash, `K`, `cA`, `cB`,
and mailbox secret. Two independent implementations reproduce every byte.

Vectors SHALL use the `v2` domain-separation labels and the
`application`/`wallet` transcript identities. Any vector published against the
version-1 labels is invalid and MUST NOT be reproduced.

This test is blocking until the vectors receive cryptographic review; examples
in this draft are not substitute vectors.

### TEST-404: Independent cross-stack interoperability

**Validates:** REQ-401, CON-404 through CON-408.

Run an application client, wallet client, pairing provider, and PROTO-002
provider from independent implementations. Complete the four frames, derive
the same mailbox slots, exchange one encrypted offer and grant, and accept the
grant only through the SPEC-004 predicate.

At least one test SHALL reuse the Hark/cbcl-bus ristretto255 primitive with
Selfsame domain parameters and one SHALL be independently implemented from
this document.

### TEST-405: Provider blindness and compromise

**Validates:** REQ-404, CON-405.

Capture the provider's complete memory, storage, logs, and traffic. Require it
to contain only bounded session metadata, token hashes, and four opaque
32-byte frames. It contains no word/index, password verifier, group scalar,
transcript hash, `K`, mailbox secret, offer/grant plaintext, application ID,
account scope, DID, VC, or device key.

Give the capture to an attacker after expiry. It cannot verify an offline word
guess, derive `K`, decrypt a mailbox record, or forge either confirmation.

### TEST-406: Wrong word, invalid point, confirmation, and N=1 burn

**Validates:** REQ-405, REQ-406, CON-404, CON-407.

For every one-word mutation, role reflection, invalid/non-canonical point,
identity point, changed binding field, changed frame, wrong MAC, missing MAC,
reorder, and replay, require no mutual confirmation and no mailbox request.

After the first failure, present the correct value through the same provider
session and require rejection. A fresh ceremony with new words and ephemerals
succeeds. Instrument the wallet to prove it evaluates at most one `cA` per
minted ceremony.

### TEST-407: Malicious relay, fork, and race

**Validates:** REQ-404, REQ-406, CON-405 through CON-407.

Let the provider read, delay, drop, replay, replace, reflect, reorder, and fork
every frame; issue inconsistent tokens; violate claim locking; and show
different values to the two roles. It may deny service but obtains no accepted
key without the correct words, causes no offer/grant plaintext release, and
causes no application-account state change.

Race two responders. At most one honest-provider claim succeeds, and each
client still locks one peer value when the provider itself is malicious.

### TEST-408: Many applications and providers

**Validates:** REQ-403, ADR-401, ADR-402, CON-401 through CON-403.

Create at least three application profiles, each with two independently
implemented providers. Reuse route `03`, nameplate `482715`, and both words
across two applications. Require different binding hashes, PAKE messages,
keys, and mailbox slots.

Within one profile, route `03` reaches only its declared descriptor. Swapping
the profile, provider ID, descriptor digest, URL, route, or application ID
fails confirmation. Blocking the selected provider fails the ceremony and
creates completely fresh material at a newly selected provider. No request
reaches a global or undeclared fallback.

### TEST-409: QR, spoken, and same-device convergence

**Validates:** REQ-408, REQ-409, CON-402, CON-407, CON-408, CON-409.

Deliver one logical bootstrap by canonical QR, by manually entered words, and by
the verified same-device platform adapter — each in both initiation directions.
Every path produces the same binding and protocol state for its fixture and
continues through the same sealed offer/grant predicate.

Give a party a well-formed code whose address resolves nothing and require
`PairingRecordUnavailable` after exactly one resolution attempt and no further
network request. Tamper the QR prefix, the JSON canonical form, or `c` and
require a fresh-ceremony failure. Require a machine carrier transporting words
rather than `c` to be rejected.

### TEST-410: Downgrade and cross-protocol isolation

**Validates:** REQ-407, REQ-408, CON-404, CON-408.

Attempt to feed the two words, `wib`, word hash, or truncated word material
into the former direct-secret HKDF. Attempt to omit `cA` or `cB`, make the
provider a responder, reuse Hark/cbcl-bus domain labels, change version or
role labels, or negotiate an unknown mode. Every attempt is rejected before a
mailbox or authorization side effect.

### TEST-411: Allocation abuse, claim burn, expiry, and retry

**Validates:** REQ-406, NFR-402, NFR-403, CON-405, CON-406.

Exercise allocation floods, nameplate enumeration, pre-claim races, conflicting
claims, identical and conflicting frame retries, dropped responses, `429`,
expiry boundaries, tombstone expiry, and replicas racing the same nameplate.
Require atomic single-claim behavior for an honest provider, fixed 600-second
expiry, bounded parsing/storage, no existence oracle from wrong tokens, and
client-authoritative burn after every ambiguous post-display action.

### TEST-412: Full authorization chain remains mandatory

**Validates:** ADR-405, CON-408.

Complete SPAKE2 with the correct code but omit or mutate application enrollment
evidence, consent, home signature, VC audience, holder key, device proof, or
fresh `did:crdt` state. Require zero accepted grants. Conversely, complete the
entire SPEC-004 chain and require successful authorization.

This proves that the PAKE authenticates the OOB capability, not the developer
origin or final credential.

### TEST-413: Meeting point, initiation direction, and prefix entry

**Validates:** REQ-402, REQ-403, REQ-408, REQ-409, ADR-406 through ADR-409,
CON-402, CON-403, CON-409.

Derive `meet_addr` from normative `C` vectors in two independent
implementations and require byte-identical addresses. Require a one-bit change
in `C` to change the address. Require `meet_seed` never to equal, and never to
be derivable from, `w_bytes`, `K`, or `mailbox_secret_16`.

Publish and resolve a valid record. Then reject, individually: a bad signature,
a signature by a key other than `meet_addr`, an expired record, a second record
at one address, an unknown or missing member, a non-canonical base64url
`profileDigest`, a `nameplate` that is not six digits, a `providerId` matching
no descriptor, a `providerId` matching two, and a `profileDigest` that does not
equal the digest of the fetched profile. Assert zero semantic action on every
rejection — no claim, no frame, no probe beyond the profile fetch.

Substitute a hostile record naming a different `applicationId`, `providerId`, or
`nameplate` while keeping a valid signature. Require the ceremony to reach
confirmation and fail there, proving the record is a hint that a divergent
`binding_hash` catches rather than a trusted routing decision.

Run a complete ceremony in **both** initiation directions with fresh randomness.
Require identical role assignment, transcript identities, frame order, derived
keys, and acceptance decisions; require the traces to differ only in which party
generated and displayed the code. Require a wallet-generated code to expire
within 600 seconds, to admit at most one resolved record, and to surface the
resolved `applicationId` before any consent affordance.

Require the twelve-word rendering and the `c` bootstrap to round-trip to the
identical sixteen octets. Reject an abbreviated word, a word absent from the
list, a failing checksum, and a machine carrier transporting words rather than
`c`. Confirm that every derivation consumes `C` and never a spelling of it, by
rendering one `C` two ways and requiring identical `w_bytes`, `meet_addr`, and
`binding_hash`.

Resolve the same record through a relay transport and a distributed hash table,
and through both raced concurrently. Require identical results and require no
trust decision to depend on which transport answered.

## Trust assumptions

- The application's profile is authenticated to its canonical HTTPS
  `applicationId` by the mechanism required in SPEC-004.
- The QR, manual code, or verified same-device handoff is confidential enough
  that a remote attacker does not learn both words before the ceremony ends.
- Client CSPRNGs, constant-time ristretto255, SHA-256/SHA-512, HKDF, HMAC, and
  secure memory behave as specified.
- At least one endpoint remains uncompromised. A compromised application or
  wallet process can disclose the code and its own resulting keys.
- TLS supplies channel integrity and server-origin authentication for the
  selected provider. End-to-end SPAKE2 and application signatures still treat
  the provider as malicious.
- The provider may deny service. Availability against a selected malicious
  operator is not guaranteed.

## Threat model

The adversary may:

- operate the pairing provider, rendezvous, network, or an unrelated
  application;
- enumerate public nameplates, claim an unclaimed session, and make one online
  word guess against an endpoint;
- replay, fork, replace, delay, drop, or reorder all relay frames;
- copy a public application profile, substitute an endpoint, or splice two
  concurrent ceremonies;
- observe QR display or manually entered code when physically present;
- induce timeouts, retries, replica races, and provider failover; and
- obtain all expired provider storage and logs.

It may not, for the protocol's remote-attacker claim:

- read a correctly delivered OOB code before expiry;
- compromise the application or wallet process, OS trust store, secure random
  generator, or platform verified-app binding;
- break the assumed cryptographic primitives; or
- forge the developer enrollment key, home key, device key, or `did:crdt`
  signatures.

### Required security properties

- **Passive offline resistance:** provider transcripts do not verify guesses
  for `C`, which at 128 bits is not guessable in any case.
- **Bounded active guessing:** the wallet evaluates at most one initiator
  confirmation per minted ceremony; success probability from guessing alone is
  at most `2^-22` for that ceremony.
- **Mutual key confirmation:** neither endpoint accepts a key without the
  opposite role's valid MAC over the same bound transcript.
- **Provider blindness:** the provider has no password verifier or agreed key.
- **Routing integrity:** application/profile/descriptor/route/nameplate changes
  produce a different transcript and cannot silently redirect an accepted
  ceremony.
- **Downgrade resistance:** low-entropy words never enter a direct-secret path.
- **Authorization separation:** successful SPAKE2 is necessary to open the
  transport but insufficient to issue or accept a grant.
- **Cross-application privacy:** route and nameplate reuse do not create a
  cryptographic equality test because application/profile/descriptor bindings
  domain-separate every key.

### Residual risks

- A person or local app that sees or captures the complete QR/code before use
  can race the intended wallet. Knowledge of the words removes PAKE's password
  barrier; application evidence, consent, home signatures, and device binding
  still prevent an unauthenticated grant, but confidentiality and availability
  may be lost.
- Two words provide only 22 bits. The N=1 rule bounds rather than eliminates
  online guessing. A future change to retry count or word count is a Tier-1
  amendment.
- A guessed or enumerated nameplate can be claimed first to cause denial of
  service. Rate limits and a six-digit space reduce bulk abuse but cannot
  guarantee availability.
- A malicious provider can give each endpoint one different active guess by
  forking. Client locking bounds each endpoint independently; the home wallet
  remains authoritative for grant issuance.
- Browser clients reveal their web `Origin` to the pairing provider. Native
  clients avoid that header, but IP/timing correlation remains possible.
- Application identity must accompany a code somehow. QR and same-device
  handoff make this automatic; a purely human cross-device fallback must show
  the application ID as well as the short code. Eliminating that context would
  require a global directory or a longer globally routable code.

## Tier-1 Gate

No implementation task may be marked ready until all boxes are checked:

- [ ] A fresh-context cross-model adversarial review covers the exact group
      construction, M/N derivation, scalar reduction, password mapping,
      transcript, identities, confirmation order, key schedule, routing,
      provider compromise, N=1 claim/burn, downgrade, and privacy.
- [ ] A second independent review verifies the amendment and closes every
      blocking finding from the first.
- [ ] A human cryptography reviewer approves CON-403, CON-404, CON-407, and
      CON-408, including the protocol-specific ristretto255 deviation from the
      ciphersuites listed by RFC 9382.
- [ ] Normative vectors required by TEST-403 are published and reproduced
      byte-for-byte by at least two independent implementations.
- [ ] The Hark/cbcl-bus implementation is reconciled with its stale four-word
      module comment and its reusable primitive/domain-separation boundary is
      documented; Selfsame does not copy its provider-as-responder trust model.
- [ ] Two independently operated providers pass TEST-401 and TEST-404 through
      TEST-411 without Anuna infrastructure or an Anuna runtime dependency.
- [ ] An application-profile security review approves route assignment,
      profile digest binding, profile updates during a ceremony, and the
      unresolvable-code failure rule.
- [ ] A privacy review covers application/profile metadata, browser Origin,
      nameplate enumeration, token handling, IP/timing retention, and
      cross-application/provider collusion.
- [ ] A production-operator review approves atomic claim/write behavior across
      replicas, exact TTL/tombstone semantics, overload handling, and abuse
      controls.
- [ ] A human cryptography reviewer approves CON-409, including the
      code-derived meeting-point keypair, its domain separation from `w`, `K`,
      and `mailbox_secret_16`, and the decision to sign rather than encrypt the
      record.
- [ ] TEST-413 passes in both initiation directions against two independent
      implementations, including the hostile-record and transport-race cases.
- [ ] OQ-401, OQ-402, and OQ-403 are resolved normatively or explicitly
      accepted by the human owner with bounded consequences.
- [ ] SPEC-004 0.9.0 or later records the completed reconciliation with
      ADR-406 through ADR-409, or this protocol is reverted.
- [ ] SPEC-004's profile-origin and mobile-platform evidence gate closes.
- [ ] Human security sign-off records an approved version and commit.

## Open questions

### OQ-401: Who operates the meeting-point transport? — blocking

[[PROTO-003-selfsame-pairing-v1#CON-409]] requires a transport that returns a
signed record, but does not say who runs one or how a client finds it. The
resolving party is by definition the one without the application profile, so the
profile cannot name it — which leaves a shipped list, a distributed hash table,
or both.

A shipped relay list brushes against
[[SPEC-004-application-scoped-identity#REQ-210]] and the Infrastructure promise.
The tension is narrower than it first appears, because a signed record means such
a host can **withhold but never substitute**, making it a liveness dependency
rather than a trust anchor — the same "hints, not trust anchors" line CON-409
already draws. But `REQ-210` and the Infrastructure promise are anti-lock-in
commitments about operator *power*, not privacy commitments, and a default
transport is exactly the operator dependency they were written to prevent.

The decision must fix: whether a version-2 client ships a relay list, whether at
least two independent operators are required before the gate closes, whether a
DHT is mandatory as the correctness arm, and what a client does when every
declared transport fails. Racing several is permitted by CON-409 and does not by
itself resolve who runs them.

Owner: HOC + application-profile working group.

### OQ-402: What does a meeting-point observer accumulate? — blocking for the privacy review

A record host observes a publish and a resolve at one address, seconds apart,
from two addresses on the network. It learns neither which person nor which
account, and 128-bit addressing makes ceremonies unlinkable to each other. But
it does learn that two devices are pairing, and — because
[[PROTO-003-selfsame-pairing-v1#CON-409]] cannot encrypt its payload — which
application they are pairing with.

The rendezvous operator already sees both endpoints today, since
[[PROTO-003-selfsame-pairing-v1#CON-408]] makes one descriptor URL the only
mailbox origin. The change is **aggregation scope**: today's observer is chosen
by the application from its own profile and sees only that application's
ceremonies, whereas a meeting-point transport must be reachable by a party that
has no profile, and therefore sees across applications.

The decision must fix whether that aggregation is acceptable, and whether
transports must be structured so that publish and resolve can land on different
hosts — which a DHT-backed cache arrangement permits and a single authoritative
relay does not.

Owner: privacy reviewer + HOC.

### OQ-403: Does version 1 coexist with version 2? — blocking for any deployed client

Version 2 changes the code grammar, the password width, every domain-separation
label, and the transcript identities, so a version-1 and a version-2 client
cannot complete a ceremony together and will fail at confirmation rather than
negotiate.

That is the intended fail-closed behaviour, but no migration is specified. The
decision must fix whether any version-1 code may still be accepted, how a client
reports a version mismatch without creating a downgrade oracle, and whether the
`selfsame-pairing-v1` capability token in
[[PROTO-003-selfsame-pairing-v1#CON-401]] is retired or served alongside a
version-2 token.

Owner: HOC.

## Traceability

| Outcome | Requirements | Decisions/contracts | Tests |
|---|---|---|---|
| Human twelve-word code | REQ-402 | ADR-406, CON-402, CON-403 | TEST-402, TEST-413 |
| Many apps and providers without a global directory | REQ-403 | ADR-401, ADR-402, CON-401–403 | TEST-408, TEST-409 |
| Provider is not a PAKE trust anchor | REQ-404 | ADR-403, CON-404–407 | TEST-405, TEST-407 |
| Mutual confirmation and N=1 guessing | REQ-405, REQ-406 | ADR-404, CON-404, CON-407 | TEST-403, TEST-406, TEST-411 |
| Existing encrypted grant ceremony reused | REQ-407 | ADR-405, CON-408 | TEST-404, TEST-410, TEST-412 |
| QR/manual/same-device equivalence | REQ-408 | CON-402, CON-407, CON-408 | TEST-409, TEST-410 |
| A code a person can say, with room for discovery | REQ-402 | ADR-406, CON-402 | TEST-402, TEST-403, TEST-413 |
| First-encounter routing without a spoken identity | REQ-402, REQ-403 | ADR-407, ADR-409, CON-409 | TEST-408, TEST-413 |
| Either party may start the ceremony | REQ-408, REQ-409 | ADR-408, CON-402, CON-409 | TEST-409, TEST-413 |
| One value, many renderings | REQ-402 | ADR-406, CON-402 | TEST-402, TEST-413 |

## Amendment Channels

This protocol may be amended only by a versioned change to this file that
identifies affected REQ/NFR/ADR/CON/TEST artefacts, updates traceability and the
changelog, records evidence, receives Tier-1 review, and is approved by the
human owner.

Any change to code entropy or grammar, BIP-39 list or packing, route/nameplate
width, group, M/N, scalar generation, labels, transcript, identities, key
schedule, confirmation order, frame state, claim count, TTL, token semantics,
mailbox derivation, bootstrap fields, provider/profile binding, or downgrade
behavior is a Tier-1 normative amendment requiring new vectors and renewed
human cryptography sign-off.

## Normative and informative sources

Normative internal specifications:

- [[SPEC-004-application-scoped-identity]] defines application profiles,
  application authentication, consent, VC grants, holder proof, and revocation.
- [[PROTO-002-selfsame-rendezvous-v1]] defines the blind mailbox used after
  PAKE confirmation.
- [[PROTO-004-selfsame-ceremony-envelope-v1]] defines the sealed offer/grant
  record derived from the confirmed key and `binding_hash`.

Normative external specifications:

- IRTF/CFRG, [RFC 9382 — SPAKE2](https://datatracker.ietf.org/doc/html/rfc9382),
  especially the two-round flow, peer identities, transcript binding, point
  validation, fresh ephemerals, and explicit confirmation requirements.
- IRTF/CFRG, [RFC 9496 — The ristretto255 and decaf448
  Groups](https://datatracker.ietf.org/doc/html/rfc9496), for ristretto255
  encoding, decoding, group operations, scalar field, and uniform-byte element
  derivation.
- IETF, RFC 2104, RFC 5869, RFC 6234, RFC 8785, and RFC 9110.
- Bitcoin Improvement Proposal
  [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki),
  used only for the fixed English word-index list. The two-word pairing phrase
  is not a BIP-39 mnemonic or wallet seed.

Informative implementation precedent:

- Hark `src/pairing` and cbcl-bus `/pair/v1` demonstrate two BIP-39 words,
  ristretto255 SPAKE2, explicit confirmation, and N=1 burn. Their existing
  provider-as-responder storage and application-specific transcript labels are
  not part of this protocol.

Standards constraints that are easy to miss:

- RFC 9382 is Informational and SPAKE2 was not selected by the CFRG PAKE
  competition. This document's exact suite requires independent review.
- RFC 9382 states that SPAKE2 is not augmented; a SPAKE2 server stores a
  password equivalent. Selfsame avoids that property by making the application
  and wallet the endpoints and the provider a relay.
- PAKE prevents passive offline guessing and bounds online guessing to one
  attempt per ceremony. At the 128-bit width fixed by
  [[PROTO-003-selfsame-pairing-v1#ADR-406]] guessing is infeasible regardless,
  so SPAKE2 is retained for its transcript binding and forward secrecy rather
  than to rescue a small password.
- Knowledge of a PAKE password authenticates shared password knowledge, not a
  developer origin, human identity, account, device key, or VC issuer.
- BIP-39 defines mnemonic-to-seed behavior. This protocol uses the English
  wordlist and its checksum purely as a transcription-resistant rendering of
  128 bits, and never derives a BIP-39 seed. A pairing code is not a wallet
  mnemonic and MUST NOT be entered as one.

## Changelog

- **0.3.0 — 2026-07-31 — draft, normative.** Replaces the code and its routing.
  Adds ADR-406 through ADR-409, REQ-409, CON-409, TEST-413, and OQ-401–403;
  rewrites CON-402; amends REQ-402, REQ-403, REQ-408, CON-403, CON-404, the
  Orientation block, the Tier-1 gate, and traceability.

  *The code.* `<8 digits>-<word>-<word>` becomes twelve BIP-39 English words
  carrying 128 bits. SPEC-004 ADR-215 cut entropy from 128 to 22 bits to fix an
  accessibility complaint about **41 Bech32m characters** — a defect of encoding,
  not of entropy. Twelve words cost two spoken tokens against the old code,
  return 80 bits, and self-check via the BIP-39 checksum. CON-402 now states the
  separation explicitly: the protocol value is `C`, sixteen octets, and words and
  the base64url bootstrap are renderings of it. Machine carriers transport `C`
  and never words. Abbreviated four-character word entry was considered and
  deliberately excluded — one value, one recogniser, one accepted spelling.

  *The routing.* Route and nameplate leave the human code entirely. The
  application publishes a signed, ephemeral record at an Ed25519 address derived
  from `C`; the other party resolves it for `applicationId`, `profileDigest`,
  `providerId`, and `nameplate`. This closes first-encounter routing, which
  version 0.2.0 could only solve by having a person say an HTTPS URI aloud. The
  128-bit address is what makes it safe: at 22 bits the same construction yields
  an enumerable directory of live ceremonies and hence targeted pre-claim denial
  of service. CON-403's binding object is unchanged in membership — route and
  nameplate are reconstructed from the record — so ADR-401 and ADR-402's
  cross-application separation survives intact.

  *The direction.* Either party may generate and display the code; the
  application is always SPAKE2 role A, always selects the provider, and always
  publishes the record. This puts the typing on whichever device has the better
  keyboard. The residual risk is recorded rather than mitigated away: a
  wallet-generated code has no intended recipient, so consent is its only
  signal.

  *Domain separation.* Every label moves to `v2` and the transcript identities
  become `application`/`wallet`, since `initiator` was a misnomer for a role that
  is always the application. This invalidates every previously published vector
  and makes a v1/v2 downgrade fail as a mismatch rather than succeed weakly.
  OQ-403 records that no v1/v2 migration is specified.

  Not changed: the ristretto255 construction, mutual confirmation, N=1 burn, the
  blind relay boundary, and mailbox derivation.
- **0.2.0 — 2026-07-31 — draft, normative.** Repairs a scope gap: this document
  placed "the encrypted offer/bundle mailbox wire contract" out of scope and
  delegated it to [[PROTO-002-selfsame-rendezvous-v1]], which had itself placed
  offer, grant, and AEAD formats out of scope. Neither owned the sealed record
  carrying every Selfsame device grant. The out-of-scope list now separates the
  sealed record, owned by [[PROTO-004-selfsame-ceremony-envelope-v1]], from the
  mailbox transport, owned by PROTO-002. CON-408 correspondingly names
  PROTO-004 as the consumer of `mailbox_secret_16` and `binding_hash` for
  encryption, replacing a reference to PROTO-002 contracts that do not define
  it, and records that slot derivation and key derivation are separate
  functions over the same secret. No code grammar, packing, SPAKE2
  construction, transcript, confirmation, burn rule, or derivation output
  changed.
- **0.1.0 — 2026-07-30 — draft, normative.** First protocol draft. Defines
  profile-local `route || nameplate` routing, the canonical
  `<8 digits>-<word>-<word>` code, a QR/bootstrap envelope, exact BIP-39 index
  packing, an application-to-wallet ristretto255 SPAKE2 construction, a blind
  four-frame provider relay, explicit mutual confirmation, N=1 local burn, and
  derivation into the existing PROTO-002 mailbox. Records the many-application
  discovery constraint and leaves the Tier-1 gate open.
