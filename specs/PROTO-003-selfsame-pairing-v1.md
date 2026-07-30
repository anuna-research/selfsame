---
id: PROTO-003
title: Selfsame Pairing Protocol v1 — routable num-word-word SPAKE2
status: draft
tier: 1
version: 0.1.0
audience: application developer, SDK implementer, wallet implementer, infrastructure operator, security reviewer
author: Anuna Research (drafted with Codex, 2026-07-30)
last-updated: 2026-07-30
owner-repo: selfsame
affects-repos: selfsame, hark, cbcl-bus, adopting applications, independent pairing implementations
review-gate: not-approved — Tier-1; independent cryptographic vectors, cross-model adversarial review, privacy review, production-operator review, and human cryptography sign-off are outstanding
depends-on: SPEC-004; PROTO-002; RFC 2104; RFC 2119; RFC 3986; RFC 4648; RFC 5234; RFC 5869; RFC 6234; RFC 8174; RFC 8785; RFC 9110; RFC 9382; RFC 9496; BIP-39
---

# PROTO-003 — Selfsame Pairing Protocol v1

## Orientation

**Intent.** Define an independently implementable pairing ceremony whose
human-facing code is:

```text
<number>-<word>-<word>
```

The same ceremony SHALL work across unrelated applications and independently
operated rendezvous services without a user-managed server setting or a
mandatory Selfsame directory.

**User promise.** The normal cross-device path is one QR scan. The accessible
fallback shows the application's authenticated HTTPS identity and one short
code such as `03482715-rocket-anchor`; the person never types or selects a
rendezvous endpoint. Same-device mobile passes the same bootstrap through a
verified OS channel without a self-scan.

**Security promise.** The two words are a 22-bit BIP-39 password used only by
SPAKE2. They are never treated as a high-entropy bearer key or passed directly
to the mailbox HKDF. The application and wallet perform SPAKE2 end to end,
including explicit key confirmation. The pairing operator relays four opaque
32-byte values and never receives the words, their indices, a password
verifier, the agreed key, an offer, a grant, a DID, or an account identifier.

**Routing promise.** A code is intentionally not a global endpoint name. The
application identity selects an authenticated application profile; the first
two digits select one descriptor within that profile; the remaining six digits
locate one short-lived session at that provider. QR and verified OS handoff
carry the application context. A manual flow supplies the application identity
beside the code. No client broadcasts a bare code to candidate services.

**Structure.**

```text
 application A profile                     application B profile
 routes 00..99                             routes 00..99
       |                                         |
       | app-selected route 03                   | independent namespace
       v                                         v
 pairing provider P                         pairing provider Q
 nameplate 482715                           nameplate 482715
       |                                         |
  03482715-rocket-anchor                    03482715-ocean-table
       |
       | QR / verified OS handoff:
       | applicationId + profileDigest + code
       v
 application (SPAKE2 A) <---- opaque relay ----> wallet (SPAKE2 B)
       |                     pA,pB,cA,cB                 |
       +---------------- mutual confirmation ------------+
                             |
                    32-byte ceremony key
                             |
                    derive 16-byte mailbox secret
                             |
                 [[PROTO-002-selfsame-rendezvous-v1]]
                    encrypted offer / grant only
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
secret from the confirmed PAKE key.

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
[[PROTO-003-selfsame-pairing-v1#REQ-408]] QR, manual, and same-device carriers
cannot create a downgrade.

**Controls digest.**

- The canonical code is eight ASCII digits, a hyphen, and exactly two
  lower-case words from the BIP-39 English list.
- The first two digits are a profile-local provider route. The last six are a
  provider-local active-session nameplate. Neither is secret.
- The two word indices carry exactly 22 bits. Their security depends on SPAKE2,
  explicit confirmation, a 600-second lifetime, one peer claim, and permanent
  local burn after the first failed confirmation.
- A QR bootstrap contains an application ID, profile digest, and the same
  human code. It contains no provider URL selected by an untrusted caller.
- A bare code without authenticated application context is rejected. Clients
  never query all known applications or providers looking for a match.
- The pairing provider stores no password-equivalent verifier and performs no
  group operation, MAC verification, grant decision, or application lookup.
- The application is SPAKE2 role A; the Selfsame wallet is role B. Both reject
  invalid ristretto255 encodings and require the opposite confirmation MAC.
- The PAKE transcript binds the application, complete provider descriptor,
  profile, route, nameplate, protocol version, and roles.
- Only after mutual confirmation do clients derive the 16-byte secret used by
  [[PROTO-002-selfsame-rendezvous-v1]].
- Every retry after ambiguity, collision, wrong input, invalid point, failed
  MAC, timeout, provider change, or carrier mismatch creates a fresh code,
  nameplate, SPAKE2 ephemerals, mailbox secret, and offer.

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
4. **two words**, which authenticate the end-to-end PAKE.

That separation is necessary: a short code cannot encode and authenticate an
arbitrary HTTPS endpoint without either more human input or a shared global
directory. Version 1 chooses application-origin discovery and profile-local
routing, not a mandatory Selfsame directory.

## Scope

### In scope

- the canonical `number-word-word` grammar and BIP-39 index encoding;
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
- the encrypted offer/bundle mailbox wire contract, owned by
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
3. It generates two uniformly random BIP-39 English word indices and a fresh
   SPAKE2 role-A ephemeral. The selected pairing provider allocates a
   six-digit nameplate and returns an initiator capability token.
4. The application combines the descriptor's two-digit route with the
   nameplate, computes `pA`, stores it, and only then displays the QR and
   `number-word-word` fallback.
5. The wallet receives the QR/bootstrap, or receives the application identity
   and code through a conforming manual or same-device carrier. It obtains the
   origin-authenticated profile, requires the profile digest to match, uses
   the route to select the exact descriptor, and claims the nameplate once.
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

Every version-1 human pairing code SHALL conform to
[[PROTO-003-selfsame-pairing-v1#CON-402]]. Its eight-digit number SHALL contain
only a two-digit profile route and a six-digit provider nameplate. Its two
words SHALL encode the SPAKE2 password according to
[[PROTO-003-selfsame-pairing-v1#CON-403]].

No digit or word SHALL encode an application account, DID, device key,
permission, endpoint URL, provider-global identity, or derivation index.

Trace:
[[PROTO-003-selfsame-pairing-v1#TEST-402]]

### REQ-403: Routing scales across applications and providers

An application profile MAY declare up to 100 pairing-capable rendezvous
descriptors with distinct routes `00` through `99`. Routes are scoped to the
exact application ID and profile digest and MAY be reused by every other
application.

The initiating application SHALL select a descriptor. The wallet SHALL follow
the route only within the matching origin-authenticated profile. It SHALL NOT
interpret the route globally, use an operator allowlist as a substitute for
the profile, query unrelated profiles, broadcast a code, or consult an
undeclared Selfsame/Anuna fallback.

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

QR, manual, and same-device carriers SHALL deliver the same logical bootstrap
defined by [[PROTO-003-selfsame-pairing-v1#CON-402]]. They may differ only in
physical transport and whether the person types the code.

No carrier may change the SPAKE2 roles, ciphersuite, transcript binding,
provider, confirmation rules, mailbox derivation, encrypted offer/grant,
application evidence, consent, or acceptance predicate. A carrier or peer that
claims a direct-secret, no-confirmation, provider-terminated, or unknown mode
causes a fresh-ceremony failure; there is no version negotiation inside a
version-1 session.

Trace:
[[PROTO-003-selfsame-pairing-v1#TEST-409]],
[[PROTO-003-selfsame-pairing-v1#TEST-410]]

## Non-functional requirements

### NFR-401: Human entry remains bounded

The canonical code contains 8 digits, 2 hyphens, and 2 BIP-39 English words.
It is case-insensitive at the presentation parser but always canonicalized to
lower-case ASCII with hyphens before use. A UI SHALL display the numeric part
as one uninterrupted value and MAY visually group its two-digit route from its
six-digit nameplate without adding a parsed character.

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

**Status:** PROPOSED.

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

### CON-402: Pairing code, application context, and QR bootstrap

Normative ABNF:

```abnf
DIGIT         = %x30-39
lower         = %x61-7A
route         = 2DIGIT
nameplate     = 6DIGIT
number        = route nameplate
word-token    = 3*8lower
pairing-code  = number "-" word-token "-" word-token
```

Each `word-token` additionally MUST be an exact member of the 2,048-word
BIP-39 English word list. Both words MAY be equal. The canonical code uses
lower-case ASCII and hyphens. A presentation parser MAY accept ASCII upper-case
letters and one or more ASCII spaces around or in place of a hyphen, but it
MUST reject non-ASCII confusables, extra tokens, missing leading zeroes, and
every value that cannot be re-encoded to one canonical code.

The logical bootstrap is:

```json
{
  "version": 1,
  "applicationId": "https://photos.example/selfsame/application",
  "profileDigest": "<base64url SHA-256 of the authenticated profile>",
  "code": "03482715-rocket-anchor"
}
```

The object has exactly those four members. `applicationId` is canonical under
[[SPEC-004-application-scoped-identity#CON-201]]. `profileDigest` is canonical
unpadded RFC 4648 base64url decoding to exactly 32 bytes. `code` passes the
grammar above.

The canonical QR payload is:

```text
ASCII("selfsame-pairing-v1:")
|| BASE64URL-NOPAD(RFC8785(logical_bootstrap))
```

It is data consumed inside a conforming Selfsame wallet, not an OS navigation
URL. It MUST NOT be opened by a browser, emitted as an HTTP query, placed in a
referrer, or registered as an authoritative private-use URL scheme.

The QR and verified same-device carriers deliver the complete bootstrap. A
manual carrier MAY deliver the code alone only when the wallet already has the
exact origin-authenticated `applicationId` and profile digest for that
ceremony. Otherwise the UI SHALL supply the exact application ID beside the
code, and the wallet SHALL retrieve and authenticate that application's
profile before routing. Supplying an application identity is ceremony
bootstrap, not a user-selected provider setting.

A bare code with no application context returns
`MissingApplicationContext`. The wallet SHALL NOT search installed apps,
historic profiles, provider lists, DNS guesses, or network endpoints for a
matching nameplate.

### CON-403: Word-index and transcript binding inputs

Let `i1` and `i2` be the zero-based BIP-39 English indices of the two words.
The password input bytes are:

```text
packed = ((i1 << 11) | i2) << 2
wib    = U24BE(packed)
```

Thus `wib` is exactly three bytes: 22 index bits followed by two zero pad bits.
For `account-clinic`, indices 12 and 345 produce hex `018564`.

Let `number`, `route`, and `nameplate` be the canonical code substrings. Let
`profile_digest` and `descriptor_digest` be canonical unpadded base64url
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
idA = ASCII("selfsame-pairing-v1/initiator/") || binding_hash
idB = ASCII("selfsame-pairing-v1/wallet/") || binding_hash
```

The words and `wib` never appear in the binding object. Two applications may
use the same route, provider ID, number, and words; their different canonical
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
  salt = ASCII("selfsame-pairing-v1"),
  info = ASCII("selfsame-pairing-password-v1"),
  L    = 64)
w = REDUCE_SCALAR_LE(w_bytes)
```

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
  info = ASCII("selfsame-pairing-session-key-v1"),
  L    = 32)

cA = HMAC-SHA256(
  K, ASCII("selfsame-pairing-initiator-confirm-v1") || tt_hash)
cB = HMAC-SHA256(
  K, ASCII("selfsame-pairing-wallet-confirm-v1") || tt_hash)
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

The output is a fresh 128-bit pseudorandom secret and becomes `secret_16` in
[[PROTO-002-selfsame-rendezvous-v1#CON-302]]. The selected descriptor's `url`
is the only mailbox origin. Offer and bundle encryption, transcript binding,
size, immutable writes, repeatable reads, CORS, expiry, and retry follow
[[PROTO-002-selfsame-rendezvous-v1#CON-302]] through
[[PROTO-002-selfsame-rendezvous-v1#CON-308]] without alteration.

The encrypted application transcript additionally binds the exact
`binding_hash`, offer digest, ceremony ID, request ID, application/account
scope, device key, permission set, and application enrollment evidence as
required by [[SPEC-004-application-scoped-identity]]. SPAKE2 establishes
shared knowledge of the OOB password; it does not replace application-origin
authentication, consent, the home signature, VC verification, or holder proof.

## Test specifications

### TEST-401: Capability and descriptor recognition

**Validates:** REQ-401, CON-401.

Accept the exact capability response and descriptor grammar. Reject every
unknown/missing member, duplicate route, invalid route width, non-canonical
URL, wrong protocol, wrong fixed limit, expired descriptor, redirect, content
encoding, oversized body, and pairing-only provider lacking PROTO-002.

### TEST-402: Code grammar and BIP-39 packing

**Validates:** REQ-402, CON-402, CON-403.

Accept and re-encode canonical `03482715-account-clinic`; split route `03` and
nameplate `482715`; and produce `wib = 018564`. Cover index boundaries
`0/0`, `0/2047`, `2047/0`, and `2047/2047`, including repeated words.

Reject missing leading zeroes, non-ASCII digits, Unicode hyphens/confusables,
one or three words, a non-list word, empty tokens, overlong input, and any
presentation form that does not converge on one canonical output.

### TEST-403: Normative SPAKE2 vectors

**Validates:** REQ-405, CON-403, CON-404.

Publish fixed vectors containing the complete binding object, RFC 8785 bytes,
binding hash, word indices, `wib`, role ephemerals, M/N encodings, `w_bytes`,
`pA`, `pB`, encoded shared element, transcript hash, `K`, `cA`, `cB`, and
mailbox secret. Two independent implementations reproduce every byte.

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

### TEST-409: QR, manual, and same-device convergence

**Validates:** REQ-408, CON-402, CON-407, CON-408.

Deliver one logical bootstrap by canonical QR, by exact application context
plus manually entered code, and by the verified same-device platform adapter.
Each path produces the same binding and protocol state for its fixture and
continues through the same encrypted offer/grant predicate.

Give a wallet only the bare code and require `MissingApplicationContext` with
zero network requests. Tamper the QR prefix, JSON canonical form, application
ID, profile digest, or code and require a fresh-ceremony failure.

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
  for the two words.
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
- [ ] An application-profile security review approves two-digit route
      assignment, profile digest binding, profile updates during a ceremony,
      and the bare-code failure rule.
- [ ] A privacy review covers application/profile metadata, browser Origin,
      nameplate enumeration, token handling, IP/timing retention, and
      cross-application/provider collusion.
- [ ] A production-operator review approves atomic claim/write behavior across
      replicas, exact TTL/tombstone semantics, overload handling, and abuse
      controls.
- [ ] SPEC-004's profile-origin and mobile-platform evidence gate closes.
- [ ] Human security sign-off records an approved version and commit.

## Traceability

| Outcome | Requirements | Decisions/contracts | Tests |
|---|---|---|---|
| Human `number-word-word` code | REQ-402 | ADR-402, CON-402, CON-403 | TEST-402 |
| Many apps and providers without a global directory | REQ-403 | ADR-401, ADR-402, CON-401–403 | TEST-408, TEST-409 |
| Provider is not a PAKE trust anchor | REQ-404 | ADR-403, CON-404–407 | TEST-405, TEST-407 |
| Mutual confirmation and N=1 guessing | REQ-405, REQ-406 | ADR-404, CON-404, CON-407 | TEST-403, TEST-406, TEST-411 |
| Existing encrypted grant ceremony reused | REQ-407 | ADR-405, CON-408 | TEST-404, TEST-410, TEST-412 |
| QR/manual/same-device equivalence | REQ-408 | CON-402, CON-407, CON-408 | TEST-409, TEST-410 |

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
- [[PROTO-002-selfsame-rendezvous-v1]] defines the encrypted offer/grant
  mailbox used after PAKE confirmation.

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
- PAKE prevents passive offline guessing; it does not make a 22-bit password
  high entropy or prevent one active online guess.
- Knowledge of a PAKE password authenticates shared password knowledge, not a
  developer origin, human identity, account, device key, or VC issuer.
- BIP-39 defines mnemonic-to-seed behavior for supported mnemonic lengths.
  This protocol uses only two English word indices as a compact 22-bit PAKE
  input and does not claim that two words form a BIP-39 mnemonic.

## Changelog

- **0.1.0 — 2026-07-30 — draft, normative.** First protocol draft. Defines
  profile-local `route || nameplate` routing, the canonical
  `<8 digits>-<word>-<word>` code, a QR/bootstrap envelope, exact BIP-39 index
  packing, an application-to-wallet ristretto255 SPAKE2 construction, a blind
  four-frame provider relay, explicit mutual confirmation, N=1 local burn, and
  derivation into the existing PROTO-002 mailbox. Records the many-application
  discovery constraint and leaves the Tier-1 gate open.
