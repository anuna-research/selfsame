---
id: PROTO-004
title: Selfsame Ceremony Envelope v1 — the sealed offer and grant record
status: draft
tier: 1
version: 0.1.0
audience: application developer, SDK implementer, wallet implementer, security reviewer
author: Anuna Research (drafted with Claude, 2026-07-31)
last-updated: 2026-07-31
owner-repo: selfsame
affects-repos: selfsame, anuna-ssi, adopting applications, independent client implementations
review-gate: not-approved — Tier-1; independent AEAD and key-schedule vectors, cross-model adversarial review, and human cryptography sign-off are outstanding
depends-on: SPEC-004; PROTO-002; PROTO-003; RFC 2119; RFC 4648; RFC 5234; RFC 5869; RFC 6234; RFC 8174; RFC 8439; RFC 8785
---

# PROTO-004 — Selfsame Ceremony Envelope v1

## Orientation

**Intent.** Define the sealed record that a Selfsame device-authorization
ceremony writes to a [[PROTO-002-selfsame-rendezvous-v1]] mailbox slot: how the
confirmed pairing key becomes an encryption key, what the ciphertext looks like
on the wire, and how a payload is recognized before it is interpreted.

**Why this document exists.** [[PROTO-002-selfsame-rendezvous-v1]] declares
offer, grant, AEAD, and transcript formats out of scope; it transports opaque
bytes. [[PROTO-003-selfsame-pairing-v1]] declared the same contract out of
scope and delegated it to PROTO-002. Neither owned it, so the layer that
carries every Selfsame credential had no specification at all. This document
owns it. It defines the **envelope**; the enclosing profile — for version 1,
[[SPEC-004-application-scoped-identity#CON-219]] — owns the **payload**.

**Security promise.** One ceremony produces exactly two envelope keys, each
sealing exactly one record. A key never encrypts a second distinct plaintext,
so the nonce is a constant and no counter or coordination exists between the
two independently writing endpoints. The rendezvous operator holds ciphertext
whose key it cannot derive, over a transcript it cannot alter without
detection.

**Structure.**

```text
 PROTO-003 mutual confirmation
        |
        | mailbox_secret_16, binding_hash
        v
 +--------------------- CON-501 key schedule ---------------------+
 |   K_offer = HKDF(secret, binding_hash, "…/offer")              |
 |   K_bundle = HKDF(secret, binding_hash, "…/bundle")            |
 +----------------------------------------------------------------+
        |                                    |
        v                                    v
 CON-502 seal(offer)                  CON-502 seal(bundle)
   application writes                   wallet writes
        |                                    |
        +-------- PROTO-002 mailbox ---------+
                 opaque immutable record
                          |
                          v
              CON-503 recognize, then interpret
                          |
                          v
          SPEC-004 CON-219 payload member set
```

**Decisions.**
[[PROTO-004-selfsame-ceremony-envelope-v1#ADR-501]] one AEAD, role-separated
single-use keys, constant nonce ·
[[PROTO-004-selfsame-ceremony-envelope-v1#ADR-502]] separate the sealed
envelope from the payload it carries ·
[[PROTO-004-selfsame-ceremony-envelope-v1#ADR-503]] make payloads RFC 8785
JSON objects whose member set the enclosing profile owns.

**Load-bearing.**
[[PROTO-004-selfsame-ceremony-envelope-v1#REQ-501]] one envelope serves every
ceremony record ·
[[PROTO-004-selfsame-ceremony-envelope-v1#REQ-502]] an envelope key seals
exactly one distinct plaintext ·
[[PROTO-004-selfsame-ceremony-envelope-v1#REQ-503]] the envelope binds the
pairing transcript ·
[[PROTO-004-selfsame-ceremony-envelope-v1#REQ-504]] recognition strictly
precedes interpretation.

**Controls digest.**

- The AEAD is RFC 8439 ChaCha20-Poly1305 and nothing else. There is no
  algorithm identifier on the wire and therefore no algorithm negotiation.
- Envelope keys come only from a `mailbox_secret_16` produced by
  [[PROTO-003-selfsame-pairing-v1#CON-408]] after mutual confirmation.
- The `offer` and `bundle` roles have distinct keys. Neither key is the
  PROTO-002 slot input, and neither slot value is a key.
- The nonce is 12 zero octets. This is sound **only** because a key seals one
  plaintext; REQ-502 is the invariant that makes it sound, not an optimisation.
- Additional authenticated data is the 5-octet header and the 32-octet
  PROTO-003 `binding_hash`, so a record cannot be replayed into another
  ceremony, role, application, profile, provider, route, or nameplate.
- A sealed record is 22 to 69,632 octets, matching
  [[PROTO-002-selfsame-rendezvous-v1#CON-304]]'s bound exactly.
- A recogniser parses the header, verifies the tag, and validates the complete
  RFC 8785 JSON payload before any semantic action.
- A client retains sealed bytes for retry. It never re-seals a changed
  plaintext under a used key; any change abandons the ceremony under
  [[PROTO-003-selfsame-pairing-v1#REQ-406]].

---

## Conformance and status

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in BCP 14 (RFC 2119 and RFC 8174) when, and only when, they appear in
all capitals.

This is a **Tier-1 draft** because it defines the confidentiality and
integrity boundary protecting every Selfsame device grant. Every `ADR-5##` is
PROPOSED. It is suitable for review, vector construction, and conformance-suite
design only. It does not authorize implementation or production deployment
until the gate in
[[PROTO-004-selfsame-ceremony-envelope-v1#Tier-1 Gate]] closes.

Artefacts in this document use the `5##` number band so they cannot collide
with SPEC-004's `2##`, PROTO-002's `3##`, or PROTO-003's `4##` band.

This document does not describe the legacy CBCL ceremony envelope referenced by
SPEC-001. Whether that envelope is migrated to this contract, and on what
schedule, is
[[PROTO-004-selfsame-ceremony-envelope-v1#OQ-501]].

## Context

A Selfsame authorization ceremony moves exactly two payloads between the
developer application and the Selfsame wallet:

1. an **offer**, written by the application, describing what it is asking to be
   authorized; and
2. a **bundle**, written by the wallet, carrying the issued device grant.

[[PROTO-003-selfsame-pairing-v1]] establishes a shared 128-bit
`mailbox_secret_16` and a 32-octet `binding_hash` covering the application,
profile, descriptor, provider, route, and nameplate.
[[PROTO-002-selfsame-rendezvous-v1#CON-302]] turns that secret into two mailbox
slot names and transports opaque octets between them.

Between those two contracts sits an undefined gap: what turns the secret into
an encryption key, what the ciphertext looks like, and how the receiver decides
a payload is well-formed. [[SPEC-004-application-scoped-identity]] assumes the
gap is filled — its threat model cites "the ceremony AEAD" and "the selected
AEAD", and [[SPEC-004-application-scoped-identity#CON-206]] step 4 reads the
issuer closure "from the encrypted bundle" — but no document selected an AEAD
or defined a record. This protocol is that missing layer.

The design constraint that shapes everything below is that the two endpoints
write independently, over an operator neither trusts, with no channel for
nonce coordination. Version 1 resolves this by making each key single-use
rather than by inventing a counter.

## Roles

| Role | Responsibility |
|---|---|
| Sealing endpoint | Derives its role key, seals exactly one plaintext, retains the sealed octets for retry. |
| Opening endpoint | Recognizes the header, verifies the tag, validates the payload, then interprets it. |
| Rendezvous operator | Stores and returns opaque octets under [[PROTO-002-selfsame-rendezvous-v1]]. It derives no key and recognizes no payload. |

## Scope

### In scope

- derivation of two role-separated envelope keys from a confirmed pairing key;
- the exact AEAD, nonce, additional authenticated data, and record grammar;
- the single-use-key invariant and its retry consequences;
- payload recognition rules and the canonical serialization every payload uses;
- the digest rule an enclosing profile uses to commit to part of a payload;
- size bounds consistent with the mailbox record bound;
- the closed error set; and
- black-box and cross-implementation tests.

### Out of scope

- payload member sets, which the enclosing profile owns — for version 1,
  [[SPEC-004-application-scoped-identity#CON-219]];
- mailbox slot derivation, HTTP transport, immutability, expiry, and retry,
  owned by [[PROTO-002-selfsame-rendezvous-v1]];
- pairing, `mailbox_secret_16` derivation, and `binding_hash` construction,
  owned by [[PROTO-003-selfsame-pairing-v1]];
- key derivation for identity, VC issuance, consent, holder proof, and
  `did:crdt` state, owned by [[SPEC-004-application-scoped-identity]];
- any secured-credential format carried *inside* a payload, which travels as
  opaque octets under
  [[SPEC-004-application-scoped-identity#REQ-211]]; and
- the legacy SPEC-001 CBCL envelope.

## Happy path

1. Both endpoints complete [[PROTO-003-selfsame-pairing-v1#CON-407]] mutual
   confirmation and derive the same `mailbox_secret_16` and `binding_hash`.
2. Each derives `K_offer` and `K_bundle` under
   [[PROTO-004-selfsame-ceremony-envelope-v1#CON-501]].
3. The application serializes its offer payload with RFC 8785, seals it under
   `K_offer` with [[PROTO-004-selfsame-ceremony-envelope-v1#CON-502]], retains
   the octets, and writes them to the offer slot.
4. The wallet reads the offer slot, recognizes the record under
   [[PROTO-004-selfsame-ceremony-envelope-v1#CON-503]], and only then
   interprets the payload.
5. The wallet seals its bundle payload under `K_bundle`, retains the octets,
   and writes them to the bundle slot.
6. The application reads, recognizes, and interprets the bundle, then applies
   its own acceptance predicate to the credential inside it.

Neither endpoint seals a second distinct plaintext under either key. A read
that fails recognition, a write that conflicts, or any changed input abandons
the ceremony; a retry starts from a new pairing ceremony with a new secret.

## Requirements

### REQ-501: One envelope serves every ceremony record

Every record a Selfsame authorization ceremony writes to a
[[PROTO-002-selfsame-rendezvous-v1]] slot SHALL be a sealed record conforming
to [[PROTO-004-selfsame-ceremony-envelope-v1#CON-502]].

There SHALL be exactly one envelope format, one AEAD, and one key schedule in
version 1. A client SHALL NOT accept a second record format, negotiate an
algorithm, or read an algorithm identifier from the record.

Rationale: the offer and the bundle differ only in their payload and their
role octet. A second envelope would double the transcript, replay, and
recognition surface for no protocol benefit.

Trace: [[PROTO-004-selfsame-ceremony-envelope-v1#TEST-502]],
[[PROTO-004-selfsame-ceremony-envelope-v1#TEST-506]]

### REQ-502: An envelope key seals exactly one distinct plaintext

For one ceremony, a conforming client SHALL seal at most one distinct plaintext
under `K_offer` and at most one distinct plaintext under `K_bundle`.

Re-serializing and re-sealing a byte-identical plaintext is permitted and is
deterministic. Sealing a plaintext that differs in any octet from one already
sealed under the same key SHALL abandon the ceremony under
[[PROTO-003-selfsame-pairing-v1#REQ-406]]. A client SHALL retain the sealed
octets it wrote and re-transmit exactly those octets on any transport retry
permitted by [[PROTO-002-selfsame-rendezvous-v1#CON-306]].

This requirement is what makes the constant nonce in
[[PROTO-004-selfsame-ceremony-envelope-v1#CON-502]] sound. Violating it repeats
a ChaCha20 keystream across two plaintexts and forges the Poly1305 key. It is a
correctness obligation, not a performance hint.

Trace: [[PROTO-004-selfsame-ceremony-envelope-v1#TEST-503]]

### REQ-503: The envelope binds the pairing transcript

The additional authenticated data of every sealed record SHALL include the
exact 32-octet `binding_hash` from
[[PROTO-003-selfsame-pairing-v1#CON-403]] and the record's role octet.

A record sealed for one ceremony, role, application, profile, provider
descriptor, route, or nameplate SHALL fail authentication when opened in the
context of another. A client SHALL NOT attempt payload recognition on a record
whose tag does not verify.

Trace: [[PROTO-004-selfsame-ceremony-envelope-v1#TEST-504]]

### REQ-504: Recognition strictly precedes interpretation

An opening endpoint SHALL complete, in order, header recognition, size
validation, AEAD tag verification, and complete payload validation against the
grammar in [[PROTO-004-selfsame-ceremony-envelope-v1#CON-503]] before it takes
any semantic action on payload content.

Semantic action includes deriving or selecting a key, signing, publishing
state, writing a mailbox record, displaying consent, creating a session, or
emitting a network request derived from payload content.

A client SHALL NOT extract a field with a regular expression, act on a partial
parse, or interpret a payload whose validation failed.

Trace: [[PROTO-004-selfsame-ceremony-envelope-v1#TEST-502]],
[[PROTO-004-selfsame-ceremony-envelope-v1#TEST-505]]

### REQ-505: The envelope carries no cleartext ceremony metadata

Outside the 5-octet header, a sealed record SHALL contain no cleartext octet.

The record SHALL NOT expose a ceremony identifier, application identifier,
account scope, DID, alias, device key, permission, provider identifier, offer
digest, timestamp, length-revealing padding marker, or error description to the
rendezvous operator. The header SHALL contain only the fixed magic, the version
octet, and the role octet.

An implementation MAY pad a payload to obscure its exact length. Padding, when
used, SHALL be inside the sealed plaintext and SHALL be defined by the
enclosing profile, never by an unauthenticated record field.

Trace: [[PROTO-004-selfsame-ceremony-envelope-v1#TEST-505]]

## Non-functional requirements

### NFR-501: Bounded parsing and allocation

A recogniser SHALL reject a record shorter than 22 or longer than 69,632
octets before allocating a payload buffer, and SHALL reject a decrypted payload
that is not valid UTF-8 or exceeds the enclosing profile's declared payload
bound.

Recognition SHALL allocate no more than a constant multiple of the record
length and SHALL terminate on every input.

### NFR-502: Algorithm confinement

Version 1 SHALL use HKDF-SHA-256 for the key schedule and RFC 8439
ChaCha20-Poly1305 for the AEAD, and no others.

Algorithm agility SHALL occur only by a new version octet and an explicit
migration, never by accepting an algorithm named by untrusted input. A record
whose version octet is unrecognized SHALL be rejected, never negotiated
downward.

### NFR-503: Deterministic portability

At least two independent implementations SHALL reproduce every normative key
schedule, additional-authenticated-data, sealed record, and rejection vector in
this document byte-for-byte before the Tier-1 gate closes.

## Architecture decisions

### ADR-501: One AEAD, role-separated single-use keys, constant nonce

**Status:** PROPOSED.

Version 1 derives one key per role and fixes the nonce at twelve zero octets.

The two endpoints write independently through an untrusted operator and share
no counter, no clock, and no channel outside the mailbox itself. The three
available options were:

- **a random nonce per record** — requires 24 octets to be safe by birthday
  bound, which means XChaCha20-Poly1305, an IRTF draft rather than an RFC, and
  it adds a wire field an attacker can grind;
- **a counter nonce** — requires state shared between two processes on two
  devices, exactly what the ceremony lacks; and
- **a single-use key with a constant nonce** — requires no wire field and no
  shared state, and reduces to one auditable invariant.

Version 1 takes the third. The invariant is enforceable because
[[PROTO-002-selfsame-rendezvous-v1#CON-304]] already makes a slot immutable on
first write and [[PROTO-003-selfsame-pairing-v1#REQ-406]] already burns a
ceremony on any change. The envelope therefore inherits single-use semantics
from contracts that exist for independent reasons, rather than asserting a new
one.

ChaCha20-Poly1305 is chosen over AES-GCM because Selfsame targets mobile and
embedded clients without a guaranteed AES instruction path, and because a
constant nonce with AES-GCM is a sharper foot-gun in the surrounding
literature. RFC 8439 is Standards Track and universally implemented.

Rejected:

- an algorithm identifier on the wire — creates negotiation and downgrade
  surface for a two-party protocol with one suite;
- reusing `mailbox_secret_16` directly as an AEAD key — it is 128 bits, it is
  already the PROTO-002 slot input, and a slot name is public; and
- one key for both roles — a shared key with a constant nonce would repeat a
  keystream across the offer and the bundle immediately.

### ADR-502: Separate the sealed envelope from the payload it carries

**Status:** PROPOSED.

This document defines confidentiality, integrity, transcript binding, and
recognition. It does not define what the offer or bundle contains. The
enclosing profile owns the member set.

This is the same split PROTO-002 already makes between a mailbox slot and the
octets inside it, applied one layer up. It keeps a payload change — a new
field, a new permission shape — out of the cryptographic contract, so an
amendment to [[SPEC-004-application-scoped-identity#CON-219]] does not require
renewed cryptography sign-off, while an amendment here does.

Rejected: defining offer and bundle members here. That would put
application-account concerns in a transport document, contradict Constitutional
Principle 15 on capability placement, and force every profile change through a
Tier-1 cryptographic review.

### ADR-503: Payloads are RFC 8785 JSON objects with a profile-owned member set

**Status:** PROPOSED.

Every payload is a JSON object serialized with the RFC 8785 JSON
Canonicalization Scheme, and every member is declared by the enclosing profile.

Canonical serialization is required for two reasons. First, it lets a profile
commit to a payload, or to a named subset of one, by digest — the mechanism
[[SPEC-004-application-scoped-identity#CON-219]] uses to break the ordering
cycle between a backend-signed enrollment statement and the offer that carries
it. Second, it removes the whitespace and member-order freedom that would
otherwise let a relay perturb bytes without changing meaning.

The member set is closed: an unknown member is a rejection, not an extension
point. Version 1 has no forward-compatibility affordance inside a payload; a
new field is a new profile version.

Rejected: CBOR, protobuf, and a length-prefixed binary struct. Each is more
compact, but the ecosystem around this ceremony — JWS grants, JCS profile
digests, JRD account records — is already canonical JSON, and a second
canonicalization discipline would be a second class of parser-differential bug.

## Contracts

### CON-501: Envelope key schedule

Inputs:

```text
mailbox_secret_16 = the exactly 16 octets produced by
                    [[PROTO-003-selfsame-pairing-v1#CON-408]] after mutual
                    confirmation
binding_hash      = the exactly 32 octets defined by
                    [[PROTO-003-selfsame-pairing-v1#CON-403]]
```

An endpoint SHALL NOT derive an envelope key from any other value. In
particular it SHALL NOT derive one from a pairing word, `wib`, the human code,
a nameplate, a role token, a PROTO-002 slot name, or the unconfirmed SPAKE2 key
`K`.

Derivation:

```text
K_offer  = HKDF-SHA256(
  ikm  = mailbox_secret_16,
  salt = binding_hash,
  info = ASCII("selfsame-envelope-v1/offer"),
  L    = 32)

K_bundle = HKDF-SHA256(
  ikm  = mailbox_secret_16,
  salt = binding_hash,
  info = ASCII("selfsame-envelope-v1/bundle"),
  L    = 32)
```

`HKDF-SHA256` is RFC 5869 with SHA-256 as specified by RFC 6234, applying both
the extract and expand stages.

Both keys are derived once per ceremony by both endpoints. `K_offer` and
`K_bundle` SHALL be distinct in every ceremony; an implementation that finds
them equal SHALL abort rather than proceed.

Each key SHALL be zeroized when the platform permits, at the earlier of
ceremony completion and ceremony abandonment under
[[PROTO-003-selfsame-pairing-v1#CON-407]].

Both keys are independent of the PROTO-002 slot derivation, which consumes the
same `mailbox_secret_16` through BLAKE3 under
[[PROTO-002-selfsame-rendezvous-v1#CON-302]]. Knowledge of a slot name
therefore yields no information about either key, and disclosure of an envelope
key yields no additional mailbox access beyond the slot the operator already
serves publicly.

### CON-502: Sealed record

Definitions:

```text
MAGIC      = ASCII("SSE1")                        ; 4 octets
VERSION    = 0x01                                 ; 1 octet, included in MAGIC
role_octet = 0x01 for the offer, 0x02 for the bundle
header     = MAGIC || role_octet                  ; exactly 5 octets
nonce_12   = twelve 0x00 octets
aad        = header || binding_hash               ; exactly 37 octets
```

The version is carried by the fourth octet of `MAGIC`, which is the ASCII digit
`1`. A record whose first four octets are not exactly `SSE1` is rejected; there
is no separate version field to parse.

Sealing:

```text
key         = K_offer  when role_octet is 0x01
              K_bundle when role_octet is 0x02

ct_and_tag  = ChaCha20-Poly1305-Seal(
                key   = key,
                nonce = nonce_12,
                aad   = aad,
                plaintext = RFC8785(payload_object) as UTF-8)

sealed_record = header || ct_and_tag
```

`ChaCha20-Poly1305-Seal` is the AEAD construction in RFC 8439 §2.8, whose
output is the ciphertext followed by the 16-octet Poly1305 tag.

The wire grammar is:

```abnf
OCTET         = %x00-FF
magic         = %x53 %x53 %x45 %x31          ; "SSE1"
role          = %x01 / %x02
header        = magic role
ct-and-tag    = 17*69627OCTET                ; >= 1 octet plaintext + 16 tag
sealed-record = header ct-and-tag
```

A sealed record is therefore 22 to 69,632 octets inclusive, and the plaintext
it carries is 1 to 69,611 octets inclusive. The upper bound is exactly the
[[PROTO-002-selfsame-rendezvous-v1#CON-304]] record bound of 69,632 octets less
the 5-octet header and the 16-octet tag.

Opening:

```text
payload_octets = ChaCha20-Poly1305-Open(
                   key   = key,
                   nonce = nonce_12,
                   aad   = aad,
                   ciphertext = ct_and_tag)
```

Tag verification SHALL be constant-time. A failed open SHALL be reported as
exactly `EnvelopeAuthFailed` under
[[PROTO-004-selfsame-ceremony-envelope-v1#CON-504]], with no distinction
between a wrong key, a wrong `binding_hash`, a wrong role, a truncated record,
and a mutated ciphertext.

An endpoint SHALL open a record only with the key matching the role it
expects: the wallet opens role `0x01` and seals role `0x02`; the application
seals role `0x01` and opens role `0x02`. An endpoint SHALL NOT attempt the
opposite role's key on failure.

### CON-503: Payload recognition

The decrypted octets SHALL be recognized in this order, and a failure at any
step SHALL stop processing:

1. require valid UTF-8 with no byte-order mark;
2. parse as JSON with no duplicate member names, no trailing content, and a
   nesting depth within the enclosing profile's declared bound;
3. require the top-level value to be an object;
4. require the member set to equal exactly the set the enclosing profile
   declares for that role — no unknown member, no missing required member;
5. validate every member value against the profile's declared grammar for it;
   and
6. re-serialize the recognized object with RFC 8785 and require byte-for-byte
   equality with the decrypted octets.

Step 6 is the canonicality check. It makes the payload's octets a function of
its meaning, which is what lets a profile commit to a payload by digest. An
implementation SHALL NOT skip it on the grounds that the AEAD already
authenticated the octets; the AEAD authenticates that the octets came from the
peer, not that the peer serialized them canonically.

The output of recognition is a typed value. Downstream code SHALL consume that
typed value and SHALL NOT re-read the raw octets.

**Profile digest rule.** When an enclosing profile commits to a payload, or to
a named subset of one, by digest, that digest SHALL be:

```text
digest = BASE64URL-NOPAD(SHA-256(RFC8785(committed_object)))
```

`BASE64URL-NOPAD` is RFC 4648 §5 without `=` padding. The `committed_object`
SHALL be a JSON object the profile names explicitly. When the committed object
is a proper subset of a payload, the profile SHALL enumerate the excluded
members, and those members SHALL NOT themselves be inputs to the digest — a
profile that commits to a payload from inside that same payload is a
specification defect, not an implementation choice.

### CON-504: Error model

The closed error set is:

| Error | Trigger |
|---|---|
| `EnvelopeMalformed` | Header, role octet, or record length fails the CON-502 grammar. |
| `EnvelopeAuthFailed` | The AEAD tag does not verify, for any reason. |
| `PayloadMalformed` | UTF-8, JSON, member set, member grammar, or canonicality check fails. |
| `PayloadTooLarge` | The plaintext exceeds the enclosing profile's declared bound. |
| `EnvelopeKeyUnavailable` | Mutual PROTO-003 confirmation has not succeeded. |
| `EnvelopeReseal` | A second distinct plaintext was offered for a used key. |

Every error SHALL leave identity, key, grant, DID, provider, and session state
unchanged. `EnvelopeReseal` SHALL additionally abandon the ceremony under
[[PROTO-003-selfsame-pairing-v1#REQ-406]].

Externally visible failures SHOULD collapse to `EnvelopeMalformed`,
`EnvelopeAuthFailed`, or `PayloadMalformed` so that a peer or operator gains no
oracle distinguishing a key error from a content error. Diagnostic detail MAY
be logged locally and SHALL NOT include a key, plaintext, or payload member
value.

Implements: REQ-501, REQ-502, REQ-503, REQ-504, REQ-505.

Verified by: TEST-502, TEST-503, TEST-504, TEST-505.

## Test specifications

### TEST-501: Key schedule vectors

**Validates:** REQ-501, NFR-502, NFR-503, CON-501.

For each normative `(mailbox_secret_16, binding_hash)` vector, reproduce
`K_offer` and `K_bundle` byte-for-byte in two independent implementations.
Require the two keys to differ in every vector. Require a one-octet change in
either input to change both keys.

Confirm that the PROTO-002 slot values derived from the same
`mailbox_secret_16` share no octet-level relationship with either key that a
test can distinguish from independent random values.

Reject derivation attempts whose `mailbox_secret_16` is not exactly 16 octets
or whose `binding_hash` is not exactly 32 octets.

### TEST-502: Record grammar and recognition order

**Validates:** REQ-501, REQ-504, CON-502, CON-503.

Accept the normative sealed-record vectors for both roles. Reject: wrong magic,
a fifth-octet role other than `0x01`/`0x02`, a 21-octet record, a 69,633-octet
record, an empty ciphertext, and a record with a trailing octet.

Prove the ordering of REQ-504 by instrumenting a client so that any signature,
state publication, mailbox write, consent display, session creation, or
outbound request is recorded. For every rejection vector, require zero recorded
actions.

Reject payloads that are invalid UTF-8, carry a byte-order mark, contain
duplicate member names, exceed the declared nesting bound, are not a top-level
object, contain an unknown member, omit a required member, or fail the
re-serialization equality check in CON-503 step 6. The canonicality corpus
SHALL include a payload that is valid JSON with correct members but non-RFC
8785 member order, and require its rejection.

### TEST-503: Single-use key and retry determinism

**Validates:** REQ-502, ADR-501, CON-504.

Seal one payload, then re-seal byte-identical plaintext under the same key and
require an identical sealed record. Write it twice to the same PROTO-002 slot
and require `201` then `204` under
[[PROTO-002-selfsame-rendezvous-v1#CON-304]].

Offer a plaintext differing in exactly one octet under a used key and require
`EnvelopeReseal`, ceremony abandonment, no mailbox write, and no further use of
either key.

Instrument a full ceremony including every transport retry permitted by
[[PROTO-002-selfsame-rendezvous-v1#CON-306]] and assert that at most one
distinct ciphertext exists per key for the ceremony's lifetime. Repeat across a
provider failover and require a new ceremony, new secret, and new keys rather
than a reused key.

### TEST-504: Transcript binding and cross-ceremony splice

**Validates:** REQ-503, CON-501, CON-502.

Construct two concurrent ceremonies, C1 and C2, that differ in exactly one of:
application ID, profile digest, provider ID, descriptor digest, route,
nameplate, or pairing words. Seal a record in each.

Present C1's record to C2's opening endpoint and the reverse, in both roles and
both directions. Require `EnvelopeAuthFailed` in every case, before any payload
recognition.

Mutate the role octet of a valid record and require `EnvelopeAuthFailed`, not
a successful open under the other role's key. Mutate one octet of the
ciphertext, one octet of the tag, and one octet of the `binding_hash` used as
additional authenticated data; require rejection in each case and require the
three failures to be indistinguishable from outside.

### TEST-505: Metadata leakage and bounded parsing

**Validates:** REQ-505, NFR-501, CON-504.

Capture every octet a conforming ceremony sends to the rendezvous operator and
require that, outside the 5-octet header, no octet matches any ceremony
identifier, application identifier, account scope, DID, alias, device public
key, permission URI, provider identifier, offer digest, or timestamp present in
either payload.

Fuzz the recogniser with at least 10^6 random and structurally mutated records,
including records of every length from 0 to 69,633. Require no panic, no
unbounded allocation, no non-termination, and only closed CON-504 errors.

Confirm that an oversized payload is rejected before buffer allocation and that
error text carries no key, plaintext, or member value.

### TEST-506: Cross-implementation interoperability

**Validates:** REQ-501, NFR-503, CON-501 through CON-504.

Run a complete ceremony between two independently written client
implementations, in both role assignments, against two independently operated
PROTO-002 providers. Require each implementation to open the other's records
and to produce byte-identical sealed records from identical inputs.

Repeat with a profile that exercises the maximum permitted payload size and
with one that exercises the minimum. Block every Anuna domain throughout and
require identical results.

## Security and threat model

### Protected assets

1. `mailbox_secret_16`, `binding_hash`, `K_offer`, and `K_bundle`;
2. the confidentiality of the offer and bundle plaintexts, including the
   account scope, device key, permission set, enrollment evidence, and issued
   grant they carry; and
3. the integrity of the association between a record and the exact ceremony,
   role, and endpoints that produced it.

### Adversary capabilities

The adversary may operate the rendezvous, the pairing relay, and the network;
read, retain, replay, reorder, truncate, and mutate every stored record;
enumerate slot names; run concurrent ceremonies and splice records between
them; and retain all expired operator storage.

It may not break the assumed primitives, read `mailbox_secret_16`, compromise
an endpoint process, or obtain the pairing words before ceremony expiry.

### Security properties

- **Confidentiality:** the operator holds only ciphertext under a key derived
  from a confirmed PAKE secret it never sees.
- **Integrity and authenticity:** any mutation of header, ciphertext, tag, or
  bound transcript fails the tag check before recognition.
- **Ceremony and role separation:** the additional authenticated data binds
  `binding_hash` and the role octet, so a record is meaningless outside the
  exact ceremony and direction that produced it.
- **No keystream reuse:** REQ-502 gives each key exactly one plaintext, and
  PROTO-002 immutability plus PROTO-003 burn semantics enforce it from two
  independent directions.
- **No negotiation surface:** one suite, no wire algorithm identifier, and an
  unrecognized magic is a rejection rather than a downgrade.
- **No parser oracle:** all failures collapse to three externally visible
  errors.

### Residual risks

- Record length is visible to the operator and correlates with payload
  content — notably whether a bundle carries an inline issuer closure. Padding
  is permitted but not required in version 1, and the profile that needs it
  must define it.
- Timing between the offer write and the bundle write reveals how long the
  person spent at the consent screen. The envelope cannot conceal this.
- A constant nonce is safe only under REQ-502. An implementation that persists
  and later reuses an envelope key across ceremonies breaks the construction
  catastrophically and silently. TEST-503 is the only mechanical defence, and
  it is a conformance test rather than a protocol-enforced impossibility.
- Compromise of either endpoint process discloses that endpoint's keys and both
  plaintexts. The envelope is a transport control and asserts nothing about
  application authenticity; the controls in
  [[SPEC-004-application-scoped-identity#CON-214]] and
  [[SPEC-004-application-scoped-identity#CON-206]] remain independently
  required.

## Tier-1 Gate

No implementation task may be marked ready until all boxes are checked:

- [ ] A fresh-context cross-model adversarial review covers the key schedule,
      domain separation from PROTO-002 slot derivation, the constant-nonce
      argument and its REQ-502 dependency, additional-authenticated-data
      coverage, the recognition order, the canonicality check, and the error
      collapse.
- [ ] A second review verifies the revised document and closes every blocking
      finding from the first.
- [ ] A human cryptography reviewer approves CON-501 and CON-502, and
      explicitly approves or rejects the constant nonce in favour of an
      extended-nonce construction.
- [ ] Normative vectors for TEST-501, TEST-502, and TEST-504 are published and
      reproduced byte-for-byte by two independent implementations.
- [ ] The recogniser is fuzzed to the TEST-505 volume with no finding.
- [ ] [[SPEC-004-application-scoped-identity#CON-219]] declares a payload
      member set, nesting bound, and payload size bound for both roles.
- [ ] PROTO-002 and PROTO-003 pass their own Tier-1 gates.
- [ ] OQ-501 and OQ-502 are resolved normatively or explicitly accepted by the
      human owner with bounded consequences.
- [ ] Human security sign-off records an approval version and commit.

## Open questions

### OQ-501: Does the legacy SPEC-001 envelope migrate? — blocking for existing users

The CBCL ceremony predating this document has its own record format and key
derivation, evidenced by the `channel_key_hex` entries in
`test-vectors/spec-001-v1.json`. SPEC-001 is not present in this vault, so this
document neither describes nor amends it.

The decision needs the legacy format on record, a statement of whether a
version-1 client must interoperate with it, and — if so — how a recogniser
distinguishes the two without creating the downgrade surface REQ-501 exists to
prevent. Until then, `SSE1` is the only record a conforming version-1 client
accepts.

Owner: SPEC-001 maintainer + HOC.

### OQ-502: Is padding required, and who defines it? — blocking for the privacy review

REQ-505 permits padding inside the sealed plaintext and requires the enclosing
profile to define it, but version 1 mandates none. A bundle that inlines an
issuer closure is visibly larger than one that does not, which leaks a
verifier-relevant fact to the operator.

The decision must fix whether padding is REQUIRED, what granularity is
sufficient against an operator observing many ceremonies, and whether the cost
against the 69,632-octet record bound is acceptable.

Owner: application-profile working group + privacy reviewer.

## Traceability

| Outcome | Requirements | Decisions/contracts | Tests |
|---|---|---|---|
| One sealed record format for every ceremony write | REQ-501 | ADR-501, ADR-502, CON-502 | TEST-502, TEST-506 |
| No keystream reuse without a shared counter | REQ-502 | ADR-501, CON-501, CON-502, CON-504 | TEST-503 |
| A record is meaningless outside its ceremony and role | REQ-503 | CON-501, CON-502 | TEST-504 |
| Full recognition before any semantic action | REQ-504 | CON-503, CON-504 | TEST-502, TEST-505 |
| The operator learns nothing but length and timing | REQ-505 | CON-502, CON-503 | TEST-505 |
| A profile can commit to a payload by digest | REQ-504 | ADR-503, CON-503 | TEST-502 |
| Independent implementations interoperate | REQ-501 | CON-501–504 | TEST-501, TEST-506 |

## Amendment Channels

This protocol may be amended only by a versioned change to this file that
identifies affected REQ/NFR/ADR/CON/TEST artefacts, updates traceability and the
changelog, records evidence, receives Tier-1 review, and is approved by the
human owner.

Any change to the key schedule, labels, AEAD, nonce, additional authenticated
data, header, magic, role encoding, size bounds, recognition order, canonical
serialization, digest rule, or error set is a Tier-1 normative amendment
requiring new vectors and renewed human cryptography sign-off.

## Normative and informative sources

Normative internal specifications:

- [[PROTO-003-selfsame-pairing-v1]] supplies `mailbox_secret_16` and
  `binding_hash` after mutual confirmation.
- [[PROTO-002-selfsame-rendezvous-v1]] transports the sealed record and
  supplies its immutability, expiry, and size bound.
- [[SPEC-004-application-scoped-identity]] declares the version-1 payload
  member sets in
  [[SPEC-004-application-scoped-identity#CON-219]].

Normative external specifications:

- IETF, [RFC 8439 — ChaCha20 and Poly1305 for IETF
  Protocols](https://datatracker.ietf.org/doc/html/rfc8439), especially the
  §2.8 AEAD construction, nonce handling, and tag verification.
- IETF, [RFC 5869 — HKDF](https://datatracker.ietf.org/doc/html/rfc5869).
- IETF, RFC 4648 §5, RFC 5234, RFC 6234, and
  [RFC 8785 — JSON Canonicalization
  Scheme](https://datatracker.ietf.org/doc/html/rfc8785).

Standards constraints that are easy to miss:

- RFC 8439 §4 states plainly that a key and nonce pair MUST NOT be reused for
  two distinct plaintexts. Version 1 satisfies this by never reusing the key,
  not by varying the nonce; REQ-502 is therefore a cryptographic obligation
  rather than a hygiene preference.
- RFC 8439 §2.8 defines the AEAD output as ciphertext followed by tag. The
  16-octet tag is not a separate wire field in this document's grammar.
- RFC 8785 canonicalization is defined for a subset of JSON. Payload grammars
  in an enclosing profile must stay inside that subset — in particular, no
  number that JCS cannot round-trip.
- A JCS re-serialization check is not implied by AEAD authentication. The tag
  proves provenance; only step 6 of CON-503 proves canonicality, and only
  canonicality makes a payload digest well-defined.
- BLAKE3 slot derivation in PROTO-002 and HKDF-SHA-256 key derivation here
  consume the same secret. They are separate functions with separate outputs;
  neither is a substitute for the other, and a slot name is public while a key
  is not.

## Changelog

- **0.1.0 — 2026-07-31 — draft, normative.** First protocol draft, created to
  close a gap in which [[PROTO-002-selfsame-rendezvous-v1]] declared the
  offer/grant/AEAD contract out of scope while
  [[PROTO-003-selfsame-pairing-v1]] delegated that same contract to PROTO-002,
  leaving the layer that carries every Selfsame device grant unspecified.
  Defines role-separated envelope keys from the confirmed pairing secret, an
  RFC 8439 ChaCha20-Poly1305 sealed record with a constant nonce justified by a
  single-use-key invariant, transcript-binding additional authenticated data, a
  strict recognition order with an RFC 8785 canonicality check, the payload
  digest rule used by [[SPEC-004-application-scoped-identity#CON-219]], size
  bounds matching the PROTO-002 record bound, and a closed error set. Leaves
  the Tier-1 gate open and records the SPEC-001 migration and payload padding
  as blocking open questions.
