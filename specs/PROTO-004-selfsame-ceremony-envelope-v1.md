---
id: PROTO-004
title: Selfsame Ceremony Envelope v1 — the sealed offer and grant record
status: draft
tier: 1
version: 0.3.0
audience: application developer, SDK implementer, wallet implementer, security reviewer
author: Anuna Research (drafted with Claude, 2026-07-31)
last-updated: 2026-08-17
owner-repo: selfsame
affects-repos: selfsame, anuna-ssi, adopting applications, independent client implementations
review-gate: not-approved — Tier-1; independent AEAD and key-schedule vectors, cross-model adversarial review, and human cryptography sign-off are outstanding
depends-on: SPEC-004; SPEC-007 for the Selfsame credential-pairing disposition; PROTO-002 and PROTO-003 for non-cutover uses; RFC 2119; RFC 4648; RFC 5234; RFC 5869; RFC 6234; RFC 8174; RFC 8439; RFC 8785
---

# PROTO-004 — Selfsame Ceremony Envelope v1

## SPEC-007 credential-pairing disposition

Selfsame credential pairing no longer uses this envelope protocol.
[[SPEC-007-cbcl-pairing-cutover]] carries recognised CON-219 bytes through the
pinned cbcl secure channel.
These artifacts remain draft authority for non-cutover consumers and historical comparison:

- REQ-501 through REQ-505 and NFR-501 through NFR-503;
- ADR-501 through ADR-504;
- CON-501 through CON-504; and
- TEST-501 through TEST-506.

CON-219 member sets remain owned by SPEC-004.
No AEAD, recognition, size, privacy, or human-review gate is weakened.
Vectors: no protocol octet changes; existing TEST-501 through TEST-506 vectors remain intact.
Evidence: [[SPEC-007-cbcl-pairing-cutover#TEST-819]].
Owner: Selfsame human protocol owner.
Approved for the Selfsame development cutover: 2026-08-17.
Production approval: not granted.

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
SPEC-001, and version 1 does not interoperate with it. No production ceremony
uses it, so `SSE1` is the only record a conforming client accepts and no
compatibility branch exists to carry. See
[[PROTO-004-selfsame-ceremony-envelope-v1#OQ-501]], withdrawn.

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

**Record length is not metadata, because there is only one length.** Every
sealed record SHALL be exactly 69,632 octets, achieved by the fixed-length
frame in [[PROTO-004-selfsame-ceremony-envelope-v1#CON-502]]. Padding is
REQUIRED, is inside the sealed plaintext, is zero octets, and is verified on
opening. An implementation SHALL NOT emit a short record, negotiate a length,
or make padding conditional on payload content.

This closes the last cleartext channel the envelope controls. Payload length
otherwise correlates with whether a bundle inlines an issuer closure, and a
closure's size is a **stable per-account quantity** that grows with a DID's
delta history — so length was not merely a one-bit leak about verifier
behaviour but a fingerprint that could link ceremonies which 128-bit addressing
had deliberately made unlinkable.

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

### ADR-504: One record length, not a ladder of buckets

**Status:** PROPOSED.

Every sealed record is padded to exactly 69,632 octets. This closes
[[PROTO-004-selfsame-ceremony-envelope-v1#OQ-502]], which asked whether padding
is required, at what granularity, and at what cost.

The leak is worse than "a bundle with an inline closure is bigger." A closure's
size tracks a DID's delta history, so it is roughly stable for one account and
grows slowly over that account's life. An operator observing many ceremonies
therefore sees a per-account length fingerprint — and length was the only
channel left that could relink ceremonies which
[[PROTO-003-selfsame-pairing-v1#CON-409]]'s 128-bit addressing had already
separated. Everything else the operator sees is opaque and uncorrelated by
construction; leaving length variable would have made the addressing work
pointless for exactly the users with the longest histories.

Granularity is the interesting part of the question, and the answer is that any
bucketing scheme fails in the same direction. Bucketing to, say, 8 KiB would
hide the ordinary range — a conforming grant is one to two kilobytes and the
closure remainder is under four — at roughly an eighth of the bandwidth. But
the accounts that overflow a bucket are the ones with the longest delta
histories, which is to say the heaviest, longest-standing users. A bucketed
scheme protects the median and fingerprints the tail, and the tail is precisely
who wants protecting. A single length has no tail.

It is also the only option with nothing to tune. There is no bucket boundary to
argue about at review, no profile-specific parameter, no negotiation, and no
second code path — which matches how
[[PROTO-004-selfsame-ceremony-envelope-v1#REQ-501]] treats the format
generally. Fixed-length records additionally make
[[PROTO-004-selfsame-ceremony-envelope-v1#NFR-501]]'s bounded allocation
trivial: the buffer size is a constant.

The cost is stated rather than minimised. A ceremony writes two records, so it
moves about 139 KiB instead of about 5 KiB — roughly a 28-fold increase, and
about eleven seconds on a poor mobile link, against a 600-second ceremony
expiry. Absolute cost is what matters here, not the ratio: a device-linking
ceremony happens a handful of times in a person's life, and 139 KiB is one
medium photograph. Operators are already required to accept 69,632-octet
records under [[PROTO-002-selfsame-rendezvous-v1#CON-304]], so no operator must
provision anything new; they lose the option of provisioning for less.

Rejected:

- **no padding, as in version 0.1.0** — leaves a per-account fingerprint in the
  one place the envelope fully controls;
- **bucketed lengths** — protects the median and exposes the tail, as above;
- **a `pad` member in each payload** — would put padding inside closed member
  sets owned by another document, inside their RFC 8785 canonicalization, and
  inside the digest rules that commit to them; the frame keeps padding entirely
  within this protocol's boundary;
- **padding with random rather than zero octets** — indistinguishable to an
  observer, since both are encrypted, but it breaks the byte-identity
  [[PROTO-004-selfsame-ceremony-envelope-v1#TEST-506]] requires and opens a
  covert channel between endpoints; and
- **leaving it to the enclosing profile**, which version 0.1.0 did — a privacy
  control that each profile may decline is one that fails wherever it is most
  needed.

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

The plaintext is a **fixed-length frame**, not the bare JSON:

```text
json        = RFC8785(payload_object) as UTF-8     ; 1..69,607 octets
pad_len     = 69,607 - len(json)

plaintext   = U32BE(len(json)) || json || (0x00 * pad_len)
            ; exactly 69,611 octets, for every record, always
```

`U32BE(n)` is the four-octet unsigned big-endian encoding of `n`. Padding
octets SHALL be `0x00`; no other value is permitted, so identical inputs
produce identical plaintexts and the byte-identity
[[PROTO-004-selfsame-ceremony-envelope-v1#TEST-506]] requires still holds.

The frame lives inside the sealed plaintext, so the length prefix is never
visible to an operator and is not the "length-revealing padding marker"
[[PROTO-004-selfsame-ceremony-envelope-v1#REQ-505]] forbids. It exists because
[[PROTO-004-selfsame-ceremony-envelope-v1#CON-503]] requires the payload to
re-serialize byte-for-byte with no trailing content, which bare trailing
padding would break, and because the payload member sets are closed languages
owned by the enclosing profile — a `pad` member would have to be added to each
of them and would then fall inside their canonicalization and digest rules.

Sealing:

```text
key         = K_offer  when role_octet is 0x01
              K_bundle when role_octet is 0x02

ct_and_tag  = ChaCha20-Poly1305-Seal(
                key   = key,
                nonce = nonce_12,
                aad   = aad,
                plaintext = plaintext)

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
ct-and-tag    = 69627OCTET                   ; 69,611 plaintext + 16 tag
sealed-record = header ct-and-tag
```

**Every sealed record is exactly 69,632 octets**, which is exactly the
[[PROTO-002-selfsame-rendezvous-v1#CON-304]] record bound, and the JSON it
carries is 1 to 69,607 octets. There is no valid record of any other length: a
record shorter or longer than 69,632 octets is rejected before any AEAD
operation. [[PROTO-004-selfsame-ceremony-envelope-v1#ADR-504]] records why the
length is fixed rather than bucketed.

Opening:

```text
require len(sealed_record) == 69,632           ; before allocating or opening

plaintext = ChaCha20-Poly1305-Open(
              key   = key,
              nonce = nonce_12,
              aad   = aad,
              ciphertext = ct_and_tag)

n = U32BE-decode(plaintext[0..4])
require 1 <= n <= 69,607
require every octet of plaintext[4+n .. 69,611] == 0x00

payload_octets = plaintext[4 .. 4+n]
```

The padding check is REQUIRED, not advisory. Unverified padding is a covert
channel between the endpoints and a source of implementation divergence that
would break byte-identity. A frame whose length prefix is out of range, or
whose padding is non-zero, SHALL be reported as exactly `EnvelopeMalformed`
under [[PROTO-004-selfsame-ceremony-envelope-v1#CON-504]] — the frame is
authenticated by the tag at that point, so distinguishing it from an auth
failure discloses nothing to an attacker who did not already hold the key.

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

The `payload_octets` slice that [[PROTO-004-selfsame-ceremony-envelope-v1#CON-502]]
extracts from the frame — the JSON alone, with the length prefix and padding
already removed and the padding already verified — SHALL be recognized in this
order, and a failure at any step SHALL stop processing:

1. require valid UTF-8 with no byte-order mark;
2. parse as JSON with no duplicate member names, no trailing content, and a
   nesting depth within the enclosing profile's declared bound;
3. require the top-level value to be an object;
4. require the member set to equal exactly the set the enclosing profile
   declares for that role — no unknown member, no missing required member;
5. validate every member value against the profile's declared grammar for it;
   and
6. re-serialize the recognized object with RFC 8785 and require byte-for-byte
   equality with `payload_octets`.

Step 6 is the canonicality check. It makes the payload's octets a function of
its meaning, which is what lets a profile commit to a payload by digest. An
implementation SHALL NOT skip it on the grounds that the AEAD already
authenticated the octets; the AEAD authenticates that the octets came from the
peer, not that the peer serialized them canonically.

Canonicality is checked against the JSON slice and never against the framed
plaintext, since the padding is not part of the payload's meaning. Padding
integrity is CON-502's business and is already settled before step 1 runs.

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
| `EnvelopeMalformed` | Header, role octet, or record length fails the CON-502 grammar, or the opened frame has an out-of-range length prefix or non-zero padding. |
| `EnvelopeAuthFailed` | The AEAD tag does not verify, for any reason. |
| `PayloadMalformed` | UTF-8, JSON, member set, member grammar, or canonicality check fails. |
| `PayloadTooLarge` | The JSON exceeds the enclosing profile's declared bound. |
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

**Fixed length.** Require every sealed record a conforming ceremony emits to be
exactly 69,632 octets, for both roles, across payloads spanning the full JSON
range from 1 to 69,607 octets — including a minimal bundle, a bundle with an
inline issuer closure, and one without. Require the emitted records to be
indistinguishable by length, and require two ceremonies whose bundles differ in
closure size by any amount to produce records of identical size.

Reject a record of any other length before any AEAD operation, and assert the
rejection happens before buffer allocation. Open a frame whose length prefix is
0, whose prefix exceeds 69,607, and whose padding contains a single non-zero
octet; require `EnvelopeMalformed` for each, and require the padding check to
run on every open rather than only when a prefix looks suspicious.

Seal identical inputs twice and require byte-identical records, so padding
cannot become a covert channel or a source of divergence.

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

- Timing between the offer write and the bundle write reveals how long the
  person spent at the consent screen. The envelope cannot conceal this, and it
  is now the **only** remaining envelope-layer channel: with every record fixed
  at 69,632 octets under CON-502, length carries nothing. Concealing timing
  would require cover traffic or delay, both of which fight the 600-second
  ceremony expiry and neither of which this protocol attempts.
- Fixed-length records cost roughly 139 KiB per ceremony against roughly 5 KiB
  unpadded. This is a deliberate trade recorded in ADR-504, not an oversight;
  an operator already had to accept records of this size.
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
- [ ] OQ-501's withdrawal is re-confirmed at sign-off: no production SPEC-001
      ceremony exists, so no legacy envelope compatibility is required.
- [ ] A privacy reviewer approves ADR-504 — specifically that one fixed record
      length is the right granularity, and that roughly 139 KiB per ceremony is
      an acceptable price for removing the per-account length fingerprint.
- [ ] Two independently operated PROTO-002 providers accept sustained
      69,632-octet records at both roles without rate-limiting a conforming
      ceremony, confirming that the fixed length costs availability nothing.
- [ ] Human security sign-off records an approval version and commit.

## Open questions

### OQ-501: Does the legacy SPEC-001 envelope migrate? — WITHDRAWN; there is no legacy population

This question assumed ceremonies in flight under the older CBCL envelope,
evidenced by the `channel_key_hex` entries in `test-vectors/spec-001-v1.json`.
There are none: no person holds a SPEC-001 identity in production, so no
ceremony needs to interoperate across the two formats.

The conclusion the question was heading toward therefore becomes the rule
outright. `SSE1` is the only record a conforming version-1 client accepts, and
[[PROTO-004-selfsame-ceremony-envelope-v1#REQ-501]] already says so without
qualification: one envelope format, one AEAD, one key schedule, no algorithm
identifier read from a record, no second format accepted. Nothing in this
document needs amending — what changes is that the exception is no longer
pending.

That is the substantive win. A recogniser that must distinguish two envelope
formats has to decide which one it is looking at *before* it has authenticated
anything, and that decision is a downgrade surface by construction. Withdrawing
this question removes the only thing that would have required one, so
[[PROTO-004-selfsame-ceremony-envelope-v1#REQ-504]]'s recognition-before-
interpretation ordering keeps a single path through it.

This is a scope decision by the human owner rather than a technical resolution,
and it reverses in one direction only: **it reopens the moment a single
production SPEC-001 ceremony exists.** Until then an implementation SHALL NOT
carry a compatibility branch for the legacy envelope, since an unexercised
second parser is a liability with no counterparty.

The parallel decision for identity is
[[SPEC-004-application-scoped-identity#OQ-206]], withdrawn on the same finding.

Owner: HOC.

### OQ-502: Is padding required, and who defines it? — RESOLVED by ADR-504 and CON-502

Padding is **REQUIRED**, the granularity is **one length for every record**,
and this protocol defines it rather than delegating to the enclosing profile.
Every sealed record is exactly 69,632 octets, produced by a fixed-length
plaintext frame of a four-octet length prefix, the canonical JSON, and verified
zero padding.

Framing the question as "how much does length leak about one bundle"
understated it. A closure's size tracks a DID's delta history, so it is stable
for one account and grows slowly over that account's life — meaning length was
a per-account fingerprint, and the one channel capable of relinking ceremonies
that CON-409's 128-bit addressing had separated. That reframing is what ruled
out bucketing: any bucket protects the median and exposes whoever overflows it,
and the accounts that overflow are the longest-standing ones.

Delegation to the profile is also withdrawn. A privacy control each profile may
decline is one that fails wherever it is most needed, and the padding sits in
the plaintext this protocol owns, not in the member sets a profile owns.

The cost is about 139 KiB per ceremony against about 5 KiB, accepted on the
grounds that the absolute figure is trivial for an operation a person performs
a handful of times and that PROTO-002 operators are already obliged to accept
records of this size. It is recorded in the residual risks rather than buried.

Timing between the two writes remains observable and is now the only
envelope-layer channel left.

Owner: privacy reviewer.

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

- **0.3.0 — 2026-08-17 — Selfsame credential-pairing deprecation.**
  Records the [[SPEC-007-cbcl-pairing-cutover]] disposition.
  The protocol remains draft authority for non-cutover consumers.
  No protocol octet or existing vector changes.
  All cryptography, privacy, and production gates remain open.

- **0.2.0 — 2026-07-31 — draft, normative.** Closes both open questions. This
  is a **wire-format change**: a version-0.1.0 record and a version-0.2.0
  record are not interchangeable, and no vectors had been published yet, which
  is why the format changes rather than the version negotiating.

  *OQ-502 — padding is now REQUIRED, fixed, and owned here.* CON-502's
  plaintext becomes a fixed-length frame — a four-octet big-endian JSON length,
  the canonical JSON, then verified zero padding — so every sealed record is
  exactly 69,632 octets and the JSON it carries is 1 to 69,607. The question
  asked about granularity and cost; the answer to granularity is that there is
  one length, because a closure's size tracks a DID's delta history and is
  therefore a per-account fingerprint, so any bucketing scheme would protect
  the median and expose the longest-standing accounts. Length was also the only
  channel still capable of relinking ceremonies that PROTO-003's 128-bit
  addressing had separated. ADR-504 records the reasoning and the rejected
  alternatives, including a `pad` payload member, which would have put padding
  inside member sets and digest rules owned by another document.

  The cost is about 139 KiB per ceremony rather than about 5 KiB, stated in the
  residual risks rather than buried, and cheap in absolute terms for something
  a person does a handful of times. Operators were already obliged to accept
  69,632-octet records under PROTO-002 CON-304.

  Affects REQ-505, CON-502, CON-503, CON-504, TEST-505, the residual risks, and
  the gate, which gains a privacy-reviewer item and a sustained-throughput item
  and loses the OQ-502 placeholder. The four-octet frame prefix reduces the
  JSON budget by four octets, so
  [[SPEC-004-application-scoped-identity#CON-219]]'s payload bound moves from
  69,611 to 69,607.

  *OQ-501 — withdrawn, not resolved.* No person holds a SPEC-001 identity, so
  no ceremony needs to interoperate with the legacy CBCL envelope. REQ-501
  already said one format and no negotiation; what changes is that the
  exception is no longer pending. The win is structural: a recogniser that must
  distinguish two envelope formats has to decide which it is looking at before
  authenticating anything, which is a downgrade surface by construction, so
  withdrawal keeps a single path through REQ-504's recognition ordering. It
  reopens if a production legacy ceremony ever exists. Affects Conformance and
  status and the gate. The parallel identity decision is
  [[SPEC-004-application-scoped-identity#OQ-206]].

  No key schedule, AEAD, role separation, transcript binding, digest rule, or
  error set changed.
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
