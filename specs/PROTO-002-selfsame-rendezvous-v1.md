---
id: PROTO-002
title: Selfsame Rendezvous Protocol v1 — a blind, replaceable link mailbox
status: draft
tier: 1
version: 0.1.0
audience: application developer, SDK implementer, infrastructure operator, security reviewer
author: Anuna Research (drafted with Codex, 2026-07-30)
last-updated: 2026-07-30
owner-repo: selfsame
affects-repos: selfsame, adopting applications, independent rendezvous implementations
review-gate: not-approved — Tier-1; independent interoperability vectors, adversarial protocol review, privacy review, production-operator review, and human security sign-off are outstanding
depends-on: RFC 2119; RFC 3986; RFC 4648; RFC 5234; RFC 8174; RFC 9110; RFC 9111; WHATWG Fetch; JSON Schema 2020-12; BLAKE3
---

# PROTO-002 — Selfsame Rendezvous Protocol v1

## Orientation

**Intent.** Define the complete public contract behind the
`selfsame-rendezvous-v1` provider descriptor. Any developer SHALL be able to
point a conforming Selfsame SDK at any conforming operator without registering
with Anuna, changing the linking ceremony, or teaching the person to configure
an endpoint.

**User promise.** The person scans or types one short-lived link code and
continues. They do not select, authenticate to, or troubleshoot a rendezvous
operator. Changing operators does not change an application-account DID, key,
alias, grant, or account scope.

**Operator promise.** A rendezvous is a blind, bounded, two-direction mailbox.
It stores opaque bytes at unguessable slot addresses. It never parses an offer,
VC, DID, account, provider hint, or application payload and never makes an
authorization decision. It may withhold, delay, observe timing, rate-limit, or
lose data; end-to-end cryptography prevents it from forging an accepted
exchange.

**Metaphor.** *Two numbered lockers in a station.* The joining device leaves an
opaque parcel in one locker, the home device leaves the reply in another, and
either party may check its locker again after a dropped connection. The station
does not have either parcel's key and does not decide whether its contents are
valid.

**Structure.**

```text
 application profile                 selected HTTPS origin
 (`selfsame-rendezvous-v1`)                    |
           |                                    v
           +---- GET /healthz ----------> [capability probe]
                                                |
       128-bit link secret                      |
          /          \                          |
   offer slot       bundle slot                 |
       |                |                       |
   PUT / GET        PUT / GET ----------------> [opaque TTL store]
       |                |                       |
  joining device   home controller              |
       \____________________  __________________/
                            \/
                 AEAD + transcript validation
                  occurs only in the clients
```

**Decisions.**
[[PROTO-002-selfsame-rendezvous-v1#ADR-301]] retain the existing role-separated
128-bit slot function ·
[[PROTO-002-selfsame-rendezvous-v1#ADR-302]] make slots immutable but readable
repeatedly until expiry ·
[[PROTO-002-selfsame-rendezvous-v1#ADR-303]] distinguish an identical retry
from an attempted overwrite ·
[[PROTO-002-selfsame-rendezvous-v1#ADR-304]] expose fixed, machine-readable
capabilities over the same HTTPS origin ·
[[PROTO-002-selfsame-rendezvous-v1#ADR-305]] keep rendezvous and `did:crdt`
state transport as independent protocol roles.

**Load-bearing.**
[[PROTO-002-selfsame-rendezvous-v1#REQ-301]] the protocol is independently
implementable ·
[[PROTO-002-selfsame-rendezvous-v1#REQ-302]] the provider remains blind ·
[[PROTO-002-selfsame-rendezvous-v1#REQ-303]] acknowledged writes are immutable
and safely retryable ·
[[PROTO-002-selfsame-rendezvous-v1#REQ-304]] reads survive ordinary network
loss ·
[[PROTO-002-selfsame-rendezvous-v1#REQ-305]] records have exact size and
retention bounds ·
[[PROTO-002-selfsame-rendezvous-v1#REQ-306]] capability probing is deterministic
and carries no trust.

**Controls digest.**

- Only an authenticated application profile supplies the HTTPS origin; link
  codes, offers, responses, and redirects never replace it.
- Clients reject every redirect and never send cookies, credentials, DIDs,
  account aliases, account scopes, stable user identifiers, or protocol-level
  application identifiers. A browser-generated `Origin` is the explicit
  transport-metadata exception governed by CON-307.
- Slot names are exactly 26 lower-case RFC 4648 base32 characters derived from
  a fresh 128-bit ceremony secret; a ceremony secret is never reused.
- Records are opaque non-empty octet strings of at most 69,632 bytes.
- A first write is immutable for exactly 600 seconds. An identical retry does
  not extend expiry; a different retry cannot overwrite it.
- Reads return byte-identical content and do not consume or extend a record.
- Successful and error responses are `no-store`; intermediaries never cache
  slot contents.
- Operators never log, index, back up, inspect, transform, compress, or expose
  slot names or record bodies.
- There is no list, search, prefix, delete, application-authentication, or
  undeclared fallback endpoint in version 1.

**Open.** Production availability and commercial SLOs are application/operator
policy, not wire interoperability. The provider-hint carrier remains owned by
[[SPEC-003-application-scoped-identity#OQ-205]]; once a client has the selected
descriptor and ceremony secret, this protocol completely defines provider use.

---

## Conformance and status

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in BCP 14 (RFC 2119 and RFC 8174) when, and only when, they appear in
all capitals.

This is a **Tier-1 draft** because it defines a public unauthenticated network
service used during authentication and device authorization. It is suitable for
review and conformance-suite design only. It does not authorize a production
deployment until the gate in
[[PROTO-002-selfsame-rendezvous-v1#Tier-1 Gate]] closes.

An implementation conforms to `selfsame-rendezvous-v1` only when it passes every
mandatory black-box test in this document. Running the reference
`selfsame-rendezvous` crate is not conformance by itself.

## Context

[[SPEC-003-application-scoped-identity]] lets each application embed several
eligible rendezvous descriptors and lets the initiating client select a healthy
operator. Its selection and provider-hint contracts deliberately do not define
the service's wire behavior. Without this protocol, the profile string
`"protocol": "selfsame-rendezvous-v1"` is only a label, and an independent
operator cannot know what to implement.

The current reference service demonstrates a useful legacy primitive:

```text
PUT /rendezvous/{slot}
GET /rendezvous/{slot}
GET /healthz
```

It is evidence, not the source of truth for this protocol. In particular, its
development behavior—4 KiB records, destructive read-once retrieval, a plain
`ok` health body, and one undifferentiated `409` response—does not satisfy this
contract.

### Roles

| Role | Responsibility |
|---|---|
| Initiator | Selects the provider and creates the ceremony secret and offer slot. |
| Joiner | Learns the authenticated provider hint and reads or writes the opposite slot. |
| Rendezvous operator | Implements only the capability and opaque-slot contracts. |
| Application verifier | Decrypts, parses, verifies, and authorizes; the operator never does. |
| State resolver | Exchanges `did:crdt` closures and deltas under a separate protocol, even when deployed at the same origin. |

## Scope

### In scope

- canonical provider base URLs;
- a deterministic capability/health response;
- role-separated slot derivation and grammar;
- opaque record writes, retries, reads, and expiry;
- response codes, media types, cache behavior, and CORS;
- payload, response, and time bounds;
- operator privacy and data-lifecycle obligations;
- denial-of-service and rate-limit behavior; and
- a black-box suite usable against independent operators.

### Out of scope

- selection priority and weighting, owned by
  [[SPEC-003-application-scoped-identity#CON-208]];
- the authenticated provider-hint carrier, owned by
  [[SPEC-003-application-scoped-identity#CON-209]] and OQ-205;
- offer, grant, VC, AEAD, transcript, or link-code formats;
- DID resolution, signed-closure retrieval, or delta publication;
- status-list projection;
- operator discovery, registration, payment, or commercial SLOs;
- user accounts at the rendezvous operator; and
- implementation work in the reference server.

## Happy path

1. The initiator receives an authenticated application profile, selects a
   descriptor, and probes its `GET /healthz` endpoint.
2. It accepts the provider only if the response passes CON-301 and arrives
   within SPEC-003's probe deadline.
3. The ceremony creates a fresh 16-byte secret, derives the offer and bundle
   slots with CON-302, encrypts the offer end to end, and writes the offer with
   CON-304.
4. After learning the authenticated provider hint and secret, the home
   controller repeatedly reads the offer slot until it receives the exact
   bytes or the signed offer expires.
5. It decrypts and validates the offer locally, creates the encrypted response,
   and writes the bundle slot.
6. The initiator repeatedly reads the bundle slot and performs all
   cryptographic and authorization checks locally.
7. Network retries can repeat either write or read without overwriting,
   consuming, extending, or transforming a record. The operator removes both
   records when their independent 600-second lifetimes expire.

The person sees none of the endpoint, slot, retry, or provider mechanics.

## Requirements

### REQ-301: Any independent operator can implement the protocol

A conforming operator SHALL implement the exact base-URL, capability, slot,
HTTP, error, and lifecycle contracts in CON-301 through CON-308 without
registration with or a runtime dependency on Anuna.

A conforming client and server produced independently from this document SHALL
complete the normative two-slot exchange using only an authenticated
`selfsame-rendezvous-v1` descriptor and the ceremony secret.

Trace:
[[PROTO-002-selfsame-rendezvous-v1#TEST-301]],
[[PROTO-002-selfsame-rendezvous-v1#TEST-308]]

### REQ-302: The rendezvous remains a blind mailbox

The operator SHALL treat every accepted record as opaque bytes. It SHALL NOT
decrypt, parse, validate, normalize, compress, transform, classify, or make an
authorization decision from a record. It SHALL NOT require or receive a DID,
account URI, account scope, device key, VC, application ID as a protocol field,
provider hint, cookie, bearer token, or user account as a condition of the core
exchange. A user agent's unavoidable CORS `Origin` header is transport metadata
under REQ-308 and CON-307, not an application credential or mailbox input.

Measuring the byte length, comparing a retry for exact byte equality, and
applying reversible storage-layer protection are the only permitted
record-content operations. They do not authorize semantic inspection.

Trace:
[[PROTO-002-selfsame-rendezvous-v1#TEST-307]],
[[PROTO-002-selfsame-rendezvous-v1#TEST-309]]

### REQ-303: Writes are immutable and safely retryable

For one unexpired slot, the first valid record SHALL become the immutable
stored value. Repeating the exact bytes SHALL succeed idempotently without
changing the value or expiry. Submitting different bytes SHALL fail and SHALL
NOT change the stored value.

Concurrent first writes SHALL produce exactly one stored value. Every caller
whose bytes equal that value receives the first-write or identical-retry
result; every different caller receives conflict.

Trace:
[[PROTO-002-selfsame-rendezvous-v1#TEST-303]],
[[PROTO-002-selfsame-rendezvous-v1#TEST-310]]

### REQ-304: Reads tolerate ordinary network loss

Every successful read before expiry SHALL return byte-for-byte identical stored
content. Reading SHALL NOT consume, mutate, delete, or extend the record.

A client SHALL be able to repeat a read after losing any response without
requiring a new ceremony. Replay resistance remains an end-to-end ceremony
property, not a destructive server-read side effect.

Trace:
[[PROTO-002-selfsame-rendezvous-v1#TEST-304]],
[[PROTO-002-selfsame-rendezvous-v1#TEST-310]]

### REQ-305: Storage is bounded

The server SHALL accept only non-empty records of at most 69,632 bytes and
SHALL retain an accepted record for exactly 600 seconds measured from the first
successful write. Identical retries and reads SHALL NOT move that deadline.

At or after the expiry boundary, the server SHALL behave as though the slot is
absent and SHALL remove the record from primary storage, replicas, queues,
snapshots, and backups within 60 additional seconds.

Rationale: 69,632 bytes is 68 KiB. It admits SPEC-003's 64 KiB compact grant
plus AEAD and bounded envelope overhead while retaining a hard unauthenticated
input cap.

Trace:
[[PROTO-002-selfsame-rendezvous-v1#TEST-304]],
[[PROTO-002-selfsame-rendezvous-v1#TEST-305]],
[[PROTO-002-selfsame-rendezvous-v1#TEST-307]]

### REQ-306: Capability probing is deterministic but non-authoritative

The operator SHALL expose the exact CON-301 capability response without
authentication. A client SHALL mark a descriptor eligible only when the
response is well-formed, names `selfsame-rendezvous-v1`, declares all mandatory
semantics, and arrives within the application's probe deadline.

A successful probe proves only current protocol compatibility and reachability.
It SHALL NOT be treated as evidence that the operator is honest, durable,
private, or available for the remainder of the ceremony.

Trace:
[[PROTO-002-selfsame-rendezvous-v1#TEST-301]],
[[PROTO-002-selfsame-rendezvous-v1#TEST-309]]

### REQ-307: Provider changes never reuse a ceremony

If an initiator changes providers after sending any slot request to the prior
provider or publishing or disclosing its provider hint, it SHALL abandon the
prior ceremony secret and offer and create a fresh secret, slots, offer,
ciphertext, and authenticated hint. Selection may move between health probes
without this reset only while no provider has received a slot request and no
hint has been published.

The SDK SHALL NOT copy an existing slot record between operators. This prevents
two operators from receiving an equality-testable slot or ciphertext for one
ceremony.

Trace:
[[PROTO-002-selfsame-rendezvous-v1#TEST-309]]

### REQ-308: Browser access carries no ambient authority

A conforming server SHALL support the credential-free CORS contract in CON-307.
A conforming browser client SHALL use `credentials: "omit"` or its exact
equivalent for every request.

No response SHALL set a cookie or require an Origin-specific allowlist.

A direct browser request necessarily discloses its web origin to the selected
operator. The browser client SHALL set `referrerPolicy: "no-referrer"` or its
exact equivalent, and the operator SHALL NOT persist, index, metric-label, or
make protocol decisions from `Origin` or `Referer`. An application requiring
the operator not to observe its web origin MUST use a native client or an
application-controlled ciphertext relay.

Trace:
[[PROTO-002-selfsame-rendezvous-v1#TEST-306]]

## Non-functional requirements

### NFR-301: Probe response bound

A provider is eligible only when the complete capability response is received
within 1,500 milliseconds of the request start. Clients SHALL cancel and
discard later responses.

Trace:
[[PROTO-002-selfsame-rendezvous-v1#TEST-301]]

### NFR-302: Bounded parsing and allocation

The server SHALL reject an oversized request while reading at most 69,633 body
bytes. A client SHALL read at most 2,049 capability bytes and 69,633 record
bytes before aborting.

Trace:
[[PROTO-002-selfsame-rendezvous-v1#TEST-301]],
[[PROTO-002-selfsame-rendezvous-v1#TEST-305]]

### NFR-303: Ephemeral privacy

The operator SHALL emit no log, trace, metric label, analytics field, crash
report, backup, or administrative listing containing a complete slot name,
record body, browser `Origin` or `Referer`, or deterministic hash of any of
them.

Aggregate counters MAY include response class, body-size bucket, and latency
when those labels cannot distinguish a ceremony.

Trace:
[[PROTO-002-selfsame-rendezvous-v1#TEST-307]]

## Architecture decisions

### ADR-301: Retain the existing role-separated slot primitive

**Status:** PROPOSED.

Version 1 retains the deployed Selfsame/SPEC-001 slot function:

```text
base32lower-no-pad(
  BLAKE3(
    UTF8("anuna-ssi/v1/slot/") ||
    UTF8(role) ||
    secret_16
  )[0..16]
)
```

Here `role` is exactly `offer` or `bundle`. The legacy domain string is an
opaque cryptographic label, not a dependency on Anuna infrastructure. Retaining
it reuses the existing core, test vectors, and link codes rather than creating
a second cryptographic ceremony solely to rename a domain separator.

The 128-bit output makes enumeration no easier than guessing the 128-bit
secret. Role separation prevents one direction from sharing an address with
the other. REQ-307 prevents equality across provider failover.

Rejected:

- a sequential or user-readable slot — enumerable and correlating;
- a raw secret in the URL — discloses the AEAD key source to the operator and
  HTTP infrastructure; and
- provider-specific input to the slot function — introduces a discovery cycle
  for clients that must learn the authenticated provider hint first.

### ADR-302: Immutable, repeatable-read records

**Status:** PROPOSED.

Writes are immutable, but reads are repeatable until a fixed expiry. A
destructive GET is rejected because the server commits the read before it can
know whether the client received the response. A connection loss after that
commit permanently destroys a correct exchange.

Repeatable ciphertext does not grant replay authority. Clients already bind the
bundle to the exact offer transcript, validate expiry, and accept one ceremony
once. Making a network mailbox pretend to be the cryptographic replay control
adds fragility without removing operator capabilities: a malicious operator
can always retain bytes before deletion.

An unauthenticated DELETE or acknowledgement endpoint is also rejected because
any party that learns a slot could delete it before the intended reader. The
fixed TTL is the only deletion mechanism in version 1.

### ADR-303: Identical PUT is success; different PUT is conflict

**Status:** PROPOSED.

HTTP response loss makes a client uncertain whether its first write committed.
Returning the same conflict for an identical retry and a different attempted
overwrite forces either unsafe success or unnecessary ceremony failure.

The server therefore compares opaque bytes:

- absent slot → store and return `201`;
- present with identical bytes → retain original expiry and return `204`; and
- present with different bytes → retain original bytes and return `409`.

The comparison reveals equality only to a caller that already knows a
128-bit slot address and candidate ciphertext. It gives the server no new
plaintext information.

### ADR-304: Fixed JSON capability response

**Status:** PROPOSED.

The application profile is the trust anchor; the health response is only a
bounded compatibility and reachability hint. A fixed JSON object supplies the
protocol name and limits needed by selection without creating runtime plugin
negotiation or a global provider registry.

Plain `ok` is rejected because it cannot distinguish protocol versions or
semantics. Server-selected algorithms and redirect-based discovery are rejected
because untrusted runtime input would then choose the parser and destination.

### ADR-305: Separate rendezvous from DID state transport

**Status:** PROPOSED.

An operator MAY deploy rendezvous and `did:crdt` state services at one origin,
but they are different roles, descriptors, and conformance suites. This
protocol defines only the blind mailbox.

Bundling the roles normatively is rejected because SPEC-003 expressly permits
different organizations to operate them and because a rendezvous should never
become an authorization-state trust anchor merely by being selected for one
link ceremony.

## Contracts

### CON-301: Provider base URL and capability response

The descriptor `url` is a canonical ASCII HTTPS origin:

```abnf
ALPHA       = %x41-5A / %x61-7A
DIGIT       = %x30-39
lower       = %x61-7A
alnum       = lower / DIGIT
ldh         = alnum / "-"
label       = alnum / (alnum *61ldh alnum)
dns-name    = label *("." label)
port        = 1*5DIGIT
base-url    = "https://" dns-name [":" port]
```

The DNS name MUST be a lower-case ASCII IDNA A-label name. A port, if present,
MUST be in `1..65535` and MUST NOT be `443`. The URL has no user information,
path, query, fragment, percent-encoding, trailing slash, or IP-literal host.
The DNS name is at most 253 ASCII octets and each label is at most 63. Clients
reject rather than normalize a non-canonical value.

The capability endpoint is the exact concatenation:

```text
base_url || "/healthz"
```

A successful response is:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "protocol": "selfsame-rendezvous-v1",
  "status": "ok",
  "maxRecordBytes": 69632,
  "slotTtlSeconds": 600,
  "writeSemantics": "immutable-idempotent",
  "readSemantics": "repeatable-until-expiry",
  "cors": true
}
```

The response body MUST be UTF-8 JSON matching this JSON Schema:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "protocol",
    "status",
    "maxRecordBytes",
    "slotTtlSeconds",
    "writeSemantics",
    "readSemantics",
    "cors"
  ],
  "properties": {
    "protocol": {"const": "selfsame-rendezvous-v1"},
    "status": {"const": "ok"},
    "maxRecordBytes": {"const": 69632},
    "slotTtlSeconds": {"const": 600},
    "writeSemantics": {"const": "immutable-idempotent"},
    "readSemantics": {"const": "repeatable-until-expiry"},
    "cors": {"const": true}
  }
}
```

Clients fully parse at most 2,048 bytes before any selection action and reject
duplicate JSON member names, non-integer numbers, unknown members, invalid
UTF-8, redirects, content encoding, wrong media type, and every non-`200`
status. A server MAY support a larger internal record limit, but it advertises
and enforces 69,632 bytes for this version; a version-1 client never sends or
accepts more.

The server returns this `200`/`"ok"` response only while it is ready to accept
new writes and serve existing reads under CON-304 and CON-305. During planned
drain, storage unavailability, or known inability to honour the advertised
contract, `/healthz` returns `503 Service Unavailable` with an empty body.

There is no runtime feature or algorithm negotiation. An incompatible change
to endpoints, slot derivation, limits, lifecycle, or semantics requires a new
profile/capability protocol token; clients reject every unknown token.

### CON-302: Slot derivation and grammar

Inputs:

```text
secret_16 = exactly 16 CSPRNG bytes unique to this ceremony
role      = exactly UTF8("offer") or UTF8("bundle")
domain    = UTF8("anuna-ssi/v1/slot/")
```

Derivation:

```text
slot_bytes = BLAKE3(domain || role || secret_16)[0..16]
slot       = BASE32LOWER-NOPAD(slot_bytes)
```

`BASE32LOWER-NOPAD` is RFC 4648 base32 with alphabet
`abcdefghijklmnopqrstuvwxyz234567`, lower-case output, and no `=` padding.

Normative vectors:

| `secret_16` hex | `offer` slot | `bundle` slot |
|---|---|---|
| `00000000000000000000000000000000` | `yzwhu56twapydav2ly2gx4wbku` | `woddqaky4t52djpvlkafg767q4` |
| `ffffffffffffffffffffffffffffffff` | `fy2ilmfxjroafpahbpppnx7u4e` | `3e6exm6fu64mmm6mys6yzmxlk4` |
| `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` | `rsgikwizn2ahqtlv36v5i4ytlq` | `avdhdaffvq34i4pckzqrvt57v4` |
| `9f3a11c2e70b4d8a5c6f9012ab34cd56` | `dc4q5nfke4wfagfd2na7lv36p4` | `b5vk2fbqviratt2kkbckz2xppa` |

These values reproduce the existing
[`test-vectors/spec-001-v1.json`](../test-vectors/spec-001-v1.json)
`con_002_rendezvous` entries; PROTO-002 adopts only their secret and slot
columns, not the legacy application or grant profile.

The accepted path grammar is:

```abnf
b32lower = lower / %x32-37
slot     = 26b32lower
```

A parser MUST decode exactly 16 bytes, re-encode them, and require byte-for-byte
equality with the path value before accessing storage. The offer and bundle
slots derived from one secret MUST differ.

### CON-303: Common HTTP transport

The slot endpoint is:

```text
base_url || "/rendezvous/" || slot
```

Every request:

- uses HTTPS with normal certificate and hostname validation;
- uses no redirect, cookie, HTTP authentication, client certificate, URL query,
  fragment, or protocol-level application identifier;
- sets `Accept-Encoding: identity` when the client controls that header;
- treats any `3xx` response as terminal `ProviderProtocolViolation`; and
- applies the application's bounded request deadline.

Browser Fetch does not expose `Accept-Encoding` to application code. A browser
client therefore uses `credentials: "omit"`, `redirect: "error"`, and
`referrerPolicy: "no-referrer"` or their exact equivalents and relies on the
server's unconditional prohibition on content encoding. The server MUST return
the same unencoded representation regardless of a user agent's automatic
request headers. The CORS `Origin` header remains visible as described in
CON-307.

Every `/healthz` and slot response, including an error response, includes:

```http
Cache-Control: no-store
Vary: Origin
Access-Control-Allow-Origin: *
```

It includes no `Set-Cookie`, redirect `Location`, content encoding, or
operator-specific authorization challenge. Error responses have an empty body
and the same `no-store` rule. A client reads no error body.

An unsupported method receives `405 Method Not Allowed` with an empty body and
an `Allow` header naming `GET, OPTIONS` for `/healthz` or `GET, PUT, OPTIONS`
for a slot. An unrecognized path within the `/rendezvous/` namespace receives
`404 Not Found` with an empty body. Behavior outside `/healthz` and that
namespace is out of scope so a separately described state service may share
the origin. Clients never intentionally elicit either response; receiving
`405` for a defined request is a `ProviderProtocolViolation`.

TLS terminates somewhere under the selected operator's responsibility, but TLS
does not protect the record from that operator. Ceremony AEAD and transcript
validation remain mandatory.

### CON-304: Store an opaque record

Request:

```http
PUT /rendezvous/{slot} HTTP/1.1
Content-Type: application/octet-stream
Content-Length: <1..69632>

<opaque bytes>
```

Servers MAY accept chunked transfer encoding but MUST stop after reading 69,633
bytes. They MUST NOT require `Content-Length`. They MUST reject content
encoding and every media type other than `application/octet-stream`.

Response:

| Condition after full recognition | Status | State change |
|---|---:|---|
| Valid slot is absent; body length `1..69632` | `201 Created` | Store exact bytes; set expiry to first-write time + 600 s. |
| Slot exists and exact bytes match | `204 No Content` | None; original expiry remains. |
| Slot exists and bytes differ | `409 Conflict` | None. |
| Malformed slot or empty body | `400 Bad Request` | None. |
| Body exceeds 69,632 bytes | `413 Content Too Large` | None. |
| Wrong or encoded media type | `415 Unsupported Media Type` | None. |
| Operator rate limit | `429 Too Many Requests` | None; include integer-seconds `Retry-After`. |
| Temporary capacity failure | `503 Service Unavailable` | None; SHOULD include integer-seconds `Retry-After`. |

Every response body is empty. `201` and `204` are acknowledgements that the
exact bytes are retrievable under CON-305 until the original expiry, subject
only to an operator availability failure. A success response is sent only
after the stored value and expiry are committed atomically.

The first-write time and 600-second interval are measured by a monotonic server
clock. Wall-clock correction, restart, identical retry, read, replication, or
failover MUST NOT move the stored expiry later.

### CON-305: Retrieve an opaque record

Request:

```http
GET /rendezvous/{slot} HTTP/1.1
Accept: application/octet-stream
Accept-Encoding: identity
```

Response:

| Condition | Status | Body |
|---|---:|---|
| Valid unexpired slot exists | `200 OK` | Exact stored bytes. |
| Slot is malformed, absent, or expired | `404 Not Found` | Empty. |
| Operator rate limit | `429 Too Many Requests` | Empty; include `Retry-After`. |
| Temporary capacity failure | `503 Service Unavailable` | Empty. |

A `200` response includes:

```http
Content-Type: application/octet-stream
Content-Length: <exact byte length>
Cache-Control: no-store
```

The server returns the same bytes on every successful read before expiry. A
read does not change any server state visible to later protocol requests.
At the exact first-write time plus 600 seconds, the response becomes `404`.

### CON-306: Error and retry model

Clients map protocol outcomes to this closed set:

| Error | Trigger | Retry within same ceremony |
|---|---|---|
| `ProviderUnreachable` | DNS, TLS, connection, or deadline failure | MAY retry or elect a new provider under REQ-307. |
| `ProviderProtocolViolation` | Redirect, malformed capability/headers/body, oversized response, or unexpected status | MUST NOT retry this provider in the ceremony. |
| `SlotNotFound` | `GET 404` before local expiry | MAY poll with bounded backoff. |
| `SlotConflict` | `PUT 409` | MUST abandon the ceremony; existing bytes are not assumed equal. |
| `RateLimited` | `429` with valid `Retry-After` | MAY retry within local expiry. |
| `ProviderUnavailable` | `503` | MAY retry within local expiry or elect anew under REQ-307. |
| `RequestInvalid` | `400`, `413`, or `415` | MUST NOT retry unchanged input. |

Unknown statuses fail as `ProviderProtocolViolation`. A server's `Retry-After`
does not extend the signed offer expiry, record TTL, application deadline, or
user-visible ceremony deadline.

Poll schedules are client policy, but clients SHOULD add randomized jitter and
SHALL NOT issue more than two `GET` requests per second per slot. A `404` is
not evidence that a link code is invalid until the local offer deadline passes.

### CON-307: Browser CORS

For `/healthz`, an `OPTIONS` request with an Origin header receives:

```http
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, OPTIONS
Access-Control-Allow-Headers: Content-Type, Accept
Access-Control-Max-Age: 600
Cache-Control: no-store
Vary: Origin
```

For `/rendezvous/{slot}`, the response is identical except that
`Access-Control-Allow-Methods` is `GET, PUT, OPTIONS`.

The server SHALL NOT emit `Access-Control-Allow-Credentials: true`. Actual GET
and PUT responses carry `Access-Control-Allow-Origin: *`. Browser clients omit
credentials and treat a CORS failure as `ProviderProtocolViolation`.

The operator necessarily receives the browser-generated `Origin` on CORS
requests. It SHALL use that value only to complete the wildcard CORS exchange:
it SHALL NOT echo a selected origin, branch protocol behavior by origin,
persist it, correlate it with slots or network addresses, or expose it through
logs, traces, metrics, analytics, or administrative tooling. The client
suppresses `Referer` as required by REQ-308.

### CON-308: Operator storage, abuse, and observability boundary

The storage key is the exact recognized 26-character slot. The value is the
exact body, first-write timestamp, and fixed expiry; no other application data
is required.

The operator:

- MUST NOT expose listing, search, prefix, batch-read, delete, extension, or
  administrative content-inspection APIs for protocol records;
- MUST NOT write slot or body values, or deterministic hashes of them, to logs,
  traces, metric labels, analytics, crash reports, queues, or backups;
- MUST NOT retain or emit browser `Origin` or `Referer` values, or hashes of
  them, in storage, logs, traces, metrics, analytics, or administrative tools;
- MUST purge expired data from primary and replicated storage within the REQ-305
  bound;
- MAY rate-limit by transient network properties or aggregate load, but MUST
  use CON-304/305 statuses and MUST NOT require identity or application
  credentials;
- SHOULD equalize error bodies and avoid response detail that makes slot
  probing cheaper; and
- SHALL emit aggregate request count, response class, size bucket, latency,
  expiry purge count, and storage-pressure signals without ceremony
  identifiers.

An operator policy may retain ordinary connection metadata required by law or
abuse response, but such policy is outside protocol conformance and SHALL be
disclosed to adopting applications. It never permits retaining slot names or
bodies beyond this contract.

## Test specifications

### TEST-301: Capability recognition and probe bound

**Validates:** REQ-301, REQ-306, NFR-301, NFR-302, CON-301.

Accept the capability object only with `maxRecordBytes` exactly 69,632. Reject
each missing, extra, duplicated, wrong-type, wrong-value, over-depth, and
invalid-UTF-8 member independently; reject bodies of 2,049 bytes, redirects,
compression, wrong media types, and responses arriving after 1,500 ms. No
failed probe may enter the eligible provider set.

Accept boundary-valid lower-case A-label origins and a non-default port. Reject
upper-case or overlength names, invalid labels or ports, IP literals, user
information, percent-encoding, path, query, fragment, trailing slash, and an
explicit port `443` before sending a probe.

### TEST-302: Slot derivation and grammar

**Validates:** REQ-301, CON-302.

Two independent implementations reproduce normative offer and bundle vectors
for all-zero, all-one, and random secrets. Exercise every accepted alphabet
character. Reject wrong length, upper-case, `0`, `1`, `8`, `9`, padding,
percent-encoding, slash, dot segment, Unicode, invalid pad bits, and
decode/re-encode mismatch before storage access.

### TEST-303: Immutable idempotent writes

**Validates:** REQ-303, CON-304.

Require `201` for a first write, `204` for exact retries without expiry change,
and `409` for every different retry while preserving the first bytes. Race 100
different writers at one empty slot and require exactly one immutable winner;
all requests carrying the winning bytes are successful and every other request
conflicts.

### TEST-304: Repeatable reads and expiry

**Validates:** REQ-304, REQ-305, CON-305.

Read one stored value repeatedly, concurrently, after a response-body disconnect,
and immediately before expiry; every `200` body is byte-identical. At and after
exactly 600 seconds require `404`. Verify that writes, identical retries, and
reads do not move the first-write expiry.

### TEST-305: Request and response bounds

**Validates:** REQ-305, NFR-302, CON-303, CON-304, CON-305.

Accept record lengths 1 and 69,632. Reject 0 and 69,633 with the specified
statuses and no storage change. Stream an unbounded chunked request and require
termination after at most 69,633 bytes. Serve a 69,633-byte response and require
the client to abort without exposing partial bytes to the ceremony parser.

### TEST-306: HTTP, cache, redirect, and CORS controls

**Validates:** REQ-308, CON-303, CON-307.

Verify every success and error response has `no-store`, no cookie, no
credential challenge, and the required CORS headers. Follow no redirect,
including same-origin redirects. Exercise browser preflight followed by
credential-free GET and PUT from two unrelated origins. Require no `Referer`,
the wildcard response rather than origin reflection, identical protocol
behavior for both origins, and no persisted or emitted origin value.

### TEST-307: Blindness, retention, and observability

**Validates:** REQ-302, REQ-305, NFR-303, CON-308.

Store malformed plaintext, valid-looking JSON, a VC-shaped body, and random
bytes; the server treats equal-length bodies identically and returns exact
bytes. Inspect storage, logs, traces, metrics, crash output, queues, and backups
and require no slot, body, browser origin/referrer, or deterministic hash.
After expiry plus 60 seconds, require zero copies while unrelated records
remain unchanged.

### TEST-308: Independent implementation interoperability

**Validates:** REQ-301 and CON-301 through CON-307.

Run client A against servers A and B, then client B against both servers. For
each pairing, exchange both directions, inject a lost write response and a lost
read response, and complete with byte-identical records. Neither implementation
may contain an Anuna endpoint, account, token, or shared non-standard parser.

### TEST-309: SPEC-003 selection and role separation

**Validates:** REQ-302, REQ-306, REQ-307, ADR-305.

Give one application two rendezvous providers and a separately operated state
resolver. Confirm that CON-208 selects only a passing provider, the joiner uses
the authenticated hint, and no rendezvous request reaches the state resolver.
Fail the selected provider once after an unacknowledged first slot request and
once after hint publication; in both cases require a new secret, slots, offer,
ciphertext, and hint before another provider is used. Compare both operators'
traffic and require no equal slot or ciphertext.

### TEST-310: Retry ambiguity is closed

**Validates:** REQ-303, REQ-304, CON-304, CON-305, CON-306.

Drop the first `201` response after commit; the exact retry receives `204` and
the exchange completes. Drop a `200` response after headers and after a partial
body; a later read returns the complete exact bytes. Replace either retry body
and require `409` with the original record unchanged.

## Trust assumptions

This protocol assumes:

- ceremony secrets contain 128 bits from a CSPRNG and are never reused;
- BLAKE3 preimage resistance and the ceremony AEAD remain secure;
- the application profile and provider hint are authenticated as specified by
  SPEC-003;
- HTTPS authenticates the selected origin to the client; and
- clients independently enforce expiry, size, transcript, signature, VC, DID,
  permission, revocation, and proof-of-possession checks.

It does not assume the operator stores, returns, deletes, or reports data
honestly. A malicious operator can deny service and observe network timing and
addresses. It cannot construct an accepted plaintext or authorization decision
without breaking the end-to-end ceremony.

## Threat model

| Threat | Required response |
|---|---|
| Slot enumeration | 128-bit pseudorandom address; no list/prefix API; uniform absent response. |
| Operator reads content | Content is AEAD ciphertext; operator never receives the link secret. |
| Operator substitutes content | Client AEAD and transcript verification reject it; immutable writes prevent the corresponding conforming-server race. |
| Lost first-write response | Identical PUT retry returns `204` without changing bytes or expiry. |
| Lost read response | Repeatable GET returns the same bytes until expiry. |
| Replay | Server may replay ciphertext; client expiry, transcript, nonce, and one-ceremony state reject authority. |
| Cross-provider correlation | Provider change requires a fresh secret, slots, offer, ciphertext, and hint. |
| Cache disclosure | `no-store`, identity encoding, no redirects, and response-size caps. |
| Ambient browser authority | Wildcard credential-free CORS; no cookies or credentials. |
| Browser origin disclosure | Direct CORS reveals the web origin transiently; `no-referrer`, no persistence/use by conforming operators, and an optional application relay bound the exposure. |
| Storage/log disclosure | Exact TTL, purge bound, and prohibition on slot/body logs, hashes, queues, and backups. |
| Resource exhaustion | Strict grammar, streaming byte cap, fixed TTL, no listing, `429`/`503`. |
| Malicious health response | Strict bounded parser; response affects eligibility only and never authorization. |

## Compatibility with the reference server

The reference `crates/selfsame-rendezvous` implementation already matches:

- the `PUT` and `GET /rendezvous/{slot}` route names;
- the 26-character lower-case base32 slot grammar and derivation;
- opaque storage and immutable first-write behavior;
- 600-second first-write TTL; and
- the absence of server-side authorization decisions.

It is not yet PROTO-002 conforming:

1. its `/healthz` body is plain `ok`, not CON-301 JSON;
2. its maximum body is 4,096 rather than 69,632 bytes;
3. it returns `409` for both identical retry and different overwrite;
4. its GET is destructive read-once rather than repeatable until expiry;
5. it lacks the normative headers, CORS, and differentiated errors; and
6. its in-memory development store does not meet the production purge and
   acknowledgement semantics.

Those are future implementation tasks. This protocol intentionally does not
change code or claim that the existing service passes.

## Tier-1 Gate

No production implementation or profile may claim
`selfsame-rendezvous-v1` until:

- [ ] Two independent client and server implementations pass TEST-301 through
      TEST-310 in all four pairings.
- [ ] Normative slot, HTTP, expiry-boundary, and retry vectors are published.
- [ ] A coverage-guided fuzzer exercises the capability JSON, URL, slot, HTTP
      header, and streaming-body recognizers.
- [ ] A cross-model adversarial review covers overwrite, replay, loss,
      redirect, cache, CORS, enumeration, logging, and resource-exhaustion
      attacks.
- [ ] A privacy reviewer approves operator-visible metadata, log prohibitions,
      TTL, and cross-provider failover behavior.
- [ ] A production operator reviews atomic commit, purge, backup, rate-limit,
      and sudden-death behavior.
- [ ] A human security reviewer approves ADR-301 through ADR-305 and CON-301
      through CON-308.
- [ ] SPEC-003's provider-hint carrier is resolved without introducing an
      undeclared global rendezvous or discovery host.
- [ ] Human security sign-off records the approved protocol version and commit.

## Traceability

| User or operator outcome | Requirements | Decisions/contracts | Tests |
|---|---|---|---|
| Any developer can use any conforming operator | REQ-301, REQ-306 | ADR-304, CON-301, CON-303 | TEST-301, TEST-308, TEST-309 |
| Operator cannot read or authorize | REQ-302 | ADR-305, CON-303, CON-308 | TEST-307, TEST-309 |
| Network loss does not destroy a correct exchange | REQ-303, REQ-304 | ADR-302, ADR-303, CON-304–306 | TEST-303, TEST-304, TEST-310 |
| Mailbox storage and parsing stay bounded | REQ-305, NFR-302 | CON-301, CON-304, CON-305, CON-308 | TEST-304, TEST-305, TEST-307 |
| Provider failover does not correlate one ceremony | REQ-307 | ADR-301, CON-302, CON-306 | TEST-302, TEST-309 |
| Native and browser clients share one protocol | REQ-308 | CON-303, CON-307 | TEST-306, TEST-308 |

## Amendment Channels

Amendable by: Selfsame protocol maintainers and the human security owner.

Through: a merged, versioned amendment to this PROTO with updated
REQ/NFR/ADR/CON/TEST traceability, interoperability vectors, adversarial
review, and Tier-1 human approval.

Not amendable by: application profiles, provider health responses, operator
documentation, deployment configuration, SDK heuristics, code comments, issue
comments, chat messages, or behavior of the reference implementation.

Hard stops: no channel may waive client-selected HTTPS-origin authentication,
the blind-mailbox rule, size/TTL bounds, immutable writes, repeatable reads,
no-store behavior, log/body prohibitions, fresh-secret provider failover, or
end-to-end cryptographic verification without a new protocol version.

## Normative and informative sources

- Selfsame,
  [`test-vectors/spec-001-v1.json`](../test-vectors/spec-001-v1.json),
  normative source for the slot vectors adopted in CON-302.
- IETF, [RFC 3986 — Uniform Resource Identifier syntax](https://datatracker.ietf.org/doc/html/rfc3986).
- IETF, [RFC 4648 — Base-N Encodings](https://datatracker.ietf.org/doc/html/rfc4648).
- IETF, [RFC 5234 — Augmented BNF for Syntax Specifications](https://datatracker.ietf.org/doc/html/rfc5234).
- IETF, [RFC 2119 — Key words for use in RFCs](https://datatracker.ietf.org/doc/html/rfc2119).
- IETF, [RFC 8174 — Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words](https://datatracker.ietf.org/doc/html/rfc8174).
- IETF, [RFC 9110 — HTTP Semantics](https://datatracker.ietf.org/doc/html/rfc9110).
- IETF, [RFC 9111 — HTTP Caching](https://datatracker.ietf.org/doc/html/rfc9111).
- WHATWG, [Fetch Living Standard](https://fetch.spec.whatwg.org/), especially
  the CORS protocol and credential modes.
- JSON Schema, [Draft 2020-12](https://json-schema.org/draft/2020-12).
- BLAKE3 team, [BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3-specs).

## Changelog

<details>
<summary>Revision history — 0.1.0</summary>

- **0.1.0 — 2026-07-30 — draft.** First complete
  `selfsame-rendezvous-v1` contract. Defines the capability response, canonical
  origin, existing slot derivation, strict slot/body grammars, 68 KiB bound,
  600-second TTL, immutable idempotent PUT, repeatable GET, closed error model,
  no-store and credential-free CORS behavior, privacy/observability boundary,
  explicit browser-Origin handling, black-box interoperability suite,
  reference-server gap analysis, and Tier-1 no-go gate.

</details>
