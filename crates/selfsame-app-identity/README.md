# selfsame-app-identity

The pure core of [SPEC-004] — application- and account-scoped identity. One
recovery secret, a different home key for every application account, a portable
W3C Verifiable Credential granting one device narrowly scoped access, and no
mandatory infrastructure operator anywhere in the picture.

> **Status: governed prototype, not for production.**
> SPEC-004 is a Tier-1 draft whose review gate is open, and its own Controls
> digest prohibits implementation and shipment until that gate closes. This
> crate exists under [EXP-001] to produce the reference implementation and
> conformance vectors that two of the gate's own boxes require. Nothing here
> ticks a gate box, and the specification remains `draft`. [CONFLICT-001]
> records the analysis and the four resolutions that were on the table.

## Quick start

```bash
cargo test -p selfsame-app-identity          # 386 tests
SELFSAME_REGEN_CORPUS=1 cargo test -p selfsame-app-identity --test con_226_corpus
```

Deriving one account's home identity:

```rust
use selfsame_app_identity::{alias, hierarchy, profile::ApplicationId, scope::AccountScopeId};

let mnemonic = hierarchy::Mnemonic::parse_in_normalized(
    bip39::Language::English,
    "abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon about",
)?;

// Both inputs are validated newtypes, so CON-202's precondition — "after
// validating canonical_account_scope_id with CON-211" — is carried by the type
// rather than by a comment.
let application = ApplicationId::parse("https://photos.example/selfsame/application")?;
let account_scope = AccountScopeId::parse(scope_from_the_account_record)?;

// The root comes from the custodian's sealed material, not from a phrase —
// CON-202 hierarchy version 2, see ADR-223. `derive_from_mnemonic` exists for
// the two moments the phrase is legitimately in hand: creation and restore.
let home = hierarchy::derive(&hierarchy_root, &application, &account_scope);
let home_did = home.home_did()?;
let acct = alias::stable_acct_uri(&home_did, "accounts.photos.example");
// acct:ss-<52 lower-case base32 characters>@accounts.photos.example
```

## Usage

### Issuing a device grant

```rust
use selfsame_app_identity::{didkey, grant};

let device_public = device_signing_key.verifying_key().to_bytes();
let compact_jws = grant::issue(
    home.signing_key(),
    &home_did,
    &token_octets,            // 32 octets from the caller's CSPRNG
    &didkey::encode(&device_public),
    &device_public,
    &application,
    &account,
    &permissions,
    valid_from,
    valid_until,              // at most maxGrantLifetimeSeconds later
);
```

### Accepting one

```rust
use selfsame_app_identity::accept::{accept_grant, Evidence, Expectation, Freshness};

let accepted = accept_grant(
    compact_jws.as_bytes(),
    &Expectation {
        profile: &profile,
        account: &expected_account,
        device_public_key: &offer.device_public_key,   // the key this context offered
        operation_permissions: &["https://photos.example/selfsame/application#device"],
        now,
        clock_skew_seconds: 0,
        freshness: Freshness::SessionEstablishment,
    },
    &Evidence {
        issuer: Some(&resolved_closure),   // the shell resolved this
        jrd: Some(&webfinger_record),      // …and fetched this
        projection: None,
        proof: Some((&challenge, &signature, &verifier_session)),
    },
)?;
```

Every failure names one of `CON-206`'s thirteen numbered steps for the local log
and the corpus, and collapses to one of three outward reasons so an attacker
gains no credential oracle.

## Architecture

Everything here is deterministic, free of I/O, and free of clock reads. The
shell injects `now`, fetched documents, probe outcomes, and resolved DID
closures as parameters.

```text
  phone / CLI / app backend / wasm verifier      ← effectful shell
                    │
                    ▼
        selfsame-app-identity  (pure)            ← this crate
                    │
                    ▼
        did-crdt · selfsame-core                 ← every arrow inward
```

That is not housekeeping. `CON-206` is **one** authorization predicate that a
phone, a CLI, an application backend, and a browser verifier must each apply
identically; four implementations of one security predicate is the
parser-differential failure LangSec Principle 5 prohibits. It is written once
and every runtime links it — which is only possible if it drags in no I/O.
`tests/purity.rs` enforces the boundary rather than asserting it, and that is
also what makes `TEST-203`'s "no network request" and `TEST-216`'s "no Anuna
endpoint" properties of the build rather than of a promise.

There is exactly **one** JSON recogniser (`json`), for the same reason. SPEC-004
never accepts "valid JSON": six of its contracts declare a closed language whose
obligations — no duplicate member names, no trailing content, a depth bound, an
octet bound, integers only, RFC 8785 round-trip byte equality — a general parser
does not decide. Linking a permissive parser beside the strict one is the
shotgun-parser shape LangSec rules out, whatever the convention about which is
"the real" one.

### Module map

| Module | Contract | Obligation |
|---|---|---|
| `json` | CON-201, 205, 214, 215, 219, 225 | the one closed-language recogniser and RFC 8785 canonicaliser |
| `codec`, `uri`, `time` | CON-203, CON-211 | canonical base64url, base32, base58btc; the restricted HTTPS URI grammar; one `dateTimeStamp` spelling |
| `hierarchy` | CON-202 | REQ-201, REQ-213 — application and account nodes |
| `scope` | CON-211 | REQ-216, REQ-217 — the opaque account scope |
| `profile` | CON-201 | REQ-202, REQ-209, REQ-210 — the closed profile language |
| `alias` | CON-203, CON-204, CON-212 | REQ-203, REQ-204, REQ-218 — `acct:` aliases and reciprocal binding |
| `jws`, `didkey` | CON-205, 214, 225 | the shared compact JWS and `did:key` |
| `grant` | CON-205 | REQ-205, REQ-206, REQ-208 — the device grant |
| `accept` | CON-206 | REQ-207 — the thirteen-step predicate |
| `proof` | CON-207 | REQ-206 — device proof of possession |
| `selection` | CON-208, CON-209 | REQ-209, REQ-212 — provider choice and the hint |
| `pairing` | CON-213, 216, 217, 218 | REQ-226–229 — descriptor binding, bootstrap obligations, PAKE composition, burn closure |
| `platform` | CON-222, CON-223 | REQ-220, REQ-223, REQ-225 — Android and Apple adapter conformance |
| `revocation` | CON-210 | REQ-208 — the grow-only revocation set |
| `enrollment` | CON-214 | REQ-222 — application enrollment evidence |
| `ceremony` | CON-215, CON-219 | REQ-211, REQ-220–225 — payloads and handoff |
| `discovery` | CON-220 | REQ-222, REQ-227 — origin-bound profile fetch |
| `confirm` | CON-221 | REQ-230 — first-enrollment confirmation |
| `context` | CON-224 | REQ-205 — the pinned credential context |
| `succession` | CON-225 | REQ-231 — bounded identity succession |

### Design decisions worth knowing before reading the code

- **`ApplicationId` and `AccountScopeId` are validated newtypes.** `CON-202`
  states its precondition in prose; the types carry it, so no call site can
  derive from an unrecognised identifier.
- **Recognition and canonicality are separate steps.** `CON-201` runs them as
  steps 2 and 5 so a profile that parses but is not canonical is *rejected*,
  never repaired. Postel's rule is refused here (LangSec Principle 4).
- **The bytes verified are the bytes that arrived.** `jws::CompactJws` keeps the
  received signing input rather than re-serialising, because re-canonicalising
  before verifying turns any difference between two serialisers into a forgery
  oracle.
- **`Submission` is a type, not a boolean.** A resolver's acknowledgement is not
  evidence of revocation, and the type makes "we sent it" impossible to read as
  "it is revoked".
- **A burned ceremony has no way back.** `Ceremony::burn` is one-way and there is
  no `reset`, because `CON-218`'s only retry transition is `burned -> new
  ceremony`. `CeremonyValues` makes the second half checkable: it fingerprints
  the thirteen values `REQ-229` names, so "did the retry reuse anything?" gets a
  list rather than a promise.
- **`platform` has no `verify_signing_certificate`.** `CON-222` records the
  target's signing identity for audit and explicitly does *not* check it against
  a registry, because none exists — which is why `CON-221` confirmation is
  required at first enrollment. A function implying an authority would invent
  one.

## API reference

Every contract's obligations live in its module's documentation, quoted from the
specification with the reasoning intact. `cargo doc -p selfsame-app-identity
--open` is the fastest route in; the module headers are written to be read in
order.

## Development

Requires the two sibling checkouts SPEC-001 ADR-010 and ADR-013 pin:

```bash
git clone https://git.anuna.io/anuna-research/did-crdt ../did-crdt
git clone https://git.anuna.io/anuna-research/cbcl-rs  ../cbcl-rs
```

```bash
cargo test -p selfsame-app-identity
cargo clippy -p selfsame-app-identity --all-targets
```

The conformance corpus is `test-vectors/spec-004-v1.json`, generated by
`tests/con_226_corpus.rs` and committed so a second implementation can read it
without running the suite. `CON-226`'s completeness rule is a test: a closed
error token or a `CON-206` step with no case fails the build.

[SPEC-004]: ../../specs/SPEC-004-application-scoped-identity.md
[EXP-001]: ../../specs/EXP-001-spec-004-reference-implementation.md
[CONFLICT-001]: ../../specs/CONFLICT-001-spec-004-tier1-gate.md
