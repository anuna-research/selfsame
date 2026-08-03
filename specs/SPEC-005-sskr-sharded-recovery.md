---
id: SPEC-005
title: SSKR Sharded Recovery — splitting the root entropy into a quorum of shares
status: draft
tier: 1
version: 0.3.0
audience: agent, human, security reviewer, interface designer
author: Anuna Research (drafted with Claude, 2026-08-03; screens folded in
  2026-08-03)
last-updated: 2026-08-03
owner-repo: selfsame
affects-repos: selfsame, anuna-ssi
review-gate: not-approved — Tier-1; all ADRs are PROPOSED; cryptography is a
  PROTO-001 no-go area requiring explicit human approval; cross-model
  adversarial review, independent SSKR vectors, and human cryptography sign-off
  are outstanding
depends-on: SPEC-001 Device Key Provisioning (CON-007, REQ-001, REQ-002);
  BCR-2020-011 SSKR; BCR-2020-011 dependency `bc-shamir`; BIP-39; RFC 5869
---

# SPEC-005 — SSKR Sharded Recovery

## Orientation

**Intent.** A person SHALL be able to recover a Selfsame identity from a quorum
of physical shares, instead of from one transcribed twelve-word phrase. No
identity already created changes, and no derived key moves, because the thing
that is split is the entropy that already sits above every derivation.

**Metaphor:** *the twelve words, cut so that no single piece is a key.* The
whole design turns on the second clause. A cut that leaves one piece able to
open the door has not divided custody — it has photocopied it. The evidence in
[[SPEC-005-sskr-sharded-recovery#OBS-602]] shows how easily the underlying
library produces exactly that.

**Structure:**

```
   16 bytes of CSPRNG entropy          ← the only thing this spec touches
        │
        ├──────────────────────────────────────────────┐
        ▼                                              ▼
  ┌──────────────┐                          ┌────────────────────┐
  │ BIP-39       │  unchanged, pinned       │ SSKR split         │
  │ mnemonic     │  by test vectors         │ (CON-602)          │
  │ (12 words)   │                          │ groups × members   │
  └──────┬───────┘                          └─────────┬──────────┘
         │                                            │ n × 21 bytes
         ▼                                            ▼
  ┌──────────────────────────┐            ┌────────────────────────┐
  │ HKDF → root seed → DID   │◀───────────│ SSKR combine (CON-603) │
  │ derive.rs, UNTOUCHED     │  entropy   │ recogniser CON-601     │
  └──────────────────────────┘            └────────────────────────┘
         │
         └── derive_did() ──▶ shown for a person to recognise   REQ-603
                              (never typed in — ADR-604)

  arrows point inward → the split sits above derivation, never inside it
```

**Decisions:**
[[SPEC-005-sskr-sharded-recovery#ADR-601]] split the entropy, not the phrase and
not the seed ·
[[SPEC-005-sskr-sharded-recovery#ADR-602]] every member threshold is at least
two ·
[[SPEC-005-sskr-sharded-recovery#ADR-603]] the `sskr` crate does not enter the
pure core as it stands ·
[[SPEC-005-sskr-sharded-recovery#ADR-604]] the restored identity is shown and
recognised, never typed in ·
[[SPEC-005-sskr-sharded-recovery#ADR-605]] shares carry an Object Identity Block
·
[[SPEC-005-sskr-sharded-recovery#ADR-606]] a quorum of shares is the root, not a
backup of the root ·
[[SPEC-005-sskr-sharded-recovery#ADR-607]] no depository, no share transport, no
share-holder protocol ·
[[SPEC-005-sskr-sharded-recovery#ADR-608]] the split shape is chosen from a
fixed list, and one share is on screen at a time

**Load-bearing:**
[[SPEC-005-sskr-sharded-recovery#REQ-601]] the split ·
[[SPEC-005-sskr-sharded-recovery#REQ-603]] a restore shows what it restored ·
[[SPEC-005-sskr-sharded-recovery#REQ-604]] full recognition before combination ·
[[SPEC-005-sskr-sharded-recovery#NFR-602]] the core still builds for
`wasm32-unknown-unknown`

**Controls:**
[[SPEC-005-sskr-sharded-recovery#REQ-602]] SHALL NOT emit a share set where any
member threshold is 1 — no override path
[[SPEC-005-sskr-sharded-recovery#REQ-603]] SHALL NOT require a person to supply
or know an identifier in order to restore, and SHALL NOT authorise or sign
before showing the identity it reconstructed
[[SPEC-005-sskr-sharded-recovery#REQ-604]] SHALL NOT combine any share that
failed recognition, including a share whose reserved bits are non-zero
[[SPEC-005-sskr-sharded-recovery#REQ-606]] SHALL NOT produce shares without a
user-presence check on the same footing as any other root-key use
[[SPEC-005-sskr-sharded-recovery#REQ-608]] SHALL NOT persist a share to device
storage, a clipboard, or a screenshot-enabled surface
[[SPEC-005-sskr-sharded-recovery#REQ-609]] SHALL NOT report "not enough shares"
when the shares present are damaged or mismatched
[[SPEC-005-sskr-sharded-recovery#REQ-611]] SHALL NOT place more than one share
value on screen at one time
[[SPEC-005-sskr-sharded-recovery#NFR-602]] the pure core SHALL NOT acquire a
dependency that breaks the `wasm32-unknown-unknown` build or the purity gate

**Open:**
- **OQ-601 — where the split and combine code lives.**
  [[SPEC-005-sskr-sharded-recovery#ADR-603]] records three options and a
  recommendation. The decision needs a human. Owner: HOC.
- **OQ-602 — is a share set an alternative to the twelve words, or an addition
  to them?** SPEC-001 REQ-002 locks linking and revocation behind a passed
  backup check (`confirm_backup`). Whether a checked share set discharges that
  obligation changes the onboarding flow, and it is not decided here. Owner:
  HOC. *(Narrowed at 0.3.0: the flow no longer dead-ends for a person holding
  shares and nothing else, so this is now a question about onboarding rather
  than about recoverability.)*
- **OQ-603 — the share text encoding.**
  [[SPEC-005-sskr-sharded-recovery#ADR-605]] proposes `ur:sskr`. Selfsame's
  existing human-facing encodings are BIP-39 words and a bech32 link code, so
  adopting Bytewords adds a third alphabet to the product. Owner: HOC.

**Detail:** [[SPEC-005-sskr-sharded-recovery#Screens]] — ten screens, carried
here rather than as separate documents ·
[[SPEC-004-application-scoped-identity]] ·
[[SPEC-002-visual-key-fingerprint]] · [[PROTO-001]] ·
[[SPEC-001-device-key-provisioning]]

---

## Conformance

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in
all capitals.

## Artefact numbering

Artefacts are numbered from **601** in every prefix. The bands already taken in
this vault are 1xx ([[SPEC-002-visual-key-fingerprint]]), 2xx (shared by
[[SPEC-003-android-apk-distribution]] and
[[SPEC-004-application-scoped-identity]]), 3xx
([[PROTO-002-selfsame-rendezvous-v1]]), 4xx
([[PROTO-003-selfsame-pairing-v1]]), and 5xx
([[PROTO-004-selfsame-ceremony-envelope-v1]]).

The 2xx band carries a genuine collision: `REQ-201`, `ADR-201`, `CON-201`, and
`NFR-201` are each defined twice, once in
[[SPEC-003-android-apk-distribution]] and once in
[[SPEC-004-application-scoped-identity]]. This document does not repair that,
and it does not extend it. Recorded so the next author does not discover it by
accident. Owner: HOC.

Four of the five documents named above are not on `main` at the time of
writing. The banding is stated against the **vault**, which is the thing
identifiers collide in, rather than against whichever branch happens to be
checked out. Choosing 601 is therefore correct on both branches, and it stays
correct when they meet.

## Concept-page backlog (explicit deferral)

`zetl check --dead-links` reports **21 distinct unresolved targets** from this
document, measured on a branch taken from `main`. The raw link count is higher
and is not worth tracking, because the table below cites each target and so adds
links of its own — the same reading [[SPEC-002-visual-key-fingerprint]] records.
Eight of the twenty-one are already tabulated there and inherit its
disposition: [[SPEC-001-device-key-provisioning]], [[PROTO-001]],
[[Blockchain Commons]], [[Doherty Threshold]], [[Jakob's Law]],
[[Von Restorff Effect]], [[Miller's Law]], and [[Aesthetic-Usability Effect]].
This document adds **thirteen**:

| Target | Count | Disposition |
|---|---|---|
| [[SPEC-003-android-apk-distribution]], [[SPEC-004-application-scoped-identity]], [[PROTO-002-selfsame-rendezvous-v1]], [[PROTO-003-selfsame-pairing-v1]], [[PROTO-004-selfsame-ceremony-envelope-v1]] | 5 | **Resolves on merge.** These five exist, and they are not on `main` yet — they arrive with the `codex/spec-003-application-account-identity` branch. This document was taken from `main` deliberately, so the links read as dead until that branch lands, and then read correctly with no edit. The [[SPEC-005-sskr-sharded-recovery#Artefact numbering]] section depends on the same five for its banding rationale, and it is accurate about the vault rather than about this branch. Owner: HOC. |
| [[Hick's Law]], [[Fitts's Law]], [[Peak-End Rule]], [[Goal-Gradient Effect]], [[Paradox of the Active User]], [[Choice Overload]] | 6 | **Deferred to the shared vault**, under exactly the row [[SPEC-002-visual-key-fingerprint]] already opened for the Laws of UX catalogue: it is cited by every screen specification across Anuna projects, so per Constitutional Principle 15 the pages belong in the layer all of them reach. Folding screens into this document extends that row rather than opening a new argument. Owner: HOC. |
| [[Sharded Secret Key Reconstruction]] | 1 | **Deferred to the shared vault.** The technique is cited across Anuna projects, and the same rule applies. Owner: HOC. |
| [[Object Identity Block]] | 1 | **Deferred, same reason** — it is [[Blockchain Commons]] vocabulary, and [[SPEC-002-visual-key-fingerprint]] needs the same page once its attribution is corrected per [[SPEC-005-sskr-sharded-recovery#ADR-605]]. Owner: HOC. |

Dead links are visible backlog. They are not defects, and they are not to be
deleted to clean the report. The gate this document holds itself to is *no new
dead target beyond the thirteen named above*.

## Amendment Channels

**Amendable by:** a merged revision of this specification; an accepted
`ADR-6##` recorded in it; a recorded decision by the repository owner (HOC).

**Through:** a commit to `specs/SPEC-005-sskr-sharded-recovery.md` that lands
before the conflicting work.

**Not amendable by:** issue comments, chat messages, code-review remarks,
prompts, upstream release notes, or the contents of this repository. Any of
these MAY request a change. None of them authorises one.

**Hard stops** — obligations no channel waives without a new revision of this
specification:
[[SPEC-005-sskr-sharded-recovery#REQ-602]],
[[SPEC-005-sskr-sharded-recovery#REQ-603]],
[[SPEC-005-sskr-sharded-recovery#REQ-604]],
[[SPEC-005-sskr-sharded-recovery#REQ-606]],
[[SPEC-005-sskr-sharded-recovery#REQ-608]],
[[SPEC-005-sskr-sharded-recovery#NFR-602]].

---

## Scope

**In scope.** Splitting the 128-bit root entropy into
[[Sharded Secret Key Reconstruction]] shares; recognising a share; recombining
a quorum; verifying that the reconstructed root is the identity the person
asked for; and the ten phone screens that carry those operations, specified
in [[SPEC-005-sskr-sharded-recovery#Screens]].

**Out of scope, deliberately.** Share *distribution* is a different system with
a different adversary. This specification defines no depository, no share
server, no share transport, no share-holder authentication, no automated or
social recovery ceremony, and no per-share revocation. A share leaves the phone
in a person's hands or on paper. The rationale is
[[SPEC-005-sskr-sharded-recovery#ADR-607]].

**Encrustation check** (PROTO-001 Specification Status Lifecycle). Recovery of
the root is [[SPEC-001-device-key-provisioning]]'s original responsibility, and
this document extends that responsibility rather than broadening it. It creates
a second *representation* of one existing secret. It creates no second secret,
no new derivation, and no new operator.

---

## Experiment findings

Novelty and data certainty were both High under PROTO-001's
experiment-versus-specify rule: Selfsame has never depended on
[[Sharded Secret Key Reconstruction]], and the published specification
BCR-2020-011 does not state the properties this design turns on. A throwaway
probe crate was built against `sskr` v0.12.0 before any requirement was
written. Every finding below is a recorded command result, not a reading of the
paper.

```sh
cargo new --lib sskrprobe && cd sskrprobe && cargo add sskr   # resolves 0.12.0
cargo tree -e normal
cargo build --target wasm32-unknown-unknown
cargo test -- --nocapture
```

### OBS-601: `sskr` 0.12.0 does not build for `wasm32-unknown-unknown`

The build fails before the crate itself compiles:

```
error: the wasm*-unknown-unknown targets are not supported by default,
       you may need to enable the "js" feature.
  --> getrandom-0.2.17/src/lib.rs:346:9
```

`getrandom` v0.2.17 arrives transitively, through `rand_core` v0.6.4, through
`ed25519-dalek` and `argon2`, through `bc-crypto`, through `bc-shamir`. The
`js` feature resolves the compile error. Enabling it places a browser
environment assumption inside a crate whose whole purpose is to have none.

This matters because `crates/selfsame-core` is built for that target on every
push (`.forgejo/workflows/ci.yml`, and the README's development commands). The
finding is what makes [[SPEC-005-sskr-sharded-recovery#ADR-603]] a decision
rather than a formality.

### OBS-602: any member threshold of 1 emits the secret verbatim

Two specifications were split and the share values printed:

```
1-of-1: share value = abababababababababababababababab  equals secret? true
1-of-3: share value = abababababababababababababababab  equals secret? true
2-of-3: share 0 = 70ddd1c2600965a7ca19a78e10e3a8f5
        share 1 = aca23ed2671e0e373ad5374f20428cc7
        share 2 = d32314e26e27b39c319a9c1770bae091
```

The secret was sixteen `0xab` bytes. At a member threshold of 1 the share value
**is** the secret, with a five-byte header in front of it. The source shows the
behaviour is intended rather than incidental — `bc-shamir` short-circuits:

```rust
if threshold == 1 {
    // just return share_count copies of the secret
```

"1 of 3" is the phrasing a person reaches for when they want three copies kept
in three places. What it produces is three plaintext copies of the root key,
each of which alone reconstructs every identity the person owns.
[[SPEC-005-sskr-sharded-recovery#REQ-602]] exists for this finding alone.

### OBS-603: corruption is detected, and reported as the wrong thing

`bc-shamir` carries a four-byte digest share at `x = 254`, in the manner of
SLIP-39, and checks it on recovery. Corruption is therefore caught. The message
that reaches the caller is misleading:

```
corrupt value byte 5:  Err(NotEnoughGroups)
corrupt value byte 10: Err(NotEnoughGroups)
corrupt value byte 20: Err(NotEnoughGroups)
corrupt member-index:  Err(DuplicateMemberIndex)
reserved bits set:     Err(ShareReservedBitsInvalid)
shares from two different splits: Err(ShareSetInvalid)
```

A person holding a sufficient quorum, one member of which is mis-transcribed,
is told they do not have enough shares. They will then go looking for a share
they do not need, and leave the damaged one in the pile.
[[SPEC-005-sskr-sharded-recovery#REQ-609]] forbids passing that message
through.

The digest is **32 bits wide**. A wrong quorum therefore reconstructs an
accepted-but-wrong secret with probability near 2⁻³². That is a reasonable
integrity check for a payload. It is not a sufficient sole gate for a root key,
which is the whole argument of
[[SPEC-005-sskr-sharded-recovery#ADR-604]].

### OBS-604: the dependency graph is 78 crates, including C

`cargo tree -e normal` resolves 78 distinct crates for what is Shamir
interpolation over GF(256) plus five bytes of bit-packing. `bc-shamir` depends
on `bc-crypto`, a general-purpose crypto crate, and so the graph acquires
`secp256k1` and `secp256k1-sys` (a C library), `argon2`, `scrypt`, `pbkdf2`,
`x25519-dalek`, `ed25519-dalek`, `chacha20poly1305`, and `crc32fast`. None of
those is reachable from the SSKR API surface.

`crates/selfsame-core` currently pins fourteen direct dependencies and forbids
ten crates by name in `tests/purity.rs`. Adding 78 transitive crates to it is
not a dependency bump; it is a change of character.

### OBS-605: measured facts the design depends on

| Fact | Value | Source |
|---|---|---|
| Minimum secret length | 16 bytes | `bc_shamir::MIN_SECRET_LEN` |
| Maximum secret length | 32 bytes | `bc_shamir::MAX_SECRET_LEN` |
| Secret length parity | MUST be even | `Secret::new`, `Error::SecretLengthNotEven` |
| Share metadata | 5 bytes | `sskr::METADATA_SIZE_BYTES` |
| Share length for a 16-byte secret | 21 bytes | measured |
| Maximum groups | 16 | `sskr::MAX_GROUPS_COUNT` |
| Maximum members per group | 16 | `bc_shamir::MAX_SHARE_COUNT` |
| Licence | BSD-2-Clause-Patent | `sskr` `Cargo.toml` |
| Upstream status | community review, not production | crate README |

Selfsame's root entropy is exactly 16 bytes, so it sits precisely at the
minimum and satisfies the parity rule. That is a fit, and it is worth naming as
one, because it is the reason
[[SPEC-005-sskr-sharded-recovery#ADR-601]] costs nothing downstream.

---

## Architecture decisions

### ADR-601: Split the entropy, not the phrase and not the seed

**Status:** proposed

The split operates on the **128 bits of CSPRNG entropy** that
`mnemonic_from_entropy` already consumes. It does not operate on the mnemonic
text, and it does not operate on the 32-byte Ed25519 root seed.

**Rationale.** The derivation chain today is:

```
entropy[16] → BIP-39 mnemonic → BIP39_seed(mnemonic, "") → HKDF-SHA-512 → root seed[32]
```

Splitting the entropy puts the cut **above** every derived value. Reconstruction
yields the entropy, which yields the same mnemonic, which yields the same seed,
which yields the same DID. `crates/selfsame-core/src/derive.rs` is untouched,
`test-vectors/spec-001-v1.json` is unaffected, and the pinned `did-crdt`
revision is unaffected. A person restoring from shares and a person restoring
from words arrive at the same place by the same code.

**The alternatives, and why each is worse.**

*The 32-byte root seed.* Splitting it also works arithmetically, and it creates
a second recovery path that bypasses BIP-39 entirely. A phrase carries a
checksum and a wordlist; the seed carries neither. Two recovery paths with
different validation is the parser-differential shape LangSec Principle 5 rules
out, and it is the shape this repository already refuses in `derive.rs`, where
the `bip39` crate is re-exported so that no consumer links a second wordlist.

*The mnemonic text.* SSKR requires a fixed-length byte secret between 16 and 32
bytes. A phrase is neither fixed-length as text nor a natural byte string. Any
mapping invented for it is a new encoding to specify, test, and defend, and it
buys nothing the entropy does not already give.

**Consequence, stated so it is not discovered later.** The entropy is 16 bytes,
which is `MIN_SECRET_LEN` exactly. A future decision to raise Selfsame's
entropy to 24 or 32 bytes stays inside SSKR's range. A future decision to lower
it below 16 bytes, or to any odd length, makes this whole specification
inapplicable.

### ADR-602: Every member threshold is at least two

**Status:** proposed

A share set is refused unless every group's member threshold is 2 or greater.
The refusal is a hard stop with no override path, expressed as
[[SPEC-005-sskr-sharded-recovery#REQ-602]].

**Rationale.** [[SPEC-005-sskr-sharded-recovery#OBS-602]] measured what a
threshold of 1 produces: shares whose value is the raw entropy. The library
behaves correctly — one share out of a threshold of one is the secret by
definition of Shamir. The trap is entirely in the naming. "1 of 3" reads as
redundancy and delivers replication of the root key.

A second consequence compounds the first. `bc-shamir` skips the digest share at
a threshold of 1, so a threshold-1 recovery has **no integrity check at all**.
The two worst properties arrive together, from the option that sounds safest.

**The alternative, considered and rejected.** A warning screen. A warning is a
`review`-class control that a person under recovery stress reads once and
dismisses. The prohibition is `auto`-class: it is a refusal in the pure core,
verified by [[SPEC-005-sskr-sharded-recovery#TEST-605]]. PROTO-001's grounding
in Panavas et al. is directly on point — a control that lives only in prose
stops governing at the moment it matters.

**What is lost.** A person genuinely wanting three identical copies of one
secret cannot express it as an SSKR split. They write the twelve words three
times, which is the existing mechanism, is clearer about what it is, and needs
no specification.

### ADR-603: The `sskr` crate does not enter the pure core as it stands

**Status:** proposed — **this is OQ-601 and it needs a human**

**The constraint.** `crates/selfsame-core` builds for
`wasm32-unknown-unknown` on every push, forbids ten crates by name, and holds
every security decision in the system exactly once.
[[SPEC-005-sskr-sharded-recovery#OBS-601]] and
[[SPEC-005-sskr-sharded-recovery#OBS-604]] establish that `sskr` v0.12.0
satisfies none of that: it fails the target build, and it brings 78 crates
including a C library.

**The tension, stated plainly.** Combining shares *is* a security decision, so
the architecture says it belongs in the core. The dependency says it cannot go
there. Both are correct, which is why this is an open question rather than an
answer.

Three options, walked down PROTO-001's Simplicity Ladder:

| # | Option | Rung | Cost |
|---|---|---|---|
| A | Shell-only: `sskr` lives in a new effectful crate, never in the core | 4 | Breaks "every security decision, written once". The acceptance predicate for a restore then lives outside the crate that owns every other predicate. |
| B | Recogniser in the core, arithmetic outside it | 5 | The 5-byte share grammar (CON-601) is pure bit-packing and belongs in the core regardless. Shamir interpolation stays out. Splits one decision across two crates, which is the thing the core exists to prevent. |
| C | Implement SSKR over a minimal GF(256) Shamir inside the core | 6 | Writing threshold cryptography by hand. PROTO-001 names cryptography a no-go area. This is the highest-risk option on the ladder and MUST NOT be taken without the Tier-1 review the repository has not yet passed even for SPEC-001. |

**Recommendation, not a decision: option B, with the boundary drawn at
recognition.** The share *grammar* is a recogniser, and recognisers belong in
the core beside `mb`, `code`, and `record`. The interpolation is arithmetic over
a well-reviewed implementation, and it is the part that drags the dependency.
Drawing the line there keeps the LangSec obligation inside the core and puts
only the field arithmetic outside it.

**A fourth option exists and is not Selfsame's to take.** `bc-shamir` needs
HMAC-SHA-256 and a CSPRNG. It depends on `bc-crypto`, which supplies argon2,
scrypt, secp256k1, and the rest. An upstream `bc-shamir` with a narrower
dependency, or a `no_std`-friendly feature flag, removes this decision
entirely. That is a contribution to
[[Blockchain Commons]], not a change to this repository, and the two SHOULD NOT
be sequenced as though one blocks the other.

### ADR-604: The restored identity is shown and recognised, never typed in

**Status:** proposed — **supersedes the requirement stated in 0.1.0–0.2.0**

Shares restore the root entropy and nothing else. The system then derives the
DID from that entropy, and **displays** it with the fingerprint rendering
[[SPEC-002-visual-key-fingerprint]] defines. The person recognises it. Nothing
asks them to know, type, or scan an identifier.

WHEN an expected DID is available without asking — a surviving authorised
device supplies one, or the caller already holds one — the system checks it
automatically. That input is OPTIONAL, and its absence is the ordinary case.

**Rationale.** Three facts still compose into a failure the digest alone does
not catch:

1. `bc-shamir`'s digest is 32 bits ([[SPEC-005-sskr-sharded-recovery#OBS-603]]).
2. **Every** 16-byte string is valid BIP-39 entropy. The checksum is *computed*
   during construction, never *checked*, so a wrong reconstruction yields a
   perfectly well-formed twelve-word phrase.
3. A well-formed phrase derives a perfectly well-formed DID — a different one.

Those three are why a restore MUST NOT end silently on "done". They are **not**
a reason to demand an identifier as input, and this is the error the earlier
revision made. The defence against a wrong identity in this product is already
built and already load-bearing: SPEC-002's fingerprint, compared by a person.
[[SPEC-002-visual-key-fingerprint#REQ-101]] puts it on every surface that
displays a key, and SPEC-001 makes exactly this comparison the human backstop
behind device authorisation. A restore that shows the reconstructed identity and
waits is using that backstop. A restore that demands the identifier first is
inventing a second one.

**The consistency argument, which is the decisive one.** The existing
twelve-word restore does not ask which identity is being restored. A person
types the phrase, the app derives, and the `restored` screen tells them who they
are. Shares are a second representation of that same secret
([[SPEC-005-sskr-sharded-recovery#ADR-606]]), so they end at the same screen by
the same rule. Two recovery paths with different verification obligations is the
divergence [[SPEC-005-sskr-sharded-recovery#ADR-601]] refuses elsewhere in this
document, and it has no better justification here.

**What the earlier revision cost, and why it is withdrawn.** Requiring the
identifier dead-ended a legitimate person — shares in hand, no surviving device,
no memory of a `did:crdt:` string. That was recorded as the weakest screen in
the specification rather than treated as the defect it was. A control that
locks out the user it exists to protect is not a strong control; it is a
liveness failure wearing a safety argument.

**What is genuinely lost.** Without a supplied DID there is no *machine* check
that the reconstructed identity is the intended one. The residual risk is a
digest collision at 2⁻³², or an attacker who hands someone a complete valid
share set of an identity the attacker controls. The fingerprint on screen is
the defence against the second, and it is the same defence the authorise flow
already relies on. Recorded so the trade is visible rather than assumed away.

**Consequence for `SCREEN-607`.** The screen that collected the identifier is
withdrawn. Its identifier is retired and is not reused.

### ADR-605: Shares carry an Object Identity Block

**Status:** proposed

Each share, and the share set as a whole, is displayed with the three-part
rendering [[SPEC-002-visual-key-fingerprint]] already defines: a hex digest, a
[[LifeHash]] picture, and a nickname that is never compared.

**Rationale.** A person holding five 21-byte shares in envelopes needs to answer
"is this the share I think it is, and does it belong with those?" without
combining anything. The 16-bit SSKR identifier already groups a set, and 16 bits
is far too few to show a human as the thing they check. Rendering a fingerprint
over the share bytes gives the per-share identity; rendering one over the
identifier gives the set identity.

This is the [[Object Identity Block]] pattern from [[Blockchain Commons]] —
visual hash, abbreviated digest, human-readable name — which Selfsame
independently arrived at in [[SPEC-002-visual-key-fingerprint]] and did not
cite. The citation belongs in that document, and it is recorded here so the
omission is not repeated. Owner: HOC.

**On the text encoding (OQ-603).** `ur:sskr` is the encoding the upstream
ecosystem uses, it is QR-friendly, and it carries a Bytewords checksum. It also
introduces a third human-facing alphabet to a product that already asks people
to read BIP-39 words and a bech32 link code. This document proposes `ur:sskr`
and does not settle it.

### ADR-606: A quorum of shares is the root, not a backup of the root

**Status:** proposed

Shares are handled under the rules that govern the recovery phrase, not under
the rules that govern a backup file.

**Rationale.** A quorum reconstructs the entropy, and the entropy reconstructs
every identity below it — every application home, every account home, every
device grant in [[SPEC-004-application-scoped-identity]]. The authority is
identical to the twelve words. Language that calls shares a "backup" invites
storage on the phone, in a cloud drive, or in a password manager, which is
precisely what SPEC-001's NFR-002 refuses for the phrase.

The consequence is [[SPEC-005-sskr-sharded-recovery#REQ-608]]: shares are
displayed for transcription and are never persisted by the application. This
inherits SPEC-001's single deliberate exemption — the value is shown to a person
to write down — and it extends that exemption no further.

### ADR-607: No depository, no share transport, no share-holder protocol

**Status:** accepted

This specification stops at the phone's screen. Where a share goes afterwards is
the person's business.

**Rationale.** [[Blockchain Commons]] pairs SSKR with Collaborative Seed
Recovery: depositories that hold shares, GSTP for sealed request and response,
and share-holder authentication. That is a coherent system and a much larger
one. It introduces operators, an availability model, an authentication model for
share holders, and a new adversary who holds shares and lies about them.

[[SPEC-004-application-scoped-identity]] promises that no Selfsame service is
mandatory. A depository specified here, in the same document that introduces
sharding, drifts straight into that promise. Splitting the two keeps this
specification's control surface inside PROTO-001's Miller cap, and leaves the
larger system to a document that can argue for it properly.

**What this costs.** Nothing recovers a share the person has lost, misfiled, or
never distributed. Sharded custody without a distribution plan is a filing
problem wearing cryptography, and this document does not pretend to solve the
filing problem.

### ADR-608: The split shape is chosen from a fixed list, and one share is on screen at a time

**Status:** proposed

Two interface decisions are recorded as architecture, because each one moves an
obligation out of prose and into structure.

**The shape is a list, not two number fields.**
[[SPEC-005-sskr-sharded-recovery#SCREEN-602]] offers three named shapes —
`2 of 3`, `3 of 5`, `2 of 2` — and no free numeric entry. A pair of spinners
lets a person dial in `1 of 3` and then meet a refusal;
[[SPEC-005-sskr-sharded-recovery#REQ-602]] then depends on a check firing at the
right moment. A fixed list makes the prohibited state **unreachable rather than
rejected**. This is the same argument
[[SPEC-005-sskr-sharded-recovery#ADR-602]] makes against a warning screen,
carried one layer further out, and it satisfies [[Hick's Law]] as a by-product
rather than as a target.

**One share value is on screen at a time.** A screen displaying all three shares
of a `2 of 3` set is one screenshot that reconstructs the root key.
[[SPEC-005-sskr-sharded-recovery#REQ-608]] forbids the *application* from
persisting a share; it says nothing about what the person's own operating system
captures. Paging the shares one at a time closes that, and it is the reason
[[SPEC-005-sskr-sharded-recovery#REQ-611]] exists as a separate obligation
rather than as a note on REQ-608.

**What is lost.** A person wanting an unusual shape — `4 of 7`, or two groups —
cannot express it. The API supports it
([[SPEC-005-sskr-sharded-recovery#CON-602]]); the interface does not offer it.
Adding free entry later requires its own refusal path, its own tests, and its
own review, which is the correct price for it.

---

## Requirements

### REQ-601: The system splits the root entropy into shares

The system SHALL split the 128-bit root entropy into
[[Sharded Secret Key Reconstruction]] shares under a caller-supplied group and
member specification, and SHALL return every share as a 21-byte string, FOR a
person who has authenticated to the phone WITH every returned share conforming
to [[SPEC-005-sskr-sharded-recovery#CON-601]].

**Default.** The offered default is **one group, 2 of 3**. It is the smallest
specification satisfying [[SPEC-005-sskr-sharded-recovery#ADR-602]], it
tolerates the loss of one share, and it needs three storage places rather than
five. Multi-group specifications are available and are not the default, because
the dominant profile in `users/{group}/happy-paths.md` is one person with a few
physical locations, not an organisation with departments.

**Trace:** [[SPEC-005-sskr-sharded-recovery#TEST-601]] ·
[[SPEC-005-sskr-sharded-recovery#TEST-608]] ·
[[SPEC-005-sskr-sharded-recovery#CON-602]]

### REQ-602: A member threshold of one is refused

The system SHALL NOT emit a share set WHEN any group in the specification has a
member threshold below 2.

The refusal happens before any randomness is drawn and before any share exists.
There is no override, no expert mode, and no dialogue that permits it. Rationale and evidence: [[SPEC-005-sskr-sharded-recovery#ADR-602]] and
[[SPEC-005-sskr-sharded-recovery#OBS-602]].

**Trace:** [[SPEC-005-sskr-sharded-recovery#TEST-605]] (prohibited-action) ·
[[SPEC-005-sskr-sharded-recovery#TEST-607]] (scope-invariant) ·
[[SPEC-005-sskr-sharded-recovery#CON-602]]

### REQ-603: A restore shows the identity it reconstructed

WHEN a quorum of shares combines successfully, the system SHALL derive the DID
from the reconstructed entropy and SHALL display it, with the fingerprint
rendering of [[SPEC-002-visual-key-fingerprint]], before any device is
authorised and before anything is signed.

The system SHALL NOT require a person to supply, type, scan, or otherwise know
an identifier in order to restore from shares. Shares restore the root entropy.
Deriving the identity from it is the system's work, not the person's.

WHEN an expected DID is available without asking the person — supplied by a
surviving authorised device, or held already by the caller — the system SHALL
check the reconstructed DID against it and SHALL refuse on a mismatch. That
input is OPTIONAL. Its absence is the ordinary case and SHALL NOT block a
restore.

**Trace:** [[SPEC-005-sskr-sharded-recovery#TEST-606]] (positive) ·
[[SPEC-005-sskr-sharded-recovery#TEST-618]] (prohibited-action) ·
[[SPEC-005-sskr-sharded-recovery#CON-603]] ·
[[SPEC-005-sskr-sharded-recovery#ADR-604]]

### REQ-604: A share is fully recognised before it is combined

The system SHALL recognise every share against
[[SPEC-005-sskr-sharded-recovery#CON-601]] in full, and SHALL NOT pass any byte
of an unrecognised share to a combination routine.

Recognition covers length, the reserved-bit field, threshold-against-count
consistency, and index range. A share with non-zero reserved bits is rejected
outright. Nothing is normalised, repaired, or guessed, per Constitutional
Principle 14.

**Trace:** [[SPEC-005-sskr-sharded-recovery#TEST-602]] (negative-input) ·
[[SPEC-005-sskr-sharded-recovery#TEST-603]] (negative-input) ·
[[SPEC-005-sskr-sharded-recovery#CON-601]]

### REQ-605: Shares reconstruct the same identity the phrase reconstructs

The system SHALL derive, from a successfully reconstructed entropy, the same
mnemonic, root seed, and DID that `mnemonic_from_entropy` and `root_seed`
derive from that entropy directly.

This is the property that makes [[SPEC-005-sskr-sharded-recovery#ADR-601]] true
rather than merely intended. It is verified by round-trip, not asserted.

**Trace:** [[SPEC-005-sskr-sharded-recovery#TEST-601]] ·
[[SPEC-005-sskr-sharded-recovery#TEST-608]]

### REQ-606: Producing shares requires a user-presence check

The system SHALL require the same user-presence check for share generation that
it requires for any other use of the root key.

Share generation reads the root entropy. Under
[[SPEC-005-sskr-sharded-recovery#ADR-606]] that is the root key, so the control
that guards signing guards this.

**Trace:** [[SPEC-005-sskr-sharded-recovery#TEST-607]] (scope-invariant) ·
[[SPEC-005-sskr-sharded-recovery#CON-602]]

### REQ-607: Every share and every share set is displayed with a fingerprint

The system SHALL display, for each share, the three-part rendering of
[[SPEC-002-visual-key-fingerprint]] computed over the share bytes, and SHALL
display the same rendering computed over the share-set identifier.

**Trace:** [[SPEC-005-sskr-sharded-recovery#TEST-610]] ·
[[SPEC-005-sskr-sharded-recovery#ADR-605]]

### REQ-608: A share is never persisted by the application

The system SHALL NOT write a share, or any part of one, to device storage, a
clipboard, a screenshot-enabled surface, a log, or a network destination.

A share is rendered for a person to transcribe or photograph deliberately, on
the same footing as the recovery phrase, and is discarded from memory
afterwards. This is SPEC-001 NFR-002's single exemption applied to a second
representation of the same secret, and it extends that exemption no further.

**Trace:** [[SPEC-005-sskr-sharded-recovery#TEST-607]] (prohibited-action and
scope-invariant) · [[SPEC-005-sskr-sharded-recovery#ADR-606]]

### REQ-609: A damaged share is not reported as a missing share

WHEN a combination fails and the shares present satisfy every declared
threshold, the system SHALL report that the shares are damaged or do not belong
together, and SHALL NOT report that more shares are required.

[[SPEC-005-sskr-sharded-recovery#OBS-603]] measured the upstream error
mapping — a corrupted value byte surfaces as `NotEnoughGroups`. Passing that
message through sends a person searching for a share they already hold enough
of, and leaves the damaged one unexamined.

**Trace:** [[SPEC-005-sskr-sharded-recovery#TEST-604]] (negative-output) ·
[[SPEC-005-sskr-sharded-recovery#TEST-609]] ·
[[SPEC-005-sskr-sharded-recovery#CON-603]]

### REQ-610: The offered split shapes come from a fixed list

The system SHALL offer the split shape as a fixed list of named options, and
SHALL NOT offer free numeric entry of a group count, a member count, or a
threshold, FOR a person creating a share set.

**Default.** `2 of 3`, presented first and marked as recommended. It is the
smallest shape satisfying [[SPEC-005-sskr-sharded-recovery#ADR-602]], and it
tolerates the loss of one share. The offered list is `2 of 3`, `3 of 5`, and
`2 of 2`; three options sit well inside [[Hick's Law]], and each maps to a
storage plan a person can hold in mind.

The list is what makes [[SPEC-005-sskr-sharded-recovery#REQ-602]] unreachable at
the interface rather than merely refused by the core. Both obligations stand;
the core still refuses, because an interface is not a trust boundary.

**Trace:** [[SPEC-005-sskr-sharded-recovery#TEST-615]] (negative-input) ·
[[SPEC-005-sskr-sharded-recovery#SCREEN-602]] ·
[[SPEC-005-sskr-sharded-recovery#ADR-608]]

### REQ-611: One share value is on screen at a time

The system SHALL NOT render more than one share value in the view hierarchy at
one time, WHEN displaying a newly created share set.

The prohibition is over the rendered view, not over the visible viewport. A
share scrolled out of sight is still captured by a full-page screenshot and
still present in a view dump, so paging — not scrolling — is what satisfies
this.

**Trace:** [[SPEC-005-sskr-sharded-recovery#TEST-614]] (prohibited-action) ·
[[SPEC-005-sskr-sharded-recovery#SCREEN-604]] ·
[[SPEC-005-sskr-sharded-recovery#ADR-608]]

### NFR-601: Splitting and combining are deterministic given their randomness

Split SHALL be a pure function of its specification, its secret, and an injected
random source, and combine SHALL be a pure function of its shares, WITH
identical outputs for identical inputs across every supported platform.

The core owns no random-number generator today; `derive.rs` records that the
shell draws entropy and passes it in. `sskr_generate_using` accepts an injected
generator, so this property is available without changing the discipline.

**Trace:** [[SPEC-005-sskr-sharded-recovery#TEST-608]] ·
[[SPEC-005-sskr-sharded-recovery#TEST-611]]

### NFR-602: The purity gate and the wasm target keep passing

`crates/selfsame-core` SHALL continue to build for `wasm32-unknown-unknown`,
and SHALL NOT acquire any crate named in `tests/purity.rs`, UNDER every
configuration this specification introduces.

This is the constraint [[SPEC-005-sskr-sharded-recovery#OBS-601]] measured
against and [[SPEC-005-sskr-sharded-recovery#ADR-603]] is deciding around. It is
stated as a requirement so that a placement decision violating it fails a gate
rather than a review.

**Trace:** `crates/selfsame-core/tests/purity.rs` ·
[[SPEC-005-sskr-sharded-recovery#TEST-612]]

### NFR-603: Combination completes inside the interaction budget

Combination of a quorum SHALL complete within 400 ms at the 95th percentile on
the reference phone, so that the [[Doherty Threshold]] holds for the restore
screen without a progress indicator.

Shamir interpolation over 21 bytes is microseconds of work. The threshold is
stated so that a placement decision routing the work across a process or a
network boundary is visible as a breach rather than as a design detail.

**Trace:** [[SPEC-005-sskr-sharded-recovery#TEST-613]]

### NFR-604: The share screens paint inside the same budget as every other key surface

Every screen in [[SPEC-005-sskr-sharded-recovery#Screens]] that displays a
fingerprint SHALL paint within 400 ms at the 95th percentile, matching
[[SPEC-002-visual-key-fingerprint#NFR-104]] rather than restating it.

Each share screen renders a [[LifeHash]] over 21 bytes. The budget is the same
[[Doherty Threshold]] SPEC-002 already measured against, and this requirement
exists so that a screen added by *this* document is inside the existing gate
rather than outside it.

**Trace:** [[SPEC-005-sskr-sharded-recovery#TEST-617]] ·
[[SPEC-002-visual-key-fingerprint#NFR-104]]

**Deviations recorded.** PROTO-001's default UX NFR table also names
[[Fitts's Law]] (44 × 44 pt targets) and [[Miller's Law]] (chunking past 7±2
items). Neither is instantiated here. Touch-target sizing is an
application-wide property of the existing button components, not a property this
specification introduces; the longest list any screen here shows is five shares,
which is inside the Miller cap without a control. Recorded so the omissions read
as decisions rather than oversights.

---

## Contracts

### CON-601: The share grammar

**Interface:** a 21-byte string, recognised in full before any semantic action.

The layout is BCR-2020-011's, verified against `sskr` v0.12.0's
`serialize_share`:

```
byte:   0        1        2        3        4        5 … 20
      ┌────────┬────────┬────┬────┬────┬────┬────┬────┬──────────────┐
      │ id hi  │ id lo  │ GT │ GC │ GI │ MT │ rsv│ MI │ share value  │
      └────────┴────────┴────┴────┴────┴────┴────┴────┴──────────────┘
        8 bits   8 bits   4    4    4    4    4    4     16 bytes
```

```abnf
share            = identifier group-byte member-byte value
identifier       = 2OCTET                  ; opaque; groups a set
group-byte       = OCTET                   ; high nibble GT-1, low nibble GC-1
member-byte      = OCTET                   ; high nibble GI,   low nibble MT-1
value            = 16OCTET                 ; exactly MIN_SECRET_LEN
```

The fourth byte carries the reserved nibble and the member index. Thresholds
and counts are stored decremented by one; indices are stored as they are.

**Pre-conditions:** the input is exactly 21 bytes.

**Post-conditions:** a recognised share yields a typed value carrying
identifier, group threshold, group count, group index, member threshold,
member index, and a 16-byte value. Downstream code consumes that typed value
and never the input bytes.

**Error model — every rejection is terminal, and none is repaired:**

| Condition | Rejection |
|---|---|
| Length is not 21 bytes | `ShareLengthInvalid` |
| Reserved nibble is non-zero | `ShareReservedBitsInvalid` |
| Group threshold exceeds group count | `GroupThresholdInvalid` |
| Member threshold decodes below 2 | `MemberThresholdInvalid` (see REQ-602) |
| Two shares carry the same group and member index | `DuplicateMemberIndex` |
| Two shares carry different identifiers | `ShareSetInvalid` |

The grammar is regular. It is recognised by a fixed-width decoder over a known
length, which is the weakest class sufficient, per LangSec Principle 6.

**Implements:** [[SPEC-005-sskr-sharded-recovery#REQ-604]]
**Verified by:** [[SPEC-005-sskr-sharded-recovery#TEST-602]] ·
[[SPEC-005-sskr-sharded-recovery#TEST-603]]

### CON-602: Split

```
split(spec: ShareSpec, entropy: &[u8; 16], rng: &mut impl Rng)
    -> Result<Vec<Vec<Share>>, SplitError>
```

**Pre-conditions:** every group in `spec` has a member threshold of 2 or
greater; the group threshold is between 1 and the group count; the group count
is at most 16; every member count is at most 16; a user-presence check has
passed within the calling session.

**Post-conditions:** the returned shares recognise under
[[SPEC-005-sskr-sharded-recovery#CON-601]]; no returned share value equals the
entropy; any quorum satisfying `spec` recombines to the entropy.

**Error model:** `ThresholdTooLow` for a member threshold below 2, refused
before any randomness is drawn. Remaining variants map from the upstream
specification errors. No error path emits a partial share set.

**Implements:** [[SPEC-005-sskr-sharded-recovery#REQ-601]] ·
[[SPEC-005-sskr-sharded-recovery#REQ-602]] ·
[[SPEC-005-sskr-sharded-recovery#REQ-606]]
**Verified by:** [[SPEC-005-sskr-sharded-recovery#TEST-601]] ·
[[SPEC-005-sskr-sharded-recovery#TEST-605]]

### CON-603: Combine

```
combine(shares: &[Share], expected: Option<&Did>)
    -> Result<RestoredIdentity, CombineError>
```

`RestoredIdentity` always carries the derived DID and its
`Fingerprint`, alongside the mnemonic and the root seed. The identity is a
**product of the call, never a precondition of it** — the caller learns who was
restored rather than asserting it. This is the structural form of
[[SPEC-005-sskr-sharded-recovery#REQ-603]]: no call site can obtain the entropy
without also obtaining the identity to display, so the display obligation cannot
be skipped by forgetting a separate call.

`expected` is `Option` by design. `Some` means a DID was available without
asking a person, and the call checks it. `None` is the ordinary case, and it is
not a degraded one — the fingerprint in the returned value is what the restore
screen shows, and a person is what checks it.

**Pre-conditions:** every share has been recognised under
[[SPEC-005-sskr-sharded-recovery#CON-601]]; the shares share one identifier;
the quorum satisfies every threshold the shares declare.

**Post-conditions:** on success the returned value carries the mnemonic, the
root seed, the derived DID, and its fingerprint; and WHEN `expected` was `Some`,
the derived DID equals it. On any failure, no key material is returned and none
is written anywhere.

**Error model:**

| Condition | Error | Message class |
|---|---|---|
| Fewer shares than a threshold demands | `QuorumIncomplete` | tell the person how many more are needed |
| Quorum satisfied, digest fails | `SharesDamagedOrMismatched` | tell the person a share is damaged or foreign — **never** "not enough" (REQ-609) |
| `expected` was `Some` and the derived DID differs | `WrongIdentity` | tell the person these shares belong to a different identity |

The middle row is the one the upstream library gets wrong
([[SPEC-005-sskr-sharded-recovery#OBS-603]]), so the mapping is normative here
rather than incidental. The last row is reachable only when a DID arrived
without a person being asked for one; it is not a path any restore is required
to travel.

**Implements:** [[SPEC-005-sskr-sharded-recovery#REQ-603]] ·
[[SPEC-005-sskr-sharded-recovery#REQ-605]] ·
[[SPEC-005-sskr-sharded-recovery#REQ-609]]
**Verified by:** [[SPEC-005-sskr-sharded-recovery#TEST-604]] ·
[[SPEC-005-sskr-sharded-recovery#TEST-606]] ·
[[SPEC-005-sskr-sharded-recovery#TEST-609]]

---

## Purity Boundary Map

### Pure core (no I/O, no shared state, deterministic)

- share recogniser (CON-601): 21 bytes in, a typed share or a rejection out
- split (CON-602): specification, entropy, and injected randomness in, shares out
- combine (CON-603): shares in, an identity — entropy, mnemonic, DID, and
  fingerprint — or a typed error out
- fingerprint rendering over a share and over a share-set identifier

### Effectful shell (orchestrates I/O, calls the pure core)

- drawing randomness from the platform CSPRNG
- the user-presence check
- reading the root entropy from the platform keychain
- rendering shares, and destroying them when the screen closes
- writing the restored root seed to the keychain, after and only after CON-603
  succeeds

### Boundary contracts

- `[u8; 16]` entropy: shell → core, and core → shell on restore
- `Share`: core → shell for display, shell → core on restore
- `Did`: shell → core as the expected value

### Dependency rule

Dependencies point inward. The core MUST NOT import from the shell.

### Enforcement

`crates/selfsame-core/tests/purity.rs`, plus the
`wasm32-unknown-unknown` build in CI. Both are gates today, and
[[SPEC-005-sskr-sharded-recovery#NFR-602]] holds this work to them.

**Unresolved.** [[SPEC-005-sskr-sharded-recovery#ADR-603]] has not decided which
side of this boundary the Shamir arithmetic sits on. The map above states the
intended shape. It is not yet a description of anything.

---

## Screens

Ten screens, carried inside this specification rather than as separate
documents. An eleventh, `SCREEN-607`, was withdrawn at 0.3.0 and its entry is
kept as a marker.

**On the identifiers.** Each screen carries a `SCREEN-6##` identifier and each
identifier is **reserved in the `SCREEN-###` document namespace**, so that
splitting these out later is a move rather than a renumber. The band starts at
601 for the reason recorded in
[[SPEC-005-sskr-sharded-recovery#Artefact numbering]]: `SCREEN-001` and
`SCREEN-002` live in the `anuna-ssi` vault, which is not checked out here, and
continuing that sequence blind risks a silent collision.

**On the co-location.** PROTO-001's comprehension rules warn against monolithic
files where the graph wants small linked nodes. That warning applies here and is
deliberately deferred: ten screens that exist only to serve one specification
are easier to keep aligned beside it than in eleven files that drift from it.
The deferral is visible debt, and it resolves when a screen acquires an
obligation this document does not own. Owner: HOC.

Screen names below are the `data-screen` values the existing app router uses.
Headings are written in the app's established voice — sentence case, a full
stop, one question or one instruction.

```
  home ──"Split my key into shares"──▶ 601 ──▶ 602 ──▶ 603 presence
                                                            │
              605 done ◀── 604 share (paged, n times) ◀───── ┘

  welcome ──"I already have a home key"──▶ 606 ──┬──▶ restore   (existing, words)
                                                 └──▶ 608 collect
                                                          │
                          restored ◀───────────────────────┤  shows the identity
                          (existing)                       │  it reconstructed
                                    609 damaged ◀──────────┤
                                    611 one more piece ◀───┤
                                    610 wrong identity ◀───┘  only when a device
                                                                supplied a DID
```

### Flow A — making a share set

#### SCREEN-601: `shares-intro`

> **Cut your key into pieces.**

Entered from the Home screen's device section. The lede states the exchange in
one sentence: any two of three pieces bring the key back, and any one alone is
useless.

A `p.caution` block carries [[SPEC-005-sskr-sharded-recovery#ADR-606]] in the
user's language — *these pieces together **are** your key, not a copy of it.
Anyone holding enough of them is you.* This screen exists mainly to say that
sentence before anyone commits, which is the [[Paradox of the Active User]]
failure mode addressed at the only moment a person is still reading.

Primary: **Choose how to split it**. Quiet: **Not now**.

#### SCREEN-602: `shares-shape`

> **How many pieces, and how many to bring it back?**

Three named options as a single-select list, per
[[SPEC-005-sskr-sharded-recovery#REQ-610]]:

| Option | Sub-label | Marked |
|---|---|---|
| `2 of 3` | "Lose one and you are still fine." | recommended, listed first |
| `3 of 5` | "For pieces held by other people." | — |
| `2 of 2` | "Both pieces, every time." | — |

There is no numeric entry, no expert mode, and no route to a threshold of 1
([[SPEC-005-sskr-sharded-recovery#ADR-608]]). A person who wants three identical
copies is told, in a `p.hint`, to write the twelve words three times instead —
which is the existing mechanism and is honest about what it is.

Primary: **Continue**. Back: to Home.

#### SCREEN-603: `shares-presence`

Reuses the existing `presence` screen pattern without modification, discharging
[[SPEC-005-sskr-sharded-recovery#REQ-606]]. The heading names the act being
authorised — *Confirm it's you* — and the body names what follows: creating
pieces that reconstruct this key.

#### SCREEN-604: `shares-one`

> **Piece 1 of 3.** · `p.step` reads "Piece 1 of 3"

One share, one screen, paged — the obligation is
[[SPEC-005-sskr-sharded-recovery#REQ-611]] and the reasoning is
[[SPEC-005-sskr-sharded-recovery#ADR-608]]. The screen carries:

- the `.fp` block SPEC-002 defines, computed over this share's bytes —
  [[LifeHash]] picture, hex, and nickname
  ([[SPEC-005-sskr-sharded-recovery#REQ-607]]);
- the share text itself, in the encoding OQ-603 settles;
- the same `p.caution` the `phrase` screen already carries — paper, not a photo,
  and not a password manager on this device.

There is deliberately **no** "show all pieces" control, **no** copy button, and
**no** share sheet. Each is a route from a screen-scoped secret to a
device-scoped one, which is what
[[SPEC-005-sskr-sharded-recovery#REQ-608]] refuses.

Primary: **I've written this one down** → advances to the next piece, or to
SCREEN-605 on the last. Back: to the previous piece.

#### SCREEN-605: `shares-done`

> **Three pieces. Any two bring you back.**

The set-level `.fp` block, computed over the SSKR identifier, sits at the top —
it is the value that answers "do these envelopes belong together?". Below it,
the per-share fingerprints as a list, so a person labels three envelopes and
checks each against the screen without re-deriving anything.

The closing line is the only instruction that matters, and it is the
[[Peak-End Rule]] moment of the flow: *keep them in three places that will not
burn down together.*

Primary: **Done**.

### Flow B — restoring from shares

#### SCREEN-606: `restore-choose`

> **How do you have your key?**

Branches the existing Welcome screen's *I already have a home key* into two
routes: **Twelve words** (the existing `restore` screen, untouched) and
**Pieces of a split key** (SCREEN-608). Two options, both primary-weight,
because neither is a fallback for the other.

#### SCREEN-607: withdrawn

`restore-which` asked the person which identity they were restoring, so that
the earlier form of [[SPEC-005-sskr-sharded-recovery#REQ-603]] had an expected
DID to compare against.

**It is withdrawn.** Shares restore the root entropy; deriving the identity from
it is the system's work. The reconstructed identity is shown on the existing
`restored` screen and recognised by its fingerprint, which is the backstop
[[SPEC-002-visual-key-fingerprint]] already puts on every surface that displays
a key. The reasoning is [[SPEC-005-sskr-sharded-recovery#ADR-604]].

The identifier is retired and is not reused, per PROTO-001's numbering rule. The
entry is kept rather than deleted so that a reader meeting `SCREEN-607` in the
0.2.0 revision, or in review comments written against it, finds out what
happened to it.

#### SCREEN-608: `restore-shares`

> **Piece 2 of 2 needed.** · the heading counts down as shares are accepted

One share entered at a time. Each accepted share is recognised immediately
against [[SPEC-005-sskr-sharded-recovery#CON-601]], so a malformed share is
refused at the moment it is typed rather than at the end of the set
([[SPEC-005-sskr-sharded-recovery#REQ-604]]).

Each accepted share renders its fingerprint in a list, which is what lets a
person notice a mis-filed envelope **before** combination rather than after.
The count comes from the thresholds the shares themselves declare, so the screen
states a real target rather than a guess.

#### SCREEN-609: `restore-damaged`

> **One of these pieces is damaged, or belongs to a different set.**

This screen exists because of [[SPEC-005-sskr-sharded-recovery#OBS-603]] and
discharges [[SPEC-005-sskr-sharded-recovery#REQ-609]]. It is reached only when
the quorum is satisfied and the digest check fails.

It MUST NOT say that more pieces are needed. It lists the shares entered with
their fingerprints and asks which one to re-enter.

Primary: **Re-enter a piece**. Quiet: **Start again**.

#### SCREEN-610: `restore-wrong-identity`

> **These pieces belong to a different key.**

The `WrongIdentity` terminal from
[[SPEC-005-sskr-sharded-recovery#CON-603]], reached **only** on the optional
path — a surviving authorised device supplied a DID, and the pieces produced a
different one. A restore that was never given an expected DID never reaches
this screen; it goes to the existing `restored` screen, which shows the
reconstructed identity for the person to recognise.

Two `.fp` blocks side by side — the identity the device named, and the identity
the pieces produce — so the mismatch is a comparison the person makes rather
than a claim the screen asserts. This is the same treatment the existing
`consent` screen gives to the authorise decision.

The screen states plainly that nothing was written and no identity was unlocked,
because a refusal that leaves a person unsure what happened is a refusal that
gets retried carelessly.

#### SCREEN-611: `restore-incomplete`

> **You need one more piece.**

The honest not-enough case, and visually distinct from SCREEN-609 —
distinct heading, distinct icon treatment, distinct primary action. The two
screens exist separately because collapsing them is exactly the upstream error
[[SPEC-005-sskr-sharded-recovery#OBS-603]] records.

On success, the flow enters the existing `restored` screen unchanged.

### Screens deliberately not added

No screen displays a share after its set is created. There is no "view my
pieces" surface, because the application does not hold them
([[SPEC-005-sskr-sharded-recovery#REQ-608]]). A person who has lost a share
creates a new set from the root, which invalidates nothing and costs one
ceremony.

---

## Applied UX Heuristics

| Law | Application |
|---|---|
| [[Jakob's Law]] | The paged one-secret-per-screen treatment matches the existing `phrase` screen, and the fingerprint block matches every other key surface. A person who has created an identity has met both. |
| [[Hick's Law]] | [[SPEC-005-sskr-sharded-recovery#SCREEN-602]] offers three shapes, not two numeric ranges whose product is 256 combinations. The cap is met by the same decision that makes REQ-602 unreachable. |
| [[Von Restorff Effect]] | On [[SPEC-005-sskr-sharded-recovery#SCREEN-610]] the two fingerprints are given equal weight, deliberately against the usual rule — the screen's job is a comparison, so emphasising one side answers the question for the reader. |
| [[Miller's Law]] | Each share is one chunk carrying one picture, one hex value, and one nickname. The longest list any screen shows is five. |
| [[Goal-Gradient Effect]] | The `p.step` counter on [[SPEC-005-sskr-sharded-recovery#SCREEN-604]] and the countdown heading on [[SPEC-005-sskr-sharded-recovery#SCREEN-608]] both make a multi-step transcription task show its end. |
| [[Peak-End Rule]] | [[SPEC-005-sskr-sharded-recovery#SCREEN-605]] is the flow's end and carries its only storage instruction. [[SPEC-005-sskr-sharded-recovery#SCREEN-610]] is the failure peak, and it states what did **not** happen. |
| [[Doherty Threshold]] | [[SPEC-005-sskr-sharded-recovery#NFR-604]], 400 ms, inherited from [[SPEC-002-visual-key-fingerprint#NFR-104]]. |
| [[Paradox of the Active User]] | The one sentence that matters — a quorum **is** the key — is on [[SPEC-005-sskr-sharded-recovery#SCREEN-601]], before the person commits, and repeated as caution text on every share screen. It is never left to help text. |
| [[Aesthetic-Usability Effect]] | Named as a risk. A grid of eleven attractive LifeHash pictures invites approval of the flow without anyone attempting a restore. [[SPEC-005-sskr-sharded-recovery#TEST-606]] and [[SPEC-005-sskr-sharded-recovery#TEST-616]] exist because a walkthrough that looks right is not evidence. |
| [[Choice Overload]] | Probed by synthetic-user simulation at [[SPEC-005-sskr-sharded-recovery#SCREEN-602]]: a person who understands neither option picks the first one, which is why `2 of 3` is first and is the recommendation. |

---

## Verification strategy

Selected under PROTO-001's technique-selection table. The system is a
security-critical pure core with a parser at a trust boundary, so it draws from
several rows at once.

| Technique | Scope | Why |
|---|---|---|
| Example-based, requirement-targeted | every REQ | the baseline; positive, negative-input, negative-output, prohibited-action, and scope-invariant per applicable REQ |
| Property-based | CON-601, CON-602, CON-603 | round-trip and threshold properties over generated specifications; `proptest` is already a dev-dependency of the core |
| Fuzzing | CON-601 | the recogniser sits at a trust boundary and consumes bytes a stranger transcribed |
| Mutation testing | the whole module | Red Gate discipline cannot be strictly enforced for an AI-synthesised specification; PROTO-001 makes mutation the mandatory fallback |
| Published vectors | CON-601, CON-603 | BCR-2020-011 carries a test vector; a second runtime MUST be checkable against the same file, as `test-vectors/spec-001-v1.json` already permits for derivation |
| Adversarial testing | all | mandatory at Tier 1 and for AI-synthesised specifications |

**Temporal properties are not formalised.** PROTO-001 requires them for Tier 1–2
artefacts *whose obligations are temporal*. Every obligation here is a state
predicate over one operation. [[SPEC-005-sskr-sharded-recovery#NFR-603]] is a
latency threshold and is verified by instrumentation, not by a monitored
formula. Recorded so the omission reads as a decision.

---

## Tests

### TEST-601: Round-trip through every declared quorum

**Validates:** [[SPEC-005-sskr-sharded-recovery#REQ-601]] ·
[[SPEC-005-sskr-sharded-recovery#REQ-605]] — *positive*

Split a known entropy under 2-of-3, and combine every one of the three
two-share subsets. Each MUST yield the original entropy, the original mnemonic,
and the original DID.

### TEST-602: Reserved bits reject the share

**Validates:** [[SPEC-005-sskr-sharded-recovery#REQ-604]] —
*negative-input*

Set any bit of the reserved nibble and assert the recogniser refuses, before any
combination is attempted. Measured upstream behaviour:
`Err(ShareReservedBitsInvalid)`.

### TEST-603: Shares from two different splits do not combine

**Validates:** [[SPEC-005-sskr-sharded-recovery#REQ-604]] —
*negative-input*

Split two distinct secrets under one specification, then present one share from
each. Measured upstream behaviour: `Err(ShareSetInvalid)`. The identifier is
what catches this, and this test is what keeps that true.

### TEST-604: A corrupted share never yields a secret

**Validates:** [[SPEC-005-sskr-sharded-recovery#REQ-609]] —
*negative-output*

Flip one bit in the value of one share of a satisfied quorum and assert that no
entropy is returned. Assert additionally that the surfaced error is
`SharesDamagedOrMismatched`, and that it is **not** the upstream
`NotEnoughGroups` ([[SPEC-005-sskr-sharded-recovery#OBS-603]]).

### TEST-605: A threshold-one specification is refused

**Validates:** [[SPEC-005-sskr-sharded-recovery#REQ-602]] —
*prohibited-action*

Request 1-of-1 and 1-of-3. Assert both are refused. Assert also that no returned
value anywhere in the failed call equals the entropy — the prohibition is about
what MUST NOT exist, so the test asserts absence rather than an error code
alone.

### TEST-606: A restore returns, and shows, the identity it rebuilt

**Validates:** [[SPEC-005-sskr-sharded-recovery#REQ-603]] — *positive*

Combine a correct quorum with `expected: None` and assert the returned
`RestoredIdentity` carries the DID and fingerprint that
`derive_did(root_signing_key(mnemonic, 0))` produces from the same entropy.
Assert the `restored` screen renders that fingerprint — picture, hex, and
nickname.

With `expected: Some(did)` and a matching DID, assert the same result. With
`expected: Some(other)`, assert `WrongIdentity`, and that no key material
reaches the keychain stub and no signing capability becomes available.

### TEST-618: A restore never demands an identifier

**Validates:** [[SPEC-005-sskr-sharded-recovery#REQ-603]] —
*prohibited-action*

Drive the whole share-restore flow with no expected DID available from any
source, and assert it completes. Assert that no screen on the path presents a
field, scanner, or control asking for an identifier.

This is the test that keeps the withdrawn `SCREEN-607` withdrawn. The
requirement it enforces is a liveness property, and liveness properties are the
ones that quietly regress when a later reviewer adds "one more check" — which
is exactly how the 0.2.0 revision of
[[SPEC-005-sskr-sharded-recovery#ADR-604]] arrived.

### TEST-607: Splitting touches nothing else

**Validates:** [[SPEC-005-sskr-sharded-recovery#REQ-602]] ·
[[SPEC-005-sskr-sharded-recovery#REQ-606]] ·
[[SPEC-005-sskr-sharded-recovery#REQ-608]] — *scope-invariant*

After a split, and after a refused split, assert: the filesystem stub recorded
zero writes; the clipboard stub recorded zero writes; the log stub contains no
share bytes; the network stub recorded zero calls; and the keychain contains
exactly the entries it held before.

### TEST-608: Round-trip holds for every generated specification

**Validates:** [[SPEC-005-sskr-sharded-recovery#REQ-601]] ·
[[SPEC-005-sskr-sharded-recovery#REQ-605]] ·
[[SPEC-005-sskr-sharded-recovery#NFR-601]] — *property*

For all valid specifications with every member threshold at 2 or greater, and
all 16-byte entropies: `combine(any_satisfying_quorum(split(spec, e))) == e`.
Shrinking on failure gives the minimal specification that breaks it.

### TEST-609: Below-quorum sets never reconstruct

**Validates:** [[SPEC-005-sskr-sharded-recovery#REQ-609]] — *property*

For all valid specifications and every subset one share short of a threshold,
combination returns `QuorumIncomplete` and no entropy. Assert additionally that
no share value in any generated set equals the entropy, which is the structural
counterpart of [[SPEC-005-sskr-sharded-recovery#OBS-602]].

### TEST-610: The fingerprint is shown for each share and for the set

**Validates:** [[SPEC-005-sskr-sharded-recovery#REQ-607]] — *positive*

Render the share screen headlessly through `tests/screens.mjs` and assert one
fingerprint per share plus one for the set, each with hex, picture, and
nickname present.

### TEST-611: Mutation kill rate on the recovery module

**Validates:** the suite itself — *mutation*

`cargo mutants` over the split, combine, and recogniser modules. The kill rate
MUST be 100 %, matching the standard SPEC-001 sets for the acceptance
predicate. A surviving mutant is a gap in this list, not a curiosity.

### TEST-612: The purity gate and the wasm build still pass

**Validates:** [[SPEC-005-sskr-sharded-recovery#NFR-602]] —
*scope-invariant*

`cargo build -p selfsame-core --target wasm32-unknown-unknown` succeeds, and
`tests/purity.rs` passes, with the recovery work present. This test is the one
that will fail first if [[SPEC-005-sskr-sharded-recovery#ADR-603]] is decided
carelessly, which is why it exists before the decision does.

### TEST-613: Combination latency

**Validates:** [[SPEC-005-sskr-sharded-recovery#NFR-603]] — *positive*

Instrumented timing of a 2-of-3 combination on the reference device, asserted at
the 95th percentile over 100 runs.

### TEST-614: Only one share value is ever in the view

**Validates:** [[SPEC-005-sskr-sharded-recovery#REQ-611]] —
*prohibited-action*

Walk [[SPEC-005-sskr-sharded-recovery#SCREEN-604]] through every page of a
`2 of 3` set in `tests/screens.mjs`. At each page, scan the **whole document**,
not the viewport, and assert that exactly one share value is present. Assert
also that no page carries a copy control or a share-sheet control.

The document-wide scan is the point. A test that reads the viewport passes a
build that renders all three shares and scrolls between them, which is the
failure [[SPEC-005-sskr-sharded-recovery#ADR-608]] exists to prevent.

### TEST-615: The shape screen offers no threshold-one option

**Validates:** [[SPEC-005-sskr-sharded-recovery#REQ-610]] —
*negative-input*

Enumerate every selectable option on
[[SPEC-005-sskr-sharded-recovery#SCREEN-602]] and assert that each parses to a
member threshold of 2 or greater. Assert additionally that the screen exposes no
free numeric input.

This is a two-sided pair with
[[SPEC-005-sskr-sharded-recovery#TEST-605]]: TEST-605 verifies the core refuses,
TEST-615 verifies the interface never asks. Both stand, because an interface is
not a trust boundary.

### TEST-616: Damaged and incomplete reach different screens

**Validates:** [[SPEC-005-sskr-sharded-recovery#REQ-609]] —
*negative-output*

Drive two restores: one quorum short of a threshold, and one satisfied quorum
with a corrupted share. Assert the first lands on
[[SPEC-005-sskr-sharded-recovery#SCREEN-611]] and the second on
[[SPEC-005-sskr-sharded-recovery#SCREEN-609]]. Assert that the text of
SCREEN-609 contains no instruction to find more pieces.

### TEST-617: The screens walk clean

**Validates:** [[SPEC-005-sskr-sharded-recovery#NFR-604]] — *positive* and
*scope-invariant*

Extend `tests/screens.mjs` over all eleven screens: exactly one screen visible
at a time, no horizontal overflow at phone width, no console errors, a
fingerprint present on every screen that displays one, and the 400 ms paint
budget met on the share screens.

---

## Status

`draft`. Nothing in this document has been implemented, and nothing in it has
been reviewed by anyone other than its author.

**This specification is stacked behind a gate that has not been passed.**
[[SPEC-001-device-key-provisioning]] remains `draft` behind an unpassed Tier-1
gate with three gate-blocking open questions, and its mutation-testing
obligation has not been run. Sharded recovery of a root key sits below that
gate, not beside it.

Three further conditions apply before any code is written:

1. Cryptography is a PROTO-001 no-go area. This work needs explicit human
   approval, recorded, before Phase 3 begins.
2. [[SPEC-005-sskr-sharded-recovery#ADR-603]] is unresolved, and it decides
   where the code goes. Writing the code first decides it by accident.
3. Every ADR here is `proposed`. Cross-model adversarial review under
   Constitutional Principle 12 has not been run, and this document was produced
   in one session by one model.

**Gate Evidence Record — Phase 1–2**

```yaml
phase: 2
gates:
  - gate: "Requirements unambiguous, verifiable, atomic"
    mechanism: "reviewer: cross-model adversarial review (Tier 1)"
    result: unverified
    evidence: "not run; escalated to HOC 2026-08-03"
  - gate: "Orientation block present with exhaustive Controls digest"
    mechanism: "self-check against PROTO-001 template"
    result: pass
    evidence: "Orientation section above; 7 Controls entries, each wikilinked"
  - gate: "Amendment Channels block present"
    mechanism: "presence check"
    result: pass
    evidence: "## Amendment Channels section above"
  - gate: "LangSec: grammar declared for every CON accepting external input"
    mechanism: "presence check on CON-601"
    result: pass
    evidence: "CON-601 ABNF plus byte-layout diagram and rejection table"
  - gate: "Capability placement justified"
    mechanism: "ADR-603 Simplicity Ladder walk"
    result: fail
    evidence: "ADR-603 records three options and a recommendation; no decision. OQ-601, owner HOC"
  - gate: "Evidence for external claims"
    mechanism: "probe crate against sskr 0.12.0; cargo tree, wasm build, tests"
    result: pass
    evidence: "OBS-601 … OBS-605, each a recorded command result"
  - gate: "Comprehension gate (Tier 1, AI-synthesised)"
    mechanism: "fresh-context agent given only the Orientation block"
    result: unverified
    evidence: "not run; escalated to HOC 2026-08-03"
  - gate: "Applied UX Heuristics subsection present for the screen set"
    mechanism: "presence check"
    result: pass
    evidence: "## Applied UX Heuristics section; 10 laws, each mapped to a screen or requirement"
  - gate: "Default UX NFRs instantiated, or deviation recorded"
    mechanism: "presence check against PROTO-001 default table"
    result: pass
    evidence: "NFR-604 instantiates Doherty; Fitts and Miller deviations recorded inline under NFR-604"
  - gate: "Synthetic User Protocol run against the screen set"
    mechanism: "sub-agent walk of the two happy paths from profile + spec only"
    result: unverified
    evidence: "not run; no users/{group}/user.md exists for a share-holder profile. Escalated to HOC 2026-08-03"
```

Phase 2 is **not complete**: one gate is `fail` and three are `unverified`.

The screens above are specified and have never been drawn, and no synthetic user
has walked them. A screen set that reads well is not a screen set that works,
which is the [[Aesthetic-Usability Effect]] this document names as a risk
against itself.

The 0.3.0 revision is evidence for that risk rather than against it. The
identifier-entry gate withdrawn in
[[SPEC-005-sskr-sharded-recovery#ADR-604]] read as rigour on the page and
locked out the person it existed to protect. It survived one authoring pass and
a self-review, and it was caught by a human reading the design — not by any
gate in this document. Recorded because the next such defect will look the
same.

---

## Changelog

<details>
<summary>Revision history — 0.1.0 → 0.3.0</summary>

- 0.3.0 — **normative, and a correction.** ADR-604 is rewritten and supersedes
  its 0.1.0–0.2.0 form. Shares restore the root entropy; the system derives the
  identity and **shows** it for recognition against the SPEC-002 fingerprint,
  and never asks a person to supply, type, or know a `did:crdt:` identifier. An
  expected DID becomes an OPTIONAL input, checked when a surviving device
  offers one. REQ-603 rewritten, CON-603 takes `Option<&Did>` and returns the
  DID and fingerprint in `RestoredIdentity`, SCREEN-607 withdrawn (identifier
  retired, not reused), SCREEN-610 re-scoped to the optional path, TEST-606
  rewritten, TEST-618 added to keep the liveness property from regressing.
  OQ-602 narrowed. The withdrawn gate had been recorded as "the weakest screen
  in the specification" rather than treated as the defect it was; the existing
  twelve-word restore already ends by showing the fingerprint, and two recovery
  paths to one secret get one verification story.

- 0.2.0 — **normative.** Eleven screens folded in rather than split into
  `SCREEN-###` documents, with the identifiers reserved so a later split is a
  move. Two interface decisions promoted to requirements because each moves an
  obligation from prose into structure: REQ-610 (fixed split shapes, making
  REQ-602 unreachable at the interface) and REQ-611 (one share value on screen,
  closing the screenshot path REQ-608 leaves open). ADR-608, NFR-604, and
  TEST-614 … TEST-617 added.
- 0.1.0 — first draft. Findings from a probe crate against `sskr` v0.12.0
  converted to specification: the wasm build failure (OBS-601), the
  threshold-one leak (OBS-602), the misleading corruption error (OBS-603), and
  the 78-crate dependency graph (OBS-604). Placement left open as OQ-601.
</details>
