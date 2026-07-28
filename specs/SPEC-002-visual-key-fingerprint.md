---
id: SPEC-002
title: Visual Key Fingerprint (LifeHash v2)
status: implemented
version: 1.0.0
last-updated: 2026-07-28
implemented-date: 2026-07-28
---

# SPEC-002 — Visual Key Fingerprint

## Orientation

**Intent:** Every key [[Selfsame]] shows a person is shown as a picture as well as
a number, so that "is this the same key?" can be answered by recognition at a
glance instead of by reading twelve hex digits. The picture is
[[LifeHash]] v2, computed from the same digest the hex renders.

**Metaphor:** *a passport.* The photograph is what you glance at to see whether
this is the same person; the passport number is what you read, character by
character, when it actually has to be right. The photograph never replaces the
number — but a passport without one is far easier to pass off.

**Structure:**

```
   selfsame-core — pure core                      shells (effectful)
  ┌──────────────────────────────────────┐
  │  fingerprint_key()  fingerprint_did() │
  │            │  6 bytes = 48 bits       │
  │            ▼                          │
  │      Fingerprint ──┬── hex()          │  normative comparison value
  │                    ├── label()        │  nickname, never compared
  │                    └── lifehash()     │  ◀── CON-101
  └────────────────────────┬──────────────┘
                           │  LifeHash: 32×32 RGB, 3072 bytes
              ┌────────────┴─────────────┐
              ▼                          ▼
     ┌──────────────────┐      ┌───────────────────┐
     │  phone shell     │      │   CLI shell       │
     │  Fp.lifehash     │      │  half-block rows  │
     │  base64 → canvas │      │  CON-103          │
     │  CON-102         │      │                   │
     └──────────────────┘      └───────────────────┘

  arrows point outward from the pure core; the core imports no shell
```

**Decisions:**
[[SPEC-002-visual-key-fingerprint#ADR-101]] adopt `bc-lifehash` rather than
re-implement ·
[[SPEC-002-visual-key-fingerprint#ADR-102]] the picture is derived from the
fingerprint, not from the key ·
[[SPEC-002-visual-key-fingerprint#ADR-103]] the capability lives in the pure
core ·
[[SPEC-002-visual-key-fingerprint#ADR-104]] raw RGB over the boundary, no
image codec ·
[[SPEC-002-visual-key-fingerprint#ADR-105]] unconditional ANSI in the terminal ·
[[SPEC-002-visual-key-fingerprint#ADR-106]] MSRV rises to 1.85

**Load-bearing:**
[[SPEC-002-visual-key-fingerprint#REQ-101]] every displayed key carries its
picture ·
[[SPEC-002-visual-key-fingerprint#REQ-103]] the hex remains the normative
comparison value ·
[[SPEC-002-visual-key-fingerprint#NFR-101]] the picture's preimage carries the
full 48 bits ·
[[SPEC-002-visual-key-fingerprint#NFR-103]] the picture is never the sole
carrier of meaning

**Open:**
- Whether the LifeHash may eventually be promoted from *recognition aid* to
  *comparison value* is *not* decided here and is deferred to the
  [[SPEC-001-device-key-provisioning]] Tier-1 gate — see
  [[SPEC-002-visual-key-fingerprint#ADR-107]] (owner: HOC).
- `bc-lifehash` has no third-party security review
  ([[SPEC-002-visual-key-fingerprint#ADR-101]] records why that is acceptable
  at this trust level) (owner: HOC).
- The **unlink confirmation** screen displays no fingerprint at all — only the
  device's label — so [[SPEC-002-visual-key-fingerprint#REQ-101]] does not
  reach it and no picture was added. Whether the most destructive screen in the
  app should name the key it is about is a
  [[SPEC-001-device-key-provisioning]] question, not one to settle by
  encrustation from a downstream spec (owner: HOC).

**Detail:** [[SPEC-001-device-key-provisioning]] · [[PROTO-001]] ·
[[SCREEN-001-authorise-a-device]] · [[SCREEN-002-device-client]]

---

## Conformance

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in
all capitals.

## Artefact numbering

[[SPEC-001-device-key-provisioning]] is not present in this working copy — the
repository references it at `../anuna-ssi/specs/`, which is not checked out.
Its artefact numbers therefore cannot be read, and continuing its sequence
would risk silent collisions in a shared [[zetl]] vault. This document numbers
its own artefacts from **101** in every prefix, a band SPEC-001 demonstrably
does not reach (its highest observed identifiers in code comments are REQ-026,
NFR-008, ADR-013, TEST-033). Cross-document references are fully qualified.

## Concept-page backlog (explicit deferral)

`zetl check --dead-links` reports **14 distinct unresolved targets** from this
vault (the raw link count is higher and not worth tracking — the table below
cites each target, which adds links of its own). They are visible backlog, not
defects, and are **not** to be deleted to clean the report.
Two pages that are load-bearing for *this* specification —
[[LifeHash]] and [[Conway's Game of Life]] — were authored here. The rest are
deferred, with reasons:

| Target | Count | Disposition |
|---|---|---|
| [[SPEC-001-device-key-provisioning]], [[SCREEN-001-authorise-a-device]], [[SCREEN-002-device-client]], [[PROTO-001]] | 24 | **Cannot be authored here.** They live in the `anuna-ssi` vault, which is not checked out in this working copy. Writing local stubs would create two documents with one identity and guarantee a collision when the vaults meet. Resolves when `anuna-ssi` is present. Owner: HOC. |
| [[Jakob's Law]], [[Von Restorff Effect]], [[Law of Similarity]], [[Miller's Law]], [[Aesthetic-Usability Effect]], [[Selective Attention]], [[Doherty Threshold]] | 8 | **Deferred to the shared vault.** The Laws of UX catalogue is cited by every `SCREEN-###` across Anuna projects, so per Constitutional Principle 15 the pages belong in the layer all of them can reach — not duplicated into one repository's local `specs/`. Owner: HOC. |
| [[Blockchain Commons]], [[Selfsame]], [[zetl]] | 6 | **Deferred, same reason** — organisation and tool pages are vault-wide vocabulary. Owner: HOC. |

Consequently `zetl check --fail-on error` exits non-zero in this repository
until the vaults are joined, and that is the correct reading: the traceability
graph genuinely is incomplete while half of it is absent. The gate this
specification holds itself to is *no new dead links beyond the table above*.

---

## Context

[[SPEC-001-device-key-provisioning]] REQ-007 and NFR-008 make a 48-bit
fingerprint the **human backstop** behind device authorisation: the user is
asked to compare a value across two screens, and that comparison is what stands
between them and an attacker who has otherwise completed the linking protocol.
`crates/selfsame-core/src/fingerprint.rs` renders that digest two ways —
`hex()`, the normative comparison value at 48 bits, and `label()`, a
≈18.6-bit nickname that names a row and is never compared.

The phone's authorise screen ([[SCREEN-001-authorise-a-device]]) additionally
drew **three muted colour bars** above the hex. They were seeded from bytes 0,
2 and 4 of the digest and mapped to `hsl(h 30% 47%)` — 24 bits of input, and
by the implementation's own comment "a few bits at most" once perception is
accounted for. They existed to make a row of hex memorable between two glances.

Three bars are a weak instrument for that job. They are drawn only on one
screen of seven that display a key; they discard half the digest before
they start; and low-saturation hue triples are among the least reliable things
to hold in working memory or to tell apart under colour-vision deficiency.

This specification replaces them with [[LifeHash]] v2 — a
[[Conway's Game of Life]]-based visual hash designed for exactly this task —
and extends the treatment to **every** surface that displays a key, in the
phone app and in the CLI alike.

### What LifeHash v2 is

[[LifeHash]] is a visual hash by Wolf McNally and Christopher Allen
([[Blockchain Commons]]), published at <https://lifehash.info/>. Version 2 is
the recommended version: a CMYK-friendly gamut, and free of the gradient
defects of version 1.

The algorithm, per the reference implementation:

1. Take a SHA-256 digest of the input.
2. Seed a 16×16 [[Conway's Game of Life]] grid from `SHA-256(digest)` — one bit per
   cell. (Version 2 re-hashes so that it in no way resembles version 1.)
3. Run the automaton for up to 150 generations, stopping early once a state
   repeats.
4. Overlay every generation into a fractional grid and normalise it to `0..1`.
5. Draw two bits of entropy from the *original* digest, then select a colour
   gradient and a symmetry pattern from the remaining bits.
6. Apply the symmetry, which doubles the grid to **32×32**, and colour it.

The output for version 2 is a 32×32 RGB image — 3072 bytes.

The Game of Life step is what makes the result *look like something*: it
converts uniform entropy into structure — blobs, symmetries, textures — which
is what human recognition memory can actually hold on to.

---

## Requirements

### REQ-101: Every displayed key carries its picture

The system SHALL display the [[LifeHash]] of a key's fingerprint adjacent to
every rendering of that fingerprint, on every screen and in every command that
displays one, FOR every user of the phone app and the CLI.

The surfaces in scope, exhaustively:

| Surface | Key shown | Fingerprint function |
|---|---|---|
| Phone — *created* | the new identity | `fingerprint_did` |
| Phone — *home*, home-key card | the root key | `fingerprint_key` |
| Phone — *home*, each device row | that device's key | `fingerprint_key` |
| Phone — *device detail* | that device's key | `fingerprint_key` |
| Phone — *authorise* (was: the bars) | the key being authorised | `fingerprint_key` |
| Phone — *linked* | the identity just joined | `fingerprint_did` |
| Phone — *restored*, and each surviving device row | the recovered root key, and each device | `fingerprint_key` |
| CLI — `selfsame status` | this device's key, and the identity | both |
| CLI — `selfsame link` report | the identity just joined | `fingerprint_did` |

Rationale: a recognition aid that appears on one screen out of seven cannot
build recognition. The user must have seen the picture often enough, in
unremarkable contexts, for its appearance on the authorise screen to mean
anything. This is why the requirement is *"every"* and not *"the authorise
screen"*.

Trace: [[SPEC-002-visual-key-fingerprint#TEST-101]],
[[SPEC-002-visual-key-fingerprint#CON-101]],
[[SPEC-002-visual-key-fingerprint#CON-102]],
[[SPEC-002-visual-key-fingerprint#CON-103]]

### REQ-102: The picture is a deterministic function of the fingerprint

The system SHALL compute the picture as `LifeHash v2` of the six-byte
fingerprint digest, deterministically, such that two displays of the same
fingerprint produce byte-identical images on every platform.

Trace: [[SPEC-002-visual-key-fingerprint#TEST-102]],
[[SPEC-002-visual-key-fingerprint#CON-101]]

### REQ-103: The hex remains the normative comparison value

The system SHALL continue to present `Fingerprint::hex` as the value the user
is asked to compare, and SHALL NOT ask the user to compare pictures in place of
it.

Rationale: promoting the picture to a comparison value is a change to
[[SPEC-001-device-key-provisioning]] NFR-008's backstop and is gated behind
that specification's outstanding Tier-1 review. See
[[SPEC-002-visual-key-fingerprint#ADR-107]].

Trace: [[SPEC-002-visual-key-fingerprint#TEST-103]]

### REQ-104: The two fingerprint domains produce different pictures

The system SHALL produce different pictures for `fingerprint_key(k)` and
`fingerprint_did(d)` whenever those functions produce different digests,
inheriting the domain separation already present in
`crates/selfsame-core/src/fingerprint.rs`.

Trace: [[SPEC-002-visual-key-fingerprint#TEST-104]]

### REQ-105: A picture is never the only thing on screen

The system SHALL accompany every picture with the fingerprint's textual
rendering (`hex` where the fingerprint is compared, `label` where it merely
names a row), and SHALL mark the picture `aria-hidden` so that assistive
technology is routed to the text rather than to a decorative canvas.

Trace: [[SPEC-002-visual-key-fingerprint#TEST-105]],
[[SPEC-002-visual-key-fingerprint#NFR-103]]

---

## Non-functional requirements

### NFR-101: Preimage entropy

The picture's preimage SHALL carry the full 48 bits of
`FINGERPRINT_BITS`, UNDER all inputs, WITH no truncation of the digest before
hashing.

This is the measurable improvement over the bars, which consumed 24 of the 48
bits and discarded the rest. It is a statement about the *input*, not about
how many bits a human eye can resolve from the output — see
[[SPEC-002-visual-key-fingerprint#NFR-102]] for what is actually verified about
the output.

Trace: [[SPEC-002-visual-key-fingerprint#TEST-102]]

### NFR-102: The picture does not collapse the fingerprint space

Distinct fingerprints SHALL produce distinct images across a corpus of ≥ 10⁵
distinct device keys, WITH zero image collisions observed.

This bounds *entropy collapse in the rendering*, not injectivity over the whole
2⁴⁸ space. A 10⁵ corpus would be expected to reveal roughly five collisions if
the image map retained only ~34 bits, and near-certainly reveal collapse to
anything smaller; it says nothing about collisions at the 2⁴⁸ birthday bound.
The stronger claim is not made because it is not tested.

Trace: [[SPEC-002-visual-key-fingerprint#TEST-106]]

### NFR-103: Colour is never the only carrier of meaning

No state, identity, or decision SHALL be conveyed by the picture alone,
CONFORMING TO WCAG 2.2 AA (1.4.1 Use of Colour) as
[[SPEC-001-device-key-provisioning]] already requires of
[[SCREEN-001-authorise-a-device]].

In particular the device-row state (`pending`, `revoked`) SHALL keep its
existing distinct *shape* treatment; the picture is added beside it and does
not replace it.

Trace: [[SPEC-002-visual-key-fingerprint#TEST-105]]

### NFR-104: Render latency

The authorise screen SHALL paint its picture WITHIN 400 ms of the screen
becoming visible, at the 95th percentile, on the reference device.

400 ms is the [[Doherty Threshold]]. The budget is generous by construction:
the image is computed once in the shell before the screen is shown and painted
from a 3072-byte buffer, so no Game of Life runs on the UI thread.

Trace: [[SPEC-002-visual-key-fingerprint#TEST-107]]

### NFR-105: The pure core stays pure

Adding the picture SHALL NOT introduce `tokio`, `reqwest`, `std::fs`,
`std::net`, or `std::time` into `selfsame-core`'s dependency graph, preserving
[[SPEC-001-device-key-provisioning]] §13 and NFR-006.

`bc-lifehash` depends only on `sha2`, which `selfsame-core` already links.

Trace: existing `crates/selfsame-core/tests/purity.rs` (TEST-033)

---

## Architecture decisions

### ADR-101: Adopt `bc-lifehash` rather than re-implement LifeHash

**Status:** accepted

**Context.** [[LifeHash]] is a non-trivial algorithm: a Game of Life engine, a
history-accumulating fractional grid, a normalisation pass, twelve colour
gradients, and a family of symmetry patterns — around 2 400 lines in the C++
reference. Re-implementing it would be re-implementing a published algorithm
whose entire value is that independent implementations agree.

**Decision.** Depend on `bc-lifehash` 0.1.0 from crates.io — the first-party
Rust implementation by [[Blockchain Commons]], the same authors as the C++
reference.

**Simplicity Ladder.** Settled at **rung 4** (an existing dependency solves
it). Rung 5 — minimum new code — was rejected: a hand-written port is roughly
2 000 lines of arithmetic whose only correctness oracle is the reference
implementation we would be declining to use, and divergence would be invisible
until two clients disagreed about a picture. That is the shotgun-parser failure
mode of [[PROTO-001]] Constitutional Principle 14, applied to a renderer.

**Evidence.** Before adopting, the published crate was checked against the
**35 reference test vectors** generated by the C++ implementation
(`bc-lifehash/test/test-vectors.json`), covering all five versions, both input
types, and module sizes. All 35 reproduce **byte-for-byte**. The crate's only
dependency is `sha2 ^0.10.6`, already in `selfsame-core`'s graph, so
[[SPEC-002-visual-key-fingerprint#NFR-105]] holds by inspection.

**Consequences and risk.**
- `bc-lifehash` carries **no third-party security review** (its
  `SECURITY-REVIEW.md` says so plainly). This is accepted because the crate sits
  entirely outside every trust boundary: it consumes a digest the core has
  already computed, it makes no decision, and its output is written to a canvas.
  A defect in it produces a wrong *picture*, which
  [[SPEC-002-visual-key-fingerprint#REQ-103]] ensures cannot by itself cause a
  wrong authorisation. It is `#![forbid(unsafe_code)]`-compatible pure
  computation over a fixed-size input.
- The version is pinned to `=0.1.0` in the workspace so that a picture cannot
  change under the user without a deliberate, reviewed bump. A LifeHash that
  silently changes is worse than no LifeHash: it teaches the user that the
  picture changing is normal.

### ADR-102: The picture is derived from the fingerprint, not from the key

**Status:** accepted

**Context.** The picture could be computed from the raw public key (or DID), or
from the six-byte fingerprint digest the hex already renders.

**Decision.** Compute it from the **fingerprint digest**:
`LifeHash::v2(SHA-256(fp.as_bytes()))`.

**Rationale.** The invariant this buys is the one the user's mental model
needs: *the picture and the number are two renderings of one value*. Equal hex
implies an equal picture, necessarily. Had the picture been derived from the
key, the two displays would be independent projections of different inputs, and
"the numbers match but the pictures don't" would be a reachable state with no
meaning the user could act on.

It also keeps the entropy story of
[[SPEC-001-device-key-provisioning]] NFR-008 exactly as it was — 48 bits, one
digest, two renderings — rather than introducing a second, differently-sized
comparison surface for a reviewer to reason about.

Domain separation comes free: `fingerprint_key` and `fingerprint_did` already
prefix distinct BLAKE3 domains, so their pictures differ for the same reason
their hexes do ([[SPEC-002-visual-key-fingerprint#REQ-104]]).

### ADR-103: The capability lives in the pure core

**Status:** accepted

**Context.** The picture is needed by the phone shell and by the CLI, and would
be needed by any future client. It could live in the JavaScript front end (as
the bars did), in each shell, or in `selfsame-core`.

**Decision.** `Fingerprint::lifehash()` on the existing type in
`crates/selfsame-core/src/fingerprint.rs`.

**Rationale.** [[PROTO-001]] Constitutional Principle 15: a capability common
to many components belongs in the shared layer. `fingerprint.rs` is already the
module that owns *which renderings of a fingerprint exist and which one is
normative*; this is a third rendering, and splitting it from its siblings would
put the answer to "what may a fingerprint be displayed as?" in two files.

The bars were the counter-example: because they lived in `app.js`, the CLI
never had them, and no Rust test could see them.

**Placement rationale (Principle 15).** In-component, on `Fingerprint` —
not a new component. The capability is a rendering of an existing type,
consumed by every shell, with no state and no lifecycle of its own. A separate
`selfsame-lifehash` crate would be an abstraction with a single implementation
and a single conceptual caller, which the Discipline Rules prohibit absent an
ADR justifying the indirection.

### ADR-104: Raw RGB across the boundary; no image codec anywhere

**Status:** accepted

**Context.** The phone shell must get a 32×32 image from Rust into the DOM.
The obvious route is to encode a PNG in Rust and hand over a `data:` URI.

**Decision.** The core exposes the 3072 raw RGB bytes, plus a Base64 rendering
of them for transport. The front end paints them into a 32×32 `<canvas>` via
`ImageData` and scales it up with `image-rendering: pixelated`.

**Simplicity Ladder.** Settled at **rung 3** (a native platform feature covers
it). `ImageData` is exactly a raw RGBA buffer, which is what we have; adding a
PNG encoder to the pure core would be a new dependency (rung 4) bought solely
to re-encode data the platform accepts directly. `base64ct` is already a
`selfsame-core` dependency, so the transport encoding costs nothing new either.

**Consequences.** Base64 of 3072 bytes is 4096 characters per fingerprint. The
home screen carries one root key plus one per device, so a ten-device identity
transfers roughly 45 KB of state — acceptable for a local IPC call, and noted
here so the ceiling is visible rather than discovered.

### ADR-105: The terminal renders with unconditional ANSI half-blocks

**Status:** accepted

**Context.** The CLI must draw a 32×32 colour image in a terminal.

**Decision.** Draw it as 16 rows of 32 `▀` characters, each cell setting a
24-bit foreground (the upper pixel) and a 24-bit background (the lower pixel).
Emit the escapes **unconditionally**, without testing `isatty`.

**Rationale.** This is the convention the CLI already established for its QR
code, whose implementation notes cite [[PROTO-001]]'s requirement that
behaviour be invariant across calling context: reformatting output when stdout
is a TTY is precisely the implicit context-sensitivity the protocol treats as a
code smell. Following the existing precedent also means one rendering
convention in the binary rather than two.

**Consequences.** A piped `selfsame status` contains escape sequences. That is
already true of `selfsame link`, and a colour image redirected to a file is not
a meaningful artefact under any encoding.

### ADR-106: The workspace MSRV rises from 1.75 to 1.85

**Status:** accepted

**Context.** `bc-lifehash` 0.1.0 is `edition = "2024"`, which requires Rust
1.85 or later. The workspace declares `rust-version = "1.75.0"`.

**Decision.** Raise `workspace.package.rust-version` to `1.85.0`.

**Rationale.** CI installs `stable` and the development toolchain is 1.95, so
nothing breaks in practice — which is exactly why this must be written down
rather than left. A declared MSRV that the dependency graph cannot honour is a
false statement in the manifest, and the next person to trust it would be
misled. The bump is recorded here so the cost of
[[SPEC-002-visual-key-fingerprint#ADR-101]] is legible.

### ADR-107: The picture is a recognition aid, not (yet) a comparison value

**Status:** accepted (deferral)

**Context.** Because [[SPEC-002-visual-key-fingerprint#ADR-102]] derives the
picture from the whole 48-bit digest, the picture's *preimage* clears
[[SPEC-001-device-key-provisioning]] NFR-008's 32-bit floor with room to spare.
It is therefore tempting to promote it to a comparison value — "do the two
pictures match?" — which is the interaction LifeHash was designed for.

**Decision.** Not now. `hex` remains the normative comparison value
([[SPEC-002-visual-key-fingerprint#REQ-103]]).

**Rationale.** Preimage entropy is a necessary but not sufficient condition.
Promoting the picture would require evidence about *human* discrimination —
how reliably users reject a near-miss image under time pressure — which is a
user-study question, not an entropy question, and it would move
[[SPEC-001-device-key-provisioning]]'s human backstop. That specification is
`draft` behind an unpassed Tier-1 gate. Changing the backstop under it would be
specification drift of the worst kind: a security-relevant change made in a
downstream document.

**Upgrade trigger.** The SPEC-001 Tier-1 review, with a synthetic-user and
human study of near-miss rejection rates attached. Owner: HOC.

---

## Contracts

### CON-101: `Fingerprint::lifehash` — the core rendering

```rust
/// LifeHash v2 of a fingerprint: a 32×32 RGB image.
pub struct LifeHash { /* [u8; 3072] */ }

impl LifeHash {
    pub const SIDE: usize = 32;
    pub const RGB_LEN: usize = 3072;
    pub fn rgb(&self) -> &[u8; Self::RGB_LEN];
    pub fn pixel(&self, x: usize, y: usize) -> (u8, u8, u8);  // panics out of range
    pub fn base64(&self) -> String;                            // transport, CON-102
}

impl Fingerprint {
    pub fn lifehash(&self) -> LifeHash;
}
```

**Interface:** pure function of `&self`. No external input crosses this
boundary — the argument is a six-byte digest the core itself produced — so
[[PROTO-001]] Principle 14 imposes no grammar obligation here. The one grammar
that *is* required is the front end's, at [[SPEC-002-visual-key-fingerprint#CON-102]].

**Pre-conditions:** none. `Fingerprint` is a six-byte value with no invalid
inhabitants, so `lifehash` is total.

**Post-conditions:**
- `lifehash()` is deterministic: equal `Fingerprint` ⇒ equal `rgb()` (REQ-102).
- `rgb().len() == 3072`, `SIDE == 32` (REQ-102).
- The image equals `bc_lifehash::make_from_data(self.as_bytes(), Version2, 1, false)` (ADR-102).
- `base64()` is the standard Base64 alphabet with padding, of exactly `rgb()`.

**Error model:** none — total function, no failure mode.

Implements: [[SPEC-002-visual-key-fingerprint#REQ-101]],
[[SPEC-002-visual-key-fingerprint#REQ-102]],
[[SPEC-002-visual-key-fingerprint#REQ-104]]
Verified by: [[SPEC-002-visual-key-fingerprint#TEST-102]],
[[SPEC-002-visual-key-fingerprint#TEST-104]],
[[SPEC-002-visual-key-fingerprint#TEST-106]]

### CON-102: `Fp.lifehash` — the Tauri boundary and its grammar

The existing `Fp` struct gains one field:

```rust
pub struct Fp {
    pub hex: String,
    pub label: String,
    /// LifeHash v2, 32×32 RGB, Base64. Decorative — see REQ-105.
    pub lifehash: String,
}
```

**Input grammar (front end).** `app.js` receives `lifehash` across the IPC
boundary and MUST recognise it fully before painting. Although the producer is
the application's own Rust half, the front end treats it as external input:
this is the boundary at which a malformed value would become a runtime fault
inside the rendering path.

```abnf
lifehash    = 4096( b64char ) ; exactly 4096 characters
b64char     = ALPHA / DIGIT / "+" / "/"
```

The grammar admits no `=`: 3072 is divisible by 3, so a correctly encoded
image never carries padding. Excluding it is the conservative reading
[[PROTO-001]] Principle 14.4 asks for — a padded value at this length is
malformed, and accepting it would be repairing input rather than recognising
it.

Recognition is *complete before any semantic action*: decode, check the byte
count is exactly 3072, and only then construct `ImageData`. A value failing the
grammar is rejected — the picture is omitted and the text rendering stands
alone — rather than partially painted. Per
[[SPEC-002-visual-key-fingerprint#REQ-105]] the text is always present, so a
rejected picture degrades to the pre-existing display rather than to a broken
screen.

**Pre-conditions:** `hex` and `label` unchanged in meaning.
**Post-conditions:** `lifehash` decodes to exactly `LifeHash::RGB_LEN` bytes.
**Error model:** a `lifehash` failing the grammar is dropped with a console
warning; the surrounding screen renders normally.

Implements: [[SPEC-002-visual-key-fingerprint#REQ-101]],
[[SPEC-002-visual-key-fingerprint#REQ-105]]
Verified by: [[SPEC-002-visual-key-fingerprint#TEST-105]],
[[SPEC-002-visual-key-fingerprint#TEST-108]]

### CON-103: The terminal rendering

```rust
/// 16 lines of 32 half-block cells: the 32×32 image, two pixel rows per line.
pub fn lifehash_lines(lh: &LifeHash, indent: &str) -> Vec<String>;
```

**Pre-conditions:** none.
**Post-conditions:** exactly 16 lines; each begins with `indent`, contains 32
`▀` glyphs, and ends with `\x1b[0m`; foreground is row `2y`, background row
`2y+1`, both as 24-bit SGR.
**Error model:** none.

Split out from the printing function for the same reason `qr_lines` was — so
the geometry is testable without capturing stdout.

Implements: [[SPEC-002-visual-key-fingerprint#REQ-101]]
Verified by: [[SPEC-002-visual-key-fingerprint#TEST-109]]

---

## Test specifications

Every test below names the requirement it validates, so a failure can be lifted
to its requirement before repair ([[PROTO-001]] Traceability).

### TEST-101: Every surface displays a picture
**Validates:** [[SPEC-002-visual-key-fingerprint#REQ-101]]
- *positive:* `tests/screens.mjs` walks all screens; every screen listed in
  REQ-101's table contains a painted, non-blank `canvas.fp__lifehash`.
- *negative-output:* a screen in the table with no canvas fails the run.

### TEST-102: Determinism and shape
**Validates:** [[SPEC-002-visual-key-fingerprint#REQ-102]], [[SPEC-002-visual-key-fingerprint#NFR-101]]
- *positive:* the same fingerprint yields byte-identical `rgb()` across calls;
  `rgb().len() == 3072`.
- *positive:* the image equals `bc_lifehash::make_from_data` of the full six
  digest bytes — the whole 48 bits reach the algorithm (NFR-101).
- *negative-output:* a one-bit change anywhere in the input key changes the
  image.

### TEST-103: Hex remains normative
**Validates:** [[SPEC-002-visual-key-fingerprint#REQ-103]]
- *positive:* the authorise screen's compared value is still `hex`, and the
  hex element remains the largest text under the question.
- *negative-output:* a screen asking the user to compare pictures fails.

### TEST-104: Domain separation survives the rendering
**Validates:** [[SPEC-002-visual-key-fingerprint#REQ-104]]
- *negative-output:* feeding a DID's first 32 bytes to `fingerprint_key` does
  not produce `fingerprint_did`'s picture.

### TEST-105: Accessibility
**Validates:** [[SPEC-002-visual-key-fingerprint#REQ-105]], [[SPEC-002-visual-key-fingerprint#NFR-103]]
- *positive:* every `canvas.fp__lifehash` carries `aria-hidden="true"` and is
  accompanied by a text rendering in the same block.
- *negative-output:* a device row conveying `revoked`/`pending` by picture
  alone — without its distinct mark shape — fails.

### TEST-106: The picture does not collapse the fingerprint space
**Validates:** [[SPEC-002-visual-key-fingerprint#NFR-102]]
- *negative-output:* over ≥ 10⁵ distinct device keys, two distinct
  fingerprints producing the same image is a failure.
- Parallelised across the machine's cores; an `#[ignore]`d 10⁶ variant exists
  for the deeper run.

### TEST-107: Render latency
**Validates:** [[SPEC-002-visual-key-fingerprint#NFR-104]]
- *positive:* in `screens.mjs`, the time from the authorise screen becoming
  visible to its canvas being painted is < 400 ms.

### TEST-108: The front end recognises before it paints
**Validates:** [[SPEC-002-visual-key-fingerprint#CON-102]]
- *positive:* a well-formed 4096-character value paints.
- *negative-input:* a truncated, over-long, or non-Base64 value is rejected;
  no canvas is painted and the screen still renders its text.

### TEST-109: Terminal geometry
**Validates:** [[SPEC-002-visual-key-fingerprint#CON-103]]
- *positive:* `lifehash_lines` returns 16 lines of 32 glyphs, resetting at each
  line end; the colours of line `y` are pixel rows `2y` and `2y+1`.
- *negative-output:* a line count other than 16, or a row not terminated by a
  reset, fails.

### TEST-110: The reference vectors still reproduce
**Validates:** [[SPEC-002-visual-key-fingerprint#ADR-101]]
- *positive:* the pinned `bc-lifehash` reproduces the [[Blockchain Commons]]
  reference vectors for version 2 byte-for-byte. This is the regression test
  that a dependency bump cannot silently change every user's picture.

---

## Defects found while implementing this specification

Both predate this work and neither was caused by it. They are recorded here
because this is the session that found them, and because the first is the
clearest evidence available that the visual fingerprint does the job
[[SPEC-002-visual-key-fingerprint#REQ-101]] claims for it.

### BUG-101: the home card headlined a fingerprint shown nowhere else

**Severity:** S2 · **Priority:** P1 · **Status:** verified

**Violates:** [[SPEC-002-visual-key-fingerprint#REQ-101]] in spirit —
"every device you link will show this same fingerprint" was false of the value
the home card displayed.

**Actual behaviour.** `create_identity` returned `fingerprint_did(did)`, and the
*created* screen headlined it. `get_state` additionally returned
`root_fingerprint = fingerprint_key(root_pk)`, and the *home* card headlined
**that**. Two domain-separated digests over different inputs, so they never
agreed — the hex and the label already differed, silently, on the screen a user
opens to ask "is this still me?".

`crates/selfsame-core/src/accept.rs` computes `fingerprint_did(&grant.did)`:
every linking client and the CLI display the DID fingerprint. The value the home
card showed appeared **nowhere else in the system**.

**Root cause category:** `design-error`. Two fingerprints were exposed on one
state object with no rule about which surface headlines which, so a screen could
pick the wrong one and nothing would notice.

**How it surfaced.** A human looked at the running app and saw two different
pictures. The hex had been diverging in exactly the same way for as long, and
had not been noticed — which is the case for a recognition aid, made
concretely rather than argued.

**Why no test caught it.** `tests/screens.mjs` used one constant for both
`fingerprint` and `root_fingerprint`, so the stub was self-consistent in a way
the real command never is. A fixture that cannot represent the bug cannot fail
on it.

**Resolution.** The home and restored screens headline `fingerprint`;
`root_fingerprint` is deleted from `AppState` rather than left available, since
a spare fingerprint on the state object is an invitation to headline the wrong
one again. The stub now carries distinct values.

**Regression test:** `tests/screens.mjs` — every screen that headlines the
identity asserts it shows the DID fingerprint. Observed failing first, on both
`06-home` and `15-restored`.

### BUG-102: "Back" from the typed-code screen was a no-op on desktop

**Severity:** S2 · **Priority:** P1 · **Status:** verified

**Violates:** specification gap — no `SCREEN-###` clause governs the typed
route's exit on a platform with no camera.

**Actual behaviour.** `startLink()` branches on the barcode-scanner plugin. On
desktop there is none, so it forwards straight to the typed-code screen — whose
Back button was wired to `to-link`, calling `startLink()` again and landing back
on the same screen. The only control that looked like an exit re-entered the
screen it was leaving.

**Root cause category:** `design-error` — a shared entry point used as a back
target, where the entry point is conditional and the back target is not.

**Resolution.** Back mirrors the same branch `startLink` makes: the scanner on
mobile, home on desktop.

**Regression test:** `tests/screens.mjs` — `back-from-type`. Observed failing
first with *"Back re-entered the typed-code screen — the user cannot leave"*.

---

## Purity Boundary Map

### Pure core (no I/O, no shared state, deterministic)
- `selfsame_core::fingerprint::LifeHash` — computes the 32×32 image
- `selfsame_core::fingerprint::Fingerprint::lifehash` — the rendering entry point

### Effectful shell (orchestrates I/O, calls pure core)
- `src-tauri/src/commands.rs` — serialises `Fp` across IPC
- `crates/selfsame-cli/src/main.rs` — writes half-blocks to stdout
- `src/app.js` — paints a canvas

### Boundary contracts (data types crossing the boundary)
- `LifeHash` → shells, as `[u8; 3072]` or Base64 (outward only)

### Dependency rule
Dependencies point inward: shell → core. The core MUST NOT import from a shell.

### Enforcement
`crates/selfsame-core/tests/purity.rs` (dependency-graph scan and module scan),
plus `cargo-deny` in CI.

---

## Applied UX Heuristics

| Law | Application |
|---|---|
| [[Jakob's Law]] | LifeHash is the established convention for this job in the wallet and DID ecosystem (Sparrow, Blockchain Commons tooling). A user meeting it here meets something they may already read. |
| [[Von Restorff Effect]] | The picture is visually distinct from surrounding text, but is deliberately *not* the most emphasised element on the authorise screen — the hex stays largest, because REQ-103 makes it the answer to the question asked. |
| [[Law of Similarity]] | The same picture treatment on every surface is what makes recognition transfer between them; a differently-styled picture per screen would defeat REQ-101's purpose. |
| [[Miller's Law]] | The picture is one chunk. It replaces three bars the user was implicitly asked to hold as three. |
| [[Doherty Threshold]] | [[SPEC-002-visual-key-fingerprint#NFR-104]], 400 ms. |
| [[Aesthetic-Usability Effect]] | Named as a risk: LifeHash is attractive, and attractiveness invites the reviewer to approve the screen without engaging the comparison task. [[SPEC-002-visual-key-fingerprint#REQ-103]] and TEST-103 exist to keep the *ugly* hex the load-bearing element. |
| [[Selective Attention]] | A small decorative square beside a heading is the shape of an avatar or an advert. Placement keeps it inside the fingerprint block, adjacent to the value it depicts, rather than floating at a screen edge. |

---

## Changelog

<details>
<summary>Revision history — 0.1.0 → 1.0.0</summary>

- 1.0.0 — implemented. Three amendments made during Phase 3, each from a test
  that failed against the spec rather than against the code:
  - [[SPEC-002-visual-key-fingerprint#REQ-101]]'s table gained the phone's
    **device-detail** screen, whose "Key fingerprint" row was a key display the
    original table missed.
  - [[SPEC-002-visual-key-fingerprint#CON-102]]'s grammar was tightened to
    reject `=`: 3072 is divisible by three, so a padded value at this length is
    malformed, and admitting it would have been repair rather than recognition.
  - The **unlink confirmation** screen was recorded under `Open` rather than
    given a picture — it renders no fingerprint at all, so REQ-101 does not
    reach it, and adding one would be a downstream spec editing
    [[SCREEN-001-authorise-a-device]]'s design by encrustation.
- 0.1.0 — initial specification: replaces the three colour bars of
  [[SCREEN-001-authorise-a-device]] with [[LifeHash]] v2, and extends a visual
  fingerprint to every surface that displays a key.
</details>
