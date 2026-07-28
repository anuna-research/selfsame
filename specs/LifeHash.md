---
id: CONCEPT-LifeHash
title: LifeHash
status: active
last-updated: 2026-07-28
---

# LifeHash

A **visual hash**: a deterministic function from arbitrary data to a small
colour image, designed so that a human can tell two inputs apart by looking
rather than by reading. By Wolf McNally and Christopher Allen at
[[Blockchain Commons]]; demo and gallery at <https://lifehash.info/>.

The problem it solves is that people do not reliably compare hex strings.
Asked whether `C0 7A 1E 42 9B 33` matches `C0 7A 1E 42 9D 33`, a user under
time pressure says yes. Asked whether two *pictures* match, they are using
recognition memory, which is the faculty humans are actually good at.

## How it works

1. SHA-256 the input.
2. Use the digest to seed a 16×16 [[Conway's Game of Life]] grid — one bit per
   cell.
3. Run the automaton, up to 150 generations, stopping early when a state
   repeats.
4. Overlay every generation into a fractional grid — so the image records the
   automaton's whole history, not just its final state — and normalise to
   `0..1`.
5. Draw entropy from the digest to choose a colour gradient and a symmetry
   pattern.
6. Apply the symmetry, doubling the grid to 32×32, and colour it.

The Game of Life step is the interesting one. Uniform entropy looks like
static, and static is not memorable. Running it through a cellular automaton
converts noise into *structure* — blobs, filaments, symmetries — which is what
recognition memory can hold. The symmetry pass then makes the result read as an
object rather than a texture.

## Versions

| Version | Grid | Generations | Notes |
|---|---|---|---|
| `version1` | 16×16 | 150 | Deprecated. HSB gamut, not CMYK-friendly, minor gradient defects. |
| `version2` | 16×16 | 150 | **Recommended.** CMYK-friendly gamut. Re-hashes the digest so it cannot resemble version 1. |
| `detailed` | 32×32 | 300 | Double resolution. |
| `fiducial` | 32×32 | 300 | High contrast, for machine vision. |
| `grayscale_fiducial` | 32×32 | 300 | As above, without colour. |

Output for `version1`/`version2` is a **32×32 RGB image** — the 16×16 grid
doubled by the symmetry pattern.

[[SPEC-002-visual-key-fingerprint]] uses `version2`.

## Implementations

The C++ implementation is canonical; the others are validated against its test
vectors. Independent implementations agreeing byte-for-byte is the whole value
proposition, so re-implementing rather than depending is a poor trade — see
[[SPEC-002-visual-key-fingerprint#ADR-101]].

| Language | Crate / package | Note |
|---|---|---|
| C++/C | `bc-lifehash` | reference |
| Rust | `bc-lifehash` | first-party; byte-identical across 35 vectors |
| Swift | `LifeHash` | reference |
| Java | `toucan` | Sparrow Wallet |
| Python | `bc-lifehash-python` | Cramium |

## Use in Selfsame

Selfsame renders the LifeHash of a key's *fingerprint*, not of the key itself,
so that the picture and the hex are two renderings of one 48-bit value
([[SPEC-002-visual-key-fingerprint#ADR-102]]). It is a recognition aid; the hex
remains the normative comparison value
([[SPEC-002-visual-key-fingerprint#REQ-103]]).
