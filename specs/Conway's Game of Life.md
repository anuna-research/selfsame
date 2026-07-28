---
id: CONCEPT-GameOfLife
title: Conway's Game of Life
status: active
last-updated: 2026-07-28
---

# Conway's Game of Life

A two-dimensional cellular automaton devised by John Conway in 1970. Cells on a
grid are live or dead; each generation, every cell's next state depends only on
its eight neighbours:

- A **live** cell with 2 or 3 live neighbours stays live; otherwise it dies.
- A **dead** cell with exactly 3 live neighbours becomes live.

That is the whole rule. From it come gliders, oscillators, still lifes, and —
relevant here — the reliable tendency of random starting states to settle into
*structured* configurations within a few dozen generations.

## Why a visual hash uses it

[[LifeHash]] seeds the grid from a cryptographic digest and runs the automaton,
accumulating every generation into one image.

The point is not randomness — the digest already supplies that. The point is
the opposite: uniform entropy renders as static, and humans cannot remember or
compare static. The automaton is a deterministic function that turns noise into
shapes with edges, symmetry and mass, which recognition memory *can* hold.
Determinism is what keeps the picture a hash: the same digest always produces
the same evolution.

The run terminates on whichever comes first — a repeated state (the automaton
has entered a cycle, so later generations carry no new information) or a
generation cap.

## Reference

- Gardner, M. *Mathematical Games: The fantastic combinations of John Conway's
  new solitaire game "life"*. Scientific American, October 1970.
- <https://en.wikipedia.org/wiki/Conway%27s_Game_of_Life>
