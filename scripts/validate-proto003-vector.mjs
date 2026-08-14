#!/usr/bin/env node
// EXP-003 structural harness. It intentionally validates no cryptographic
// relation; TEST-403 remains blocked on reviewed vectors and two implementations.
//
// The validator is EXPORTED so its refusals can be tested. An accept-only
// harness proves that one fixture passes and nothing whatever about what it
// rejects — and EXP-003's exit criteria ask for both halves: it converges when
// the harness "accepts a labelled non-normative fixture and rejects each
// missing/wrong-width field". See validate-proto003-vector.test.mjs.
import { readFileSync } from "node:fs";

export const REQUIRED = [
  "status", "domainVersion", "bindingCanonicalJson", "bindingHash", "c", "words",
  "m", "n", "wBytes", "pA", "pB", "sharedElement", "transcriptHash", "k", "cA",
  "cB", "mailboxSecret",
];

// Unpadded base64url of a fixed-width byte string: 16 bytes -> 22 chars,
// 32 bytes -> 43. Width is checked rather than merely "looks like base64",
// because a truncated element is the failure a shape harness can actually catch.
const bytes16 = /^[A-Za-z0-9_-]{22}$/;
const bytes32 = /^[A-Za-z0-9_-]{43}$/;

export const BYTES16_FIELDS = ["c", "mailboxSecret"];
export const BYTES32_FIELDS = [
  "bindingHash", "m", "n", "wBytes", "pA", "pB", "sharedElement",
  "transcriptHash", "k", "cA", "cB",
];

/** Throws on the first structural fault. Returns the vector on success. */
export function validateVector(vector) {
  if (vector === null || typeof vector !== "object" || Array.isArray(vector)) {
    throw new Error("vector must be a JSON object");
  }
  for (const field of REQUIRED) if (!(field in vector)) throw new Error(`missing ${field}`);
  // The label is load-bearing, not decorative: EXP-003 forbids treating any
  // fixture as normative cryptographic output, so a fixture that does not say
  // so about itself is refused here rather than trusted downstream.
  if (vector.status !== "non-normative") throw new Error("fixture must be labelled non-normative");
  if (vector.domainVersion !== "v2") throw new Error("domainVersion must be v2");
  if (typeof vector.bindingCanonicalJson !== "string") throw new Error("bindingCanonicalJson must be text");
  if (!Array.isArray(vector.words) || vector.words.length !== 12
      || vector.words.some((word) => typeof word !== "string" || word.length === 0)) {
    throw new Error("words must be twelve non-empty strings");
  }
  for (const field of BYTES16_FIELDS) {
    if (!bytes16.test(vector[field])) throw new Error(`${field} must be 16-byte base64url`);
  }
  for (const field of BYTES32_FIELDS) {
    if (!bytes32.test(vector[field])) throw new Error(`${field} must be 32-byte base64url`);
  }
  // Closed shape: an unknown member is a rejection rather than an extension
  // point, so a second implementation cannot quietly add a field the first
  // never reproduces.
  for (const field of Object.keys(vector)) if (!REQUIRED.includes(field)) throw new Error(`unknown ${field}`);
  return vector;
}

// CLI only when invoked directly, so importing this for tests runs nothing.
if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  const input = process.argv[2] ?? "test-vectors/proto-003-spake2-v1.non-normative.json";
  validateVector(JSON.parse(readFileSync(input, "utf8")));
  console.log(`${input}: structurally valid non-normative EXP-003 fixture`);
}
