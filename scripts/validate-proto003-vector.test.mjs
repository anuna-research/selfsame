// EXP-003 exit criterion: the harness "accepts a labelled non-normative fixture
// AND REJECTS EACH MISSING/WRONG-WIDTH FIELD". The accepting half was already
// demonstrated by running the CLI; this is the other half, and without it the
// harness's refusals are entirely unevidenced — a validator that has never been
// shown to reject is indistinguishable from one that returns true.
//
// Nothing here asserts a cryptographic relation. Every value is structural.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  BYTES16_FIELDS, BYTES32_FIELDS, REQUIRED, validateVector,
} from "./validate-proto003-vector.mjs";

const FIXTURE = "test-vectors/proto-003-spake2-v1.non-normative.json";
const load = () => JSON.parse(readFileSync(FIXTURE, "utf8"));
const without = (key) => { const v = load(); delete v[key]; return v; };

// The control matters as much as the refusals: without it, a harness that threw
// on everything would pass every test below.
test("the control: the shipped fixture is accepted", () => {
  const vector = load();
  assert.doesNotThrow(() => validateVector(vector));
  assert.equal(validateVector(vector), vector, "a valid vector is returned, not copied");
});

test("every required field is required", () => {
  assert.equal(REQUIRED.length, 17, "the field list is the contract; a change here is a schema change");
  for (const field of REQUIRED) {
    assert.throws(() => validateVector(without(field)), new RegExp(`missing ${field}`),
      `removing ${field} must be refused`);
  }
});

test("every fixed-width field rejects a wrong width", () => {
  for (const [fields, ok, short, long] of [
    [BYTES16_FIELDS, 22, "A".repeat(21), "A".repeat(23)],
    [BYTES32_FIELDS, 43, "A".repeat(42), "A".repeat(44)],
  ]) {
    for (const field of fields) {
      assert.equal(load()[field].length, ok, `${field} is ${ok} chars in the fixture`);
      for (const bad of [short, long, "", "A".repeat(ok - 1) + "="]) {
        const v = load(); v[field] = bad;
        assert.throws(() => validateVector(v), /base64url/, `${field} = ${bad.length} chars must be refused`);
      }
    }
  }
});

test("the non-normative label is enforced, not decorative", () => {
  for (const status of ["normative", "", "NON-NORMATIVE", null]) {
    const v = load(); v.status = status;
    assert.throws(() => validateVector(v), /non-normative/,
      "a fixture claiming to be anything but non-normative must be refused");
  }
});

test("the domain version is pinned to v2", () => {
  for (const dv of ["v1", "V2", "", 2]) {
    const v = load(); v.domainVersion = dv;
    assert.throws(() => validateVector(v), /domainVersion must be v2/);
  }
});

test("words must be exactly twelve non-empty strings", () => {
  const cases = [
    load().words.slice(0, 11),
    [...load().words, load().words[0]],
    load().words.map((w, i) => (i === 0 ? "" : w)),
    load().words.map((w, i) => (i === 0 ? 7 : w)),
    "twelve words as one string",
  ];
  for (const words of cases) {
    const v = load(); v.words = words;
    assert.throws(() => validateVector(v), /twelve non-empty strings/);
  }
});

test("the shape is closed: an unknown member is a rejection", () => {
  const v = load(); v.unexpected = "smuggled";
  assert.throws(() => validateVector(v), /unknown unexpected/);
});

test("a non-object is refused before any field is read", () => {
  for (const bad of [null, [], "a string", 42]) {
    assert.throws(() => validateVector(bad), /must be a JSON object/);
  }
});
