#!/usr/bin/env node
// EXP-003 structural harness. It intentionally validates no cryptographic
// relation; TEST-403 remains blocked on reviewed vectors and two implementations.
import { readFileSync } from "node:fs";

const input = process.argv[2] ?? "test-vectors/proto-003-spake2-v1.non-normative.json";
const vector = JSON.parse(readFileSync(input, "utf8"));
const required = ["status", "domainVersion", "bindingCanonicalJson", "bindingHash", "c", "words", "m", "n", "wBytes", "pA", "pB", "sharedElement", "transcriptHash", "k", "cA", "cB", "mailboxSecret"];
const bytes16 = /^[A-Za-z0-9_-]{22}$/;
const bytes32 = /^[A-Za-z0-9_-]{43}$/;
const bytes32Fields = ["bindingHash", "m", "n", "wBytes", "pA", "pB", "sharedElement", "transcriptHash", "k", "cA", "cB"];

for (const field of required) if (!(field in vector)) throw new Error(`missing ${field}`);
if (vector.status !== "non-normative") throw new Error("fixture must be labelled non-normative");
if (vector.domainVersion !== "v2") throw new Error("domainVersion must be v2");
if (typeof vector.bindingCanonicalJson !== "string") throw new Error("bindingCanonicalJson must be text");
if (!Array.isArray(vector.words) || vector.words.length !== 12 || vector.words.some(word => typeof word !== "string" || word.length === 0)) throw new Error("words must be twelve non-empty strings");
if (!bytes16.test(vector.c) || !bytes16.test(vector.mailboxSecret)) throw new Error("C and mailboxSecret must be 16-byte base64url");
for (const field of bytes32Fields) if (!bytes32.test(vector[field])) throw new Error(`${field} must be 32-byte base64url`);
for (const field of Object.keys(vector)) if (!required.includes(field)) throw new Error(`unknown ${field}`);

console.log(`${input}: structurally valid non-normative EXP-003 fixture`);
