import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path) => readFile(new URL(`../${path}`, import.meta.url), "utf8");

test("TEST-803/804/805: the real wallet shell exposes relay consent and acceptance", async () => {
  const [tauri, commands, html, pairing] = await Promise.all([
    read("src-tauri/Cargo.toml"),
    read("src-tauri/src/cbcl_pairing.rs"),
    read("src/index.html"),
    read("src/pairing.js"),
  ]);

  assert.match(tauri, /local-pairing-demo/);
  assert.match(commands, /cbcl_pairing_approve/);
  assert.match(commands, /cbcl_pairing_decline/);
  assert.match(commands, /ClaimantRelaySession/);
  assert.match(html, /data-screen="pairing-consent"/);
  assert.match(html, /data-screen="pairing-result"/);
  assert.match(pairing, /cbcl_pairing_approve/);
  assert.match(pairing, /cbcl_pairing_decline/);
});

test("TEST-803: the development application exposes the pinned binary relay", async () => {
  const [core, server, liveServer] = await Promise.all([
    read("crates/selfsame-pairing/src/live.rs"),
    read("crates/selfsame-pairing/examples/web-demo/server.rs"),
    read("crates/selfsame-pairing/examples/web-demo/live.rs"),
  ]);

  assert.match(core, /AllocatorRelaySession/);
  assert.match(core, /ClaimantRelaySession/);
  assert.match(`${server}\n${liveServer}`, /route\("\/relay"/);
  assert.match(liveServer, /RelayService/);
});

test("REQ-809: local relay capability cannot enable production allocation", async () => {
  const [release, tauri] = await Promise.all([
    read("crates/selfsame-pairing/src/release.rs"),
    read("src-tauri/Cargo.toml"),
  ]);

  assert.match(release, /PRODUCTION_ALLOCATION_ENABLED:\s*bool\s*=\s*false/);
  assert.doesNotMatch(tauri, /local-pairing-demo[^\n]*PRODUCTION_ALLOCATION_ENABLED/);
});
