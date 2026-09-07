import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = await readFile(new URL("../src/app-identity.js", import.meta.url), "utf8");
const { initAppIdentity } = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);

test("home counts unique installed applications and clears removed links", () => {
  const summary = { textContent: "" };
  const identity = initAppIdentity({
    $: selector => selector === "[data-applications-summary]" ? summary : null,
    actions: {},
  });
  identity.renderSummary([]);
  assert.match(summary.textContent, /^None yet/);
  identity.renderSummary([], [{ applicationId: "https://chat.example/app" }]);
  assert.match(summary.textContent, /^1 application,/);
  identity.renderSummary([{ application_id: "https://chat.example/app" }]);
  assert.match(summary.textContent, /^1 application,/);
  identity.renderSummary([{ application_id: "https://other.example/app" }]);
  assert.match(summary.textContent, /^2 applications,/);
  identity.renderSummary([], []);
  assert.match(summary.textContent, /^None yet/);
});
