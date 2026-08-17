import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import axe from "axe-core";
import puppeteer from "puppeteer";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "src");
const MIME = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css" };

test("TEST-814 CBCL wallet states are keyboard complete and WCAG-clean", async (t) => {
  const server = createServer((request, response) => {
    const path = request.url === "/" ? "/index.html" : request.url.split("?")[0];
    try {
      const body = readFileSync(join(ROOT, path));
      response.writeHead(200, { "content-type": MIME[extname(path)] ?? "application/octet-stream" });
      response.end(body);
    } catch {
      response.writeHead(404).end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const origin = `http://127.0.0.1:${server.address().port}`;
  const browser = await puppeteer.launch({
    headless: true,
    args: process.env.CI ? ["--no-sandbox", "--disable-dev-shm-usage"] : [],
  });
  t.after(() => browser.close());

  for (const width of [1200, 320]) {
    const page = await browser.newPage();
    await page.setViewport({ width, height: 900, deviceScaleFactor: 1 });
    await page.evaluateOnNewDocument(bridge);
    await page.goto(origin, { waitUntil: "networkidle0" });
    await page.click('[data-action="to-applications"]');
    await page.click('[data-action="to-pairing"]');
    await visible(page, "pairing-enter");
    await audit(page, `invitation entry at ${width}px`);

    await page.type("#pairing-input", "o2ZyZWxheXgaaHR0cHM6Ly9yZWxheS5leGFtcGxl");
    assert.equal(await page.$eval('[data-action="start-cbcl-pairing"]', (node) => node.disabled), false);
    await page.focus("#pairing-input");
    await page.keyboard.press("Tab");
    assert.equal(
      await page.evaluate(() => document.activeElement?.dataset.action),
      "start-cbcl-pairing",
    );
    await page.keyboard.press("Enter");
    await visible(page, "pairing-wait");
    assert.equal(await page.evaluate(() => document.activeElement?.dataset.screen), "pairing-wait");
    await audit(page, `pending secure channel at ${width}px`);

    await page.evaluate(() => globalThis.__completeCbclPairingStart());
    await visible(page, "pairing-consent");
    assert.match(await page.$eval("[data-cbcl-authority]", (node) => node.textContent), /Selfsame device grant/);
    assert.match(await page.$eval("[data-cbcl-intent-fields]", (node) => node.textContent), /photos\.example/);
    assert.equal(await page.evaluate(() => document.activeElement?.dataset.screen), "pairing-consent");
    await audit(page, `exact intent consent at ${width}px`);

    await page.keyboard.press("Tab");
    assert.equal(
      await page.evaluate(() => document.activeElement?.dataset.action),
      "cancel-cbcl-pairing",
    );
    await page.keyboard.press("Tab");
    assert.equal(
      await page.evaluate(() => document.activeElement?.dataset.action),
      "approve-cbcl-pairing",
    );
    await page.keyboard.press("Enter");
    await visible(page, "pairing-result");
    assert.match(await page.$eval("[data-cbcl-result-message]", (node) => node.textContent), /13 credential checks/);
    await audit(page, `accepted terminal result at ${width}px`);
    await page.keyboard.press("Tab");
    await page.keyboard.press("Enter");
    await visible(page, "applications");

    await page.click('[data-action="to-pairing"]');
    await page.type("#pairing-input", "selfsame-pairing-v2:obsolete");
    await page.click('[data-action="start-cbcl-pairing"]');
    await page.waitForFunction(() => !document.querySelector('[data-error="pairing"]').hidden);
    assert.match(
      await page.$eval('[data-error="pairing"]', (node) => node.textContent),
      /obsolete development build/,
    );
    await audit(page, `retired invitation refusal at ${width}px`);
    await page.close();
  }
});

function bridge() {
  const state = {
    has_identity: true,
    backup_confirmed: true,
    did: "did:crdt:fixture",
    fingerprint: { hex: "2E 41 D0 88 6B 15", label: "garnet-plover-31", lifehash: "A".repeat(4096) },
    pending_publications: 0,
    devices: [],
    applications: [],
  };
  globalThis.__TAURI__ = {
    core: {
      invoke: async (command, args) => {
        if (command === "get_state") return state;
        if (command === "flush_publications") return 0;
        if (command === "cbcl_pairing_cancel") return null;
        if (command === "cbcl_pairing_approve") {
          return {
            outcome: "accepted",
            title: "Application connected",
            message: "Selfsame accepted all 13 credential checks.",
          };
        }
        if (command === "cbcl_pairing_decline") {
          return {
            outcome: "declined",
            title: "Request declined",
            message: "No credential was shared and the invitation is spent.",
          };
        }
        if (command === "cbcl_pairing_start") {
          if (args.invitation.startsWith("selfsame-pairing-v2:")) {
            throw "PairingVersionUnsupported";
          }
          return new Promise((resolve) => {
            globalThis.__completeCbclPairingStart = () => resolve({
              relayOrigin: "https://relay.example",
              status: "Secure channel ready. Review the exact request.",
              intent: {
                application: "anuna.io/credential/v1",
                action: "issue-credential",
                authoritySummary: "Transfer one Selfsame device grant",
                fields: [
                  { label: "Application", value: "https://photos.example/selfsame/application", claimedBySecretHolder: true },
                  { label: "Origin", value: "https://photos.example", claimedBySecretHolder: true },
                  { label: "Scope", value: "device", claimedBySecretHolder: true },
                ],
              },
            });
          });
        }
        return null;
      },
    },
  };
}

async function visible(page, name) {
  await page.waitForFunction(
    (screen) => !document.querySelector(`[data-screen="${screen}"]`).hidden,
    {},
    name,
  );
}

async function audit(page, state) {
  await page.addScriptTag({ content: axe.source });
  const results = await page.evaluate(async () => globalThis.axe.run(document, {
    runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"] },
  }));
  const blocking = results.violations.filter((item) => ["serious", "critical"].includes(item.impact));
  assert.deepEqual(blocking, [], `${state} has blocking WCAG violations`);
  assert.equal(
    await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth),
    true,
    `${state} overflows horizontally`,
  );
}
