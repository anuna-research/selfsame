// SPEC-077 TEST-004/007: actual rendered wallet screen with controlled native bridge.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import puppeteer from "puppeteer";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "src");
const mime = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css" };

async function openWallet(t) {
  const server = createServer((req, res) => {
    const path = req.url === "/" ? "/index.html" : req.url.split("?")[0];
    try { const body = readFileSync(join(root, path)); res.writeHead(200, { "content-type": mime[extname(path)] ?? "application/octet-stream" }); res.end(body); }
    catch { res.writeHead(404).end(); }
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const browser = await puppeteer.launch({ headless: true, args: process.env.CI ? ["--no-sandbox"] : [] });
  t.after(() => browser.close());
  const page = await browser.newPage();
  page.setDefaultTimeout(4000);
  await page.evaluateOnNewDocument(scanBridge);
  await page.goto(`http://127.0.0.1:${server.address().port}`, { waitUntil: "networkidle0" });
  await page.click('[data-action="to-applications"]');
  await page.click('[data-action="to-pairing"]');
  return page;
}

const title = page => page.$eval("[data-cbcl-consent-title]", el => el.textContent);
const visible = (page, screen) => page.waitForSelector(`[data-screen="${screen}"]:not([hidden])`);

async function scanToIntent(page) {
  await page.type("#pairing-passcode", "fixture passcode");
  await page.click('[data-action="scan-cbcl-pairing"]');
  await page.waitForFunction(() => globalThis.__calls.some(c => c.command === "cbcl_v2_recognise_handoff"));
  assert.deepEqual(await page.evaluate(() => __calls.find(c => c.command === "cbcl_v2_recognise_handoff").args), { handoff: "SSPAIR1:fixture" });
  await visible(page, "pairing-consent");
  assert.match(await title(page), /relay/i);
  assert.doesNotMatch(await page.$eval('[data-screen="pairing-consent"]', el => el.textContent), /Finished values verified/);
  await page.click('[data-action="approve-cbcl-pairing"]');
  await page.waitForFunction(() => /exact request/i.test(document.querySelector('[data-cbcl-consent-title]').textContent));
}

test("SPEC-077 scan needs no pairing-code typing; preview paints before comparison and final keeps request", async t => {
  const page = await openWallet(t);
  await page.setViewport({ width: 320, height: 900 });
  await scanToIntent(page);
  await page.evaluate(() => {
    globalThis.__frames = [];
    window.requestAnimationFrame = callback => { __frames.push(callback); return __frames.length; };
  });
  await page.click('[data-action="approve-cbcl-pairing"]');
  await page.waitForFunction(() => document.querySelector('[data-cbcl-intent-fields]').textContent.includes("AA BB CC DD EE FF"));
  assert.equal(await page.$eval('[data-cbcl-intent-fields]', el => {
    const fingerprint = [...el.querySelectorAll('dd')].find(node => node.textContent === 'AA BB CC DD EE FF');
    const bounds = fingerprint.getBoundingClientRect();
    return bounds.top >= 0 && bounds.bottom <= window.innerHeight;
  }), true, 'comparison fingerprint is visible without scrolling');
  assert.equal(await page.$eval('[data-action="approve-cbcl-pairing"]', el => el.disabled), true);
  assert.equal(await page.evaluate(() => __calls.filter(c => c.command === "cbcl_v2_compare").length), 0);
  await page.evaluate(() => { for (let i = 0; i < 3; i++) { const batch = __frames.splice(0); for (const f of batch) f(performance.now()); } });
  await page.waitForFunction(() => __calls.some(c => c.command === "cbcl_v2_compare"));
  assert.equal(await page.$eval('[data-action="approve-cbcl-pairing"]', el => el.disabled), true);
  await page.evaluate(() => __finishComparison());
  await page.waitForFunction(() => /account linking/i.test(document.querySelector('[data-cbcl-consent-title]').textContent));
  const fields = await page.$eval('[data-cbcl-intent-fields]', el => el.textContent);
  for (const value of ["AA BB CC DD EE FF", "photos.example", "relay.example", "did:key:device-fixture", "#device"]) assert.ok(fields.includes(value), value);
  assert.equal(await page.$eval('[data-action="approve-cbcl-pairing"]', el => el.disabled), false);
  await page.click('[data-action="approve-cbcl-pairing"]');
  await visible(page, "pairing-result");
  assert.equal(await page.evaluate(() => __calls.filter(c => c.command === "cbcl_v2_final_decide").length), 1);
});

test("SPEC-077 cancellation suppresses a delayed comparison result and final approval", async t => {
  const page = await openWallet(t);
  await scanToIntent(page);
  await page.click('[data-action="approve-cbcl-pairing"]');
  await page.waitForFunction(() => __calls.some(c => c.command === "cbcl_v2_compare"));
  await page.click('[data-screen="pairing-consent"] [data-action="cancel-cbcl-pairing"]');
  await visible(page, "applications");
  await page.evaluate(async () => { __finishComparison(); await new Promise(resolve => setTimeout(resolve, 30)); });
  await visible(page, "applications");
  assert.equal(await page.evaluate(() => __calls.filter(c => c.command === "cbcl_v2_final_decide").length), 0);
});

test("SPEC-077 cancellation during invitation recognition ignores its delayed response", async t => {
  const page = await openWallet(t);
  await page.evaluate(() => { globalThis.__holdRecognition = true; });
  await page.click('[data-action="scan-cbcl-pairing"]');
  await visible(page, "pairing-wait");
  await page.click('[data-screen="pairing-wait"] [data-action="cancel-cbcl-pairing"]');
  await visible(page, "applications");
  await page.evaluate(async () => { __finishRecognition(); await new Promise(resolve => setTimeout(resolve, 30)); });
  await visible(page, "applications");
  assert.equal(await page.evaluate(() => __calls.filter(c => c.command === "cbcl_v2_relay_decide").length), 0);
});


test("SPEC-077 cancelling makes final approval inert before native cancellation returns", async t => {
  const page = await openWallet(t);
  await scanToIntent(page);
  await page.click('[data-action="approve-cbcl-pairing"]');
  await page.waitForFunction(() => typeof __finishComparison === 'function');
  await page.evaluate(() => __finishComparison());
  await page.waitForFunction(() => /account linking/i.test(document.querySelector('[data-cbcl-consent-title]').textContent));
  await page.evaluate(() => { globalThis.__holdCancel = true; });
  await page.click('[data-screen="pairing-consent"] [data-action="cancel-cbcl-pairing"]');
  await page.waitForFunction(() => typeof __finishCancel === 'function');
  assert.equal(await page.$eval('[data-action="approve-cbcl-pairing"]', el => el.disabled), true);
  await page.evaluate(() => document.querySelector('[data-action="approve-cbcl-pairing"]').click());
  assert.equal(await page.evaluate(() => __calls.filter(c => c.command === "cbcl_v2_final_decide").length), 0);
  await page.evaluate(() => __finishCancel());
  await visible(page, "applications");
});


function scanBridge() {
  const preview = {
    applicationId: "https://photos.example/selfsame/application",
    previewIssuerDid: "did:crdt:fixture-account",
    previewFingerprint: { hex: "AA BB CC DD EE FF", label: "copper-lynx-42", lifehash: "A".repeat(4096) },
    comparison: "waiting",
  };
  globalThis.__calls = [];
  globalThis.__TAURI__ = {
    barcodeScanner: {
      checkPermissions: async () => "granted",
      scan: async () => ({ content: "SSPAIR1:fixture" }),
    },
    core: { invoke: async (command, args) => {
      __calls.push({ command, args });
      if (command === "get_state") return { has_identity: true, backup_confirmed: true, did: "did:crdt:fixture", fingerprint: { hex: "00 00 00 00 00 00", label: "fixture", lifehash: "A".repeat(4096) }, pending_publications: 0, devices: [], applications: [] };
      if (command === "flush_publications") return 0;
      if (command === "cbcl_v2_cancel" && globalThis.__holdCancel) return new Promise(resolve => { globalThis.__finishCancel = () => resolve(null); });
      if (command === "cbcl_v2_recognise_handoff") {
        const view = { applicationId: preview.applicationId, relayOrigin: "https://relay.example", requiresApproval: true };
        return globalThis.__holdRecognition
          ? new Promise(resolve => { globalThis.__finishRecognition = () => resolve(view); })
          : view;
      }
      if (command === "cbcl_v2_relay_decide") return { outcome: "intent", intent: {
        applicationId: preview.applicationId, httpsOrigin: "https://photos.example", relayOrigin: "https://relay.example", permissions: [preview.applicationId + "#device"], deviceDid: "did:key:device-fixture", accountPrincipalDigest: "A".repeat(43), tofuState: "new-pair", transition: { kind: "none", migrationRooms: [] },
      } };
      if (command === "cbcl_v2_preliminary_decide") return { outcome: "preview", finalReview: preview };
      if (command === "cbcl_v2_compare") return new Promise(resolve => { globalThis.__finishComparison = () => resolve({ ...preview, comparison: "no-binding-person-compared" }); });
      if (command === "cbcl_v2_final_decide") return { outcome: "payload-sent" };
      if (command === "cbcl_v2_finish") return { outcome: "installed" };
      return null;
    } },
  };
}
