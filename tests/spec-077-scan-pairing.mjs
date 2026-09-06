// SPEC-077 TEST-004/007: actual rendered wallet screen with controlled native bridge.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import puppeteer from "puppeteer";
import axe from "axe-core";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "src");
const mime = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css" };

async function openWallet(t, mode = "full") {
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
  await page.evaluate(mode => { globalThis.__manualEntry = mode === "manual"; }, mode);
  if (mode === "manual") {
    await page.click('[data-pairing-manual] summary');
    await page.waitForFunction(() => document.querySelector('[data-pairing-complete]').hidden);
  }
  return page;
}

const title = page => page.$eval("[data-cbcl-consent-title]", el => el.textContent);
const visible = (page, screen) => page.waitForSelector(`[data-screen="${screen}"]:not([hidden])`);

async function beginEntry(page) {
  if (await page.evaluate(() => !!globalThis.__manualEntry)) {
    await page.click('[data-action="scan-cbcl-manual"]');
    await page.waitForFunction(() => document.querySelector('#pairing-manual-bootstrap').value.length > 0);
    await page.type('#pairing-manual-words', "abandon abandon absent");
    await page.click('[data-action="start-cbcl-pairing"]');
  } else await page.click('[data-action="scan-cbcl-pairing"]');
}
async function scanToIntent(page) {
  await beginEntry(page);
  await page.waitForFunction(() => globalThis.__calls.some(c => c.command === "cbcl_v2_contact"));
  const manual = await page.evaluate(() => !!globalThis.__manualEntry);
  assert.deepEqual(await page.evaluate(command => __calls.find(c => c.command === command).args,
    manual ? "cbcl_v2_begin_manual" : "cbcl_v2_begin_handoff"), manual
    ? { request: { bootstrap: "SSPAIR-M1:fixture", words: "abandon abandon absent" } }
    : { request: { handoff: "SSPAIR1:fixture" } });
  await visible(page, "pairing-consent");
  assert.match(await title(page), /exact request/i);
  await page.type("#pairing-passcode", "fixture passcode");
}
async function ready(page) {
  await scanToIntent(page);
  await page.click('[data-action="approve-cbcl-pairing"]');
  await page.waitForFunction(() => __calls.some(c => c.command === "cbcl_v2_preview_rendered"));
  await page.waitForFunction(() => !document.querySelector('[data-action="approve-cbcl-pairing"]').disabled);
}
const count = (page, command) => page.evaluate(c => __calls.filter(x => x.command === c).length, command);

for (const mode of ["full", "manual"]) {
test(`${mode}: SPEC079 TEST002/003/010 scan unlocks once and a real render enables one Link`, async t => {
  const page = await openWallet(t, mode);
  await page.setViewport({ width: 320, height: 900 });
  await scanToIntent(page);
  const original = await page.$eval('[data-cbcl-intent-fields]', el => [...el.querySelectorAll('dd')].map(x => x.textContent));
  await page.evaluate(() => {
    globalThis.__frames = [];
    window.requestAnimationFrame = callback => { __frames.push(callback); return __frames.length; };
  });
  await page.click('[data-action="approve-cbcl-pairing"]');
  await page.waitForFunction(() => document.querySelector('[data-cbcl-intent-fields]').textContent.includes("AA BB CC DD EE FF"));
  assert.equal(await page.$eval('#pairing-passcode', el => el.value), "");
  assert.equal(await page.$eval('[data-action="approve-cbcl-pairing"]', el => el.disabled), true);
  assert.equal(await count(page, "cbcl_v2_preview_rendered"), 0);
  assert.equal(await count(page, "cbcl_v2_link"), 0);
  await page.evaluate(() => { const batch = __frames.splice(0); for (const f of batch) f(performance.now()); });
  assert.equal(await count(page, "cbcl_v2_preview_rendered"), 0, "one animation callback is not a paint barrier");
  await page.evaluate(() => { const batch = __frames.splice(0); for (const f of batch) f(performance.now()); });
  await page.waitForFunction(() => __calls.some(c => c.command === "cbcl_v2_preview_rendered"));
  assert.equal(await count(page, "cbcl_v2_link"), 0, "rendering alone grants no disclosure");
  const review = await page.$eval('[data-cbcl-intent-fields]', el => el.textContent);
  for (const value of original) assert.ok(review.includes(value), value);
  assert.match(review, /did:crdt:fixture-account/);
  assert.equal(await page.evaluate(() => document.activeElement.dataset.action), "approve-cbcl-pairing");
  await page.keyboard.press("Enter");
  await page.waitForFunction(() => __calls.some(c => c.command === "cbcl_v2_continue_link"));
  assert.equal(await count(page, "cbcl_v2_finish_link"), 0);
  assert.equal(await page.$eval('[data-action="approve-cbcl-pairing"]', el => el.disabled), true);
  assert.match(await page.$eval('[data-cbcl-channel-status]', el => el.textContent), /desktop comparison/i);
  assert.equal(await page.$eval('[data-cbcl-channel-status]', el => el.getAttribute('role')), "status");
  await page.evaluate(() => { document.querySelector('[data-action="approve-cbcl-pairing"]').click(); __finishComparison(); });
  await visible(page, "pairing-result");
  for (const command of ["cbcl_v2_unlock_preview", "cbcl_v2_link", "cbcl_v2_continue_link", "cbcl_v2_finish_link"]) assert.equal(await count(page, command), 1);
  for (const command of ["cbcl_v2_preliminary_decide", "cbcl_v2_compare", "cbcl_v2_final_decide", "cbcl_v2_relay_decide"]) assert.equal(await count(page, command), 0);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
});

test(`${mode}: SPEC079 TEST007 cancel fences a delayed comparison and never reports installation`, async t => {
  const page = await openWallet(t, mode);
  await ready(page);
  await page.click('[data-action="approve-cbcl-pairing"]');
  await page.waitForFunction(() => __calls.some(c => c.command === "cbcl_v2_continue_link"));
  await page.click('[data-screen="pairing-consent"] [data-action="cancel-cbcl-pairing"]');
  await visible(page, "applications");
  await page.evaluate(async () => { __finishComparison(); await new Promise(resolve => setTimeout(resolve, 30)); });
  await visible(page, "applications");
  assert.equal(await count(page, "cbcl_v2_finish_link"), 0);
  assert.equal(await count(page, "cbcl_v2_cancel_link"), 1);
});

test(`${mode}: SPEC079 TEST007 a late reservation is cancelled before contact without cancelling the new tag`, async t => {
  const page = await openWallet(t, mode);
  await page.evaluate(() => { globalThis.__holdRecognition = true; });
  await beginEntry(page);
  await visible(page, "pairing-wait");
  await page.click('[data-screen="pairing-wait"] [data-action="cancel-cbcl-pairing"]');
  await visible(page, "applications");
  await page.evaluate(() => { globalThis.__holdRecognition = false; });
  await page.click('[data-action="to-pairing"]');
  if (mode === "manual") {
    await page.click('[data-pairing-manual] summary');
    await page.waitForFunction(() => document.querySelector('[data-pairing-complete]').hidden);
  }
  await ready(page);
  await page.evaluate(async () => { __finishRecognition(); await new Promise(resolve => setTimeout(resolve, 30)); });
  await visible(page, "pairing-consent");
  const commands = await page.evaluate(() => __calls.filter(c => ["cbcl_v2_contact", "cbcl_v2_cancel_link"].includes(c.command)));
  assert.equal(commands.length, 2);
  assert.equal(commands[0].command, "cbcl_v2_contact");
  assert.equal(commands[1].command, "cbcl_v2_cancel_link");
  assert.notEqual(commands[0].args.request.attemptTag, commands[1].args.request.attemptTag);
});

test(`${mode}: SPEC079 TEST007 cancelling disables Link before cancellation returns`, async t => {
  const page = await openWallet(t, mode);
  await ready(page);
  await page.evaluate(() => { globalThis.__holdCancel = true; });
  await page.click('[data-screen="pairing-consent"] [data-action="cancel-cbcl-pairing"]');
  await page.waitForFunction(() => typeof __finishCancel === 'function');
  assert.equal(await page.$eval('[data-action="approve-cbcl-pairing"]', el => el.disabled), true);
  await page.evaluate(() => document.querySelector('[data-action="approve-cbcl-pairing"]').click());
  assert.equal(await count(page, "cbcl_v2_link"), 0);
  await page.evaluate(() => __finishCancel());
  await visible(page, "applications");
});

test(`${mode}: SPEC079 TEST010 failed unlock clears passcode`, async t => {
  const page = await openWallet(t, mode);
  await scanToIntent(page);
  await page.evaluate(() => { globalThis.__badUnlock = true; });
  await page.click('[data-action="approve-cbcl-pairing"]');
  await visible(page, "pairing-enter");
  assert.equal(await page.$eval('#pairing-passcode', el => el.value), "");
  assert.equal(await count(page, "cbcl_v2_link"), 0);
});

test(`${mode}: SPEC079 TEST008/010 a non-installed finish result cannot report success`, async t => {
  const page = await openWallet(t, mode);
  await page.evaluate(() => { globalThis.__badReceipt = true; });
  await ready(page);
  await page.click('[data-action="approve-cbcl-pairing"]');
  await page.waitForFunction(() => typeof __finishComparison === 'function');
  await page.evaluate(() => __finishComparison());
  await visible(page, "pairing-result");
  assert.doesNotMatch(await page.$eval('[data-cbcl-result-title]', el => el.textContent), /connected/i);
  assert.match(await page.$eval('[data-cbcl-result-title]', el => el.textContent), /needs checking/i);
  assert.match(await page.$eval('[data-cbcl-result-message]', el => el.textContent), /could not establish/i);
  assert.doesNotMatch(await page.$eval('[data-screen="pairing-result"]', el => el.textContent), /grant was not installed/i);
});

test(`${mode}: SPEC079 TEST007/008 ambiguous continuation exposes retained recovery without a negative claim`, async t => {
  const page = await openWallet(t, mode);
  await ready(page);
  await page.evaluate(() => { globalThis.__badContinue = true; });
  await page.click('[data-action="approve-cbcl-pairing"]');
  await visible(page, "pairing-result");
  assert.match(await page.$eval('[data-cbcl-result-title]', el => el.textContent), /needs checking/i);
  assert.match(await page.$eval('[data-cbcl-result-message]', el => el.textContent), /sealed completion checkpoint/i);
  assert.doesNotMatch(await page.$eval('[data-screen="pairing-result"]', el => el.textContent), /nothing (?:was )?shared|was not installed/i);
  assert.equal(await count(page, "cbcl_v2_finish_link"), 0);
  assert.ok(await count(page, "cbcl_v2_pending_recoveries") >= 1);
});

test(`${mode}: SPEC079 TEST008 finish committed-then-error reports unknown completion and checks local state`, async t => {
  const page = await openWallet(t, mode);
  await page.evaluate(() => { globalThis.__finishError = true; });
  await ready(page);
  await page.click('[data-action="approve-cbcl-pairing"]');
  await page.waitForFunction(() => typeof __finishComparison === 'function');
  await page.evaluate(() => __finishComparison());
  await visible(page, "pairing-result");
  assert.doesNotMatch(await page.$eval('[data-cbcl-result-title]', el => el.textContent), /connected/i);
  assert.match(await page.$eval('[data-cbcl-result-title]', el => el.textContent), /needs checking/i);
  assert.match(await page.$eval('[data-cbcl-result-message]', el => el.textContent), /installed link is present/i);
  assert.doesNotMatch(await page.$eval('[data-screen="pairing-result"]', el => el.textContent), /grant was not installed/i);
  assert.ok(await count(page, "cbcl_v2_installed_links") >= 1);
});

test(`${mode}: SPEC079 TEST007 background and navigation revoke tagged review before further actions`, async t => {
  const page = await openWallet(t, mode);
  await ready(page);
  await page.evaluate(() => {
    Object.defineProperty(document, 'hidden', { configurable: true, value: true });
    document.dispatchEvent(new Event('visibilitychange'));
  });
  await page.waitForFunction(() => __calls.some(c => c.command === "cbcl_v2_cancel_link"));
  await page.evaluate(() => document.querySelector('[data-action="approve-cbcl-pairing"]').click());
  assert.equal(await count(page, "cbcl_v2_link"), 0);
});

}

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
      checkPermissions: async () => globalThis.__cameraAccess ?? "granted",
      requestPermissions: async () => "denied",
      scan: async () => {
        const result = { content: globalThis.__manualEntry ? "SSPAIR-M1:fixture" : "SSPAIR1:fixture" };
        return globalThis.__holdScan ? new Promise(resolve => { globalThis.__finishScan = () => resolve(result); }) : result;
      },
      cancel: async () => { globalThis.__cameraCancels = (globalThis.__cameraCancels ?? 0) + 1; },
    },
    core: { invoke: async (command, args) => {
      __calls.push({ command, args });
      if (command === "get_state") return { has_identity: true, backup_confirmed: true, did: "did:crdt:fixture", fingerprint: { hex: "00 00 00 00 00 00", label: "fixture", lifehash: "A".repeat(4096) }, pending_publications: 0, devices: [], applications: [] };
      if (command === "flush_publications") return 0;
      if (command === "cbcl_v2_cancel_link" && globalThis.__holdCancel) return new Promise(resolve => { globalThis.__finishCancel = () => resolve(null); });
      if (command === "cbcl_v2_begin_handoff" || command === "cbcl_v2_begin_manual") {
        if (command === "cbcl_v2_begin_manual" && globalThis.__badManual) throw "RecognitionFailed";
        globalThis.__tagNumber = (globalThis.__tagNumber ?? 0) + 1;
        const view = { attemptTag: __tagNumber.toString(16).padStart(32, '0'), phase: "reserved", applicationId: preview.applicationId, relayOrigin: "https://relay.example" };
        return globalThis.__holdRecognition
          ? new Promise(resolve => { globalThis.__finishRecognition = () => resolve(view); })
          : view;
      }
      if (command === "cbcl_v2_contact") return { phase: "authenticated-request", intent: {
        applicationId: preview.applicationId, httpsOrigin: "https://photos.example", relayOrigin: "https://relay.example", permissions: [preview.applicationId + "#device"], deviceDid: "did:key:device-fixture", accountPrincipalDigest: "A".repeat(43), tofuState: "ceremony-gesture", transition: { kind: "path-a-to-b", legacyHandle:"@alice", migrationRooms: ["room-fixture"] },
      } };
      if (command === "cbcl_v2_unlock_preview") {
        if (globalThis.__badUnlock) throw new Error("BadPasscode");
        return { phase: "preview-unpainted", review: preview };
      }
      if (command === "cbcl_v2_preview_rendered") return { phase: "review-ready" };
      if (command === "cbcl_v2_link") return { phase: "comparing" };
      if (command === "cbcl_v2_continue_link") {
        if (globalThis.__badContinue) {
          globalThis.__recoverable = true;
          throw new Error("PairingCheckpointUnavailable");
        }
        return new Promise(resolve => { globalThis.__finishComparison = () => resolve({ phase: "await-receipt" }); });
      }
      if (command === "cbcl_v2_finish_link") {
        if (globalThis.__finishError) {
          globalThis.__installed = true;
          throw new Error("PairingExpired");
        }
        if (globalThis.__badReceipt) return { outcome: "pending" };
        return { outcome: "installed" };
      }
      if (command === "cbcl_v2_pending_recoveries") return globalThis.__recoverable ? [preview.applicationId] : [];
      if (command === "cbcl_v2_installed_links") return globalThis.__installed ? [{ applicationId: preview.applicationId }] : [];
      return null;
    } },
  };
}


test("manual bootstrap scan waits for words and local refusal preserves correction", async t => {
  const page = await openWallet(t, "manual");
  const messages = [];
  page.on("console", message => messages.push(message.text()));
  await page.setViewport({ width: 320, height: 900 });
  await page.click('[data-action="scan-cbcl-manual"]');
  await page.waitForFunction(() => document.querySelector('#pairing-manual-bootstrap').value === "SSPAIR-M1:fixture" || __calls.some(c => c.command === "cbcl_v2_begin_handoff" || c.command === "cbcl_v2_begin_manual"));
  assert.equal(await count(page, "cbcl_v2_begin_manual"), 0);
  assert.equal(await count(page, "cbcl_v2_contact"), 0);
  assert.equal(await page.$eval('[data-action="start-cbcl-pairing"]', el => el.disabled), true);
  assert.equal(await page.evaluate(() => document.activeElement.id), "pairing-manual-words");
  await page.type('#pairing-manual-words', "wrong local spelling");
  await page.evaluate(() => { globalThis.__badManual = true; });
  await page.click('[data-action="start-cbcl-pairing"]');
  await visible(page, "pairing-enter");
  await page.waitForFunction(() => !document.querySelector('[data-error="pairing"]').hidden);
  assert.equal(await page.$eval('#pairing-manual-bootstrap', el => el.value), "SSPAIR-M1:fixture");
  assert.equal(await page.$eval('#pairing-manual-words', el => el.value), "wrong local spelling");
  assert.match(await page.$eval('[data-error="pairing"]', el => el.textContent), /check both inputs/i);
  assert.equal(await count(page, "cbcl_v2_contact"), 0);
  assert.equal(await count(page, "cbcl_v2_begin_handoff"), 0);
  assert.equal(await count(page, "cbcl_v2_recognise"), 0);
  assert.equal(await page.$eval('[data-action="start-cbcl-pairing"]', el => el.disabled), false);
  await page.evaluate(source => { const script = document.createElement("script"); script.textContent = source; document.head.append(script); }, axe.source);
  const audit = await page.evaluate(() => axe.run(document.querySelector('[data-screen="pairing-enter"]'), { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21aa"] } }));
  assert.deepEqual(audit.violations.map(v => v.id), []);
  await page.$eval('#pairing-manual-words', el => { el.value = " ABANDON\tABANDON absent "; el.dispatchEvent(new Event("input", { bubbles: true })); });
  await page.evaluate(() => { globalThis.__badManual = false; });
  await page.click('[data-action="start-cbcl-pairing"]');
  await visible(page, "pairing-consent");
  assert.equal(await count(page, "cbcl_v2_begin_manual"), 2);
  assert.equal(await count(page, "cbcl_v2_contact"), 1);
  for (const field of ["#pairing-manual-bootstrap", "#pairing-manual-words"]) assert.equal(await page.$eval(field, el => el.value), "");
  const observations = await page.evaluate(() => ({
    url: location.href, text: document.body.textContent,
    attributes: [...document.querySelectorAll('*')].flatMap(el => [...el.attributes].map(a => a.value)).join(" "),
    storage: JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage)]),
  }));
  for (const text of [...Object.values(observations), ...messages]) assert.doesNotMatch(text, /SSPAIR-M1:fixture|wrong local spelling|ABANDON\tABANDON absent/);
});

for (const mode of ["full", "manual"]) test(`${mode}: late scanner cannot enter or overwrite a successor`, async t => {
  const page = await openWallet(t, mode);
  await page.evaluate(() => { globalThis.__holdScan = true; });
  await page.click(mode === "manual" ? '[data-action="scan-cbcl-manual"]' : '[data-action="scan-cbcl-pairing"]');
  await page.waitForFunction(() => typeof __finishScan === "function");
  await page.click('[data-screen="pairing-enter"] [data-action="cancel-cbcl-pairing"]');
  await visible(page, "applications");
  assert.equal(await page.evaluate(() => __cameraCancels), 1);
  await page.click('[data-action="to-pairing"]');
  await page.type('#pairing-input', "successor-private-input");
  await page.evaluate(async () => { __finishScan(); await new Promise(resolve => setTimeout(resolve, 30)); });
  assert.equal(await page.$eval('#pairing-input', el => el.value), "successor-private-input");
  assert.equal(await page.$eval('#pairing-manual-bootstrap', el => el.value), "");
  assert.equal(await count(page, "cbcl_v2_begin_manual"), 0);
  assert.equal(await count(page, "cbcl_v2_begin_handoff"), 0);
  assert.equal(await count(page, "cbcl_v2_contact"), 0);
});

test("manual disposal clears inputs and explicit legacy selection cannot fall back", async t => {
  const page = await openWallet(t, "manual");
  await page.type('#pairing-manual-bootstrap', "private-bootstrap");
  await page.type('#pairing-manual-words', "private words here");
  await page.$eval('[data-pairing-legacy]', el => { el.open = true; });
  await page.waitForFunction(() => !document.querySelector('[data-pairing-manual]').open);
  for (const field of ["#pairing-manual-bootstrap", "#pairing-manual-words"]) assert.equal(await page.$eval(field, el => el.value), "");
  await page.click('[data-pairing-manual] summary');
  await page.waitForFunction(() => !document.querySelector('[data-pairing-legacy]').open);
  await page.type('#pairing-manual-bootstrap', "private-bootstrap");
  await page.type('#pairing-manual-words', "private words here");
  await page.evaluate(() => { Object.defineProperty(document, "hidden", { configurable: true, value: true }); document.dispatchEvent(new Event("visibilitychange")); });
  for (const field of ["#pairing-manual-bootstrap", "#pairing-manual-words"]) assert.equal(await page.$eval(field, el => el.value), "");
  assert.equal(await count(page, "cbcl_v2_begin_manual"), 0);
});

for (const [access, expected] of [["denied", /off for Selfsame/i], ["prompt", /was declined/i]]) {
  test(`manual camera ${access} leaves a separate paste path`, async t => {
    const page = await openWallet(t, "manual");
    await page.evaluate(access => { globalThis.__cameraAccess = access; }, access);
    await page.click('[data-action="scan-cbcl-manual"]');
    await page.waitForFunction(() => !document.querySelector('[data-pairing-scanner-note]').hidden);
    assert.match(await page.$eval('[data-pairing-scanner-note]', el => el.textContent), expected);
    assert.ok(await page.$('#pairing-manual-bootstrap'));
    assert.equal(await count(page, "cbcl_v2_begin_manual"), 0);
    assert.equal(await count(page, "cbcl_v2_contact"), 0);
  });
}

test("manual missing camera plugin keeps paste usable without contact", async t => {
  const page = await openWallet(t, "manual");
  await page.evaluate(() => { delete window.__TAURI__.barcodeScanner; });
  await page.click('[data-action="scan-cbcl-manual"]');
  assert.match(await page.$eval('[data-pairing-scanner-note]', el => el.textContent), /no camera.*paste/i);
  await page.type('#pairing-manual-bootstrap', "SSPAIR-M1:pasted-fixture");
  await page.type('#pairing-manual-words', "abandon abandon absent");
  assert.equal(await page.$eval('[data-action="start-cbcl-pairing"]', el => el.disabled), false);
  assert.equal(await count(page, "cbcl_v2_contact"), 0);
});
