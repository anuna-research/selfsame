import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import axe from "axe-core";
import puppeteer from "puppeteer";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "src");
const TAURI_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "src-tauri", "src");
const MIME = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css" };

test("TEST-1161 pending completion retains the authenticated offer profile for restart recovery", () => {
  const completion = readFileSync(join(TAURI_ROOT, "cbcl_v2_completion.rs"), "utf8");
  const commands = readFileSync(join(TAURI_ROOT, "cbcl_v2_commands.rs"), "utf8");
  assert.match(completion, /offer_profile: String/);
  assert.match(completion, /pub fn offer_profile_octets\(&self\)/);
  assert.match(commands, /offer_profile_octets: pending\.claimant\.profile_octets\(\)/);
});

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
    await page.type("#pairing-presence-code", "PAIR1-22222-22222-22222-22222-22222-22222-22222-22222-22222-22222-22222");
    await page.type("#pairing-passcode", "correct horse battery staple");
    assert.equal(await page.$eval('[data-action="start-cbcl-pairing"]', (node) => node.disabled), false);
    await page.click('[data-action="start-cbcl-pairing"]');
    await visible(page, "pairing-wait");
    assert.equal(await page.evaluate(() => document.activeElement?.dataset.screen), "pairing-wait");
    await audit(page, `pending secure channel at ${width}px`);

    await page.evaluate(() => globalThis.__completeCbclV2Recognise());
    await visible(page, "pairing-consent");
    assert.match(await page.$eval("[data-cbcl-consent-title]", (node) => node.textContent), /Trust this new relay/);
    assert.match(await page.$eval("[data-cbcl-intent-fields]", (node) => node.textContent), /relay\.example/);
    assert.equal(await page.evaluate(() => document.activeElement?.dataset.screen), "pairing-consent");
    await audit(page, `exact application-relay consent at ${width}px`);

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
    await page.waitForFunction(() => /exact request/i.test(document.querySelector("[data-cbcl-consent-title]").textContent));
    assert.match(await page.$eval("[data-cbcl-intent-fields]", (node) => node.textContent), /photos\.example/);
    await audit(page, `authenticated intent consent at ${width}px`);
    await page.click('[data-action="approve-cbcl-pairing"]');
    await page.waitForFunction(() => /account linking/i.test(document.querySelector("[data-cbcl-consent-title]").textContent));
    assert.match(await page.$eval("[data-cbcl-intent-fields]", (node) => node.textContent), /AA BB CC DD EE FF/);
    await audit(page, `final identity consent at ${width}px`);
    await page.click('[data-action="approve-cbcl-pairing"]');
    await visible(page, "pairing-result");
    assert.match(await page.$eval("[data-cbcl-result-message]", (node) => node.textContent), /reciprocal account binding/);
    await audit(page, `accepted terminal result at ${width}px`);
    await page.keyboard.press("Tab");
    await page.keyboard.press("Enter");
    await visible(page, "applications");

    await page.click('[data-action="to-pairing"]');
    await page.type("#pairing-input", "selfsame-pairing-v2:obsolete");
    await page.type("#pairing-presence-code", "PAIR1-22222-22222-22222-22222-22222-22222-22222-22222-22222-22222-22222");
    await page.click('[data-action="start-cbcl-pairing"]');
    await page.waitForFunction(() => !document.querySelector('[data-error="pairing"]').hidden);
    assert.match(
      await page.$eval('[data-error="pairing"]', (node) => node.textContent),
      /could not be recognised/,
    );
    await audit(page, `retired invitation refusal at ${width}px`);
    await page.close();
  }
});

test("TEST-1161 restart recovery preserves pending through rotation consent", async (t) => {
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
  const browser = await puppeteer.launch({ headless: true });
  t.after(() => browser.close());
  const page = await browser.newPage();
  await page.evaluateOnNewDocument(recoveryBridge);
  await page.goto(`http://127.0.0.1:${server.address().port}`, { waitUntil: "networkidle0" });

  await visible(page, "pairing-consent");
  assert.match(
    await page.$eval("[data-cbcl-consent-title]", (node) => node.textContent),
    /Finish interrupted link/,
  );
  await page.type("#pairing-passcode", "correct horse battery staple");
  await page.click('[data-action="approve-cbcl-pairing"]');
  await page.waitForFunction(() => /authority changed/i.test(
    document.querySelector("[data-cbcl-consent-title]").textContent,
  ));
  assert.match(
    await page.$eval("[data-cbcl-intent-fields]", (node) => node.textContent),
    /old-profile-digest.*new-profile-digest/s,
  );
  await page.click('[data-action="decline-cbcl-pairing"]');
  await page.waitForFunction(() => document.querySelector('[data-screen="pairing-consent"]').hidden);
  assert.equal(await page.evaluate(() => globalThis.__recoveryCalls.length), 1);
  assert.equal(await page.evaluate(() => globalThis.__recoveryCalls[0].approveRotation), false);

  await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
  await visible(page, "pairing-consent");
  await page.type("#pairing-passcode", "correct horse battery staple");
  await page.click('[data-action="approve-cbcl-pairing"]');
  await page.waitForFunction(() => /authority changed/i.test(
    document.querySelector("[data-cbcl-consent-title]").textContent,
  ));
  await page.click('[data-action="approve-cbcl-pairing"]');
  await visible(page, "pairing-result");
  assert.match(
    await page.$eval("[data-cbcl-result-title]", (node) => node.textContent),
    /Application connected/,
  );
  assert.equal(await page.evaluate(() => globalThis.__recoveryCalls.at(-1).approveRotation), true);
  assert.equal(
    await page.evaluate(() => JSON.stringify(globalThis.__recoveryCalls).includes("recoveryToken")),
    false,
  );
});

test("TEST-1159 installed links reload, prompt on rotation, and unlink locally", async (t) => {
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
  const browser = await puppeteer.launch({ headless: true });
  t.after(() => browser.close());
  const page = await browser.newPage();
  await page.evaluateOnNewDocument(installedBridge);
  await page.goto(`http://127.0.0.1:${server.address().port}`, { waitUntil: "networkidle0" });
  await page.click('[data-action="to-applications"]');
  await page.waitForSelector("[data-cbcl-v2-link]");
  assert.match(
    await page.$eval("[data-cbcl-v2-links]", (node) => node.textContent),
    /chat\.anuna\.io.*acct:ss-installed/s,
  );

  await page.click("[data-cbcl-v2-link]");
  await visible(page, "pairing-link");
  await audit(page, "installed credential/v2 link");
  await page.click('[data-action="verify-cbcl-v2-link"]');
  await page.waitForFunction(() => /authority changed/i.test(
    document.querySelector("[data-cbcl-v2-link-status]").textContent,
  ));
  assert.equal(
    await page.$eval('[data-action="accept-cbcl-v2-rotation"]', (node) => node.hidden),
    false,
  );
  await page.click('[data-action="accept-cbcl-v2-rotation"]');
  await page.waitForFunction(() => /fresh pairing/i.test(
    document.querySelector("[data-cbcl-v2-link-status]").textContent,
  ));

  await page.click('[data-action="to-cbcl-v2-unlink"]');
  await visible(page, "pairing-link-unlink");
  await audit(page, "installed credential/v2 unlink confirmation");
  await page.type("#cbcl-v2-unlink-passcode", "correct horse battery staple");
  await page.click('[data-action="confirm-cbcl-v2-unlink"]');
  await visible(page, "applications");
  assert.equal(await page.evaluate(() => globalThis.__v2UnlinkCalls.length), 1);
  assert.deepEqual(
    await page.evaluate(() => globalThis.__v2UnlinkCalls[0]),
    {
      applicationId: "https://chat.anuna.io/selfsame/v2",
      confirmation: true,
      passcode: "correct horse battery staple",
    },
  );
  assert.equal(await page.$("[data-cbcl-v2-link]"), null);
  assert.match(
    await page.$eval("[data-cbcl-v2-unlink-boundary]", (node) => node.textContent),
    /does not revoke.*hub/i,
  );
});

test("TEST-1162 interrupted pre-payload links are visible and locally abandonable", async (t) => {
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
  const browser = await puppeteer.launch({ headless: true });
  t.after(() => browser.close());
  const page = await browser.newPage();
  await page.evaluateOnNewDocument(pendingLinkBridge);
  await page.goto(`http://127.0.0.1:${server.address().port}`, { waitUntil: "networkidle0" });
  await page.click('[data-action="to-applications"]');
  await page.waitForSelector("[data-cbcl-v2-pending-link]");
  assert.match(
    await page.$eval("[data-cbcl-v2-links]", (node) => node.textContent),
    /Interrupted link.*chat\.anuna\.io.*chat\.anuna\.io:9443/s,
  );

  await page.click("[data-cbcl-v2-pending-link]");
  await visible(page, "pairing-pending-link");
  await audit(page, "interrupted credential/v2 link");
  await page.click('[data-action="to-cbcl-v2-pending-unlink"]');
  await visible(page, "pairing-link-unlink");
  await page.type("#cbcl-v2-unlink-passcode", "correct horse battery staple");
  await page.click('[data-action="confirm-cbcl-v2-unlink"]');
  await visible(page, "applications");
  assert.deepEqual(
    await page.evaluate(() => globalThis.__v2PendingUnlinkCalls),
    [{
      applicationId: "https://chat.anuna.io/selfsame/v2",
      confirmation: true,
      passcode: "correct horse battery staple",
    }],
  );
  assert.equal(await page.$("[data-cbcl-v2-pending-link]"), null);
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
        if (command === "cbcl_v2_cancel") return null;
        if (command === "cbcl_v2_recognise") {
          if (args.invitation.startsWith("selfsame-pairing-v2:")) {
            throw "RecognitionFailed";
          }
          return new Promise((resolve) => {
            globalThis.__completeCbclV2Recognise = () => resolve({
              applicationId: "https://photos.example/selfsame/application",
              relayOrigin: "https://relay.example",
              requiresApproval: true,
            });
          });
        }
        if (command === "cbcl_v2_relay_decide") return args.approve ? {
          outcome: "intent",
          intent: {
            applicationId: "https://photos.example/selfsame/application",
            httpsOrigin: "https://photos.example",
            relayOrigin: "https://relay.example",
            permissions: ["https://photos.example/selfsame/application#device"],
            deviceDid: `did:key:z6Mk${"1".repeat(44)}`,
            accountPrincipalDigest: "A".repeat(43),
            tofuState: "new-pair",
            transition: { kind: "none", legacyHandle: null, migrationRooms: [] },
          },
        } : { outcome: "declined", intent: null };
        if (command === "cbcl_v2_preliminary_decide") return args.approve ? {
          outcome: "final-review",
          finalReview: {
            applicationId: "https://photos.example/selfsame/application",
            previewIssuerDid: "did:crdt:fixture-account",
            previewFingerprint: { hex: "AA BB CC DD EE FF", label: "copper-lynx-42", lifehash: "A".repeat(4096) },
            comparison: "no-binding-person-compared",
          },
        } : { outcome: "declined", finalReview: null };
        if (command === "cbcl_v2_final_decide") return { outcome: args.approve ? "payload-sent" : "declined" };
        if (command === "cbcl_v2_finish") return { outcome: "installed" };
        return null;
      },
    },
  };
}

function recoveryBridge() {
  const applicationId = "https://photos.example/selfsame/application";
  const state = {
    has_identity: true,
    backup_confirmed: true,
    did: "did:crdt:fixture",
    fingerprint: { hex: "2E 41 D0 88 6B 15", label: "garnet-plover-31", lifehash: "A".repeat(4096) },
    pending_publications: 0,
    devices: [],
    applications: [],
  };
  globalThis.__recoveryCalls = [];
  globalThis.__TAURI__ = {
    core: {
      invoke: async (command, args) => {
        if (command === "get_state") return state;
        if (command === "flush_publications") return 0;
        if (command === "cbcl_v2_pending_recoveries") return [applicationId];
        if (command === "cbcl_v2_recover") {
          globalThis.__recoveryCalls.push(args);
          if (!args.approveRotation) return {
            outcome: "authority-rotation",
            applicationId,
            retryAfterSeconds: null,
            authorityRotation: {
              retainedKid: `${applicationId}#old`,
              currentKid: `${applicationId}#new`,
              retainedProfileDigest: "old-profile-digest",
              currentProfileDigest: "new-profile-digest",
            },
          };
          return { outcome: "installed", applicationId, retryAfterSeconds: null, authorityRotation: null };
        }
        return null;
      },
    },
  };
}

function installedBridge() {
  const applicationId = "https://chat.anuna.io/selfsame/v2";
  const account = "acct:ss-installed@accounts.chat.anuna.io";
  const state = {
    has_identity: true,
    backup_confirmed: true,
    did: "did:crdt:fixture",
    fingerprint: { hex: "2E 41 D0 88 6B 15", label: "garnet-plover-31", lifehash: "A".repeat(4096) },
    pending_publications: 0,
    devices: [],
    applications: [],
  };
  let linked = true;
  let reloadCount = 0;
  globalThis.__v2UnlinkCalls = [];
  globalThis.__TAURI__ = {
    core: {
      invoke: async (command, args) => {
        if (command === "get_state") return state;
        if (command === "flush_publications") return 0;
        if (command === "service_endpoint") return "https://did.example";
        if (command === "cbcl_pairing_capability") return { demoRelay: false, productionClaimant: true };
        if (command === "cbcl_v2_pending_recoveries") return [];
        if (command === "cbcl_v2_installed_links") return linked ? [{
          applicationId,
          account,
          relayOrigin: "https://chat.anuna.io:9443",
          issuerDid: `did:crdt:${"a".repeat(64)}`,
        }] : [];
        if (command === "cbcl_v2_reload_verify") {
          reloadCount += 1;
          if (reloadCount === 1) return {
            outcome: "authority-rotation",
            applicationId,
            capability: false,
            recordRetained: true,
            rotation: { kind: "profile-signing-key", retained: "old", current: "new" },
          };
          return {
            outcome: "fresh-pairing-required",
            applicationId,
            capability: false,
            recordRetained: true,
            rotation: { kind: "profile-signing-key", retained: "old", current: "new" },
          };
        }
        if (command === "cbcl_v2_unlink") {
          globalThis.__v2UnlinkCalls.push(args);
          linked = false;
          return { outcome: "unlinked", applicationId, remoteRevocationClaimed: false };
        }
        return null;
      },
    },
  };
}

function pendingLinkBridge() {
  const applicationId = "https://chat.anuna.io/selfsame/v2";
  const relayOrigin = "https://chat.anuna.io:9443";
  const state = {
    has_identity: true,
    backup_confirmed: true,
    did: "did:crdt:fixture",
    fingerprint: { hex: "2E 41 D0 88 6B 15", label: "garnet-plover-31", lifehash: "A".repeat(4096) },
    pending_publications: 0,
    devices: [],
    applications: [],
  };
  let pending = true;
  globalThis.__v2PendingUnlinkCalls = [];
  globalThis.__TAURI__ = {
    core: {
      invoke: async (command, args) => {
        if (command === "get_state") return state;
        if (command === "flush_publications") return 0;
        if (command === "service_endpoint") return "https://did.example";
        if (command === "cbcl_pairing_capability") return { demoRelay: false, productionClaimant: true };
        if (command === "cbcl_v2_pending_recoveries") return [];
        if (command === "cbcl_v2_installed_links") return [];
        if (command === "cbcl_v2_pending_links") return pending ? [{
          applicationId,
          relayOrigin,
          phase: "issuer-created",
        }] : [];
        if (command === "cbcl_v2_unlink") {
          globalThis.__v2PendingUnlinkCalls.push(args);
          pending = false;
          return { outcome: "abandoned", applicationId, remoteRevocationClaimed: false };
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
