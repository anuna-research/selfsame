import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { after } from "node:test";
import axe from "axe-core";
import puppeteer from "puppeteer";

const ROOT = new URL("../", import.meta.url).pathname;
const CLEAN_TARGET = mkdtempSync(join(tmpdir(), "selfsame-pairing-demo-"));

after(() => rmSync(CLEAN_TARGET, { recursive: true, force: true }));

test("TEST-704 approved and declined ceremonies run in same-browser tabs", async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));
  const browser = await puppeteer.launch({
    headless: true,
    args: process.env.CI ? ["--no-sandbox", "--disable-setuid-sandbox"] : [],
  });
  t.after(() => browser.close());

  for (const width of [1200, 320]) {
    await approvedJourney(browser, server.origin, width);
    await declinedJourney(browser, server.origin, width);
  }

  const refusalServer = await startServer({ verifierRefusal: true });
  t.after(() => stopServer(refusalServer));
  await verifierRefusalJourney(browser, refusalServer.origin, 320);

  const failureServer = await startServer({ protocolFailure: true });
  t.after(() => stopServer(failureServer));
  await protocolFailureJourney(browser, failureServer.origin, 1200);
});

test("TEST-709 demo rejects a non-loopback bind", async () => {
  const process = spawn("cargo", [
    "run", "-p", "selfsame-pairing", "--example", "web-demo", "--", "0.0.0.0:0",
  ], {
    cwd: ROOT,
    env: { ...globalThis.process.env, CARGO_TARGET_DIR: CLEAN_TARGET },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  process.stderr.on("data", (chunk) => { stderr += chunk; });
  const [code] = await once(process, "exit");
  assert.equal(code, 2);
  assert.match(stderr, /only to 127\.0\.0\.1/);
});

async function approvedJourney(browser, origin, width) {
  const context = await browser.createBrowserContext();
  await context.overridePermissions(origin, ["clipboard-read", "clipboard-write"]);
  const application = await context.newPage();
  const wallet = await context.newPage();
  await Promise.all([
    application.setViewport({ width, height: 900, deviceScaleFactor: 1 }),
    wallet.setViewport({ width, height: 900, deviceScaleFactor: 1 }),
  ]);
  await Promise.all([application.setBypassCSP(true), wallet.setBypassCSP(true)]);
  await Promise.all([
    application.goto(`${origin}/application`, { waitUntil: "networkidle0" }),
    wallet.goto(`${origin}/wallet`, { waitUntil: "networkidle0" }),
  ]);

  await assertBaseline(application, "Application endpoint");
  await assertBaseline(wallet, "Selfsame wallet endpoint");
  await assertRail(application, ["Waiting", "Waiting", "Waiting", "Waiting", "Waiting", "Waiting", "Waiting", "Waiting"]);
  await assertRail(wallet, ["Waiting", "Waiting", "Waiting", "Waiting", "Waiting", "Waiting", "Waiting", "Waiting"]);
  assert.equal(await wallet.$eval("#consent-panel", (node) => node.hidden), true);

  const startFeedback = await pendingFeedback(application, "#start", "Creating a single-use invitation");
  assert.ok(startFeedback < 100, `start feedback took ${startFeedback}ms`);
  await waitForInvitation(application);
  const invitation = await application.$eval("#invitation", (node) => node.value);
  assert.match(await application.$eval("#status", (node) => node.textContent), /Invitation created/);
  const copyFeedback = await pendingFeedback(application, "#copy", "Copying invitation");
  assert.ok(copyFeedback < 100, `copy feedback took ${copyFeedback}ms`);
  await waitForDom(application, () => /Invitation copied|Copy refused/.test(document.querySelector("#status").textContent));
  assert.equal(await application.$eval("#copy", (node) => node.disabled), false);
  await assertRail(application, ["Complete", "Waiting", "Waiting", "Waiting", "Waiting", "Waiting", "Waiting", "Waiting"]);
  await assertWcag(application, "application invitation-created");

  await wallet.bringToFront();
  await wallet.type("#invitation", invitation);
  const joinFeedback = await pendingFeedback(wallet, "#join", "Establishing the secure ceremony");
  assert.ok(joinFeedback < 100, `join feedback took ${joinFeedback}ms`);
  await wallet.waitForSelector("#consent-panel:not([hidden])");
  await waitForDom(application, () => document.querySelector("#result-title").textContent === "Awaiting wallet decision");
  assert.equal(await wallet.evaluate(() => document.activeElement?.id), "consent-panel");
  const intent = await wallet.$$eval("#intent-fields dd", (nodes) => nodes.map((node) => node.textContent));
  assert.ok(intent.includes("https://photos.example/selfsame/application"));
  assert.ok(intent.includes("https://photos.example"));
  assert.ok(intent.length >= 4);

  const relayText = await wallet.$eval(".relay", (node) => node.textContent);
  assert.ok(!relayText.includes(invitation));
  assert.ok(!relayText.includes("did:key:"));

  for (const page of [application, wallet]) {
    await assertRail(page, ["Complete", "Complete", "Complete", "Complete", "Complete", "Waiting", "Waiting", "Waiting"]);
    await assertWcag(page, "awaiting decision");
  }
  await assertTabOrder(wallet, ["home", "approve", "decline"]);

  await wallet.focus("#approve");
  await new Promise((resolve) => setTimeout(resolve, 800));
  assert.equal(await wallet.evaluate(() => document.activeElement?.id), "approve", "polling must preserve decision focus");
  const approveFeedback = await keyboardFeedback(wallet, "Applying explicit approval");
  assert.ok(approveFeedback < 100, `approval feedback took ${approveFeedback}ms`);
  await Promise.all([
    waitForDom(wallet, () => document.querySelector("#result-title").textContent === "Credential accepted"),
    waitForDom(application, () => document.querySelector("#result-title").textContent === "Credential accepted"),
  ]);
  assert.match(await wallet.$eval("#verifier-summary", (node) => node.textContent), /13 of 13/);
  assert.equal(await wallet.$eval("#reset", (node) => node.disabled), false);
  assert.equal(await wallet.$eval("#approve", (node) => node.disabled), true);
  assert.equal(await wallet.$eval("#decline", (node) => node.disabled), true);
  assert.equal(await application.$eval("#copy", (node) => node.disabled), true);
  assert.deepEqual(await enabledButtons(application), ["reset"]);
  assert.deepEqual(await enabledButtons(wallet), ["reset"]);
  for (const page of [application, wallet]) {
    await assertRail(page, ["Complete", "Complete", "Complete", "Complete", "Complete", "Complete", "Complete", "Complete"]);
    await assertWcag(page, "accepted terminal");
  }

  for (const page of [application, wallet]) {
    assert.equal(
      await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth),
      true,
      "320px viewport must not overflow horizontally",
    );
    assert.deepEqual(await localAccessibilityAudit(page), []);
    await assertWcag(page, `accepted terminal at ${width}px`);
  }
  await assertTabOrder(application, ["home", "reset"]);
  await assertTabOrder(wallet, ["home", "reset"]);
  if (width === 1200) {
    await wallet.setRequestInterception(true);
    const abortReset = (request) => {
      if (request.url().endsWith("/api/reset")) request.abort("failed");
      else request.continue();
    };
    wallet.on("request", abortReset);
    await wallet.click("#reset");
    await waitForDom(wallet, () => document.querySelector("#status").textContent.includes("Retry reset"));
    assert.equal(await wallet.$eval("#reset", (node) => node.disabled), false);
    assert.equal(await wallet.$eval("#reset", (node) => node.hasAttribute("aria-busy")), false);
    await wallet.setRequestInterception(false);
    wallet.off("request", abortReset);
  }
  const walletNavigation = wallet.waitForNavigation({ waitUntil: "domcontentloaded" });
  const resetFeedback = await pendingFeedback(wallet, "#reset", "Resetting ceremony");
  assert.ok(resetFeedback < 100, `wallet reset feedback took ${resetFeedback}ms`);
  await walletNavigation;
  assert.equal(await wallet.$eval("#join", (node) => node.disabled), false);
  assert.equal(await wallet.$eval("#consent-panel", (node) => node.hidden), true);
  await assertWcag(wallet, "wallet reset baseline");
  await context.close();
}

async function declinedJourney(browser, origin, width) {
  const context = await browser.createBrowserContext();
  const application = await context.newPage();
  const wallet = await context.newPage();
  await Promise.all([
    application.setViewport({ width, height: 900, deviceScaleFactor: 1 }),
    wallet.setViewport({ width, height: 900, deviceScaleFactor: 1 }),
  ]);
  await Promise.all([application.setBypassCSP(true), wallet.setBypassCSP(true)]);
  await application.goto(`${origin}/application`);
  await wallet.goto(`${origin}/wallet`);
  await assertBaseline(application, "Application endpoint");
  await assertBaseline(wallet, "Selfsame wallet endpoint");
  await wallet.bringToFront();
  await wallet.type("#invitation", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  await wallet.click("#join");
  await waitForDom(wallet, () => document.querySelector("#result-title").textContent === "Invitation mismatch");
  await assertWcag(wallet, "invitation mismatch");
  await wallet.$eval("#invitation", (node) => { node.value = ""; });
  await application.bringToFront();
  await application.click("#start");
  await waitForInvitation(application);
  await assertWcag(application, "application invitation-created before decline");
  const invitation = await application.$eval("#invitation", (node) => node.value);
  await wallet.bringToFront();
  await wallet.type("#invitation", invitation);
  await wallet.click("#join");
  await wallet.waitForSelector("#consent-panel:not([hidden])");
  await waitForDom(application, () => document.querySelector("#result-title").textContent === "Awaiting wallet decision");
  await Promise.all([
    assertWcag(application, "application awaiting decline"),
    assertWcag(wallet, "wallet awaiting decline"),
  ]);

  if (width === 1200) {
    await wallet.setRequestInterception(true);
    const abortDecision = (request) => {
      if (request.url().endsWith("/api/decline")) request.abort("failed");
      else request.continue();
    };
    wallet.on("request", abortDecision);
    await wallet.bringToFront();
    await wallet.click("#decline");
    await waitForDom(wallet, () => document.querySelector("#status").textContent.includes("Retry, or reset"));
    assert.equal(await wallet.$eval("#approve", (node) => node.disabled), false);
    assert.equal(await wallet.$eval("#decline", (node) => node.disabled), false);
    assert.equal(await wallet.$eval("#reset", (node) => node.disabled), false);
    await wallet.setRequestInterception(false);
    wallet.off("request", abortDecision);
  }

  await wallet.focus("#decline");
  const declineFeedback = await keyboardFeedback(wallet, "Recording decline");
  assert.ok(declineFeedback < 100, `decline feedback took ${declineFeedback}ms`);
  await Promise.all([
    waitForDom(wallet, () => document.querySelector("#result-title").textContent === "Transfer declined"),
    waitForDom(application, () => document.querySelector("#result-title").textContent === "Transfer declined"),
  ]);
  assert.equal(await wallet.$("#relay-mailboxes"), null);
  assert.match(await wallet.$eval("#verifier-summary", (node) => node.textContent), /No accepted credential/);
  assert.equal(await application.$eval("#copy", (node) => node.disabled), true);
  assert.deepEqual(await enabledButtons(application), ["reset"]);
  assert.deepEqual(await enabledButtons(wallet), ["reset"]);
  for (const page of [application, wallet]) {
    await assertRail(page, ["Complete", "Complete", "Complete", "Complete", "Complete", "Complete", "Skipped", "Skipped"]);
    await assertWcag(page, "declined terminal");
  }
  await assertTabOrder(application, ["home", "reset"]);
  await assertTabOrder(wallet, ["home", "reset"]);
  const applicationNavigation = application.waitForNavigation({ waitUntil: "domcontentloaded" });
  const resetFeedback = await pendingFeedback(application, "#reset", "Resetting ceremony");
  assert.ok(resetFeedback < 100, `application reset feedback took ${resetFeedback}ms`);
  await applicationNavigation;
  assert.equal(await application.$eval("#start", (node) => node.disabled), false);
  await assertWcag(application, "application reset baseline");
  await context.close();
}

async function verifierRefusalJourney(browser, origin, width) {
  const applicationContext = await browser.createBrowserContext();
  const walletContext = await browser.createBrowserContext();
  const application = await applicationContext.newPage();
  const wallet = await walletContext.newPage();
  await Promise.all([
    application.setViewport({ width, height: 900, deviceScaleFactor: 1 }),
    wallet.setViewport({ width, height: 900, deviceScaleFactor: 1 }),
  ]);
  await Promise.all([application.setBypassCSP(true), wallet.setBypassCSP(true)]);
  await Promise.all([application.goto(`${origin}/application`), wallet.goto(`${origin}/wallet`)]);
  await application.bringToFront();
  await application.click("#start");
  await waitForInvitation(application);
  const invitation = await application.$eval("#invitation", (node) => node.value);
  await wallet.bringToFront();
  await wallet.type("#invitation", invitation);
  await wallet.click("#join");
  await wallet.waitForSelector("#consent-panel:not([hidden])");
  await wallet.click("#approve");
  await Promise.all([
    waitForDom(wallet, () => document.querySelector("#result-title").textContent === "Verifier refusal"),
    waitForDom(application, () => document.querySelector("#result-title").textContent === "Verifier refusal"),
  ]);
  for (const page of [application, wallet]) {
    await assertRail(page, ["Complete", "Complete", "Complete", "Complete", "Complete", "Complete", "Refused", "Refused"]);
    assert.deepEqual(await enabledButtons(page), ["reset"]);
    assert.equal(
      await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth),
      true,
    );
    await assertWcag(page, "verifier refusal at 320px");
  }
  await Promise.all([applicationContext.close(), walletContext.close()]);
}

async function protocolFailureJourney(browser, origin, width) {
  const applicationContext = await browser.createBrowserContext();
  const walletContext = await browser.createBrowserContext();
  const application = await applicationContext.newPage();
  const wallet = await walletContext.newPage();
  await Promise.all([
    application.setViewport({ width, height: 900, deviceScaleFactor: 1 }),
    wallet.setViewport({ width, height: 900, deviceScaleFactor: 1 }),
  ]);
  await Promise.all([application.setBypassCSP(true), wallet.setBypassCSP(true)]);
  await Promise.all([application.goto(`${origin}/application`), wallet.goto(`${origin}/wallet`)]);
  await application.bringToFront();
  await application.click("#start");
  await waitForInvitation(application);
  const invitation = await application.$eval("#invitation", (node) => node.value);
  await wallet.bringToFront();
  await wallet.type("#invitation", invitation);
  await wallet.click("#join");
  await wallet.waitForSelector("#consent-panel:not([hidden])");
  await wallet.click("#approve");
  await Promise.all([
    waitForDom(wallet, () => document.querySelector("#result-title").textContent === "Protocol failure"),
    waitForDom(application, () => document.querySelector("#result-title").textContent === "Protocol failure"),
  ]);
  for (const page of [application, wallet]) {
    await assertRail(page, ["Complete", "Complete", "Complete", "Complete", "Complete", "Complete", "Refused", "Refused"]);
    assert.deepEqual(await enabledButtons(page), ["reset"]);
    await assertWcag(page, "protocol failure");
  }
  await Promise.all([applicationContext.close(), walletContext.close()]);
}

async function assertBaseline(page, eyebrow) {
  assert.equal(await page.$eval(".hero .eyebrow", (node) => node.textContent), eyebrow);
  const boundary = await page.$eval(".boundary", (node) => node.textContent);
  assert.match(boundary, /Experimental/);
  assert.match(boundary, /cbcl-pairing/);
  assert.match(boundary, /Not production-approved/);
  assert.deepEqual(await localAccessibilityAudit(page), []);
  await assertWcag(page, "baseline");
  const role = await page.evaluate(() => document.documentElement.dataset.role);
  await assertTabOrder(page, role === "application" ? ["home", "start"] : ["home", "invitation", "join"]);
}

async function localAccessibilityAudit(page) {
  await page.bringToFront();
  return page.evaluate(() => {
    const violations = [];
    if (document.documentElement.lang !== "en") violations.push("document-language");
    if (!document.title.trim()) violations.push("document-title");
    if (document.querySelectorAll("h1").length !== 1) violations.push("single-h1");
    if (!document.querySelector("main")) violations.push("main-landmark");
    const ids = [...document.querySelectorAll("[id]")].map((node) => node.id);
    if (new Set(ids).size !== ids.length) violations.push("duplicate-id");
    for (const control of document.querySelectorAll("button, textarea")) {
      if (control.hidden || control.closest("[hidden]")) continue;
      const name = control.labels?.[0]?.textContent?.trim()
        || control.getAttribute("aria-label")
        || control.textContent.trim();
      if (!name) violations.push(`unnamed-control:${control.id}`);
      const box = control.getBoundingClientRect();
      if (control.matches("button") && (box.width < 44 || box.height < 44)) {
        violations.push(`small-target:${control.id}`);
      }
    }
    const live = document.querySelector('[role="status"][aria-live="polite"]');
    if (!live) violations.push("missing-live-region");

    const parseColor = (value) => {
      const parts = value.match(/[\d.]+/g)?.map(Number) || [];
      return parts.length >= 3 ? [parts[0], parts[1], parts[2], parts[3] ?? 1] : null;
    };
    const luminance = ([red, green, blue]) => {
      const linear = [red, green, blue].map((channel) => {
        const value = channel / 255;
        return value <= .04045 ? value / 12.92 : ((value + .055) / 1.055) ** 2.4;
      });
      return .2126 * linear[0] + .7152 * linear[1] + .0722 * linear[2];
    };
    const background = (node) => {
      for (let current = node; current; current = current.parentElement) {
        const color = parseColor(getComputedStyle(current).backgroundColor);
        if (color && color[3] > .99) return color;
      }
      return [255, 255, 255, 1];
    };
    for (const node of document.querySelectorAll("h1, h2, p, label, button, a, dt, dd, em, .step-number")) {
      if (node.hidden || node.closest("[hidden]") || node.matches(":disabled")) continue;
      const style = getComputedStyle(node);
      if (style.display === "none" || style.visibility === "hidden" || Number(style.opacity) < 1) continue;
      const foreground = parseColor(style.color);
      if (!foreground) continue;
      const light = Math.max(luminance(foreground), luminance(background(node)));
      const dark = Math.min(luminance(foreground), luminance(background(node)));
      const ratio = (light + .05) / (dark + .05);
      const size = Number.parseFloat(style.fontSize);
      const weight = Number.parseInt(style.fontWeight, 10) || 400;
      const minimum = size >= 24 || (size >= 18.66 && weight >= 700) ? 3 : 4.5;
      if (ratio < minimum) violations.push(`contrast:${node.id || node.className || node.tagName}`);
    }

    const decisions = [...document.querySelectorAll(".decision-row button:not(:disabled)")]
      .filter((node) => !node.closest("[hidden]"));
    if (decisions.length === 2) {
      const first = decisions[0].getBoundingClientRect();
      const second = decisions[1].getBoundingClientRect();
      const horizontal = Math.max(0, second.left - first.right, first.left - second.right);
      const vertical = Math.max(0, second.top - first.bottom, first.top - second.bottom);
      if (Math.max(horizontal, vertical) < 8) violations.push("decision-target-spacing");
    }
    return violations;
  });
}

async function assertWcag(page, state) {
  await page.bringToFront();
  assert.equal(
    await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth),
    true,
    `${state} must not overflow horizontally`,
  );
  const loaded = await page.evaluate(() => Boolean(globalThis.axe));
  if (!loaded) await page.addScriptTag({ content: axe.source });
  const results = await page.evaluate(async () => globalThis.axe.run(document, {
    runOnly: {
      type: "tag",
      values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"],
    },
  }));
  const blocking = results.violations
    .filter((violation) => ["critical", "serious"].includes(violation.impact))
    .map((violation) => `${violation.id}: ${violation.nodes.map((node) => node.target.join(" ")).join(", ")}`);
  assert.deepEqual(blocking, [], `${state} must have no serious or critical WCAG 2.2 AA violations`);
}

async function assertRail(page, expected) {
  await page.bringToFront();
  assert.deepEqual(
    await page.$$eval("[data-gate] em", (nodes) => nodes.map((node) => node.textContent)),
    expected,
  );
}

async function enabledButtons(page) {
  await page.bringToFront();
  return page.$$eval("button:not(:disabled)", (nodes) => nodes
    .filter((node) => !node.closest("[hidden]"))
    .map((node) => node.id));
}

async function assertTabOrder(page, expected) {
  await page.bringToFront();
  await page.focus("#home");
  const observed = [await page.evaluate(() => document.activeElement?.id)];
  for (let index = 1; index < expected.length; index += 1) {
    await page.keyboard.press("Tab");
    observed.push(await page.evaluate(() => document.activeElement?.id));
  }
  assert.deepEqual(observed, expected, "Tab order must follow the visual control order");
}

async function keyboardFeedback(page, expected) {
  await page.bringToFront();
  await page.evaluate((message) => {
    const status = document.querySelector("#status");
    globalThis.__selfsameFeedback = new Promise((resolve, reject) => {
      const started = performance.now();
      const timeout = setTimeout(() => {
        observer.disconnect();
        reject(new Error(`missing pending feedback: ${status.textContent}`));
      }, 1_000);
      const observer = new MutationObserver(() => {
        if (status.textContent.includes(message)) {
          clearTimeout(timeout);
          observer.disconnect();
          resolve(performance.now() - started);
        }
      });
      observer.observe(status, { childList: true, characterData: true, subtree: true });
    });
  }, expected);
  await page.keyboard.press("Enter");
  return page.evaluate(() => globalThis.__selfsameFeedback);
}

async function pendingFeedback(page, selector, expected) {
  await page.bringToFront();
  return page.$eval(selector, (button, message) => {
    const started = performance.now();
    button.click();
    const status = document.querySelector("#status").textContent;
    if (!status.includes(message)) throw new Error(`missing pending feedback: ${status}`);
    return performance.now() - started;
  }, expected);
}

async function waitForInvitation(page) {
  try {
    await waitForDom(page, () => document.querySelector("#invitation").value.length > 80);
  } catch (error) {
    const state = await page.evaluate(() => ({
      role: document.documentElement.dataset.role,
      status: document.querySelector("#status").textContent,
      invitationLength: document.querySelector("#invitation").value.length,
    }));
    const cookieNames = (await page.cookies()).map((cookie) => cookie.name);
    throw new Error(`invitation did not appear: ${JSON.stringify({ state, cookieNames })}`, { cause: error });
  }
}

async function waitForDom(page, predicate) {
  await page.bringToFront();
  await page.waitForFunction(predicate, { polling: 50 });
}

async function startServer({ verifierRefusal = false, protocolFailure = false } = {}) {
  const process = spawn(
    "cargo",
    ["run", "-p", "selfsame-pairing", "--example", "web-demo"],
    {
      cwd: ROOT,
      env: {
        ...globalThis.process.env,
        CARGO_TARGET_DIR: CLEAN_TARGET,
        ...(verifierRefusal ? { SELFSAME_DEMO_TEST_VERIFIER_REFUSAL: "1" } : {}),
        ...(protocolFailure ? { SELFSAME_DEMO_TEST_PROTOCOL_FAILURE: "1" } : {}),
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let output = "";
  let errors = "";
  process.stderr.on("data", (chunk) => { errors += chunk; });
  const origin = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`demo did not start: ${output}${errors}`)), 120_000);
    process.stdout.on("data", (chunk) => {
      output += chunk;
      const match = output.match(/(http:\/\/127\.0\.0\.1:\d+)\/application/);
      if (match) {
        clearTimeout(timeout);
        resolve(match[1]);
      }
    });
    process.once("exit", (code) => reject(new Error(`demo exited ${code}: ${output}${errors}`)));
    process.once("error", reject);
  });
  return { process, origin };
}

async function stopServer(server) {
  if (server.process.exitCode !== null) return;
  server.process.kill("SIGTERM");
  await once(server.process, "exit");
}
