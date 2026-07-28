/**
 * Screen-render check for Selfsame.
 *
 * Walks every screen of the flow with a stubbed Tauri bridge and asserts three
 * things a Rust test cannot see: exactly one screen is visible at a time, no
 * screen overflows horizontally at phone width, and nothing throws on the way
 * through. It also writes a PNG per screen, which is how the implementation is
 * compared against `docs/mockup/Selfsame.html`.
 *
 * The bridge returns the shapes the real commands return. It is deliberately
 * dumb: this file checks *presentation*, and every security decision it might
 * otherwise appear to exercise is made in `selfsame-core` and tested there.
 *
 *   node apps/selfsame/tests/screens.mjs out/
 */
import puppeteer from 'puppeteer';
import { createServer } from 'node:http';
import { readFileSync, mkdirSync } from 'node:fs';
import { extname, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// ES modules are blocked from file:// origins, so serve the real directory.
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };
const server = createServer((req, res) => {
  const path = req.url === '/' ? '/index.html' : req.url.split('?')[0];
  try {
    const body = readFileSync(join(ROOT, path));
    res.writeHead(200, { 'content-type': MIME[extname(path)] || 'application/octet-stream' });
    res.end(body);
  } catch {
    res.writeHead(404).end();
  }
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const SRC = `http://127.0.0.1:${server.address().port}/index.html`;
const OUT = process.argv[2] ?? 'screens-out';
mkdirSync(OUT, { recursive: true });

const STATE_LINKED = {
  has_identity: true,
  backup_confirmed: true,
  did: 'did:crdt:9f3a11c2e70b4d8a5c6f9012ab34cd56ef78901234abcd56ef7890123456abcd',
  fingerprint: '5F 9A C9 07 2E 11',
  root_fingerprint: '5F 9A C9 07 2E 11',
  pending_publications: 1,
  devices: [
    { method_id: 'did:crdt:9f3a…#dev-1', label: 'Chrome on macOS', revoked: false, last_seen: Math.floor(Date.now()/1000) - 120, pending: false },
    { method_id: 'did:crdt:9f3a…#dev-2', label: 'hark on workstation-01', revoked: false, last_seen: null, pending: true },
    { method_id: 'did:crdt:9f3a…#dev-3', label: 'Firefox on the old laptop', revoked: true, last_seen: null, pending: false },
  ],
};

const bridge = (state) => `
  window.__TAURI__ = {
    core: {
      invoke: async (cmd, args) => {
        switch (cmd) {
          case 'get_state': return ${JSON.stringify(state)};
          case 'service_endpoint': return 'http://127.0.0.1:8787';
          case 'create_identity': return {
            words: ['harbour','lichen','quarry','saddle','verbena','tundra','gravel','mussel','plover','basalt','ferment','willow'],
            did: ${JSON.stringify(STATE_LINKED.did)},
            fingerprint: '5F 9A C9 07 2E 11',
          };
          case 'confirm_backup': return true;
          case 'read_link_code': return {
            application: 'cbcl-chat',
            purpose: 'chat-device',
            device_description: 'Chrome on macOS',
            key_fingerprint: 'C0 7A 1E 42 9B 33',
            expires_in: 252,
          };
          case 'authorise': return {
            method_id: 'did:crdt:9f3a…#dev-1',
            did: ${JSON.stringify(STATE_LINKED.did)},
            fingerprint: '5F 9A C9 07 2E 11',
            publishing: 1,
          };
          case 'reject_offer': return null;
          case 'flush_publications': return 0;
          default: return null;
        }
      },
    },
  };
`;

const shots = [
  { name: '01-welcome', state: { has_identity: false, backup_confirmed: false, devices: [], pending_publications: 0 }, steps: [] },
  { name: '02-passcode', state: { has_identity: false, backup_confirmed: false, devices: [], pending_publications: 0 }, steps: ['begin-create'] },
  { name: '03-phrase', state: { has_identity: false, backup_confirmed: false, devices: [], pending_publications: 0 }, steps: ['begin-create', 'fill-passcode', 'create-identity'] },
  { name: '04-confirm', state: { has_identity: false, backup_confirmed: false, devices: [], pending_publications: 0 }, steps: ['begin-create', 'fill-passcode', 'create-identity', 'to-confirm'] },
  { name: '05-created', state: { has_identity: false, backup_confirmed: false, devices: [], pending_publications: 0 }, steps: ['begin-create', 'fill-passcode', 'create-identity', 'to-confirm', 'check-backup'] },
  { name: '06-home', state: STATE_LINKED, steps: [] },
  { name: '07-type-code', state: STATE_LINKED, steps: ['to-link'] },
  { name: '08-consent', state: STATE_LINKED, steps: ['to-link', 'fill-code', 'read-code'] },
  { name: '09-presence', state: STATE_LINKED, steps: ['to-link', 'fill-code', 'read-code', 'to-presence'] },
  { name: '10-linked', state: STATE_LINKED, steps: ['to-link', 'fill-code', 'read-code', 'to-presence', 'authorise'] },
  { name: '11-rejected', state: STATE_LINKED, steps: ['to-link', 'fill-code', 'read-code', 'reject'] },
  { name: '12-device', state: STATE_LINKED, steps: ['open-device'] },
  { name: '13-unlink', state: STATE_LINKED, steps: ['open-device', 'to-unlink'] },
  { name: '14-restore', state: { has_identity: false, backup_confirmed: false, devices: [], pending_publications: 0 }, steps: ['begin-restore'] },
];

// `protocolTimeout` is raised because a screenshot on a loaded machine can take
// longer than the 30 s default, and a flaky presentation check is worse than a
// slow one.
const browser = await puppeteer.launch({ headless: 'new', protocolTimeout: 120_000 });
const errors = [];

for (const shot of shots) {
  const page = await browser.newPage();
  page.on('pageerror', (e) => errors.push(`${shot.name}: ${e.message}`));
  page.on('console', (m) => { if (m.type() === 'error' && !/favicon|Failed to load resource/.test(m.text())) errors.push(`${shot.name}: console ${m.text()}`); });
  await page.setViewport({ width: 430, height: 900, deviceScaleFactor: 2 });
  // Reduced motion makes the capture deterministic — the scanner sweep and the
  // spinner are infinite animations, and it also exercises the
  // `prefers-reduced-motion` rules in styles.css rather than leaving them
  // unvisited.
  await page.emulateMediaFeatures([{ name: 'prefers-reduced-motion', value: 'reduce' }]);
  await page.evaluateOnNewDocument(bridge(shot.state));
  await page.goto(SRC, { waitUntil: 'networkidle0' });
  await new Promise((r) => setTimeout(r, 250));

  for (const step of shot.steps) {
    if (step === 'fill-passcode') {
      await page.evaluate(() => {
        document.querySelector('#passcode-1').value = 'correct horse';
        document.querySelector('#passcode-2').value = 'correct horse';
      });
    } else if (step === 'fill-code') {
      await page.evaluate(() => {
        const el = document.querySelector('#code-input');
        el.value = 'anuna1qyqsqqqqqqqqqqqqqqqqqqqqqqqqqjdgkrf';
        el.dispatchEvent(new Event('input'));
      });
    } else if (step === 'open-device') {
      await page.evaluate(() => document.querySelector('.device')?.click());
    } else {
      await page.evaluate((a) => document.querySelector(`[data-action="${a}"]`)?.click(), step);
    }
    await new Promise((r) => setTimeout(r, 250));
  }

  const visible = await page.evaluate(() =>
    [...document.querySelectorAll('.screen')].filter((s) => !s.hidden).map((s) => s.dataset.screen),
  );
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  console.log(`${shot.name.padEnd(14)} screen=${visible.join(',') || 'NONE'}${overflow ? '  ⚠ horizontal overflow' : ''}`);
  if (visible.length !== 1) errors.push(`${shot.name}: ${visible.length} screens visible (${visible})`);
  if (overflow) errors.push(`${shot.name}: horizontal overflow at 430px`);

  try {
    await page.screenshot({ path: `${OUT}/${shot.name}.png` });
  } catch (e) {
    // A failed capture is a reporting problem, not a defect in the page. The
    // structural assertions above have already run.
    console.log(`${' '.repeat(15)}(screenshot skipped: ${e.message.split('\n')[0]})`);
  }
  await page.close();
}

// ── the bridge itself ────────────────────────────────────────────────────
//
// Every case above injects a stub, so none of them can see the bridge being
// *absent* — which is exactly the bug that shipped: Tauri v2 does not expose
// `window.__TAURI__` unless `app.withGlobalTauri` is set, `app.js` threw on its
// first line, and the window rendered as a black rectangle with no explanation.
// This case loads the page with **no stub at all** and asserts the failure is
// legible.
{
  const page = await browser.newPage();
  await page.setViewport({ width: 430, height: 900 });
  await page.goto(SRC, { waitUntil: 'networkidle0' });
  await new Promise((r) => setTimeout(r, 250));
  const text = await page.evaluate(() => document.body.innerText);
  if (!/can't reach its own backend/i.test(text)) {
    errors.push(`no-bridge: a missing window.__TAURI__ must render an explanation, got: ${JSON.stringify(text.slice(0, 120))}`);
  } else {
    console.log('no-bridge      renders an explanation rather than a black screen');
  }
  await page.close();
}

await browser.close();
server.close();
if (errors.length) {
  console.log('\nERRORS:');
  for (const e of errors) console.log('  ' + e);
  process.exit(1);
}
console.log('\nall screens rendered clean');
