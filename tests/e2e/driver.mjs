/**
 * EXP-002 — the end-to-end linking harness.
 *
 * Orchestrates one SPEC-001 linking ceremony between two genuinely separate
 * clients and asserts they independently arrive at the same identity.
 *
 *   node tests/e2e/driver.mjs                     # layer two: scripted phone
 *   node tests/e2e/driver.mjs --wallet emulator   # layer three: the real app
 *
 * The `--wallet` switch is the only difference between the layers, and that is
 * deliberate: everything else — the rendezvous, the browser device, the code
 * passing between them, the assertions — is identical, so a failure under
 * `--wallet emulator` that passes under the default is a failure *of the
 * wallet*. Nothing else moved.
 *
 * # Why the code passes through here
 *
 * The link secret is drawn fresh in the browser on every run, so the code is
 * different every time. `ar-crawl`'s `commit`/`replay` records a fixed script
 * and cannot carry a value that does not exist until the run starts — which is
 * why this is a driver rather than a recording. Replay stays useful for
 * sub-flows and screenshot regression; it cannot express the ceremony.
 */

import { spawn, execFileSync } from 'node:child_process';
import { createServer } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..');
const DEVICE_DIR = join(HERE, 'device');
const PKG_DIR = join(DEVICE_DIR, 'pkg');

const WALLET = process.argv.includes('--wallet')
  ? process.argv[process.argv.indexOf('--wallet') + 1]
  : 'scripted';

/** Everything started, so a failure anywhere still tears the run down. */
const running = [];
function track(child) {
  running.push(child);
  return child;
}
function teardown() {
  for (const c of running.splice(0)) {
    try {
      c.kill('SIGTERM');
    } catch {
      /* already gone */
    }
  }
}
process.on('exit', teardown);
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => (teardown(), process.exit(130)));

const log = (...a) => console.log('  ', ...a);

function die(message) {
  console.error(`\ndriver: ${message}\n`);
  teardown();
  process.exit(1);
}

/** Wait until `probe()` returns truthy, or give up. */
async function until(probe, { timeoutMs = 20_000, everyMs = 200, what = 'a condition' } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const got = await probe();
    if (got) return got;
    if (Date.now() > deadline) die(`timed out after ${timeoutMs}ms waiting for ${what}`);
    await new Promise((r) => setTimeout(r, everyMs));
  }
}

// ── the rendezvous ─────────────────────────────────────────────────────────

/**
 * The real service, on loopback.
 *
 * Built rather than assumed: a stale binary would produce failures that look
 * like protocol defects.
 *
 * Every cargo invocation here passes `--locked`, which on a working copy whose
 * sibling checkouts are *ahead* of the pins in `cbcl-rs.sha` will refuse to
 * run. That is the intended outcome: without it, cargo silently rewrites
 * `Cargo.lock` to match whatever siblings happen to be present, the harness
 * passes, and CI then fails on a lockfile the harness itself changed. Failing
 * here names the cause; failing there does not.
 */
async function startRendezvous(port) {
  log(`building the rendezvous…`);
  try {
    execFileSync('cargo', ['build', '--locked', '-p', 'selfsame-rendezvous'], {
      cwd: ROOT,
      stdio: ['ignore', 'ignore', 'pipe'],
    });
  } catch (e) {
    die(`the rendezvous did not build:\n${e.stderr?.toString() ?? e}`);
  }

  const child = track(
    spawn('cargo', ['run', '-q', '--locked', '-p', 'selfsame-rendezvous'], {
      cwd: ROOT,
      env: { ...process.env, SELFSAME_BIND: `127.0.0.1:${port}` },
      stdio: ['ignore', 'ignore', 'pipe'],
    }),
  );
  child.stderr.on('data', (d) => {
    if (process.env.E2E_VERBOSE) process.stderr.write(`[rendezvous] ${d}`);
  });

  const base = `http://127.0.0.1:${port}`;
  await until(
    async () => {
      try {
        return (await fetch(`${base}/healthz`)).ok;
      } catch {
        return false;
      }
    },
    { what: 'the rendezvous to answer /healthz' },
  );
  log(`rendezvous on ${base}`);
  return base;
}

// ── the page ───────────────────────────────────────────────────────────────

const MIME = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.wasm': 'application/wasm',
  '.json': 'application/json',
};

/**
 * Serve the page, and proxy the rendezvous through the same origin.
 *
 * # FINDING-018 — the dev rendezvous sends no CORS headers
 *
 * A browser device client cannot talk to `selfsame-rendezvous` cross-origin: it
 * sets no `Access-Control-Allow-*` on any route, so the `PUT` of the sealed
 * offer never leaves the page. Nothing had noticed, because until now every
 * client of that service was a CLI or a test using an HTTP library, and neither
 * is subject to the same-origin policy. The first browser client finds it
 * immediately, which is the sort of thing EXP-002 exists to find.
 *
 * It is recorded rather than fixed here. EXP-002's isolation clause says a
 * production change made to suit the harness is a finding needing its own
 * justification, not a convenience to help a test along — and adding CORS to a
 * service is a decision about who may call it from where, which deserves that
 * justification on its own terms. Alongside EXP-002 Q1, it is the owner's.
 *
 * So the harness sidesteps it without touching the service: `/rendezvous/*` and
 * `/dids/*` are forwarded to the real rendezvous from this origin. The browser
 * sees one origin and needs no CORS; the real service still handles every
 * request and makes every decision. What this costs is honest to state — a
 * proxy sits in the path, so the harness does not prove the browser can reach
 * the service *cross-origin*, which is the very thing the finding says it
 * cannot.
 */
async function startPageServer(port, rendezvousBase) {
  if (!existsSync(join(PKG_DIR, 'selfsame_web_device.js'))) {
    die(
      `the wasm package is missing from ${PKG_DIR}\n` +
        `        build it with:  npm run e2e:wasm\n` +
        `        (it is a build artefact and is not committed)`,
    );
  }
  const server = createServer(async (req, res) => {
    // Forwarded to the real service, unchanged. Method, body and status all
    // pass through; nothing here inspects or decides.
    if (req.url.startsWith('/rendezvous/') || req.url.startsWith('/dids/')) {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      try {
        const upstream = await fetch(`${rendezvousBase}${req.url}`, {
          method: req.method,
          headers: req.headers['content-type']
            ? { 'content-type': req.headers['content-type'] }
            : undefined,
          body: chunks.length ? Buffer.concat(chunks) : undefined,
        });
        const body = Buffer.from(await upstream.arrayBuffer());
        res.writeHead(upstream.status, {
          'content-type': upstream.headers.get('content-type') ?? 'application/octet-stream',
        });
        res.end(body);
      } catch (e) {
        res.writeHead(502).end(String(e));
      }
      return;
    }

    // Strip the query *before* testing for the root, not after. The page is
    // always fetched as `/?rendezvous=…`, so the other order compares
    // `"/?rendezvous=…" === "/"`, takes the else branch, splits back to `"/"`,
    // and then tries to read a directory — a 404 that renders as a blank page
    // with no console error and no failed request. `tests/screens.mjs` carries
    // the same expression and never trips it, because it navigates to an
    // explicit `/index.html` and passes no query.
    const requested = req.url.split('?')[0];
    const path = requested === '/' ? '/index.html' : requested;
    try {
      const body = readFileSync(join(DEVICE_DIR, path));
      res.writeHead(200, { 'content-type': MIME[extname(path)] ?? 'application/octet-stream' });
      res.end(body);
    } catch {
      res.writeHead(404).end();
    }
  });
  await new Promise((r) => server.listen(port, '127.0.0.1', r));
  track({ kill: () => server.close() });
  log(`device page on http://127.0.0.1:${port}`);
  return `http://127.0.0.1:${port}`;
}

// ── ar-crawl, as a line-oriented JSON session ──────────────────────────────

/**
 * One `ar-crawl session` (or `ar-crawl android session`) as an object.
 *
 * Both speak the same protocol — JSON commands on stdin, one JSON object per
 * line on stdout — which is why one wrapper drives both roles and why layer
 * three is a swap rather than a rewrite.
 */
function openSession(args, label) {
  const child = track(spawn('ar-crawl', args, { stdio: ['pipe', 'pipe', 'pipe'] }));
  const lines = createInterface({ input: child.stdout });
  const pending = [];
  const queued = [];

  lines.on('line', (line) => {
    let value;
    try {
      value = JSON.parse(line);
    } catch {
      return; // ar-crawl prints the odd non-JSON banner; ignore rather than fail.
    }
    if (process.env.E2E_VERBOSE) log(`[${label}] ${line.slice(0, 200)}`);
    const waiter = pending.shift();
    if (waiter) waiter(value);
    else queued.push(value);
  });
  child.stderr.on('data', (d) => {
    if (process.env.E2E_VERBOSE) process.stderr.write(`[${label}] ${d}`);
  });

  const next = () =>
    queued.length ? Promise.resolve(queued.shift()) : new Promise((r) => pending.push(r));

  return {
    /** The session's own ready line. */
    ready: () => next(),
    /** Send a command and read the one reply it produces. */
    async send(command) {
      child.stdin.write(`${typeof command === 'string' ? command : JSON.stringify(command)}\n`);
      const reply = await next();
      if (reply && reply.success === false) {
        die(`[${label}] ${JSON.stringify(command)} failed: ${reply.error}`);
      }
      return reply;
    },
    close() {
      try {
        child.stdin.write('exit\n');
      } catch {
        /* already gone */
      }
    },
  };
}

// ── the wallet, in either form ─────────────────────────────────────────────

/**
 * Layer two's wallet: a Rust program that plays the phone with `selfsame-core`.
 *
 * Not a JavaScript approximation, deliberately. The harness's value is that one
 * implementation of the offer format and the grant is exercised from both ends;
 * a second phone written here would be the parser differential `CON-205`
 * exists to prevent, with both copies in this repository.
 */
function scriptedWallet(base, code) {
  log('scripted phone authorising…');
  try {
    const did = execFileSync(
      'cargo',
      ['run', '-q', '--locked', '-p', 'selfsame-web-device', '--example', 'scripted_phone', '--', base, code],
      { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    ).trim();
    if (!did.startsWith('did:crdt:')) die(`the scripted phone printed no DID, got: ${did}`);
    return did;
  } catch (e) {
    die(`the scripted phone failed:\n${e.stderr?.toString() ?? e}`);
  }
}

/**
 * Layer three's wallet: the real application in an emulator.
 *
 * Unimplemented, and refusing rather than pretending. EXP-002's three unknowns
 * — whether `ar-crawl android` can reach the Tauri WebView's DOM, how the
 * application is pointed at a loopback rendezvous, and what the biometric
 * presence check needs — are all unanswered, and none can be answered on a
 * machine with no Android SDK. A stub that silently passed would make the
 * harness report success for a ceremony that never happened, which is the exact
 * defect the last review round was about.
 */
function emulatorWallet() {
  die(
    'the emulator wallet is not implemented yet.\n' +
      '        EXP-002 records three unknowns it depends on (U1 the WebView, U2 the\n' +
      '        endpoint, U3 the presence check), none of which can be settled without\n' +
      '        an Android SDK. Run `node tests/e2e/preflight.mjs` to see what is missing.',
  );
}

// ── the ceremony ───────────────────────────────────────────────────────────

async function main() {
  console.log(`\nEXP-002 — SPEC-001 linking, end to end (wallet: ${WALLET})\n`);

  if (WALLET !== 'scripted' && WALLET !== 'emulator') {
    die(`--wallet takes "scripted" or "emulator", got "${WALLET}"`);
  }

  const rendezvousPort = 8787;
  const pagePort = 8788;

  const base = await startRendezvous(rendezvousPort);
  const pageBase = await startPageServer(pagePort, base);

  const device = openSession(['session'], 'device');
  await device.ready();

  await device.send({ type: 'goto', url: `${pageBase}/?rendezvous=${encodeURIComponent(pageBase)}` });
  // Wait for the *text*, not the element. The element is in the markup from the
  // start; the text appears only once the sealed offer is in its slot, which is
  // the page's way of saying the ceremony can proceed. Waiting on the element
  // alone reads the code before the offer exists and the wallet gets a 404 —
  // the first failure this harness produced.
  const code = await until(
    async () => {
      const r = await device.send({
        type: 'evaluate',
        expression: `(document.querySelector('[data-link-code]')?.textContent || '').trim() || null`,
      });
      return r.result ?? r.value ?? r.data ?? null;
    },
    { what: 'the device to publish its offer and show a link code' },
  );
  if (typeof code !== 'string' || !code) die(`could not read the link code, got: ${code}`);
  log(`link code: ${code}`);

  const walletDid = WALLET === 'scripted' ? scriptedWallet(base, code) : emulatorWallet();
  log(`wallet published: ${walletDid}`);

  // The browser polls on its own; wait for it to reach a terminal state rather
  // than assuming how long that takes.
  const terminal = await until(
    async () => {
      const r = await device.send({
        type: 'evaluate',
        expression: `(document.querySelector('[data-state="linked"]:not([hidden])') && 'linked')
          || (document.querySelector('[data-state="refused"]:not([hidden])') && 'refused')
          || (document.querySelector('[data-state="broken"]:not([hidden])') && 'broken')
          || null`,
      });
      return r.result ?? r.value ?? r.data ?? null;
    },
    { what: 'the device to reach a terminal state', timeoutMs: 30_000 },
  );

  if (terminal !== 'linked') {
    const why = await device.send({
      type: 'evaluate',
      expression: `(document.querySelector('[data-refusal]')?.textContent
        || document.querySelector('[data-error]')?.textContent || '').trim()`,
    });
    die(`the device did not link — it reached "${terminal}": ${why.result ?? why.value ?? ''}`);
  }

  const reported = await device.send({
    type: 'evaluate',
    expression: `JSON.stringify({
      did: document.querySelector('[data-did]').textContent.trim(),
      fingerprintHex: document.querySelector('[data-fingerprint-hex]').textContent.trim(),
      ownMethodId: document.querySelector('[data-own-method-id]').textContent.trim(),
    })`,
  });
  const seen = JSON.parse(reported.result ?? reported.value ?? reported.data);

  // The assertion the whole harness exists to make.
  if (seen.did !== walletDid) {
    die(`the two parties disagree:\n        wallet: ${walletDid}\n        device: ${seen.did}`);
  }
  if (!seen.fingerprintHex) die('the device linked without a fingerprint to compare');
  if (seen.ownMethodId !== `${walletDid}#dev-1`) {
    die(`the device's own method id is wrong: ${seen.ownMethodId}`);
  }

  device.close();
  teardown();

  console.log(`
  ✓ both parties independently reached the same identity

      identity     ${seen.did}
      fingerprint  ${seen.fingerprintHex}
      this device  ${seen.ownMethodId}
`);
}

main().catch((e) => die(e.stack ?? String(e)));
