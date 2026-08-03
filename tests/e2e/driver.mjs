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
 * The verification method the linked device should report, per wallet.
 *
 * The two wallets fragment differently, and the difference is real rather than
 * incidental. The application calls `Session::new_device_fragment()`, which is
 * 64 bits from the CSPRNG rendered as `dev-<16 hex>` — counting was dropped
 * because a counter has to be allocated against state a restored wallet may not
 * have. `examples/scripted_phone.rs` still adds its one device as `dev-1`,
 * which is fine for a program that links exactly once.
 *
 * Asserting `#dev-1` for both reported every successful emulator run as a
 * failure — the one outcome a harness must never produce, because it makes the
 * thing it exists to detect indistinguishable from its own bug.
 */
function deviceMethodId(walletDid) {
  const did = walletDid.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return WALLET === 'scripted'
    ? { pattern: new RegExp(`^${did}#dev-1$`), description: `${walletDid}#dev-1` }
    : {
        pattern: new RegExp(`^${did}#dev-[0-9a-f]{16}$`),
        description: `${walletDid}#dev-<16 hex, from Session::new_device_fragment>`,
      };
}

/** The Tauri identifier from `src-tauri/tauri.conf.json`. */
const PACKAGE = 'io.anuna.selfsame';

/** Run adb, returning stdout, or null if it could not run. */
function adb(args, { serial } = {}) {
  try {
    return execFileSync('adb', serial ? ['-s', serial, ...args] : args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 30_000,
    }).trim();
  } catch {
    return null;
  }
}

/**
 * Layer three's wallet: the real application in an emulator.
 *
 * **Written but never executed.** There is no Android SDK on the machine this
 * was authored on, so every line below is unverified — and the three unknowns
 * EXP-002 exists to settle are settled *by running this*, not by having written
 * it. It is therefore built to **report** what it finds rather than to assume:
 * each unknown is probed, the answer is printed, and a failure names which
 * unknown defeated it. That is the difference between a spike apparatus and a
 * guess with a confident interface.
 *
 * The one thing it will not do is pass without linking. Every path out of here
 * either returns a DID the wallet genuinely reported or calls `die`.
 */
async function emulatorWallet(base, code, rendezvousPort) {
  // ── the prerequisites, before anything slow ─────────────────────────────
  const { preflight } = await import('./preflight.mjs');
  const report = preflight();
  if (!report.ready) {
    die(
      'the emulator wallet needs a toolchain this machine does not have:\n' +
        report.results
          .filter((r) => !r.found)
          .map((r) => `          ${r.name} — ${r.fix}`)
          .join('\n') +
        '\n\n        Run `npm run e2e:preflight` for the full report.',
    );
  }

  // ── a device to drive ───────────────────────────────────────────────────
  const listed = JSON.parse(execFileSync('ar-crawl', ['android', 'devices'], { encoding: 'utf8' }));
  const device = listed.devices?.[0];
  if (!device) die('no Android device or emulator is running — start your AVD first');
  log(`device: ${device.serial} (${device.model ?? 'unknown model'})`);

  // ── U2: point the application at the host's rendezvous ──────────────────
  //
  // `adb reverse` makes the host's port reachable inside the emulator on the
  // same number, so `127.0.0.1:<port>` means the same thing on both sides. That
  // half is reliable. The unreliable half is telling the application to use it:
  // `net.rs` reads `SELFSAME_ENDPOINT` from the process environment, and Android
  // does not hand out process environments.
  //
  // `setprop wrap.<package>` is Android's supported mechanism for a *debuggable*
  // application and needs no source change, so it is tried first — EXP-002 U2
  // candidate 2. Candidate 1, a debug-only cargo feature, is a production change
  // and is EXP-002 Q1, which is the owner's to answer. If this fails, that is
  // the finding, and it is reported as one rather than worked around.
  if (adb(['reverse', `tcp:${rendezvousPort}`, `tcp:${rendezvousPort}`], { serial: device.serial }) === null) {
    die('adb reverse failed — the emulator cannot reach the host rendezvous');
  }
  log(`adb reverse tcp:${rendezvousPort} → host`);

  const endpoint = `http://127.0.0.1:${rendezvousPort}`;
  const wrapped = adb(
    ['shell', 'setprop', `wrap.${PACKAGE}`, `SELFSAME_ENDPOINT='${endpoint}'`],
    { serial: device.serial },
  );
  if (wrapped === null) {
    die(
      `U2 unresolved: could not set wrap.${PACKAGE}.\n` +
        '        The application will use its compiled-in endpoint and this run would\n' +
        '        test nothing. EXP-002 U2 candidate 2 has failed; candidate 1 is a\n' +
        '        debug-only cargo feature, which is EXP-002 Q1 and is the owner\'s call.',
    );
  }
  log(`U2: wrap.${PACKAGE} set to ${endpoint} (unverified until the app reads it)`);

  // ── a clean application, so a previous run cannot satisfy this one ──────
  adb(['shell', 'pm', 'clear', PACKAGE], { serial: device.serial });
  adb(['shell', 'monkey', '-p', PACKAGE, '-c', 'android.intent.category.LAUNCHER', '1'], {
    serial: device.serial,
  });

  const wallet = openSession(['android', 'session', device.serial], 'wallet');
  await wallet.ready();

  // ── U1: is the Tauri WebView reachable? ─────────────────────────────────
  const views = await wallet.send('webviews');
  const hasWebview = Array.isArray(views?.webviews) && views.webviews.length > 0;
  log(
    hasWebview
      ? `U1: WebView reachable (${views.webviews.length}) — DOM assertions available`
      : 'U1: no WebView reported — falling back to native selectors, which is a ' +
          'materially weaker harness (EXP-002 records this as a possible outcome)',
  );

  // ── drive the ceremony ──────────────────────────────────────────────────
  //
  // `IMPL-004` requires a `data-action` hook on every interactive element, so
  // the DOM path uses exactly the selectors `tests/screens.mjs` uses. The native
  // path matches on visible text, which is the thing that path can see — and is
  // why it is weaker: text is a display label, and `PROTO-001` is explicit that
  // stable identifiers must never be derived from one.
  const tap = async (action, text) =>
    hasWebview
      ? wallet.send({ type: 'tap', selector: `css=[data-action="${action}"]` })
      : wallet.send({ type: 'tap', selector: `text=${text}` });

  await tap('to-link', 'Link a device');
  await wallet.send(
    hasWebview
      ? { type: 'fill', selector: 'css=#code-input', text: code }
      : { type: 'fill', selector: `res=${PACKAGE}:id/code-input`, text: code },
  );
  await tap('read-code', 'Continue');
  await tap('to-presence', 'Continue');

  // ── U3: the presence check ──────────────────────────────────────────────
  //
  // Biometric on mobile, which is a native dialog rather than a DOM element.
  // The emulator answers `finger touch` for exactly this. Best-effort: on a
  // build where the check is the typed passcode instead, there is no prompt and
  // this is a no-op.
  adb(['emu', 'finger', 'touch', '1'], { serial: device.serial });

  await tap('authorise', 'Authorise');

  // ── what the wallet says it did ─────────────────────────────────────────
  const method = await until(
    async () => {
      if (!hasWebview) {
        // Without the DOM there is no reliable way to read the method id, and
        // guessing from a screenshot would be a claim the harness cannot back.
        die(
          'U1 resolved against the DOM path, so the wallet reached the linked screen ' +
            'but its identity cannot be read. The harness cannot assert the two parties ' +
            'agree, which is the one assertion it exists to make. Recorded as an EXP-002 ' +
            'finding rather than reported as a pass.',
        );
      }
      const r = await wallet.send({
        type: 'evaluate',
        expression: `(document.querySelector('[data-linked-method]')?.textContent || '').trim() || null`,
      });
      return r.result ?? r.value ?? r.data ?? null;
    },
    { what: 'the wallet to reach its linked screen', timeoutMs: 60_000 },
  );

  const did = String(method).split('#')[0];
  if (!did.startsWith('did:crdt:')) die(`the wallet reported no usable identity: ${method}`);
  wallet.close();
  return did;
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

  const walletDid =
    WALLET === 'scripted'
      ? scriptedWallet(base, code)
      : await emulatorWallet(base, code, rendezvousPort);
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
  const expected = deviceMethodId(walletDid);
  if (!expected.pattern.test(seen.ownMethodId)) {
    die(
      `the device's own method id is wrong:\n` +
        `        expected  ${expected.description}\n` +
        `        got       ${seen.ownMethodId}`,
    );
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
