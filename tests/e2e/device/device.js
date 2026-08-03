/**
 * EXP-002 layer two — the browser device client.
 *
 * Everything that decides anything is in the wasm module, which is
 * `selfsame-web-device` over `selfsame-core`. This file is the shell: it draws
 * randomness, makes HTTP requests, and puts strings on screen. It does not
 * parse an offer, derive a slot, or judge a reply, because a second
 * implementation of any of those is the parser differential `CON-205` exists to
 * prevent — and both implementations would be in this repository, which makes
 * it worse rather than better.
 *
 * The division is the same one `selfsame-cli` draws and the same one
 * `src/app.js` draws against the Tauri commands: the shell fetches, the core
 * decides.
 */

import init, { LinkSession } from './pkg/selfsame_web_device.js';

/** `OFFER_TTL_SECONDS` from `selfsame-core`. Mirrored, and asserted below. */
const OFFER_TTL_SECONDS = 300;

/** How often to look for a reply. The CLI polls at 750 ms; so does this. */
const POLL_INTERVAL_MS = 750;

const $ = (sel) => document.querySelector(sel);

/** Show exactly one state section, the way the wallet shows exactly one screen. */
function show(state) {
  for (const el of document.querySelectorAll('[data-state]')) {
    el.hidden = el.dataset.state !== state;
  }
}

/**
 * The rendezvous this fixture talks to, recognised rather than trusted.
 *
 * It arrives in the query string because the harness assigns a loopback port at
 * run time and the page has to be told. That makes it input at a boundary even
 * though both ends are ours, so it is checked against a grammar before it is
 * used to build a request:
 *
 *     base = "http://127.0.0.1:" 1*5DIGIT / "https://" host [":" 1*5DIGIT]
 *
 * Plaintext is admitted **only** for loopback. A fixture that accepted
 * `http://` for any host would be one someone later points at a real service,
 * and the reason the wallet refuses plaintext is not weaker here just because
 * this is a test.
 */
function recogniseRendezvous(raw) {
  if (!raw) throw new Error('no ?rendezvous= was supplied');
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('the rendezvous is not a URL');
  }
  if (url.search || url.hash || url.pathname !== '/') {
    throw new Error('the rendezvous is an origin, with no path, query or fragment');
  }
  const loopback = url.hostname === '127.0.0.1' || url.hostname === '[::1]';
  if (url.protocol === 'http:' && !loopback) {
    throw new Error('plaintext is admitted only for loopback');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('the rendezvous is an HTTP origin');
  }
  return url.origin;
}

/** Unix seconds. The core takes the clock as an argument; this is the shell's. */
const now = () => Math.floor(Date.now() / 1000);

/**
 * Draw the two secrets.
 *
 * `crypto.getRandomValues` rather than anything the wasm module could carry:
 * the browser's CSPRNG is better than one compiled into a fixture, and drawing
 * them here keeps them visible at the boundary where they are created rather
 * than hidden inside a module that also decides things.
 */
function draw() {
  const secret = new Uint8Array(16);
  const deviceSeed = new Uint8Array(32);
  crypto.getRandomValues(secret);
  crypto.getRandomValues(deviceSeed);
  return { secret, deviceSeed };
}

/** What this client calls itself, bounded by `MAX_DEVICE_DESCRIPTION_CHARS`. */
function describeThisBrowser() {
  const ua = navigator.userAgent;
  const name = /Chrome\/[\d.]+/.test(ua) ? 'Chrome' : /Firefox/.test(ua) ? 'Firefox' : 'a browser';
  return `${name} on the test bench`.slice(0, 64);
}

async function main() {
  await init();

  let base;
  try {
    base = recogniseRendezvous(new URLSearchParams(location.search).get('rendezvous'));
  } catch (e) {
    $('[data-error]').textContent = String(e.message ?? e);
    show('broken');
    return;
  }

  const { secret, deviceSeed } = draw();
  const session = new LinkSession(
    secret,
    deviceSeed,
    describeThisBrowser(),
    now() + OFFER_TTL_SECONDS,
  );

  // The offer is written *first*, and only then does the code appear.
  //
  // A person must never be looking at a code the rendezvous has not been told
  // about: typing it would address an empty slot and the wallet would report a
  // code that does not exist. The harness feels the same race harder — it reads
  // the code the instant it appears and authorises immediately — and the first
  // run of it failed exactly this way, with the phone getting a 404 from a slot
  // the browser had not filled yet.
  //
  // So the invariant is: `[data-link-code]` is non-empty only after the PUT has
  // succeeded, which makes the text's presence the signal that the ceremony can
  // proceed. The driver waits for the text rather than the element.
  show('waiting');

  try {
    const written = await fetch(`${base}/rendezvous/${session.offer_slot}`, {
      method: 'PUT',
      body: session.sealed_offer(),
    });
    if (!written.ok) throw new Error(`the rendezvous refused the offer (${written.status})`);
  } catch (e) {
    $('[data-error]').textContent = String(e.message ?? e);
    show('broken');
    return;
  }

  $('[data-link-code]').textContent = session.link_code;

  // Poll until the reply appears or the offer expires. The deadline is the
  // offer's own, not a timer this file invented: an offer that has expired is
  // refused by `accept` regardless, and stopping here only avoids asking.
  const deadline = now() + OFFER_TTL_SECONDS;
  while (now() <= deadline) {
    let sealed = null;
    try {
      const response = await fetch(`${base}/rendezvous/${session.bundle_slot}`);
      if (response.ok) sealed = new Uint8Array(await response.arrayBuffer());
    } catch {
      // A transport failure is not an answer. Keep asking until the deadline —
      // the same shape as the CLI's loop, which ignores a failed GET.
    }

    if (sealed) {
      try {
        const accepted = JSON.parse(session.accept(sealed, now()));
        $('[data-did]').textContent = accepted.did;
        $('[data-fingerprint-hex]').textContent = accepted.fingerprintHex;
        $('[data-fingerprint-label]').textContent = accepted.fingerprintLabel;
        $('[data-own-method-id]').textContent = accepted.ownMethodId;
        show('linked');
      } catch (e) {
        // One line, no detail — and there is no detail to give: the refusal
        // crossed the wasm boundary carrying nothing.
        $('[data-refusal]').textContent = String(e.message ?? e);
        show('refused');
      }
      return;
    }

    $('[data-status]').textContent =
      `Waiting for your phone… expires in ${deadline - now()}s`;
    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
  }

  $('[data-refusal]').textContent = 'That code has expired — reload for a new one.';
  show('refused');
}

main();
