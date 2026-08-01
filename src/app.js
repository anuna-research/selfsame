/**
 * Selfsame — the shell in front of the shell.
 *
 * This file holds *no* security logic. Every decision — is the offer signed,
 * does the DID commit to its genesis, is the code's checksum right — is made
 * in `selfsame-core` and reaches here as a value or an error. What lives here
 * is sequence and presentation, and the sequence obligations that are
 * user-visible:
 *
 *   REQ-019  the consent screen is a separate step from the presence check,
 *            so scope and fingerprint are always shown *before* the passcode
 *   REQ-002  linking is unreachable until the backup confirmation passes
 *   REQ-016  the countdown is real: at zero the offer is gone
 *   REQ-009  no partial or provisional state is ever rendered
 *
 * The `RejectReason` detail from the core never reaches a user. SCREEN-001's
 * error model is one line — "That code isn't valid." — because a parse detail
 * teaches nothing and says which check failed.
 */

/**
 * The bridge to the Rust side.
 *
 * `window.__TAURI__` exists only when `app.withGlobalTauri` is set in
 * `tauri.conf.json` — Tauri v2 does not expose it by default, expecting you to
 * import `@tauri-apps/api` through a bundler. This app deliberately has no
 * bundler, so the global is the bridge and its absence is a build
 * misconfiguration rather than a runtime condition.
 *
 * It is checked here, loudly. Reading `.core.invoke` off `undefined` throws
 * before the module body finishes, nothing binds, `refresh()` never runs, and
 * the user gets a black rectangle with no explanation — the worst failure mode
 * this app has, because it looks like a crashed device rather than a broken
 * build.
 */
const bridge = window.__TAURI__?.core?.invoke;
if (!bridge) {
  document.body.innerHTML = "";
  const panel = document.createElement("section");
  panel.className = "screen";
  panel.hidden = false;
  const title = document.createElement("h1");
  title.textContent = "Selfsame can't reach its own backend.";
  const detail = document.createElement("p");
  detail.className = "lede";
  detail.textContent =
    "window.__TAURI__ is missing. Set \"withGlobalTauri\": true under \"app\" " +
    "in src-tauri/tauri.conf.json and rebuild. This is a build problem, not " +
    "something you did.";
  panel.append(title, detail);
  document.body.append(panel);
  throw new Error("window.__TAURI__ is undefined — see app.withGlobalTauri");
}
const invoke = bridge;

// IMPL-004 ADR-601 — the SPEC-004 surface. One-way: this file hands it the
// primitives it needs, and imports nothing back. A cycle would work and would
// make the boundary a convention rather than a fact.
import { initAppIdentity } from "./app-identity.js";

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

/** Everything the UI is holding between screens. Cleared aggressively. */
const ui = {
  /** The twelve words, held only for the length of the HP-1 ceremony. */
  mnemonic: null,
  /** The three positions the confirmation is asking about. */
  challenge: [],
  /** The device currently open in the detail screen. */
  device: null,
  /** The offer under consideration, for the countdown. */
  offerExpiresAt: null,
  countdownTimer: null,
  state: null,
};

// ── routing ────────────────────────────────────────────────────────────

function show(name) {
  $$(".screen").forEach((s) => {
    s.hidden = s.dataset.screen !== name;
  });
  clearErrors();
  const first = $(`[data-screen="${name}"] h1`);
  if (first) first.setAttribute("tabindex", "-1"), first.focus({ preventScroll: true });
  if (name !== "consent") stopCountdown();
}

function busy(note) {
  $("[data-busy-note]").textContent = note;
  $("[data-busy]").hidden = false;
}

function idle() {
  $("[data-busy]").hidden = true;
}

function clearErrors() {
  $$("[data-error]").forEach((e) => {
    e.hidden = true;
    e.textContent = "";
  });
}

function fail(which, message) {
  const el = $(`[data-error="${which}"]`);
  if (!el) return;
  el.textContent = message;
  el.hidden = false;
}

/** Errors from Rust arrive as plain strings; anything else is a bug in this file. */
const message = (e) => (typeof e === "string" ? e : "Something went wrong. Try again.");

// ── home ───────────────────────────────────────────────────────────────

async function refresh() {
  ui.state = await invoke("get_state");
  const s = ui.state;

  if (!s.has_identity) {
    show("welcome");
    return;
  }

  // The *identity* fingerprint — `fingerprint_did` — not the root key's own.
  //
  // This is the value every linked client and the CLI compute and display, and
  // the one the created screen introduced with "every device you link will show
  // this same fingerprint". The home card used to show `fingerprint_key` of the
  // root key instead: a different 48-bit value, shown nowhere else in the
  // system, on the screen the user opens to ask "is this still me?".
  $("[data-home-fingerprint]").textContent = s.fingerprint?.hex ?? "";
  $("[data-home-label]").textContent = s.fingerprint?.label ?? "";
  renderLifehash($("[data-home-lifehash]"), s.fingerprint?.lifehash);
  $("[data-home-did]").textContent = s.did ?? "";

  const pending = $("[data-pending]");
  if (s.pending_publications > 0) {
    // OBS-005 made visible: the user believes they are linked while peers
    // cannot see it yet, so say so rather than implying everything is settled.
    pending.textContent =
      s.pending_publications === 1
        ? "1 change still publishing"
        : `${s.pending_publications} changes still publishing`;
    pending.hidden = false;
  } else {
    pending.hidden = true;
  }

  renderDevices(s.devices);

  // REQ-002: the link control is unreachable until the backup is confirmed.
  const link = $('[data-action="to-link"]');
  link.disabled = !s.backup_confirmed;
  link.title = s.backup_confirmed ? "" : "Confirm your recovery phrase first";

  // IMPL-004: applications beside devices, under one identity.
  appIdentity.renderApplications(s.applications ?? []);
  appIdentity.renderSummary(s.applications ?? []);

  $("[data-endpoint]").textContent = await invoke("service_endpoint");
  show("home");
}

function renderDevices(devices) {
  const list = $("[data-devices]");
  list.textContent = "";
  $("[data-devices-empty]").hidden = devices.length > 0;

  for (const d of devices) {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.className = "device";
    if (d.revoked) btn.classList.add("device--revoked");
    else if (d.pending) btn.classList.add("device--pending");

    // The state mark and the picture are two different jobs and both stay.
    // The mark carries `revoked`/`pending` as a distinct *shape*, so the state
    // survives monochrome and colour-vision deficiency (NFR-103); the picture
    // says which key this row is about and carries no state at all. Collapsing
    // them into one element would put state on a decorative canvas.
    const mark = document.createElement("div");
    mark.className = "mark";
    if (d.revoked) mark.classList.add("mark--broken");
    else if (d.pending) mark.classList.add("mark--pending");
    mark.setAttribute("aria-hidden", "true");

    // REQ-101: the device list is where the user sees these most often, and so
    // where recognition is actually built.
    const picture = d.lifehash ? lifehashElement(d.lifehash, "fp__lifehash fp__lifehash--row") : null;

    const body = document.createElement("div");
    body.className = "device__body";
    const name = document.createElement("span");
    name.className = "device__name";
    // Untrusted text, inserted as text and never as markup.
    name.textContent = d.label || "Unnamed device";
    const meta = document.createElement("span");
    meta.className = "device__meta";
    // The nickname names the row; the state follows it. Both are recognition,
    // not comparison — nothing on this screen asks the user to check a value.
    const state = d.revoked
      ? "Unlinked"
      : d.pending
        ? "publishing — others can't see it yet"
        : d.last_seen
          ? `seen ${since(d.last_seen)}`
          : d.method_id.split("#")[1];
    // The nickname stays on a revoked row now that the row carries a picture.
    // REQ-105 forbids a picture standing alone, and a revoked row is precisely
    // where "which key was that?" is worth answering — the state follows it
    // rather than displacing it.
    meta.textContent = d.nickname ? `${d.nickname} · ${state}` : state;

    body.append(name, meta);
    if (picture) btn.append(picture);
    btn.append(mark, body);
    btn.addEventListener("click", () => openDevice(d));
    li.append(btn);
    list.append(li);
  }
}

function since(seconds) {
  const delta = Math.max(0, Math.floor(Date.now() / 1000) - seconds);
  if (delta < 90) return "just now";
  if (delta < 3600) return `${Math.round(delta / 60)}m ago`;
  if (delta < 86400) return `${Math.round(delta / 3600)}h ago`;
  return `${Math.round(delta / 86400)}d ago`;
}

// ── HP-1: create the root ──────────────────────────────────────────────

async function createIdentity() {
  const a = $("#passcode-1").value;
  const b = $("#passcode-2").value;
  if (a !== b) return fail("passcode", "Those two don't match.");
  if (a.length < 6) return fail("passcode", "A passcode must be at least 6 characters.");

  busy("Creating your home key…");
  try {
    const created = await invoke("create_identity", { passcode: a });
    ui.mnemonic = created.words;
    ui.created = created;
    renderWords(created.words);
    show("phrase");
  } catch (e) {
    fail("passcode", message(e));
  } finally {
    idle();
    $("#passcode-1").value = "";
    $("#passcode-2").value = "";
  }
}

function renderWords(words) {
  const list = $("[data-words]");
  list.textContent = "";
  for (const w of words) {
    const li = document.createElement("li");
    li.textContent = w;
    list.append(li);
  }
  // NFR-002 forbids the mnemonic reaching a screenshot-enabled surface. On
  // Android and iOS that is enforceable; on a desktop it is not, and claiming
  // otherwise would be a lie the user might rely on.
  const mobile = /Android|iPhone|iPad/i.test(navigator.userAgent);
  $("[data-screenshot-note]").textContent = mobile
    ? "Screenshots are blocked on this screen."
    : "Don't screenshot this screen — this desktop build cannot stop you, and a screenshot is a copy of your identity.";
}

function toConfirm() {
  // Three positions at random, drawn from the platform CSPRNG so the choice is
  // not predictable from anything the user or an attacker controls.
  const picks = new Set();
  const draw = new Uint32Array(24);
  crypto.getRandomValues(draw);
  for (const n of draw) {
    if (picks.size === 3) break;
    picks.add(n % 12);
  }
  ui.challenge = [...picks].sort((x, y) => x - y);

  const box = $("[data-challenge]");
  box.textContent = "";
  for (const index of ui.challenge) {
    const label = document.createElement("label");
    label.className = "field";
    const span = document.createElement("span");
    span.className = "field__label";
    span.textContent = `word ${index + 1}`;
    const input = document.createElement("input");
    input.type = "text";
    input.autocapitalize = "none";
    input.autocomplete = "off";
    input.spellcheck = false;
    input.dataset.word = String(index);
    label.append(span, input);
    box.append(label);
  }
  show("confirm");
}

async function checkBackup() {
  const answers = $$("[data-challenge] input").map((i) => [
    Number(i.dataset.word),
    i.value.trim(),
  ]);
  busy("Checking…");
  try {
    const ok = await invoke("confirm_backup", {
      mnemonic: ui.mnemonic.join(" "),
      answers,
    });
    if (!ok) {
      // Deliberately not "word 7 is wrong": a per-word oracle turns the
      // ceremony into a guessing game.
      return fail("confirm", "That isn't right. Go back and check the words.");
    }
    $("[data-created-fingerprint]").textContent = ui.created.fingerprint.hex;
    $("[data-created-label]").textContent = ui.created.fingerprint.label;
    // The first time the user ever meets their picture. REQ-101 puts it here
    // precisely so that the authorise screen is not the first time.
    renderLifehash($("[data-created-lifehash]"), ui.created.fingerprint.lifehash);
    $("[data-created-did]").textContent = ui.created.did;
    // The words leave memory the moment they have done their job.
    ui.mnemonic = null;
    show("created");
  } catch (e) {
    fail("confirm", message(e));
  } finally {
    idle();
  }
}

async function restore() {
  const phrase = $("#restore-phrase").value;
  const passcode = $("#restore-passcode").value;
  busy("Restoring…");
  try {
    await invoke("restore_identity", { phrase, passcode });
    $("#restore-phrase").value = "";
    $("#restore-passcode").value = "";

    // REQ-021: the device list is rebuilt from signed state, so a phone that
    // holds no local file still knows what it is responsible for. Showing it
    // here is the evidence for that claim, not decoration.
    ui.state = await invoke("get_state");
    // Same value as the home card and the created screen — "your twelve words
    // rebuilt the same home key" is a claim the user can only check if the
    // fingerprint they are shown is the one they were asked to memorise.
    $("[data-restored-fingerprint]").textContent = ui.state.fingerprint?.hex ?? "";
    $("[data-restored-label]").textContent = ui.state.fingerprint?.label ?? "";
    renderLifehash($("[data-restored-lifehash]"), ui.state.fingerprint?.lifehash);
    renderRestored(ui.state.devices);
    show("restored");
  } catch (e) {
    fail("restore", message(e));
  } finally {
    idle();
  }
}

function renderRestored(devices) {
  const list = $("[data-restored-devices]");
  list.textContent = "";
  for (const d of devices) {
    if (d.revoked) continue;
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.className = "device__name";
    name.textContent = d.label || "Unnamed device";
    const meta = document.createElement("span");
    meta.className = "device__meta";
    meta.textContent = d.nickname ?? d.method_id.split("#")[1];
    // Same treatment as the home list, and the same structure — picture, then
    // a name/meta column — so the recognition transfers between the two (Law of
    // Similarity: a differently-styled picture per screen would defeat the
    // point of REQ-101).
    const body = document.createElement("div");
    body.className = "device__body";
    body.append(name, meta);
    if (d.lifehash) li.append(lifehashElement(d.lifehash, "fp__lifehash fp__lifehash--row"));
    li.append(body);
    list.append(li);
  }
}

// ── linking ────────────────────────────────────────────────────────────

async function startLink() {
  const scanner = $("[data-scanner]");
  const note = $("[data-scanner-note]");
  const mobile = window.__TAURI__?.barcodeScanner !== undefined;
  if (mobile) {
    note.textContent = "Point the camera at the code on your other screen.";
    scanner.hidden = false;
    show("link");
    try {
      const scanned = await window.__TAURI__.barcodeScanner.scan({
        formats: ["QRCode"],
        windowed: true,
      });
      await readCode(scanned.content);
    } catch {
      // A denied camera is not an error state — REQ-011 makes typing a
      // first-class route, and the button for it is already on this screen.
      note.textContent = "No camera. Enter the code by hand instead.";
    }
  } else {
    // Desktop: the typed route is the route. Say so plainly rather than
    // showing a dead camera frame.
    scanner.hidden = true;
    show("type");
  }
}

/**
 * A shape check, not a validity check.
 *
 * The Bech32m charset and length are cheap to test here and give the user a
 * live "n of 41" while they type. It decides **nothing**: the checksum, the
 * version, and the application byte are all verified in the core, and a code
 * that passes this and fails there gets the same one-line refusal as any other
 * invalid code. Duplicating the checksum in JavaScript would be a second
 * recogniser for one language, which is exactly what LangSec Principle 5 rules
 * out — so this stops at counting characters.
 */
const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const CODE_CHARS = 41;

function onCodeInput() {
  const compact = $("#code-input").value.trim().toLowerCase().replace(/\s+/g, "");
  const state = $("[data-code-state]");
  const button = $('[data-action="read-code"]');
  const looksComplete = new RegExp(
    `^anuna1[${BECH32_CHARSET}]{${CODE_CHARS - 6}}$`,
  ).test(compact);
  state.textContent = `${compact.length} of ${CODE_CHARS}`;
  state.classList.toggle("code-state--ok", looksComplete);
  button.disabled = !looksComplete;
}

async function readCode(code) {
  busy("Reading the code…");
  try {
    // REQ-018 happens inside this call: the offer's signature is verified
    // before any field comes back, so nothing below can render an unverified
    // claim. The "never reached" rows of SCREEN-001 are this throwing.
    const offer = await invoke("read_link_code", { code });
    renderConsent(offer);
    show("consent");
  } catch (e) {
    refuseCode(code, message(e));
  } finally {
    idle();
  }
}

/**
 * Render a refusal. **Never says which check failed.**
 *
 * The two branches below are the only two messages `read_link_code` produces,
 * and both are already distinguishable today — expiry is a fact about the
 * *code's age*, not about which conjunct of the predicate refused it. Every
 * other failure, the REQ-018 signature check included, arrives as the same
 * single line and is rendered as the same single line.
 */
function refuseCode(code, note) {
  const expired = note.includes("expired");
  $("[data-refused-code]").textContent = code;
  $("[data-refused-title]").textContent = expired
    ? "This code has expired"
    : "That code isn't valid";
  $("[data-refused-body]").textContent = expired
    ? "Codes last five minutes. Ask the device to show a new one — the old one can't be used, even by you."
    : "Check it against the device again, or scan it instead.";
  show("refused-code");
}

function renderConsent(offer) {
  // REQ-019's four required facts. The application and purpose come from the
  // compiled table (REQ-026), so they can be stated as one sentence without
  // implying either was taken from the code.
  $("[data-offer-asked]").textContent =
    `${offer.application}, to add a ${offer.purpose.replace(/-/g, " ")}`;
  // Untrusted: text, never markup, and already length-capped by the recogniser.
  $("[data-offer-desc]").textContent = offer.device_description || "(it said nothing)";

  // The compared value. `label` sits beneath it and is never the answer to the
  // question this screen asks — see the note in index.html.
  $("[data-offer-fingerprint]").textContent = offer.key_fingerprint.hex;
  $("[data-offer-label]").textContent = offer.key_fingerprint.label;
  renderLifehash($("[data-offer-lifehash]"), offer.key_fingerprint.lifehash);

  ui.offerExpiresAt = Math.floor(Date.now() / 1000) + offer.expires_in;
  startCountdown();
}

// ── the visual fingerprint (SPEC-002) ──────────────────────────────────────

/** LifeHash v2 geometry, fixed by SPEC-002 CON-101. */
const LIFEHASH_SIDE = 32;
const LIFEHASH_RGB_LEN = LIFEHASH_SIDE * LIFEHASH_SIDE * 3;

/**
 * CON-102's grammar, as a recogniser.
 *
 * Exactly 4096 characters, no padding: 3072 is divisible by three, so a
 * correctly encoded image never carries an `=`. Admitting one would be
 * repairing malformed input rather than recognising valid input, which
 * PROTO-001 Principle 14 rules out at a boundary.
 */
const LIFEHASH_B64 = /^[A-Za-z0-9+/]{4096}$/;

/**
 * Recognise a `lifehash` field, or return `null`.
 *
 * The producer is this application's own Rust half, but this is still the
 * boundary at which a malformed value becomes a fault inside the paint path,
 * so it is recognised *in full* before any of it is drawn (CON-102). There is
 * no partial paint and no repair: either the whole value is well-formed, or the
 * picture is dropped and the text rendering stands alone. REQ-105 guarantees
 * that text is always there, which is what makes dropping safe.
 */
function decodeLifehash(value) {
  if (typeof value !== "string" || !LIFEHASH_B64.test(value)) return null;
  let bytes;
  try {
    bytes = atob(value);
  } catch {
    return null;
  }
  return bytes.length === LIFEHASH_RGB_LEN ? bytes : null;
}

/**
 * Paint a fingerprint's LifeHash into a canvas — SPEC-002 REQ-101.
 *
 * This replaced three colour bars derived from bytes 0, 2 and 4 of the digest.
 * The picture is computed in `selfsame-core` from all six, so the front end no
 * longer derives any rendering of a security-relevant value for itself — it
 * only draws what the core sends (ADR-103).
 *
 * `aria-hidden` on the canvas, and the text beside it is what a screen reader
 * gets: a picture nobody is asked to compare has nothing to say to assistive
 * technology that its hex does not say better (REQ-105).
 *
 * The canvas is its natural 32×32 and is scaled by CSS with
 * `image-rendering: pixelated`, so there is no image codec on either side of
 * the boundary — `ImageData` takes exactly the buffer we already have
 * (ADR-104).
 */
function renderLifehash(canvas, value) {
  if (!canvas) return;
  const rgb = decodeLifehash(value);
  if (rgb === null) {
    // Degrade to the pre-existing display rather than to a broken screen.
    canvas.hidden = true;
    console.warn("lifehash failed CON-102's grammar; showing the text alone");
    return;
  }

  canvas.width = LIFEHASH_SIDE;
  canvas.height = LIFEHASH_SIDE;
  const ctx = canvas.getContext("2d");
  const image = ctx.createImageData(LIFEHASH_SIDE, LIFEHASH_SIDE);
  for (let src = 0, dst = 0; src < LIFEHASH_RGB_LEN; src += 3, dst += 4) {
    image.data[dst] = rgb.charCodeAt(src);
    image.data[dst + 1] = rgb.charCodeAt(src + 1);
    image.data[dst + 2] = rgb.charCodeAt(src + 2);
    image.data[dst + 3] = 255;
  }
  ctx.putImageData(image, 0, 0);
  canvas.hidden = false;
}

/** A device row's picture, built in JS because the row itself is. */
function lifehashElement(value, className) {
  const canvas = document.createElement("canvas");
  canvas.className = className;
  canvas.setAttribute("aria-hidden", "true");
  renderLifehash(canvas, value);
  return canvas;
}

function startCountdown() {
  stopCountdown();
  const tick = () => {
    const left = ui.offerExpiresAt - Math.floor(Date.now() / 1000);
    const el = $("[data-countdown]");
    if (left <= 0) {
      // REQ-016: at zero the offer is gone. The user is told so on a screen
      // with a route out of it, not by a toast behind the home screen.
      stopCountdown();
      invoke("reject_offer").catch(() => {});
      refuseCode("", "That code has expired — generate a new one.");
      return;
    }
    el.textContent = `expires ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
    el.classList.toggle("countdown--urgent", left <= 60);
  };
  tick();
  ui.countdownTimer = setInterval(tick, 1000);
}

function stopCountdown() {
  if (ui.countdownTimer) clearInterval(ui.countdownTimer);
  ui.countdownTimer = null;
}

async function reject() {
  stopCountdown();
  await invoke("reject_offer");
  show("rejected");
}

async function authorise() {
  const passcode = $("#presence-passcode").value;
  busy("Signing…");
  try {
    const result = await invoke("authorise", { passcode });
    $("#presence-passcode").value = "";
    stopCountdown();

    const label = $("[data-offer-desc]").textContent;
    $("[data-linked-title]").textContent = `${label} is yours.`;
    // A comparison prompt — "check it now shows this" — so it carries the hex,
    // for the same reason SCREEN-001's question does.
    $("[data-linked-fingerprint]").textContent = result.fingerprint.hex;
    renderLifehash($("[data-linked-lifehash]"), result.fingerprint.lifehash);
    $("[data-linked-method]").textContent = result.method_id;
    $("[data-linked-publishing]").textContent =
      result.publishing > 0 ? "publishing…" : "done";
    show("linked");

    // Keep trying in the background — REQ-020 is retried until acknowledged.
    if (result.publishing > 0) {
      setTimeout(() => invoke("flush_publications").catch(() => {}), 3000);
    }
  } catch (e) {
    fail("presence", message(e));
  } finally {
    idle();
  }
}

// ── devices ────────────────────────────────────────────────────────────

function openDevice(device) {
  ui.device = device;
  $("[data-device-title]").textContent = device.label || "Unnamed device";
  // This screen's "Key fingerprint" row is a key display like any other, so it
  // carries the picture too (REQ-101). It is also the screen the user reaches
  // just before unlinking, which is the moment being sure which device this is
  // matters most.
  renderLifehash($("[data-device-lifehash]"), device.lifehash);
  $("[data-device-nickname]").textContent = device.nickname ?? "—";
  $("[data-device-name]").textContent = device.label || "Unnamed device";
  $("[data-device-method]").textContent = device.method_id;
  $("[data-device-seen]").textContent = device.last_seen
    ? since(device.last_seen)
    : "not since this phone was set up";
  $("[data-device-status]").textContent = device.revoked
    ? "Unlinked"
    : device.pending
      ? "Publishing — others can't see it yet"
      : "Linked";
  $('[data-action="to-unlink"]').hidden = device.revoked;
  show("device");
}

function toUnlink() {
  $("[data-unlink-title]").textContent = `Unlink ${ui.device.label || "this device"}?`;
  show("unlink");
}

async function unlink() {
  const passcode = $("#unlink-passcode").value;
  const name = ui.device.label || "That device";
  busy("Signing…");
  try {
    await invoke("unlink_device", { methodId: ui.device.method_id, passcode });
    $("#unlink-passcode").value = "";

    // OBS-003: the revocation is signed here and then has to travel. The screen
    // says how far it has actually got rather than implying a kill switch.
    ui.state = await invoke("get_state");
    $("[data-unlinked-title]").textContent = `${name} is no longer you.`;
    $("[data-unlinked-publishing]").textContent =
      ui.state.pending_publications > 0
        ? "Retrying — will keep trying in the background"
        : "Done, just now";
    show("unlinked");
    if (ui.state.pending_publications > 0) {
      setTimeout(() => invoke("flush_publications").catch(() => {}), 3000);
    }
  } catch (e) {
    fail("unlink", message(e));
  } finally {
    idle();
  }
}

// ── wiring ─────────────────────────────────────────────────────────────

const actions = {
  "begin-create": () => show("passcode"),
  "begin-restore": () => show("restore"),
  "to-welcome": () => show("welcome"),
  "create-identity": createIdentity,
  "to-confirm": toConfirm,
  "to-phrase": () => show("phrase"),
  "check-backup": checkBackup,
  restore,
  "to-home": refresh,
  "to-link": startLink,
  "to-type": () => show("type"),
  // Back out of the typed-code screen.
  //
  // It cannot be `to-link`: on desktop `startLink` forwards straight to `type`
  // because there is no camera, so Back would re-enter the screen it was
  // leaving and the user would be stuck with no way out. Mirror the same branch
  // `startLink` makes — scanner on mobile, home on desktop — so Back always
  // lands where the user actually came from.
  "back-from-type": () =>
    window.__TAURI__?.barcodeScanner !== undefined ? startLink() : refresh(),
  "read-code": () => readCode($("#code-input").value.trim()),
  reject,
  "to-presence": () => show("presence"),
  "back-to-consent": () => show("consent"),
  authorise,
  "to-unlink": toUnlink,
  "back-to-device": () => openDevice(ui.device),
  unlink,
};

// IMPL-004 registers its own actions into the same map, so the delegated
// listener below dispatches both surfaces without knowing there are two.
const appIdentity = initAppIdentity({
  $, $$, show, invoke, fail, clearErrors, message, renderLifehash, since, actions,
});

document.addEventListener("click", (e) => {
  const el = e.target.closest("[data-action]");
  if (!el || el.disabled) return;
  const fn = actions[el.dataset.action];
  if (fn) fn();
});

$("#code-input").addEventListener("input", onCodeInput);

// Publication is retried whenever the app comes back to the foreground: a
// phone that was offline when a device was linked should catch up without the
// user having to know that publication is a thing (REQ-020).
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) invoke("flush_publications").catch(() => {});
});

refresh().catch((e) => {
  document.body.textContent = `Selfsame could not start: ${message(e)}`;
});
