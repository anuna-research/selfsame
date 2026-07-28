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

  $("[data-home-fingerprint]").textContent = s.root_fingerprint ?? "";
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

    const mark = document.createElement("div");
    mark.className = "mark";
    if (d.revoked) mark.classList.add("mark--broken");
    else if (d.pending) mark.classList.add("mark--pending");
    mark.setAttribute("aria-hidden", "true");

    const body = document.createElement("div");
    body.className = "device__body";
    const name = document.createElement("span");
    name.className = "device__name";
    // Untrusted text, inserted as text and never as markup.
    name.textContent = d.label || "Unnamed device";
    const meta = document.createElement("span");
    meta.className = "device__meta";
    meta.textContent = d.revoked
      ? "Unlinked"
      : d.pending
        ? "publishing — others can't see it yet"
        : d.last_seen
          ? `seen ${since(d.last_seen)}`
          : d.method_id.split("#")[1];

    body.append(name, meta);
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
    $("[data-created-fingerprint]").textContent = ui.created.fingerprint;
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
    await refresh();
  } catch (e) {
    fail("restore", message(e));
  } finally {
    idle();
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
    fail("code", message(e));
    show("type");
  } finally {
    idle();
  }
}

function renderConsent(offer) {
  // REQ-019's four required facts, in the order the screen states them.
  $("[data-offer-app]").textContent = offer.application;
  $("[data-offer-purpose]").textContent = offer.purpose;
  // Untrusted: text, never markup, and already length-capped by the recogniser.
  $("[data-offer-desc]").textContent = offer.device_description || "(it said nothing)";
  $("[data-offer-fingerprint]").textContent = offer.key_fingerprint;

  ui.offerExpiresAt = Math.floor(Date.now() / 1000) + offer.expires_in;
  startCountdown();
}

function startCountdown() {
  stopCountdown();
  const tick = () => {
    const left = ui.offerExpiresAt - Math.floor(Date.now() / 1000);
    const el = $("[data-countdown]");
    if (left <= 0) {
      stopCountdown();
      cancelOffer("That code has expired — generate a new one.");
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

async function cancelOffer(note) {
  stopCountdown();
  await invoke("reject_offer");
  if (note) fail("code", note);
  await refresh();
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
    $("[data-linked-fingerprint]").textContent = result.fingerprint;
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
  busy("Signing…");
  try {
    await invoke("unlink_device", { methodId: ui.device.method_id, passcode });
    $("#unlink-passcode").value = "";
    await refresh();
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
  "read-code": () => readCode($("#code-input").value.trim()),
  "cancel-offer": () => cancelOffer(),
  reject,
  "to-presence": () => show("presence"),
  "back-to-consent": () => show("consent"),
  authorise,
  "to-unlink": toUnlink,
  "back-to-device": () => openDevice(ui.device),
  unlink,
};

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
