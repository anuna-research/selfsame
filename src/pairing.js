/**
 * The ordinary Selfsame pairing action after the SPEC-007 cutover.
 *
 * JavaScript holds only display values. CPace, Finished, channel keys, relay
 * sequencing, the explicit decision, payload authorization, and Selfsame
 * acceptance remain in Rust.
 */

export function initPairing(d) {
  const { $, show, invoke, fail, message, actions, busy, idle } = d;

  function onInput() {
    const value = $("#pairing-input")?.value.trim() ?? "";
    $("[data-pairing-state]").textContent = value ? "Invitation ready" : "Paste one invitation";
    $('[data-action="start-cbcl-pairing"]').disabled = value.length === 0;
  }

  async function start(presented) {
    const input = $("#pairing-input");
    const invitation = typeof presented === "string" ? presented.trim() : input.value.trim();
    busy("Starting secure pairing…");
    $("[data-cbcl-relay]").textContent = "Checking invitation…";
    $("[data-cbcl-status]").textContent = "Establishing CPace, Finished, and fixed roles.";
    show("pairing-wait");
    $("[data-screen='pairing-wait']").focus();
    try {
      const view = await invoke("cbcl_pairing_start", { invitation });
      input.value = "";
      onInput();
      $("[data-cbcl-relay]").textContent = view.relayOrigin;
      $("[data-cbcl-status]").textContent = view.status;
      if (view.intent) showIntent(view.intent);
    } catch (error) {
      const token = message(error);
      show("pairing-enter");
      fail(
        "pairing",
        token === "PairingVersionUnsupported"
          ? "That invitation came from an obsolete development build. Ask the application for a new one."
          : token === "PairingRelayUnavailable"
            ? "The local relay could not be reached. Check the demo server and adb reverse, then create a fresh invitation."
            : token === "PairingRelayRefused"
              ? "That invitation does not name the approved local demo relay. Nothing was shared."
              : "That invitation could not be recognised. Nothing was shared.",
      );
    } finally {
      idle();
    }
  }

  function showIntent(intent) {
    $("[data-cbcl-authority]").textContent = intent.authoritySummary;
    $("[data-cbcl-application]").textContent = intent.application;
    $("[data-cbcl-action]").textContent = intent.action;
    const fields = $("[data-cbcl-intent-fields]");
    fields.replaceChildren();
    for (const field of intent.fields) {
      const row = document.createElement("div");
      const label = document.createElement("dt");
      const value = document.createElement("dd");
      label.textContent = field.label;
      value.textContent = field.value;
      row.append(label, value);
      fields.append(row);
    }
    show("pairing-consent");
    $("[data-screen='pairing-consent']").focus();
  }

  async function decide(approve) {
    busy(approve ? "Applying explicit approval…" : "Recording decline…");
    try {
      const result = await invoke(approve ? "cbcl_pairing_approve" : "cbcl_pairing_decline");
      $("[data-cbcl-result-title]").textContent = result.title;
      $("[data-cbcl-result-message]").textContent = result.message;
      const mark = $("[data-cbcl-result-mark]");
      mark.classList.toggle("mark--ok", result.outcome === "accepted");
      mark.classList.toggle("mark--broken", result.outcome !== "accepted");
      show("pairing-result");
      $("[data-screen='pairing-result']").focus();
    } catch (_) {
      show("pairing-enter");
      fail("pairing", "The secure ceremony failed closed. Create a fresh invitation and try again.");
    } finally {
      idle();
    }
  }

  async function cancel() {
    try {
      await invoke("cbcl_pairing_cancel");
    } finally {
      show("applications");
    }
  }

  // The QR payload IS the paste payload: the application encodes the unpadded
  // base64url carrier into the symbol, so a scan and a paste recognise
  // identical input and everything after this line is the one ordinary
  // `start` path. The camera choreography mirrors the linking screen's:
  // `scan` checks the permission and throws rather than requesting it, so the
  // asking is this caller's job; `windowed: true` renders the preview beneath
  // the webview, so the page must get out of its way for the duration.
  async function scan() {
    const note = $("[data-pairing-scanner-note]");
    const say = (text) => {
      if (note) {
        note.hidden = !text;
        note.textContent = text;
      }
    };
    const camera = window.__TAURI__?.barcodeScanner;
    if (!camera) {
      say("No camera in this build — paste the invitation instead.");
      return;
    }
    try {
      let access = await camera.checkPermissions();
      if (access !== "granted") {
        access = await camera.requestPermissions();
      }
      if (access !== "granted") {
        say(
          "Camera access is off for Selfsame — turn it on in Settings, " +
            "or paste the invitation instead.",
        );
        return;
      }
      document.body.classList.add("scanning");
      let scanned;
      try {
        scanned = await camera.scan({ formats: ["QRCode"], windowed: true });
      } finally {
        document.body.classList.remove("scanning");
      }
      say("");
      await start(scanned.content);
    } catch (error) {
      const reason = String(error?.message ?? error ?? "unknown");
      console.error("pairing scan unavailable:", reason);
      say(
        /denied|permission|not allowed/i.test(reason)
          ? "Camera access is off for Selfsame — turn it on in Settings, " +
              "or paste the invitation instead."
          : "The camera isn’t available. Paste the invitation instead.",
      );
    }
  }

  function forget() {
    const input = $("#pairing-input");
    if (input) input.value = "";
  }

  Object.assign(actions, {
    "to-pairing": () => {
      forget();
      onInput();
      show("pairing-enter");
    },
    "start-cbcl-pairing": start,
    "scan-cbcl-pairing": scan,
    "approve-cbcl-pairing": () => decide(true),
    "decline-cbcl-pairing": () => decide(false),
    "cancel-cbcl-pairing": cancel,
    "finish-cbcl-pairing": () => show("applications"),
  });

  const input = $("#pairing-input");
  if (input) input.addEventListener("input", onInput);
  // Desktop: the pasted route is the route. Hide the dead camera affordance
  // rather than offering a button that can only apologise.
  if (!window.__TAURI__?.barcodeScanner) {
    const scanButton = $('[data-action="scan-cbcl-pairing"]');
    if (scanButton) scanButton.hidden = true;
  }
  return { forget };
}
