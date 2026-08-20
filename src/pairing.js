/**
 * The ordinary Selfsame pairing action after the SPEC-007 cutover.
 *
 * JavaScript holds only display values. CPace, Finished, channel keys, relay
 * sequencing, the explicit decision, payload authorization, and Selfsame
 * acceptance remain in Rust.
 */

export function initPairing(d) {
  const { $, show, invoke, fail, message, actions, busy, idle } = d;

  // REQ-908: capability comes from the build, never from hardcoded prose.
  // Until the answer arrives the surface assumes the production shape, which
  // shows no demo copy — the fail-safe direction.
  let capability = { demoRelay: false, productionClaimant: true };
  const passcodeField = $("[data-pairing-passcode-field]");
  // Fail-safe default (review finding m-5): the production shape shows the
  // field; only a build that ANSWERS demo hides it. A failed capability call
  // leaves the production surface intact.
  if (passcodeField) passcodeField.hidden = false;
  invoke("cbcl_pairing_capability")
    .then((view) => {
      // A bridge that answers with anything but the capability shape leaves
      // the fail-safe production default standing (screens harness stubs
      // unknown commands as null).
      if (view && typeof view.productionClaimant === "boolean") {
        capability = view;
      }
      if (passcodeField) passcodeField.hidden = !capability.productionClaimant;
    })
    .catch(() => {});

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
      const passcodeInput = $("#pairing-passcode");
      const passcode = capability.productionClaimant
        ? (passcodeInput?.value ?? "")
        : null;
      const view = await invoke("cbcl_pairing_start", { invitation, passcode });
      // The shell holds what it needs; the DOM does not (review finding m-5).
      if (passcodeInput) passcodeInput.value = "";
      input.value = "";
      onInput();
      $("[data-cbcl-relay]").textContent = view.relayOrigin;
      $("[data-cbcl-status]").textContent = view.status;
      if (view.intent) showIntent(view.intent);
    } catch (error) {
      const token = message(error);
      show("pairing-enter");
      fail("pairing", startFailureText(token));
    } finally {
      idle();
    }
  }

  // One message per closed error token (REQ-906/CON-901 error model), and
  // demo-only wording exists only when the build carries the demo relay
  // (REQ-908 / TEST-912).
  function startFailureText(token) {
    if (token === "PairingVersionUnsupported")
      return "That invitation came from an obsolete development build. Ask the application for a new one.";
    if (token === "PairingRelayUnavailable")
      return capability.demoRelay
        ? "The local relay could not be reached. Check the demo server and adb reverse, then create a fresh invitation."
        : "The relay could not be reached. Ask the application for a fresh invitation and try again.";
    if (token === "PairingRelayRefused")
      return capability.demoRelay
        ? "That invitation does not name the approved local demo relay. Nothing was shared."
        : "That invitation names a relay none of your connected applications vouches for. Nothing was shared.";
    if (token === "PairingRelayAmbiguous")
      return "More than one of your applications names that relay, so Selfsame refused rather than guessed. Nothing was shared.";
    if (token === "PairingRelayTlsRefused")
      return "The relay's identity could not be verified, so nothing was sent to it.";
    if (token === "PresenceRequired" || token === "BadPasscode")
      return "Enter your Selfsame passcode to start pairing.";
    if (token === "PairingScopeAmbiguous")
      return "That application asks for more than one kind of access, which pairing cannot carry yet. Nothing was shared.";
    if (token === "PairingProfileUnavailable")
      return "The application's profile could not be re-verified. Check your connection and try again.";
    if (token === "AuthorityUnreachable" || token === "PairingIssuerUnavailable" || token === "PairingIdentityUnavailable")
      return "Your account's authority could not be reached to verify this pairing. Nothing was shared.";
    return "That invitation could not be recognised. Nothing was shared.";
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
      // REQ-908: the boundary line states what THIS build did, derived from
      // its capability — never a hardcoded claim about a different build.
      const boundary = $("[data-cbcl-result-boundary]");
      if (boundary) {
        boundary.textContent = capability.demoRelay
          ? "This local conformance ceremony does not enable production pairing."
          : "This ceremony ran against a relay your application's own profile vouches for.";
      }
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
    const passcode = $("#pairing-passcode");
    if (passcode) passcode.value = "";
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
