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

  async function start() {
    const input = $("#pairing-input");
    const invitation = input.value.trim();
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
    "approve-cbcl-pairing": () => decide(true),
    "decline-cbcl-pairing": () => decide(false),
    "cancel-cbcl-pairing": cancel,
    "finish-cbcl-pairing": () => show("applications"),
  });

  const input = $("#pairing-input");
  if (input) input.addEventListener("input", onInput);
  return { forget };
}
