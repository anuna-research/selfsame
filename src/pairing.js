/**
 * The ordinary Selfsame pairing action after the SPEC-007 cutover.
 *
 * JavaScript holds only the base64url invitation long enough to cross the
 * Tauri bridge. CPace and signing state remain in Rust, and there is no
 * protocol selector or legacy fallback on this surface.
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
    try {
      const view = await invoke("cbcl_pairing_start", { invitation });
      input.value = "";
      onInput();
      $("[data-cbcl-relay]").textContent = view.relayOrigin;
      $("[data-cbcl-status]").textContent = view.status;
      show("pairing-wait");
      $("[data-screen='pairing-wait']").focus();
    } catch (error) {
      const token = message(error);
      fail(
        "pairing",
        token === "PairingVersionUnsupported"
          ? "That invitation came from an obsolete development build. Ask the application for a new one."
          : "That invitation could not be recognised. Nothing was shared.",
      );
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
    "cancel-cbcl-pairing": cancel,
  });

  const input = $("#pairing-input");
  if (input) input.addEventListener("input", onInput);
  return { forget };
}
