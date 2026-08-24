/**
 * The ordinary Selfsame pairing action after the SPEC-007 cutover.
 *
 * JavaScript holds only display values. CPace, Finished, channel keys, relay
 * sequencing, the explicit decision, payload authorization, and Selfsame
 * acceptance remain in Rust.
 */

export function initPairing(d) {
  const { $, show, invoke, fail, message, actions, busy, idle, refresh } = d;
  const presencePattern = /^PAIR1-(?:[0-9A-HJKMNP-TV-Z]{5}-){10}[0-9A-HJKMNP-TV-Z]{5}$/;
  let credentialV2Stage = "idle";
  let recoveryApplication = null;

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
    const presence = $("#pairing-presence-code")?.value.trim().toUpperCase() ?? "";
    const ready = value.length > 0 && presencePattern.test(presence);
    $("[data-pairing-state]").textContent = ready
      ? "Invitation and presence code ready"
      : value.length > 0
        ? "Enter the PAIR1 code shown by the application"
        : "Paste one invitation";
    $('[data-action="start-cbcl-pairing"]').disabled = !ready;
  }

  async function start(presented) {
    const input = $("#pairing-input");
    const invitation = typeof presented === "string" ? presented.trim() : input.value.trim();
    const presenceInput = $("#pairing-presence-code");
    const presenceCode = (presenceInput?.value ?? "").trim().toUpperCase();
    busy("Authenticating the application profile…");
    $("[data-cbcl-relay]").textContent = "No relay connection yet";
    $("[data-cbcl-status]").textContent = "Checking the invitation and its declared relay before any socket opens.";
    show("pairing-wait");
    $("[data-screen='pairing-wait']").focus();
    try {
      const view = await invoke("cbcl_v2_recognise", { invitation, presenceCode });
      input.value = "";
      if (presenceInput) presenceInput.value = "";
      onInput();
      if (view.requiresApproval) {
        showRelayConsent(view);
      } else {
        await advanceRelay(true);
      }
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
        : "The live authenticated application profile does not declare that relay. Nothing was shared.";
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
    if (token === "PairingReceiptRefused" || token === "PairingAuthorityRefused" || token === "PairingResolverRefused")
      return "The application's final receipt or reciprocal account binding could not be verified. The grant was not installed.";
    if (token === "AuthorityUnreachable" || token === "PairingIssuerUnavailable" || token === "PairingIdentityUnavailable")
      return "Your account's authority could not be reached to verify this pairing. Nothing was shared.";
    return "That invitation could not be recognised. Nothing was shared.";
  }

  function paintConsent({ title, authority, application, action, fields: fieldList, approve = "Approve request", decline = "Decline" }) {
    $("[data-cbcl-consent-title]").textContent = title;
    $("[data-cbcl-authority]").textContent = authority;
    $("[data-cbcl-application]").textContent = application;
    $("[data-cbcl-action]").textContent = action;
    const fields = $("[data-cbcl-intent-fields]");
    fields.replaceChildren();
    for (const field of fieldList) {
      const row = document.createElement("div");
      const label = document.createElement("dt");
      const value = document.createElement("dd");
      label.textContent = field.label;
      value.textContent = field.value;
      row.append(label, value);
      fields.append(row);
    }
    const approveButton = $('[data-action="approve-cbcl-pairing"]');
    const declineButton = $('[data-action="decline-cbcl-pairing"]');
    approveButton.textContent = approve;
    declineButton.textContent = decline;
    declineButton.hidden = false;
    show("pairing-consent");
    $("[data-screen='pairing-consent']").focus();
  }

  function showRelayConsent(view) {
    credentialV2Stage = "relay";
    paintConsent({
      title: "Trust this new relay?",
      authority: "The application’s live authenticated profile declares this relay, but you have not approved this exact application–relay pair before.",
      application: view.applicationId,
      action: "Your approval adds only this exact pair to your own relay policy.",
      fields: [
        { label: "Application", value: view.applicationId },
        { label: "New blind relay", value: view.relayOrigin },
      ],
      approve: "Trust and continue",
      decline: "Reject relay",
    });
  }

  function showIntent(intent) {
    credentialV2Stage = "intent";
    const fields = [
      { label: "Authenticated application", value: intent.applicationId },
      { label: "HTTPS origin", value: intent.httpsOrigin },
      { label: "Blind relay", value: intent.relayOrigin },
      { label: "Installation device", value: intent.deviceDid },
      { label: "Account principal", value: intent.accountPrincipalDigest },
      ...intent.permissions.map((value) => ({ label: "Permission", value })),
    ];
    if (intent.transition?.kind === "path-a-to-b") {
      fields.push({ label: "Existing chat handle", value: intent.transition.legacyHandle });
      for (const room of intent.transition.migrationRooms) {
        fields.push({ label: "Room to migrate", value: room });
      }
    }
    paintConsent({
      title: "Review the exact request",
      authority: "CPace and both Finished values authenticated this request under the live application profile.",
      application: intent.applicationId,
      action: "Approval permits a pure account-identity preview; it does not issue or publish anything.",
      fields,
      approve: "Preview identity",
    });
  }

  function showFinalReview(review) {
    credentialV2Stage = "final";
    paintConsent({
      title: "Approve account linking?",
      authority: "This is the second and final decision. Only approval here permits identity publication and one account grant.",
      application: review.applicationId,
      action: review.comparison === "bound-same-did"
        ? "The application’s existing reciprocal binding matches this wallet identity."
        : "No prior binding exists; compare this identity with the application in front of you.",
      fields: [
        { label: "Account issuer DID", value: review.previewIssuerDid },
        { label: "Comparison fingerprint", value: review.previewFingerprint.hex },
        { label: "Recognition aid", value: review.previewFingerprint.label },
      ],
      approve: "Approve and link",
    });
  }

  function showRecovery(applicationId) {
    recoveryApplication = applicationId;
    credentialV2Stage = "recovery";
    paintConsent({
      title: "Finish interrupted link?",
      authority: "Selfsame retained a sealed, non-authorising completion checkpoint after the blind relay window closed.",
      application: applicationId,
      action: "Recovery asks the authenticated application origin for its signed final status. It cannot derive, publish, issue, or resend the credential payload again.",
      fields: [
        { label: "Authenticated application", value: applicationId },
        { label: "Recovery route", value: "Direct HTTPS final-status check" },
      ],
      approve: "Recover link",
      decline: "Not now",
    });
  }

  function showRecoveryRotation(view) {
    credentialV2Stage = "recovery-rotation";
    const rotation = view.authorityRotation;
    paintConsent({
      title: "Application authority changed",
      authority: "The historical pairing result verified under the sealed offer profile, but the application’s currently authenticated signing authority differs.",
      application: view.applicationId,
      action: "Approve only if you expect this application authority rotation. Declining preserves the sealed pending link unchanged.",
      fields: [
        { label: "Retained key", value: rotation.retainedKid },
        { label: "Current key", value: rotation.currentKid ?? "Retained key no longer listed" },
        { label: "Retained profile digest", value: rotation.retainedProfileDigest },
        { label: "Current profile digest", value: rotation.currentProfileDigest },
      ],
      approve: "Accept rotation",
      decline: "Keep pending",
    });
  }

  function showResult(outcome, title, resultMessage, boundary) {
    $("[data-cbcl-result-title]").textContent = title;
    $("[data-cbcl-result-message]").textContent = resultMessage;
    $("[data-cbcl-result-boundary]").textContent = boundary;
    const mark = $("[data-cbcl-result-mark]");
    mark.classList.toggle("mark--ok", outcome === "accepted");
    mark.classList.toggle("mark--broken", outcome !== "accepted");
    show("pairing-result");
    $("[data-screen='pairing-result']").focus();
  }

  async function advanceRelay(approve) {
    busy(approve ? "Opening the approved blind relay…" : "Rejecting the relay…");
    const result = await invoke("cbcl_v2_relay_decide", { approve });
    if (result.outcome === "declined") {
      credentialV2Stage = "idle";
      showResult("declined", "Relay rejected", "No relay socket was opened and no credential was shared.", "The invitation was not allowed to choose relay trust for you.");
      return;
    }
    $("[data-cbcl-relay]").textContent = result.intent.relayOrigin;
    showIntent(result.intent);
  }

  async function decide(approve) {
    busy(approve ? "Applying explicit approval…" : "Recording decline…");
    try {
      if (credentialV2Stage === "recovery" || credentialV2Stage === "recovery-rotation") {
        if (!approve) {
          recoveryApplication = null;
          credentialV2Stage = "idle";
          const passcodeInput = $("#pairing-passcode");
          if (passcodeInput) passcodeInput.value = "";
          await refresh();
          return;
        }
        const approveRotation = credentialV2Stage === "recovery-rotation";
        const passcodeInput = $("#pairing-passcode");
        const passcode = passcodeInput?.value ?? "";
        const result = await invoke("cbcl_v2_recover", {
          applicationId: recoveryApplication,
          passcode,
          approveRotation,
        });
        if (result.outcome === "authority-rotation") {
          showRecoveryRotation(result);
          return;
        }
        recoveryApplication = null;
        credentialV2Stage = "idle";
        if (passcodeInput) passcodeInput.value = "";
        if (result.outcome === "installed") {
          showResult(
            "accepted",
            "Application connected",
            "The recovered signed hub status and live reciprocal account binding were verified before installation.",
            "No key, grant, publication, or credential payload was created a second time.",
          );
          return;
        }
        if (result.outcome === "not-finalized") {
          showResult(
            "declined",
            "Interrupted link closed",
            "The application signed that this ceremony can no longer finalize, so Selfsame removed only its pending checkpoint.",
            "No account grant was installed.",
          );
          return;
        }
        const detail = result.outcome === "in-progress"
          ? `The application is still finalizing this link. Try again in about ${result.retryAfterSeconds} seconds.`
          : result.outcome === "unknown"
            ? "The application no longer retains enough evidence to answer. The sealed pending link remains until you explicitly unlink it or remove this wallet identity."
            : result.outcome === "relay-window-open"
              ? "The blind relay window is still open. Selfsame will use direct HTTPS recovery only after it closes."
              : "The application’s recovery service is temporarily unavailable. The sealed pending link remains safe to retry.";
        showResult("declined", "Recovery not complete", detail, "No pending state was removed and no capability was granted.");
        return;
      }
      if (credentialV2Stage === "relay") {
        await advanceRelay(approve);
        return;
      }
      const passcodeInput = $("#pairing-passcode");
      const passcode = approve ? (passcodeInput?.value ?? "") : null;
      if (credentialV2Stage === "intent") {
        const result = await invoke("cbcl_v2_preliminary_decide", { approve, passcode });
        if (result.outcome === "declined") {
          credentialV2Stage = "idle";
          if (passcodeInput) passcodeInput.value = "";
          showResult("declined", "Request declined", "No identity was issued, published, or shared.", "The authenticated request ended before any identity effect.");
        } else {
          showFinalReview(result.finalReview);
        }
        return;
      }
      if (credentialV2Stage === "final") {
        const result = await invoke("cbcl_v2_final_decide", { approve, passcode });
        if (result.outcome === "declined") {
          credentialV2Stage = "idle";
          if (passcodeInput) passcodeInput.value = "";
          showResult("declined", "Link declined", "No account grant was installed.", "The final person decision released no credential payload.");
          return;
        }
        credentialV2Stage = "finish";
      }
      if (credentialV2Stage === "finish") {
        $("[data-cbcl-status]").textContent = "Waiting for the hub’s atomic acceptance and reciprocal account binding.";
        show("pairing-wait");
        const result = await invoke("cbcl_v2_finish", { passcode });
        if (result.outcome !== "installed") throw new Error("credential/v2 installation was refused");
        credentialV2Stage = "idle";
        if (passcodeInput) passcodeInput.value = "";
        showResult("accepted", "Application connected", "The signed hub receipt and live reciprocal account binding were verified before the grant was installed.", "The relay learned only opaque protocol frames; trust is scoped to this application–relay pair.");
      }
    } catch (error) {
      const token = message(error);
      if (credentialV2Stage === "finish") {
        show("pairing-consent");
        $('[data-action="approve-cbcl-pairing"]').textContent = "Retry final verification";
        $('[data-action="decline-cbcl-pairing"]').hidden = true;
        fail("pairing-consent", `The final verification did not complete (${token}). The durable pending link is safe to retry.`);
      } else {
        show("pairing-enter");
        fail("pairing", startFailureText(token));
      }
    } finally {
      idle();
    }
  }

  async function cancel() {
    try {
      await invoke("cbcl_v2_cancel");
    } finally {
      credentialV2Stage = "idle";
      const passcode = $("#pairing-passcode");
      if (passcode) passcode.value = "";
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
      const input = $("#pairing-input");
      if (input) input.value = scanned.content;
      onInput();
      $("#pairing-presence-code")?.focus();
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
    const presence = $("#pairing-presence-code");
    if (presence) presence.value = "";
    credentialV2Stage = "idle";
    recoveryApplication = null;
  }

  async function resumePending() {
    if (credentialV2Stage !== "idle") return;
    const applications = await invoke("cbcl_v2_pending_recoveries");
    if (Array.isArray(applications) && applications.length > 0) {
      showRecovery(applications[0]);
    }
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
  const presence = $("#pairing-presence-code");
  if (presence) presence.addEventListener("input", onInput);
  // Desktop: the pasted route is the route. Hide the dead camera affordance
  // rather than offering a button that can only apologise.
  if (!window.__TAURI__?.barcodeScanner) {
    const scanButton = $('[data-action="scan-cbcl-pairing"]');
    if (scanButton) scanButton.hidden = true;
  }
  return { forget, resumePending };
}
