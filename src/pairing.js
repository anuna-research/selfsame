/**
 * The ordinary Selfsame pairing action after the SPEC-007 cutover.
 *
 * JavaScript holds only display values. CPace, Finished, channel keys, relay
 * sequencing, the explicit decision, payload authorization, and Selfsame
 * acceptance remain in Rust.
 */

export function initPairing(d) {
  const { $, show, invoke, fail, message, renderLifehash, actions, busy, idle, refresh } = d;
  const presencePattern = /^PAIR1-(?:[0-9A-HJKMNP-TV-Z]{5}-){10}[0-9A-HJKMNP-TV-Z]{5}$/;
  let credentialV2Stage = "idle";
  let attemptEpoch = 0;
  let flow = "single";
  let entryMode = "full";
  let attemptTag = null;
  let attemptApplication = null;
  let decisionPending = false;
  let intentFields = [];
  let recoveryApplication = null;
  let installedLink = null;
  let pendingLink = null;

  // REQ-908: capability comes from the build, never from hardcoded prose.
  // Until the answer arrives the surface assumes the production shape, which
  // shows no demo copy — the fail-safe direction.
  let capability = { demoRelay: false, productionClaimant: true };
  const passcodeField = $("[data-pairing-passcode-field]");
  // SingleLink asks for presence only after the request is authenticated.
  // Explicit legacy entry reveals this production field from `onInput`; a
  // build that identifies itself as demo keeps the field hidden there too.
  if (passcodeField) passcodeField.hidden = true;
  let applicationLifecycle = false;
  const capabilityReady = invoke("cbcl_pairing_capability")
    .then(async (view) => {
      // A bridge that answers with anything but the capability shape leaves
      // the fail-safe production default standing (screens harness stubs
      // unknown commands as null).
      if (view && typeof view.productionClaimant === "boolean") {
        capability = view;
      }
      if (passcodeField) passcodeField.hidden = flow === "single" || !capability.productionClaimant;
      if (view?.applicationLifecycle && window.__TAURI__?.event?.listen) {
        await window.__TAURI__.event.listen("selfsame-pairing-backgrounded", () => {
          clearTransferInputs();
          onInput();
          interruptPairing();
        });
        applicationLifecycle = true;
      }
    })
    .catch(() => {});

  function clearTransferInputs() {
    for (const selector of ["#pairing-input", "#pairing-presence-code", "#pairing-manual-bootstrap", "#pairing-manual-words"]) {
      const input = $(selector);
      if (input) input.value = "";
    }
  }
  function selectEntryMode(mode) {
    if (credentialV2Stage !== "idle" || entryMode === mode) return;
    ++attemptEpoch;
    clearTransferInputs();
    entryMode = mode;
    if (mode !== "manual") $("[data-pairing-manual]").open = false;
    if (mode !== "legacy") $("[data-pairing-legacy]").open = false;
    $("[data-pairing-complete]").hidden = mode === "manual";
    $("[data-action='scan-cbcl-pairing']").hidden = mode !== "full" || !window.__TAURI__?.barcodeScanner;
    onInput();
  }
  function onInput() {
    const manual = entryMode === "manual";
    const legacy = entryMode === "legacy";
    const value = $(manual ? "#pairing-manual-bootstrap" : "#pairing-input")?.value ?? "";
    const presence = $("#pairing-presence-code")?.value.trim().toUpperCase() ?? "";
    const words = $("#pairing-manual-words")?.value ?? "";
    if (credentialV2Stage === "idle" && passcodeField) passcodeField.hidden = !legacy || !capability.productionClaimant;
    // Only presence of input is a UI affordance; Rust owns every manual bound,
    // word/checksum and bootstrap rule, including accepted normalization.
    const ready = value.length > 0 && (manual ? words.length > 0 : !legacy || presencePattern.test(presence));
    $("[data-pairing-state]").textContent = ready
      ? "Invitation ready"
      : manual ? "Enter the manual invitation and three words"
        : legacy && value.length > 0 ? "Enter the older invitation’s PAIR1 code"
          : "Scan a QR code or paste an invitation";
    $('[data-action="start-cbcl-pairing"]').disabled = credentialV2Stage !== "idle" || !ready;
  }

  async function start(presented) {
    await capabilityReady;
    if (credentialV2Stage !== "idle") return;
    const epoch = ++attemptEpoch;
    const manual = typeof presented !== "string" && entryMode === "manual";
    const input = $(manual ? "#pairing-manual-bootstrap" : "#pairing-input");
    let handoff = typeof presented === "string" ? presented : input.value;
    let words = manual ? $("#pairing-manual-words").value : "";
    const legacy = typeof presented !== "string" && entryMode === "legacy";
    flow = legacy ? "legacy" : "single";
    attemptTag = null;
    attemptApplication = null;
    credentialV2Stage = "entry";
    const presenceInput = $("#pairing-presence-code");
    const presenceCode = (presenceInput?.value ?? "").trim().toUpperCase();
    if (!manual) {
      input.value = "";
      if (presenceInput) presenceInput.value = "";
    }
    intentFields = [];
    onInput();
    busy("Checking the invitation…");
    $("[data-cbcl-relay]").textContent = "No relay connection yet";
    $("[data-cbcl-status]").textContent = "Checking the application and its relay.";
    show("pairing-wait");
    $("[data-screen='pairing-wait']").focus();
    idle(); // The wait screen keeps cancellation reachable.
    try {
      if (legacy) {
        const view = await invoke("cbcl_v2_recognise", { invitation: handoff.trim(), presenceCode });
        if (epoch !== attemptEpoch) return;
        if (view.requiresApproval) showRelayConsent(view);
        else await advanceRelay(true, epoch);
      } else {
        const reservation = manual
          ? await invoke("cbcl_v2_begin_manual", { request: { bootstrap: handoff, words } })
          : await invoke("cbcl_v2_begin_handoff", { request: { handoff } });
        handoff = "";
        words = "";
        if (epoch !== attemptEpoch) {
          await invoke("cbcl_v2_cancel_link", { request: { attemptTag: reservation.attemptTag } }).catch(() => {});
          return;
        }
        clearTransferInputs();
        attemptTag = reservation.attemptTag;
        attemptApplication = reservation.applicationId;
        credentialV2Stage = "contact";
        $("[data-cbcl-relay]").textContent = reservation.relayOrigin;
        $("[data-cbcl-status]").textContent = `This invitation permits contact with ${reservation.applicationId} and its displayed relay for this link only.`;
        const result = await invoke("cbcl_v2_contact", { request: { attemptTag } });
        if (epoch !== attemptEpoch) return;
        showIntent(result.intent);
      }
    } catch (error) {
      if (epoch !== attemptEpoch) return;
      const localRecognition = credentialV2Stage === "entry";
      await revokeNative();
      if (epoch !== attemptEpoch) return;
      credentialV2Stage = "idle";
      attemptTag = null;
      restoreEntryUnlock();
      show("pairing-enter");
      fail("pairing", manual && localRecognition && message(error) === "RecognitionFailed"
        ? "The manual invitation could not be recognised. Check both inputs and try again."
        : startFailureText(message(error)));
      onInput();
      if (manual) $("#pairing-manual-words").focus();
    } finally {
      if (epoch === attemptEpoch) idle();
    }
  }

  // One message per closed error token (REQ-906/CON-901 error model), and
  // demo-only wording exists only when the build carries the demo relay
  // (REQ-908 / TEST-912).
  function startFailureText(token) {
    if (token === "PairingVersionUnsupported")
      return "Update Selfsame and the application, then create a new invitation.";
    if (token === "PairingInvitationExpired" || token === "PairingOfferExpired" || token === "PairingExpired")
      return "That invitation expired. Create a new one in the application and scan it again.";
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
    if (token === "PairingApplicationAlreadyLinked")
      return "This application already has a link on this device. Finish or close it from the Applications screen before pairing again. Nothing was shared.";
    if (token === "PairingResolverUnavailable")
      return "Your new identity could not be published to the application's declared resolver. Check your connection and try again.";
    if (token === "PairingOfferExpired")
      return "The application's offer expired before approval finished. Ask the application for a fresh invitation.";
    if (token === "PairingPreviewChanged")
      return "The identity being linked changed since it was shown to you, so Selfsame refused. Nothing was shared.";
    // Custody refusals arrive as person-readable sentences ("finish writing
    // down your recovery phrase first") rather than closed tokens; show them
    // as they stand. Any other unlisted token names itself, because a hidden
    // token makes unrelated failures indistinguishable at the screen.
    if (typeof token === "string" && token.includes(" ")) return token;
    return `That invitation could not be recognised${token ? ` (${token})` : ""}. Nothing was shared.`;
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
      if (field.lifehash && renderLifehash) {
        const canvas = document.createElement("canvas");
        canvas.className = "fp__lifehash fp__lifehash--lg";
        canvas.setAttribute("aria-hidden", "true");
        renderLifehash(canvas, field.lifehash);
        value.append(canvas);
      }
      fields.append(row);
    }
    const approveButton = $('[data-action="approve-cbcl-pairing"]');
    const declineButton = $('[data-action="decline-cbcl-pairing"]');
    approveButton.textContent = approve;
    approveButton.disabled = actionDisabled();
    const channel = $("[data-cbcl-channel-status]");
    if (channel) channel.textContent = credentialV2Stage === "relay"
      ? "Application profile checked; secure connection follows your approval"
      : credentialV2Stage.startsWith("recovery")
        ? "Checking the saved link with the application"
        : "Secure connection verified";
    const unlockSlot = $("[data-pairing-consent-unlock]");
    if (unlockSlot && passcodeField) {
      unlockSlot.append(passcodeField);
      passcodeField.hidden = !capability.productionClaimant ||
        (flow === "single" && !credentialV2Stage.startsWith("recovery") ? credentialV2Stage !== "single-unlock" : credentialV2Stage === "relay" || credentialV2Stage === "comparison");
    }
    declineButton.textContent = decline;
    declineButton.hidden = false;
    declineButton.disabled = false;
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
    credentialV2Stage = flow === "single" ? "single-unlock" : "intent";
    const fields = [
      { label: "Authenticated application", value: intent.applicationId },
      { label: "HTTPS origin", value: intent.httpsOrigin },
      { label: "Blind relay", value: intent.relayOrigin },
      { label: "Installation device", value: intent.deviceDid },
      { label: "Account principal", value: intent.accountPrincipalDigest },
      { label: "Contact permission", value: intent.tofuState === "ceremony-gesture" ? "This ceremony only" : intent.tofuState === "trusted-pair" ? "Previously approved exact application–relay pair" : "New exact application–relay approval" },
      { label: "Transition", value: intent.transition?.kind ?? "none" },
      ...intent.permissions.map((value) => ({ label: "Permission", value })),
    ];
    if (intent.transition?.kind === "path-a-to-b") {
      fields.push({ label: "Existing chat handle", value: intent.transition.legacyHandle });
      for (const room of intent.transition.migrationRooms) {
        fields.push({ label: "Room to migrate", value: room });
      }
    }
    intentFields = fields;
    paintConsent({
      title: "Review the exact request",
      authority: "CPace and both Finished values authenticated this request under the live application profile.",
      application: intent.applicationId,
      action: flow === "single" ? "Unlock to show your local identity for this request." : "Approval permits a pure account-identity preview; it does not issue or publish anything.",
      fields,
      approve: flow === "single" ? "Unlock to show identity" : "Preview identity",
    });
  }

  const linkWording = "Share this identity with this application and link this device if the desktop comparison succeeds.";
  function actionDisabled() {
    return decisionPending || ["comparison", "single-preview", "single-link", "single-comparison", "single-finish", "cancelling"].includes(credentialV2Stage);
  }
  function showSinglePreview(review) {
    credentialV2Stage = "single-preview";
    paintConsent({
      title: "Review and link this device",
      authority: "Your identity is shown locally. Nothing has been shared with the application.",
      application: review.applicationId,
      action: linkWording,
      fields: [...intentFields,
        { label: "Account issuer DID", value: review.previewIssuerDid },
        { label: "Comparison fingerprint", value: review.previewFingerprint.hex, lifehash: review.previewFingerprint.lifehash },
        { label: "Recognition aid", value: review.previewFingerprint.label }],
      approve: "Link", decline: "Cancel linking",
    });
    idle();
  }
  async function revokeNative(tag = attemptTag, mode = flow) {
    if (mode === "single") {
      if (tag) await invoke("cbcl_v2_cancel_link", { request: { attemptTag: tag } }).catch(() => {});
    } else await invoke("cbcl_v2_cancel").catch(() => {});
  }
  async function inspectSingleCompletion(applicationId) {
    const [recoveries, installed] = await Promise.allSettled([
      invoke("cbcl_v2_pending_recoveries"),
      invoke("cbcl_v2_installed_links"),
    ]);
    return {
      recoverable: recoveries.status === "fulfilled" &&
        Array.isArray(recoveries.value) && recoveries.value.includes(applicationId),
      installed: installed.status === "fulfilled" && Array.isArray(installed.value) &&
        installed.value.some(link => link?.applicationId === applicationId),
    };
  }
  function showUncertainSingleCompletion(state) {
    const resultMessage = state.recoverable
      ? "A sealed completion checkpoint is retained. After the relay window closes, use the pending link in Applications to check the signed final status with fresh presence."
      : state.installed
        ? "A local installed link is present, but this command did not return verified success. Check that link in Applications before taking another action."
        : "Selfsame could not establish the final completion state. Check Applications for an installed link or pending recovery before starting another invitation.";
    showResult(
      "failed",
      "Link completion needs checking",
      resultMessage,
      "Authenticated linking work may already have occurred, and installation status remains unresolved until checked.",
    );
  }
  async function decideSingle(approve) {
    if (!approve) { await cancel(); return; }
    if (decisionPending || !["single-unlock", "single-ready"].includes(credentialV2Stage)) return;
    const epoch = attemptEpoch;
    const tag = attemptTag;
    const applicationId = attemptApplication;
    const request = { attemptTag: tag };
    decisionPending = true;
    $('[data-action="approve-cbcl-pairing"]').disabled = true;
    idle();
    try {
      if (credentialV2Stage === "single-unlock") {
        const input = $("#pairing-passcode");
        let result;
        $("[data-cbcl-channel-status]").textContent = "Confirm it's you on your device to show your identity.";
        try {
          result = await invoke("cbcl_v2_unlock_preview", { request: { ...request, passcode: input?.value ?? "" } });
        } finally {
          if (input) input.value = "";
        }
        if (epoch !== attemptEpoch) return;
        showSinglePreview(result.review);
        await previewRendered();
        if (epoch !== attemptEpoch) return;
        await invoke("cbcl_v2_preview_rendered", { request });
        if (epoch !== attemptEpoch) return;
        credentialV2Stage = "single-ready";
        $("[data-cbcl-channel-status]").textContent = "Review is ready. Select Link when you are ready to share this identity.";
        // Preserve the review and move keyboard focus to its now-available action.
        $('[data-action="approve-cbcl-pairing"]').disabled = false;
        $('[data-action="approve-cbcl-pairing"]').focus();
        return;
      }
      credentialV2Stage = "single-link";
      $("[data-cbcl-authority]").textContent = "Sharing the reviewed identity for this request.";
      $("[data-cbcl-channel-status]").textContent = "Waiting for the desktop comparison. Cancel remains available.";
      await invoke("cbcl_v2_link", { request });
      if (epoch !== attemptEpoch) return;
      credentialV2Stage = "single-comparison";
      await invoke("cbcl_v2_continue_link", { request });
      if (epoch !== attemptEpoch) return;
      credentialV2Stage = "single-finish";
      $("[data-cbcl-channel-status]").textContent = "Verifying the signed hub receipt and live reciprocal account binding.";
      const result = await invoke("cbcl_v2_finish_link", { request });
      if (epoch !== attemptEpoch) return;
      if (result.outcome !== "installed") throw new Error("PairingReceiptRefused");
      credentialV2Stage = "idle";
      attemptTag = null;
      attemptApplication = null;
      showResult("accepted", "Application connected", "The signed hub receipt and live reciprocal account binding were verified before the grant was installed.", "The invitation permitted contact for this ceremony only.");
    } catch (error) {
      if (epoch !== attemptEpoch) return;
      const afterLink = ["single-link", "single-comparison", "single-finish"].includes(credentialV2Stage);
      await revokeNative(tag, "single");
      if (epoch !== attemptEpoch) return;
      const completion = afterLink
        ? await inspectSingleCompletion(applicationId)
        : null;
      if (epoch !== attemptEpoch) return;
      credentialV2Stage = "idle";
      attemptTag = null;
      attemptApplication = null;
      if (afterLink) {
        showUncertainSingleCompletion(completion);
      } else {
        restoreEntryUnlock();
        show("pairing-enter");
        fail("pairing", startFailureText(message(error)));
      }
    } finally {
      if (epoch === attemptEpoch) {
        decisionPending = false;
        $('[data-action="approve-cbcl-pairing"]').disabled = actionDisabled();
        idle();
      }
    }
  }

  function showFinalReview(review) {
    credentialV2Stage = "final";
    paintConsent({
      title: "Approve account linking?",
      authority: "This is the second and final decision. Only approval here permits identity publication and one account grant.",
      application: review.applicationId,
      action: review.comparison === "bound-same-did"
        ? "The application’s existing reciprocal binding matches this wallet identity."
        : "You confirmed that this identity matches on your desktop.",
      fields: [
        ...intentFields,
        { label: "Account issuer DID", value: review.previewIssuerDid },
        { label: "Comparison fingerprint", value: review.previewFingerprint.hex, lifehash: review.previewFingerprint.lifehash },
        { label: "Recognition aid", value: review.previewFingerprint.label },
      ],
      approve: "Approve and link",
    });
  }

  function showPreview(review) {
    credentialV2Stage = "comparison";
    paintConsent({
      title: "Compare with your desktop",
      authority: "Check that this fingerprint matches the one shown in the application.",
      application: review.applicationId,
      action: "Confirm the match on your desktop to continue here.",
      fields: [
        { label: "Comparison fingerprint", value: review.previewFingerprint.hex, lifehash: review.previewFingerprint.lifehash },
        { label: "Account issuer DID", value: review.previewIssuerDid },
        { label: "Recognition aid", value: review.previewFingerprint.label },
        ...intentFields,
      ],
      approve: "Waiting for comparison…",
      decline: "Cancel linking",
    });
    // Let the preview become visible before the native continuation discloses it.
    idle();
  }

  const previewRendered = () => new Promise(resolve =>
    requestAnimationFrame(() => requestAnimationFrame(resolve)));

  function showRecovery(applicationId) {
    flow = "legacy";
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

  async function advanceRelay(approve, epoch = attemptEpoch) {
    $("[data-cbcl-status]").textContent = approve ? "Connecting to the application…" : "Declining the connection…";
    show("pairing-wait");
    idle();
    const result = await invoke("cbcl_v2_relay_decide", { approve });
    if (epoch !== attemptEpoch) return;
    if (result.outcome === "declined") {
      credentialV2Stage = "idle";
      showResult("declined", "Relay rejected", "No relay socket was opened and no credential was shared.", "The invitation was not allowed to choose relay trust for you.");
      return;
    }
    $("[data-cbcl-relay]").textContent = result.intent.relayOrigin;
    showIntent(result.intent);
  }

  async function decide(approve) {
    if (flow === "single" && !credentialV2Stage.startsWith("recovery")) return decideSingle(approve);
    if (credentialV2Stage === "comparison") {
      if (!approve) await cancel();
      return;
    }
    if (decisionPending) return;
    const epoch = attemptEpoch;
    decisionPending = true;
    $('[data-action="approve-cbcl-pairing"]').disabled = true;
    // Keep the Cancel control reachable while native work is in flight.
    idle();
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
        if (epoch !== attemptEpoch) return;
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
        await advanceRelay(approve, epoch);
        return;
      }
      const passcodeInput = $("#pairing-passcode");
      const passcode = approve ? (passcodeInput?.value ?? "") : null;
      if (credentialV2Stage === "intent") {
        const result = await invoke("cbcl_v2_preliminary_decide", { approve, passcode });
        if (epoch !== attemptEpoch) return;
        if (result.outcome === "declined") {
          credentialV2Stage = "idle";
          if (passcodeInput) passcodeInput.value = "";
          showResult("declined", "Request declined", "No identity was issued, published, or shared.", "The authenticated request ended before any identity effect.");
        } else {
          showPreview(result.finalReview);
          await previewRendered();
          if (epoch !== attemptEpoch) return;
          const review = await invoke("cbcl_v2_compare");
          if (epoch !== attemptEpoch) return;
          showFinalReview(review);
        }
        return;
      }
      if (credentialV2Stage === "final") {
        const result = await invoke("cbcl_v2_final_decide", { approve, passcode });
        if (epoch !== attemptEpoch) return;
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
        if (epoch !== attemptEpoch) return;
        if (result.outcome !== "installed") throw new Error("credential/v2 installation was refused");
        credentialV2Stage = "idle";
        if (passcodeInput) passcodeInput.value = "";
        showResult("accepted", "Application connected", "The signed hub receipt and live reciprocal account binding were verified before the grant was installed.", "The relay learned only opaque protocol frames; trust is scoped to this application–relay pair.");
      }
    } catch (error) {
      if (epoch !== attemptEpoch) return;
      const token = message(error);
      if (credentialV2Stage === "finish") {
        show("pairing-consent");
        $('[data-action="approve-cbcl-pairing"]').textContent = "Retry final verification";
        $('[data-action="decline-cbcl-pairing"]').hidden = true;
        const detail = token === "PairingRelayTimedOut"
          ? "The relay stayed connected but the final receipt did not arrive before the local wait deadline. The durable pending link is safe to retry."
          : `The final verification did not complete (${token}). The durable pending link is safe to retry.`;
        fail("pairing-consent", detail);
      } else {
        await invoke("cbcl_v2_cancel").catch(() => {});
        if (epoch !== attemptEpoch) return;
        credentialV2Stage = "idle";
        restoreEntryUnlock();
        show("pairing-enter");
        fail("pairing", startFailureText(token));
      }
    } finally {
      if (epoch === attemptEpoch) {
        decisionPending = false;
        $('[data-action="approve-cbcl-pairing"]').disabled = credentialV2Stage === "comparison";
        idle();
      }
    }
  }

  async function cancel(navigate = true) {
    const tag = attemptTag;
    const mode = flow;
    const wasScanning = credentialV2Stage === "scanning";
    const epoch = ++attemptEpoch;
    attemptTag = null;
    attemptApplication = null;
    credentialV2Stage = "cancelling";
    clearTransferInputs();
    setCameraVisible(false);
    decisionPending = true;
    $('[data-action="approve-cbcl-pairing"]').disabled = true;
    $('[data-action="decline-cbcl-pairing"]').disabled = true;
    intentFields = [];
    const passcode = $("#pairing-passcode");
    if (passcode) passcode.value = "";
    idle();
    try {
      await Promise.allSettled([
        revokeNative(tag, mode),
        wasScanning ? Promise.resolve().then(() => window.__TAURI__?.barcodeScanner?.cancel?.()) : Promise.resolve(),
      ]);
    }
    finally {
      if (epoch !== attemptEpoch) return;
      credentialV2Stage = "idle";
      decisionPending = false;
      if (navigate) show("applications");
    }
  }

  function leaving(name) {
    if (!["pairing-enter", "pairing-wait", "pairing-consent"].includes(name)) { clearTransferInputs(); onInput(); }
    if (!["idle", "cancelling"].includes(credentialV2Stage) &&
        !["pairing-enter", "pairing-wait", "pairing-consent"].includes(name)) {
      void cancel(false);
    }
  }
  function interruptPairing() {
    if (["idle", "cancelling"].includes(credentialV2Stage)) return;
    // Fence late native responses immediately, then replace the stale consent
    // even if native cancellation is still waiting for a device prompt.
    void cancel(false);
    showResult("failed", "Pairing interrupted",
      "Selfsame stopped this pairing when the app left the foreground. Return to Applications to check the link status before starting a fresh invitation.",
      "An interrupted request cannot resume from this review.");
  }
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      clearTransferInputs();
      onInput();
      if (!applicationLifecycle) interruptPairing();
    }
  });
  window.addEventListener("pagehide", () => {
    clearTransferInputs();
    interruptPairing();
  });

  function setCameraVisible(visible) {
    document.body.classList.toggle("scanning", visible);
    document.body.classList.toggle("pairing-scanning", visible);
    const cameraView = $("[data-pairing-camera]");
    if (cameraView) cameraView.hidden = !visible;
    if (visible) $("[data-action='stop-pairing-camera']")?.focus();
  }

  async function stopCamera(typeInstead = false) {
    if (credentialV2Stage !== "scanning") return;
    const epoch = ++attemptEpoch;
    credentialV2Stage = "cancelling";
    setCameraVisible(false);
    try { await window.__TAURI__?.barcodeScanner?.cancel?.(); }
    catch { /* The opaque entry screen remains usable after a camera error. */ }
    finally {
      if (epoch === attemptEpoch) {
        credentialV2Stage = "idle";
        onInput();
        $(typeInstead
          ? entryMode === "manual" ? "#pairing-manual-bootstrap" : "#pairing-input"
          : entryMode === "manual" ? "[data-action='scan-cbcl-manual']" : "[data-action='scan-cbcl-pairing']")?.focus();
      }
    }
  }

  // The confidential QR payload IS the paste payload. Scan and paste recognise
  // identical input and everything after this line is the one ordinary
  // `start` path. The camera choreography mirrors the linking screen's:
  // `scan` checks the permission and throws rather than requesting it, so the
  // asking is this caller's job; `windowed: true` renders the preview beneath
  // the webview, so the page must get out of its way for the duration.
  async function scan(manual = false) {
    await capabilityReady;
    if (credentialV2Stage !== "idle" || entryMode !== (manual ? "manual" : "full")) return;
    const epoch = ++attemptEpoch;
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
    credentialV2Stage = "scanning";
    onInput();
    try {
      let access = await camera.checkPermissions();
      if (epoch !== attemptEpoch) return;
      if (access === "denied") {
        say("Camera access is off for Selfsame — turn it on in Settings, or paste the invitation instead.");
        return;
      }
      if (access !== "granted") {
        access = await camera.requestPermissions();
        if (epoch !== attemptEpoch) return;
        if (access !== "granted") {
          say("Camera access was declined. You can paste the invitation instead.");
          return;
        }
      }
      setCameraVisible(true);
      let scanned;
      try {
        scanned = await camera.scan({ formats: ["QRCode"], windowed: true });
      } finally {
        if (epoch === attemptEpoch) setCameraVisible(false);
      }
      if (epoch !== attemptEpoch) return;
      say("");
      credentialV2Stage = "idle";
      const input = $(manual ? "#pairing-manual-bootstrap" : "#pairing-input");
      if (input) input.value = scanned.content;
      onInput();
      if (manual) $("#pairing-manual-words").focus();
      else await start(scanned.content);
    } catch (error) {
      if (epoch !== attemptEpoch) return;
      const reason = String(error?.message ?? error ?? "unknown");
      say(
        /cancel/i.test(reason) ? "Camera scanning was cancelled. You can paste the invitation instead."
          : /denied|permission|not allowed/i.test(reason)
          ? "Camera access is off for Selfsame — turn it on in Settings, " +
              "or paste the invitation instead."
          : "The camera isn’t available. Paste the invitation instead.",
      );
    } finally {
      if (epoch === attemptEpoch && credentialV2Stage === "scanning") {
        credentialV2Stage = "idle";
        onInput();
      }
    }
  }

  function restoreEntryUnlock() {
    const unlockSlot = $("[data-pairing-entry-unlock]");
    if (unlockSlot && passcodeField) {
      unlockSlot.append(passcodeField);
      passcodeField.hidden = flow === "single" || !capability.productionClaimant;
    }
  }

  function forget() {
    if (credentialV2Stage === "scanning") void Promise.resolve().then(() => window.__TAURI__?.barcodeScanner?.cancel?.()).catch(() => {});
    if (credentialV2Stage !== "idle") void revokeNative();
    attemptTag = null;
    attemptApplication = null;
    flow = "single";
    ++attemptEpoch;
    decisionPending = false;
    intentFields = [];
    restoreEntryUnlock();
    entryMode = "full";
    clearTransferInputs();
    setCameraVisible(false);
    $("[data-pairing-manual]").open = false;
    $("[data-pairing-complete]").hidden = false;
    $("[data-action='scan-cbcl-pairing']").hidden = !window.__TAURI__?.barcodeScanner;
    const legacy = $("[data-pairing-legacy]");
    if (legacy) legacy.open = false;
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
    const epoch = attemptEpoch;
    if (credentialV2Stage !== "idle") return;
    const installedRefresh = refreshInstalledLinks().catch(() => {});
    const applications = await invoke("cbcl_v2_pending_recoveries");
    await installedRefresh;
    if (epoch !== attemptEpoch) return;
    if (Array.isArray(applications) && applications.length > 0) {
      showRecovery(applications[0]);
    }
  }

  async function refreshInstalledLinks() {
    const list = $("[data-cbcl-v2-links]");
    if (!list) return;
    const [links, pendingLinks] = await Promise.all([
      invoke("cbcl_v2_installed_links"),
      invoke("cbcl_v2_pending_links"),
    ]);
    list.replaceChildren();
    const rows = Array.isArray(links) ? links : [];
    const interrupted = Array.isArray(pendingLinks) ? pendingLinks : [];
    d.renderInstalledSummary?.(rows);
    $("[data-cbcl-v2-links-empty]").hidden = rows.length + interrupted.length > 0;
    $("[data-applications-empty]").hidden =
      rows.length + interrupted.length > 0 || $("[data-applications]").children.length > 0;
    for (const link of interrupted) {
      const item = document.createElement("li");
      const button = document.createElement("button");
      button.className = "application";
      button.dataset.cbclV2PendingLink = "";
      const mark = document.createElement("div");
      mark.className = "mark";
      mark.setAttribute("aria-hidden", "true");
      const body = document.createElement("div");
      body.className = "application__body";
      const application = document.createElement("span");
      application.className = "application__name";
      application.textContent = `Interrupted link — ${link.applicationId}`;
      const relay = document.createElement("span");
      relay.className = "application__meta";
      relay.textContent = link.relayOrigin;
      body.append(application, relay);
      button.append(mark, body);
      button.addEventListener("click", () => openPendingLink(link));
      item.append(button);
      list.append(item);
    }
    for (const link of rows) {
      const item = document.createElement("li");
      const button = document.createElement("button");
      button.className = "application";
      button.dataset.cbclV2Link = "";
      const mark = document.createElement("div");
      mark.className = "mark";
      mark.setAttribute("aria-hidden", "true");
      const body = document.createElement("div");
      body.className = "application__body";
      const application = document.createElement("span");
      application.className = "application__name";
      application.textContent = link.applicationId;
      const account = document.createElement("span");
      account.className = "application__meta";
      const count = link.devices?.length;
      account.textContent = count == null ? link.account
        : `${link.account} · ${count} device${count === 1 ? "" : "s"}`;
      body.append(application, account);
      button.append(mark, body);
      button.addEventListener("click", () => openInstalledLink(link));
      item.append(button);
      list.append(item);
    }
  }

  function openInstalledLink(link) {
    installedLink = link;
    pendingLink = null;
    const devices = $("[data-cbcl-v2-link-devices]");
    devices.replaceChildren();
    for (const [index, device] of (link.devices ?? []).entries()) {
      const row = document.createElement("li");
      row.className = "evidence__row";
      const name = document.createElement("p");
      name.className = "evidence__key";
      name.textContent = `Device ${index + 1}`;
      const identifier = document.createElement("p");
      identifier.className = "evidence__val evidence__val--mono";
      identifier.textContent = device.installationDeviceDid;
      row.append(name, identifier);
      devices.append(row);
    }
    $("[data-cbcl-v2-link-application]").textContent = link.applicationId;
    $("[data-cbcl-v2-link-account]").textContent = link.account;
    $("[data-cbcl-v2-link-relay]").textContent = link.relayOrigin;
    $("[data-cbcl-v2-link-status]").textContent =
      "Verify current standing before using this installed capability.";
    $('[data-action="accept-cbcl-v2-rotation"]').hidden = true;
    show("pairing-link");
  }

  function openPendingLink(link) {
    pendingLink = link;
    installedLink = null;
    $("[data-cbcl-v2-pending-application]").textContent = link.applicationId;
    $("[data-cbcl-v2-pending-relay]").textContent = link.relayOrigin;
    $("[data-cbcl-v2-pending-phase]").textContent = link.phase;
    show("pairing-pending-link");
  }

  async function verifyInstalledLink(approveRotation = false) {
    if (!installedLink) return;
    busy("Verifying the installed grant and current application standing…");
    try {
      const result = await invoke("cbcl_v2_reload_verify", {
        applicationId: installedLink.applicationId,
        observedAccount: installedLink.account,
        approveRotation,
      });
      const status = $("[data-cbcl-v2-link-status]");
      const accept = $('[data-action="accept-cbcl-v2-rotation"]');
      accept.hidden = true;
      if (result.outcome === "usable" || result.outcome === "profile-refreshed") {
        status.textContent = result.outcome === "profile-refreshed"
          ? "The grant and current profile verified. The profile digest was safely refreshed."
          : "The grant, current profile, authority, issuer, reciprocal account, revocation state, and hub status verified.";
      } else if (result.outcome === "authority-rotation" || result.outcome === "issuer-rotation") {
        status.textContent = result.outcome === "authority-rotation"
          ? "The application authority changed. Review this unexpected rotation before continuing."
          : "The account issuer changed. Review this unexpected rotation before continuing.";
        accept.hidden = false;
      } else if (result.outcome === "fresh-pairing-required") {
        status.textContent = "This rotation requires unlinking locally and completing a fresh pairing ceremony.";
      } else if (result.outcome === "account-device-handle-change-refused") {
        status.textContent = "The installed account handle changed. Selfsame refused capability and sent no enrollment or pairing frame.";
      } else if (result.outcome === "hub-deleted") {
        status.textContent = "The hub deleted this link. Unlink locally, then complete a fresh pairing ceremony.";
      } else if (result.outcome === "unavailable") {
        status.textContent = "The application hub or resolver is unavailable. The installed record was retained and no capability was granted.";
      } else {
        status.textContent = "The installed grant is revoked or no longer verifies. The record was retained and no capability was granted.";
      }
    } catch (error) {
      fail("cbcl-v2-link", `The installed link could not be verified (${message(error)}).`);
    } finally {
      idle();
    }
  }

  function beginInstalledUnlink() {
    if (!installedLink) return;
    $("[data-cbcl-v2-unlink-application]").textContent = installedLink.applicationId;
    const passcode = $("#cbcl-v2-unlink-passcode");
    if (passcode) passcode.value = "";
    show("pairing-link-unlink");
  }

  function beginPendingUnlink() {
    if (!pendingLink) return;
    $("[data-cbcl-v2-unlink-application]").textContent = pendingLink.applicationId;
    const passcode = $("#cbcl-v2-unlink-passcode");
    if (passcode) passcode.value = "";
    show("pairing-link-unlink");
  }

  async function unlinkLocal() {
    const localLink = installedLink ?? pendingLink;
    if (!localLink) return;
    const passcode = $("#cbcl-v2-unlink-passcode")?.value ?? "";
    busy("Removing this local application link…");
    try {
      await invoke("cbcl_v2_unlink", {
        applicationId: localLink.applicationId,
        confirmation: true,
        passcode,
      });
      installedLink = null;
      pendingLink = null;
      if ($("#cbcl-v2-unlink-passcode")) $("#cbcl-v2-unlink-passcode").value = "";
      await refreshInstalledLinks();
      show("applications");
    } catch (error) {
      fail("cbcl-v2-unlink", `This local link was not removed (${message(error)}).`);
    } finally {
      idle();
    }
  }

  Object.assign(actions, {
    "to-pairing": () => {
      forget();
      onInput();
      show("pairing-enter");
    },
    "start-cbcl-pairing": start,
    "scan-cbcl-pairing": () => scan(false),
    "stop-pairing-camera": () => stopCamera(false),
    "type-pairing-invitation": () => stopCamera(true),
    "scan-cbcl-manual": () => scan(true),
    "approve-cbcl-pairing": () => decide(true),
    "decline-cbcl-pairing": () => decide(false),
    "cancel-cbcl-pairing": cancel,
    "finish-cbcl-pairing": async () => {
      await refreshInstalledLinks();
      show("applications");
    },
    "verify-cbcl-v2-link": () => verifyInstalledLink(false),
    "accept-cbcl-v2-rotation": () => verifyInstalledLink(true),
    "to-cbcl-v2-unlink": beginInstalledUnlink,
    "to-cbcl-v2-pending-unlink": beginPendingUnlink,
    "back-to-cbcl-v2-link": () => pendingLink
      ? openPendingLink(pendingLink)
      : installedLink
        ? openInstalledLink(installedLink)
        : show("applications"),
    "confirm-cbcl-v2-unlink": unlinkLocal,
  });

  const input = $("#pairing-input");
  if (input) input.addEventListener("input", onInput);
  for (const mode of ["manual", "legacy"]) {
    const panel = $(`[data-pairing-${mode}]`);
    panel?.addEventListener("toggle", () => {
      if (credentialV2Stage !== "idle") { panel.open = entryMode === mode; return; }
      if (panel.open) selectEntryMode(mode);
      else if (entryMode === mode) selectEntryMode("full");
    });
  }
  for (const selector of ["#pairing-manual-bootstrap", "#pairing-manual-words"]) {
    $(selector)?.addEventListener("input", onInput);
  }
  const presence = $("#pairing-presence-code");
  if (presence) presence.addEventListener("input", onInput);
  // Desktop: the pasted route is the route. Hide the dead camera affordance
  // rather than offering a button that can only apologise.
  if (!window.__TAURI__?.barcodeScanner) {
    const scanButton = $('[data-action="scan-cbcl-pairing"]');
    if (scanButton) scanButton.hidden = true;
    $("[data-action='scan-cbcl-manual']").hidden = true;
  }
  return { forget, resumePending, refreshInstalledLinks, leaving };
}
