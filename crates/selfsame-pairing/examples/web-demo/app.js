(() => {
  "use strict";

  const role = document.documentElement.dataset.role;
  let capability = document.querySelector('meta[name="selfsame-bootstrap"]').content;
  let ceremonyId = null;
  let version = 0;
  let pollTimer = null;
  let lastStatus = null;
  let resetRecoveryAvailable = false;
  const byId = (id) => document.getElementById(id);
  const status = byId("status");
  const terminalStatuses = ["accepted", "declined", "verifier-refusal", "protocol-failure"];

  function announce(message) {
    status.textContent = message;
  }

  async function api(path, body, method = "POST") {
    const headers = {
      "X-Selfsame-Capability": capability,
      "X-Selfsame-Role": role,
    };
    if (ceremonyId) headers["X-Selfsame-Ceremony"] = ceremonyId;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const response = await fetch(path, {
      method,
      headers,
      credentials: "same-origin",
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const value = await response.json();
    if (!response.ok) throw new Error(value.error || "request-failed");
    return value;
  }

  function pending(button, message) {
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    announce(message);
  }

  function render(state) {
    const previousStatus = lastStatus;
    lastStatus = state.status;
    version = state.version;
    byId("relay-frames").textContent = state.relay.opaque_frames;
    byId("relay-bytes").textContent = state.relay.aggregate_bytes;
    const relayMailboxes = byId("relay-mailboxes");
    if (relayMailboxes) relayMailboxes.textContent = state.relay.retained_mailboxes;
    const terminal = terminalStatuses.includes(state.status);
    byId("reset").disabled = !(terminal || resetRecoveryAvailable);
    if (terminal && role === "application") {
      byId("start").disabled = true;
      byId("copy").disabled = true;
    }

    renderRail(state);
    if (role === "application") renderApplication(state, previousStatus);
    else renderWallet(state);

    if (terminal && previousStatus !== state.status) {
      clearInterval(pollTimer);
      const titles = {
        accepted: "Credential accepted",
        declined: "Transfer declined",
        "verifier-refusal": "Verifier refusal",
        "protocol-failure": "Protocol failure",
      };
      byId("result-title").textContent = titles[state.status];
      byId("result-copy").textContent = state.result;
      byId("verifier-summary").textContent = state.verification.accepted_steps === 13
        ? "Selfsame authorization: 13 of 13 checks passed."
        : "No accepted credential was exposed.";
      byId("result-panel").dataset.state = state.status;
      byId("result-panel").focus();
      announce(state.result);
    }
  }

  function renderRail(state) {
    const terminal = terminalStatuses.includes(state.status);
    const stage = {
      invitation: state.version >= 1 ? "Complete" : "Waiting",
      cpace: state.version >= 2 ? "Complete" : "Waiting",
      finished: state.version >= 2 ? "Complete" : "Waiting",
      roles: state.version >= 2 ? "Complete" : "Waiting",
      intent: state.version >= 2 ? "Complete" : "Waiting",
      consent: terminal ? "Complete" : "Waiting",
      credential: state.status === "accepted" ? "Complete" : state.status === "declined" ? "Skipped" : terminal ? "Refused" : "Waiting",
      acceptance: state.status === "accepted" ? "Complete" : state.status === "declined" ? "Skipped" : terminal ? "Refused" : "Waiting",
    };
    document.querySelectorAll("[data-gate]").forEach((item) => {
      const statusText = stage[item.dataset.gate];
      item.classList.toggle("complete", statusText === "Complete");
      item.dataset.state = statusText.toLowerCase();
      item.querySelector("em").textContent = statusText;
    });
  }

  function renderApplication(state, previousStatus) {
    if (state.status === "awaiting-decision" && previousStatus !== state.status) {
      byId("invitation").value = "";
      byId("invitation").disabled = true;
      byId("copy").disabled = true;
      byId("result-title").textContent = "Awaiting wallet decision";
      byId("result-copy").textContent = "The secure channel is ready. No credential has moved.";
      announce("Wallet joined. Awaiting an explicit decision.");
    }
  }

  function renderWallet(state) {
    if (state.status === "awaiting-decision" && state.intent) {
      const panel = byId("consent-panel");
      const newlyRevealed = panel.hidden;
      panel.hidden = false;
      if (newlyRevealed) {
        byId("authority-summary").textContent = state.intent.authority_summary;
        const fields = byId("intent-fields");
        fields.replaceChildren();
        state.intent.fields.forEach((field) => {
          const row = document.createElement("div");
          const term = document.createElement("dt");
          const value = document.createElement("dd");
          term.textContent = field.label;
          value.textContent = field.value;
          row.append(term, value);
          fields.append(row);
        });
        byId("invitation").value = "";
        byId("invitation").disabled = true;
        byId("join").disabled = true;
        byId("join").removeAttribute("aria-busy");
        panel.focus();
        announce("Secure ceremony established. Review the recognized request.");
      }
    }
    if (terminalStatuses.includes(state.status)) {
      byId("approve").disabled = true;
      byId("decline").disabled = true;
    }
  }

  function beginPolling() {
    clearInterval(pollTimer);
    pollTimer = setInterval(async () => {
      try { render(await api("/api/state", undefined, "GET")); }
      catch (error) { clearInterval(pollTimer); announce(`State check refused: ${error.message}`); }
    }, 350);
  }

  if (role === "application") {
    byId("start").addEventListener("click", async () => {
      const button = byId("start");
      pending(button, "Creating a single-use invitation…");
      try {
        const value = await api("/api/start", {});
        capability = value.capability;
        ceremonyId = value.ceremony_id;
        byId("invitation").value = value.invitation;
        byId("invitation-panel").hidden = false;
        byId("copy").focus();
        render(value.state);
        announce("Invitation created. Copy it to the wallet page.");
        beginPolling();
      } catch (error) {
        button.disabled = false;
        announce(`Invitation refused: ${error.message}`);
      } finally { button.removeAttribute("aria-busy"); }
    });
    byId("copy").addEventListener("click", async () => {
      const button = byId("copy");
      pending(button, "Copying invitation…");
      try {
        await navigator.clipboard.writeText(byId("invitation").value);
        announce("Invitation copied.");
      } catch (error) {
        announce(`Copy refused: ${error.message}`);
      } finally {
        button.disabled = false;
        button.removeAttribute("aria-busy");
      }
    });
  } else {
    byId("join").addEventListener("click", async () => {
      const button = byId("join");
      pending(button, "Establishing the secure ceremony…");
      try {
        const value = await api("/api/claim", { invitation: byId("invitation").value.trim() });
        capability = value.capability;
        ceremonyId = value.ceremony_id;
        render(value.state);
        beginPolling();
      } catch (error) {
        button.disabled = false;
        button.removeAttribute("aria-busy");
        if (error.message === "invalid-invitation") {
          byId("result-title").textContent = "Invitation mismatch";
          byId("result-copy").textContent = "This carrier does not match an available ceremony.";
          byId("verifier-summary").textContent = "No credential was exposed.";
          byId("result-panel").dataset.state = "invitation-mismatch";
          byId("result-panel").focus();
        }
        announce(`Join refused: ${error.message}`);
      }
    });
    for (const action of ["approve", "decline"]) {
      byId(action).addEventListener("click", async () => {
        pending(byId(action), action === "approve" ? "Applying explicit approval…" : "Recording decline…");
        byId(action === "approve" ? "decline" : "approve").disabled = true;
        try {
          const value = await api(`/api/${action}`, { version });
          resetRecoveryAvailable = false;
          render(value);
        }
        catch (error) {
          byId("approve").disabled = false;
          byId("decline").disabled = false;
          resetRecoveryAvailable = true;
          byId("reset").disabled = false;
          byId(action).removeAttribute("aria-busy");
          announce(`Decision refused: ${error.message}. Retry, or reset to start a fresh ceremony.`);
        }
      });
    }
  }

  byId("reset").addEventListener("click", async () => {
    pending(byId("reset"), "Resetting ceremony…");
    try {
      const value = await api("/api/reset", { version });
      capability = value.capability;
      ceremonyId = null;
      location.reload();
    } catch (error) {
      byId("reset").disabled = false;
      byId("reset").removeAttribute("aria-busy");
      announce(`Reset refused: ${error.message}. Retry reset or reload this endpoint.`);
    }
  });
})();
