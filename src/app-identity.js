/**
 * The SPEC-004 surface — IMPL-004's thirteen screens.
 *
 * This file holds *no* security logic, for the same reason `app.js` does not:
 * every decision — is the application authenticated, is this grant revoked, is
 * that scope canonical — is made in `selfsame-app-identity` and reaches here as
 * a value or a closed error token.
 *
 * What lives here is sequence and presentation, and the sequence obligations
 * that are user-visible:
 *
 *   REQ-222  the application's own name never carries the decision — it is
 *            rendered under the untrusted treatment, beside the authenticated
 *            origin under the verified one
 *   REQ-230  the first-enrollment comparison offers no skip; there is no third
 *            control on that screen and no back button
 *   REQ-217  `scope-unavailable` offers no remedial control at all
 *   CON-222  the wallet checks the calling package against the CON-214
 *            binding, and shows the mismatch; it never renders the
 *            application's own `WalletUnavailable`
 *   CON-210  `remove-pending` claims nothing; only a verified closure moves it
 *   NFR-203  no screen renders an accountScopeId, and none is passed one
 *
 * # Why this is a separate module
 *
 * The boundary already exists everywhere else: `selfsame-core`,
 * `selfsame-app-identity` and `selfsame-app-identity-net` are separate crates
 * with a tested purity boundary between them. A frontend that interleaved both
 * specifications in one file would be the only place it stopped being visible.
 * See IMPL-004 ADR-601.
 *
 * Dependencies arrive as a parameter rather than an import, so the direction is
 * one-way — `app.js` → here, never back. A cycle would work in ES modules and
 * would make the boundary a convention rather than a fact.
 */

/** Everything this surface is holding between screens. Cleared with the app. */
const s = {
  /** The application currently open. */
  app: null,
  /** The grant row currently being acted on. */
  grant: null,
  /** Where a refusal should return to. */
  origin: null,
};

/**
 * Wire the SPEC-004 screens into the shell.
 *
 * @param {object} d  primitives owned by `app.js`
 */
export function initAppIdentity(d) {
  const { $, $$, show, invoke, fail, clearErrors, message, renderLifehash, since, actions } = d;

  // ── HP-3: the applications list ──────────────────────────────────────

  /** The one-line summary the home screen carries. */
  function renderSummary(apps) {
    const el = $("[data-applications-summary]");
    if (!el) return;
    el.textContent = apps.length
      ? `${apps.length} application${apps.length === 1 ? "" : "s"}, each with its own identity`
      : "None yet. They appear here as you sign into them.";
  }

  function renderApplications(apps) {
    const list = $("[data-applications]");
    list.textContent = "";
    $("[data-applications-empty]").hidden = apps.length > 0;

    for (const a of apps) {
      const li = document.createElement("li");
      const btn = document.createElement("button");
      btn.className = "application";

      const mark = document.createElement("div");
      mark.className = "mark";
      mark.setAttribute("aria-hidden", "true");

      const body = document.createElement("div");
      body.className = "application__body";

      // Untrusted text, inserted as text and never as markup. The list is a
      // list of *the person's own* applications, so the name is a label here
      // rather than evidence — but it is still the application's own words, and
      // `textContent` is what keeps that from mattering.
      const name = document.createElement("span");
      name.className = "application__name";
      name.textContent = a.display_name || a.application_id;

      // The alias, not the scope. NFR-203 keeps the scope off every screen, and
      // the way to be sure is never to hand it to one.
      const meta = document.createElement("span");
      meta.className = "application__meta";
      meta.textContent = a.username
        ? `${a.username} · ${a.devices.length} device${a.devices.length === 1 ? "" : "s"}`
        : `${a.devices.length} device${a.devices.length === 1 ? "" : "s"}`;

      body.append(name, meta);
      btn.append(mark, body);
      btn.addEventListener("click", () => openApplication(a));
      li.append(btn);
      list.append(li);
    }
  }

  // ── HP-3: one application ────────────────────────────────────────────

  async function openApplication(app) {
    s.app = app;

    // HP-7's cliff, reached the moment the application cannot name its own
    // account. REQ-217 forbids guessing and forbids prompting, so this is a
    // terminal screen rather than a retry.
    if (!app.account_alias) {
      // The application's own name. It is untrusted text and is inserted as
      // text, but naming it is what tells the person which row they tapped —
      // and the *alias* is the value that is legitimately missing here, not
      // the application.
      $("[data-scope-title]").textContent = app.display_name
        ? `${app.display_name} can't be opened.`
        : "This account can't be opened.";
      show("scope-unavailable");
      return;
    }

    $("[data-app-title]").textContent = app.display_name || "Application";
    $("[data-app-origin]").textContent = app.application_id;
    $("[data-app-alias]").textContent = app.account_alias;

    const hasName = !!app.username;
    $("[data-app-username-label]").hidden = !hasName;
    $("[data-app-username]").hidden = !hasName;
    if (hasName) $("[data-app-username]").textContent = `acct:${app.username}@…`;
    $("[data-app-username-cta]").textContent = hasName
      ? "Change your public username"
      : "Set a public username";

    renderGrants(app.devices ?? []);
    show("application");
  }

  function renderGrants(devices) {
    const list = $("[data-grants]");
    list.textContent = "";
    $("[data-grants-empty]").hidden = devices.length > 0;

    for (const g of devices) {
      const li = document.createElement("li");
      const btn = document.createElement("button");
      btn.className = "grant";

      const mark = document.createElement("div");
      mark.className = "mark";
      mark.setAttribute("aria-hidden", "true");

      const body = document.createElement("div");
      body.className = "grant__body";
      const name = document.createElement("span");
      name.className = "grant__name";
      name.textContent = g.label || "Unnamed device";
      const meta = document.createElement("span");
      meta.className = "grant__meta";
      // The grant ID is held so a removal can name what it revokes. It is not
      // rendered, and not put in an attribute either — a `data-grant-id` in the
      // DOM is rendered as far as anything reading the page is concerned.
      meta.textContent = g.is_this_device
        ? `this device · added ${since(g.added_at)}`
        : `added ${since(g.added_at)}`;

      body.append(name, meta);
      btn.append(mark, body);
      btn.addEventListener("click", () => openGrant(g));
      li.append(btn);
      list.append(li);
    }
  }

  function openGrant(grant) {
    s.grant = grant;
    $("[data-remove-title]").textContent = `Remove ${grant.label || "this device"}?`;
    $("[data-remove-account]").textContent = s.app?.display_name ?? "this account";
    show("remove-device");
  }

  // ── HP-3: the username (CON-212, NFR-201) ────────────────────────────

  async function toUsername() {
    clearErrors();
    $("#username-input").value = "";
    await previewUsername();
    show("username-set");
  }

  /**
   * The live preview.
   *
   * Built by the core, not here. A frontend that assembled `acct:name@host`
   * itself would be a second implementation of an identifier other parties
   * compare as text — which is the parser-differential hazard applied to a
   * string the person is about to publish.
   */
  async function previewUsername() {
    const local = $("#username-input").value.trim();
    const el = $("[data-username-preview]");
    if (!s.app) return;
    try {
      const out = await invoke("alias_preview", {
        homeDid: s.app.home_did,
        accountAuthority: authorityOf(s.app.account_alias),
        localpart: local || null,
      });
      el.textContent = out.usernameAlias ?? out.stableAlias;
    } catch {
      // A refusal while typing is not an error state — the person is mid-word.
      // The refusal that matters is the one on submit.
      el.textContent = "—";
    }
  }

  /** The authority half of an `acct:` URI, which the core already validated. */
  function authorityOf(acct) {
    return String(acct).split("@")[1] ?? "";
  }

  async function setUsername() {
    clearErrors();
    const local = $("#username-input").value.trim();
    if (!local) return fail("username", "Type a username first.");
    try {
      await invoke("alias_preview", {
        homeDid: s.app.home_did,
        accountAuthority: authorityOf(s.app.account_alias),
        localpart: local,
      });
      // Recognition is not reservation. CON-212 step 3 has the *authority*
      // validate, reserve, and publish the reciprocal binding, and only then
      // does the name exist — so the wallet asks it, and does not decide.
      //
      // An earlier version stopped at the line above and set `username`
      // locally, which put a name nobody held on the application screen under
      // the heading "Public username". That is the same defect as promising a
      // retry that does not run: a screen reporting a state the system is not
      // in. Nothing may set this but the authority's answer.
      await invoke("provision_username", {
        homeDid: s.app.home_did,
        accountAuthority: authorityOf(s.app.account_alias),
        localpart: local,
      });
      s.app = { ...s.app, username: local };
      await openApplication(s.app);
    } catch (e) {
      // One closed token, no detail. The person picks another and is never
      // asked to edit a URI.
      const token = message(e);
      if (token.includes("UsernameUnavailable")) return show("username-taken");
      // CON-204's failure, and HP-1 names it: the authority was unreachable, so
      // nothing was reserved. Shown as the token rather than as prose, because
      // the person needs to know it did *not* happen — not why.
      if (token.includes("AccountProvisioningFailed")) {
        return fail("username", "AccountProvisioningFailed — nothing was reserved.");
      }
      fail("username", "That username can't be used.");
    }
  }

  // ── HP-4a: first enrollment (CON-221, REQ-230) ───────────────────────

  async function toFingerprint() {
    if (!s.app) return;
    try {
      const fp = await invoke("home_fingerprint", { homeDid: s.app.home_did });
      $("[data-home-fp-hex]").textContent = fp.hex;
      $("[data-home-fp-label]").textContent = fp.label;
      // `renderLifehash` is the shell's own painter: it validates the value
      // against CON-102's grammar before touching the canvas and sizes it to
      // the 32x32 CON-101 fixes. Painting here by hand would be a second
      // implementation of both.
      renderLifehash($("[data-home-fp-lifehash]"), fp.lifehash);
      // Name the application, so "not your home key fingerprint" lands on a
      // specific thing rather than an abstraction.
      $("[data-fp-app]").textContent = s.app.display_name || "this application";
      show("fingerprint-compare");
    } catch (e) {
      fail("username", message(e));
    }
  }

  // ── HP-5: the caller check the wallet actually performs (CON-222) ────

  /**
   * Render `PlatformBindingMismatch`.
   *
   * This is the wallet's whole part in the same-device path. `WalletUnavailable`
   * and `UnverifiedWalletTarget` are the developer application's outcomes — its
   * adapter looked for a wallet and did not find or could not verify one — and
   * a wallet cannot render either without asserting its own absence.
   *
   * REQ-225: every result but `Dispatched` abandons the ceremony, so there is
   * nothing to retry here and nothing offered.
   */
  function showBindingMismatch(handoff) {
    $("[data-mismatch-expected]").textContent = handoff.claimed ?? "(nothing named)";
    $("[data-mismatch-actual]").textContent = handoff.observed ?? "(not attributed)";
    show("binding-mismatch");
  }

  // ── HP-6: removal (CON-210) ──────────────────────────────────────────

  async function removeDevice() {
    if (!s.grant) return;
    await invoke("revoke_grant", { grantId: s.grant.grant_id }).catch(() => {});
    // Submitted, and that is all submission means. CON-210: "A resolver's
    // acknowledgement is not evidence of revocation." The only thing that can
    // move this is a re-resolved verified closure carrying the grant ID, so
    // that is what is asked for — and pending is where it stops when the
    // answer is no, which in a build with no resolver is always.
    show("remove-pending");
    await settleRevocation();
  }

  /**
   * Only a verified closure moves a removal to confirmed.
   *
   * Reachable in this build solely through the screen check, because nothing
   * here can resolve one. That is the correct shape: the transition exists and
   * is unreachable without the evidence, rather than being a timer.
   */
  async function settleRevocation() {
    const out = await invoke("revocation_status", { grantId: s.grant?.grant_id }).catch(() => null);
    if (!out?.confirmed) return;
    $("[data-removed-title]").textContent = `${s.grant?.label ?? "That device"} was removed.`;
    show("remove-confirmed");
  }

  // ── consent (REQ-222) ────────────────────────────────────────────────

  function toConsent() {
    if (!s.app) return;
    $("[data-consent-origin]").textContent = s.app.application_id;
    // Untrusted, and rendered under the treatment that says so.
    $("[data-consent-name]").textContent = s.app.display_name || "(no name given)";
    $("[data-consent-alias]").textContent = s.app.account_alias;

    const list = $("[data-consent-permissions]");
    list.textContent = "";
    for (const p of s.app.permissions ?? []) {
      const li = document.createElement("li");
      li.className = "permission";
      const what = document.createElement("span");
      what.className = "permission__what";
      // An unrecognised permission is shown as its URI, verbatim. Paraphrasing
      // one would be consenting the person to a description nobody wrote.
      what.textContent = p.known && p.title ? p.title : p.uri;
      const uri = document.createElement("span");
      uri.className = "permission__uri";
      uri.textContent = p.known && p.title ? p.uri : "not recognised by this wallet";
      li.append(what, uri);
      list.append(li);
    }
    show("consent-application");
  }

  // ── registration ─────────────────────────────────────────────────────

  Object.assign(actions, {
    "to-applications": () => show("applications"),
    "back-to-application": () => (s.app ? openApplication(s.app) : show("applications")),
    "to-username": toUsername,
    "set-username": setUsername,
    "to-fingerprint": toFingerprint,
    "fingerprint-matches": () => (s.app ? openApplication(s.app) : show("applications")),
    "fingerprint-differs": () => show("binding-mismatch"),
    "to-app-consent": toConsent,
    "consent-approve": () => (s.app ? openApplication(s.app) : show("applications")),
    "consent-refuse": () => (s.app ? openApplication(s.app) : show("applications")),
    "to-remove-device": () => (s.grant ? openGrant(s.grant) : show("application")),
    "remove-device": removeDevice,
  });

  const input = $("#username-input");
  if (input) input.addEventListener("input", previewUsername);

  return { renderApplications, renderSummary, showBindingMismatch };
}
