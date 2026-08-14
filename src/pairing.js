/**
 * The PROTO-003 surface — a pairing, from twelve words to a written bundle.
 *
 * Like `app-identity.js` this file holds *no* security logic. Every decision —
 * does the record verify, does the profile digest match, did the PAKE confirm,
 * is the application authenticated, may a bundle be sealed — is made in Rust and
 * reaches here as a value or a closed error token. What lives here is sequence
 * and presentation.
 *
 * # What this file deliberately never holds
 *
 * The pairing code. `CON-407` requires the binding, the code, the role token and
 * the terminal state to be held "in process-private memory", and `C` is the
 * SPAKE2 password — a page that held it would be holding the password in the
 * least trustworthy process in the system. So `read_pairing_code` keeps the
 * ceremony in the Rust session and returns a `bindingHash`, and every later call
 * NAMES the ceremony rather than carrying it.
 *
 * The code is typed into `#pairing-input`, which means it exists in a DOM node
 * for as long as the person is typing it. That is unavoidable — somebody has to
 * type it somewhere — and it is cleared the moment it has been handed over.
 *
 * # The two consent screens are not the same screen twice
 *
 *   pairing-target   an UNAUTHENTICATED claim; the human check is the only one
 *   pairing-grant    the same origin after CON-214 evidence verified
 *
 * `CON-217`: "a valid confirmation is never sufficient application
 * authentication or authorization". The difference between the two screens is
 * the whole of what `pairing_answer` does, and rendering the first one as though
 * it were the second is the mistake this surface is shaped to prevent.
 *
 * Dependencies arrive as a parameter rather than an import, so the direction is
 * one-way — `app.js` → here, never back.
 */

/** Everything this surface is holding between screens. Cleared on every exit. */
const p = {
  /** Names the ceremony in the Rust session. Not a secret; useless without `C`. */
  bindingHash: null,
  /** The claimed target, for the screens before authentication. */
  target: null,
  /** What `pairing_answer` returned: offer octets, profile octets, observation. */
  answer: null,
  /** The `ceremonyId` `app_grant_prepare` bound its pending issuance to. */
  ceremonyId: null,
  /** Wall-clock second the record expires, for the countdown. */
  expiresAt: null,
  timer: null,
};

/**
 * Every refusal a person can arrive at, as a sentence.
 *
 * `CON-407`: a UI "reports that the code expired or pairing failed; it does not
 * distinguish a wrong word from an active attack". So the tokens that mean
 * "somebody is on the other end of this and it went wrong" all collapse to one
 * line here, and only the ones that are facts about the person's own situation —
 * the code aged out, the provider is down — say anything more specific.
 */
const REFUSALS = {
  PairingExpired: [
    "This pairing has expired",
    "Pairing codes last a few minutes. Ask the application for a new one — the old one can't be used, even by you.",
  ],
  PairingProviderUnreachable: [
    "Couldn't reach the relay",
    "The service that passes messages between you and the application didn't answer. Nothing was shared. Try again in a moment.",
  ],
  PairingRecordUnavailable: [
    "Nothing is waiting on that code",
    "Either it was already used, or it has expired. Ask the application for a new one.",
  ],
  UnverifiedApplication: [
    "That application couldn't be verified",
    "It didn't sign for this request with a key its own site publishes. Nothing was shared.",
  ],
  EnrollmentReplay: [
    "That request was already used",
    "A pairing code authorises one connection. Ask the application for a new one.",
  ],
  AuthorityUnreachable: [
    "Couldn't check this account",
    "The service that holds your account records didn't answer, and this wallet won't guess. Try again in a moment.",
  ],
  BackupNotConfirmed: [
    "Write down your recovery words first",
    "Until they are written down, this identity can't hand out authority that outlives this device.",
  ],
};

/** The one line everything else collapses to. */
const REFUSAL_DEFAULT = [
  "The pairing failed",
  "Nothing was shared and nothing was authorised. If you were expecting this, ask the application for a new code.",
];

/**
 * Wire the PROTO-003 screens into the shell.
 *
 * @param {object} d primitives owned by `app.js`
 */
export function initPairing(d) {
  const { $, show, invoke, fail, message, renderLifehash, actions, busy, idle, refresh } = d;

  // ── entry (CON-402) ──────────────────────────────────────────────────

  /**
   * Twelve words is the whole grammar. Counted rather than validated: the
   * checksum is BIP-39's and is verified in Rust before any address is derived
   * or any socket is opened, so a check here would be a second recogniser
   * disagreeing with the one that matters.
   */
  function onInput() {
    const value = $("#pairing-input").value.trim();
    const words = value.split(/[\s-]+/).filter(Boolean).length;
    const qr = value.startsWith("selfsame-pairing-v2:");
    $("[data-pairing-state]").textContent = qr ? "scanned code" : `${words} of 12 words`;
    $("[data-pairing-state]").classList.toggle("code-state--ok", qr || words === 12);
    $('[data-action="read-pairing-code"]').disabled = !(qr || words === 12);
  }

  async function readCode() {
    const input = $("#pairing-input");
    const code = input.value.trim();
    busy("Looking up that code…");
    try {
      const target = await invoke("read_pairing_code", { code });
      // Handed over, so this page has no further use for it.
      input.value = "";
      onInput();
      p.bindingHash = target.bindingHash;
      p.target = target;
      p.expiresAt = Math.floor(Date.now() / 1000) + target.expiresIn;
      renderTarget(target);
      show("pairing-target");
      startCountdown("[data-pairing-countdown]");
    } catch (e) {
      // A code that resolves nothing is the ordinary case — it aged out — so it
      // is reported on the entry screen rather than as a terminal refusal.
      fail("pairing", refusalOf(message(e))[1]);
    } finally {
      idle();
    }
  }

  // ── CON-409: the claimed target ──────────────────────────────────────

  function renderTarget(target) {
    // Every one of these is `.textContent`. The strings came off a wire and are
    // a claim; putting one through `innerHTML` would let a record author write
    // markup into the screen that exists to doubt them.
    $("[data-pairing-origin]").textContent = target.claimedOrigin;
    $("[data-pairing-application]").textContent = target.claimedApplicationId;
    $("[data-pairing-provider]").textContent = target.providerId;
  }

  /**
   * "Yes, this is me" — and the ceremony stops being reversible.
   *
   * Everything from claiming the nameplate to opening the offer happens inside
   * this one call, because none of it is a decision a person makes. What comes
   * back is an authenticated application or a refusal.
   */
  async function approve() {
    if (!p.bindingHash) return show("applications");
    busy("Meeting the application…");
    try {
      p.answer = await invoke("pairing_answer", { bindingHash: p.bindingHash });
      const view = await invoke("app_grant_review", {
        offer: p.answer.offer,
        profile: p.answer.profile,
        observed: p.answer.observed,
      });
      renderGrant(view);
      show("pairing-grant");
      p.expiresAt = Math.floor(Date.now() / 1000) + view.expiresIn;
      startCountdown("[data-grant-countdown]");
    } catch (e) {
      refuse(message(e));
    } finally {
      idle();
    }
  }

  /**
   * "This isn't mine", and every other exit.
   *
   * `CON-218`: decline "burns before a nameplate claim, PAKE frame, mailbox
   * action, or grant can occur", and the burn is the Rust side's — this only
   * asks for it. The result is ignored on purpose: the ceremony is over either
   * way, and a person who has said no should not then be shown an error about
   * saying no.
   */
  async function decline() {
    const named = p.bindingHash;
    forget();
    if (named) {
      try {
        await invoke("pairing_decline", { bindingHash: named });
      } catch {
        /* over regardless */
      }
    }
    show("applications");
  }

  // ── CON-219: what was actually asked for ─────────────────────────────

  function renderGrant(view) {
    $("[data-grant-application]").textContent = view.applicationId;
    $("[data-grant-device]").textContent = view.deviceDid;

    const list = $("[data-grant-permissions]");
    list.textContent = "";
    for (const uri of view.permissions ?? []) {
      const li = document.createElement("li");
      li.className = "permission";
      const what = document.createElement("span");
      what.className = "permission__what";
      // Verbatim. `app_grant_review` returns the permissions "exactly as they
      // will appear in the credential", and paraphrasing one would be consenting
      // the person to a description nobody wrote.
      what.textContent = uri;
      li.append(what);
      list.append(li);
    }
  }

  // ── REQ-024: presence, then the key ──────────────────────────────────

  /**
   * `app_grant_prepare` — the one place a `SPEC-004` credential is signed.
   *
   * The passcode is read, passed, and cleared in the same breath. It is never
   * held in `p`: a module-level field would outlive the screen and be readable
   * by anything else running in this page.
   */
  async function prepare() {
    const field = $("#pairing-passcode");
    const passcode = field.value;
    field.value = "";
    if (!p.answer) return show("applications");

    busy("Signing…");
    try {
      const request = await invoke("app_grant_prepare", {
        offer: p.answer.offer,
        profile: p.answer.profile,
        observed: p.answer.observed,
        passcode,
      });
      p.ceremonyId = request.ceremonyId;

      if (request.applicability === "required") {
        renderComparison(request);
        show("pairing-compare");
        return;
      }
      // `notRequired` — the authority already holds this binding, so the
      // comparison has been made once and is not asked again. `failClosed` never
      // arrives here: `app_grant_prepare` returns `AuthorityUnreachable` for it
      // rather than a request, because an unreachable authority must not be read
      // as first use.
      await confirm();
    } catch (e) {
      const token = message(e);
      // A wrong passcode is a fact about the person's own typing and belongs on
      // the screen they typed it on, where they can try again. Everything else
      // is terminal.
      if (/passcode/i.test(token)) fail("pairing-presence", token);
      else refuse(token);
    } finally {
      idle();
    }
  }

  function renderComparison(request) {
    $("[data-pairing-fp-hex]").textContent = request.fingerprint?.hex ?? "";
    $("[data-pairing-fp-label]").textContent = request.fingerprint?.label ?? "";
    renderLifehash($("[data-pairing-fp-lifehash]"), request.fingerprint?.lifehash);
    $("[data-pairing-fp-account]").textContent = request.account;
  }

  // ── CON-408: the bundle goes back ────────────────────────────────────

  /**
   * Release the bundle, seal it, and write it to the mailbox.
   *
   * Two calls, and the order matters: `app_grant_confirm` hands back a signed
   * bundle that has been transmitted nowhere, and `pairing_deliver` is what
   * transmits it. A failure between them leaves a credential that was signed and
   * never delivered, which confers nothing — the same property
   * `app_grant_confirm` relies on when a person says no.
   */
  async function confirm() {
    if (!p.ceremonyId || !p.bindingHash) return show("applications");
    busy("Sending it back…");
    try {
      const grant = await invoke("app_grant_confirm", {
        ceremonyId: p.ceremonyId,
        confirmed: true,
      });
      await invoke("pairing_deliver", { bindingHash: p.bindingHash, bundle: grant.bundle });
      renderDone(grant);
      forget();
      // Re-derive the applications list before showing anything: the wallet now
      // holds a grant it did not hold a moment ago, and `refresh` navigates —
      // it decides a screen from state, so calling it afterwards would land the
      // person on the home screen instead of the one that says what just
      // happened.
      await refresh();
      show("pairing-done");
    } catch (e) {
      refuse(message(e));
    } finally {
      idle();
    }
  }

  function renderDone(grant) {
    $("[data-done-application]").textContent = p.target?.claimedApplicationId ?? "It";
    $("[data-done-account]").textContent = grant.account;
    $("[data-done-until]").textContent = new Date(grant.validUntil * 1000).toLocaleString();
    $("[data-done-publishing]").textContent = grant.published
      ? "Published to your account's state resolver."
      : "This grant carries its own proof, because no state resolver is deployed yet. It works now; a verifier just can't look it up independently.";
  }

  // ── refusal ──────────────────────────────────────────────────────────

  function refusalOf(token) {
    return REFUSALS[token] ?? REFUSAL_DEFAULT;
  }

  /**
   * Terminal. Every arrival burns the ceremony, and there is nothing to retry:
   * `CON-218`'s only retry transition is to a new ceremony, which means a new
   * code.
   */
  function refuse(token) {
    const [title, body] = refusalOf(token);
    $("[data-refused-pairing-title]").textContent = title;
    $("[data-refused-pairing-body]").textContent = body;
    forget();
    show("pairing-refused");
  }

  /** Drop everything this surface is holding. */
  function forget() {
    stopCountdown();
    p.bindingHash = null;
    p.target = null;
    p.answer = null;
    p.ceremonyId = null;
    p.expiresAt = null;
  }

  // ── the countdown ────────────────────────────────────────────────────

  function startCountdown(selector) {
    stopCountdown();
    const el = $(selector);
    if (!el) return;
    const tick = () => {
      const left = (p.expiresAt ?? 0) - Math.floor(Date.now() / 1000);
      if (left <= 0) {
        // Not a cosmetic timer. The record's own expiry has passed, so every
        // command below this point would refuse anyway — saying so here is what
        // stops a person staring at a screen that has already stopped working.
        refuse("PairingExpired");
        return;
      }
      el.textContent = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
    };
    tick();
    p.timer = window.setInterval(tick, 1000);
  }

  function stopCountdown() {
    if (p.timer) window.clearInterval(p.timer);
    p.timer = null;
  }

  // ── registration ─────────────────────────────────────────────────────

  Object.assign(actions, {
    "to-pairing": () => {
      forget();
      $("#pairing-input").value = "";
      onInput();
      show("pairing-enter");
    },
    "read-pairing-code": readCode,
    "pairing-approve": approve,
    "pairing-decline": decline,
    "pairing-grant-allow": () => {
      $("#pairing-passcode").value = "";
      show("pairing-presence");
    },
    "pairing-prepare": prepare,
    "pairing-confirm": confirm,
  });

  const input = $("#pairing-input");
  if (input) input.addEventListener("input", onInput);

  return { forget };
}
