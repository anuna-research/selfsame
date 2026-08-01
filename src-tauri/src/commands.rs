//! The command surface — one function per thing a user can do.
//!
//! Every command maps to a screen in
//! [the design](../../../../../anuna-ssi/docs/mockup/Anuna%20Key.html) and to the
//! requirements that screen implements. The ordering obligations live here
//! rather than in the UI, because a UI that forgets to ask is a UI that grants
//! authority silently:
//!
//! | Obligation | Where it is enforced |
//! |---|---|
//! | REQ-018 — verify the offer before **any** field is shown | [`read_link_code`] returns `Err` and no view |
//! | REQ-019 — show scope and fingerprint before the presence check | [`read_link_code`] is a separate call from [`authorise`] |
//! | REQ-024 — user presence for every root-key use | `authorise`, `unlink_device`, `create_identity` each take a passcode |
//! | REQ-002 — no linking or revoking before backup confirmation | `Custody::require_backup_confirmed` in both |
//! | REQ-026 — endpoints from the compiled table | `net::endpoint`, never from the offer |
//! | REQ-020 — publication retried, and visible | [`flush_publications`], `pending` in [`AppState`] |

use std::sync::Mutex;

use selfsame_core::{
    fingerprint, identity,
    record::{Application, Grant, Offer},
    seal,
};
use serde::Serialize;
use tauri::{Manager, State};

use crate::custody::{Custody, CustodyError};
use crate::net::{self, NetError};
use crate::session::{DeviceRow, PendingOffer, Session, SessionError};

/// The one error type that crosses to the UI.
///
/// It carries a message a person can act on and never a `RejectReason`-style
/// internal detail. SCREEN-001's error model is explicit: *"the user sees 'that
/// code isn't valid', never a parse detail."*
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct UiError(String);

impl serde::Serialize for UiError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

/// A closed error token, straight through.
///
/// `IMPL-004`'s refusal screens each render exactly one token from
/// `CON-226`'s set and nothing else, so the token *is* the message. This
/// conversion exists so those commands cannot accidentally grow a second
/// sentence explaining which check failed — there is nowhere to put one.
impl From<&'static str> for UiError {
    fn from(token: &'static str) -> Self {
        UiError(token.to_owned())
    }
}
impl From<CustodyError> for UiError {
    fn from(e: CustodyError) -> Self {
        UiError(e.to_string())
    }
}
impl From<SessionError> for UiError {
    fn from(e: SessionError) -> Self {
        UiError(e.to_string())
    }
}
impl From<NetError> for UiError {
    fn from(e: NetError) -> Self {
        UiError(e.to_string())
    }
}
impl From<identity::IdentityError> for UiError {
    fn from(e: identity::IdentityError) -> Self {
        UiError(e.to_string())
    }
}

type Result<T> = std::result::Result<T, UiError>;

/// The application this build links into. ADR-011 keeps one application; the
/// field exists so a second one is a table entry rather than a redesign.
const APP: Application = Application::CbclChat;

pub struct AppSession(pub Mutex<Session>);

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Run a root-key operation off the UI thread.
///
/// Argon2id at the REQ-024 cost takes ~100 ms, which is a visible stall on the
/// main thread and would make the Doherty Threshold budget in SCREEN-001 fail
/// for the wrong reason.
async fn with_root<T: Send + 'static>(
    passcode: String,
    f: impl FnOnce(&ed25519_dalek::SigningKey) -> T + Send + 'static,
) -> Result<T> {
    tauri::async_runtime::spawn_blocking(move || Custody::use_root_key(&passcode, f))
        .await
        .map_err(|_| UiError("that took too long — try again".into()))?
        .map_err(UiError::from)
}

// ── fingerprint rendering ───────────────────────────────────────────────────

/// All three renderings of one fingerprint, so the shell never has to derive any
/// of them.
///
/// **`hex` is the comparison value and `label` is not.** `selfsame-core`'s
/// [`fingerprint`] module is explicit: `hex` carries 48 bits against NFR-008's
/// floor of 32, while `label` carries ≈ 18.6 bits and *"is a nickname, not a
/// comparison value"*. Both travel because SCREEN-001 asks the user to compare a
/// fingerprint across two devices and a word pair is what makes a row of hex
/// recognisable at a glance — but the screen ranks `hex` first and every
/// question the user answers is a question about `hex`.
///
/// Shipping the set from one place is what keeps that true: a shell that
/// received only `label` could not show the compared value even if it wanted to,
/// and a shell that derived its own words — or its own picture — would be a
/// second rendering of a security-relevant value outside the core. That is
/// exactly what the three colour bars in `app.js` were, and why they are gone
/// (SPEC-002 ADR-103).
#[derive(Serialize)]
pub struct Fp {
    /// Six uppercase hex pairs, spaced — `C0 7A 1E 42 9B 33`. The normative
    /// comparison rendering.
    pub hex: String,
    /// The nickname — `copper-lynx-42`. Recognition aid, never compared.
    pub label: String,
    /// The picture — LifeHash v2, 32×32 RGB, Base64, exactly 4096 characters
    /// (SPEC-002 CON-102). Recognition aid, never compared: REQ-103 keeps `hex`
    /// the answer to every question a screen asks.
    pub lifehash: String,
}

impl From<fingerprint::Fingerprint> for Fp {
    fn from(f: fingerprint::Fingerprint) -> Self {
        Self { hex: f.hex(), label: f.label(), lifehash: f.lifehash().base64() }
    }
}

// ── home ────────────────────────────────────────────────────────────────────

/// Everything SCREEN-002's home needs, in one round trip.
#[derive(Serialize)]
pub struct AppState {
    /// Is there an identity on this device at all?
    pub has_identity: bool,
    /// REQ-002: until this is true, linking and revoking are refused.
    pub backup_confirmed: bool,
    pub did: Option<String>,
    /// `fingerprint_did` — what the user compares against a linking client,
    /// and what the home card, the created screen and the restored screen all
    /// headline.
    ///
    /// There is deliberately no second fingerprint here. This struct used to
    /// also carry `root_fingerprint` (`fingerprint_key` of the root key), and
    /// the home card showed *that* — a different 48-bit value, displayed
    /// nowhere else in the system, on the screen the user opens to ask "is this
    /// still me?". Nothing consumed it once the card was corrected, and it is
    /// gone rather than left available: a spare fingerprint on the state object
    /// is an invitation to headline the wrong one again.
    pub fingerprint: Option<Fp>,
    pub devices: Vec<DeviceRow>,
    /// OBS-005 — deltas signed but not yet acknowledged. Non-zero means the
    /// user believes they are linked while peers cannot see it, so the UI says
    /// so rather than implying everything is settled.
    pub pending_publications: usize,
}

#[tauri::command]
pub async fn get_state(session: State<'_, AppSession>) -> Result<AppState> {
    if !Custody::exists()? {
        return Ok(AppState {
            has_identity: false,
            backup_confirmed: false,
            did: None,
            fingerprint: None,
            devices: Vec::new(),
            pending_publications: 0,
        });
    }

    let root_pk = Custody::root_public_key()?;
    let did = identity::derive_did(&root_pk)?.to_string();
    let session = session.0.lock().unwrap_or_else(|p| p.into_inner());

    Ok(AppState {
        has_identity: true,
        backup_confirmed: Custody::backup_confirmed()?,
        fingerprint: Some(fingerprint::fingerprint_did(&did).into()),
        devices: session.devices(&root_pk).unwrap_or_default(),
        pending_publications: session.pending_count(),
        did: Some(did),
    })
}

// ── HP-1: create the root ───────────────────────────────────────────────────

#[derive(Serialize)]
pub struct CreatedIdentity {
    /// The twelve words. **The one deliberate exception to NFR-002** — they are
    /// the recovery mechanism, they are shown for transcription, and they are
    /// never written to storage or a clipboard.
    pub words: Vec<String>,
    pub did: String,
    pub fingerprint: Fp,
}

/// HP-1 steps 01–02 — create the identity and show the recovery phrase.
///
/// The genesis and the ADR-006 profile declaration are signed and queued for
/// publication here rather than after the backup confirmation, because
/// ADR-012's persona discovery depends on the genesis being published: *"a
/// persona whose genesis was never acknowledged is not discoverable and is lost
/// on restore."* REQ-002 gates *linking and revoking*, which is what it says,
/// and not identity creation.
#[tauri::command]
pub async fn create_identity(
    passcode: String,
    session: State<'_, AppSession>,
) -> Result<CreatedIdentity> {
    let phrase = {
        let passcode = passcode.clone();
        tauri::async_runtime::spawn_blocking(move || Custody::create(&passcode))
            .await
            .map_err(|_| UiError("that took too long — try again".into()))??
    };

    let root_pk = Custody::root_public_key()?;
    let did = identity::derive_did(&root_pk)?;

    // Sign the genesis and the profile declaration.
    let signed = with_root(passcode, move |root| -> std::result::Result<_, identity::IdentityError> {
        let (document, genesis) = identity::sign_genesis(root)?;
        let profile = identity::declare_profile(&document, root, now() * 1_000)?;
        Ok((genesis, profile))
    })
    .await??;

    {
        let mut s = session.0.lock().unwrap_or_else(|p| p.into_inner());
        s.record(&signed.0);
        s.record(&signed.1);
    }
    let _ = flush(&session).await;

    Ok(CreatedIdentity {
        words: phrase.split_whitespace().map(str::to_owned).collect(),
        fingerprint: fingerprint::fingerprint_did(did.as_str()).into(),
        did: did.to_string(),
    })
}

/// HP-1 step 03 — the REQ-002 confirmation.
///
/// The caller holds the words on screen and passes them back with the user's
/// three answers. Storing the phrase in order to check it would defeat the very
/// exemption NFR-002 grants for showing it.
#[tauri::command]
pub async fn confirm_backup(mnemonic: String, answers: Vec<(usize, String)>) -> Result<bool> {
    Ok(Custody::confirm_backup(&mnemonic, &answers)?)
}

/// Restore on a replacement phone, then pull the closure so the devices list
/// can name what it can revoke (REQ-021).
#[tauri::command]
pub async fn restore_identity(
    phrase: String,
    passcode: String,
    session: State<'_, AppSession>,
) -> Result<AppState> {
    tauri::async_runtime::spawn_blocking(move || Custody::restore(&phrase, &passcode))
        .await
        .map_err(|_| UiError("that took too long — try again".into()))??;

    let root_pk = Custody::root_public_key()?;
    let did = identity::derive_did(&root_pk)?.to_string();

    if let Ok(deltas) = net::fetch_closure(APP, &did).await {
        let mut s = session.0.lock().unwrap_or_else(|p| p.into_inner());
        s.adopt_closure(&deltas);
    }
    get_state(session).await
}

// ── SCREEN-001: authorise a link ────────────────────────────────────────────

/// Exactly what REQ-019 requires be shown, and nothing that would let the UI
/// show something else.
#[derive(Serialize)]
pub struct OfferView {
    /// From the compiled table (REQ-026) — never the string on the wire.
    pub application: String,
    pub purpose: String,
    /// **Untrusted.** The device's own words, capped at recognition. The UI
    /// renders this in the dashed region with no formatting interpreted.
    pub device_description: String,
    /// `fingerprint_key` of the key about to be authorised — the value the
    /// user compares against what the other screen is showing. SCREEN-001 puts
    /// [`Fp::hex`] in that comparison and [`Fp::label`] beneath it.
    pub key_fingerprint: Fp,
    /// Seconds remaining, for the countdown.
    pub expires_in: u64,
}

/// Read a typed or scanned code, fetch the offer, and **verify it** — REQ-018.
///
/// Nothing is shown unless this returns `Ok`. SCREEN-001's "Never reached" rows
/// are the `Err` arms: an absent, wrong-key, or wrong-domain signature, an
/// application outside the compiled table, and an expired offer each stop here.
/// Parsing the offer is not authorising it.
#[tauri::command]
pub async fn read_link_code(code: String, session: State<'_, AppSession>) -> Result<OfferView> {
    // REQ-002: refuse before doing any work, so the UI can route to the backup
    // flow rather than discovering the block after the user has scanned.
    Custody::require_backup_confirmed()?;

    let link = selfsame_core::LinkCode::parse(&code)
        .map_err(|_| UiError("That code isn't valid.".into()))?;
    // REQ-026: the application byte selects the endpoint from the compiled
    // table. Nothing in the code is an address.
    let application = link.application;
    let secret = *link.secret.as_bytes();

    let sealed = net::fetch_offer(application, &secret)
        .await
        .map_err(|_| UiError("That code isn't valid.".into()))?;
    let plaintext = seal::open_offer(&seal::derive_key(&secret), &sealed)
        .map_err(|_| UiError("That code isn't valid.".into()))?;

    // Recognise fully, and verify the signature, before any field exists.
    let offer =
        Offer::parse(&plaintext).map_err(|_| UiError("That code isn't valid.".into()))?;
    if offer.application != application {
        return Err(UiError("That code isn't valid.".into()));
    }

    let now = now();
    if now > offer.expiry {
        return Err(UiError("That code has expired — generate a new one.".into()));
    }

    let view = OfferView {
        application: offer.application.slug().to_owned(),
        purpose: offer.purpose.to_owned(),
        device_description: offer.device_description.clone(),
        key_fingerprint: fingerprint::fingerprint_key(&offer.device_key).into(),
        expires_in: offer.expiry - now,
    };

    let mut s = session.0.lock().unwrap_or_else(|p| p.into_inner());
    s.pending_offer = Some(PendingOffer { expires_at: offer.expiry, offer, secret });
    Ok(view)
}

/// *This isn't me — reject.* Nothing is signed, written, or published.
#[tauri::command]
pub async fn reject_offer(session: State<'_, AppSession>) -> Result<()> {
    let mut s = session.0.lock().unwrap_or_else(|p| p.into_inner());
    s.pending_offer = None;
    Ok(())
}

#[derive(Serialize)]
pub struct Authorised {
    pub method_id: String,
    pub did: String,
    /// `fingerprint_did` — what the *client* will show, so the user knows what
    /// to expect on the other screen.
    pub fingerprint: Fp,
    pub publishing: usize,
}

/// The one screen in the system where a user grants authority.
///
/// Order matters and is enforced here: backup confirmed (REQ-002), offer still
/// valid (REQ-016), user presence (REQ-024), then sign, then seal, then reply,
/// then publish (REQ-020). The bundle is written to the rendezvous *before*
/// publication succeeds, because CON-006 is explicit that publication failure
/// degrades attribution and must never block linking.
#[tauri::command]
pub async fn authorise(passcode: String, session: State<'_, AppSession>) -> Result<Authorised> {
    Custody::require_backup_confirmed()?;

    let (offer, secret) = {
        let s = session.0.lock().unwrap_or_else(|p| p.into_inner());
        let pending = s.pending_offer.as_ref().ok_or_else(|| UiError("Nothing to authorise.".into()))?;
        if now() > pending.expires_at {
            return Err(UiError("That code has expired — generate a new one.".into()));
        }
        (pending.offer.clone(), pending.secret)
    };

    let root_pk = Custody::root_public_key()?;
    // The fragment is chosen against the *whole* identity, so a new device
    // cannot collide with a method id that already exists in signed state.
    let fragment = {
        let s = session.0.lock().unwrap_or_else(|p| p.into_inner());
        let document = s.document(&root_pk).map_err(UiError::from)?;
        s.next_device_fragment(&document)
    };

    let device_key = offer.device_key;
    let label = offer.device_description.clone();
    let did = identity::derive_did(&root_pk)?;
    let method_id = format!("{did}#{fragment}");
    let id_for_signing = method_id.clone();

    // REQ-024 — the presence check, and the only place the root key exists.
    // Both deltas are signed inside one gate: they are one user decision, and
    // asking twice would train the user to type the passcode without reading.
    //
    // **The two deltas are parented on the genesis, not on the identity's
    // current frontier.** CON-002 admits 2–3 deltas in a bundle — genesis, the
    // add, and the optional label — so the bundle can only ever be causally
    // closed if the add's parent *is* the genesis. Parenting on the frontier
    // instead made every bundle unresolvable the moment the identity had any
    // other delta in it, which it always does: ADR-006's profile declaration is
    // written at identity creation. A verifier then held a delta whose parent it
    // had never seen, and refused the whole closure.
    //
    // Being concurrent with the rest of the document is fine and is what a CRDT
    // is for: verification methods are a G-Set, so a device added off the
    // genesis converges with everything else. The full closure — profile
    // declaration included — reaches verifiers from the resolver (REQ-025); the
    // bundle carries the offline-verifiable minimum (NFR-006).
    let (genesis, add, label_delta) =
        with_root(passcode, move |root| -> std::result::Result<_, identity::IdentityError> {
            let ms = now() * 1_000;
            let (mut from_genesis, genesis) = identity::sign_genesis(root)?;
            let add = identity::add_device(&from_genesis, root, &device_key, &fragment, ms)?;
            // The label commits to a frontier that already contains the add, so
            // the two are causally ordered and a verifier sees them in the
            // order they were meant.
            from_genesis.merge_verified_delta(add.clone()).ok();
            let label_delta =
                identity::set_device_label(&from_genesis, root, &id_for_signing, &label, ms + 1)?;
            Ok((genesis, add, label_delta))
        })
        .await??;

    // Assemble the bundle: genesis, the add, and the label — CON-002's 2–3
    // deltas. It is self-contained, so the client can recompute the DID from
    // the genesis it carries (REQ-003) without asking anyone.
    let deltas: Vec<Vec<u8>> = [&genesis, &add, &label_delta]
        .iter()
        .map(|d| serde_json::to_vec(d).unwrap_or_default())
        .collect();
    let grant = Grant::new(did.to_string(), deltas);
    let sealed =
        seal::seal_bundle(&seal::derive_key(&secret), &grant.to_bytes(), &offer.transcript());

    net::put_bundle(APP, &secret, sealed)
        .await
        .map_err(|_| UiError("Couldn't reach the other device — try again.".into()))?;

    let publishing = {
        let mut s = session.0.lock().unwrap_or_else(|p| p.into_inner());
        s.record(&add);
        s.record(&label_delta);
        s.note_seen(&method_id, now());
        s.pending_offer = None;
        s.pending_count()
    };

    // REQ-020: publish, and keep trying. A failure here is reported as
    // *publishing…* and not as a failed link.
    let _ = flush(&session).await;

    Ok(Authorised {
        method_id,
        fingerprint: fingerprint::fingerprint_did(did.as_str()).into(),
        did: did.to_string(),
        publishing,
    })
}

// ── HP-5: unlink ────────────────────────────────────────────────────────────

/// Revoke a device using only the root key (REQ-010).
///
/// Works whether or not the device is switched on: the revoked device is not
/// consulted, cannot refuse, and does not need to be reachable.
#[tauri::command]
pub async fn unlink_device(
    method_id: String,
    passcode: String,
    session: State<'_, AppSession>,
) -> Result<AppState> {
    Custody::require_backup_confirmed()?;
    let root_pk = Custody::root_public_key()?;
    let document = {
        let s = session.0.lock().unwrap_or_else(|p| p.into_inner());
        s.document(&root_pk)?
    };

    let id = method_id.clone();
    let revoke = with_root(passcode, move |root| {
        identity::revoke_device(&document, root, &id, now() * 1_000)
    })
    .await??;

    {
        let mut s = session.0.lock().unwrap_or_else(|p| p.into_inner());
        s.record(&revoke);
    }
    let _ = flush(&session).await;
    get_state(session).await
}

// ── REQ-020: publication ────────────────────────────────────────────────────

/// Retry every unacknowledged delta. Safe to call at any time: publication is
/// idempotent, and a `409` means "already there", which is success.
#[tauri::command]
pub async fn flush_publications(session: State<'_, AppSession>) -> Result<usize> {
    flush(&session).await
}

async fn flush(session: &State<'_, AppSession>) -> Result<usize> {
    let Ok(root_pk) = Custody::root_public_key() else { return Ok(0) };
    let did = identity::derive_did(&root_pk)?.to_string();

    let pending = {
        let s = session.0.lock().unwrap_or_else(|p| p.into_inner());
        s.pending().unwrap_or_default()
    };

    // Causal order: a delta whose parent has not been published yet would be
    // refused, so publish in the order they were signed and stop at the first
    // failure rather than firing the rest at a resolver that cannot take them.
    for delta in pending {
        match net::publish(APP, &did, &delta).await {
            Ok(()) => {
                let mut s = session.0.lock().unwrap_or_else(|p| p.into_inner());
                s.acknowledge(&delta);
            }
            Err(_) => break,
        }
    }

    let s = session.0.lock().unwrap_or_else(|p| p.into_inner());
    Ok(s.pending_count())
}

// ── first-run reset ─────────────────────────────────────────────────────────

/// Destroy the local identity.
///
/// This is **not** revocation: it destroys the only key that could revoke
/// anything, so every device linked to this identity stays linked forever with
/// nobody able to change that. The UI says exactly that before calling it.
#[tauri::command]
pub async fn forget_identity(session: State<'_, AppSession>) -> Result<()> {
    Custody::forget()?;
    let mut s = session.0.lock().unwrap_or_else(|p| p.into_inner());
    s.clear();
    Ok(())
}

/// Where the rendezvous and resolver for this build live — shown in the UI so
/// an operator can see which service a development build is talking to.
#[tauri::command]
pub fn service_endpoint() -> String {
    net::endpoint(APP)
}

/// Wire the commands into a Tauri builder.
pub fn init(app: &tauri::App) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let dir = app.path().app_data_dir()?;
    app.manage(AppSession(Mutex::new(Session::load(dir))));
    Ok(())
}
