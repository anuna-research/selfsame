//! `PROTO-003` resolution, answer, and delivery — the wallet's half of a pairing.
//!
//! Three commands and one piece of state that never leaves this process:
//!
//! ```text
//!   read_pairing_code   CON-409   what a scanned code turns into      → discloses
//!   pairing_answer      CON-405   claim, four frames, open the offer  → "this is me"
//!   pairing_deliver     CON-408   seal the bundle back                → done
//!   pairing_decline     CON-218   burn without touching the relay
//! ```
//!
//! # The one thing the consent screen must not imply
//!
//! A resolved record is an **unauthenticated, bearer-routable hint**. `CON-409`
//! is unusually blunt about it: the signature *"proves only that whoever holds
//! `C` wrote it; it establishes neither application authority nor an intended
//! recipient"*, and a party who knows `C` can publish a coherent record for a
//! **different** application and complete the PAKE for it — the `binding_hash`
//! is internally consistent either way, so confirmation cannot detect the
//! substitution.
//!
//! So [`PairingTarget`] carries `claimed_application_id`, not `application_id`.
//! The name is the whole point: the field is a claim, the screen must say so,
//! and there is nothing [`read_pairing_code`] could do to make it more than that.
//! What turns the claim into an authenticated application is `CON-214`'s
//! enrollment evidence, and that arrives inside the offer — three network
//! round-trips and a completed PAKE later, in [`pairing_answer`].
//!
//! # Why the ceremony lives here and not in the webview
//!
//! Two reasons, and the weaker one is the CSP. The application's
//! `connect-src 'self' ipc: http://ipc.localhost` means the webview cannot fetch
//! a record, a profile, a frame, or a mailbox slot at all — which points the
//! right way but is a property of a configuration file.
//!
//! The binding one is `CON-407`: each client "records the exact
//! application/profile/descriptor binding, code, role token, peer frame hashes,
//! and terminal state **in process-private memory**". The code `C` is the SPAKE2
//! password. A design that returned it to the page and took it back would have
//! published the password to the least trustworthy process in the system and
//! called the result a pairing.
//!
//! That is why [`PendingPairing`] exists and why [`PairingTarget`] carries a
//! `binding_hash` rather than anything secret: the page names the ceremony it is
//! answering, and holds none of it.

use selfsame_app_identity::authorise::{self, Observation};
use selfsame_app_identity::ceremony::{self, OfferCore};
use selfsame_app_identity::pairing::{
    self as pairing_policy, BindingObject, BoundOrigins, Ceremony, CeremonyValues, Confirmation,
    GatedAction, RecordClaim, Role,
};
use selfsame_app_identity::pairing_code::{self, Code, MeetingRecord};
use selfsame_app_identity::profile::ApplicationId;
use selfsame_app_identity_net::profile as profile_net;
use selfsame_core::envelope::{EnvelopeKey, EnvelopeKeys};
use selfsame_core::seal;
use selfsame_core::spake2::{Party, Pairing as Spake2};
use serde::Serialize;
use zeroize::Zeroize;

use crate::commands::{now, AppSession, UiError};
use crate::pairing_net::{self, Frame, Relay, RelayError};

type Result<T> = std::result::Result<T, UiError>;

/// How long the record and profile fetches may take, in total.
const RESOLVE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// The largest record envelope a wallet will read.
const MAX_ENVELOPE_OCTETS: usize = 8 * 1024;

// ── the state CON-407 requires be process-private ───────────────────────────

/// One live ceremony, held where the webview cannot reach it.
///
/// Every field is one `CON-407` names, and the type is deliberately opaque: it
/// derives no `Serialize`, so there is no way to accidentally return it across
/// the IPC boundary.
pub struct PendingPairing {
    /// The password `C`. Never rendered, never returned, never logged —
    /// [`Code`] is not `Debug`, `Display`, or `Clone` for that reason.
    code: Code,
    /// `CON-217`'s ordering and `CON-218`'s closure, as a value.
    ceremony: Ceremony,
    binding_hash: [u8; 32],
    /// The only PAKE relay origin and the only mailbox origin for this ceremony
    /// (`CON-213`). They may have different operators.
    origins: BoundOrigins,
    nameplate: String,
    provider_id: String,
    descriptor_digest: String,
    /// The digest the record committed to, which the offer must also bind to.
    profile_digest: String,
    /// The exact profile octets whose digest was checked. Carried rather than
    /// re-fetched, because a second fetch may return a different document.
    profile: Vec<u8>,
    /// The record's own expiry, in seconds since the epoch.
    expires_at: i64,
    /// What the answer produced. `None` until [`pairing_answer`] succeeds.
    answered: Option<Answered>,
}

/// What survives a completed PAKE, for the delivery step.
struct Answered {
    /// `CON-501`'s `K_bundle`. `Option` because sealing consumes it, which is
    /// how `REQ-502`'s one-plaintext-per-key rule is kept.
    bundle_key: Option<EnvelopeKey>,
    /// `CON-408`'s mailbox secret, for the bundle slot. Zeroized on drop.
    mailbox_secret: [u8; 16],
    /// The offer this ceremony admitted. `CON-219`: a bundle whose identifiers
    /// are not the ones this ceremony's offer carried "is a rejection, not a new
    /// ceremony".
    offer: OfferCore,
}

impl Drop for Answered {
    fn drop(&mut self) {
        self.mailbox_secret.zeroize();
    }
}

// ── CON-409: what a scanned code turns into ─────────────────────────────────

/// What the consent screen is given.
///
/// Every string here is either a claim from the record or a fact this wallet
/// derived. Nothing is a verified statement about who is asking, because at this
/// point in the ceremony no such statement exists.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingTarget {
    /// The `applicationId` the record CLAIMS. Displayed as a claim.
    pub claimed_application_id: String,
    /// Its HTTPS origin, which `CON-409` requires be shown alongside — a person
    /// comparing a full URL reads the path and misses the host, and the host is
    /// the part that decides who they are about to be granted by.
    pub claimed_origin: String,
    /// The six-digit nameplate the ceremony will meet at.
    pub nameplate: String,
    /// The descriptor selected from the profile, by id.
    pub provider_id: String,
    /// The pairing endpoint the selected descriptor names.
    pub pairing_url: String,
    /// `binding_hash`, base64url — **the name of this ceremony**, and the only
    /// thing the page needs in order to answer it. Not a secret: both endpoints
    /// hold it, and holding it confers nothing without `C`.
    pub binding_hash: String,
    /// Seconds until the record expires.
    pub expires_in: i64,
}

/// Resolve a scanned or typed pairing code.
///
/// `CON-409`'s steps, in its order: recover `C` and verify the checksum; derive
/// the address and resolve; verify the signature; reject expiry; recognise the
/// closed member set; fetch the profile and match its digest; select the unique
/// descriptor; construct the binding.
///
/// It stops at the binding. No nameplate is claimed, no frame is sent and no key
/// is derived, because `CON-409` requires the wallet to display the claimed
/// identity *before* either — and a command that resolved and claimed in one call
/// would have shown the person nothing to decide on.
#[tauri::command]
pub async fn read_pairing_code(
    code: String,
    session: tauri::State<'_, AppSession>,
) -> Result<PairingTarget> {
    // Step 1. A QR carries the bootstrap; a typed code carries twelve words.
    // Both are renderings of the same sixteen octets, and the checksum is
    // verified here — before any address is derived or any socket is opened.
    let code = Code::from_qr_payload(&code)
        .or_else(|_| Code::from_words(&code))
        .map_err(|_| UiError::from("That code isn't valid."))?;

    // Step 2. The address is a function of `C` alone, so nothing about where to
    // look came from the person or the wire.
    let point = code.meeting_point();
    let envelope = resolve_record(&point.address_text()).await?;

    // Steps 3, 4, 5 — signature, expiry, closed member set — are the pure core's.
    let record = pairing_code::recognise_meeting_record(
        &point.address(),
        &envelope.payload,
        &envelope.signature,
        now() as i64,
    )
    .map_err(|_| UiError::from("That code isn't valid."))?;

    // Step 6. The profile comes from the canonical `applicationId` ORIGIN, not
    // from the record, and its digest must equal what the record claimed. This
    // is the only thing in the whole resolution that ties the claim to bytes
    // somebody else served.
    let application_id = ApplicationId::parse(&record.application_id)
        .map_err(|_| UiError::from("That code isn't valid."))?;
    // `UiError` converts `crate::net::NetError`, not the profile client's, and
    // the two are different types. Mapped explicitly rather than widened: a
    // blanket conversion would let any future network error reach a person as
    // whatever this one happens to say.
    let fetched = profile_net::fetch(&application_id, now() as i64)
        .await
        .map_err(|_| UiError::from("UnverifiedApplication"))?;
    if selfsame_app_identity::codec::b64url(fetched.profile.digest()) != record.profile_digest {
        // The record named an application whose published profile is not the one
        // it committed to. That is a substitution, not a stale cache.
        return Err(UiError::from("PairingProfileMismatch"));
    }

    // Step 7. Exactly one descriptor, and `CON-216`'s resolution checks with it.
    // `providerId` is REQUIRED alongside the digest because `pairingUrl` alone is
    // ambiguous when one profile declares two descriptors at one origin — so a
    // match by URL would be a coin flip.
    let claim = RecordClaim {
        application_id: record.application_id.clone(),
        profile_digest: record.profile_digest.clone(),
        provider_id: record.provider_id.clone(),
        nameplate: record.nameplate.clone(),
    };
    let descriptor = pairing_policy::resolve_record(&claim, &fetched.profile)
        .map_err(|_| UiError::from("PairingProviderUnknown"))?;

    // Step 8. The binding, built from THIS wallet's own resolved profile and
    // selection. `CON-403` requires both parties to hold every member before
    // either processes a peer frame, and building it from the record alone would
    // be taking the initiator's word for what the ceremony is about.
    let binding = BindingObject {
        application_id: application_id.as_str().to_owned(),
        descriptor_digest: selfsame_app_identity::codec::b64url(&descriptor.digest),
        nameplate: record.nameplate.clone(),
        number: format!("{}{}", descriptor.pairing_route, record.nameplate),
        profile_digest: record.profile_digest.clone(),
        protocol: descriptor.pairing_protocol.clone(),
        provider_id: record.provider_id.clone(),
        route: descriptor.pairing_route.clone(),
        version: 1,
    };
    let binding_hash = binding.binding_hash();

    // The disclosure the pure core requires before it will permit an approval.
    // `record_pairing_target_disclosure` takes a value only
    // `resolve_pairing_target` can construct, so an approval cannot be attached
    // to an application/origin tuple this command invented.
    let mut ceremony = Ceremony::new(Role::Wallet, binding_hash, CeremonyValues::new());
    ceremony
        .record_pairing_target_disclosure(
            pairing_policy::resolve_pairing_target(&claim, &fetched.profile)
                .map_err(|_| UiError::from("PairingProviderUnknown"))?,
        )
        .map_err(|_| UiError::from("PairingBurned"))?;

    let expires_at = expires_at(&record);
    let view = PairingTarget {
        claimed_origin: application_id.origin().to_owned(),
        claimed_application_id: application_id.as_str().to_owned(),
        nameplate: record.nameplate.clone(),
        provider_id: record.provider_id.clone(),
        pairing_url: descriptor.pairing_url.clone(),
        binding_hash: selfsame_app_identity::codec::b64url(&binding_hash),
        expires_in: (expires_at - now() as i64).max(0),
    };

    let pending = PendingPairing {
        code,
        ceremony,
        binding_hash,
        origins: BoundOrigins::of(descriptor),
        nameplate: record.nameplate,
        provider_id: record.provider_id,
        descriptor_digest: binding.descriptor_digest.clone(),
        profile_digest: record.profile_digest,
        profile: fetched.octets,
        expires_at,
        answered: None,
    };

    // A second scan replaces the first outright. `CON-218` has one retry
    // transition — `burned -> new ceremony` — and the ceremony being replaced
    // has claimed nothing, sent no frame and derived no key, so dropping it here
    // *is* abandoning it. Nothing about it can be reused: `REQ-229` requires a
    // retry to regenerate every value, and this one regenerates all of them
    // because it starts from a different `C`.
    session.0.lock().unwrap_or_else(|p| p.into_inner()).pending_pairing = Some(pending);
    Ok(view)
}

// ── CON-405 to CON-408: the answer ──────────────────────────────────────────

/// What a completed pairing hands to the grant commands.
///
/// The three arguments `app_grant_review` and `app_grant_prepare` take, produced
/// together so the page cannot pair them up wrongly — an offer from one ceremony
/// beside the profile of another is a transposition the type would otherwise
/// permit.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnsweredPairing {
    /// The offer payload octets, opened from the mailbox and already recognised.
    pub offer: Vec<u8>,
    /// The profile octets this ceremony is pinned to.
    pub profile: Vec<u8>,
    /// What this wallet observed for itself, as against what the offer asserts.
    pub observed: crate::app_grant::CeremonyObservation,
}

/// Answer a pairing: claim the nameplate, run SPAKE2 as role B, and open the
/// offer.
///
/// This is the "this is me" action, and it is where the ceremony stops being
/// reversible. `CON-407`'s state sequence for this role is
/// `claim -> pA locked -> pB stored -> cA verified -> cB stored -> confirmed`,
/// and every step of it is below in that order.
///
/// **Every failure burns.** `CON-406` permits a retry only when the client can
/// prove it is byte-identical, uses the same role token, and has not processed a
/// conflicting peer value — which is true of the polling inside
/// [`crate::pairing_net`] and of nothing out here. So the pending ceremony is
/// taken at entry and returned only on success: a failure drops it, which
/// zeroizes the code and the keys and leaves `burned -> new ceremony` as the only
/// way forward.
#[tauri::command]
pub async fn pairing_answer(
    binding_hash: String,
    session: tauri::State<'_, AppSession>,
) -> Result<AnsweredPairing> {
    let mut pending = take(&session, &binding_hash)?;

    match answer(&mut pending).await {
        Ok(answered) => {
            session.0.lock().unwrap_or_else(|p| p.into_inner()).pending_pairing = Some(pending);
            Ok(answered)
        }
        Err(e) => {
            // Dropped, not stored back. There is no state from which this
            // ceremony may be resumed.
            Err(e)
        }
    }
}

async fn answer(pending: &mut PendingPairing) -> Result<AnsweredPairing> {
    if now() as i64 >= pending.expires_at {
        return Err(UiError::from("PairingExpired"));
    }

    // The approval the person just gave. The pure core refuses it unless the
    // target was disclosed first, and refuses every PAKE action until it exists.
    pending.ceremony.record_pairing_target_approval().map_err(|_| UiError::from("PairingBurned"))?;
    pending.ceremony.may(GatedAction::ClaimNameplate).map_err(|_| UiError::from("PairingBurned"))?;

    let relay = Relay::at(&pending.origins.pairing).map_err(relay_token)?;

    // `claim`. The first claim after `pA` exists returns `201`; polling covers
    // the window before the application has stored it.
    relay
        .claim_when_ready(&pending.nameplate, pairing_net::PEER_DEADLINE)
        .await
        .map_err(relay_token)?;

    // `pA locked`. Read before anything is computed from it.
    pending.ceremony.may(GatedAction::PakeFrame).map_err(|_| UiError::from("PairingBurned"))?;
    let p_a = relay.get_frame(&pending.nameplate, Frame::PA).await.map_err(relay_token)?;

    // `pB stored`. `CON-404`: 64 fresh uniform octets per role, reduced to a
    // scalar, redrawn if zero. The caller owns the CSPRNG, so the caller redraws.
    let spake = begin(Party::Wallet, pending.code.octets(), &pending.binding_hash)?;
    let p_b = spake.message();
    relay.put_frame(&pending.nameplate, Frame::PB, &p_b).await.map_err(relay_token)?;

    // `cA verified` — the transition that makes this role confirmed, and
    // `REQ-406`'s one authorization-critical online password guess. A failure
    // here burns locally "even if the provider offers another frame".
    let confirmed = spake.confirm(&p_a).map_err(|_| UiError::from("PairingConfirmationFailed"))?;
    let c_a = relay
        .await_frame(&pending.nameplate, Frame::CA, pairing_net::PEER_DEADLINE)
        .await
        .map_err(relay_token)?;
    let c_b = confirmed.confirmation();
    let mutual =
        confirmed.verify_peer(&c_a).map_err(|_| UiError::from("PairingConfirmationFailed"))?;

    // Recorded against the policy core as the APPLICATION's confirmation,
    // because that is who produced it. A party is never authenticated by its own
    // MAC, and `REQ-229` allows exactly one initiator confirmation per minted
    // ceremony — the counter behind this call is what bounds active guessing.
    pending
        .ceremony
        .accept_confirmation(Confirmation { role: Role::Application, binding_hash: pending.binding_hash })
        .map_err(|_| UiError::from("PairingBurned"))?;

    // `cB stored`. Written only after `cA` verified, per `CON-407`.
    relay.put_frame(&pending.nameplate, Frame::CB, &c_b).await.map_err(relay_token)?;

    // `CON-408`, and the gate before it. Nothing above this line derived a
    // mailbox slot or touched `K`.
    pending.ceremony.may(GatedAction::RequestMailboxSlot).map_err(|_| UiError::from("PairingBurned"))?;
    let mailbox_secret = mutual.mailbox_secret();
    let keys = EnvelopeKeys::derive(&mailbox_secret, &pending.binding_hash)
        .map_err(|_| UiError::from("EnvelopeMalformed"))?;

    // `CON-302`'s slot, from the confirmed secret and never from the code.
    let slot = seal::slot(seal::Role::Offer, &mailbox_secret);
    let sealed = pairing_net::await_slot(
        &pending.origins.mailbox,
        &slot,
        pairing_net::OFFER_DEADLINE,
    )
    .await
    .map_err(relay_token)?;
    let offer = keys.offer.open(&sealed).map_err(envelope_token)?;

    // `CON-214`, run by the wallet over the wallet's OWN pinned profile and its
    // OWN selection — not over anything the page will later hand back. This is
    // what turns the claim in `PairingTarget` into an authenticated application,
    // and it is the transition `CON-217` requires before consent may be shown.
    let observed = crate::app_grant::CeremonyObservation {
        ceremony_profile_digest: pending.profile_digest.clone(),
        provider_id: pending.provider_id.clone(),
        descriptor_digest: pending.descriptor_digest.clone(),
        // `None` is correct and is not a default. `platform_binding_id` is
        // `CON-215`'s same-device attribution; on a cross-device pairing the
        // application is on another machine and this platform reports no caller
        // for it, so claiming one would be inventing evidence.
        platform_binding_id: None,
    };
    let decided = authorise::authorise(
        &offer,
        &pending.profile,
        &Observation {
            ceremony_profile_digest: &observed.ceremony_profile_digest,
            provider_id: &observed.provider_id,
            descriptor_digest: &observed.descriptor_digest,
            platform_binding_id: None,
            now: now() as i64,
        },
    )
    .map_err(crate::app_grant::token)?;

    pending
        .ceremony
        .record_application_authenticated()
        .map_err(|_| UiError::from("PairingBurned"))?;
    // Belt and braces, and cheap: the screen this returns to is the consent
    // screen, and `CON-217` gates showing one on both halves.
    pending.ceremony.may(GatedAction::DisplayConsent).map_err(|_| UiError::from("PairingBurned"))?;

    pending.answered = Some(Answered {
        bundle_key: Some(keys.bundle),
        mailbox_secret,
        offer: decided.offer,
    });

    Ok(AnsweredPairing { offer, profile: pending.profile.clone(), observed })
}

/// Draw an ephemeral and begin, redrawing on the zero scalar (`CON-404`).
fn begin(party: Party, wib: &[u8; 16], binding_hash: &[u8; 32]) -> Result<Spake2> {
    for _ in 0..4 {
        let mut ephemeral = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut ephemeral);
        let begun = Spake2::begin(party, wib, binding_hash, &ephemeral);
        ephemeral.zeroize();
        match begun {
            Ok(spake) => return Ok(spake),
            // "redrawing if the result is zero". Four draws rather than an
            // unbounded loop: the probability of one zero is about 2^-252, so a
            // second is not a retry condition, it is a broken CSPRNG.
            Err(selfsame_core::spake2::Spake2Error::ZeroEphemeral) => continue,
            Err(_) => return Err(UiError::from("PairingConfirmationFailed")),
        }
    }
    Err(UiError::from("PairingConfirmationFailed"))
}

// ── CON-408 and CON-502: the bundle goes back ───────────────────────────────

/// Seal the signed bundle and write it to the mailbox.
///
/// Takes the bundle `app_grant_confirm` released. The identifiers in it must be
/// the ones **this ceremony's** offer carried: `CON-219` says a bundle that does
/// not match "is a rejection, not a new ceremony", and here that check is also
/// what stops a grant prepared against some other offer from being delivered
/// into this mailbox.
#[tauri::command]
pub async fn pairing_deliver(
    binding_hash: String,
    bundle: Vec<u8>,
    session: tauri::State<'_, AppSession>,
) -> Result<()> {
    // Taken, not borrowed. A ceremony delivers at most one bundle, and a second
    // call finds nothing rather than writing again.
    let mut pending = take(&session, &binding_hash)?;

    // `CON-217`: the bundle gate needs the confirmation *and* `CON-214`
    // authentication, which `pairing_answer` recorded only because it verified
    // the evidence itself.
    pending.ceremony.may(GatedAction::SendGrantBundle).map_err(|_| UiError::from("PairingBurned"))?;
    let answered = pending.answered.as_mut().ok_or_else(|| UiError::from("PairingBurned"))?;

    let payload = ceremony::recognise_bundle(&bundle).map_err(|_| UiError::from("OfferMalformed"))?;
    ceremony::bundle_matches_offer(&payload, &answered.offer)
        .map_err(|_| UiError::from("OfferMalformed"))?;

    let key = answered.bundle_key.take().ok_or_else(|| UiError::from("PairingBurned"))?;
    let sealed = key.seal(&bundle).map_err(envelope_token)?;
    let slot = seal::slot(seal::Role::Bundle, &answered.mailbox_secret);

    pairing_net::put_slot(&pending.origins.mailbox, &slot, sealed).await.map_err(relay_token)?;

    // `CON-407`: after a terminal success the code, ephemerals, `K`, tokens and
    // derived mailbox secret are zeroized. Dropping `pending` is all of that —
    // and the ceremony is over either way, since `CON-218`'s only retry
    // transition is to a new one.
    Ok(())
}

/// Burn a ceremony the person declined, without touching the relay.
///
/// `CON-218`: decline "has no retry transition inside this ceremony: it burns
/// before a nameplate claim, PAKE frame, mailbox action, or grant can occur." So
/// nothing here contacts the provider — a decline that announced itself would
/// tell an unauthenticated party that a real wallet resolved its record.
#[tauri::command]
pub async fn pairing_decline(
    binding_hash: String,
    session: tauri::State<'_, AppSession>,
) -> Result<()> {
    let mut pending = take(&session, &binding_hash)?;
    pending.ceremony.decline_pairing_target().map_err(|_| UiError::from("PairingBurned"))?;
    Ok(())
}

// ── the plumbing ────────────────────────────────────────────────────────────

/// Take the named ceremony out of the session.
///
/// Naming it matters: a command that operated on "whatever is pending" would act
/// on a ceremony the person is not looking at, which is the same defect
/// `app_grant_confirm` refuses by comparing `ceremony_id`.
fn take(session: &tauri::State<'_, AppSession>, binding_hash: &str) -> Result<PendingPairing> {
    let mut guard = session.0.lock().unwrap_or_else(|p| p.into_inner());
    let pending = guard.pending_pairing.take().ok_or_else(|| UiError::from("PairingUnknown"))?;
    if selfsame_app_identity::codec::b64url(&pending.binding_hash) != binding_hash {
        // Dropped rather than replaced: the caller named a ceremony this wallet
        // is not running, and the one it *was* running is now unreferenced.
        return Err(UiError::from("PairingUnknown"));
    }
    if pending.ceremony.is_burned() {
        return Err(UiError::from("PairingBurned"));
    }
    Ok(pending)
}

/// Map a transport outcome onto the closed token set the screens render.
fn relay_token(e: RelayError) -> UiError {
    UiError::from(match e {
        RelayError::Unreachable => "PairingProviderUnreachable",
        RelayError::ProtocolViolation => "PairingProviderRefused",
        // At a caller, "not yet" has already outlived its deadline.
        RelayError::NotYet | RelayError::Expired => "PairingExpired",
        RelayError::Conflict => "PairingConflict",
    })
}

/// `CON-504`'s externally visible collapse.
fn envelope_token(e: selfsame_core::envelope::EnvelopeError) -> UiError {
    UiError::from(match e {
        selfsame_core::envelope::EnvelopeError::AuthFailed => "EnvelopeAuthFailed",
        selfsame_core::envelope::EnvelopeError::Malformed => "EnvelopeMalformed",
        selfsame_core::envelope::EnvelopeError::PayloadTooLarge => "PayloadTooLarge",
    })
}

fn expires_at(record: &MeetingRecord) -> i64 {
    selfsame_app_identity::time::parse_date_time_stamp(&record.expires_at).unwrap_or(0)
}

/// The record envelope, as the host serves it.
struct Envelope {
    payload: Vec<u8>,
    signature: [u8; 64],
}

/// Fetch and decode the envelope at a meeting address.
///
/// Nothing here checks the signature: that is the caller's, against an address
/// this wallet derived. A fetch that verified would be verifying against
/// whatever the response claimed the address was.
async fn resolve_record(address: &str) -> Result<Envelope> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        payload: String,
        signature: String,
    }

    let host = record_host();
    let response = reqwest::Client::builder()
        .timeout(RESOLVE_DEADLINE)
        .build()
        .map_err(|_| UiError::from("PairingRecordUnavailable"))?
        .get(format!("{host}/pairing/records/{address}"))
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|_| UiError::from("PairingRecordUnavailable"))?;
    if !response.status().is_success() {
        // `CON-409`: a code that resolves no record returns
        // `PairingRecordUnavailable`, and a resolving party SHALL NOT search
        // installed applications, historic profiles, provider lists, DNS
        // guesses, or any other endpoint for a match, nor retry with a mutated
        // code. So this is where it stops.
        return Err(UiError::from("PairingRecordUnavailable"));
    }
    let body = response
        .bytes()
        .await
        .map_err(|_| UiError::from("PairingRecordUnavailable"))?;
    if body.len() > MAX_ENVELOPE_OCTETS {
        return Err(UiError::from("PairingRecordUnavailable"));
    }
    let wire: Wire =
        serde_json::from_slice(&body).map_err(|_| UiError::from("PairingRecordUnavailable"))?;

    use base64ct::Encoding as _;
    let payload = base64ct::Base64UrlUnpadded::decode_vec(&wire.payload)
        .map_err(|_| UiError::from("PairingRecordUnavailable"))?;
    let signature: [u8; 64] = base64ct::Base64UrlUnpadded::decode_vec(&wire.signature)
        .map_err(|_| UiError::from("PairingRecordUnavailable"))?
        .try_into()
        .map_err(|_| UiError::from("PairingRecordUnavailable"))?;
    Ok(Envelope { payload, signature })
}

/// Where records are resolved from.
///
/// A deployment declares record hosts in its profile's `pairingRecordRelays`,
/// but a wallet has no profile until step 6 — it needs a host to resolve the
/// record that names the application whose profile it would read. So the host is
/// a wallet-side setting rather than a profile-side one, exactly as the
/// `CON-208` endpoint table is, and for the same reason: nothing in a code is an
/// address.
fn record_host() -> String {
    std::env::var("SELFSAME_PAIRING_RECORDS")
        .unwrap_or_else(|_| "https://rendezvous.cbcl.chat".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The view names the claim as a claim.
    ///
    /// A field called `application_id` on a consent screen is read as "this is
    /// who is asking". `CON-409` says it is not, and no code in this file can
    /// make it so — the name is the only place that distinction survives being
    /// passed to a designer.
    #[test]
    fn the_target_names_the_application_as_claimed() {
        let json = serde_json::to_string(&PairingTarget {
            claimed_application_id: "https://chat.anuna.io/selfsame/application".into(),
            claimed_origin: "https://chat.anuna.io".into(),
            nameplate: "482715".into(),
            provider_id: "dev-local".into(),
            pairing_url: "https://localhost:8443".into(),
            binding_hash: "x".into(),
            expires_in: 300,
        })
        .unwrap();
        assert!(json.contains("claimedApplicationId"));
        assert!(json.contains("claimedOrigin"));
        assert!(
            !json.contains("\"applicationId\""),
            "an unqualified applicationId would read as verified",
        );
    }

    /// `CON-407`: the code lives in process-private memory.
    ///
    /// The view is the whole of what crosses to the page, so this is a test that
    /// a future field cannot be added without someone reading this line. `C` in
    /// the webview is `C` in the least trustworthy process in the system, and it
    /// is the SPAKE2 password.
    #[test]
    fn nothing_secret_reaches_the_page() {
        let fields = serde_json::to_value(&PairingTarget {
            claimed_application_id: "https://chat.anuna.io/selfsame/application".into(),
            claimed_origin: "https://chat.anuna.io".into(),
            nameplate: "482715".into(),
            provider_id: "dev-local".into(),
            pairing_url: "https://localhost:8443".into(),
            binding_hash: "x".into(),
            expires_in: 300,
        })
        .unwrap();
        let mut names: Vec<_> =
            fields.as_object().unwrap().keys().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "bindingHash",
                "claimedApplicationId",
                "claimedOrigin",
                "expiresIn",
                "nameplate",
                "pairingUrl",
                "providerId",
            ],
        );
    }
}
