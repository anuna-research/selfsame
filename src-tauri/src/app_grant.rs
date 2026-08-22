//! Issuing a `SPEC-004` device grant — the phone's half of Path B.
//!
//! This is the command `FINDING-016` made unwritable. Until hierarchy version 2
//! the wallet held no material from which an application-account home key could
//! be derived, so there was nothing to sign a grant *with*; `grant::issue` was
//! reachable only from test fixtures. `ADR-223` closed that, and this module is
//! what it unblocked.
//!
//! # What this is, and what it deliberately is not
//!
//! It is the **decision and the signature**: recognise the offer, verify the
//! application is who it claims, derive the account's home key, mint the
//! credential, and hand back the bundle payload.
//!
//! It is **not the transport**. The cbcl encrypted channel is separate, so this
//! takes offer octets that the shell has already opened and returns bundle
//! octets for the shell to send. That split is the same one `selfsame-core` draws for
//! `SPEC-001`, and it is why this module reads no clock beyond `now()`, opens no
//! socket, and holds no state.
//!
//! # What is here and what is next door
//!
//! Recognition, verification, binding and freshness are one decision and they
//! live in [`selfsame_app_identity::authorise`], not here. That is the
//! dependency rule this repository states — the pure core decides, the shell
//! does I/O — and it is load-bearing rather than tidy: written in this module
//! the decision could only be tested by standing up a keychain, so it had no
//! tests at all. Next door it has eight, over fixtures this crate cannot build.
//!
//! What the shell owes the core is **observations** — things it saw for itself
//! rather than read from the offer: the `profileDigest` this ceremony is bound
//! to, the provider and descriptor it selected, and the caller identity the
//! platform reported. An earlier version passed none of them, which meant the
//! decision verified that whoever supplied the profile had signed their own
//! statement with their own key. See
//! [[g2-grant-issuance-review-disposition]].
//!
//! What remains here is what genuinely needs a device:
//!
//! 1. **`REQ-002`'s gate** — an identity whose phrase has not been written down
//!    does not issue authority that outlives the device holding it.
//! 2. **Presence and the sealed root** — `Custody::use_hierarchy_root`, inside
//!    whose closure the home key exists and nowhere else.
//! 3. **The signature** (`CON-205`) and the bundle (`CON-219`).
//!
//! A failure at any step returns a closed token and leaves nothing behind: no
//! grant, no durable write, no partial bundle.

use selfsame_app_identity::{
    alias::AcctUri,
    authorise::{self, AuthoriseError, Observation},
    ceremony,
    confirm::{self, Applicability, AuthorityState, Response},
    grant, hierarchy, issuer,
};
use selfsame_app_identity_net::state::SignedClosure;

use crate::commands::{now, UiError};
use crate::custody::Custody;

type Result<T> = std::result::Result<T, UiError>;

/// What the wallet hands back to the shell to seal and send.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorisedGrant {
    /// The `CON-219` bundle payload for the cbcl channel to carry.
    pub bundle: Vec<u8>,
    /// The account this grant was issued under, as an RFC 7565 `acct:` URI.
    ///
    /// Returned so the screen can show the person which identity they just
    /// authorised a device for, without the shell recomputing it from a DID and
    /// risking a second derivation that disagrees with the signed one.
    pub account: String,
    /// The application-account home DID that issued it.
    pub issuer: String,
    /// When the grant stops being valid, seconds since the epoch.
    pub valid_until: i64,
    /// Whether the issuer's deltas reached a declared `stateResolvers` entry.
    ///
    /// Always `false` today, and reported rather than hidden. `CON-206` step 4
    /// prefers a resolver and treats the bundled closure as *"a bootstrap for a
    /// first ceremony on a degraded network, not a standing arrangement"* — a
    /// verifier may lean on the bundle only at a grant's first acceptance with
    /// no resolver reachable.
    ///
    /// Publication needs a conforming `did:crdt` resolver, and none is deployed:
    /// that is `G6` of the Path-B readiness review. A caller can see from this
    /// field that it is relying on the bootstrap, which is better than a
    /// silence it would have to infer.
    pub published: bool,
}

/// A grant that is signed and deliberately not yet handed over.
///
/// `CON-221` requires the person to compare fingerprints *"after deriving the
/// home DID and before writing the grant bundle"*. Signing is not writing the
/// bundle, and holding the credential here rather than re-deriving means one
/// presence prompt rather than two.
///
/// If the person rejects, this is dropped and nothing was ever transmitted, so
/// no authority was conferred by having signed it.
pub struct PendingIssuance {
    compact: String,
    identity: issuer::IssuerIdentity,
    ceremony_id: String,
    request_id: String,
    valid_until: i64,
    /// SPEC-008 ADR-912 inputs, recorded as the pairing-trust entry on
    /// release: the CON-201-authenticated profile octets (verified inside
    /// `authorise` before any key was touched), the canonical application
    /// id, and the account scope this grant's account derives from.
    trust_application_id: String,
    trust_profile_octets: Vec<u8>,
    trust_account_scope: String,
    /// The offer's own expiry. A preparation started shortly before it, or a
    /// prompt left open, must not still release a long-lived grant afterwards —
    /// so the deadline travels with the pending state and is compared at
    /// release. Without it `Response::TimedOut` is unreachable and any later
    /// `confirmed = true` becomes `Confirmed`.
    expires_at: i64,
}

/// A first-contact CON-219 enrolment fetched from the rendezvous and reviewed,
/// held between the consent screen and the person's decision (`IMPL-008`
/// `ADR-913`).
///
/// Never exposed to the page: `offer_plaintext` carries the private account
/// scope, and `secret` addresses the mailbox slots. The whole point of holding
/// it server-side is that the JS drives the enrolment by ceremony id alone and
/// never sees either.
pub struct PendingEnrolment {
    /// The 16-octet link secret, for the bundle slot and its sealing.
    secret: [u8; 16],
    /// The opened CON-219 offer plaintext.
    offer_plaintext: Vec<u8>,
    /// The live-fetched, CON-201-authenticated profile octets.
    profile_octets: Vec<u8>,
    /// The observation built from the offer (`platform_binding_id: None`).
    observed: CeremonyObservation,
    /// The application whose compiled endpoint carries the mailbox.
    application: selfsame_core::record::Application,
}

/// What the shell observed for itself, as against what the offer asserts.
///
/// Mirrors [`authorise::Observation`] and exists for the same reason: every
/// field is something the caller obtained independently of the offer payload,
/// and grouping them says so at the call site. It also keeps the commands under
/// clippy's argument bound — which is a real signal here rather than a lint to
/// silence, since a command taking eight loose values is one whose caller can
/// transpose two of them.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CeremonyObservation {
    /// The `profileDigest` this ceremony is bound to.
    pub ceremony_profile_digest: String,
    /// The provider the shell selected, per `CON-208`.
    pub provider_id: String,
    /// `SHA-256` of that descriptor, base64url.
    pub descriptor_digest: String,
    /// The caller identity the platform reported, where it reports one.
    pub platform_binding_id: Option<String>,
}

impl CeremonyObservation {
    pub fn as_observation(&self, now: i64) -> Observation<'_> {
        Observation {
            ceremony_profile_digest: &self.ceremony_profile_digest,
            provider_id: &self.provider_id,
            descriptor_digest: &self.descriptor_digest,
            platform_binding_id: self.platform_binding_id.as_deref(),
            now,
        }
    }
}

/// Build the ceremony observation for a first-contact enrolment offer opened
/// from the rendezvous (`IMPL-008` `ADR-913`).
///
/// The observation the held-path tests thread in from an OS adapter has, on
/// the cross-device enrolment path, exactly one honest source: the opened
/// offer itself, plus the fact that no OS attributed a caller. The offer
/// carries a **real** `applicationId` and the profile digest it committed to;
/// the provider fields come from its authenticated `provider_hint`; and
/// `platform_binding_id` is `None` because a pasted or scanned code is the
/// unattributed manual path — which is exactly the caller evidence a
/// [[SPEC-004-application-scoped-identity#CON-227]] web binding accepts and any
/// native binding refuses. Nothing here is taken on trust that the pure
/// `authorise` does not then re-verify against the freshly fetched profile.
pub fn observation_for_enrolment_offer(
    offer: &ceremony::OfferPayload,
    profile: &selfsame_app_identity::profile::ApplicationProfile,
) -> Result<CeremonyObservation> {
    let hint = selfsame_app_identity::provider_hint::ProviderHint::recognise(&offer.provider_hint)
        .map_err(|_| UiError::from("OfferMalformed"))?;

    // Codex review, finding "undeclared providers pass": the observation is
    // supposed to be what the shell established INDEPENDENTLY, but for first
    // contact the provider fields have only the offer's own hint as a source.
    // `authorise` compares the statement to these copied values without
    // establishing the provider exists in the profile, so a hostile producer
    // (or the signing oracle) could name an undeclared provider. Verify the hint
    // against the freshly fetched profile and the offer's own digest here — the
    // exact check the honest `build_offer` producer runs — so the values passed
    // on are profile-anchored, not offer-asserted.
    hint.verify(profile, &offer.offer_digest)
        .map_err(|_| UiError::from("ProviderMismatch"))?;

    // Codex review, finding 2: `platform_binding_id: None` is NOT self-evidently
    // the web path — Apple's CON-223 carve-out also accepts `None`, so an offer
    // whose CON-214 statement names an `apple:` binding would be admitted over
    // the manual transport, downgrading a native binding. The manual path
    // attributes no caller precisely because it IS the web binding, so require
    // the statement to name one: recognise the evidence and refuse any binding
    // that is not `web:`. A native binding belongs to its OS adapter, never to a
    // pasted or scanned code.
    let (statement, _) = selfsame_app_identity::enrollment::recognise(&offer.enrollment_evidence)
        .map_err(|_| UiError::from("OfferMalformed"))?;
    if !statement.platform_binding_id.starts_with("web:") {
        return Err(UiError::from("PlatformBindingMismatch"));
    }

    Ok(CeremonyObservation {
        ceremony_profile_digest: offer.core.profile_digest.clone(),
        provider_id: hint.provider_id,
        descriptor_digest: hint.descriptor_digest,
        // The manual cross-device path attributes no caller. Verified above to
        // carry a web binding, so `None` is the CON-227 unattributed case a web
        // binding accepts — and no native binding can reach here.
        platform_binding_id: None,
    })
}

/// What a person is being asked to approve, before they approve it.
///
/// `CON-221` and the consent screens need this *before* any signature exists,
/// so recognition and verification are split from issuance. A caller that
/// skipped straight to [`app_grant_issue`] would be asking the person to
/// approve something nobody had checked.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantRequestView {
    /// The application's canonical identifier.
    pub application_id: String,
    /// The permissions it is asking for, exactly as they will appear in the
    /// credential.
    pub permissions: Vec<String>,
    /// The device that will hold the grant, as a `did:key`.
    pub device_did: String,
    /// Seconds until the offer expires.
    pub expires_in: i64,
}

/// Recognise and verify an offer, returning what the consent screen must show.
///
/// Takes no passcode and derives nothing: this runs before the person has
/// decided, and a command that unsealed custody in order to render a screen
/// would put a presence prompt in front of a question the person has not been
/// asked yet.
#[tauri::command]
pub async fn app_grant_review(
    offer: Vec<u8>,
    profile: Vec<u8>,
    observed: CeremonyObservation,
) -> Result<GrantRequestView> {
    let decided = authorise::authorise(&offer, &profile, &observed.as_observation(now() as i64))
        .map_err(token)?;

    // Reported, not consumed: a person looking at a consent screen has decided
    // nothing, and a review that burned the id would make the offer unusable by
    // the act of showing it.
    if crate::replay::is_consumed(&decided.offer.request_id, decided.valid_from)
        .map_err(|_| UiError::from("GrantIssuanceFailed"))?
    {
        return Err(UiError::from("EnrollmentReplay"));
    }

    Ok(GrantRequestView {
        application_id: decided.profile.application_id.as_str().to_owned(),
        permissions: decided.offer.requested_permissions,
        device_did: decided.offer.device_did,
        expires_in: decided.offer.expires_at - decided.valid_from,
    })
}

/// Map the core's closed refusal onto the token the screens already render.
///
/// One arm per variant and no catch-all, so a variant added upstream fails to
/// compile here rather than silently becoming whatever the wildcard said.
pub(crate) fn token(e: AuthoriseError) -> UiError {
    UiError::from(match e {
        AuthoriseError::UnverifiedApplication => "UnverifiedApplication",
        AuthoriseError::OfferMalformed => "OfferMalformed",
        AuthoriseError::OfferExpired => "OfferExpired",
        AuthoriseError::ScopeNotCanonical => "ScopeNotCanonical",
        AuthoriseError::ProfileNotBound => "ProfileNotBound",
        AuthoriseError::HintMismatch => "HintMismatch",
    })
}

/// What the confirmation screen must show, and whether it must show anything.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmationRequest {
    /// `"required"`, `"notRequired"`, or `"failClosed"`.
    pub applicability: String,
    /// **The value the person compares**, and the recognition aids shown beside
    /// it.
    ///
    /// `SPEC-002` `REQ-103` makes `hex` the normative rendering; the LifeHash
    /// and the label are never the thing being compared. All three are returned
    /// together because the screen cannot compute them: the issuer DID stays
    /// private until confirmation, so the shell cannot call `home_fingerprint`,
    /// and deriving a second rendering in the frontend is exactly the
    /// duplicate-implementation this repository refuses. `CON-221` requires the
    /// LifeHash beside the hex, so withholding it makes the screen
    /// unimplementable rather than merely plainer.
    pub fingerprint: Option<crate::commands::Fp>,
    /// The account this would be, for the screen to name.
    pub account: String,
    /// The ceremony this preparation belongs to.
    ///
    /// Returned so [`app_grant_confirm`] can be told which preparation the
    /// person actually looked at.
    pub ceremony_id: String,
}

/// Issue the grant. The one place a `SPEC-004` credential is signed.
///
/// `REQ-002`'s gate applies for the same reason it applies to SPEC-001 linking:
/// an identity whose recovery phrase has not been written down must not be the
/// issuer of authority that outlives the device holding it.
#[tauri::command]
pub async fn app_grant_prepare(
    offer: Vec<u8>,
    profile: Vec<u8>,
    observed: CeremonyObservation,
    passcode: String,
    session: tauri::State<'_, crate::commands::AppSession>,
) -> Result<ConfirmationRequest> {
    prepare_issuance(&offer, profile, &observed, &passcode, &session).await
}

/// Sign the grant and stash it pending `CON-221`, from offer/profile/observation
/// the caller has already assembled.
///
/// Factored out of [`app_grant_prepare`] so the first-contact enrolment path
/// (`IMPL-008` `ADR-913`) drives the identical signing, replay, and authority
/// logic from a rendezvous-fetched offer rather than one handed in by the page —
/// the two must not diverge, because a second copy of this is a second place the
/// `CON-221` gate could be forgotten.
async fn prepare_issuance(
    offer: &[u8],
    profile: Vec<u8>,
    observed: &CeremonyObservation,
    passcode: &str,
    session: &tauri::State<'_, crate::commands::AppSession>,
) -> Result<ConfirmationRequest> {
    Custody::require_backup_confirmed()?;

    // Every recognition, verification, binding and freshness check is the pure
    // core's, and it has already run by the time a key is touched.
    let decided = authorise::authorise(offer, &profile, &observed.as_observation(now() as i64))
        .map_err(token)?;

    // `CON-214` step 5, and it happens **before** the key is touched. A ledger
    // updated after signing has already let the second signature happen.
    crate::replay::consume(
        &decided.offer.request_id,
        decided.offer.expires_at,
        decided.valid_from,
    )
    .map_err(|e| match e {
        crate::replay::ReplayError::Replay => UiError::from("EnrollmentReplay"),
        _ => UiError::from("GrantIssuanceFailed"),
    })?;

    // `CON-205`: independent for every grant, and never derived from the device
    // key, the scope, a timestamp, or recovery material.
    let mut grant_token = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut grant_token);

    // Presence, then the key — which exists only inside this closure.
    let (compact, identity) = Custody::use_hierarchy_root(passcode, |root| {
        let home = hierarchy::derive(root, &decided.profile.application_id, &decided.scope);

        // `CON-203`, both stages. Until this existed the wallet signed with a
        // key whose `did:crdt` document had never been constructed, so every
        // grant it produced was unverifiable at `CON-206` step 4 — F3 of the
        // review.
        let identity = issuer::create(
            home.signing_key(),
            &decided.profile.account_authority,
            (decided.valid_from as u64) * 1_000,
        )
        .map_err(|_| UiError::from("GrantIssuanceFailed"))?;

        // `CON-206` step 6 would refuse every bundle built from this closure:
        // the grant's `kid` is `#jwk-0` and the document authorises `#key-0`.
        // Refusing here is the whole difference between a gate and a hope — a
        // grant that fails at the recipient surfaces later and somewhere else,
        // and by then a person believes they linked a device.
        if !identity.authorises_grants {
            return Err(UiError::from("IssuerKeyProjectionUnavailable"));
        }

        let home_did = identity.did.clone();
        let account =
            AcctUri::parse(&identity.acct_uri).map_err(|_| UiError::from("GrantIssuanceFailed"))?;

        let compact = grant::issue(
            home.signing_key(),
            &home_did,
            &grant_token,
            &decided.offer.device_did,
            &decided.offer.device_public_key,
            &decided.profile.application_id,
            &account,
            &decided.offer.requested_permissions,
            decided.valid_from,
            decided.valid_until,
        );
        Ok::<_, UiError>((compact, identity))
    })??;

    // `CON-221`: determined from **authority state**, never from local cache,
    // and an unreachable authority is `Unknown` rather than an assumption of
    // first use. Failing closed here costs a retry; guessing costs the one
    // comparison that stands between a person and a substituted issuer.
    let authority = authority_state(&identity.acct_uri, &identity.did).await;
    let applicability = Applicability::decide(authority, &identity.did);

    let request = ConfirmationRequest {
        applicability: match &applicability {
            Applicability::Required(_) => "required",
            Applicability::NotRequired => "notRequired",
            Applicability::FailClosed => "failClosed",
        }
        .to_owned(),
        fingerprint: match &applicability {
            Applicability::Required(_) => {
                Some(selfsame_core::fingerprint::fingerprint_did(&identity.did).into())
            }
            _ => None,
        },
        account: identity.acct_uri.clone(),
        ceremony_id: decided.offer.ceremony_id.clone(),
    };

    if matches!(applicability, Applicability::FailClosed) {
        return Err(UiError::from("AuthorityUnreachable"));
    }

    let mut guard = session.0.lock().unwrap_or_else(|p| p.into_inner());

    // A second preparation must not silently displace a prompt the person is
    // looking at: confirming the displayed request would then release a
    // different signed bundle. An overlapping ceremony is refused rather than
    // allowed to overwrite, and the earlier one is left intact — it expires on
    // its own.
    if let Some(existing) = &guard.pending_issuance {
        if existing.expires_at > decided.valid_from
            && existing.ceremony_id != decided.offer.ceremony_id
        {
            return Err(UiError::from("CeremonyInProgress"));
        }
    }

    guard.pending_issuance = Some(PendingIssuance {
        compact,
        identity,
        ceremony_id: decided.offer.ceremony_id,
        request_id: decided.offer.request_id,
        valid_until: decided.valid_until,
        expires_at: decided.offer.expires_at,
        trust_application_id: decided.profile.application_id.as_str().to_owned(),
        trust_profile_octets: profile,
        trust_account_scope: decided.scope.as_str().to_owned(),
    });

    Ok(request)
}

/// Release the bundle, once the person has compared what `CON-221` asks them to.
///
/// Separate from [`app_grant_prepare`] because the comparison is a person's, and
/// a single command could only have asked them after the fact. `NotRequired`
/// still comes through here so there is one place a bundle is written.
#[tauri::command]
pub async fn app_grant_confirm(
    ceremony_id: String,
    confirmed: bool,
    session: tauri::State<'_, crate::commands::AppSession>,
) -> Result<AuthorisedGrant> {
    confirm_issuance(&ceremony_id, confirmed, &session)
}

/// Release the bundle for a confirmed ceremony. Shared by
/// [`app_grant_confirm`] and the first-contact enrolment path, which then also
/// writes the bundle back to the rendezvous.
fn confirm_issuance(
    ceremony_id: &str,
    confirmed: bool,
    session: &tauri::State<'_, crate::commands::AppSession>,
) -> Result<AuthorisedGrant> {
    let pending = {
        let mut guard = session.0.lock().unwrap_or_else(|p| p.into_inner());
        // Taken, not borrowed: one preparation yields at most one bundle, and a
        // second call finds nothing rather than re-releasing the same grant.
        let pending = guard
            .pending_issuance
            .take()
            .ok_or_else(|| UiError::from("NothingToConfirm"))?;
        // And it must be the ceremony the person was shown. Without this the
        // caller is confirming "whatever is pending", which is a different
        // question from the one on the screen.
        if pending.ceremony_id != *ceremony_id {
            return Err(UiError::from("NothingToConfirm"));
        }
        pending
    };

    // `CON-221`'s timeout is a real outcome, not a UI nicety: a prompt left open
    // past the ceremony's own expiry must not still yield a grant.
    let response = if now() as i64 >= pending.expires_at {
        Response::TimedOut
    } else if confirmed {
        Response::Confirmed
    } else {
        Response::Rejected
    };
    if !confirm::outcome(response).may_proceed {
        // The signed credential is dropped with `pending`. It was never
        // transmitted, so having signed it conferred nothing.
        return Err(UiError::from("ConfirmationRejected"));
    }

    // Serialised here rather than in the pure crate, which excludes `serde` on
    // purpose — a second, more permissive JSON parser beside the strict one is
    // the shotgun-parser shape LangSec Principle 5 rules out. The shape is
    // `did_crdt`'s own and `SignedClosure` is the reader for it, so writer and
    // reader cannot drift.
    let closure = serde_json::to_vec(&SignedClosure {
        target: pending.identity.closure.target.clone(),
        deltas: pending.identity.closure.deltas.clone(),
    })
    .map_err(|_| UiError::from("GrantIssuanceFailed"))?;

    let bundle = ceremony::build_bundle(
        &pending.ceremony_id,
        &pending.request_id,
        &pending.compact,
        Some(&closure),
    )
    .map_err(|_| UiError::from("GrantIssuanceFailed"))?;

    // SPEC-008 ADR-912: a released grant is the wallet's evidence of a real
    // relationship with this application — record its authenticated profile
    // and account scope as the pairing-trust entry. Failure to record does
    // not un-release the grant; the person can re-link to repair it.
    let _ = crate::cbcl_context::record_pairing_trust(
        &pending.trust_application_id,
        &pending.trust_profile_octets,
        &pending.trust_account_scope,
        now() as i64,
    );

    Ok(AuthorisedGrant {
        bundle,
        account: pending.identity.acct_uri,
        issuer: pending.identity.did,
        valid_until: pending.valid_until,
        published: false,
    })
}

// ── First-contact CON-219 enrolment over the rendezvous (IMPL-008 ADR-913) ──
//
// The three commands below are the wallet half of the enrolment wire: they
// fetch a sealed CON-219 offer from the rendezvous the shared addressing points
// at, open it, authenticate the application's profile live from the offer's own
// `applicationId` (CON-220), and drive the *same* review/prepare/confirm the
// held path uses — then write the released bundle back to the mailbox. The
// pairing-trust record `SPEC-008` `REQ-906` consumes is written by
// `confirm_issuance`'s call to `record_pairing_trust`, only after the person
// confirms. Nothing here is a fixture or a second copy of the decision.

/// Recognise a link code, fetch and open its sealed CON-219 offer, authenticate
/// the application profile live, review, and hold it pending consent.
#[tauri::command]
pub async fn cbcl_enrol_start(
    code: String,
    session: tauri::State<'_, crate::commands::AppSession>,
) -> Result<GrantRequestView> {
    use selfsame_core::{code::LinkCode, seal};

    let link = LinkCode::parse(&code).map_err(|_| UiError::from("RecognitionFailed"))?;
    let application = link.application;
    let secret = *link.secret.as_bytes();

    // The rendezvous carries the sealed offer at H(offer-slot). One fetch; the
    // slot is read-once, so a retry needs a fresh code — the CON-002 contract.
    let sealed = crate::net::fetch_offer(application, &secret)
        .await
        .map_err(|_| UiError::from("PairingRelayUnavailable"))?;
    let offer_plaintext = seal::open_offer(&seal::derive_key(&secret), &sealed)
        .map_err(|_| UiError::from("RecognitionFailed"))?;

    enrol_from_opened(offer_plaintext, secret, application, &session).await
}

/// Drive the CON-219 enrolment review from an already-opened offer plaintext.
///
/// Split out of [`cbcl_enrol_start`] because the read-once rendezvous slot is
/// consumed by exactly one fetch/open. The wallet's single code entry
/// ([`crate::commands::read_link_code`]) opens the slot once, then dispatches
/// here when the plaintext is a CON-219 offer rather than a SPEC-001 device
/// offer — so the enrolment path is reachable without a second read that the
/// read-once contract would refuse.
pub(crate) async fn enrol_from_opened(
    offer_plaintext: Vec<u8>,
    secret: [u8; 16],
    application: selfsame_core::record::Application,
    session: &crate::commands::AppSession,
) -> Result<GrantRequestView> {
    // Recognise it as a CON-219 offer (not a SPEC-001 device-link offer). A
    // SPEC-001 offer refuses here and takes the other command's path.
    let offer =
        ceremony::recognise_offer(&offer_plaintext).map_err(|_| UiError::from("OfferMalformed"))?;

    // CON-220: the profile is fetched live from the offer's own `applicationId`,
    // never from the offer, the invitation, or a cache the person never linked.
    // `authorise` below re-verifies the offer's `profileDigest` against exactly
    // these octets, so a substituted profile fails closed.
    let application_id = selfsame_app_identity::profile::ApplicationId::parse(
        &offer.core.application_id,
    )
    .map_err(|_| UiError::from("UnverifiedApplication"))?;
    let fetched = selfsame_app_identity_net::profile::fetch(&application_id, now() as i64)
        .await
        .map_err(|_| UiError::from("PairingProfileUnavailable"))?;
    let observed = observation_for_enrolment_offer(&offer, &fetched.profile)?;
    let profile_octets = fetched.octets;

    // Review — the same pure decision the page's `app_grant_review` runs, and
    // the replay pre-check that keeps a consent screen from burning the id.
    let decided = authorise::authorise(
        &offer_plaintext,
        &profile_octets,
        &observed.as_observation(now() as i64),
    )
    .map_err(token)?;
    if crate::replay::is_consumed(&decided.offer.request_id, decided.valid_from)
        .map_err(|_| UiError::from("GrantIssuanceFailed"))?
    {
        return Err(UiError::from("EnrollmentReplay"));
    }
    let view = GrantRequestView {
        application_id: decided.profile.application_id.as_str().to_owned(),
        permissions: decided.offer.requested_permissions.clone(),
        device_did: decided.offer.device_did.clone(),
        expires_in: decided.offer.expires_at - decided.valid_from,
    };

    session
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .pending_enrolment = Some(PendingEnrolment {
        secret,
        offer_plaintext,
        profile_octets,
        observed,
        application,
    });
    Ok(view)
}

/// Sign the grant for the held enrolment and stash it pending `CON-221`.
#[tauri::command]
pub async fn cbcl_enrol_prepare(
    passcode: String,
    session: tauri::State<'_, crate::commands::AppSession>,
) -> Result<ConfirmationRequest> {
    let (offer_plaintext, profile_octets, observed) = {
        let guard = session.0.lock().unwrap_or_else(|p| p.into_inner());
        let pending = guard
            .pending_enrolment
            .as_ref()
            .ok_or_else(|| UiError::from("NothingToConfirm"))?;
        (
            pending.offer_plaintext.clone(),
            pending.profile_octets.clone(),
            CeremonyObservation {
                ceremony_profile_digest: pending.observed.ceremony_profile_digest.clone(),
                provider_id: pending.observed.provider_id.clone(),
                descriptor_digest: pending.observed.descriptor_digest.clone(),
                platform_binding_id: pending.observed.platform_binding_id.clone(),
            },
        )
    };
    prepare_issuance(&offer_plaintext, profile_octets, &observed, &passcode, &session).await
}

/// Release the confirmed grant and write the sealed bundle back to the mailbox.
#[tauri::command]
pub async fn cbcl_enrol_confirm(
    ceremony_id: String,
    confirmed: bool,
    session: tauri::State<'_, crate::commands::AppSession>,
) -> Result<AuthorisedGrant> {
    use selfsame_core::seal;

    let grant = confirm_issuance(&ceremony_id, confirmed, &session)?;

    // The enrolment context is taken here, so a decline (which returns an error
    // from `confirm_issuance` above and never reaches this line) leaves nothing,
    // and a second confirm finds nothing.
    let pending = session
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .pending_enrolment
        .take()
        .ok_or_else(|| UiError::from("NothingToConfirm"))?;

    // Seal the bundle under the offer transcript and PUT it to the bundle slot,
    // where the browser allocator opens it with `open_bundle_bytes` over the
    // same offer plaintext — the shared `selfsame-core` sealing contract.
    let transcript = seal::transcript(&pending.offer_plaintext);
    let sealed = seal::seal_bundle(&seal::derive_key(&pending.secret), &grant.bundle, &transcript);
    crate::net::put_bundle(pending.application, &pending.secret, sealed)
        .await
        .map_err(|_| UiError::from("PairingRelayUnavailable"))?;

    Ok(grant)
}

/// Ask the account authority whether it already holds a binding (`CON-204`).
///
/// Every failure is `Unknown`, deliberately. `CON-221` requires an unreachable
/// authority to fail closed rather than be read as first use, and collapsing
/// "no binding" with "could not ask" is exactly the substitution the comparison
/// exists to catch.
async fn authority_state(acct_uri: &str, home_did: &str) -> AuthorityState {
    let Ok(acct) = AcctUri::parse(acct_uri) else {
        return AuthorityState::Unknown;
    };

    // `fetch` alone recognises syntax. A JRD that parses but whose `subject`
    // names another account — stale, cache-mixed, or substituted — would
    // otherwise read as `Bound` and suppress the one-time comparison while
    // proving nothing about *this* account. `fetch_and_verify` requires the
    // reciprocal binding `CON-204` defines, in both directions.
    match selfsame_app_identity_net::webfinger::fetch_and_verify(
        &acct,
        home_did,
        &[acct_uri.to_owned()],
    )
    .await
    {
        Ok(_) => AuthorityState::Bound,
        // The authority answered and holds nothing: a first enrolment.
        Err(selfsame_app_identity_net::NetError::NotFound) => AuthorityState::NoBinding,
        // Everything else — unreachable, refused, or an answer that does not
        // bind this account — is "could not ask". `CON-221` requires that to
        // fail closed rather than be read as first use, and a semantic mismatch
        // is precisely the substitution the comparison exists to catch.
        Err(_) => AuthorityState::Unknown,
    }
}

#[cfg(test)]
mod enrolment_observation_tests {
    //! IMPL-008 ADR-913 + codex-review fixes 2 & 9. The observation is built
    //! from the opened offer AND the freshly fetched profile: it verifies the
    //! provider hint against that profile (no undeclared provider passes) and
    //! requires the CON-214 statement to name a web binding (no native-binding
    //! downgrade over the manual path). Offers are built for the real corpus
    //! profile with its enrolment key, so the checks run against a consistent
    //! offer/profile pair rather than a fabricated one.
    use super::*;
    use ed25519_dalek::SigningKey;
    use selfsame_app_identity::ceremony::{OfferCore, OfferPayload};
    use selfsame_app_identity::enrollment::{self as en, EnrollmentStatement};
    use selfsame_app_identity::json::{self, Json};
    use selfsame_app_identity::profile::ApplicationProfile;
    use selfsame_app_identity::provider_hint::ProviderHint;
    use selfsame_app_identity::{codec, didkey};

    const KID: &str = "https://photos.example/selfsame/application#enrollment-test";
    const NOW: i64 = 1_785_412_800;

    fn corpus_profile_octets() -> Vec<u8> {
        let corpus: serde_json::Value =
            serde_json::from_str(include_str!("../../test-vectors/spec-004-v1.json")).unwrap();
        corpus["con_201_application_profile"][0]["input"]["profile"]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    // Build a real offer for the corpus profile. `binding` and `provider`/`digest`
    // are overridable so the negative cases can name a native binding or an
    // undeclared provider.
    fn offer_for(
        profile: &ApplicationProfile,
        binding: &str,
        provider: &str,
        descriptor_digest: &str,
    ) -> OfferPayload {
        let app = profile.application_id.as_str().to_string();
        let origin = profile.application_id.origin();
        let device = SigningKey::from_bytes(&[3u8; 32]).verifying_key().to_bytes();
        let core = OfferCore {
            ceremony_id: codec::b64url(&[1u8; 32]),
            request_id: codec::b64url(&[2u8; 32]),
            application_id: app.clone(),
            profile_version: 1,
            profile_digest: codec::b64url(profile.digest()),
            account_scope_id: codec::b64url(&[4u8; 32]),
            device_did: didkey::encode(&device),
            device_public_key: device,
            requested_permissions: profile.allowed_permissions.clone(),
            issued_at: NOW,
            expires_at: NOW + 120,
        };
        let hint = ProviderHint {
            application_id: app.clone(),
            profile_version: 1,
            provider_id: provider.to_string(),
            descriptor_digest: descriptor_digest.to_string(),
            offer_digest: core.digest(),
        };
        let statement = EnrollmentStatement {
            request_id: core.request_id.clone(),
            ceremony_id: core.ceremony_id.clone(),
            application_id: app.clone(),
            profile_version: 1,
            profile_digest: core.profile_digest.clone(),
            account_scope_id: core.account_scope_id.clone(),
            device_key_digest: en::device_key_digest(&core),
            requested_permissions: core.requested_permissions.clone(),
            provider_id: hint.provider_id.clone(),
            descriptor_digest: hint.descriptor_digest.clone(),
            offer_digest: core.digest(),
            platform_binding_id: binding.to_string(),
            return_uri: format!("{origin}/.well-known/selfsame/return"),
            issued_at: NOW,
            expires_at: NOW + 120,
        };
        let evidence = en::sign(&statement, KID, &SigningKey::from_bytes(&[6u8; 32]));
        OfferPayload {
            core,
            enrollment_evidence: evidence,
            provider_hint: hint.to_json(),
            offer_digest: {
                let Json::Object(_) = hint.to_json() else { unreachable!() };
                // The offer_digest field mirrors the core digest.
                String::new()
            },
        }
    }

    fn declared(profile: &ApplicationProfile) -> (String, String) {
        let d = &profile.cbcl_pairing_relays[0];
        (d.operator_id.clone(), codec::b64url(&d.digest))
    }

    #[test]
    fn a_web_binding_offer_with_a_declared_provider_is_observed() {
        let octets = corpus_profile_octets();
        let profile = ApplicationProfile::recognise(&octets).unwrap();
        let (prov, dig) = declared(&profile);
        let mut offer = offer_for(&profile, &format!("web:{}", profile.application_id.origin()), &prov, &dig);
        offer.offer_digest = offer.core.digest();
        let obs = observation_for_enrolment_offer(&offer, &profile).expect("web + declared provider");
        assert_eq!(obs.provider_id, prov);
        assert_eq!(obs.platform_binding_id, None);
    }

    #[test]
    fn a_native_binding_offer_is_refused_on_the_manual_path() {
        // Finding 2: an apple: binding must not be admitted over the manual path.
        let octets = corpus_profile_octets();
        let profile = ApplicationProfile::recognise(&octets).unwrap();
        let (prov, dig) = declared(&profile);
        let apple = "apple:TEAM123456:com.example.photos:https://photos.example";
        let mut offer = offer_for(&profile, apple, &prov, &dig);
        offer.offer_digest = offer.core.digest();
        assert!(observation_for_enrolment_offer(&offer, &profile).is_err());
    }

    #[test]
    fn an_undeclared_provider_is_refused() {
        // Finding 9: a provider not in the profile must not pass as an observation.
        let octets = corpus_profile_octets();
        let profile = ApplicationProfile::recognise(&octets).unwrap();
        let mut offer = offer_for(
            &profile,
            &format!("web:{}", profile.application_id.origin()),
            "not-a-real-operator",
            &codec::b64url(&[9u8; 32]),
        );
        offer.offer_digest = offer.core.digest();
        assert!(observation_for_enrolment_offer(&offer, &profile).is_err());
    }
}
