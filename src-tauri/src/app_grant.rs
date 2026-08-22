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
    fn as_observation(&self, now: i64) -> Observation<'_> {
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
) -> Result<CeremonyObservation> {
    let hint = selfsame_app_identity::provider_hint::ProviderHint::recognise(&offer.provider_hint)
        .map_err(|_| UiError::from("OfferMalformed"))?;
    Ok(CeremonyObservation {
        ceremony_profile_digest: offer.core.profile_digest.clone(),
        provider_id: hint.provider_id,
        descriptor_digest: hint.descriptor_digest,
        // The manual cross-device path attributes no caller. A web-binding
        // statement accepts this; a native-binding statement refuses it, which
        // is the CON-227 property that keeps first contact from silently
        // downgrading a native application's stronger binding.
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
    Custody::require_backup_confirmed()?;

    // Every recognition, verification, binding and freshness check is the pure
    // core's, and it has already run by the time a key is touched.
    let decided = authorise::authorise(&offer, &profile, &observed.as_observation(now() as i64))
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
    let (compact, identity) = Custody::use_hierarchy_root(&passcode, |root| {
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
        if pending.ceremony_id != ceremony_id {
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
    //! IMPL-008 ADR-913 — the enrolment observation is built from the opened
    //! offer alone, with no OS caller attribution. These pin the field mapping
    //! and the unattributed-caller property CON-227 depends on; the full
    //! fetch → app_grant → put_bundle wrapper is depth (needs a live rendezvous,
    //! covered by tests/live_link.rs's rig).
    use super::*;
    use selfsame_app_identity::ceremony::{OfferCore, OfferPayload};
    use selfsame_app_identity::provider_hint::ProviderHint;

    fn offer_payload() -> OfferPayload {
        let hint = ProviderHint {
            application_id: "https://chat.anuna.io/selfsame/application".into(),
            profile_version: 1,
            provider_id: "anuna-1".into(),
            descriptor_digest: "cCnyIp8IxUiyUjCUBbrZ5b3flzqMM8c-S_tUCPdCwUI".into(),
            offer_digest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        };
        let core = OfferCore {
            ceremony_id: "c".repeat(43),
            request_id: "r".repeat(43),
            application_id: "https://chat.anuna.io/selfsame/application".into(),
            profile_version: 1,
            profile_digest: "PdigestPdigestPdigestPdigestPdigestPdigestX".into(),
            account_scope_id: "s".repeat(43),
            device_did: "did:key:zTEST".into(),
            device_public_key: [7u8; 32],
            requested_permissions: vec![
                "https://chat.anuna.io/selfsame/application#chat-send".into(),
            ],
            issued_at: 1_000,
            expires_at: 1_120,
        };
        OfferPayload {
            core,
            enrollment_evidence: "e.e.e".into(),
            provider_hint: hint.to_json(),
            offer_digest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        }
    }

    #[test]
    fn observation_maps_offer_and_hint_fields() {
        let offer = offer_payload();
        let obs = observation_for_enrolment_offer(&offer).expect("well-formed hint");
        assert_eq!(obs.ceremony_profile_digest, offer.core.profile_digest);
        assert_eq!(obs.provider_id, "anuna-1");
        assert_eq!(obs.descriptor_digest, "cCnyIp8IxUiyUjCUBbrZ5b3flzqMM8c-S_tUCPdCwUI");
    }

    #[test]
    fn the_manual_path_attributes_no_caller() {
        // The property CON-227 rests on: a pasted/scanned first-contact offer
        // reaches acceptance as `Unattributed`, which a web binding accepts and
        // a native binding refuses. If this ever became `Some(..)`, a native
        // application's stronger binding could be silently downgraded.
        let obs = observation_for_enrolment_offer(&offer_payload()).unwrap();
        assert_eq!(obs.platform_binding_id, None);
    }

    #[test]
    fn a_malformed_hint_refuses() {
        let mut offer = offer_payload();
        offer.provider_hint = selfsame_app_identity::json::Json::obj([]);
        assert!(observation_for_enrolment_offer(&offer).is_err());
    }
}
