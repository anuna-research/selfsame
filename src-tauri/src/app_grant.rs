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
//! It is **not the transport**. `PROTO-004`'s sealed envelope and `PROTO-002`'s
//! mailbox are separate specifications with their own open gates, so this takes
//! offer octets that the shell has already opened and returns bundle octets for
//! the shell to seal. That split is the same one `selfsame-core` draws for
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
    /// The `CON-219` bundle payload, for `PROTO-004` to seal.
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
    ceremony_profile_digest: String,
    provider_id: String,
    descriptor_digest: String,
    platform_binding_id: Option<String>,
) -> Result<GrantRequestView> {
    let decided = authorise::authorise(
        &offer,
        &profile,
        &Observation {
            ceremony_profile_digest: &ceremony_profile_digest,
            provider_id: &provider_id,
            descriptor_digest: &descriptor_digest,
            platform_binding_id: platform_binding_id.as_deref(),
            now: now() as i64,
        },
    )
    .map_err(token)?;

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
fn token(e: AuthoriseError) -> UiError {
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
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmationRequest {
    /// `"required"`, `"notRequired"`, or `"failClosed"`.
    pub applicability: String,
    /// **The value the person compares.** `SPEC-002` `REQ-103` makes the hex the
    /// normative rendering; the LifeHash beside it is a recognition aid and is
    /// never the thing being compared.
    pub comparison_value: Option<String>,
    /// The account this would be, for the screen to name.
    pub account: String,
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
    ceremony_profile_digest: String,
    provider_id: String,
    descriptor_digest: String,
    platform_binding_id: Option<String>,
    passcode: String,
    session: tauri::State<'_, crate::commands::AppSession>,
) -> Result<ConfirmationRequest> {
    Custody::require_backup_confirmed()?;

    // Every recognition, verification, binding and freshness check is the pure
    // core's, and it has already run by the time a key is touched.
    let decided = authorise::authorise(
        &offer,
        &profile,
        &Observation {
            ceremony_profile_digest: &ceremony_profile_digest,
            provider_id: &provider_id,
            descriptor_digest: &descriptor_digest,
            platform_binding_id: platform_binding_id.as_deref(),
            now: now() as i64,
        },
    )
    .map_err(token)?;

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
    let authority = authority_state(&identity.acct_uri).await;
    let applicability = Applicability::decide(authority, &identity.did);

    let request = ConfirmationRequest {
        applicability: match &applicability {
            Applicability::Required(_) => "required",
            Applicability::NotRequired => "notRequired",
            Applicability::FailClosed => "failClosed",
        }
        .to_owned(),
        comparison_value: match &applicability {
            Applicability::Required(d) => Some(d.comparison_value()),
            _ => None,
        },
        account: identity.acct_uri.clone(),
    };

    if matches!(applicability, Applicability::FailClosed) {
        return Err(UiError::from("AuthorityUnreachable"));
    }

    let mut guard = session.0.lock().unwrap_or_else(|p| p.into_inner());
    guard.pending_issuance = Some(PendingIssuance {
        compact,
        identity,
        ceremony_id: decided.offer.ceremony_id,
        request_id: decided.offer.request_id,
        valid_until: decided.valid_until,
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
    confirmed: bool,
    session: tauri::State<'_, crate::commands::AppSession>,
) -> Result<AuthorisedGrant> {
    let pending = {
        let mut guard = session.0.lock().unwrap_or_else(|p| p.into_inner());
        // Taken, not borrowed: one preparation yields at most one bundle, and a
        // second call finds nothing rather than re-releasing the same grant.
        guard.pending_issuance.take().ok_or_else(|| UiError::from("NothingToConfirm"))?
    };

    let response = if confirmed { Response::Confirmed } else { Response::Rejected };
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
async fn authority_state(acct_uri: &str) -> AuthorityState {
    let Ok(acct) = AcctUri::parse(acct_uri) else { return AuthorityState::Unknown };
    match selfsame_app_identity_net::webfinger::fetch(&acct).await {
        Ok(jrd) => {
            if jrd.aliases.is_empty() {
                AuthorityState::NoBinding
            } else {
                AuthorityState::Bound
            }
        }
        // A 404 is a genuine "no binding"; anything else is "could not ask".
        Err(e) if is_not_found(&e) => AuthorityState::NoBinding,
        Err(_) => AuthorityState::Unknown,
    }
}

fn is_not_found(e: &selfsame_app_identity_net::NetError) -> bool {
    matches!(e, selfsame_app_identity_net::NetError::NotFound)
}
