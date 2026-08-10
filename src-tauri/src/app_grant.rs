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
    alias::{self, AcctUri},
    authorise::{self, AuthoriseError},
    ceremony, grant, hierarchy,
};

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
    provider_id: String,
    descriptor_digest: String,
) -> Result<GrantRequestView> {
    let decided = authorise::authorise(
        &offer,
        &profile,
        &provider_id,
        &descriptor_digest,
        now() as i64,
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
    })
}

/// Issue the grant. The one place a `SPEC-004` credential is signed.
///
/// `REQ-002`'s gate applies for the same reason it applies to SPEC-001 linking:
/// an identity whose recovery phrase has not been written down must not be the
/// issuer of authority that outlives the device holding it.
#[tauri::command]
pub async fn app_grant_issue(
    offer: Vec<u8>,
    profile: Vec<u8>,
    provider_id: String,
    descriptor_digest: String,
    passcode: String,
) -> Result<AuthorisedGrant> {
    Custody::require_backup_confirmed()?;

    // Every recognition, verification, binding and freshness check is the pure
    // core's, and it has already run by the time a key is touched.
    let decided = authorise::authorise(
        &offer,
        &profile,
        &provider_id,
        &descriptor_digest,
        now() as i64,
    )
    .map_err(token)?;

    // `CON-205`: independent for every grant, and never derived from the device
    // key, the scope, a timestamp, or recovery material.
    let mut grant_token = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut grant_token);

    // Presence, then the key — which exists only inside this closure.
    let (compact, home_did, account) = Custody::use_hierarchy_root(&passcode, |root| {
        let home = hierarchy::derive(root, &decided.profile.application_id, &decided.scope);
        let home_did = home.home_did().map_err(|_| UiError::from("GrantIssuanceFailed"))?;
        let account = AcctUri::parse(&alias::stable_acct_uri(
            &home_did,
            &decided.profile.account_authority,
        ))
        .map_err(|_| UiError::from("GrantIssuanceFailed"))?;

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
        Ok::<_, UiError>((compact, home_did, account))
    })??;

    let bundle = ceremony::build_bundle(
        &decided.offer.ceremony_id,
        &decided.offer.request_id,
        &compact,
        None,
    )
    .map_err(|_| UiError::from("GrantIssuanceFailed"))?;

    Ok(AuthorisedGrant {
        bundle,
        account: account.as_str().to_owned(),
        issuer: home_did,
        valid_until: decided.valid_until,
    })
}
