//! The wallet's decision to issue a device grant — everything except the key.
//!
//! `CON-219` offer recognition, `CON-201` profile recognition, `CON-214`
//! enrollment verification and the offer-to-profile binding are one decision,
//! and this is where it is made. The shell supplies octets and a clock and
//! receives either a refusal or the exact parameters `grant::issue` needs.
//!
//! # Why this is not in the shell
//!
//! It was, briefly. Writing it there produced a function that could only be
//! tested by standing up a keychain, which is how a security decision ends up
//! with no tests at all. The dependency rule this repository states — the pure
//! core decides, the shell does I/O — is not a stylistic preference: a decision
//! in the shell is a decision the fixtures cannot reach.
//!
//! Nothing here reads a clock, opens a socket, or touches custody. The one
//! thing it cannot do is sign, because the home key belongs to whatever holds
//! the sealed root, and that is the shell's.

use crate::ceremony::{self, OfferCore};
use crate::enrollment::{self, Observed};
use crate::profile::ApplicationProfile;
use crate::provider_hint::ProviderHint;
use crate::scope::AccountScopeId;
use crate::UnixSeconds;

/// Why an offer was refused.
///
/// A closed enumeration, and deliberately coarser than the checks behind it:
/// a caller learns that the application is unverified, not *which* of the four
/// reasons made it so, because the difference between "no such `kid`" and "bad
/// signature" is an oracle for anyone probing with a copied profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthoriseError {
    /// The profile did not recognise, the offer named a different application,
    /// or the enrollment evidence did not verify under a profile key.
    #[error("unverified application")]
    UnverifiedApplication,
    /// The offer payload is not `CON-219`'s language.
    #[error("malformed offer")]
    OfferMalformed,
    /// The offer's own expiry has passed.
    #[error("offer expired")]
    OfferExpired,
    /// The account scope is not `CON-211` canonical.
    #[error("account scope is not canonical")]
    ScopeNotCanonical,
    /// The supplied profile is not the one this ceremony is bound to.
    ///
    /// Distinct from [`AuthoriseError::UnverifiedApplication`] because it is not
    /// a statement about the application at all: the profile may be perfectly
    /// genuine and simply not the document the authenticated intent committed this
    /// ceremony to. Collapsing the two would tell an operator to go looking at
    /// an application that is fine.
    #[error("profile does not match the ceremony binding")]
    ProfileNotBound,
    /// The `CON-209` provider hint is malformed, or selects a provider,
    /// descriptor or offer other than the one observed.
    #[error("provider hint does not match what was observed")]
    HintMismatch,
}

/// A verified offer, and the parameters issuing a grant from it requires.
///
/// Holding the parsed profile and scope rather than re-parsing them in the
/// shell is the point: a second parse is a second chance to disagree with the
/// one that was checked.
#[derive(Debug)]
pub struct Authorised {
    /// The recognised profile, whose `applicationId` the offer matched.
    pub profile: ApplicationProfile,
    /// The recognised offer.
    pub offer: OfferCore,
    /// The account scope, already `CON-211` canonical.
    pub scope: AccountScopeId,
    /// `validFrom` for the credential — the instant this decision was made.
    pub valid_from: UnixSeconds,
    /// `validUntil`, the profile's own declared bound and not a local constant.
    pub valid_until: UnixSeconds,
}

/// What the wallet observed for itself, as against what the offer asserts.
///
/// Every field here is something the caller must obtain independently of the
/// offer payload. That is the point of the type: an earlier version of this
/// function took only octets, hard-coded the platform binding to `None`, and
/// never checked the profile against anything — so it verified that whoever
/// supplied the profile had signed their own statement with their own key.
pub struct Observation<'a> {
    /// The `profileDigest` this ceremony is bound to. The supplied profile must
    /// hash to it.
    ///
    /// Without this the profile is whatever the caller passed, and `CON-214`'s
    /// guarantee — that the `kid` resolves only in an authenticated document —
    /// verifies nothing.
    pub ceremony_profile_digest: &'a str,
    /// The provider the wallet selected, per `CON-208`.
    pub provider_id: &'a str,
    /// `SHA-256` of that descriptor, base64url.
    pub descriptor_digest: &'a str,
    /// The caller identity the platform reported, where it reports one.
    ///
    /// `None` is meaningful and is correct on Apple, where `CON-223` records
    /// that the platform gives no general caller attribution. It is **not** a
    /// default: on Android the adapter observes a binding, and passing `None`
    /// there makes `enrollment::verify` refuse every legitimate handoff.
    pub platform_binding_id: Option<&'a str>,
    /// The wallet's clock.
    pub now: UnixSeconds,
}

/// Recognise, verify, and bind — in that order, because each is a precondition.
///
/// 1. **Profile** (`CON-201`), because everything afterwards trusts it,
///    including the key that verifies the application's own statement — and
///    then **bound to the ceremony**, because recognising a document says
///    nothing about whether it is the one this ceremony is about.
/// 2. **Offer** (`CON-219`), a closed fifteen-member language. No field is read
///    before the whole payload recognises.
/// 3. **Binding**, checked before the signature because it is cheaper and
///    equally disqualifying: an offer naming another application must not reach
///    a signature check at all.
/// 4. **Provider hint** (`CON-209`), which `offerDigest` cannot cover.
/// 5. **Enrollment evidence** (`CON-214`) — the step that makes a copied public
///    profile useless to a hostile caller, since the `kid` resolves only in the
///    profile step 1 bound, and its private half is a backend credential.
/// 6. **Expiry**, before the signature so an ordinary stale code is not
///    reported as an unverifiable application, and using `CON-214`'s own
///    comparison so the two cannot disagree by a second.
/// 7. The scope's canonical form.
pub fn authorise(
    offer: &[u8],
    profile: &[u8],
    observed: &Observation<'_>,
) -> Result<Authorised, AuthoriseError> {
    let now = observed.now;

    let profile = ApplicationProfile::recognise(profile)
        .map_err(|_| AuthoriseError::UnverifiedApplication)?;

    // The profile is only as trustworthy as the binding that names it. Syntax
    // recognition says a document is well formed, not that it is *this
    // ceremony's* document — and `CON-214`'s whole guarantee rests on the
    // second. Compared here, before any field of it is used.
    if crate::codec::b64url(profile.digest()) != observed.ceremony_profile_digest {
        return Err(AuthoriseError::ProfileNotBound);
    }

    let payload = ceremony::recognise_offer(offer).map_err(|_| AuthoriseError::OfferMalformed)?;

    if payload.core.application_id != profile.application_id.as_str() {
        return Err(AuthoriseError::UnverifiedApplication);
    }

    // Expiry is checked *before* the signature, and with `CON-214`'s own
    // comparison — `now >= expiresAt` is expired, so the boundary second is
    // not usable.
    //
    // Two reasons for the order. `enrollment::verify` enforces the same window
    // and would otherwise mask an ordinary expiry as `UnverifiedApplication`,
    // telling a person their application could not be verified when in fact
    // their code went stale — the difference between "try again" and "something
    // is wrong". And the leak this ordering might otherwise risk does not
    // exist: expiry is a function of values the offer's own author chose, so a
    // prober learns nothing from the distinction it did not already know.
    //
    // Using a different comparison from `CON-214` would be worse than either:
    // an offer accepted here and rejected there is a one-second window in which
    // the wallet reports the wrong reason for a refusal it cannot avoid.
    if now >= payload.core.expires_at {
        return Err(AuthoriseError::OfferExpired);
    }

    // `CON-209`. `offerDigest` deliberately excludes `providerHint` — a digest
    // over an object containing itself has no fixed point — so a mismatched
    // hint can sit beside otherwise valid signed evidence. A hint nobody reads
    // binds nothing, which is the opposite of what `CON-209` is for.
    let hint = ProviderHint::recognise(&payload.provider_hint)
        .map_err(|_| AuthoriseError::HintMismatch)?;
    if hint.application_id != profile.application_id.as_str()
        || hint.provider_id != observed.provider_id
        || hint.descriptor_digest != observed.descriptor_digest
        || hint.offer_digest != payload.offer_digest
    {
        return Err(AuthoriseError::HintMismatch);
    }

    enrollment::verify(
        &payload.enrollment_evidence,
        &Observed {
            profile: &profile,
            offer: &payload.core,
            provider_id: observed.provider_id,
            descriptor_digest: observed.descriptor_digest,
            platform_binding_id: observed.platform_binding_id,
            now,
        },
    )
    .map_err(|_| AuthoriseError::UnverifiedApplication)?;

    let scope = AccountScopeId::parse(&payload.core.account_scope_id)
        .map_err(|_| AuthoriseError::ScopeNotCanonical)?;

    let valid_until = now + profile.revocation.max_grant_lifetime_seconds;

    Ok(Authorised {
        profile,
        offer: payload.core,
        scope,
        valid_from: now,
        valid_until,
    })
}
