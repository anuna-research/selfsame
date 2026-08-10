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

/// Recognise, verify, and bind — in that order, because each is a precondition.
///
/// 1. **Profile** (`CON-201`), because everything afterwards trusts it,
///    including the key that verifies the application's own statement.
/// 2. **Offer** (`CON-219`), a closed fifteen-member language. No field is read
///    before the whole payload recognises.
/// 3. **Binding**, checked before the signature because it is cheaper and
///    equally disqualifying: an offer naming another application must not reach
///    a signature check at all.
/// 4. **Enrollment evidence** (`CON-214`) — the step that makes a copied public
///    profile useless to a hostile caller, since the `kid` resolves only in the
///    authenticated profile and its private half is a backend credential.
/// 5. **Expiry**, before the signature so an ordinary stale code is not
///    reported as an unverifiable application, and using `CON-214`'s own
///    comparison so the two cannot disagree by a second.
/// 6. The scope's canonical form.
pub fn authorise(
    offer: &[u8],
    profile: &[u8],
    provider_id: &str,
    descriptor_digest: &str,
    now: UnixSeconds,
) -> Result<Authorised, AuthoriseError> {
    let profile = ApplicationProfile::recognise(profile)
        .map_err(|_| AuthoriseError::UnverifiedApplication)?;

    let payload =
        ceremony::recognise_offer(offer).map_err(|_| AuthoriseError::OfferMalformed)?;

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

    enrollment::verify(
        &payload.enrollment_evidence,
        &Observed {
            profile: &profile,
            offer: &payload.core,
            provider_id,
            descriptor_digest,
            platform_binding_id: None,
            now,
        },
    )
    .map_err(|_| AuthoriseError::UnverifiedApplication)?;

    let scope = AccountScopeId::parse(&payload.core.account_scope_id)
        .map_err(|_| AuthoriseError::ScopeNotCanonical)?;

    let valid_until = now + profile.revocation.max_grant_lifetime_seconds;

    Ok(Authorised { profile, offer: payload.core, scope, valid_from: now, valid_until })
}
