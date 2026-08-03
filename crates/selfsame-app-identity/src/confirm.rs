//! First-enrollment issuer confirmation — `CON-221`, `REQ-230`, `NFR-205`.
//!
//! # The hole this closes
//!
//! `CON-206` step 8 compares the grant's account against "the exact RFC 7565
//! account expected by the current authenticated application-account context".
//! At an account's **very first** enrollment that expectation does not exist
//! yet, so the check degrades to self-consistency: whichever wallet answers the
//! ceremony names an account derived from its own DID, and the comparison
//! trivially passes.
//!
//! `REQ-230` states the consequence: without this contract, "whichever wallet
//! answers a first ceremony becomes the account's identity permanently".
//!
//! `NFR-205` forbids a trust-on-first-use path anywhere, and this is the one
//! place where no prior binding *can* exist. It is closed by human confirmation
//! rather than by prior trust — and `NFR-205` says so explicitly: "An
//! implementation that accepts a first grant without that confirmation **is** a
//! TOFU path and does not conform."
//!
//! # What is compared, and what merely sits beside it
//!
//! The person compares **the hexadecimal fingerprint**. The LifeHash is a
//! recognition aid shown next to it and is never presented as the thing being
//! compared:
//!
//! - [`SPEC-002` `REQ-103`] makes the hex the normative comparison value;
//! - `REQ-105` forbids a picture being alone on screen;
//! - `ADR-107` defers promoting the image pending evidence about human
//!   discrimination.
//!
//! [`Display`] carries both for that reason, and names which is which.
//!
//! # No skip, and no second showing
//!
//! Neither side may offer a "remember this" or "skip" affordance: the
//! confirmation happens once per account ever, and an affordance to skip it is
//! an affordance to reinstate the trust-on-first-use this contract removes.
//!
//! Equally, an application "SHALL NOT re-enter this contract to 're-confirm' an
//! account, because a prompt that can appear twice can be induced to appear at
//! an attacker's chosen moment." [`Applicability::decide`] is the only entry
//! point, and it returns [`Applicability::NotRequired`] whenever a binding
//! already exists.
//!
//! [`SPEC-002` `REQ-103`]: ../../../../specs/SPEC-002-visual-key-fingerprint.md

use selfsame_core::fingerprint::{fingerprint_did, Fingerprint};

/// What the account authority says about this account's existing binding.
///
/// `CON-221`: the application "SHALL determine this from authority state, not
/// from local cache, and SHALL treat an unreachable authority as 'unknown' and
/// fail closed rather than assume first use."
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityState {
    /// The authority holds no binding for this authenticated account.
    NoBinding,
    /// The authority holds a binding, which is authoritative from now on.
    Bound,
    /// The authority could not be reached, or gave an answer that does not
    /// decide the question.
    Unknown,
}

/// Whether confirmation applies to this enrollment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Applicability {
    /// First enrollment: the person must compare fingerprints before the alias
    /// is provisioned or the grant accepted.
    Required(Display),
    /// A binding exists. The authority's record is authoritative and a grant
    /// naming a different issuer is rejected under `CON-204` before `CON-206`
    /// runs. No prompt is shown.
    NotRequired,
    /// The authority state is unknown. Fail closed.
    FailClosed,
}

/// What each side puts on screen (`CON-221`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Display {
    /// The fingerprint of the home DID.
    pub fingerprint: Fingerprint,
}

impl Display {
    /// The value the person is asked to compare.
    ///
    /// `SPEC-002` `REQ-103` makes this the normative comparison rendering.
    pub fn comparison_value(&self) -> String {
        self.fingerprint.hex()
    }

    /// The recognition aid shown beside the comparison value.
    ///
    /// Never presented as the thing being compared. The name says so at every
    /// call site, which is the cheapest way to keep a UI from swapping them.
    pub fn recognition_aid(&self) -> &Fingerprint {
        &self.fingerprint
    }
}

impl Applicability {
    /// Decide whether this enrollment needs confirmation.
    ///
    /// The only entry point, so "re-confirm this account" has nowhere to be
    /// called from.
    pub fn decide(authority: AuthorityState, home_did: &str) -> Self {
        match authority {
            AuthorityState::NoBinding => {
                Applicability::Required(Display { fingerprint: fingerprint_did(home_did) })
            }
            AuthorityState::Bound => Applicability::NotRequired,
            AuthorityState::Unknown => Applicability::FailClosed,
        }
    }
}

/// What the person did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Response {
    /// The two fingerprints matched and the person confirmed.
    Confirmed,
    /// The person rejected the comparison.
    Rejected,
    /// The prompt timed out.
    TimedOut,
}

/// What the application must do next (`CON-221`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// Whether the alias may be provisioned and `CON-206` run.
    pub may_proceed: bool,
    /// Whether the ceremony is burned under `REQ-229`.
    pub burn_ceremony: bool,
    /// Whether the grant ID SHOULD be revoked, if a controller is reachable.
    pub should_revoke: bool,
}

/// Apply `CON-221`'s "what follows" clause.
///
/// On rejection **or any timeout** the application provisions nothing, accepts
/// nothing, creates no session, burns the ceremony, and should revoke the grant
/// ID if it can reach a controller. A timeout is treated exactly as a rejection:
/// an unanswered prompt is not a quiet yes.
pub fn outcome(response: Response) -> Outcome {
    match response {
        Response::Confirmed => {
            Outcome { may_proceed: true, burn_ceremony: false, should_revoke: false }
        }
        Response::Rejected | Response::TimedOut => {
            Outcome { may_proceed: false, burn_ceremony: true, should_revoke: true }
        }
    }
}

/// Whether the two sides are looking at the same identity.
///
/// Both compute this from their own input — the wallet from the DID it derived,
/// the application from the grant's `issuer` — so agreement means the DID the
/// authority is about to bind is the one the person's wallet derived.
///
/// `CON-221` is careful about what that does *not* establish: "It establishes
/// nothing about the wallet's provenance, build, or integrity, and it is not an
/// authentication of the wallet."
pub fn fingerprints_agree(wallet_home_did: &str, grant_issuer: &str) -> bool {
    fingerprint_did(wallet_home_did) == fingerprint_did(grant_issuer)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &str = "did:crdt:zAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const OTHER: &str = "did:crdt:zBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    // TEST-238 positive: first enrollment shows the comparison.
    #[test]
    fn a_first_enrollment_requires_confirmation() {
        let applicability = Applicability::decide(AuthorityState::NoBinding, HOME);
        let Applicability::Required(display) = applicability else {
            panic!("first enrollment must require confirmation")
        };
        assert_eq!(display.comparison_value(), fingerprint_did(HOME).hex());
        // Six octets rendered as pairs: the SPEC-002 normative rendering.
        assert_eq!(display.comparison_value().split(' ').count(), 6);
    }

    #[test]
    fn a_subsequent_enrollment_shows_no_prompt_at_all() {
        // "A prompt that can appear twice can be induced to appear at an
        // attacker's chosen moment."
        assert_eq!(
            Applicability::decide(AuthorityState::Bound, HOME),
            Applicability::NotRequired
        );
    }

    #[test]
    fn an_unreachable_authority_fails_closed_rather_than_assuming_first_use() {
        // Assuming first use would let an attacker who can partition the
        // authority induce the one prompt that establishes an identity.
        assert_eq!(
            Applicability::decide(AuthorityState::Unknown, HOME),
            Applicability::FailClosed
        );
    }

    #[test]
    fn both_sides_agree_only_on_the_same_did() {
        assert!(fingerprints_agree(HOME, HOME));
        assert!(!fingerprints_agree(HOME, OTHER));
    }

    #[test]
    fn confirmation_permits_provisioning_and_nothing_else_does() {
        assert_eq!(
            outcome(Response::Confirmed),
            Outcome { may_proceed: true, burn_ceremony: false, should_revoke: false }
        );
    }

    #[test]
    fn rejection_and_timeout_are_treated_identically() {
        // An unanswered prompt is not a quiet yes. CON-221 names "rejection, or
        // any timeout" in one breath, and the outcomes are equal here so a UI
        // cannot drift them apart.
        let rejected = outcome(Response::Rejected);
        let timed_out = outcome(Response::TimedOut);
        assert_eq!(rejected, timed_out);
        assert!(!rejected.may_proceed);
        assert!(rejected.burn_ceremony);
        assert!(rejected.should_revoke);
    }

    #[test]
    fn the_recognition_aid_is_not_the_comparison_value() {
        // SPEC-002 REQ-103 makes the hex normative and ADR-107 defers promoting
        // the image. The two accessors are named so that a screen written
        // against this API says which is which.
        let Applicability::Required(display) = Applicability::decide(AuthorityState::NoBinding, HOME)
        else {
            panic!("required")
        };
        let hex = display.comparison_value();
        let aid = display.recognition_aid();
        assert_eq!(aid.hex(), hex, "the aid is computed from the same digest");
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() || c == ' '));
    }
}
