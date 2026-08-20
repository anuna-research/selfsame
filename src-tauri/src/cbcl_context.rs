//! SPEC-008 `REQ-906` / `CON-902` — profile-anchored origin trust and (in a
//! later slice) real verification-context assembly.
//!
//! The origin gate runs BEFORE any socket opens (`CON-901` pre-condition).
//! A scanned origin is never trusted for being scanned; it is trusted for
//! being pre-declared by an authenticated profile the person already holds
//! (`ADR-902`, acquisition per `IMPL-008` `ADR-912`). Zero matches and
//! multiple matches both refuse, distinctly, with no repair path — the person
//! is never offered a way to enter, choose, or repair a relay origin
//! (inherited `SPEC-007` `REQ-813`).

use selfsame_app_identity::cbcl_relay::{self, RelayPolicy};
use selfsame_app_identity::profile::ApplicationProfile;

/// Closed origin-gate refusals (`REQ-906`). Each surfaces as one distinct,
/// secret-free message and ends the attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginRefusal {
    /// No held authenticated profile pre-declares this origin as an eligible
    /// relay (includes: digest not in the compiled registry, forbidden
    /// operator, loopback in an ordinary build).
    NoEligibleMatch,
    /// More than one held profile pre-declares this origin — ambiguous, and
    /// the wallet never guesses which application the ceremony belongs to.
    AmbiguousMatch,
}

/// Admit an invitation origin only when exactly one held profile lists it as
/// its one eligible relay descriptor, and return that profile.
///
/// Within one profile, `cbcl_relay::verify_invitation_origin` is the one
/// existing eligibility decision (descriptor match + registry digest +
/// operator + loopback policy); relay origins are unique within a profile, so
/// per-profile the match count is 0 or 1. Across the held set this function
/// demands a total of exactly one.
pub fn gate_invitation_origin<'a>(
    held: &'a [ApplicationProfile],
    policy: &RelayPolicy<'_>,
    invitation_origin: &str,
) -> Result<&'a ApplicationProfile, OriginRefusal> {
    let mut matched = held.iter().filter(|profile| {
        cbcl_relay::verify_invitation_origin(profile, policy, invitation_origin).is_ok()
    });
    match (matched.next(), matched.next()) {
        (Some(only), None) => Ok(only),
        (Some(_), Some(_)) => Err(OriginRefusal::AmbiguousMatch),
        (None, _) => Err(OriginRefusal::NoEligibleMatch),
    }
}

#[cfg(test)]
#[path = "../../crates/selfsame-app-identity/tests/common/mod.rs"]
mod fixture;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbcl_registry;
    use selfsame_app_identity::json::Json;

    use super::fixture;

    const ORIGIN: &str = "https://relay.example:9443";
    const OTHER_ORIGIN: &str = "https://other.example:9443";

    fn profile_with_relay(operator: &str, origin: &str, digest_byte: u8) -> ApplicationProfile {
        let octets = fixture::with_member(
            "cbclPairingRelays",
            Json::arr([fixture::cbcl_relay(operator, origin, 1, 1, digest_byte)]),
        );
        ApplicationProfile::recognise(&octets).expect("fixture profile recognised")
    }

    fn approving_policy(digests: &'static [[u8; 32]]) -> RelayPolicy<'static> {
        RelayPolicy {
            forbidden_operator_ids: &[],
            approved_conformance: digests,
            allow_loopback: false,
        }
    }

    // TEST-909 (positive): exactly one eligible descriptor proceeds, and the
    // gate returns the owning profile.
    #[test]
    fn one_eligible_match_admits_and_names_the_profile() {
        let held = vec![
            profile_with_relay("op-a", ORIGIN, 3),
            profile_with_relay("op-b", OTHER_ORIGIN, 3),
        ];
        let policy = approving_policy(&[[19; 32]]);
        let admitted = gate_invitation_origin(&held, &policy, ORIGIN).expect("one match admits");
        assert_eq!(
            admitted.cbcl_pairing_relays[0].relay_origin, ORIGIN,
            "the admitted profile is the one that pre-declared the origin"
        );
    }

    // TEST-909 (negative): zero matches refuse — nothing pre-declared the
    // origin. The gate is pure, so no socket can have opened.
    #[test]
    fn zero_matches_refuse() {
        let held = vec![profile_with_relay("op-a", OTHER_ORIGIN, 3)];
        let policy = approving_policy(&[[19; 32]]);
        assert_eq!(
            gate_invitation_origin(&held, &policy, ORIGIN).unwrap_err(),
            OriginRefusal::NoEligibleMatch
        );
        assert_eq!(
            gate_invitation_origin(&[], &policy, ORIGIN).unwrap_err(),
            OriginRefusal::NoEligibleMatch,
            "an empty held set refuses everything"
        );
    }

    // TEST-909 (negative): two held profiles pre-declaring one origin is
    // ambiguous, and the wallet refuses rather than guesses.
    #[test]
    fn two_matches_refuse_as_ambiguous() {
        let held = vec![
            profile_with_relay("op-a", ORIGIN, 3),
            profile_with_relay("op-b", ORIGIN, 3),
        ];
        let policy = approving_policy(&[[19; 32]]);
        assert_eq!(
            gate_invitation_origin(&held, &policy, ORIGIN).unwrap_err(),
            OriginRefusal::AmbiguousMatch
        );
    }

    // TEST-910: a descriptor whose conformance digest is not in the compiled
    // registry refuses, even though the origin matches exactly.
    #[test]
    fn unregistered_digest_refuses() {
        let held = vec![profile_with_relay("op-a", ORIGIN, 7)];
        let policy = approving_policy(&[[19; 32]]);
        assert_eq!(
            gate_invitation_origin(&held, &policy, ORIGIN).unwrap_err(),
            OriginRefusal::NoEligibleMatch
        );
    }

    // TEST-910: the shipped registry is empty, so the production policy
    // refuses every non-loopback origin — the valid fail-closed birth state.
    #[test]
    fn empty_registry_refuses_every_origin() {
        assert!(cbcl_registry::APPROVED_CONFORMANCE.is_empty());
        let held = vec![
            profile_with_relay("op-a", ORIGIN, 3),
            profile_with_relay("op-b", "https://chat.anuna.io:9443", 19),
        ];
        let policy = cbcl_registry::production_relay_policy();
        for origin in [ORIGIN, "https://chat.anuna.io:9443"] {
            assert_eq!(
                gate_invitation_origin(&held, &policy, origin).unwrap_err(),
                OriginRefusal::NoEligibleMatch,
                "{origin} must refuse against an empty registry"
            );
        }
    }

    // REQ-908 boundary: the ordinary policy never admits loopback, even when
    // a digest is somehow approved.
    #[test]
    fn production_policy_refuses_loopback() {
        let held = vec![profile_with_relay("op-a", "https://localhost:7443", 3)];
        let policy = RelayPolicy {
            forbidden_operator_ids: &[],
            approved_conformance: &[[19; 32]],
            allow_loopback: false,
        };
        assert_eq!(
            gate_invitation_origin(&held, &policy, "https://localhost:7443").unwrap_err(),
            OriginRefusal::NoEligibleMatch
        );
    }
}
