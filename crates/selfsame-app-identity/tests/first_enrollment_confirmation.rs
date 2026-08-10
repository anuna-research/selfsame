//! `CON-221` first-enrollment confirmation, as the issuance path uses it.
//!
//! `F5` of the G2 review was that issuance derived and signed immediately,
//! checking no authority state and exposing no fingerprint, so it could not tell
//! a first enrolment from any other and could mint the first grant without the
//! comparison the contract requires.
//!
//! The pure decision existed the whole time and nothing called it. These tests
//! pin the three answers it gives and the two properties that make the
//! comparison meaningful, so a future caller cannot quietly collapse them.

mod common;

use common::*;
use selfsame_app_identity::confirm::{self, Applicability, AuthorityState, Response};
use selfsame_app_identity::{hierarchy, profile::ApplicationId, scope::AccountScopeId};

fn home_did(scope_byte: u8) -> String {
    let app = ApplicationId::parse(APPLICATION_ID).unwrap();
    let scope = AccountScopeId::from_octets([scope_byte; 32]);
    hierarchy::derive_from_mnemonic(&mnemonic(0), &app, &scope)
        .home_did()
        .expect("derives a DID")
}

#[test]
fn no_binding_requires_the_comparison() {
    let did = home_did(1);
    let out = Applicability::decide(AuthorityState::NoBinding, &did);
    assert!(matches!(out, Applicability::Required(_)));
}

#[test]
fn an_existing_binding_asks_nobody_anything() {
    // `CON-221` is spent once. The authority's record is authoritative from
    // then on, and a grant naming another issuer is rejected at `CON-204`
    // before `CON-206` runs — so a second prompt would be theatre.
    assert_eq!(
        Applicability::decide(AuthorityState::Bound, &home_did(2)),
        Applicability::NotRequired
    );
}

/// The property the whole contract turns on: *"SHALL treat an unreachable
/// authority as 'unknown' and fail closed rather than assume first use."*
///
/// Reading an outage as first use is the substitution the comparison exists to
/// catch — an attacker who can stop the authority answering would otherwise get
/// a first-enrolment prompt on an account that already has a binding.
#[test]
fn an_unreachable_authority_fails_closed_and_never_reads_as_first_use() {
    let out = Applicability::decide(AuthorityState::Unknown, &home_did(3));
    assert_eq!(out, Applicability::FailClosed);
    assert!(
        !matches!(out, Applicability::Required(_)),
        "an outage must never be mistaken for a first enrolment"
    );
}

/// `SPEC-002` `REQ-103`: the hex is the normative comparison rendering, and the
/// LifeHash beside it is a recognition aid. A screen that compared the picture
/// would be comparing 18 bits of a name rather than 48 bits of a digest.
#[test]
fn the_compared_value_is_the_hex_of_the_home_did() {
    let did = home_did(4);
    let Applicability::Required(display) = Applicability::decide(AuthorityState::NoBinding, &did)
    else {
        panic!("no binding requires confirmation");
    };

    assert_eq!(display.comparison_value(), selfsame_core::fingerprint::fingerprint_did(&did).hex());
}

/// Two accounts must not present the same thing to compare, or the comparison
/// decides nothing.
#[test]
fn distinct_accounts_present_distinct_comparison_values() {
    let a = Applicability::decide(AuthorityState::NoBinding, &home_did(5));
    let b = Applicability::decide(AuthorityState::NoBinding, &home_did(6));
    let (Applicability::Required(a), Applicability::Required(b)) = (a, b) else {
        panic!("both are first enrolments");
    };
    assert_ne!(a.comparison_value(), b.comparison_value());
}

#[test]
fn only_a_confirmation_may_proceed() {
    assert!(confirm::outcome(Response::Confirmed).may_proceed);
    assert!(!confirm::outcome(Response::Rejected).may_proceed);
    // A timeout is not a quiet yes. It is the case a person walked away from,
    // and the one an attacker would rely on if it were.
    assert!(!confirm::outcome(Response::TimedOut).may_proceed);
}
