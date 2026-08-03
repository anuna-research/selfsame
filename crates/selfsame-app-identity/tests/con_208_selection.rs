//! `TEST-214`, `TEST-215`, `TEST-218` — provider selection, one election per
//! ceremony, and provider-hint integrity.
//!
//! **Validates:** `REQ-209`, `REQ-212`, `REQ-219`, `NFR-207`.
//!
//! `TEST-218` is the reason this file exists. It says:
//!
//! > Alter application ID, profile version/digest, provider ID, pairing route,
//! > nameplate, descriptor digest, offer digest, SPAKE2 binding/confirmation,
//! > ciphertext, and authentication tag separately. **Every alteration is
//! > rejected before grant retrieval.**
//!
//! The last three of those are PROTO-003 and PROTO-004 values; the rest are
//! `CON-209`'s, and they are what a joiner checks against **its own
//! origin-authenticated profile** rather than against anything the hint
//! supplied. That asymmetry is the whole design: a hint can only ever *select
//! among* things the joiner already trusts, so altering one makes the hint name
//! something the joiner cannot find.

mod common;

use common::*;
use selfsame_app_identity::codec;
use selfsame_app_identity::json::Json;
use selfsame_app_identity::profile::ApplicationProfile;
use selfsame_app_identity::selection::{
    self, HintError, ProbeOutcome, ProviderHint, SelectionError, MAX_PROBE_MILLISECONDS,
};

fn profile() -> ApplicationProfile {
    ApplicationProfile::recognise(&profile_octets()).unwrap()
}

const OFFER_DIGEST: &str = "PgUKGH7pVGpJDLzWfLdSVvVFLLLzXTvvXlPMdCLbPmA";

fn hint(p: &ApplicationProfile) -> ProviderHint {
    ProviderHint {
        application_id: APPLICATION_ID.into(),
        profile_version: 1,
        provider_id: p.rendezvous[0].id.clone(),
        descriptor_digest: codec::b64url(&p.rendezvous[0].digest),
        offer_digest: OFFER_DIGEST.into(),
    }
}

fn healthy() -> ProbeOutcome {
    ProbeOutcome { pairing_ok: true, mailbox_ok: true, elapsed_milliseconds: 40 }
}

// ── TEST-218: the provider hint ────────────────────────────────────────────

#[test]
fn an_untouched_hint_verifies_against_the_joiners_own_profile() {
    let p = profile();
    assert!(hint(&p).verify(&p, OFFER_DIGEST).is_ok());
}

#[test]
fn the_hint_round_trips_through_its_serialised_form() {
    let p = profile();
    let value = hint(&p).to_json();
    assert_eq!(ProviderHint::recognise(&value).unwrap(), hint(&p));
    assert_eq!(
        value.member_names(),
        vec![
            "applicationId",
            "profileVersion",
            "providerId",
            "descriptorDigest",
            "offerDigest"
        ]
    );
}

#[test]
fn altering_the_application_id_is_rejected() {
    let p = profile();
    let altered = ProviderHint { application_id: OTHER_APPLICATION_ID.into(), ..hint(&p) };
    assert_eq!(altered.verify(&p, OFFER_DIGEST), Err(HintError::ApplicationMismatch));
}

#[test]
fn altering_the_profile_version_is_rejected() {
    let p = profile();
    for version in [0i64, 2, -1] {
        let altered = ProviderHint { profile_version: version, ..hint(&p) };
        assert_eq!(
            altered.verify(&p, OFFER_DIGEST),
            Err(HintError::UnsupportedProfileVersion),
            "version {version}"
        );
    }
}

#[test]
fn altering_the_provider_id_is_rejected() {
    let p = profile();
    // A provider the profile does not declare at all.
    let altered = ProviderHint { provider_id: "attacker-relay".into(), ..hint(&p) };
    assert_eq!(altered.verify(&p, OFFER_DIGEST), Err(HintError::UnknownProvider));

    // A provider the profile *does* declare, but not the one whose descriptor
    // digest the hint carries. This is the substitution that matters: both
    // values are individually legitimate and only their pairing is wrong.
    let altered = ProviderHint { provider_id: p.rendezvous[1].id.clone(), ..hint(&p) };
    assert_eq!(altered.verify(&p, OFFER_DIGEST), Err(HintError::DescriptorMismatch));
}

#[test]
fn altering_the_descriptor_digest_is_rejected() {
    let p = profile();
    let altered =
        ProviderHint { descriptor_digest: codec::b64url(&[0u8; 32]), ..hint(&p) };
    assert_eq!(altered.verify(&p, OFFER_DIGEST), Err(HintError::DescriptorMismatch));
}

#[test]
fn altering_the_offer_digest_is_rejected() {
    let p = profile();
    let altered = ProviderHint { offer_digest: codec::b64url(&[9u8; 32]), ..hint(&p) };
    assert_eq!(altered.verify(&p, OFFER_DIGEST), Err(HintError::OfferMismatch));
    // …and equally, the same hint against a different offer.
    assert_eq!(
        hint(&p).verify(&p, &codec::b64url(&[9u8; 32])),
        Err(HintError::OfferMismatch)
    );
}

#[test]
fn altering_the_pairing_route_or_any_descriptor_field_is_rejected_through_the_digest() {
    // TEST-218 names the pairing route and the nameplate separately, but
    // CON-201 makes the descriptor digest cover the *complete* descriptor
    // "including all three pairing fields" — so altering the route changes the
    // digest, and the hint no longer matches the joiner's local descriptor.
    let mutated = with_member(
        "rendezvous",
        Json::arr([
            descriptor("au-primary", "rendezvous-au.provider.example", "pairing-au.provider.example", "99", 10, 80),
            descriptor("global-secondary", "rendezvous.example.net", "pairing.example.net", "17", 20, 20),
        ]),
    );
    let rerouted = ApplicationProfile::recognise(&mutated).unwrap();
    assert_ne!(
        rerouted.rendezvous[0].digest,
        profile().rendezvous[0].digest,
        "a changed pairing route must change the descriptor digest"
    );
    // A hint built for the original profile no longer verifies against the
    // rerouted one.
    assert_eq!(
        hint(&profile()).verify(&rerouted, OFFER_DIGEST),
        Err(HintError::DescriptorMismatch)
    );
}

#[test]
fn a_hint_carrying_an_account_scope_is_refused_by_name() {
    // CON-209: "The hint SHALL NOT contain `accountScopeId`." Called out with
    // its own error because leaking it would hand the rendezvous provider the
    // private derivation selector — the one value REQ-217 keeps off every wire.
    let p = profile();
    let Json::Object(mut members) = hint(&p).to_json() else { unreachable!() };
    members.push(("accountScopeId".into(), Json::text(codec::b64url(&[4u8; 32]))));
    assert_eq!(
        ProviderHint::recognise(&Json::Object(members)),
        Err(HintError::CarriesAccountScope)
    );
}

#[test]
fn a_hint_with_any_other_unknown_member_is_refused() {
    let p = profile();
    let Json::Object(mut members) = hint(&p).to_json() else { unreachable!() };
    members.push(("pairingUrl".into(), Json::text("https://attacker.example")));
    assert_eq!(
        ProviderHint::recognise(&Json::Object(members)),
        Err(HintError::UnknownMember)
    );
}

#[test]
fn a_hint_missing_a_member_or_of_the_wrong_shape_is_refused() {
    let p = profile();
    for drop in ["applicationId", "profileVersion", "providerId", "descriptorDigest", "offerDigest"]
    {
        let Json::Object(members) = hint(&p).to_json() else { unreachable!() };
        let kept: Vec<(String, Json)> = members.into_iter().filter(|(k, _)| k != drop).collect();
        assert_eq!(
            ProviderHint::recognise(&Json::Object(kept)),
            Err(HintError::Malformed),
            "dropping {drop}"
        );
    }
    assert_eq!(ProviderHint::recognise(&Json::text("x")), Err(HintError::Malformed));
    assert_eq!(ProviderHint::recognise(&Json::arr([])), Err(HintError::Malformed));
}

#[test]
fn every_check_reads_the_joiners_profile_and_never_the_hint() {
    // The design property, stated as a test: a hint that names a provider,
    // digest, and offer the joiner has never heard of fails on *all three*
    // grounds rather than teaching the joiner anything.
    let p = profile();
    let fabricated = ProviderHint {
        application_id: OTHER_APPLICATION_ID.into(),
        profile_version: 1,
        provider_id: "attacker-relay".into(),
        descriptor_digest: codec::b64url(&[0u8; 32]),
        offer_digest: codec::b64url(&[0u8; 32]),
    };
    // The first check to fire is the application, because a hint for another
    // application is not a substitution — it is a different ceremony.
    assert_eq!(fabricated.verify(&p, OFFER_DIGEST), Err(HintError::ApplicationMismatch));
    // With the application corrected it still cannot name a provider.
    let closer = ProviderHint { application_id: APPLICATION_ID.into(), ..fabricated };
    assert_eq!(closer.verify(&p, OFFER_DIGEST), Err(HintError::UnknownProvider));
}

// ── TEST-214: selection ────────────────────────────────────────────────────

#[test]
fn the_lowest_priority_group_is_offered_first_and_exhaustion_moves_to_the_next() {
    let p = profile();
    let first = selection::next_group(&p, NOW, &[], None).expect("a first group");
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].id, "au-primary");
    assert_eq!(first[0].priority, 10);

    // CON-208 step 7: "if none are eligible, repeats steps 4–6 with the next
    // priority group".
    let second = selection::next_group(&p, NOW, &[], Some(10)).expect("a second group");
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].id, "global-secondary");
    assert_eq!(second[0].priority, 20);

    // Step 8: every group exhausted.
    assert!(selection::next_group(&p, NOW, &[], Some(20)).is_none());
}

#[test]
fn an_expired_descriptor_is_ineligible() {
    let p = profile();
    // The fixture's descriptors expire 2027-07-30. After that, neither is
    // offered and selection has nowhere to go — REQ-210's stop, not a fallback.
    let after_expiry = 1_900_000_000;
    assert!(selection::next_group(&p, after_expiry, &[], None).is_none());
    assert!(selection::next_group(&p, NOW, &[], None).is_some());
}

#[test]
fn a_locally_forbidden_descriptor_is_skipped_without_changing_the_order() {
    let p = profile();
    let group = selection::next_group(&p, NOW, &["au-primary"], None).expect("a group");
    assert_eq!(group.len(), 1);
    assert_eq!(group[0].id, "global-secondary", "local policy removes it, it does not reorder");
}

#[test]
fn a_group_whose_probes_all_fail_yields_no_eligible_rendezvous() {
    let p = profile();
    let group = selection::next_group(&p, NOW, &[], None).unwrap();
    let unhealthy = vec![ProbeOutcome { mailbox_ok: false, ..healthy() }; group.len()];
    assert_eq!(
        selection::choose(&group, &unhealthy, 0),
        Err(SelectionError::NoEligibleRendezvous)
    );
}

#[test]
fn a_slow_provider_is_ineligible_rather_than_blocking_its_fallbacks() {
    // NFR-207: "Health probes SHALL be bounded and parallel. A slow
    // high-priority provider SHALL NOT serially block all fallbacks."
    //
    // Parallelism is the shell's; what the core owns is the bound, and that a
    // descriptor which blew it is simply ineligible rather than fatal. The
    // fall-through in `next_group` is what turns that into "the fallback is
    // still reachable".
    let p = profile();
    let first = selection::next_group(&p, NOW, &[], None).unwrap();
    let slow = vec![
        ProbeOutcome { elapsed_milliseconds: MAX_PROBE_MILLISECONDS + 1, ..healthy() };
        first.len()
    ];
    assert_eq!(
        selection::choose(&first, &slow, 0),
        Err(SelectionError::NoEligibleRendezvous)
    );

    let second = selection::next_group(&p, NOW, &[], Some(first[0].priority))
        .expect("the fallback group is still offered");
    assert!(selection::choose(&second, &[healthy()], 0).is_ok());
}

#[test]
fn the_probe_deadline_is_the_one_con_208_fixes() {
    assert_eq!(MAX_PROBE_MILLISECONDS, 1_500);
}

// ── TEST-215: one initiator, one selection ─────────────────────────────────

#[test]
fn the_joiner_follows_the_bound_descriptor_and_never_runs_its_own_election() {
    // TEST-215: "Give two devices different health observations and profile
    // revisions. Confirm that the joiner follows only the route and descriptor
    // bound by the valid initiator bootstrap/hint and never starts a second
    // election for the same ceremony."
    let p = profile();

    // The initiator elects `au-primary` and binds it into the hint.
    let initiator_group = selection::next_group(&p, NOW, &[], None).unwrap();
    let elected = selection::choose(&initiator_group, &[healthy()], 0).unwrap();
    assert_eq!(elected.id, "au-primary");
    let bound = ProviderHint {
        application_id: APPLICATION_ID.into(),
        profile_version: 1,
        provider_id: elected.id.clone(),
        descriptor_digest: codec::b64url(&elected.digest),
        offer_digest: OFFER_DIGEST.into(),
    };

    // The joiner observes `au-primary` as unhealthy. It has no API through
    // which to prefer the other descriptor for this ceremony: `verify` names
    // the one the initiator bound, and there is no "choose again" that takes a
    // hint. REQ-212: "It SHALL NOT independently select a different
    // rendezvous."
    assert!(bound.verify(&p, OFFER_DIGEST).is_ok());
    let joiner_would_have_picked = selection::choose(
        &selection::next_group(&p, NOW, &[], None).unwrap(),
        &[ProbeOutcome { mailbox_ok: false, ..healthy() }],
        0,
    );
    assert_eq!(
        joiner_would_have_picked,
        Err(SelectionError::NoEligibleRendezvous),
        "the joiner's own view is unhealthy, and it still follows the hint"
    );

    // If the selected provider is genuinely unusable the answer is a *fresh
    // ceremony*, not a second election — which is CON-213's abandonment rule
    // and is tested in the pairing suite.
    assert_eq!(bound.provider_id, "au-primary");
}

#[test]
fn a_joiner_holding_a_different_profile_revision_refuses_rather_than_reconciling() {
    // "different profile revisions" — the joiner's profile has a different
    // digest for the same provider id, so the descriptor digest no longer
    // matches and the hint is refused. It does not fetch, repair, or prefer
    // either side.
    let p = profile();
    let bound = hint(&p);

    let revised = ApplicationProfile::recognise(&with_member(
        "rendezvous",
        Json::arr([
            descriptor("au-primary", "rendezvous-au.provider.example", "pairing-au.provider.example", "03", 10, 81),
            descriptor("global-secondary", "rendezvous.example.net", "pairing.example.net", "17", 20, 20),
        ]),
    ))
    .unwrap();

    assert_eq!(bound.verify(&revised, OFFER_DIGEST), Err(HintError::DescriptorMismatch));
}
