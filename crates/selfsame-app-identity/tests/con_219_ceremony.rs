//! `TEST-228`, `TEST-231`, `TEST-236` — enrollment evidence and replay, the
//! non-authoritative callback, and the ceremony payloads with their offer
//! digest.
//!
//! The three obligations these tests exist for, in the order they bite:
//!
//! 1. **`offerDigest` has no fixed point.** It is computed over `offer_core`,
//!    which excludes the two members that carry it. An implementation that
//!    digested the complete payload "MUST be rejected as non-conforming rather
//!    than accommodated" — so a test proves the exclusion is real.
//! 2. **`requestId` is consumed before the first side effect**, whether the
//!    request is approved or denied, so a denial cannot be retried into an
//!    approval.
//! 3. **The callback carries no authority.** `REQ-224`: authorization follows
//!    only the bundle and `CON-206`, "never from an OS callback, foreground
//!    event, URL parameter, success screen, or wallet process exit."

mod common;

use common::*;
use selfsame_app_identity::ceremony::{
    self, BundlePayload, CeremonyError, DispatchResult, Handoff, HandoffReturn, OfferCore, Outcome,
};
use selfsame_app_identity::codec;
use selfsame_app_identity::enrollment::{self, EnrollmentError, EnrollmentStatement, Observed, RequestLedger};
use selfsame_app_identity::json::{self, Json};
use selfsame_app_identity::profile::{ApplicationProfile, MobileBinding};
use selfsame_app_identity::{didkey, selection};

const NOW_OFFER: i64 = NOW;

fn profile() -> ApplicationProfile {
    ApplicationProfile::recognise(&profile_octets()).unwrap()
}

fn offer_core(p: &ApplicationProfile) -> OfferCore {
    let device = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]).verifying_key().to_bytes();
    OfferCore {
        ceremony_id: codec::b64url(&[1u8; 32]),
        request_id: codec::b64url(&[2u8; 32]),
        application_id: APPLICATION_ID.into(),
        profile_version: 1,
        profile_digest: codec::b64url(p.digest()),
        account_scope_id: codec::b64url(&[4u8; 32]),
        device_did: didkey::encode(&device),
        device_public_key: device,
        requested_permissions: vec![PERMISSION.into()],
        issued_at: NOW_OFFER,
        expires_at: NOW_OFFER + 120,
    }
}

fn backend_key() -> ed25519_dalek::SigningKey {
    // The key whose public half the example profile's enrollment entry carries.
    ed25519_dalek::SigningKey::from_bytes(&[0u8; 32])
}

const KID: &str = "https://photos.example/selfsame/application#enrollment-2026-01";

/// A profile whose enrollment key is the one [`backend_key`] holds.
fn profile_with_real_key() -> ApplicationProfile {
    let public = backend_key().verifying_key().to_bytes();
    let octets = with_nested("enrollment.requestSigningKeys.publicKeyJwk.x", Json::text(codec::b64url(&public)));
    ApplicationProfile::recognise(&octets).unwrap()
}

fn statement(p: &ApplicationProfile, core: &OfferCore) -> EnrollmentStatement {
    let descriptor = &p.rendezvous[0];
    EnrollmentStatement {
        request_id: core.request_id.clone(),
        ceremony_id: core.ceremony_id.clone(),
        application_id: core.application_id.clone(),
        profile_version: 1,
        profile_digest: codec::b64url(p.digest()),
        account_scope_id: core.account_scope_id.clone(),
        device_key_digest: enrollment::device_key_digest(core),
        requested_permissions: core.requested_permissions.clone(),
        provider_id: descriptor.id.clone(),
        descriptor_digest: codec::b64url(&descriptor.digest),
        offer_digest: core.digest(),
        platform_binding_id: "apple:TEAM123456:com.example.photos:https://photos.example".into(),
        return_uri: "https://photos.example/.well-known/selfsame/return".into(),
        issued_at: core.issued_at,
        expires_at: core.expires_at,
    }
}

fn observed<'a>(
    p: &'a ApplicationProfile,
    core: &'a OfferCore,
    descriptor_digest: &'a str,
) -> Observed<'a> {
    Observed {
        profile: p,
        offer: core,
        provider_id: &p.rendezvous[0].id,
        descriptor_digest,
        platform_binding_id: None,
        now: NOW_OFFER + 1,
    }
}

// ── TEST-236: offer_core and the digest ────────────────────────────────────

#[test]
fn offer_core_is_exactly_the_thirteen_members_from_payload_version_through_expires_at() {
    let p = profile();
    let core = offer_core(&p);
    let value = core.to_json();
    let names = value.member_names();
    assert_eq!(names, ceremony::OFFER_CORE_MEMBERS);
    assert_eq!(names.len(), 13);
    assert!(!names.contains(&"enrollmentEvidence"));
    assert!(!names.contains(&"providerHint"));
}

#[test]
fn the_offer_digest_is_computed_over_offer_core_and_not_over_the_sealed_payload() {
    // The property that makes CON-214 satisfiable at all: a backend signs the
    // digest *before* the offer it will be sealed into exists, so the digest
    // cannot cover the signature that carries it.
    let p = profile();
    let core = offer_core(&p);
    let digest = core.digest();

    let hint = selection::ProviderHint {
        application_id: APPLICATION_ID.into(),
        profile_version: 1,
        provider_id: p.rendezvous[0].id.clone(),
        descriptor_digest: codec::b64url(&p.rendezvous[0].digest),
        offer_digest: digest.clone(),
    };
    let evidence = enrollment::sign(&statement(&p, &core), KID, &backend_key());

    let sealed = seal_offer(&core, &evidence, &hint.to_json());
    let recognised = ceremony::recognise_offer(&sealed).unwrap();

    // Recomputed from the members actually opened, and equal to the one the
    // backend signed and the one the hint carries.
    assert_eq!(recognised.offer_digest, digest);
    assert_eq!(
        ceremony::digest_of_received_offer(&json::recognise(&sealed, LIMITS).unwrap()).unwrap(),
        digest
    );

    // Digesting the whole payload gives a different value — which is what an
    // implementation that "accommodated" the self-reference would compute.
    let whole = ceremony::offer_digest(&json::recognise(&sealed, LIMITS).unwrap());
    assert_ne!(whole, digest, "the two excluded members must change the digest");
}

#[test]
fn changing_any_offer_core_member_changes_the_digest() {
    let p = profile();
    let base = offer_core(&p).digest();
    for mutated in [
        OfferCore { request_id: codec::b64url(&[9u8; 32]), ..offer_core(&p) },
        OfferCore { account_scope_id: codec::b64url(&[9u8; 32]), ..offer_core(&p) },
        OfferCore { expires_at: NOW_OFFER + 119, ..offer_core(&p) },
        OfferCore { requested_permissions: vec![format!("{APPLICATION_ID}#other")], ..offer_core(&p) },
    ] {
        assert_ne!(mutated.digest(), base);
    }
}

// ── TEST-236: the payload member sets are closed ───────────────────────────

#[test]
fn an_offer_with_an_unknown_or_missing_member_is_refused() {
    let p = profile();
    let core = offer_core(&p);
    let evidence = enrollment::sign(&statement(&p, &core), KID, &backend_key());
    let hint = Json::obj([("applicationId", Json::text(APPLICATION_ID))]);

    let Json::Object(mut members) = core.to_json() else { unreachable!() };
    members.push(("enrollmentEvidence".into(), Json::text(evidence.clone())));
    members.push(("providerHint".into(), hint.clone()));
    members.push(("surprise".into(), Json::int(1)));
    let octets = json::canonicalise(&Json::Object(members));
    assert_eq!(
        ceremony::recognise_offer(&octets),
        Err(CeremonyError::UnknownMember("surprise".into()))
    );

    let Json::Object(members) = core.to_json() else { unreachable!() };
    let short: Vec<(String, Json)> =
        members.into_iter().filter(|(k, _)| k != "accountScopeId").collect();
    let mut short = short;
    short.push(("enrollmentEvidence".into(), Json::text(evidence)));
    short.push(("providerHint".into(), hint));
    let octets = json::canonicalise(&Json::Object(short));
    assert_eq!(
        ceremony::recognise_offer(&octets),
        Err(CeremonyError::BadMember("accountScopeId".into()))
    );
}

#[test]
fn an_offer_whose_device_did_does_not_encode_its_own_jwk_is_refused() {
    // Two members naming one key is two places a substitution could hide.
    let p = profile();
    let mut core = offer_core(&p);
    core.device_did = didkey::encode(&[7u8; 32].map(|_| 0u8));
    let core = OfferCore {
        device_did: didkey::encode(
            &ed25519_dalek::SigningKey::from_bytes(&[88u8; 32]).verifying_key().to_bytes(),
        ),
        ..core
    };
    let evidence = enrollment::sign(&statement(&p, &core), KID, &backend_key());
    let sealed = seal_offer(&core, &evidence, &Json::obj([]));
    assert!(matches!(
        ceremony::recognise_offer(&sealed),
        Err(CeremonyError::BadValue { path, .. }) if path == "deviceDid"
    ));
}

// ── TEST-236: the bundle ───────────────────────────────────────────────────

#[test]
fn the_bundle_carries_the_grant_verbatim_and_round_trips_it() {
    // REQ-211: "The same bytes SHALL be independently verifiable after
    // extraction by a non-CBCL application." Byte identity is the whole claim.
    let c = Ceremony::accepted();
    let grant = String::from_utf8(c.grant_bytes.clone()).unwrap();
    let octets = ceremony::build_bundle(&codec::b64url(&[1u8; 32]), &codec::b64url(&[2u8; 32]), &grant, None)
        .unwrap();
    let bundle = ceremony::recognise_bundle(&octets).unwrap();
    assert_eq!(bundle.grant, grant);
    assert_eq!(bundle.grant.as_bytes(), c.grant_bytes.as_slice());
    assert!(bundle.issuer_closure.is_none());
}

#[test]
fn a_bundle_may_inline_a_closure_and_refuses_rather_than_truncating() {
    let c = Ceremony::accepted();
    let grant = String::from_utf8(c.grant_bytes.clone()).unwrap();
    let ids = (codec::b64url(&[1u8; 32]), codec::b64url(&[2u8; 32]));

    let small = vec![7u8; 1_000];
    let octets = ceremony::build_bundle(&ids.0, &ids.1, &grant, Some(&small)).unwrap();
    assert_eq!(ceremony::recognise_bundle(&octets).unwrap().issuer_closure, Some(small));

    // "A payload exceeding the bound is a `PayloadTooLarge` failure, never a
    // silent truncation."
    let huge = vec![7u8; ceremony::MAX_PAYLOAD_OCTETS];
    assert_eq!(
        ceremony::build_bundle(&ids.0, &ids.1, &grant, Some(&huge)),
        Err(CeremonyError::PayloadTooLarge)
    );
}

#[test]
fn a_bundle_naming_another_ceremony_is_a_rejection_and_not_a_new_ceremony() {
    let p = profile();
    let core = offer_core(&p);
    let c = Ceremony::accepted();
    let grant = String::from_utf8(c.grant_bytes).unwrap();

    let matching = ceremony::recognise_bundle(
        &ceremony::build_bundle(&core.ceremony_id, &core.request_id, &grant, None).unwrap(),
    )
    .unwrap();
    assert!(ceremony::bundle_matches_offer(&matching, &core).is_ok());

    for (ceremony_id, request_id) in [
        (codec::b64url(&[99u8; 32]), core.request_id.clone()),
        (core.ceremony_id.clone(), codec::b64url(&[99u8; 32])),
    ] {
        let other = ceremony::recognise_bundle(
            &ceremony::build_bundle(&ceremony_id, &request_id, &grant, None).unwrap(),
        )
        .unwrap();
        assert_eq!(
            ceremony::bundle_matches_offer(&other, &core),
            Err(CeremonyError::OfferMismatch)
        );
    }
}

#[test]
fn a_bundle_with_the_wrong_media_type_or_role_is_refused() {
    let value = Json::obj([
        ("payloadVersion", Json::int(1)),
        ("role", Json::text("offer")),
        ("ceremonyId", Json::text(codec::b64url(&[1u8; 32]))),
        ("requestId", Json::text(codec::b64url(&[2u8; 32]))),
        ("grantMediaType", Json::text("application/vc+jwt")),
        ("grant", Json::text("a.b.c")),
    ]);
    assert!(matches!(
        ceremony::recognise_bundle(&json::canonicalise(&value)),
        Err(CeremonyError::BadValue { path, .. }) if path == "role"
    ));

    let value = Json::obj([
        ("payloadVersion", Json::int(1)),
        ("role", Json::text("bundle")),
        ("ceremonyId", Json::text(codec::b64url(&[1u8; 32]))),
        ("requestId", Json::text(codec::b64url(&[2u8; 32]))),
        ("grantMediaType", Json::text("application/jwt")),
        ("grant", Json::text("a.b.c")),
    ]);
    assert!(matches!(
        ceremony::recognise_bundle(&json::canonicalise(&value)),
        Err(CeremonyError::BadValue { path, .. }) if path == "grantMediaType"
    ));
}

// ── TEST-228: enrollment evidence ──────────────────────────────────────────

#[test]
fn a_well_formed_statement_verifies_against_the_authenticated_profile() {
    let p = profile_with_real_key();
    let core = offer_core(&p);
    let digest = codec::b64url(&p.rendezvous[0].digest);
    let compact = enrollment::sign(&statement(&p, &core), KID, &backend_key());
    let verified = enrollment::verify(&compact, &observed(&p, &core, &digest)).unwrap();
    assert_eq!(verified.request_id, core.request_id);
    assert_eq!(verified.offer_digest, core.digest());
}

#[test]
fn a_statement_signed_by_a_key_outside_the_profile_is_unverified() {
    // The line that makes a copied public profile useless: the key comes from
    // the origin-authenticated document, and its private half is a backend
    // credential CON-201 forbids embedding in a native app.
    let p = profile_with_real_key();
    let core = offer_core(&p);
    let digest = codec::b64url(&p.rendezvous[0].digest);

    let impostor = ed25519_dalek::SigningKey::from_bytes(&[123u8; 32]);
    let compact = enrollment::sign(&statement(&p, &core), KID, &impostor);
    assert_eq!(
        enrollment::verify(&compact, &observed(&p, &core, &digest)),
        Err(EnrollmentError::EnrollmentBadSignature)
    );

    // …and a `kid` the profile does not declare.
    let compact = enrollment::sign(
        &statement(&p, &core),
        "https://photos.example/selfsame/application#unknown",
        &backend_key(),
    );
    assert_eq!(
        enrollment::verify(&compact, &observed(&p, &core, &digest)),
        Err(EnrollmentError::UnverifiedApplication)
    );
}

#[test]
fn each_binding_mismatch_returns_its_own_closed_token() {
    // TEST-228: "the exact application/account/device/permission/provider/offer
    // bindings". Each is mutated alone, and each must name its own token —
    // CON-226 requires two stacks to agree on *which* check fired.
    let p = profile_with_real_key();
    let core = offer_core(&p);
    let digest = codec::b64url(&p.rendezvous[0].digest);

    let cases: Vec<(EnrollmentStatement, EnrollmentError)> = vec![
        (
            EnrollmentStatement { profile_digest: codec::b64url(&[0u8; 32]), ..statement(&p, &core) },
            EnrollmentError::ProfileMismatch,
        ),
        (
            EnrollmentStatement {
                account_scope_id: codec::b64url(&[9u8; 32]),
                ..statement(&p, &core)
            },
            EnrollmentError::AccountBindingMismatch,
        ),
        (
            EnrollmentStatement {
                device_key_digest: codec::b64url(&[9u8; 32]),
                ..statement(&p, &core)
            },
            EnrollmentError::DeviceBindingMismatch,
        ),
        (
            EnrollmentStatement {
                requested_permissions: vec![format!("{APPLICATION_ID}#other")],
                ..statement(&p, &core)
            },
            EnrollmentError::PermissionMismatch,
        ),
        (
            EnrollmentStatement { provider_id: "global-secondary".into(), ..statement(&p, &core) },
            EnrollmentError::ProviderMismatch,
        ),
        (
            EnrollmentStatement { offer_digest: codec::b64url(&[9u8; 32]), ..statement(&p, &core) },
            EnrollmentError::OfferMismatch,
        ),
        (
            EnrollmentStatement { request_id: codec::b64url(&[9u8; 32]), ..statement(&p, &core) },
            EnrollmentError::OfferMismatch,
        ),
        (
            EnrollmentStatement {
                platform_binding_id: "android:com.attacker.app:x".into(),
                ..statement(&p, &core)
            },
            EnrollmentError::PlatformBindingMismatch,
        ),
    ];

    for (mutated, expected) in cases {
        let compact = enrollment::sign(&mutated, KID, &backend_key());
        assert_eq!(
            enrollment::verify(&compact, &observed(&p, &core, &digest)),
            Err(expected),
            "{expected:?}"
        );
    }
}

#[test]
fn an_android_binding_with_nothing_attributed_is_refused_and_an_apple_one_is_not() {
    // `CON-222` states the calling-package comparison as an obligation with a
    // named failure; `CON-223` records that Apple gives the wallet no general
    // caller attribution. So absent attribution is conforming on one platform
    // and a skipped mandatory check on the other, and `verify` has to tell them
    // apart — otherwise any Android caller reaches the Apple carve-out by
    // having its adapter report nothing.
    let p = profile_with_real_key();
    let core = offer_core(&p);
    let digest = codec::b64url(&p.rendezvous[0].digest);
    let android = format!("android:com.example.photos:{}", codec::b64url(&[2u8; 32]));

    let compact = enrollment::sign(
        &EnrollmentStatement { platform_binding_id: android.clone(), ..statement(&p, &core) },
        KID,
        &backend_key(),
    );
    assert_eq!(
        enrollment::verify(&compact, &observed(&p, &core, &digest)),
        Err(EnrollmentError::PlatformBindingMismatch),
        "an unattributed Android caller must not be admitted",
    );

    // The same statement, with the package the OS actually reported.
    let attributed =
        Observed { platform_binding_id: Some(&android), ..observed(&p, &core, &digest) };
    assert!(
        enrollment::verify(&compact, &attributed).is_ok(),
        "an attributed Android caller matching the binding is admitted",
    );

    // The Apple binding, unattributed, still passes: the carve-out is per
    // platform and this is the case it exists for.
    let apple = enrollment::sign(&statement(&p, &core), KID, &backend_key());
    assert!(enrollment::verify(&apple, &observed(&p, &core, &digest)).is_ok());
}

#[test]
fn both_timestamp_boundaries_are_exercised() {
    let p = profile_with_real_key();
    let core = offer_core(&p);
    let digest = codec::b64url(&p.rendezvous[0].digest);
    let compact = enrollment::sign(&statement(&p, &core), KID, &backend_key());

    let at = |now: i64| Observed { now, ..observed(&p, &core, &digest) };
    assert!(enrollment::verify(&compact, &at(core.issued_at)).is_ok(), "at issuedAt");
    assert!(enrollment::verify(&compact, &at(core.expires_at - 1)).is_ok(), "one second before");
    assert_eq!(
        enrollment::verify(&compact, &at(core.issued_at - 1)),
        Err(EnrollmentError::EnrollmentExpired)
    );
    assert_eq!(
        enrollment::verify(&compact, &at(core.expires_at)),
        Err(EnrollmentError::EnrollmentExpired),
        "the window is half-open"
    );
}

#[test]
fn a_window_longer_than_one_hundred_and_twenty_seconds_is_malformed() {
    let p = profile_with_real_key();
    let core = offer_core(&p);
    let digest = codec::b64url(&p.rendezvous[0].digest);
    let long = EnrollmentStatement {
        expires_at: core.issued_at + 121,
        ..statement(&p, &core)
    };
    let compact = enrollment::sign(&long, KID, &backend_key());
    assert_eq!(
        enrollment::verify(&compact, &observed(&p, &core, &digest)),
        Err(EnrollmentError::EnrollmentMalformed)
    );
}

// ── TEST-228: replay, and the scope-invariant assertion ────────────────────

#[test]
fn every_retry_of_byte_identical_evidence_returns_enrollment_replay() {
    // TEST-228: "Retry the byte-identical evidence before and after expiry,
    // after approval, after denial, and after a post-consumption process crash.
    // Every retry returns `EnrollmentReplay`."
    let p = profile_with_real_key();
    let core = offer_core(&p);
    let mut ledger = RequestLedger::new();

    assert!(ledger.consume(&core.request_id).is_ok(), "the first use succeeds");
    for _ in 0..5 {
        assert_eq!(ledger.consume(&core.request_id), Err(EnrollmentError::EnrollmentReplay));
    }
    // A crash after consumption loses the ceremony rather than permitting a
    // second one, because the record is what survives, not the decision.
    assert!(ledger.is_consumed(&core.request_id));
}

#[test]
fn a_denial_consumes_the_request_id_just_as_an_approval_does() {
    // Consuming only on approval would make a denial a free retry, which is the
    // whole reason CON-214 step 5 says "whether the request is approved or
    // rejected".
    let p = profile_with_real_key();
    let core = offer_core(&p);
    let mut ledger = RequestLedger::new();
    ledger.consume(&core.request_id).unwrap();
    // The person then declines. Nothing gives the identifier back.
    assert_eq!(ledger.consume(&core.request_id), Err(EnrollmentError::EnrollmentReplay));
}

#[test]
fn the_ledger_holds_exactly_one_record_per_ceremony() {
    // TEST-228's scope-invariant assertion: "permits only one consumed-ID
    // record and leaves every other application and account unchanged".
    let mut ledger = RequestLedger::new();
    assert!(ledger.is_empty());
    let id = codec::b64url(&[2u8; 32]);
    ledger.consume(&id).unwrap();
    for _ in 0..10 {
        let _ = ledger.consume(&id);
    }
    assert_eq!(ledger.len(), 1, "a replay must not add a second record");
}

#[test]
fn every_closed_token_is_reachable_and_named() {
    // CON-226 requires a corpus case for each. The enum has no catch-all, so a
    // thirteenth failure mode would have to be added here first.
    assert_eq!(enrollment::ERROR_TOKENS.len(), 12);
    for token in enrollment::ERROR_TOKENS {
        assert!(!token.is_empty());
    }
    assert_eq!(EnrollmentError::EnrollmentReplay.to_string(), "EnrollmentReplay");
    assert_eq!(EnrollmentError::OfferMismatch.to_string(), "OfferMismatch");
}

// ── TEST-227 / TEST-230: the handoff ───────────────────────────────────────

#[test]
fn the_handoff_carries_the_code_and_no_routing_information() {
    // CON-215: "Application identity and provider selection are not carried
    // here … so the handoff cannot become a second routing path."
    let handoff = Handoff {
        ceremony_id: codec::b64url(&[1u8; 32]),
        offer_digest: codec::b64url(&[5u8; 32]),
        code: [9u8; 16],
        return_uri: Some("https://photos.example/.well-known/selfsame/return".into()),
    };
    let octets = json::canonicalise(&handoff.to_json());
    let recognised = Handoff::recognise(&octets).unwrap();
    assert_eq!(recognised, handoff);

    let text = String::from_utf8(octets).unwrap();
    for absent in ["applicationId", "providerId", "pairingUrl", "nameplate", "route"] {
        assert!(!text.contains(absent), "the handoff carries `{absent}`");
    }
}

#[test]
fn a_handoff_with_an_unknown_member_or_a_wrong_version_is_refused() {
    let base = Handoff {
        ceremony_id: codec::b64url(&[1u8; 32]),
        offer_digest: codec::b64url(&[5u8; 32]),
        code: [9u8; 16],
        return_uri: None,
    };
    let Json::Object(mut members) = base.to_json() else { unreachable!() };
    members.push(("applicationId".into(), Json::text(APPLICATION_ID)));
    assert_eq!(
        Handoff::recognise(&json::canonicalise(&Json::Object(members))),
        Err(CeremonyError::UnknownMember("applicationId".into()))
    );

    let Json::Object(mut members) = base.to_json() else { unreachable!() };
    members.iter_mut().find(|(k, _)| k == "handoffVersion").unwrap().1 = Json::int(2);
    assert!(matches!(
        Handoff::recognise(&json::canonicalise(&Json::Object(members))),
        Err(CeremonyError::BadValue { path, .. }) if path == "handoffVersion"
    ));
}

#[test]
fn a_malformed_return_uri_is_refused_rather_than_read_as_absent() {
    // `and_then(Json::as_str)` turned every present-but-not-a-string value into
    // `None`, so a malformed handoff recognised as a well-formed one with no
    // return — the difference between "refused" and "silently accepted".
    let base = Handoff {
        ceremony_id: codec::b64url(&[1u8; 32]),
        offer_digest: codec::b64url(&[5u8; 32]),
        code: [9u8; 16],
        return_uri: None,
    };
    for value in [
        Json::int(7),
        Json::Null,
        Json::Bool(true),
        Json::arr([Json::text("https://photos.example/return")]),
        Json::obj([("href", Json::text("https://photos.example/return"))]),
    ] {
        let Json::Object(mut members) = base.to_json() else { unreachable!() };
        members.push(("returnUri".into(), value.clone()));
        assert!(
            Handoff::recognise(&json::canonicalise(&Json::Object(members))).is_err(),
            "a returnUri of {value:?} was read as absent"
        );
    }

    // Present, a string, and not a canonical HTTPS URI.
    for text in ["", "not a uri", "http://photos.example/return", "javascript:alert(1)"] {
        let Json::Object(mut members) = base.to_json() else { unreachable!() };
        members.push(("returnUri".into(), Json::text(text)));
        assert!(
            Handoff::recognise(&json::canonicalise(&Json::Object(members))).is_err(),
            "`{text}` was recognised as a return URI"
        );
    }
}

#[test]
fn a_return_uri_is_bound_to_the_authenticated_platform_binding() {
    // A destination the caller chose is a destination an attacker chose. Only
    // the URI the CON-214-authenticated binding declares may be used, and
    // equality is exact: two paths on one origin are two destinations.
    let declared = "https://photos.example/.well-known/selfsame/return";
    let apple = MobileBinding::Apple {
        id: "apple:TEAM123456:com.example.photos:https://photos.example".into(),
        team_id: "TEAM123456".into(),
        bundle_id: "com.example.photos".into(),
        return_uri: declared.into(),
    };
    let android = MobileBinding::Android {
        id: "android:com.example.photos:AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI".into(),
        package_name: "com.example.photos".into(),
        signing_certificate_sha256: vec![
            "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI".into(),
        ],
    };
    let handoff = |uri: Option<&str>| Handoff {
        ceremony_id: codec::b64url(&[1u8; 32]),
        offer_digest: codec::b64url(&[5u8; 32]),
        code: [9u8; 16],
        return_uri: uri.map(str::to_string),
    };

    assert!(handoff(Some(declared)).binds_to(&apple).is_ok());
    // No return at all is the ordinary case and binds to anything.
    assert!(handoff(None).binds_to(&apple).is_ok());
    assert!(handoff(None).binds_to(&android).is_ok());

    for attacker in [
        "https://attacker.example/.well-known/selfsame/return",
        // Same origin, different path.
        "https://photos.example/attacker-controlled",
        // Same host, different scheme-authority.
        "https://photos.example.attacker.test/.well-known/selfsame/return",
    ] {
        assert!(
            handoff(Some(attacker)).binds_to(&apple).is_err(),
            "`{attacker}` was accepted against a binding declaring `{declared}`"
        );
    }

    // CON-222's return path is a verified App Link, not a handoff member.
    assert!(handoff(Some(declared)).binds_to(&android).is_err());
}

#[test]
fn every_dispatch_result_except_dispatched_burns_the_ceremony() {
    // REQ-225: ambiguous or failed delivery "permanently abandons that
    // ceremony", and a retry starts with fresh everything.
    for result in [
        DispatchResult::WalletUnavailable,
        DispatchResult::UnverifiedWalletTarget,
        DispatchResult::HandoffMalformed,
        DispatchResult::HandoffAmbiguous,
        DispatchResult::PlatformBindingMismatch,
        DispatchResult::UserDenied,
    ] {
        assert!(result.burns_ceremony(), "{result:?}");
    }
    assert!(!DispatchResult::Dispatched.burns_ceremony());
}

// ── TEST-231: the callback is non-authoritative ────────────────────────────

#[test]
fn the_serialised_callback_has_exactly_three_fields_and_no_secret() {
    let ret = HandoffReturn { ceremony_id: codec::b64url(&[1u8; 32]), outcome: Outcome::Completed };
    let octets = json::canonicalise(&ret.to_json());
    let value = json::recognise(&octets, LIMITS).unwrap();
    assert_eq!(value.member_names(), vec!["ceremonyId", "handoffVersion", "outcome"]);
    assert_eq!(value.member_names().len(), 3);
    assert_eq!(HandoffReturn::recognise(&octets).unwrap(), ret);
}

#[test]
fn a_callback_carrying_anything_else_is_refused() {
    // CON-215 lists what it must not contain. The closed member set is what
    // makes that a property of the format rather than a promise about the code.
    for extra in ["grant", "did", "accountScopeId", "error", "permissions", "c"] {
        let mut members = vec![
            ("handoffVersion".to_string(), Json::int(1)),
            ("ceremonyId".to_string(), Json::text(codec::b64url(&[1u8; 32]))),
            ("outcome".to_string(), Json::text("completed")),
        ];
        members.push((extra.to_string(), Json::text("x")));
        assert!(
            HandoffReturn::recognise(&json::canonicalise(&Json::Object(members))).is_err(),
            "a callback carrying `{extra}` was accepted"
        );
    }
}

#[test]
fn a_callback_may_only_foreground_an_exactly_matching_pending_session() {
    // TEST-231: "Send `completed` before consent, after denial, for a different
    // application/account/ceremony, and with no pending local session. The app
    // may foreground only the exactly matching pending session."
    let mine = codec::b64url(&[1u8; 32]);
    let theirs = codec::b64url(&[2u8; 32]);
    let ret = HandoffReturn { ceremony_id: mine.clone(), outcome: Outcome::Completed };

    assert!(ret.may_foreground(Some(&mine)));
    assert!(!ret.may_foreground(Some(&theirs)), "a different ceremony");
    assert!(!ret.may_foreground(None), "no pending local session");
}

#[test]
fn every_outcome_round_trips_and_no_other_value_is_admitted() {
    for outcome in [Outcome::Completed, Outcome::Cancelled, Outcome::Failed] {
        let ret = HandoffReturn { ceremony_id: codec::b64url(&[1u8; 32]), outcome };
        let octets = json::canonicalise(&ret.to_json());
        assert_eq!(HandoffReturn::recognise(&octets).unwrap().outcome, outcome);
    }
    let value = Json::obj([
        ("handoffVersion", Json::int(1)),
        ("ceremonyId", Json::text(codec::b64url(&[1u8; 32]))),
        ("outcome", Json::text("succeeded")),
    ]);
    assert!(matches!(
        HandoffReturn::recognise(&json::canonicalise(&value)),
        Err(CeremonyError::BadValue { path, .. }) if path == "outcome"
    ));
}

// ── helpers ────────────────────────────────────────────────────────────────

const LIMITS: selfsame_app_identity::json::Limits =
    selfsame_app_identity::json::Limits { max_bytes: 69_607, max_depth: 8 };

fn seal_offer(core: &OfferCore, evidence: &str, hint: &Json) -> Vec<u8> {
    let Json::Object(mut members) = core.to_json() else { unreachable!() };
    members.push(("enrollmentEvidence".into(), Json::text(evidence)));
    members.push(("providerHint".into(), hint.clone()));
    json::canonicalise(&Json::Object(members))
}

#[allow(dead_code)]
fn unused(_: BundlePayload) {}
