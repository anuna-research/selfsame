//! `TEST-228` and `TEST-236` — enrollment evidence and replay, and the ceremony
//! payloads with their offer digest.
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
mod common;

use common::*;
use selfsame_app_identity::ceremony::{self, BundlePayload, CeremonyError, OfferCore};
use selfsame_app_identity::codec;
use selfsame_app_identity::enrollment::{
    self, EnrollmentError, EnrollmentStatement, Observed, RequestLedger,
};
use selfsame_app_identity::json::{self, Json};
use selfsame_app_identity::profile::ApplicationProfile;
use selfsame_app_identity::{didkey, provider_hint};

const NOW_OFFER: i64 = NOW;

fn profile() -> ApplicationProfile {
    ApplicationProfile::recognise(&profile_octets()).unwrap()
}

fn offer_core(p: &ApplicationProfile) -> OfferCore {
    let device = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32])
        .verifying_key()
        .to_bytes();
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
    let octets = with_nested(
        "enrollment.requestSigningKeys.publicKeyJwk.x",
        Json::text(codec::b64url(&public)),
    );
    ApplicationProfile::recognise(&octets).unwrap()
}

fn statement(p: &ApplicationProfile, core: &OfferCore) -> EnrollmentStatement {
    let descriptor = &p.cbcl_pairing_relays[0];
    EnrollmentStatement {
        request_id: core.request_id.clone(),
        ceremony_id: core.ceremony_id.clone(),
        application_id: core.application_id.clone(),
        profile_version: 1,
        profile_digest: codec::b64url(p.digest()),
        account_scope_id: core.account_scope_id.clone(),
        device_key_digest: enrollment::device_key_digest(core),
        requested_permissions: core.requested_permissions.clone(),
        provider_id: descriptor.operator_id.clone(),
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
        provider_id: &p.cbcl_pairing_relays[0].operator_id,
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

    let hint = provider_hint::ProviderHint {
        application_id: APPLICATION_ID.into(),
        profile_version: 1,
        provider_id: p.cbcl_pairing_relays[0].operator_id.clone(),
        descriptor_digest: codec::b64url(&p.cbcl_pairing_relays[0].digest),
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
    assert_ne!(
        whole, digest,
        "the two excluded members must change the digest"
    );
}

#[test]
fn changing_any_offer_core_member_changes_the_digest() {
    let p = profile();
    let base = offer_core(&p).digest();
    for mutated in [
        OfferCore {
            request_id: codec::b64url(&[9u8; 32]),
            ..offer_core(&p)
        },
        OfferCore {
            account_scope_id: codec::b64url(&[9u8; 32]),
            ..offer_core(&p)
        },
        OfferCore {
            expires_at: NOW_OFFER + 119,
            ..offer_core(&p)
        },
        OfferCore {
            requested_permissions: vec![format!("{APPLICATION_ID}#other")],
            ..offer_core(&p)
        },
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

    let Json::Object(mut members) = core.to_json() else {
        unreachable!()
    };
    members.push(("enrollmentEvidence".into(), Json::text(evidence.clone())));
    members.push(("providerHint".into(), hint.clone()));
    members.push(("surprise".into(), Json::int(1)));
    let octets = json::canonicalise(&Json::Object(members));
    assert_eq!(
        ceremony::recognise_offer(&octets),
        Err(CeremonyError::UnknownMember("surprise".into()))
    );

    let Json::Object(members) = core.to_json() else {
        unreachable!()
    };
    let short: Vec<(String, Json)> = members
        .into_iter()
        .filter(|(k, _)| k != "accountScopeId")
        .collect();
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
            &ed25519_dalek::SigningKey::from_bytes(&[88u8; 32])
                .verifying_key()
                .to_bytes(),
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
    let octets = ceremony::build_bundle(
        &codec::b64url(&[1u8; 32]),
        &codec::b64url(&[2u8; 32]),
        &grant,
        None,
    )
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
    assert_eq!(
        ceremony::recognise_bundle(&octets).unwrap().issuer_closure,
        Some(small)
    );

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
    let digest = codec::b64url(&p.cbcl_pairing_relays[0].digest);
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
    let digest = codec::b64url(&p.cbcl_pairing_relays[0].digest);

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
    let digest = codec::b64url(&p.cbcl_pairing_relays[0].digest);

    let cases: Vec<(EnrollmentStatement, EnrollmentError)> = vec![
        (
            EnrollmentStatement {
                profile_digest: codec::b64url(&[0u8; 32]),
                ..statement(&p, &core)
            },
            EnrollmentError::ProfileMismatch,
        ),
        // The profile block has three clauses and only its third was ever the
        // sole one true, so a mutant collapsing the application-ID comparison
        // survived. `profileVersion != 1` is now outside the closed CON-214
        // language and is exercised separately as `EnrollmentMalformed`.
        (
            EnrollmentStatement {
                // Keep the origin fixed so the `kid` and permission remain in
                // the closed language; only the application identifier differs
                // from the authenticated profile.
                application_id: "https://photos.example/selfsame/other".into(),
                ..statement(&p, &core)
            },
            EnrollmentError::ProfileMismatch,
        ),
        // `expiresAt` alone, so the second clause of the timestamp comparison
        // carries the refusal on its own. Shortened rather than extended:
        // `recognise` caps the evidence window at 120 s, so a longer one is
        // `EnrollmentMalformed` and never reaches the comparison at all. And
        // the wallet's own window check that follows does not fire on this
        // value either, which is what leaves the offer comparison as the only
        // thing that can refuse it.
        (
            EnrollmentStatement {
                expires_at: core.expires_at - 30,
                ..statement(&p, &core)
            },
            EnrollmentError::OfferMismatch,
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
            EnrollmentStatement {
                provider_id: "global-secondary".into(),
                ..statement(&p, &core)
            },
            EnrollmentError::ProviderMismatch,
        ),
        (
            EnrollmentStatement {
                offer_digest: codec::b64url(&[9u8; 32]),
                ..statement(&p, &core)
            },
            EnrollmentError::OfferMismatch,
        ),
        (
            EnrollmentStatement {
                request_id: codec::b64url(&[9u8; 32]),
                ..statement(&p, &core)
            },
            EnrollmentError::OfferMismatch,
        ),
        (
            EnrollmentStatement {
                platform_binding_id: format!(
                    "android:com.attacker.app:{}",
                    codec::b64url(&[8u8; 32])
                ),
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
fn inherited_con_214_grammars_are_part_of_recognition_for_both_paths() {
    let p = profile_with_real_key();
    let core = offer_core(&p);
    let base = statement(&p, &core);

    let mut too_many_permissions = Vec::new();
    for index in 0..65 {
        too_many_permissions.push(format!("{APPLICATION_ID}#{index:02}"));
    }

    let cases = [
        EnrollmentStatement {
            profile_version: 2,
            ..base.clone()
        },
        EnrollmentStatement {
            application_id: "not-an-https-uri".into(),
            ..base.clone()
        },
        EnrollmentStatement {
            account_scope_id: "not-base64url".into(),
            ..base.clone()
        },
        EnrollmentStatement {
            requested_permissions: vec!["https://elsewhere.example/app#device".into()],
            ..base.clone()
        },
        EnrollmentStatement {
            requested_permissions: too_many_permissions,
            ..base.clone()
        },
        EnrollmentStatement {
            provider_id: "Not-A-Provider".into(),
            ..base.clone()
        },
        EnrollmentStatement {
            platform_binding_id: "not-a-binding".into(),
            ..base.clone()
        },
        EnrollmentStatement {
            return_uri: "https://elsewhere.example/return".into(),
            ..base.clone()
        },
    ];

    for malformed in cases {
        let octets = json::canonicalise(&enrollment::build(&malformed));
        assert_eq!(
            enrollment::recognise_unsigned(&octets, KID),
            Err(EnrollmentError::EnrollmentMalformed)
        );

        let compact = enrollment::sign(&malformed, KID, &backend_key());
        assert_eq!(
            enrollment::recognise(&compact),
            Err(EnrollmentError::EnrollmentMalformed)
        );
    }

    let octets = json::canonicalise(&enrollment::build(&base));
    let other_origin_kid = "https://elsewhere.example/app#enrollment";
    assert_eq!(
        enrollment::recognise_unsigned(&octets, other_origin_kid),
        Err(EnrollmentError::EnrollmentMalformed)
    );
    let compact = enrollment::sign(&base, other_origin_kid, &backend_key());
    assert_eq!(
        enrollment::recognise(&compact),
        Err(EnrollmentError::EnrollmentMalformed)
    );
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
    let digest = codec::b64url(&p.cbcl_pairing_relays[0].digest);
    let android = format!("android:com.example.photos:{}", codec::b64url(&[2u8; 32]));

    let compact = enrollment::sign(
        &EnrollmentStatement {
            platform_binding_id: android.clone(),
            ..statement(&p, &core)
        },
        KID,
        &backend_key(),
    );
    assert_eq!(
        enrollment::verify(&compact, &observed(&p, &core, &digest)),
        Err(EnrollmentError::PlatformBindingMismatch),
        "an unattributed Android caller must not be admitted",
    );

    // The same statement, with the package the OS actually reported.
    let attributed = Observed {
        platform_binding_id: Some(&android),
        ..observed(&p, &core, &digest)
    };
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
fn an_attributed_caller_that_is_not_the_binding_the_statement_names_is_refused() {
    // `CON-222`: "compares it to the `platformBindingId` in the `CON-214`
    // evidence. A mismatch is `PlatformBindingMismatch`." That comparison is
    // the whole point of the caller check, and nothing exercised it — the
    // existing mismatch case names a binding the profile does not carry, so the
    // lookup fails first and the comparison is never reached.
    //
    // This is the case where both are real: the profile declares both bindings,
    // the statement names the Apple one, and the OS reports the Android one. A
    // caller substituting itself for another declared application on the same
    // device is exactly what the comparison stands between.
    let p = profile_with_real_key();
    let core = offer_core(&p);
    let digest = codec::b64url(&p.cbcl_pairing_relays[0].digest);
    let android = format!("android:com.example.photos:{}", codec::b64url(&[2u8; 32]));

    // The statement names Apple; the platform attributed Android.
    let apple = enrollment::sign(&statement(&p, &core), KID, &backend_key());
    let elsewhere = Observed {
        platform_binding_id: Some(&android),
        ..observed(&p, &core, &digest)
    };
    assert_eq!(
        enrollment::verify(&apple, &elsewhere),
        Err(EnrollmentError::PlatformBindingMismatch),
        "an observed caller that is not the one the statement names must not pass",
    );

    // …and the same statement with the caller it names does pass, so the
    // refusal above is the comparison rather than the presence of an
    // observation.
    let apple_id = "apple:TEAM123456:com.example.photos:https://photos.example";
    let matching = Observed {
        platform_binding_id: Some(apple_id),
        ..observed(&p, &core, &digest)
    };
    assert!(enrollment::verify(&apple, &matching).is_ok());
}

#[test]
fn a_statement_matching_the_profile_and_contradicting_the_offer_is_refused() {
    // The check `verify` carries a paragraph of reasoning for and no test:
    //
    //   "A backend that signs a statement whose profile fields match the
    //   fetched profile while the *offer* carries different ones satisfies the
    //   first check and contradicts the offer it claims to be enrolling."
    //
    // `applicationId`, `profileVersion` and `profileDigest` are compared twice
    // — once against the profile the wallet fetched, once against the offer
    // this ceremony is processing — and no case could ever reach the second
    // comparison, because mutating the *statement* trips the first. Three
    // mutants collapsing the offer comparison therefore survived.
    //
    // Reaching it needs the offer mutated instead, with the statement left
    // agreeing with the profile. `offerDigest` is taken from the mutated offer
    // so the digest check does not fire first and mask which clause refused.
    let p = profile_with_real_key();
    let digest = codec::b64url(&p.cbcl_pairing_relays[0].digest);

    let mut by_application = offer_core(&p);
    by_application.application_id = OTHER_APPLICATION_ID.into();
    let mut by_version = offer_core(&p);
    by_version.profile_version = 2;
    let mut by_digest = offer_core(&p);
    by_digest.profile_digest = codec::b64url(&[9u8; 32]);

    for (member, offer) in [
        ("applicationId", by_application),
        ("profileVersion", by_version),
        ("profileDigest", by_digest),
    ] {
        let st = EnrollmentStatement {
            // The three the first block checks, restored to the profile's own
            // values — so the statement passes that block cleanly.
            application_id: p.application_id.as_str().to_string(),
            profile_version: 1,
            profile_digest: codec::b64url(p.digest()),
            // …and bound to the offer actually being processed, so nothing
            // else fires.
            offer_digest: offer.digest(),
            ..statement(&p, &offer)
        };
        let compact = enrollment::sign(&st, KID, &backend_key());
        assert_eq!(
            enrollment::verify(&compact, &observed(&p, &offer, &digest)),
            Err(EnrollmentError::OfferMismatch),
            "an offer whose {member} contradicts the statement must be refused",
        );
    }

    // The same construction with nothing substituted is accepted, so each
    // refusal above is the substitution and not the way the fixture is built.
    let offer = offer_core(&p);
    let st = EnrollmentStatement {
        application_id: p.application_id.as_str().to_string(),
        profile_version: 1,
        profile_digest: codec::b64url(p.digest()),
        offer_digest: offer.digest(),
        ..statement(&p, &offer)
    };
    let compact = enrollment::sign(&st, KID, &backend_key());
    assert!(enrollment::verify(&compact, &observed(&p, &offer, &digest)).is_ok());
}

#[test]
fn both_timestamp_boundaries_are_exercised() {
    let p = profile_with_real_key();
    let core = offer_core(&p);
    let digest = codec::b64url(&p.cbcl_pairing_relays[0].digest);
    let compact = enrollment::sign(&statement(&p, &core), KID, &backend_key());

    let at = |now: i64| Observed {
        now,
        ..observed(&p, &core, &digest)
    };
    assert!(
        enrollment::verify(&compact, &at(core.issued_at)).is_ok(),
        "at issuedAt"
    );
    assert!(
        enrollment::verify(&compact, &at(core.expires_at - 1)).is_ok(),
        "one second before"
    );
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
    let digest = codec::b64url(&p.cbcl_pairing_relays[0].digest);
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

    assert!(
        ledger.consume(&core.request_id).is_ok(),
        "the first use succeeds"
    );
    for _ in 0..5 {
        assert_eq!(
            ledger.consume(&core.request_id),
            Err(EnrollmentError::EnrollmentReplay)
        );
    }
    // A crash after consumption loses the ceremony rather than permitting a
    // second one, because the record is what survives, not the decision.
    assert!(ledger.is_consumed(&core.request_id));
    // …and the query answers about *this* identifier rather than about having
    // consumed anything. A ledger that said yes to everything would refuse
    // every ceremony after the first, which fails closed and is therefore easy
    // to mistake for correct — a body of `true` survived the suite until now.
    assert!(!ledger.is_consumed("a request id this ledger has never seen"));
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
    assert_eq!(
        ledger.consume(&core.request_id),
        Err(EnrollmentError::EnrollmentReplay)
    );
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
    assert_eq!(
        EnrollmentError::EnrollmentReplay.to_string(),
        "EnrollmentReplay"
    );
    assert_eq!(EnrollmentError::OfferMismatch.to_string(), "OfferMismatch");
}

// ── helpers ────────────────────────────────────────────────────────────────

const LIMITS: selfsame_app_identity::json::Limits = selfsame_app_identity::json::Limits {
    max_bytes: 69_607,
    max_depth: 8,
};

fn seal_offer(core: &OfferCore, evidence: &str, hint: &Json) -> Vec<u8> {
    let Json::Object(mut members) = core.to_json() else {
        unreachable!()
    };
    members.push(("enrollmentEvidence".into(), Json::text(evidence)));
    members.push(("providerHint".into(), hint.clone()));
    json::canonicalise(&Json::Object(members))
}

#[allow(dead_code)]
fn unused(_: BundlePayload) {}
