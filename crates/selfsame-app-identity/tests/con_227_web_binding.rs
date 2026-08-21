//! `TEST-246` — web manual binding acceptance rules, `CON-227`.
//!
//! **Validates:** `REQ-220`, `REQ-222`, `REQ-223`, `CON-214`, `CON-227`.
//!
//! The recogniser rows live in `con_201_profile.rs`; these are the verifier
//! rows: unattributed evidence passes exactly a declared web binding, any
//! platform-attributed caller against one is `PlatformBindingMismatch`, and
//! the mixed-profile downgrade route around `CON-222` stays shut.

mod common;

use common::*;
use selfsame_app_identity::authorise::{authorise, AuthoriseError, Observation};
use selfsame_app_identity::ceremony::OfferCore;
use selfsame_app_identity::codec;
use selfsame_app_identity::enrollment::{self, EnrollmentStatement};
use selfsame_app_identity::json::{self, Json};
use selfsame_app_identity::platform::{caller_matches_binding, CallerEvidence, PlatformError};
use selfsame_app_identity::profile::{ApplicationProfile, MobileBinding};
use selfsame_app_identity::{didkey, provider_hint};

const KID: &str = "https://photos.example/selfsame/application#enrollment-2026-01";
const WEB_BINDING_ID: &str = "web:https://photos.example";

fn backend_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0u8; 32])
}

fn web_binding() -> MobileBinding {
    MobileBinding::Web {
        id: WEB_BINDING_ID.into(),
        origin: "https://photos.example".into(),
    }
}

/// The example profile with a real enrollment key and the given bindings.
fn profile_octets_with(bindings: Json) -> Vec<u8> {
    let Json::Object(mut members) = profile_value() else {
        unreachable!()
    };
    let enrollment_slot = members
        .iter_mut()
        .find(|(k, _)| k == "enrollment")
        .expect("fixture has enrollment");
    let Json::Object(ref mut enrollment_members) = enrollment_slot.1 else {
        unreachable!()
    };
    for (name, value) in enrollment_members.iter_mut() {
        if name == "mobileBindings" {
            *value = bindings.clone();
        }
        if name == "requestSigningKeys" {
            let public = backend_key().verifying_key().to_bytes();
            *value = Json::arr([Json::obj([
                ("kid", Json::text(KID)),
                ("publicKeyJwk", jwk(public)),
            ])]);
        }
    }
    json::canonicalise(&Json::Object(members))
}

fn web_binding_json() -> Json {
    Json::obj([
        ("id", Json::text(WEB_BINDING_ID)),
        ("platform", Json::text("web")),
        ("origin", Json::text("https://photos.example")),
    ])
}

fn android_binding_json() -> Json {
    Json::obj([
        (
            "id",
            Json::text(format!(
                "android:com.example.photos:{}",
                codec::b64url(&[2u8; 32])
            )),
        ),
        ("platform", Json::text("android")),
        ("packageName", Json::text("com.example.photos")),
        (
            "signingCertificateSha256",
            Json::arr([Json::text(codec::b64url(&[2u8; 32]))]),
        ),
    ])
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
        issued_at: NOW,
        expires_at: NOW + 120,
    }
}

fn statement(p: &ApplicationProfile, core: &OfferCore, binding_id: &str) -> EnrollmentStatement {
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
        platform_binding_id: binding_id.into(),
        return_uri: "https://photos.example/.well-known/selfsame/return".into(),
        issued_at: core.issued_at,
        expires_at: core.expires_at,
    }
}

fn seal(core: &OfferCore, evidence: &str, p: &ApplicationProfile) -> Vec<u8> {
    let hint = provider_hint::ProviderHint {
        application_id: APPLICATION_ID.into(),
        profile_version: 1,
        provider_id: p.cbcl_pairing_relays[0].operator_id.clone(),
        descriptor_digest: codec::b64url(&p.cbcl_pairing_relays[0].digest),
        offer_digest: core.digest(),
    };
    let Json::Object(mut members) = core.to_json() else {
        unreachable!()
    };
    members.push(("enrollmentEvidence".into(), Json::text(evidence)));
    members.push(("providerHint".into(), hint.to_json()));
    json::canonicalise(&Json::Object(members))
}

/// A well-formed web-binding ceremony over the given bindings array.
fn ceremony(bindings: Json, binding_id: &str) -> (Vec<u8>, Vec<u8>, String, String, String) {
    let octets = profile_octets_with(bindings);
    let p = ApplicationProfile::recognise(&octets).expect("fixture profile recognised");
    let core = offer_core(&p);
    let evidence = enrollment::sign(&statement(&p, &core, binding_id), KID, &backend_key());
    let provider = p.cbcl_pairing_relays[0].operator_id.clone();
    let descriptor_digest = codec::b64url(&p.cbcl_pairing_relays[0].digest);
    let profile_digest = codec::b64url(p.digest());
    (
        seal(&core, &evidence, &p),
        octets,
        provider,
        descriptor_digest,
        profile_digest,
    )
}

fn observed<'a>(
    profile_digest: &'a str,
    provider: &'a str,
    descriptor_digest: &'a str,
    platform_binding_id: Option<&'a str>,
) -> Observation<'a> {
    Observation {
        ceremony_profile_digest: profile_digest,
        provider_id: provider,
        descriptor_digest,
        platform_binding_id,
        now: NOW + 1,
    }
}

// ── caller evidence (`CON-227`) ─────────────────────────────────────────────

#[test]
fn unattributed_evidence_passes_a_web_binding() {
    assert_eq!(
        caller_matches_binding(&CallerEvidence::Unattributed, &web_binding()),
        Ok(())
    );
}

#[test]
fn any_attributed_caller_refuses_a_web_binding() {
    // Even the package a sibling android binding declares: matching *a*
    // declared binding is not matching *the named* binding (TEST-246
    // mixed-profile downgrade row, adapter layer).
    for evidence in [
        CallerEvidence::Package("com.example.photos".into()),
        CallerEvidence::Package("com.android.chrome".into()),
        CallerEvidence::AssociatedOrigin("https://photos.example".into()),
    ] {
        assert_eq!(
            caller_matches_binding(&evidence, &web_binding()),
            Err(PlatformError::PlatformBindingMismatch),
            "{evidence:?} must refuse a web binding"
        );
    }
}

// ── the full acceptance path (`CON-214` + `CON-227`) ────────────────────────

#[test]
fn a_web_statement_with_unattributed_observation_reaches_acceptance() {
    let (offer, profile, provider, digest, pdigest) =
        ceremony(Json::arr([web_binding_json()]), WEB_BINDING_ID);
    authorise(
        &offer,
        &profile,
        &observed(&pdigest, &provider, &digest, None),
    )
    .expect("a manual web ceremony with no platform attribution is the conforming case");
}

#[test]
fn an_attributed_observation_against_a_web_statement_refuses() {
    // The OS attributed a handoff that claimed the web binding: an OS-mediated
    // handoff claiming a manual binding is a contradiction (CON-227).
    let (offer, profile, provider, digest, pdigest) =
        ceremony(Json::arr([web_binding_json()]), WEB_BINDING_ID);
    assert_eq!(
        authorise(
            &offer,
            &profile,
            &observed(&pdigest, &provider, &digest, Some(WEB_BINDING_ID)),
        )
        .unwrap_err(),
        AuthoriseError::UnverifiedApplication
    );
}

#[test]
fn the_mixed_profile_downgrade_route_stays_shut() {
    // Profile declares BOTH an android and a web binding; the statement names
    // the web binding; the caller is attributed as exactly the declared
    // android binding id. Matching *a* declared binding is not matching *the
    // named* binding.
    let bindings = Json::arr([android_binding_json(), web_binding_json()]);
    let android_id = format!("android:com.example.photos:{}", codec::b64url(&[2u8; 32]));
    let (offer, profile, provider, digest, pdigest) = ceremony(bindings, WEB_BINDING_ID);
    assert_eq!(
        authorise(
            &offer,
            &profile,
            &observed(&pdigest, &provider, &digest, Some(&android_id)),
        )
        .unwrap_err(),
        AuthoriseError::UnverifiedApplication
    );
}

#[test]
fn a_web_statement_naming_an_undeclared_binding_refuses() {
    // Profile declares only the android binding; the statement names the web
    // binding anyway.
    let (offer, profile, provider, digest, pdigest) =
        ceremony(Json::arr([android_binding_json()]), WEB_BINDING_ID);
    assert_eq!(
        authorise(
            &offer,
            &profile,
            &observed(&pdigest, &provider, &digest, None),
        )
        .unwrap_err(),
        AuthoriseError::UnverifiedApplication
    );
}
