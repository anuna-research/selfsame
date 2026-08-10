//! The wallet's decision to issue a device grant — `authorise`.
//!
//! `CON-201` recognition, `CON-219` recognition, the offer-to-profile binding
//! and `CON-214` verification are one decision, and these tests are the reason
//! it lives in this crate rather than in the Tauri shell: every fixture below
//! is one the shell could not reach without a keychain.
//!
//! The negatives matter more than the positive. A grant is authority that
//! outlives the ceremony that produced it, so what is interesting is not that a
//! good offer is accepted but that each specific bad one is refused, and refused
//! for a reason a prober cannot read.

mod common;

use common::*;
use selfsame_app_identity::authorise::{authorise, AuthoriseError};
use selfsame_app_identity::ceremony::OfferCore;
use selfsame_app_identity::codec;
use selfsame_app_identity::enrollment::{self, EnrollmentStatement};
use selfsame_app_identity::json::{self, Json};
use selfsame_app_identity::profile::ApplicationProfile;
use selfsame_app_identity::{didkey, selection};

const NOW_OFFER: i64 = NOW;
const KID: &str = "https://photos.example/selfsame/application#enrollment-2026-01";

/// The key whose public half the example profile's enrollment entry carries.
fn backend_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0u8; 32])
}

fn profile_octets_with_real_key() -> Vec<u8> {
    let public = backend_key().verifying_key().to_bytes();
    with_nested(
        "enrollment.requestSigningKeys.publicKeyJwk.x",
        Json::text(codec::b64url(&public)),
    )
}

fn profile_with_real_key() -> ApplicationProfile {
    ApplicationProfile::recognise(&profile_octets_with_real_key()).unwrap()
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

fn seal(core: &OfferCore, evidence: &str, p: &ApplicationProfile) -> Vec<u8> {
    let hint = selection::ProviderHint {
        application_id: APPLICATION_ID.into(),
        profile_version: 1,
        provider_id: p.rendezvous[0].id.clone(),
        descriptor_digest: codec::b64url(&p.rendezvous[0].digest),
        offer_digest: core.digest(),
    };
    let Json::Object(mut members) = core.to_json() else { unreachable!() };
    members.push(("enrollmentEvidence".into(), Json::text(evidence)));
    members.push(("providerHint".into(), hint.to_json()));
    json::canonicalise(&Json::Object(members))
}

/// A complete, well-formed offer and the profile it belongs to.
fn good() -> (Vec<u8>, Vec<u8>, String, String) {
    let p = profile_with_real_key();
    let core = offer_core(&p);
    let evidence = enrollment::sign(&statement(&p, &core), KID, &backend_key());
    let provider = p.rendezvous[0].id.clone();
    let descriptor_digest = codec::b64url(&p.rendezvous[0].digest);
    (seal(&core, &evidence, &p), profile_octets_with_real_key(), provider, descriptor_digest)
}

// ── the positive ────────────────────────────────────────────────────────────

#[test]
fn a_verified_offer_yields_the_parameters_a_grant_needs() {
    let (offer, profile, provider, digest) = good();
    let out = authorise(&offer, &profile, &provider, &digest, NOW_OFFER + 1)
        .expect("a well-formed offer under its own profile");

    assert_eq!(out.offer.application_id, APPLICATION_ID);
    assert_eq!(out.offer.requested_permissions, vec![PERMISSION.to_string()]);
    assert_eq!(out.valid_from, NOW_OFFER + 1);

    // `validUntil` is the profile's declared bound, not a constant chosen by
    // the wallet. If this ever reads as a literal, someone has stopped asking
    // the application how long its own grants may live.
    assert_eq!(
        out.valid_until - out.valid_from,
        out.profile.revocation.max_grant_lifetime_seconds
    );
}

// ── the negatives ───────────────────────────────────────────────────────────

#[test]
fn an_unrecognisable_profile_is_refused_before_the_offer_is_read() {
    let (offer, _, provider, digest) = good();
    // Garbage where the profile should be. The offer is perfectly good, so a
    // refusal here can only come from the profile step — which is the ordering
    // this asserts.
    assert_eq!(authorise(&offer, b"{}", &provider, &digest, NOW_OFFER + 1).unwrap_err(), AuthoriseError::UnverifiedApplication);
}

#[test]
fn a_malformed_offer_is_refused() {
    let (_, profile, provider, digest) = good();
    assert_eq!(authorise(b"not an offer", &profile, &provider, &digest, NOW_OFFER + 1).unwrap_err(), AuthoriseError::OfferMalformed);
}

/// The check that stops a hostile application spending someone else's identity:
/// an offer naming a different `applicationId` must not reach the signature
/// step, let alone a derivation.
#[test]
fn an_offer_for_another_application_is_refused_and_reads_as_unverified() {
    let p = profile_with_real_key();
    let mut core = offer_core(&p);
    core.application_id = OTHER_APPLICATION_ID.into();
    let evidence = enrollment::sign(&statement(&p, &core), KID, &backend_key());
    let offer = seal(&core, &evidence, &p);

    let out = authorise(
        &offer,
        &profile_octets_with_real_key(),
        &p.rendezvous[0].id,
        &codec::b64url(&p.rendezvous[0].digest),
        NOW_OFFER + 1,
    );

    // Not a distinct "wrong application" token: a prober must not be able to
    // tell a mismatched identifier from a bad signature.
    assert_eq!(out.unwrap_err(), AuthoriseError::UnverifiedApplication);
}

/// A copied public profile is useless without the backend's private key. This
/// is `CON-214`'s whole purpose, checked at the point a wallet would act on it.
#[test]
fn evidence_signed_by_the_wrong_key_is_refused() {
    let p = profile_with_real_key();
    let core = offer_core(&p);
    let impostor = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let evidence = enrollment::sign(&statement(&p, &core), KID, &impostor);
    let offer = seal(&core, &evidence, &p);

    assert_eq!(authorise(
            &offer,
            &profile_octets_with_real_key(),
            &p.rendezvous[0].id,
            &codec::b64url(&p.rendezvous[0].digest),
            NOW_OFFER + 1
        ).unwrap_err(), AuthoriseError::UnverifiedApplication);
}

#[test]
fn an_expired_offer_is_refused() {
    let (offer, profile, provider, digest) = good();
    // One second past `expiresAt`, which the offer itself declares.
    assert_eq!(authorise(&offer, &profile, &provider, &digest, NOW_OFFER + 121).unwrap_err(), AuthoriseError::OfferExpired);
}

#[test]
fn the_boundary_second_is_expired_exactly_as_con_214_says() {
    let (offer, profile, provider, digest) = good();

    // `CON-214` treats `now >= expiresAt` as expired, and `authorise` uses the
    // same comparison deliberately. An earlier draft used `now > expiresAt`,
    // which opened a one-second window where this decision accepted an offer
    // that `enrollment::verify` then refused — reporting `UnverifiedApplication`
    // for what was only a stale code.
    assert_eq!(
        authorise(&offer, &profile, &provider, &digest, NOW_OFFER + 120).unwrap_err(),
        AuthoriseError::OfferExpired
    );
    // One second earlier is the last usable instant.
    assert!(authorise(&offer, &profile, &provider, &digest, NOW_OFFER + 119).is_ok());
}

/// The provider and descriptor the wallet observed are inputs to `CON-214`, not
/// decoration: evidence bound to one descriptor must not verify under another.
#[test]
fn evidence_bound_to_a_different_descriptor_is_refused() {
    let (offer, profile, provider, _) = good();
    let wrong_digest = codec::b64url(&[7u8; 32]);
    assert_eq!(authorise(&offer, &profile, &provider, &wrong_digest, NOW_OFFER + 1).unwrap_err(), AuthoriseError::UnverifiedApplication);
}
