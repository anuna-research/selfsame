//! `TEST-206`, `TEST-217`, `TEST-219`, `TEST-237`, `TEST-240`.
//!
//! Five tests that share no module but share a shape: each is a property of the
//! *whole* profile rather than of one contract, so each needs a complete
//! ceremony to be stated at all.
//!
//! - `TEST-206` account privacy — what a generated artefact must **not** contain
//! - `TEST-217` opaque transport — byte identity through the ceremony
//! - `TEST-219` provider-independent recovery — identity survives an operator change
//! - `TEST-237` profile discovery and origin binding
//! - `TEST-240` freshness tiers and projection inference

mod common;

use common::*;
use selfsame_app_identity::accept::{
    accept_grant, AcceptStep, ClosureSource, Evidence, Expectation, Freshness, Projection,
};
use selfsame_app_identity::json::{self, Json};
use selfsame_app_identity::profile::{ApplicationId, ApplicationProfile, ProjectionPolicy};
use selfsame_app_identity::revocation::{self, ProjectionReading};
use selfsame_app_identity::scope::AccountScopeId;
use selfsame_app_identity::{accept, alias, ceremony, codec, discovery, hierarchy, pairing};

// ── TEST-206: account privacy ──────────────────────────────────────────────

/// The values a generated artefact must never contain (`TEST-206`, `NFR-203`).
///
/// > Generated DID, account, WebFinger, VC, status, and provider-hint fixtures
/// > contain none of the fixture user's email, display name, phone number,
/// > global account ID, `accountScopeId`, sibling scope, or application-A
/// > identifier.
const FORBIDDEN_IN_ARTEFACTS: &[(&str, &str)] = &[
    ("email", "alice@personal.example"),
    ("display name", "Alice Alvarez"),
    ("phone number", "+61400000000"),
    ("global account ID", "user-000199"),
];

#[test]
fn no_generated_artefact_carries_the_persons_identity_or_the_account_scope() {
    let c = Ceremony::accepted();
    let scope = AccountScopeId::from_octets([1u8; 32]);
    let sibling = AccountScopeId::from_octets([2u8; 32]);

    // Every artefact that leaves the device, as one corpus of text.
    let grant = String::from_utf8(c.grant_bytes.clone()).unwrap();
    let jrd = String::from_utf8(json::canonicalise(&Json::obj([
        ("subject", Json::text(c.account.as_str())),
        ("aliases", Json::arr([Json::text(c.home_did.clone())])),
    ])))
    .unwrap();
    let hint = String::from_utf8(json::canonicalise(
        &selfsame_app_identity::selection::ProviderHint {
            application_id: APPLICATION_ID.into(),
            profile_version: 1,
            provider_id: "au-primary".into(),
            descriptor_digest: codec::b64url(&[3u8; 32]),
            offer_digest: codec::b64url(&[4u8; 32]),
        }
        .to_json(),
    ))
    .unwrap();

    let artefacts: [(&str, &str); 6] = [
        ("home DID", &c.home_did),
        ("account alias", c.account.as_str()),
        ("device DID", &c.device_did),
        ("grant", &grant),
        ("WebFinger JRD", &jrd),
        ("provider hint", &hint),
    ];

    for (name, artefact) in artefacts {
        for (kind, value) in FORBIDDEN_IN_ARTEFACTS {
            assert!(!artefact.contains(value), "the {name} carries the fixture user's {kind}");
        }
        // REQ-217: "The raw or encoded scope SHALL NOT appear in a DID, DID
        // Document, `acct:` URI, VC, JWS header, WebFinger response, provider
        // hint, status entry, log, analytics event, or other public protocol
        // artifact."
        assert!(!artefact.contains(scope.as_str()), "the {name} carries the account scope");
        assert!(!artefact.contains(sibling.as_str()), "the {name} carries a sibling's scope");
    }
}

#[test]
fn a_grant_carries_only_the_members_nfr_203_permits() {
    // NFR-203 enumerates what the VC may contain, and the enumeration is
    // exhaustive: "It SHALL NOT contain recovery metadata, the optional
    // human-readable alias, another application's identifier, a display name,
    // email address, mnemonic fingerprint, `accountScopeId`, or
    // provider-selection history."
    let c = Ceremony::accepted();
    let text = core::str::from_utf8(&c.grant_bytes).unwrap();
    let signed =
        selfsame_app_identity::jws::recognise(text, selfsame_app_identity::grant::GRANT_JWS, &[])
            .unwrap();

    // The payload arrives in RFC 8785 order because `jws::sign` canonicalises
    // it, so the comparison is against the sorted set — which is the right
    // comparison anyway: NFR-203 bounds *which* members exist, not their order.
    let mut permitted = [
        "@context",
        "type",
        "id",
        "issuer",
        "validFrom",
        "validUntil",
        "credentialSubject",
        "credentialStatus",
        "aud",
        "cnf",
    ];
    permitted.sort_unstable();
    assert_eq!(signed.payload.member_names(), permitted);

    // The other application's identifier appears nowhere.
    let payload = String::from_utf8(signed.payload_octets().to_vec()).unwrap();
    assert!(!payload.contains(OTHER_APPLICATION_ID));
    // Nor a human-readable alias, which REQ-218 keeps out of the account claim.
    assert!(!payload.contains("acct:alice@"));
}

#[test]
fn two_accounts_in_one_application_share_no_public_value() {
    // NFR-201: "The two profiles SHALL share no derived public key, DID,
    // `acct:` URI, credential ID, revocation entry, projection index,
    // rendezvous route key, or device key by default."
    let a1 = Ceremony::build(0, 1, 3, APPLICATION_ID);
    let a2 = Ceremony::build(0, 2, 4, APPLICATION_ID);

    assert_ne!(a1.home_did, a2.home_did);
    assert_ne!(a1.account.as_str(), a2.account.as_str());
    assert_ne!(a1.device_did, a2.device_did);
    assert_ne!(a1.grant_bytes, a2.grant_bytes);

    // …and nothing of one appears inside the other's grant.
    let g1 = String::from_utf8(a1.grant_bytes.clone()).unwrap();
    let g2 = String::from_utf8(a2.grant_bytes.clone()).unwrap();
    assert!(!g1.contains(&a2.home_did));
    assert!(!g2.contains(&a1.home_did));
    assert!(!g1.contains(a2.account.as_str()));
    assert!(!g2.contains(a1.account.as_str()));
}

// ── TEST-217: opaque transport ─────────────────────────────────────────────

#[test]
fn the_grant_survives_the_ceremony_byte_for_byte_and_still_verifies() {
    // TEST-217: "Issue one compact JWS, transport it through every supported
    // ceremony encoding, extract it, and require byte identity and successful
    // verification by an independent non-CBCL verifier."
    //
    // REQ-211's point is that the ceremony "protects the transport, and the
    // credential's own JWS is the only signature a verifier accepts". So the
    // test that matters is that extraction is the identity function.
    let c = Ceremony::accepted();
    let original = String::from_utf8(c.grant_bytes.clone()).unwrap();

    let sealed = ceremony::build_bundle(
        &codec::b64url(&[1u8; 32]),
        &codec::b64url(&[2u8; 32]),
        &original,
        None,
    )
    .unwrap();
    let extracted = ceremony::recognise_bundle(&sealed).unwrap();

    assert_eq!(extracted.grant, original, "the bundle is not an encoding");
    assert_eq!(extracted.grant.as_bytes(), c.grant_bytes.as_slice());

    // A verifier that never saw the ceremony accepts the extracted bytes.
    let accepted = accept_grant(extracted.grant.as_bytes(), &c.expectation(), &c.evidence())
        .expect("the extracted bytes verify independently");
    assert_eq!(accepted.grant.issuer, c.home_did);
}

#[test]
fn the_bundle_names_the_media_type_alongside_the_bytes() {
    // REQ-211 requires both: the compact JWS bytes *and* the exact media type.
    let c = Ceremony::accepted();
    let grant = String::from_utf8(c.grant_bytes).unwrap();
    let sealed = ceremony::build_bundle(
        &codec::b64url(&[1u8; 32]),
        &codec::b64url(&[2u8; 32]),
        &grant,
        None,
    )
    .unwrap();
    let text = String::from_utf8(sealed).unwrap();
    assert!(text.contains("application/vc+jwt"));
}

// ── TEST-219: provider-independent recovery ────────────────────────────────

#[test]
fn changing_every_provider_endpoint_changes_no_derived_identity() {
    // TEST-219: "Change every provider and account endpoint in the profile
    // without changing `applicationId` or `accountScopeId`; confirm that the
    // application node, account node, and home key do not change."
    let app = ApplicationId::parse(APPLICATION_ID).unwrap();
    let scope = AccountScopeId::from_octets([1u8; 32]);
    let before = hierarchy::derive(&mnemonic(0), &app, &scope);

    // A profile with entirely different operators for every role.
    let moved = with_member(
        "rendezvous",
        Json::arr([descriptor("elsewhere", "r.other.example", "p.other.example", "42", 10, 50)]),
    );
    let moved = ApplicationProfile::recognise(&moved).unwrap();
    let restated = ApplicationProfile::recognise(&with_member(
        "stateResolvers",
        Json::arr([resolver("other", "https://state.other.example")]),
    ))
    .unwrap();

    let after = hierarchy::derive(&mnemonic(0), &app, &scope);

    assert_eq!(before.public_key(), after.public_key());
    assert_eq!(before.home_did().unwrap(), after.home_did().unwrap());
    assert_eq!(
        alias::stable_localpart(&before.home_did().unwrap()),
        alias::stable_localpart(&after.home_did().unwrap()),
        "REQ-213: changing providers does not rotate the acct: localpart"
    );
    // The profiles genuinely differ — the derivation simply cannot see them.
    assert_ne!(moved.digest(), restated.digest());
    assert_ne!(moved.rendezvous[0].id, "au-primary");
}

// ── TEST-237: profile discovery and origin binding ─────────────────────────

fn ok_response(body: &[u8]) -> discovery::HttpResponse<'_> {
    discovery::HttpResponse {
        https_validated: true,
        redirected: false,
        status: 200,
        content_type: discovery::PROFILE_MEDIA_TYPE,
        content_encoding: None,
        body,
    }
}

#[test]
fn a_profile_fetched_from_its_own_identifier_binds_to_the_origin() {
    let octets = profile_octets();
    let app = ApplicationId::parse(APPLICATION_ID).unwrap();
    let fetched = discovery::recognise_profile_response(&ok_response(&octets), &app).unwrap();
    assert_eq!(fetched.application_id.as_str(), APPLICATION_ID);
    assert_eq!(discovery::profile_request_path(&app).unwrap(), "/selfsame/application");
}

#[test]
fn step_six_is_what_makes_the_fetch_trustworthy_rather_than_merely_encrypted() {
    // "TLS authenticates the origin; the record digest — asserted by a party
    // holding `C` — pins *which* profile that origin served. A host that serves
    // a substituted profile fails step 6."
    let octets = profile_octets();
    let app = ApplicationId::parse(APPLICATION_ID).unwrap();
    let fetched = discovery::recognise_profile_response(&ok_response(&octets), &app).unwrap();

    let genuine = codec::b64url(fetched.digest());
    assert!(discovery::check_record_digest(&fetched, &genuine).is_ok());

    // A substituted profile: valid, from the right origin, naming the right
    // identifier — and not the one the record pinned.
    let substituted = ApplicationProfile::recognise(&with_member(
        "allowedPermissions",
        // Sorted by Unicode code point, as CON-201 requires: `#admin` before
        // `#device`.
        Json::arr([
            Json::text(format!("{APPLICATION_ID}#admin")),
            Json::text(PERMISSION),
        ]),
    ))
    .unwrap();
    assert_eq!(substituted.application_id.as_str(), APPLICATION_ID, "same identifier");
    assert_eq!(
        discovery::check_record_digest(&substituted, &genuine),
        Err(discovery::DiscoveryError::DigestMismatch),
        "a substituted profile passes TLS and fails the pin"
    );
}

#[test]
fn a_profile_naming_a_different_identifier_than_the_uri_dereferenced_is_refused() {
    let octets = profile_octets();
    let other = ApplicationId::parse(OTHER_APPLICATION_ID).unwrap();
    assert_eq!(
        discovery::recognise_profile_response(&ok_response(&octets), &other),
        Err(discovery::DiscoveryError::IdentifierMismatch)
    );
}

#[test]
fn the_record_resolves_to_exactly_one_declared_descriptor() {
    // CON-216's on-resolution checks. "The resolving party never repairs,
    // guesses, broadcasts, or falls back, and never searches for a matching
    // nameplate."
    let p = ApplicationProfile::recognise(&profile_octets()).unwrap();
    let claim = pairing::RecordClaim {
        application_id: APPLICATION_ID.into(),
        profile_digest: codec::b64url(p.digest()),
        provider_id: "au-primary".into(),
        nameplate: "004821".into(),
    };
    let descriptor = pairing::resolve_record(&claim, &p).expect("resolves to one descriptor");
    assert_eq!(descriptor.id, "au-primary");

    // A provider the profile does not declare.
    let unknown = pairing::RecordClaim { provider_id: "attacker".into(), ..claim.clone() };
    assert_eq!(
        pairing::resolve_record(&unknown, &p),
        Err(pairing::PairingError::ProviderNotUnique)
    );

    // A changed profile digest, and a record for another application.
    let redigested = pairing::RecordClaim {
        profile_digest: codec::b64url(&[0u8; 32]),
        ..claim.clone()
    };
    assert_eq!(
        pairing::resolve_record(&redigested, &p),
        Err(pairing::PairingError::RecordMismatch)
    );
    let elsewhere =
        pairing::RecordClaim { application_id: OTHER_APPLICATION_ID.into(), ..claim };
    assert_eq!(
        pairing::resolve_record(&elsewhere, &p),
        Err(pairing::PairingError::RecordMismatch)
    );
}

// ── CON-204: the remote-controller ordering ────────────────────────────────

#[test]
fn the_issuer_can_be_read_before_any_signature_is_checked_and_grants_nothing() {
    // CON-204's remote-controller order: the application "reads `issuer` from
    // the grant and recomputes the expected localpart" *before* it provisions.
    // No signature has been checked at that point, which is why the value may
    // only be used to derive a name.
    let c = Ceremony::accepted();
    let issuer = accept::peek_issuer(&c.grant_bytes).expect("readable");
    assert_eq!(issuer, c.home_did);

    // The recomputed alias is the one the grant claims…
    let recomputed = alias::stable_acct_uri(&issuer, ACCOUNT_AUTHORITY);
    assert_eq!(recomputed, c.account.as_str());

    // …and peeking authorises nothing: the grant still has to pass all thirteen
    // steps, and it fails at step 9 while the alias is unprovisioned.
    let unprovisioned = Evidence { jrd: None, ..c.evidence() };
    let err = accept_grant(&c.grant_bytes, &c.expectation(), &unprovisioned).unwrap_err();
    assert_eq!(err.step, AcceptStep::AccountBinding);
}

#[test]
fn peeking_at_a_malformed_grant_yields_no_issuer() {
    assert!(accept::peek_issuer(b"not-a-jws").is_err());
    assert!(accept::peek_issuer(&[0xFF, 0xFE]).is_err());
}

// ── TEST-240: freshness tiers and projection inference ─────────────────────

#[test]
fn the_two_freshness_tiers_are_derived_from_members_con_201_already_defines() {
    let p = ApplicationProfile::recognise(&profile_octets()).unwrap();
    assert_eq!(p.revocation.propagation_sla_seconds, 60);
    assert_eq!(p.revocation.max_closure_age_seconds, 900);
    assert_eq!(
        p.revocation.session_establishment_bound(),
        60,
        "min(maxClosureAgeSeconds, propagationSlaSeconds)"
    );
}

#[test]
fn a_revoked_device_cannot_start_a_new_session_past_the_composed_bound() {
    // CON-206: "A revoked device therefore cannot start a new session more than
    // `propagationSlaSeconds + min(maxClosureAgeSeconds, propagationSlaSeconds)`
    // after the revocation was submitted: 120 seconds at the defaults."
    let c = Ceremony::accepted();
    let p = &c.profile;
    let composed =
        p.revocation.propagation_sla_seconds + p.revocation.session_establishment_bound();
    assert_eq!(composed, 120, "the defaults compose to two minutes");

    // At establishment, a closure older than 60s is refused outright — so the
    // verifier cannot be shown state predating the revocation.
    let mut stale = c.issuer.clone();
    stale.closure_age_seconds = 61;
    let evidence = Evidence { issuer: Some(&stale), ..c.evidence() };
    let err = accept_grant(&c.grant_bytes, &c.expectation(), &evidence).unwrap_err();
    assert_eq!(err.step, AcceptStep::Status);
}

#[test]
fn a_verifier_that_cannot_tell_which_case_applies_uses_the_stricter_bound() {
    // "A verifier that cannot determine which case applies SHALL use the
    // session-establishment bound." Encoded as the default a caller reaches
    // for: `Freshness::SessionEstablishment` is the strict one, and a verifier
    // whose record of accepted grant IDs is lost picks it by treating the next
    // acceptance as establishment.
    let c = Ceremony::accepted();
    let mut middling = c.issuer.clone();
    middling.closure_age_seconds = 300;
    let evidence = Evidence { issuer: Some(&middling), ..c.evidence() };

    let strict = Expectation { freshness: Freshness::SessionEstablishment, ..c.expectation() };
    assert!(accept_grant(&c.grant_bytes, &strict, &evidence).is_err());

    let lenient = Expectation { freshness: Freshness::Continuation, ..c.expectation() };
    assert!(accept_grant(&c.grant_bytes, &lenient, &evidence).is_ok());
}

#[test]
fn a_bundle_supplied_closure_is_recorded_at_establishment() {
    // "A verifier MAY rely on the bundle-supplied closure only when it is
    // accepting a grant ID for the first time and no declared resolver is
    // reachable, and SHALL record that it did so."
    let c = Ceremony::accepted();
    let mut bundled = c.issuer.clone();
    bundled.source = ClosureSource::BundleOrCache;
    let evidence = Evidence { issuer: Some(&bundled), ..c.evidence() };
    let accepted = accept_grant(&c.grant_bytes, &c.expectation(), &evidence).unwrap();
    assert!(accepted.used_bundle_closure, "the reliance is recorded, not silent");
}

#[test]
fn the_projection_reading_is_asymmetric_at_every_age() {
    // TEST-240's inference half. CON-210: "a set bit is permanently true … an
    // unset bit is a claim about the world at `validFrom`, and it decays."
    let policy = ProjectionPolicy {
        kind: "BitstringStatusList".into(),
        allocation_url: "https://s.example/slots".into(),
        credential_base_url: "https://s.example/lists/".into(),
        max_age_seconds: 900,
    };
    let (from, until) = (1_000, 1_900);

    for now in [from, from + 450, until - 1] {
        assert_eq!(
            revocation::read_projection(true, from, until, now, &policy),
            ProjectionReading::Revoked
        );
        assert_eq!(
            revocation::read_projection(false, from, until, now, &policy),
            ProjectionReading::NoInformationYet
        );
    }
    // Past `validUntil` the two diverge permanently.
    assert_eq!(
        revocation::read_projection(true, from, until, until + 10_000, &policy),
        ProjectionReading::Revoked
    );
    assert_eq!(
        revocation::read_projection(false, from, until, until, &policy),
        ProjectionReading::Unavailable
    );
}

#[test]
fn no_projection_state_can_rescue_a_grant_the_crdt_set_has_revoked() {
    // "an unset, stale, invalid, or unavailable projection never bypasses the
    // CRDT check" — which is why the CRDT check runs whatever the projection
    // said.
    let c = Ceremony::accepted();
    let id = accept_grant(&c.grant_bytes, &c.expectation(), &c.evidence()).unwrap().grant.id;
    let mut revoked = c.issuer.clone();
    revoked.revoked_credential_ids.push(id);

    for projection in [None, Some(Projection::BitUnset), Some(Projection::Unavailable)] {
        let evidence = Evidence { issuer: Some(&revoked), projection, ..c.evidence() };
        let err = accept_grant(&c.grant_bytes, &c.expectation(), &evidence).unwrap_err();
        assert_eq!(err.step, AcceptStep::Status, "{projection:?} bypassed the CRDT check");
    }
}
