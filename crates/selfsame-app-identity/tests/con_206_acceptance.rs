//! `TEST-207` to `TEST-212` — the grant, the JWS negative corpus, holder
//! binding, challenge replay, the authorization predicate, and validity.
//!
//! The centrepiece is `TEST-211`:
//!
//! > Mutate each of `CON-206`'s thirteen checks independently. No mutation may
//! > leave the result authorized.
//!
//! Each test below mutates exactly one thing and asserts both that the grant is
//! refused **and which numbered step refused it**. Asserting the step matters:
//! two implementations that reject the same input at different steps have not
//! implemented the same predicate, which is why `CON-226`'s corpus records the
//! reason rather than merely the failure.

mod common;

use common::*;
use selfsame_app_identity::accept::{
    accept_grant, AcceptStep, ClosureSource, Evidence, Expectation, Freshness, Projection,
    PublicReason,
};
use selfsame_app_identity::alias::Jrd;
use selfsame_app_identity::codec;
use selfsame_app_identity::json::{self, Json};
use selfsame_app_identity::{didkey, grant, jws, proof};

fn accepts(c: &Ceremony) {
    accept_grant(&c.grant_bytes, &c.expectation(), &c.evidence())
        .unwrap_or_else(|e| panic!("the reference ceremony should be accepted: {e}"));
}

fn refused_at(c: &Ceremony, expect: Expectation<'_>, evidence: Evidence<'_>, step: AcceptStep) {
    let err = accept_grant(&c.grant_bytes, &expect, &evidence)
        .expect_err("this mutation must not leave the result authorized");
    assert_eq!(err.step, step, "refused at the wrong step: {err}");
}

// ── TEST-207: the positive vector ──────────────────────────────────────────

#[test]
fn accepts_a_complete_well_formed_ceremony() {
    accepts(&Ceremony::accepted());
}

#[test]
fn the_issued_grant_recognises_with_every_cross_field_equality_intact() {
    let c = Ceremony::accepted();
    let text = core::str::from_utf8(&c.grant_bytes).unwrap();
    let signed = jws::recognise(text, grant::GRANT_JWS, &[]).unwrap();
    let g = grant::recognise(&signed.payload).unwrap();

    assert_eq!(g.issuer, c.home_did);
    assert_eq!(g.device_did, c.device_did);
    assert_eq!(g.account.as_str(), c.account.as_str());
    assert_eq!(g.application, APPLICATION_ID);
    assert_eq!(g.permissions, vec![PERMISSION.to_string()]);
    // The three identifiers CON-205 derives from one token.
    assert_eq!(g.id, format!("{}#grant-{}", c.home_did, g.token));
    assert_eq!(g.status_id, format!("{}#status-{}", c.home_did, g.token));
    assert_eq!(g.token.len(), 43);
    assert!(g.projection_entry.is_none());
    // The device key in `cnf.jwk` is the key the subject DID encodes.
    assert_eq!(didkey::decode(&g.device_did).unwrap(), g.device_public_key);
}

#[test]
fn the_protected_header_is_exactly_what_con_205_fixes() {
    let c = Ceremony::accepted();
    let text = core::str::from_utf8(&c.grant_bytes).unwrap();
    let signed = jws::recognise(text, grant::GRANT_JWS, &[]).unwrap();
    assert_eq!(signed.protected.get("alg").and_then(Json::as_str), Some("EdDSA"));
    assert_eq!(signed.protected.get("typ").and_then(Json::as_str), Some("vc+jwt"));
    assert_eq!(signed.protected.get("cty").and_then(Json::as_str), Some("vc"));
    assert_eq!(signed.kid, format!("{}#jwk-0", c.home_did));
    assert_eq!(signed.protected.member_names().len(), 4, "the header is closed at four members");
}

// ── TEST-211: one mutation per step ────────────────────────────────────────

#[test]
fn step_1_rejects_input_over_sixty_four_kibibytes() {
    let c = Ceremony::accepted();
    let oversized = vec![b'a'; grant::MAX_GRANT_OCTETS + 1];
    let err = accept_grant(&oversized, &c.expectation(), &c.evidence()).unwrap_err();
    assert_eq!(err.step, AcceptStep::Size);
}

#[test]
fn step_2_rejects_a_malformed_compact_serialisation() {
    let c = Ceremony::accepted();
    let text = String::from_utf8(c.grant_bytes.clone()).unwrap();
    for mutated in [text.replace('.', "-"), format!("{text}.extra"), format!("{text}=")] {
        let err = accept_grant(mutated.as_bytes(), &c.expectation(), &c.evidence()).unwrap_err();
        assert_eq!(err.step, AcceptStep::Jws, "{mutated:.30}");
    }
}

#[test]
fn step_3_rejects_alg_none_a_relative_kid_and_a_key_discovery_parameter() {
    let c = Ceremony::accepted();
    let payload = payload_of(&c);

    for header in [
        // `alg: none` — the classic, and not special-cased: it is simply not
        // the one algorithm on the allowlist.
        Json::obj([
            ("alg", Json::text("none")),
            ("kid", Json::text(format!("{}#jwk-0", c.home_did))),
            ("typ", Json::text("vc+jwt")),
            ("cty", Json::text("vc")),
        ]),
        // A relative `kid` would be resolved against something, and whatever it
        // was resolved against would be choosing the key.
        Json::obj([
            ("alg", Json::text("EdDSA")),
            ("kid", Json::text("#jwk-0")),
            ("typ", Json::text("vc+jwt")),
            ("cty", Json::text("vc")),
        ]),
        // An embedded key lets the credential nominate what verifies it.
        Json::obj([
            ("alg", Json::text("EdDSA")),
            ("kid", Json::text(format!("{}#jwk-0", c.home_did))),
            ("typ", Json::text("vc+jwt")),
            ("cty", Json::text("vc")),
            ("jwk", Json::text("x")),
        ]),
        // A remote key URL is the same move with a network hop.
        Json::obj([
            ("alg", Json::text("EdDSA")),
            ("kid", Json::text(format!("{}#jwk-0", c.home_did))),
            ("typ", Json::text("vc+jwt")),
            ("cty", Json::text("vc")),
            ("jku", Json::text("https://attacker.example/keys")),
        ]),
    ] {
        let mutated = jws::sign(&header, &payload, &c.home_key);
        let err = accept_grant(mutated.as_bytes(), &c.expectation(), &c.evidence()).unwrap_err();
        assert_eq!(err.step, AcceptStep::Header, "{header:?}");
    }
}

#[test]
fn step_4_rejects_when_no_issuer_closure_is_available() {
    let c = Ceremony::accepted();
    let evidence = Evidence { issuer: None, ..c.evidence() };
    refused_at(&c, c.expectation(), evidence, AcceptStep::Closure);
    // The one failure that is the verifier's problem rather than the
    // presenter's, so it is distinguishable outward.
    let err = accept_grant(&c.grant_bytes, &c.expectation(), &evidence).unwrap_err();
    assert_eq!(err.public(), PublicReason::StateUnavailable);
}

#[test]
fn step_5_rejects_an_unverified_deactivated_or_mismatched_did() {
    let c = Ceremony::accepted();
    for mutate in [
        |s: &mut selfsame_app_identity::accept::IssuerState| s.did_recomputed_ok = false,
        |s: &mut selfsame_app_identity::accept::IssuerState| s.deltas_verified = false,
        |s: &mut selfsame_app_identity::accept::IssuerState| s.deactivated = true,
    ] {
        let mut issuer = c.issuer.clone();
        mutate(&mut issuer);
        let evidence = Evidence { issuer: Some(&issuer), ..c.evidence() };
        refused_at(&c, c.expectation(), evidence, AcceptStep::DidResolution);
    }
}

#[test]
fn step_6_rejects_a_kid_outside_assertion_method() {
    let c = Ceremony::accepted();

    // Not present at all.
    let mut issuer = c.issuer.clone();
    issuer.assertion_methods.clear();
    let evidence = Evidence { issuer: Some(&issuer), ..c.evidence() };
    refused_at(&c, c.expectation(), evidence, AcceptStep::IssuerKey);

    // Present, but not a `JsonWebKey`. CON-206 step 6 names the type, and the
    // did:crdt method emitting `publicKeyMultibase` instead is a Tier-1 gate
    // item — so this check is the one that will fire first if that lands wrong.
    let mut issuer = c.issuer.clone();
    issuer.assertion_methods[0].kind = "Multikey".into();
    let evidence = Evidence { issuer: Some(&issuer), ..c.evidence() };
    refused_at(&c, c.expectation(), evidence, AcceptStep::IssuerKey);

    // Carrying a private component.
    let mut issuer = c.issuer.clone();
    issuer.assertion_methods[0].has_private_component = true;
    let evidence = Evidence { issuer: Some(&issuer), ..c.evidence() };
    refused_at(&c, c.expectation(), evidence, AcceptStep::IssuerKey);
}

#[test]
fn step_6_rejects_a_kid_belonging_to_a_different_did() {
    // A valid signature by an unrelated issuer, whose own closure was resolved.
    let c = Ceremony::accepted();
    let other = Ceremony::build(1, 1, 3, APPLICATION_ID);
    let mut issuer = c.issuer.clone();
    issuer.assertion_methods[0].id = format!("{}#jwk-0", other.home_did);
    let evidence = Evidence { issuer: Some(&issuer), ..c.evidence() };
    refused_at(&c, c.expectation(), evidence, AcceptStep::IssuerKey);
}

#[test]
fn step_7_rejects_a_signature_by_the_wrong_key() {
    let c = Ceremony::accepted();
    let impostor = Ceremony::build(1, 1, 3, APPLICATION_ID);
    // The document is unchanged and the closure is genuine; only the key that
    // signed it is not the one `assertionMethod` names.
    let mutated = jws::sign(&grant::header(&c.home_did), &payload_of(&c), &impostor.home_key);
    let err = accept_grant(mutated.as_bytes(), &c.expectation(), &c.evidence()).unwrap_err();
    assert_eq!(err.step, AcceptStep::Signature);
}

#[test]
fn step_7_rejects_a_payload_altered_after_signing() {
    let c = Ceremony::accepted();
    let text = String::from_utf8(c.grant_bytes.clone()).unwrap();
    let mut parts: Vec<String> = text.split('.').map(str::to_string).collect();
    let mut payload = payload_of(&c);
    let Json::Object(members) = &mut payload else { unreachable!() };
    members.iter_mut().find(|(k, _)| k == "validUntil").unwrap().1 =
        Json::text("2030-01-01T00:00:00Z");
    parts[1] = codec::b64url(&json::canonicalise(&payload));
    let mutated = parts.join(".");
    let err = accept_grant(mutated.as_bytes(), &c.expectation(), &c.evidence()).unwrap_err();
    assert_eq!(err.step, AcceptStep::Signature, "an altered payload must fail the signature");
}

#[test]
fn step_8_rejects_a_grant_for_another_application_or_another_account() {
    // The splice TEST-229 describes: a valid grant from one context presented
    // in another. Both are properly signed by their own issuers.
    let a1 = Ceremony::accepted();
    let a2 = Ceremony::build(0, 2, 3, APPLICATION_ID);

    // A2's grant presented where A1 is expected.
    let err = accept_grant(&a2.grant_bytes, &a1.expectation(), &a2.evidence()).unwrap_err();
    assert_eq!(err.step, AcceptStep::Fields);

    // …and the reverse.
    let err = accept_grant(&a1.grant_bytes, &a2.expectation(), &a1.evidence()).unwrap_err();
    assert_eq!(err.step, AcceptStep::Fields);
}

#[test]
fn step_8_rejects_a_credential_whose_fields_do_not_agree_with_each_other() {
    let c = Ceremony::accepted();
    let base = payload_of(&c);

    // `aud` no longer equals `credentialSubject.application`.
    let mut payload = base.clone();
    set(&mut payload, "aud", Json::text(OTHER_APPLICATION_ID));
    reject_field(&c, &payload);

    // `credentialStatus.credentialId` no longer equals `id`.
    let mut payload = base.clone();
    let status = payload.get("credentialStatus").unwrap().clone();
    let mut status_members = status.as_object().unwrap().to_vec();
    status_members.iter_mut().find(|(k, _)| k == "credentialId").unwrap().1 =
        Json::text(format!("{}#grant-{}", c.home_did, codec::b64url(&[0u8; 32])));
    set(&mut payload, "credentialStatus", Json::Object(status_members));
    reject_field(&c, &payload);

    // An unknown top-level member.
    let mut payload = base.clone();
    set(&mut payload, "surprise", Json::int(1));
    reject_field(&c, &payload);

    // A human-readable alias where only the stable one may appear (REQ-218).
    let mut payload = base.clone();
    let subject = payload.get("credentialSubject").unwrap().clone();
    let mut subject_members = subject.as_object().unwrap().to_vec();
    subject_members.iter_mut().find(|(k, _)| k == "account").unwrap().1 =
        Json::text(format!("acct:alice@{ACCOUNT_AUTHORITY}"));
    set(&mut payload, "credentialSubject", Json::Object(subject_members));
    reject_field(&c, &payload);
}

#[test]
fn step_8_rejects_a_cnf_key_that_is_not_the_key_the_subject_did_encodes() {
    // TEST-209: "a key whose public bytes differ from the subject DID."
    let c = Ceremony::accepted();
    let mut payload = payload_of(&c);
    let other = ed25519_dalek::SigningKey::from_bytes(&[77u8; 32]).verifying_key().to_bytes();
    set(
        &mut payload,
        "cnf",
        Json::obj([(
            "jwk",
            Json::obj([
                ("kty", Json::text("OKP")),
                ("crv", Json::text("Ed25519")),
                ("alg", Json::text("EdDSA")),
                ("x", Json::text(codec::b64url(&other))),
            ]),
        )]),
    );
    reject_field(&c, &payload);
}

#[test]
fn step_9_rejects_an_unprovisioned_or_broken_reciprocal_binding() {
    let c = Ceremony::accepted();

    // The alias is deterministically named but the authority holds no record.
    // TEST-205's remote-controller ordering: the grant exists and is unusable.
    let evidence = Evidence { jrd: None, ..c.evidence() };
    refused_at(&c, c.expectation(), evidence, AcceptStep::AccountBinding);

    // The authority names a different DID.
    let wrong = Jrd {
        subject: c.account.as_str().to_string(),
        aliases: vec!["did:crdt:someone-else".into()],
    };
    let evidence = Evidence { jrd: Some(&wrong), ..c.evidence() };
    refused_at(&c, c.expectation(), evidence, AcceptStep::AccountBinding);

    // The controller never asserted the alias in `alsoKnownAs`.
    let mut issuer = c.issuer.clone();
    issuer.also_known_as.clear();
    let evidence = Evidence { issuer: Some(&issuer), ..c.evidence() };
    refused_at(&c, c.expectation(), evidence, AcceptStep::AccountBinding);
}

#[test]
fn step_9_accepts_the_same_unmodified_grant_once_provisioning_completes() {
    // TEST-205: "then provision, then require the same unmodified grant bytes
    // to be accepted. Require no re-issuance, no new grant ID, no key change,
    // and no DID change between the two attempts."
    let c = Ceremony::accepted();

    let before = Evidence { jrd: None, ..c.evidence() };
    let err = accept_grant(&c.grant_bytes, &c.expectation(), &before).unwrap_err();
    assert_eq!(err.step, AcceptStep::AccountBinding);

    let after = accept_grant(&c.grant_bytes, &c.expectation(), &c.evidence()).unwrap();
    assert_eq!(after.grant.issuer, c.home_did, "the DID did not change");
    assert_eq!(after.grant.account.as_str(), c.account.as_str(), "the alias did not change");
}

#[test]
fn step_10_rejects_a_revoked_grant_whatever_else_is_valid() {
    let c = Ceremony::accepted();
    let g = accept_grant(&c.grant_bytes, &c.expectation(), &c.evidence()).unwrap().grant;

    let mut issuer = c.issuer.clone();
    issuer.revoked_credential_ids.push(g.id.clone());
    let evidence = Evidence { issuer: Some(&issuer), ..c.evidence() };
    refused_at(&c, c.expectation(), evidence, AcceptStep::Status);
}

#[test]
fn step_10_rejects_a_stale_or_causally_incomplete_closure() {
    let c = Ceremony::accepted();

    // Session establishment uses min(maxClosureAge, propagationSla) = 60.
    let mut issuer = c.issuer.clone();
    issuer.closure_age_seconds = 61;
    let evidence = Evidence { issuer: Some(&issuer), ..c.evidence() };
    refused_at(&c, c.expectation(), evidence, AcceptStep::Status);

    let mut issuer = c.issuer.clone();
    issuer.causally_complete = false;
    let evidence = Evidence { issuer: Some(&issuer), ..c.evidence() };
    refused_at(&c, c.expectation(), evidence, AcceptStep::Status);
}

#[test]
fn step_10_applies_the_two_freshness_tiers_the_way_con_206_derives_them() {
    // The whole point of the split: strictness is nearly free at establishment,
    // and a fifteen-minute resolver outage must not sever every live session.
    let c = Ceremony::accepted();
    let mut issuer = c.issuer.clone();
    issuer.closure_age_seconds = 300; // > 60, < 900

    let evidence = Evidence { issuer: Some(&issuer), ..c.evidence() };
    refused_at(&c, c.expectation(), evidence, AcceptStep::Status);

    let continuing = Expectation { freshness: Freshness::Continuation, ..c.expectation() };
    assert!(
        accept_grant(&c.grant_bytes, &continuing, &evidence).is_ok(),
        "continuation uses maxClosureAgeSeconds"
    );
}

#[test]
fn step_10_records_when_a_bundle_supplied_closure_was_relied_on() {
    // CON-206: a verifier that relies on the bundle's closure "SHALL record
    // that it did so". The closure is the issuer's own account of its own
    // revocations, and the issuer is the party a revocation constrains.
    let c = Ceremony::accepted();
    assert!(!accept_grant(&c.grant_bytes, &c.expectation(), &c.evidence())
        .unwrap()
        .used_bundle_closure);

    let mut issuer = c.issuer.clone();
    issuer.source = ClosureSource::BundleOrCache;
    let evidence = Evidence { issuer: Some(&issuer), ..c.evidence() };
    let accepted = accept_grant(&c.grant_bytes, &c.expectation(), &evidence).unwrap();
    assert!(accepted.used_bundle_closure);
}

#[test]
fn step_10_treats_a_set_projection_bit_as_permanently_true_and_an_unset_one_as_decaying() {
    // CON-210: the two bit values are not symmetric. A set bit rejects at any
    // age; an unset, stale, or unavailable one never bypasses the CRDT check —
    // which is why the CRDT check runs regardless of what the projection said.
    let c = Ceremony::accepted();

    let set = Evidence { projection: Some(Projection::BitSet), ..c.evidence() };
    refused_at(&c, c.expectation(), set, AcceptStep::Status);

    for benign in [Projection::BitUnset, Projection::Unavailable] {
        let evidence = Evidence { projection: Some(benign), ..c.evidence() };
        assert!(accept_grant(&c.grant_bytes, &c.expectation(), &evidence).is_ok(), "{benign:?}");
    }

    // An unset bit does not rescue a grant the CRDT set has revoked.
    let g = accept_grant(&c.grant_bytes, &c.expectation(), &c.evidence()).unwrap().grant;
    let mut issuer = c.issuer.clone();
    issuer.revoked_credential_ids.push(g.id);
    let evidence = Evidence {
        issuer: Some(&issuer),
        projection: Some(Projection::BitUnset),
        ..c.evidence()
    };
    refused_at(&c, c.expectation(), evidence, AcceptStep::Status);
}

#[test]
fn step_11_rejects_outside_the_half_open_validity_window() {
    // TEST-212: before validFrom, at validFrom, immediately before validUntil,
    // at validUntil.
    let c = Ceremony::accepted();
    let g = accept_grant(&c.grant_bytes, &c.expectation(), &c.evidence()).unwrap().grant;

    let at = |now: i64| Expectation { now, ..c.expectation() };

    refused_at(&c, at(g.valid_from - 1), c.evidence(), AcceptStep::Validity);
    assert!(accept_grant(&c.grant_bytes, &at(g.valid_from), &c.evidence()).is_ok(), "at validFrom");
    assert!(
        accept_grant(&c.grant_bytes, &at(g.valid_until - 1), &c.evidence()).is_ok(),
        "immediately before validUntil"
    );
    // Half-open: invalid *at* its own expiry, not one second later.
    refused_at(&c, at(g.valid_until), c.evidence(), AcceptStep::Validity);
}

#[test]
fn step_11_checks_the_lifetime_bound_on_the_interval_not_on_the_instant() {
    // TEST-212: "reject one exceeding it by a single second **while the current
    // time sits inside its window**, proving the check is on the interval
    // rather than on the instant."
    let c = Ceremony::accepted();
    let valid_from = NOW - 3_600;

    for (extra, should_pass) in [(0i64, true), (1, false)] {
        let bytes = reissue(&c, valid_from, valid_from + 2_592_000 + extra);
        let outcome = accept_grant(&bytes, &c.expectation(), &c.evidence());
        if should_pass {
            assert!(outcome.is_ok(), "a lifetime equal to the ceiling is accepted");
        } else {
            let err = outcome.unwrap_err();
            assert_eq!(err.step, AcceptStep::Validity, "one second over the ceiling");
        }
    }
}

#[test]
fn step_12_rejects_an_undeclared_permission_or_a_missing_required_one() {
    let c = Ceremony::accepted();

    // A permission the profile never declared.
    let undeclared = format!("{APPLICATION_ID}#admin");
    let bytes = reissue_with_permissions(&c, &[undeclared]);
    let err = accept_grant(&bytes, &c.expectation(), &c.evidence()).unwrap_err();
    assert_eq!(err.step, AcceptStep::Permissions);

    // The grant is fine, but the operation needs scope it does not carry.
    let needed = [format!("{APPLICATION_ID}#admin")];
    let refs: Vec<&str> = needed.iter().map(String::as_str).collect();
    let expect = Expectation { operation_permissions: &refs, ..c.expectation() };
    refused_at(&c, expect, c.evidence(), AcceptStep::Permissions);
}

#[test]
fn step_13_rejects_a_missing_wrong_or_mismatched_device_proof() {
    let c = Ceremony::accepted();

    // Absent.
    let evidence = Evidence { proof: None, ..c.evidence() };
    refused_at(&c, c.expectation(), evidence, AcceptStep::Proof);

    // Signed by another device — REQ-206's whole point.
    let impostor = ed25519_dalek::SigningKey::from_bytes(&[99u8; 32]);
    let forged = proof::sign(&c.challenge, &impostor);
    let evidence =
        Evidence { proof: Some((&c.challenge, &forged, common::VERIFIER_SESSION)), ..c.evidence() };
    refused_at(&c, c.expectation(), evidence, AcceptStep::Proof);

    // A nonce issued for a different grant.
    let other = Ceremony::build(0, 2, 3, APPLICATION_ID);
    let evidence = Evidence {
        proof: Some((&other.challenge, &other.signature, common::VERIFIER_SESSION)),
        ..c.evidence()
    };
    refused_at(&c, c.expectation(), evidence, AcceptStep::Proof);
}

#[test]
fn step_13_rejects_a_nonce_issued_in_another_verifier_session() {
    // CON-207: the verifier "SHALL reject a nonce issued for another
    // application, account, grant, verifier session, or time window."
    //
    // Every other binding here agrees — same application, same account, same
    // grant, valid signature — and only the session differs. That is the case a
    // verifier running concurrent sessions over one durable nonce ledger sees,
    // and the one that used to be accepted.
    let c = Ceremony::accepted();
    let evidence =
        Evidence { proof: Some((&c.challenge, &c.signature, "a-different-session")), ..c.evidence() };
    refused_at(&c, c.expectation(), evidence, AcceptStep::Proof);
}

// ── the outward-facing error set stays small ───────────────────────────────

#[test]
fn externally_visible_errors_collapse_to_three_outcomes() {
    // CON-206: "externally visible errors SHOULD collapse to a small stable set
    // so that attackers do not gain a credential oracle." The step is for the
    // local log and the corpus; this is what may cross a wire.
    let c = Ceremony::accepted();
    let mut seen = std::collections::HashSet::new();

    let oversized = vec![b'a'; grant::MAX_GRANT_OCTETS + 1];
    seen.insert(
        accept_grant(&oversized, &c.expectation(), &c.evidence()).unwrap_err().public(),
    );

    let no_issuer = Evidence { issuer: None, ..c.evidence() };
    seen.insert(
        accept_grant(&c.grant_bytes, &c.expectation(), &no_issuer).unwrap_err().public(),
    );

    let no_proof = Evidence { proof: None, ..c.evidence() };
    seen.insert(accept_grant(&c.grant_bytes, &c.expectation(), &no_proof).unwrap_err().public());

    assert!(seen.contains(&PublicReason::Rejected));
    assert!(seen.contains(&PublicReason::StateUnavailable));
    assert!(seen.contains(&PublicReason::ProofFailed));
    assert_eq!(seen.len(), 3, "the outward set must not grow: {seen:?}");
}

#[test]
fn every_step_has_a_corpus_identifier() {
    // CON-226's completeness rule: "for each of CON-206's thirteen numbered
    // steps, the corpus SHALL contain at least one case whose `expect.reject`
    // names it."
    let steps = [
        AcceptStep::Size,
        AcceptStep::Jws,
        AcceptStep::Header,
        AcceptStep::Closure,
        AcceptStep::DidResolution,
        AcceptStep::IssuerKey,
        AcceptStep::Signature,
        AcceptStep::Fields,
        AcceptStep::AccountBinding,
        AcceptStep::Status,
        AcceptStep::Validity,
        AcceptStep::Permissions,
        AcceptStep::Proof,
    ];
    assert_eq!(steps.len(), 13);
    for (i, step) in steps.iter().enumerate() {
        assert_eq!(step.corpus_id(), format!("con_206_step_{}", i + 1));
    }
}

// ── helpers ────────────────────────────────────────────────────────────────

fn payload_of(c: &Ceremony) -> Json {
    let text = core::str::from_utf8(&c.grant_bytes).unwrap();
    jws::recognise(text, grant::GRANT_JWS, &[]).unwrap().payload
}

fn set(payload: &mut Json, name: &str, value: Json) {
    let Json::Object(members) = payload else { unreachable!() };
    match members.iter_mut().find(|(k, _)| k == name) {
        Some(slot) => slot.1 = value,
        None => members.push((name.to_string(), value)),
    }
}

/// Sign a mutated payload with the genuine home key, so the failure attributes
/// to the field rather than to the signature.
fn reject_field(c: &Ceremony, payload: &Json) {
    let mutated = jws::sign(&grant::header(&c.home_did), payload, &c.home_key);
    let err = accept_grant(mutated.as_bytes(), &c.expectation(), &c.evidence())
        .expect_err("a field mutation must not leave the result authorized");
    assert_eq!(err.step, AcceptStep::Fields, "{err}");
}

fn reissue(c: &Ceremony, valid_from: i64, valid_until: i64) -> Vec<u8> {
    reissue_inner(c, valid_from, valid_until, &[PERMISSION.to_string()])
}

fn reissue_with_permissions(c: &Ceremony, permissions: &[String]) -> Vec<u8> {
    reissue_inner(c, NOW - 3_600, NOW - 3_600 + 2_592_000, permissions)
}

fn reissue_inner(
    c: &Ceremony,
    valid_from: i64,
    valid_until: i64,
    permissions: &[String],
) -> Vec<u8> {
    use selfsame_app_identity::profile::ApplicationId;
    let app = ApplicationId::parse(APPLICATION_ID).unwrap();
    let device_public = c.device_key.verifying_key().to_bytes();
    grant::issue(
        &c.home_key,
        &c.home_did,
        &[12u8; 32],
        &c.device_did,
        &device_public,
        &app,
        &c.account,
        permissions,
        valid_from,
        valid_until,
    )
    .into_bytes()
}
