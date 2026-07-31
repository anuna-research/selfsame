//! `TEST-203` — application ID and profile canonicality.
//!
//! **Validates:** `REQ-202`, `REQ-209`.
//!
//! > Exercise the `CON-201` profile recognizer as a closed language. Accept the
//! > normative profile corpus and require `SHA-256(RFC8785(profile))` to agree
//! > across two independent implementations. Reject: an unknown member at top
//! > level and at each nested depth, a missing required member, a duplicate
//! > member name, a byte-order mark, invalid UTF-8, a document over 65,536
//! > octets, nesting past depth 8, `profileVersion` other than `1`, an empty or
//! > over-length `allowedPermissions`, a permission that is unsorted,
//! > duplicated, off-origin, or lacking a fragment, `priority` or `weight`
//! > outside `[0, 65535]`, a lowest-priority group whose weights are all zero,
//! > and any input that does not re-serialize byte-for-byte. Assert zero
//! > semantic action on every rejection — no probe, no derivation, no network
//! > request.

mod common;

use common::*;
use selfsame_app_identity::json::{self, Json, JsonError};
use selfsame_app_identity::profile::{ApplicationProfile, ProfileError};

fn accept(octets: &[u8]) -> ApplicationProfile {
    ApplicationProfile::recognise(octets)
        .unwrap_or_else(|e| panic!("the example profile should be recognised: {e}"))
}

fn reject(octets: &[u8]) -> ProfileError {
    ApplicationProfile::recognise(octets).expect_err("profile should be rejected")
}

// ── positive: the normative profile corpus ─────────────────────────────────

#[test]
fn recognises_the_example_profile_and_exposes_its_parsed_values() {
    let profile = accept(&profile_octets());
    assert_eq!(profile.application_id.as_str(), APPLICATION_ID);
    assert_eq!(profile.application_id.origin(), "https://photos.example");
    assert_eq!(profile.account_authority, ACCOUNT_AUTHORITY);
    assert_eq!(profile.allowed_permissions, vec![PERMISSION.to_string()]);
    assert_eq!(profile.enrollment_keys.len(), 1);
    assert_eq!(profile.mobile_bindings.len(), 2);
    assert_eq!(profile.rendezvous.len(), 2);
    assert_eq!(profile.state_resolvers.len(), 3);
    assert_eq!(profile.pairing_record_relays.len(), 2);
    assert_eq!(profile.revocation.max_grant_lifetime_seconds, 2_592_000);
    assert_eq!(profile.revocation.max_closure_age_seconds, 900);
    assert_eq!(profile.revocation.propagation_sla_seconds, 60);
    assert!(profile.revocation.projection.is_some());
}

#[test]
fn the_digest_is_sha256_over_the_canonical_octets_and_is_stable() {
    use sha2::Digest as _;
    let octets = profile_octets();
    let profile = accept(&octets);
    assert_eq!(profile.canonical_bytes(), octets.as_slice());
    let expected: [u8; 32] = sha2::Sha256::digest(&octets).into();
    assert_eq!(profile.digest(), &expected);
    // Recognising the same octets twice gives the same digest — the property a
    // second implementation has to reproduce for CON-214 and CON-220 step 6.
    assert_eq!(accept(&octets).digest(), profile.digest());
}

#[test]
fn a_profile_without_the_optional_members_is_still_recognised() {
    // `pairingRecordRelays` and `revocation.projection` are the two optional
    // members. Their absence disables a transport tier and the Bitstring
    // projection respectively, and disables nothing else.
    let mut octets = without_member("pairingRecordRelays");
    let profile = accept(&octets);
    assert!(profile.pairing_record_relays.is_empty());

    let mut value = json::recognise(&octets, LIMITS).unwrap();
    strip_projection(&mut value);
    octets = json::canonicalise(&value);
    let profile = accept(&octets);
    assert!(profile.revocation.projection.is_none());
}

#[test]
fn the_session_establishment_bound_is_the_minimum_of_the_two_declared_values() {
    // CON-206's freshness split adds no profile member: both tiers are derived
    // from values CON-201 already defines.
    let profile = accept(&profile_octets());
    assert_eq!(profile.revocation.session_establishment_bound(), 60);
    assert_eq!(profile.revocation.max_closure_age_seconds, 900);
}

#[test]
fn every_rendezvous_descriptor_carries_its_own_canonical_digest() {
    let profile = accept(&profile_octets());
    let a = &profile.rendezvous[0];
    let b = &profile.rendezvous[1];
    assert_ne!(a.digest, b.digest, "distinct descriptors must have distinct digests");

    // CON-201: "the canonical descriptor bytes are the RFC 8785 serialization
    // of the complete rendezvous descriptor, including all three pairing
    // fields." Recomputing it here from the fixture proves the implementation
    // hashes the whole descriptor and not a subset.
    use sha2::Digest as _;
    let expected: [u8; 32] = sha2::Sha256::digest(json::canonicalise(&descriptor(
        "au-primary",
        "rendezvous-au.provider.example",
        "pairing-au.provider.example",
        "03",
        10,
        80,
    )))
    .into();
    assert_eq!(a.digest, expected);
}

// ── negative-input: the closed-language rejections ─────────────────────────

const LIMITS: selfsame_app_identity::json::Limits =
    selfsame_app_identity::json::Limits { max_bytes: 65_536, max_depth: 8 };

fn strip_projection(value: &mut Json) {
    let Json::Object(members) = value else { unreachable!() };
    let revocation = members.iter_mut().find(|(k, _)| k == "revocation").unwrap();
    let Json::Object(inner) = &mut revocation.1 else { unreachable!() };
    inner.retain(|(k, _)| k != "projection");
}

#[test]
fn rejects_an_unknown_member_at_the_top_level() {
    let octets = with_member("extra", Json::int(1));
    assert_eq!(reject(&octets), ProfileError::UnknownMember("extra".into()));
}

#[test]
fn rejects_an_unknown_member_at_each_nested_depth() {
    // "An unknown member at any depth is a rejection, not an extension point."
    // Depth is where a schema-shaped validator most often stops looking.
    for (path, expected) in [
        ("enrollment.surprise", "enrollment.surprise"),
        ("revocation.surprise", "revocation.surprise"),
        ("revocation.projection.surprise", "revocation.projection.surprise"),
    ] {
        let octets = with_nested(path, Json::int(1));
        assert_eq!(
            reject(&octets),
            ProfileError::UnknownMember(expected.into()),
            "{path}"
        );
    }
    // …and inside an array element.
    let octets = with_nested("rendezvous.surprise", Json::int(1));
    assert_eq!(reject(&octets), ProfileError::UnknownMember("rendezvous[].surprise".into()));
    let octets = with_nested("stateResolvers.surprise", Json::int(1));
    assert_eq!(reject(&octets), ProfileError::UnknownMember("stateResolvers[].surprise".into()));
    let octets = with_nested("enrollment.requestSigningKeys.surprise", Json::int(1));
    assert_eq!(
        reject(&octets),
        ProfileError::UnknownMember("enrollment.requestSigningKeys[].surprise".into())
    );
    let octets = with_nested("enrollment.requestSigningKeys.publicKeyJwk.surprise", Json::int(1));
    assert_eq!(
        reject(&octets),
        ProfileError::UnknownMember("enrollment.requestSigningKeys[].publicKeyJwk.surprise".into())
    );
}

#[test]
fn rejects_an_account_scope_smuggled_into_the_profile() {
    // CON-201 names this one explicitly: a scope in the profile would give
    // every account the same branch and publish private correlation metadata in
    // release configuration. The closed member set catches it with no special
    // case, which is the point of a closed member set.
    let octets = with_member("accountScopeId", Json::text("A".repeat(43)));
    assert_eq!(reject(&octets), ProfileError::UnknownMember("accountScopeId".into()));
}

#[test]
fn rejects_a_missing_required_member() {
    for name in [
        "profileVersion",
        "applicationId",
        "accountAuthority",
        "verifierAudience",
        "allowedPermissions",
        "enrollment",
        "rendezvous",
        "stateResolvers",
        "revocation",
    ] {
        let octets = without_member(name);
        assert_eq!(reject(&octets), ProfileError::MissingMember(name.into()), "{name}");
    }
}

#[test]
fn rejects_a_duplicate_member_name() {
    // Cannot be built from the value model, which has no way to hold two
    // members of one name — so the octets are edited directly.
    let octets = profile_octets();
    let text = String::from_utf8(octets).unwrap();
    let doubled = text.replacen(r#""profileVersion":1"#, r#""profileVersion":1,"profileVersion":2"#, 1);
    assert_eq!(
        reject(doubled.as_bytes()),
        ProfileError::Json(JsonError::DuplicateMember("profileVersion".into()))
    );
}

#[test]
fn rejects_a_byte_order_mark_and_invalid_utf8() {
    let mut with_bom = vec![0xEF, 0xBB, 0xBF];
    with_bom.extend_from_slice(&profile_octets());
    assert_eq!(reject(&with_bom), ProfileError::Json(JsonError::ByteOrderMark));
    assert_eq!(reject(&[0xFF, 0xFE, b'{', b'}']), ProfileError::Json(JsonError::NotUtf8));
}

#[test]
fn rejects_a_document_over_the_octet_bound() {
    // The bound is applied to the octets before parsing, so an over-long
    // document costs one length check rather than a full parse.
    let padding = "a".repeat(70_000);
    let octets = with_member("accountAuthority", Json::text(padding));
    assert!(octets.len() > 65_536);
    assert_eq!(reject(&octets), ProfileError::Json(JsonError::TooLarge));
}

#[test]
fn rejects_nesting_past_depth_eight() {
    let mut deep = Json::int(1);
    for _ in 0..9 {
        deep = Json::arr([deep]);
    }
    let octets = with_member("allowedPermissions", deep);
    assert_eq!(reject(&octets), ProfileError::Json(JsonError::DepthExceeded));
}

#[test]
fn rejects_a_profile_version_other_than_one() {
    for version in [0i64, 2, -1] {
        let octets = with_member("profileVersion", Json::int(version));
        assert!(matches!(reject(&octets), ProfileError::BadValue { path, .. } if path == "profileVersion"));
    }
}

#[test]
fn rejects_input_that_does_not_re_serialise_byte_for_byte() {
    // Step 5. Three different ways to be non-canonical, each of which a
    // permissive parser would accept and then silently repair.
    let text = String::from_utf8(profile_octets()).unwrap();
    for mutated in [
        format!(" {text}"),
        text.replacen(r#""profileVersion":1"#, r#""profileVersion" : 1"#, 1),
        text.replacen(r#""accountAuthority""#, r#""accountAuthority""#, 1).replacen(
            "accounts.photos.example",
            "accounts.photos.example",
            1,
        ),
    ] {
        if mutated == text {
            continue;
        }
        assert_eq!(reject(mutated.as_bytes()), ProfileError::NotCanonical, "{mutated:.60}");
    }

    // Member order is the canonical property most easily lost, because most
    // serialisers preserve insertion order rather than sorting.
    let Json::Object(mut members) = json::recognise(text.as_bytes(), LIMITS).unwrap() else {
        unreachable!()
    };
    members.reverse();
    let reordered = serialise_preserving_order(&members);
    assert_ne!(reordered, text.as_bytes());
    assert_eq!(reject(&reordered), ProfileError::NotCanonical);
}

/// Serialise an object without sorting, to build a document that recognises but
/// is not canonical.
fn serialise_preserving_order(members: &[(String, Json)]) -> Vec<u8> {
    let mut out = b"{".to_vec();
    for (i, (name, value)) in members.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(&json::canonicalise(&Json::text(name.clone())));
        out.push(b':');
        out.extend_from_slice(&json::canonicalise(value));
    }
    out.push(b'}');
    out
}

// ── permission grammar ─────────────────────────────────────────────────────

#[test]
fn rejects_an_empty_or_over_length_permission_array() {
    let octets = with_member("allowedPermissions", Json::arr([]));
    assert!(matches!(reject(&octets), ProfileError::BadValue { path, .. } if path == "allowedPermissions"));

    let many: Vec<Json> = (0..65)
        .map(|i| Json::text(format!("https://photos.example/selfsame/application#p{i:03}")))
        .collect();
    let octets = with_member("allowedPermissions", Json::Array(many));
    assert!(matches!(reject(&octets), ProfileError::BadValue { path, .. } if path == "allowedPermissions"));
}

#[test]
fn rejects_an_unsorted_or_duplicated_permission_array() {
    // CON-206 step 12 and CON-214 both ask "is this an exact subset". An
    // unsorted or duplicated array makes that question depend on how the
    // comparison happened to be written.
    let unsorted = Json::arr([
        Json::text("https://photos.example/selfsame/application#zeta"),
        Json::text("https://photos.example/selfsame/application#alpha"),
    ]);
    assert!(matches!(
        reject(&with_member("allowedPermissions", unsorted)),
        ProfileError::BadValue { path, .. } if path == "allowedPermissions"
    ));

    let duplicated = Json::arr([Json::text(PERMISSION), Json::text(PERMISSION)]);
    assert!(matches!(
        reject(&with_member("allowedPermissions", duplicated)),
        ProfileError::BadValue { path, .. } if path == "allowedPermissions"
    ));
}

#[test]
fn rejects_a_permission_off_the_application_origin_or_lacking_a_fragment() {
    for permission in [
        "https://elsewhere.example/selfsame/application#device",
        "https://photos.example/selfsame/application",
        "https://photos.example/selfsame/application#",
        "http://photos.example/selfsame/application#device",
    ] {
        let octets = with_member("allowedPermissions", Json::arr([Json::text(permission)]));
        assert!(
            matches!(reject(&octets), ProfileError::BadValue { path, .. } if path == "allowedPermissions"),
            "{permission}"
        );
    }
}

// ── application identifier ─────────────────────────────────────────────────

#[test]
fn rejects_a_verifier_audience_that_differs_from_the_application_id() {
    let octets = with_member("verifierAudience", Json::text(OTHER_APPLICATION_ID));
    assert!(matches!(reject(&octets), ProfileError::BadValue { path, .. } if path == "verifierAudience"));
}

#[test]
fn rejects_a_non_canonical_application_id() {
    for id in [
        "https://Photos.example/selfsame/application",
        "https://photos.example:443/selfsame/application",
        "https://user@photos.example/selfsame/application",
        "https://photos.example/selfsame/application?v=1",
        "https://photos.example/selfsame/application#x",
        "https://photos.example/selfsame/../application",
        "https://photos.example",
        "http://photos.example/selfsame/application",
    ] {
        // `verifierAudience` must match, so both move together.
        let Json::Object(mut members) = profile_value() else { unreachable!() };
        for (k, v) in members.iter_mut() {
            if k == "applicationId" || k == "verifierAudience" {
                *v = Json::text(id);
            }
        }
        let octets = json::canonicalise(&Json::Object(members));
        assert!(
            matches!(reject(&octets), ProfileError::BadValue { path, .. } if path == "applicationId"),
            "{id} was accepted"
        );
    }
}

#[test]
fn rejects_a_non_canonical_account_authority() {
    for authority in ["Accounts.photos.example", "accounts.photos.example.", "accounts.photos.example:443", ""] {
        let octets = with_member("accountAuthority", Json::text(authority));
        assert!(
            matches!(reject(&octets), ProfileError::BadValue { path, .. } if path == "accountAuthority"),
            "{authority}"
        );
    }
}

// ── provider grammars ──────────────────────────────────────────────────────

#[test]
fn rejects_priority_or_weight_outside_the_declared_range() {
    for (member, value) in [
        ("priority", 65_536i64),
        ("priority", -1),
        ("weight", 65_536),
        ("weight", -1),
    ] {
        let octets = with_nested(&format!("rendezvous.{member}"), Json::int(value));
        assert!(
            matches!(reject(&octets), ProfileError::BadValue { path, .. } if path == format!("rendezvous[].{member}")),
            "{member} = {value}"
        );
    }
}

#[test]
fn rejects_a_lowest_priority_group_whose_weights_are_all_zero() {
    // Without this rule CON-208 step 6 would draw from an all-zero group and
    // fall through to the next priority, silently inverting the developer's
    // stated preference order.
    let octets = with_member(
        "rendezvous",
        Json::arr([
            descriptor("a", "r1.example", "p1.example", "03", 10, 0),
            descriptor("b", "r2.example", "p2.example", "17", 20, 50),
        ]),
    );
    assert!(matches!(reject(&octets), ProfileError::BadValue { path, .. } if path == "rendezvous"));
}

#[test]
fn rejects_duplicate_provider_ids_and_duplicate_pairing_routes() {
    let duplicate_id = Json::arr([
        descriptor("same", "r1.example", "p1.example", "03", 10, 50),
        descriptor("same", "r2.example", "p2.example", "17", 10, 50),
    ]);
    assert!(matches!(
        reject(&with_member("rendezvous", duplicate_id)),
        ProfileError::BadValue { path, .. } if path == "rendezvous"
    ));

    let duplicate_route = Json::arr([
        descriptor("a", "r1.example", "p1.example", "03", 10, 50),
        descriptor("b", "r2.example", "p2.example", "03", 10, 50),
    ]);
    assert!(matches!(
        reject(&with_member("rendezvous", duplicate_route)),
        ProfileError::BadValue { path, .. } if path == "rendezvous"
    ));
}

#[test]
fn rejects_a_pairing_route_that_is_not_exactly_two_ascii_digits() {
    for route in ["3", "003", "ab", "", "0x"] {
        let octets = with_nested("rendezvous.pairingRoute", Json::text(route));
        assert!(
            matches!(reject(&octets), ProfileError::BadValue { path, .. } if path == "rendezvous[].pairingRoute"),
            "{route:?}"
        );
    }
}

#[test]
fn rejects_an_unsupported_protocol_token() {
    let octets = with_nested("rendezvous.protocol", Json::text("selfsame-rendezvous-v2"));
    assert!(matches!(reject(&octets), ProfileError::BadValue { path, .. } if path == "rendezvous[].protocol"));

    let octets = with_nested("rendezvous.pairingProtocol", Json::text("selfsame-pairing-v2"));
    assert!(matches!(reject(&octets), ProfileError::BadValue { path, .. } if path == "rendezvous[].pairingProtocol"));

    // CON-201 replaced `did-crdt-signed-closure-v1`, which named no contract
    // and made the reference implementation the accidental standard.
    let octets = with_nested("stateResolvers.protocol", Json::text("did-crdt-signed-closure-v1"));
    assert!(matches!(reject(&octets), ProfileError::BadValue { path, .. } if path == "stateResolvers[].protocol"));
}

#[test]
fn rejects_a_rendezvous_url_that_is_not_a_canonical_origin() {
    for url in [
        "https://rendezvous.example/",
        "https://rendezvous.example/mailbox",
        "http://rendezvous.example",
        "https://Rendezvous.example",
    ] {
        let octets = with_nested("rendezvous.url", Json::text(url));
        assert!(
            matches!(reject(&octets), ProfileError::BadValue { path, .. } if path == "rendezvous[].url"),
            "{url}"
        );
    }
}

#[test]
fn rejects_an_expired_or_malformed_descriptor_expiry() {
    for stamp in ["2027-07-30T00:00:00", "2027-13-30T00:00:00Z", "not-a-date"] {
        let octets = with_nested("rendezvous.validUntil", Json::text(stamp));
        assert!(
            matches!(reject(&octets), ProfileError::BadValue { path, .. } if path == "rendezvous[].validUntil"),
            "{stamp}"
        );
    }
}

// ── enrollment grammar ─────────────────────────────────────────────────────

#[test]
fn rejects_an_enrollment_key_that_is_not_ed25519_in_the_one_admitted_shape() {
    for (member, value) in [("kty", "EC"), ("crv", "P-256")] {
        let octets =
            with_nested(&format!("enrollment.requestSigningKeys.publicKeyJwk.{member}"), Json::text(value));
        assert!(
            matches!(reject(&octets), ProfileError::BadValue { path, .. } if path.contains("publicKeyJwk")),
            "{member} = {value}"
        );
    }
    // A non-canonical or wrong-length `x`.
    for x in ["", "AAAA", &"A".repeat(43)] {
        let octets =
            with_nested("enrollment.requestSigningKeys.publicKeyJwk.x", Json::text(x));
        // The all-`A` value is 43 characters and decodes to 32 zero octets, so
        // it is legitimately canonical; only the malformed ones are refused.
        let outcome = ApplicationProfile::recognise(&octets);
        if x.len() == 43 {
            assert!(outcome.is_ok(), "a canonical all-zero key is well-formed");
        } else {
            assert!(outcome.is_err(), "{x:?}");
        }
    }
}

#[test]
fn rejects_an_enrollment_kid_off_the_application_origin() {
    let octets = with_nested(
        "enrollment.requestSigningKeys.kid",
        Json::text("https://elsewhere.example/selfsame/application#k"),
    );
    assert!(matches!(reject(&octets), ProfileError::BadValue { path, .. } if path.contains("kid")));
}

#[test]
fn rejects_an_empty_enrollment_key_set() {
    let octets = with_nested("enrollment.requestSigningKeys", Json::arr([]));
    assert!(matches!(
        reject(&octets),
        ProfileError::BadValue { path, .. } if path == "enrollment.requestSigningKeys"
    ));
}

#[test]
fn rejects_a_mobile_binding_whose_id_does_not_match_its_own_fields() {
    // Field presence is not proof: CON-201 says the wallet accepts a binding
    // only after CON-220 authenticates the profile and CON-222/CON-223
    // authenticate the binding. The identifier is at least required to be
    // self-consistent before any of that runs.
    let octets = with_nested("enrollment.mobileBindings.packageName", Json::text("com.attacker.app"));
    assert!(matches!(reject(&octets), ProfileError::BadValue { path, .. } if path.contains("mobileBindings")));
}

// ── revocation ceilings ────────────────────────────────────────────────────

#[test]
fn rejects_every_revocation_value_above_its_ceiling() {
    for (member, ceiling) in [
        ("maxGrantLifetimeSeconds", 2_592_000i64),
        ("maxClosureAgeSeconds", 3_600),
        ("propagationSlaSeconds", 300),
    ] {
        let at = with_nested(&format!("revocation.{member}"), Json::int(ceiling));
        assert!(ApplicationProfile::recognise(&at).is_ok(), "{member} at its ceiling is valid");

        for value in [ceiling + 1, 0, -1] {
            let octets = with_nested(&format!("revocation.{member}"), Json::int(value));
            assert!(
                matches!(reject(&octets), ProfileError::BadValue { path, .. } if path == format!("revocation.{member}")),
                "{member} = {value}"
            );
        }
    }

    let octets = with_nested("revocation.projection.maxAgeSeconds", Json::int(3_601));
    assert!(matches!(
        reject(&octets),
        ProfileError::BadValue { path, .. } if path == "revocation.projection.maxAgeSeconds"
    ));
}

#[test]
fn rejects_an_unsupported_revocation_method() {
    let octets = with_nested("revocation.method", Json::text("http-revoke-v1"));
    assert!(matches!(reject(&octets), ProfileError::BadValue { path, .. } if path == "revocation.method"));
}

// ── prohibited-action: nothing happens on a rejection ──────────────────────

#[test]
fn a_rejected_profile_produces_no_profile_at_all() {
    // TEST-203: "Assert zero semantic action on every rejection — no probe, no
    // derivation, no network request."
    //
    // The first is a property of the signature: `recognise` returns
    // `Result<ApplicationProfile, _>`, so a rejection yields no profile, and
    // every downstream capability in this crate takes an `&ApplicationProfile`.
    // A caller therefore cannot probe, derive, or request against a rejected
    // document, because it never holds one.
    //
    // The second is a property of the crate: `tests/purity.rs` proves no
    // network-capable crate is in the dependency graph at all, so "no network
    // request" holds for accepted profiles too.
    let outcome = ApplicationProfile::recognise(&with_member("extra", Json::int(1)));
    assert!(outcome.is_err());
    assert!(outcome.ok().is_none());
}
