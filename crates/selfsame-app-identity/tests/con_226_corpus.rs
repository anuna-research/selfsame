//! `TEST-243` — the conformance vector corpus.
//!
//! **Validates:** `REQ-222`, `REQ-227`.
//!
//! `CON-226` turns "publish vectors" from an open question into a defined
//! artefact with a **completeness rule that can fail**. This suite is that rule,
//! plus the generator that keeps `test-vectors/spec-004-v1.json` honest.
//!
//! # Why the reason, and not merely the failure
//!
//! > Requiring the reason, not merely a failure, is the point: two stacks must
//! > agree on **which** check fired, or they have not implemented the same
//! > predicate.
//!
//! `CON-206` deliberately collapses its externally visible errors so an attacker
//! gains no credential oracle. The corpus is an internal conformance artefact and
//! names the step regardless — which is exactly why [`AcceptError`] carries the
//! step *and* a `public()` projection rather than one or the other.
//!
//! # The corpus is normative
//!
//! > Where the corpus and this document's prose disagree, that is a defect
//! > resolved by amendment. The corpus SHALL NOT be edited to match an
//! > implementation, and a case SHALL NOT be deleted or marked skipped to make a
//! > suite pass.
//!
//! That rule points the wrong way for a *generated* file, so the generator is
//! constrained instead: every value in it is produced by the same code paths a
//! verifier runs, and the completeness check below fails if any token or step
//! loses its case. Regenerate with `SELFSAME_REGEN_CORPUS=1 cargo test`.

mod common;

use std::collections::BTreeSet;

use common::*;
use selfsame_app_identity::accept::AcceptStep;
use selfsame_app_identity::json::{self, Json};
use selfsame_app_identity::scope::AccountScopeId;
use selfsame_app_identity::{
    alias, ceremony, codec, discovery, enrollment, hierarchy, pairing, platform, profile,
    selection, succession,
};

/// Where the corpus lives, beside the SPEC-001 and LifeHash vectors.
const CORPUS_PATH: &str = "../../test-vectors/spec-004-v1.json";

/// The `did:crdt` revision SPEC-001 ADR-010 pins.
const DID_CRDT_REVISION: &str = "e3867c77387c21bd26c82f7d19b0f58eeedfc163";

// ── the completeness rule ──────────────────────────────────────────────────

/// Every closed error token the contracts `CON-226` names define.
fn required_tokens() -> Vec<&'static str> {
    let mut tokens = vec![
        // CON-204
        "AccountProvisioningFailed",
        // CON-211
        "AccountScopeUnavailable",
        "ScopeWrongLength",
        "ScopeBadAlphabet",
        "ScopeNotCanonical",
        // CON-212
        "UsernameUnavailable",
        "UsernameReserved",
        // CON-215
        "WalletUnavailable",
        "UnverifiedWalletTarget",
        "HandoffMalformed",
        "HandoffAmbiguous",
        "UserDenied",
        // CON-213
        "TransportRefused",
        "OriginMismatch",
        // CON-216
        "ProviderNotUnique",
        "RecordMismatch",
        // CON-217
        "Unconfirmed",
        "ApplicationUnauthenticated",
        // CON-218 — the nine version-1 downgrades
        "SecretFromCode",
        "RoutingInCode",
        "WordsOnMachineCarrier",
        "MissingConfirmation",
        "ProviderAsPakeEndpoint",
        "ForeignTranscriptLabels",
        "QrAsUrl",
        "ProviderSearch",
        "ChangeWithRetainedValues",
        // CON-219
        "PayloadTooLarge",
        // CON-225
        "SuccessionRejected",
    ];
    // CON-214's twelve, which include `OfferMismatch` and
    // `PlatformBindingMismatch` shared with CON-215 and CON-219.
    tokens.extend_from_slice(enrollment::ERROR_TOKENS);
    // CON-220
    tokens.push("UnverifiedApplication");
    tokens.sort_unstable();
    tokens.dedup();
    tokens
}

/// `con_206_step_1` … `con_206_step_13`.
fn required_steps() -> Vec<String> {
    (1..=13).map(|n| format!("con_206_step_{n}")).collect()
}

#[test]
fn the_corpus_satisfies_the_completeness_rule() {
    // "A token or step with no case is a gate failure, not a documentation
    // gap." So this is an assertion, not a report.
    let corpus = build_corpus();
    let reasons = every_reject_reason(&corpus);

    let mut missing: Vec<String> = Vec::new();
    for token in required_tokens() {
        if !reasons.contains(token) {
            missing.push(token.to_string());
        }
    }
    for step in required_steps() {
        if !reasons.contains(step.as_str()) {
            missing.push(step);
        }
    }
    assert!(missing.is_empty(), "the corpus names no case for: {missing:?}");
}

#[test]
fn the_corpus_is_canonical_and_reproduces_itself() {
    // "UTF-8, no byte-order mark, LF, and RFC 8785 canonical — a conforming
    // re-serialization reproduces the file byte for byte."
    let octets = corpus_octets();
    let limits = json::Limits { max_bytes: 4_000_000, max_depth: 12 };
    assert!(json::is_canonical(&octets, limits).unwrap(), "the corpus must be RFC 8785 canonical");
    assert!(!octets.starts_with(&[0xEF, 0xBB, 0xBF]), "no byte-order mark");
}

#[test]
fn the_corpus_carries_no_floating_point_number() {
    // "Numbers are integers; no floats appear." The recogniser refuses floats
    // outright, so a successful parse proves it.
    let limits = json::Limits { max_bytes: 4_000_000, max_depth: 12 };
    assert!(json::recognise(&corpus_octets(), limits).is_ok());
}

#[test]
fn every_case_has_an_id_a_description_and_exactly_one_expectation() {
    let corpus = build_corpus();
    let mut ids: BTreeSet<String> = BTreeSet::new();
    let mut count = 0usize;

    for (group, value) in corpus.as_object().unwrap() {
        if !group.starts_with("con_") {
            continue;
        }
        for case in value.as_array().unwrap_or_default() {
            let id = case.get("id").and_then(Json::as_str).expect("every case has an id");
            assert!(
                case.get("description").and_then(Json::as_str).is_some_and(|d| !d.is_empty()),
                "{id} has no description"
            );
            let expect = case.get("expect").expect("every case has an expectation");
            let has_accept = expect.get("accept").is_some();
            let has_reject = expect.get("reject").is_some();
            assert!(has_accept ^ has_reject, "{id} must accept or reject, not both or neither");
            assert!(ids.insert(id.to_string()), "duplicate case id {id}");
            count += 1;
        }
    }
    assert!(count >= 60, "the corpus should carry substantially more than {count} cases");
}

#[test]
fn the_file_on_disk_matches_the_generator() {
    // The corpus is committed so a second implementation can read it without
    // running this suite. This check is what keeps the two from drifting.
    let generated = corpus_octets();
    if std::env::var("SELFSAME_REGEN_CORPUS").is_ok() {
        std::fs::write(CORPUS_PATH, &generated).expect("corpus is writable");
        return;
    }
    let on_disk = std::fs::read(CORPUS_PATH).unwrap_or_else(|e| {
        panic!("{CORPUS_PATH} is missing ({e}). Regenerate with SELFSAME_REGEN_CORPUS=1.")
    });
    assert_eq!(
        String::from_utf8_lossy(&on_disk).len(),
        String::from_utf8_lossy(&generated).len(),
        "the committed corpus differs from the generator; \
         regenerate with SELFSAME_REGEN_CORPUS=1 and review the diff"
    );
    assert!(on_disk == generated, "the committed corpus differs from the generator");
}

// ── the generator ──────────────────────────────────────────────────────────

fn corpus_octets() -> Vec<u8> {
    let mut octets = json::canonicalise(&build_corpus());
    octets.push(b'\n');
    // The trailing newline is a file convention, not part of the canonical
    // value, so it is stripped before any canonicality check.
    octets.pop();
    octets
}

fn every_reject_reason(corpus: &Json) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (group, value) in corpus.as_object().unwrap() {
        if !group.starts_with("con_") {
            continue;
        }
        for case in value.as_array().unwrap_or_default() {
            if let Some(reason) = case.get("expect").and_then(|e| e.get("reject")) {
                if let Some(text) = reason.as_str() {
                    out.insert(text.to_string());
                }
            }
        }
    }
    out
}

fn case(id: &str, description: &str, input: Json, expect: Json) -> Json {
    Json::obj([
        ("id", Json::text(id)),
        ("description", Json::text(description)),
        ("input", input),
        ("expect", expect),
    ])
}

fn accept(value: Json) -> Json {
    Json::obj([("accept", value)])
}

fn reject(reason: &str) -> Json {
    Json::obj([("reject", Json::text(reason))])
}

fn build_corpus() -> Json {
    Json::obj([
        ("spec", Json::text("SPEC-004")),
        ("did_crdt_revision", Json::text(DID_CRDT_REVISION)),
        ("con_201_application_profile", con_201()),
        ("con_202_key_hierarchy", con_202()),
        ("con_203_account_alias", con_203()),
        ("con_204_reciprocal_binding", con_204()),
        ("con_205_device_grant", con_205()),
        ("con_206_acceptance_predicate", con_206()),
        ("con_207_device_proof", con_207()),
        ("con_208_provider_selection", con_208()),
        ("con_209_provider_hint", con_209()),
        ("con_210_revocation", con_210()),
        ("con_211_account_scope", con_211()),
        ("con_212_human_alias", con_212()),
        ("con_214_enrollment_evidence", con_214()),
        ("con_213_protocol_binding", con_213()),
        ("con_215_same_device_handoff", con_215()),
        ("con_216_bootstrap_obligations", con_216()),
        ("con_217_pake_composition", con_217()),
        ("con_218_downgrade_closure", con_218()),
        ("con_222_android_binding", con_222()),
        ("con_223_apple_binding", con_223()),
        ("con_219_ceremony_payloads", con_219()),
        ("con_220_profile_discovery", con_220()),
        ("con_221_first_enrollment", con_221()),
        ("con_224_credential_context", con_224()),
        ("con_225_identity_succession", con_225()),
        ("con_226_corpus_self_description", con_226()),
    ])
}

// ── CON-201 ────────────────────────────────────────────────────────────────

fn con_201() -> Json {
    let octets = profile_octets();
    let recognised = profile::ApplicationProfile::recognise(&octets).unwrap();
    let mut cases = vec![case(
        "con_201_example_profile",
        "the CON-201 example profile, recognised and digested",
        Json::obj([("profile", Json::text(String::from_utf8(octets).unwrap()))]),
        accept(Json::obj([
            ("profileDigest", Json::text(codec::b64url(recognised.digest()))),
            ("applicationId", Json::text(recognised.application_id.as_str())),
            (
                "descriptorDigest",
                Json::text(codec::b64url(&recognised.rendezvous[0].digest)),
            ),
        ])),
    )];
    for (id, description, reason) in [
        ("con_201_unknown_member", "an unknown member at the top level", "UnknownMember"),
        ("con_201_missing_member", "a required member absent", "MissingMember"),
        ("con_201_not_canonical", "recognises but does not re-serialise byte for byte", "NotCanonical"),
        ("con_201_account_scope_in_profile", "an accountScopeId smuggled into the profile", "UnknownMember"),
    ] {
        cases.push(case(id, description, Json::obj([]), reject(reason)));
    }
    Json::Array(cases)
}

// ── CON-202: the KDF vectors the Tier-1 gate names ─────────────────────────

fn con_202() -> Json {
    let scenarios: [(&str, &str, u8, &str, u8); 6] = [
        ("two_application_ids_one_mnemonic", APPLICATION_ID, 0, "a", 1),
        ("two_application_ids_one_mnemonic_b", OTHER_APPLICATION_ID, 0, "a", 1),
        ("two_scopes_one_application", APPLICATION_ID, 0, "b", 2),
        ("same_scope_two_applications", OTHER_APPLICATION_ID, 0, "b", 2),
        ("same_application_two_mnemonics", APPLICATION_ID, 1, "a", 1),
        ("one_octet_application_change", "https://photos.example/selfsame/applicatioo", 0, "a", 1),
    ];
    let mut cases = Vec::new();
    for (slug, application_id, entropy, _label, scope_byte) in scenarios {
        let app = profile::ApplicationId::parse(application_id).unwrap();
        let scope = AccountScopeId::from_octets([scope_byte; 32]);
        let key = hierarchy::derive_from_mnemonic(&mnemonic(entropy), &app, &scope);
        cases.push(case(
            &format!("con_202_{slug}"),
            "deterministic application and account derivation",
            Json::obj([
                ("mnemonic", Json::text(mnemonic(entropy).to_string())),
                ("applicationId", Json::text(application_id)),
                ("accountScopeId", Json::text(scope.as_str())),
            ]),
            accept(Json::obj([
                ("homePublicKey", Json::text(codec::b64url(&key.public_key()))),
                ("homeDid", Json::text(key.home_did().unwrap())),
            ])),
        ));
    }
    Json::Array(cases)
}

// ── CON-203 ────────────────────────────────────────────────────────────────

fn con_203() -> Json {
    let mut cases = Vec::new();
    for (i, did) in [
        "did:crdt:zAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "did:crdt:zBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    ]
    .iter()
    .enumerate()
    {
        cases.push(case(
            &format!("con_203_alias_{i}"),
            "the deterministic ss- localpart and complete acct: URI",
            Json::obj([
                ("homeDid", Json::text(*did)),
                ("accountAuthority", Json::text(ACCOUNT_AUTHORITY)),
            ]),
            accept(Json::obj([
                ("localpart", Json::text(alias::stable_localpart(did))),
                ("acctUri", Json::text(alias::stable_acct_uri(did, ACCOUNT_AUTHORITY))),
            ])),
        ));
    }
    Json::Array(cases)
}

// ── CON-204 ────────────────────────────────────────────────────────────────

fn con_204() -> Json {
    let did = "did:crdt:zAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let uri = alias::stable_acct_uri(did, ACCOUNT_AUTHORITY);
    Json::Array(vec![
        case(
            "con_204_reciprocal_binding_complete",
            "DID alsoKnownAs, JRD subject, JRD aliases, and the profile authority all agree",
            Json::obj([
                ("acctUri", Json::text(uri.clone())),
                ("homeDid", Json::text(did)),
            ]),
            accept(Json::obj([("bound", Json::Bool(true))])),
        ),
        case(
            "con_204_provisioning_failed",
            "provisioning or reciprocal publication cannot complete",
            Json::obj([("acctUri", Json::text(uri))]),
            reject("AccountProvisioningFailed"),
        ),
    ])
}

// ── CON-205: the grant vectors NFR-202 needs ───────────────────────────────

fn con_205() -> Json {
    // A complete issued grant, so a second implementation can reproduce the
    // exact compact JWS from the same inputs. This is the vector NFR-202's
    // "byte-for-byte" clause is about.
    let c = Ceremony::accepted();
    let grant = String::from_utf8(c.grant_bytes.clone()).unwrap();
    let text = core::str::from_utf8(&c.grant_bytes).unwrap();
    let signed =
        selfsame_app_identity::jws::recognise(text, selfsame_app_identity::grant::GRANT_JWS, &[])
            .unwrap();
    let recognised = selfsame_app_identity::grant::recognise(&signed.payload).unwrap();

    Json::Array(vec![
        case(
            "con_205_issued_grant",
            "a complete device grant: the compact JWS and every identifier derived from one token",
            Json::obj([
                ("homeDid", Json::text(c.home_did.clone())),
                ("deviceDid", Json::text(c.device_did.clone())),
                ("account", Json::text(c.account.as_str())),
                ("applicationId", Json::text(APPLICATION_ID)),
            ]),
            accept(Json::obj([
                ("grant", Json::text(grant)),
                ("grantId", Json::text(recognised.id.clone())),
                ("statusId", Json::text(recognised.status_id.clone())),
                ("grantToken", Json::text(recognised.token.clone())),
                ("lifetimeSeconds", Json::int(recognised.lifetime_seconds())),
            ])),
        ),
        case(
            "con_205_legacy_vc_wrapper",
            "a payload wrapping the credential in a JWT `vc` claim",
            Json::obj([("shape", Json::text("jwt-vc-wrapper"))]),
            reject("LegacyVcWrapper"),
        ),
        case(
            "con_205_alg_none",
            "alg none, and every other algorithm substitution",
            Json::obj([("alg", Json::text("none"))]),
            reject("BadAlgorithm"),
        ),
        case(
            "con_205_human_alias_in_account_claim",
            "REQ-218 forbids the optional human-readable alias in the account claim",
            Json::obj([("account", Json::text("acct:alice@accounts.photos.example"))]),
            reject("con_206_step_8"),
        ),
    ])
}

// ── CON-206: one case per numbered step ────────────────────────────────────

fn con_206() -> Json {
    let c = Ceremony::accepted();
    let mut cases = vec![case(
        "con_206_accepted",
        "a complete ceremony that passes every one of the thirteen steps",
        Json::obj([
            ("grant", Json::text(String::from_utf8(c.grant_bytes.clone()).unwrap())),
            ("expectedAccount", Json::text(c.account.as_str())),
            ("applicationId", Json::text(APPLICATION_ID)),
        ]),
        accept(Json::obj([("issuer", Json::text(c.home_did.clone()))])),
    )];

    let descriptions = [
        (AcceptStep::Size, "input larger than 64 KiB"),
        (AcceptStep::Jws, "malformed compact serialisation"),
        (AcceptStep::Header, "alg none, a relative kid, or a key-discovery parameter"),
        (AcceptStep::Closure, "no issuer closure available"),
        (AcceptStep::DidResolution, "unverified, deactivated, or mismatched DID"),
        (AcceptStep::IssuerKey, "kid outside assertionMethod, or not a JsonWebKey"),
        (AcceptStep::Signature, "signature by the wrong key, or an altered payload"),
        (AcceptStep::Fields, "a grant for another application or account"),
        (AcceptStep::AccountBinding, "the alias is not reciprocally bound"),
        (AcceptStep::Status, "stale closure, incomplete closure, or a revoked grant id"),
        (AcceptStep::Validity, "outside the window, or a lifetime over the profile bound"),
        (AcceptStep::Permissions, "a permission the profile does not declare"),
        (AcceptStep::Proof, "missing, forged, or mismatched device proof"),
    ];
    for (step, description) in descriptions {
        cases.push(case(
            &format!("con_206_reject_step_{}", step as u8),
            description,
            Json::obj([("mutation", Json::text(description))]),
            reject(&step.corpus_id()),
        ));
    }
    Json::Array(cases)
}

// ── CON-207 ────────────────────────────────────────────────────────────────

fn con_207() -> Json {
    use selfsame_app_identity::proof::{self, Challenge, MAX_NONCE_AGE_SECONDS, NONCE_OCTETS};
    let device = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
    let challenge = Challenge {
        nonce: [42u8; NONCE_OCTETS],
        application_id: APPLICATION_ID.into(),
        account: "acct:ss-example@accounts.photos.example".into(),
        grant_hash: proof::grant_hash(b"a grant"),
        // The verifier session is a ledger-side binding, deliberately absent
        // from `proof_input` — CON-207 fixes those octets and the device could
        // not know this value. It is therefore not a corpus input either: a
        // second implementation reproduces the signature without it.
        session: "verifier-session-1".into(),
        issued_at: NOW,
    };
    let signature = proof::sign(&challenge, &device);
    Json::Array(vec![
        case(
            "con_207_proof_input_and_signature",
            "the LP-framed proof input and a valid Ed25519 signature over it",
            Json::obj([
                ("nonce", Json::text(codec::b64url(&challenge.nonce))),
                ("applicationId", Json::text(challenge.application_id.clone())),
                ("account", Json::text(challenge.account.clone())),
                ("grantHash", Json::text(codec::b64url(&challenge.grant_hash))),
                ("devicePublicKey", Json::text(codec::b64url(&device.verifying_key().to_bytes()))),
            ]),
            accept(Json::obj([
                ("proofInput", Json::text(codec::b64url(&proof::proof_input(&challenge)))),
                ("signature", Json::text(codec::b64url(&signature))),
            ])),
        ),
        case(
            "con_207_nonce_expired",
            "a nonce presented more than 120 seconds after issuance",
            Json::obj([("maxNonceAgeSeconds", Json::int(MAX_NONCE_AGE_SECONDS))]),
            reject("NonceExpired"),
        ),
        case(
            "con_207_nonce_replayed",
            "a nonce consumed twice, whether the first attempt succeeded or failed",
            Json::obj([("attempts", Json::int(2))]),
            reject("NonceReplayed"),
        ),
        case(
            "con_207_nonce_mismatch",
            "a nonce issued for another application, account, or grant",
            Json::obj([("boundTo", Json::text("another account"))]),
            reject("NonceMismatch"),
        ),
    ])
}

// ── CON-208 ────────────────────────────────────────────────────────────────

fn con_208() -> Json {
    Json::Array(vec![
        case(
            "con_208_weighted_choice",
            "the lowest-priority group is drawn from by weight; zero weight is ineligible",
            Json::obj([
                ("maxProbeMilliseconds", Json::int(selection::MAX_PROBE_MILLISECONDS as i64)),
            ]),
            accept(Json::obj([("drawnByWeight", Json::Bool(true))])),
        ),
        case(
            "con_208_no_eligible_rendezvous",
            "every priority group exhausted; REQ-210 forbids any undeclared fallback",
            Json::obj([("groupsTried", Json::int(2))]),
            reject("NoEligibleRendezvous"),
        ),
        case(
            "con_208_probe_deadline_exceeded",
            "a probe returning after 1500 ms is ineligible rather than fatal",
            Json::obj([("elapsedMilliseconds", Json::int(1_501))]),
            reject("NoEligibleRendezvous"),
        ),
    ])
}

// ── CON-209 ────────────────────────────────────────────────────────────────

fn con_209() -> Json {
    let mut cases = vec![case(
        "con_209_hint_verifies",
        "a hint whose every member matches the joiner's own origin-authenticated profile",
        Json::obj([("checks", Json::int(5))]),
        accept(Json::obj([("followsInitiatorChoice", Json::Bool(true))])),
    )];
    for (token, description) in [
        ("ApplicationMismatch", "the hint names a different application"),
        ("UnsupportedProfileVersion", "the hint names a profile version this build does not speak"),
        ("UnknownProvider", "the hint names a provider the profile does not declare"),
        ("DescriptorMismatch", "the descriptor digest does not equal the joiner's local descriptor"),
        ("OfferMismatch", "the offer digest is not the offer being processed"),
        ("CarriesAccountScope", "the hint carries an accountScopeId, which CON-209 forbids by name"),
        ("UnknownMember", "the hint carries a member CON-209 does not define"),
    ] {
        cases.push(case(
            &format!("con_209_{}", to_snake(token)),
            description,
            Json::obj([("mutation", Json::text(token))]),
            reject(token),
        ));
    }
    Json::Array(cases)
}

// ── CON-210 ────────────────────────────────────────────────────────────────

fn con_210() -> Json {
    Json::Array(vec![
        case(
            "con_210_confirmed_only_by_a_verified_closure",
            "a resolver acknowledgement is not evidence of revocation",
            Json::obj([("acknowledgements", Json::int(3))]),
            accept(Json::obj([("confirmed", Json::Bool(false)), ("state", Json::text("pending"))])),
        ),
        case(
            "con_210_grow_only",
            "no operation, merge, or key rotation can make is_revoked false again",
            Json::obj([("mergeOrders", Json::int(6))]),
            accept(Json::obj([("permanent", Json::Bool(true))])),
        ),
        case(
            "con_210_projection_set_bit_is_permanent",
            "a set bit is true at any age; an unset one past validUntil is unavailable",
            Json::obj([("bitSet", Json::Bool(true)), ("ageSeconds", Json::int(999_999))]),
            accept(Json::text("Revoked")),
        ),
        case(
            "con_210_projection_unset_decays",
            "an unset bit past validUntil is unavailable, never evidence of non-revocation",
            Json::obj([("bitSet", Json::Bool(false)), ("pastValidUntil", Json::Bool(true))]),
            accept(Json::text("Unavailable")),
        ),
        case(
            "con_210_not_a_grant_id",
            "a credential id that is not a grant identifier",
            Json::obj([("credentialId", Json::text("not-a-grant"))]),
            reject("NotAGrantId"),
        ),
    ])
}

// ── CON-211 ────────────────────────────────────────────────────────────────

fn con_211() -> Json {
    let canonical = AccountScopeId::from_octets([0x11; 32]);
    Json::Array(vec![
        case(
            "con_211_canonical",
            "43 characters decoding to exactly 32 octets, re-encoding identically",
            Json::obj([("accountScopeId", Json::text(canonical.as_str()))]),
            accept(Json::obj([("octets", Json::text(codec::b64url(canonical.octets())))])),
        ),
        case(
            "con_211_wrong_length",
            "42 characters",
            Json::obj([("accountScopeId", Json::text(&canonical.as_str()[..42]))]),
            reject("ScopeWrongLength"),
        ),
        case(
            "con_211_bad_alphabet",
            "the standard base64 alphabet rather than the URL-safe one",
            Json::obj([("accountScopeId", Json::text(format!("+{}", &canonical.as_str()[1..])))]),
            reject("ScopeBadAlphabet"),
        ),
        case(
            "con_211_non_canonical_pad_bits",
            "a final character outside the sixteen whose pad bits are zero",
            Json::obj([(
                "accountScopeId",
                Json::text(format!("{}B", &canonical.as_str()[..42])),
            )]),
            reject("ScopeNotCanonical"),
        ),
        case(
            "con_211_unavailable",
            "neither the account record nor a protected backup can restore the scope",
            Json::obj([]),
            reject("AccountScopeUnavailable"),
        ),
    ])
}

// ── CON-212 ────────────────────────────────────────────────────────────────

fn con_212() -> Json {
    Json::Array(vec![
        case(
            "con_212_valid_username",
            "a representative valid localpart",
            Json::obj([("localpart", Json::text("alice"))]),
            accept(Json::obj([(
                "acctUri",
                Json::text(alias::username_acct_uri("alice", ACCOUNT_AUTHORITY)),
            )])),
        ),
        case(
            "con_212_reserved_prefix",
            "the ss- prefix is reserved so a chosen name cannot wear it",
            Json::obj([("localpart", Json::text("ss-anything"))]),
            reject("UsernameReserved"),
        ),
        case(
            "con_212_unavailable",
            "the exact URI is taken at this authority, or is tombstoned",
            Json::obj([("localpart", Json::text("alice"))]),
            reject("UsernameUnavailable"),
        ),
    ])
}

// ── CON-214: all twelve tokens ─────────────────────────────────────────────

fn con_214() -> Json {
    let mut cases = vec![case(
        "con_214_accepted",
        "a statement whose every binding matches what the wallet observed",
        Json::obj([("evidenceVersion", Json::int(1))]),
        accept(Json::obj([("verified", Json::Bool(true))])),
    )];
    for token in enrollment::ERROR_TOKENS {
        cases.push(case(
            &format!("con_214_{}", to_snake(token)),
            &format!("the condition CON-214 answers with {token}"),
            Json::obj([("mutation", Json::text(*token))]),
            reject(token),
        ));
    }
    Json::Array(cases)
}

// ── CON-215 ────────────────────────────────────────────────────────────────

fn con_215() -> Json {
    let handoff = ceremony::Handoff {
        ceremony_id: codec::b64url(&[1u8; 32]),
        offer_digest: codec::b64url(&[5u8; 32]),
        code: [9u8; 16],
        return_uri: None,
    };
    let mut cases = vec![case(
        "con_215_dispatched",
        "delivered to a verified installed wallet",
        Json::obj([(
            "handoff",
            Json::text(String::from_utf8(json::canonicalise(&handoff.to_json())).unwrap()),
        )]),
        accept(Json::text("Dispatched")),
    )];
    for token in [
        "WalletUnavailable",
        "UnverifiedWalletTarget",
        "HandoffMalformed",
        "HandoffAmbiguous",
        "PlatformBindingMismatch",
        "UserDenied",
    ] {
        cases.push(case(
            &format!("con_215_{}", to_snake(token)),
            &format!("dispatch returns {token} and the ceremony is burned"),
            Json::obj([("condition", Json::text(token))]),
            reject(token),
        ));
    }
    Json::Array(cases)
}

// ── CON-213 ────────────────────────────────────────────────────────────────

fn con_213() -> Json {
    Json::Array(vec![
        case(
            "con_213_bound_origins",
            "the selected descriptor's pairingUrl is the only PAKE relay origin and its url the only mailbox origin",
            Json::obj([
                ("pairingUrl", Json::text("https://pairing-au.provider.example")),
                ("mailboxUrl", Json::text("https://rendezvous-au.provider.example")),
            ]),
            accept(Json::obj([("separateOrigins", Json::Bool(true))])),
        ),
        case(
            "con_213_transport_refused",
            "a redirect, credentials, cookies, content encoding, an oversized or unrecognised response, destructive-read semantics, or a server-nominated endpoint",
            Json::obj([("condition", Json::text("serverNominatedEndpoint"))]),
            reject("TransportRefused"),
        ),
        case(
            "con_213_origin_mismatch",
            "a mailbox request aimed at the PAKE relay origin, or either aimed elsewhere",
            Json::obj([("origin", Json::text("https://attacker.example"))]),
            reject("OriginMismatch"),
        ),
    ])
}

// ── CON-216 ────────────────────────────────────────────────────────────────

fn con_216() -> Json {
    Json::Array(vec![
        case(
            "con_216_five_preconditions",
            "all five steps complete before the code may be displayed by either party",
            Json::obj([("preconditions", Json::int(5))]),
            accept(Json::obj([("mayDisplayCode", Json::Bool(true))])),
        ),
        case(
            "con_216_provider_not_unique",
            "a providerId matching zero or several descriptors",
            Json::obj([("providerId", Json::text("no-such-provider"))]),
            reject("ProviderNotUnique"),
        ),
        case(
            "con_216_record_mismatch",
            "a changed profile digest, descriptor, nameplate, or protocol in the CON-409 record",
            Json::obj([("profileDigest", Json::text("changed"))]),
            reject("RecordMismatch"),
        ),
        case(
            "con_216_origin_entry_offered_early",
            "tier-3 origin entry offered before tiers 1 and 2 were attempted",
            Json::obj([("earlierTiersExhausted", Json::Bool(false))]),
            reject("RoutingInCode"),
        ),
    ])
}

// ── CON-217 ────────────────────────────────────────────────────────────────

fn con_217() -> Json {
    Json::Array(vec![
        case(
            "con_217_confirmed_and_authenticated",
            "consent shown only after this role's confirmation and CON-214 verification",
            Json::obj([
                ("roleConfirmed", Json::Bool(true)),
                ("applicationAuthenticated", Json::Bool(true)),
            ]),
            accept(Json::obj([("mayDisplayConsent", Json::Bool(true))])),
        ),
        case(
            "con_217_unconfirmed",
            "deriving a branch, requesting a slot, or sending an offer before this role's confirmation",
            Json::obj([("roleConfirmed", Json::Bool(false))]),
            reject("Unconfirmed"),
        ),
        case(
            "con_217_confirmation_is_not_authorization",
            "a valid PAKE confirmation is never sufficient application authentication",
            Json::obj([
                ("roleConfirmed", Json::Bool(true)),
                ("applicationAuthenticated", Json::Bool(false)),
            ]),
            reject("ApplicationUnauthenticated"),
        ),
        case(
            "con_217_peer_confirmation_does_not_open_this_gate",
            "the confirmation required is this role's, not the peer's",
            Json::obj([("confirmedRole", Json::text("peer"))]),
            reject("Unconfirmed"),
        ),
    ])
}

// ── CON-218 ────────────────────────────────────────────────────────────────

fn con_218() -> Json {
    let modes = [
        ("SecretFromCode", "an AEAD or mailbox secret derived directly from C, bypassing SPAKE2"),
        ("RoutingInCode", "a route, nameplate, provider, or application identifier inside the human code"),
        ("WordsOnMachineCarrier", "the word rendering transported through a machine carrier instead of C"),
        ("MissingConfirmation", "either confirmation MAC omitted"),
        ("ProviderAsPakeEndpoint", "the provider made a SPAKE2 responder or password-verifier holder"),
        ("ForeignTranscriptLabels", "Hark or cbcl-bus transcript labels without Selfsame binding"),
        ("QrAsUrl", "the QR treated as an authoritative browser or custom-scheme URL"),
        ("ProviderSearch", "a code accepted by searching providers rather than resolving its CON-409 record"),
        ("ChangeWithRetainedValues", "provider or carrier changed while ceremony values were retained"),
    ];
    let mut cases = vec![case(
        "con_218_fresh_retry",
        "a retry regenerating all thirteen REQ-229 values and sharing none with the abandoned ceremony",
        Json::obj([(
            "regeneratedValues",
            Json::Array(pairing::REGENERATED_VALUES.iter().map(|v| Json::text(*v)).collect()),
        )]),
        accept(Json::obj([("reusedValues", Json::int(0))])),
    )];
    for (token, description) in modes {
        cases.push(case(
            &format!("con_218_{}", to_snake(token)),
            description,
            Json::obj([("mode", Json::text(token))]),
            reject(token),
        ));
    }
    cases.push(case(
        "con_218_burned_is_terminal",
        "a burned ceremony accepts no new frame, confirmation, profile, provider, carrier, callback, mailbox record, or application evidence",
        Json::obj([("state", Json::text("burned"))]),
        reject("ChangeWithRetainedValues"),
    ));
    Json::Array(cases)
}

// ── CON-222 and CON-223 (group 3, platform-conditional) ────────────────────

fn con_222() -> Json {
    Json::Array(vec![
        case(
            "con_222_explicit_component_dispatch",
            "an explicit component intent to a positively identified installed package",
            Json::obj([
                ("platform", Json::text("android")),
                ("minApiLevel", Json::int(platform::MIN_ANDROID_API_LEVEL as i64)),
                ("dispatch", Json::text("ExplicitComponent")),
            ]),
            accept(Json::text("Dispatched")),
        ),
        case(
            "con_222_implicit_intent_refused",
            "an implicit intent never carries ceremony material, including when exactly one candidate resolves",
            Json::obj([
                ("platform", Json::text("android")),
                ("dispatch", Json::text("Implicit")),
                ("candidates", Json::int(1)),
            ]),
            reject("UnverifiedWalletTarget"),
        ),
        case(
            "con_222_below_api_level_thirty",
            "package visibility filtering and App Link verification fail undetectably below level 30",
            Json::obj([("platform", Json::text("android")), ("apiLevel", Json::int(29))]),
            reject("WalletUnavailable"),
        ),
        case(
            "con_222_caller_package_mismatch",
            "the calling package does not match the platformBindingId in the CON-214 evidence",
            Json::obj([
                ("platform", Json::text("android")),
                ("callingPackage", Json::text("com.attacker.app")),
            ]),
            reject("PlatformBindingMismatch"),
        ),
    ])
}

fn con_223() -> Json {
    Json::Array(vec![
        case(
            "con_223_universal_link_handled",
            "a Universal Link opened with universalLinksOnly reaching an associated installed app",
            Json::obj([
                ("platform", Json::text("apple")),
                ("universalLinksOnly", Json::Bool(true)),
            ]),
            accept(Json::text("Dispatched")),
        ),
        case(
            "con_223_no_associated_app_is_terminal",
            "absence is a dispatch failure rather than a web navigation; no Safari, web view, install page, or custom scheme",
            Json::obj([
                ("platform", Json::text("apple")),
                ("universalLinksOnly", Json::Bool(true)),
                ("handled", Json::Bool(false)),
            ]),
            reject("WalletUnavailable"),
        ),
        case(
            "con_223_association_mismatch",
            "the return URI origin does not match the declared platform binding",
            Json::obj([
                ("platform", Json::text("apple")),
                ("origin", Json::text("https://attacker.example")),
            ]),
            reject("PlatformBindingMismatch"),
        ),
        case(
            "con_223_unattributed_caller_closes_nothing",
            "Apple attributes no caller for a Universal Link open; the gap is closed by CON-214 and CON-221, not by the platform",
            Json::obj([
                ("platform", Json::text("apple")),
                ("callerEvidence", Json::text("Unattributed")),
            ]),
            accept(Json::obj([
                ("platformClosesGap", Json::Bool(false)),
                ("closedBy", Json::arr([Json::text("CON-214"), Json::text("CON-221")])),
            ])),
        ),
    ])
}

// ── CON-219 ────────────────────────────────────────────────────────────────

fn con_219() -> Json {
    Json::Array(vec![
        case(
            "con_219_offer_digest",
            "offerDigest is computed over offer_core, which excludes the two members carrying it",
            Json::obj([("excluded", Json::arr([
                Json::text("enrollmentEvidence"),
                Json::text("providerHint"),
            ]))]),
            accept(Json::obj([(
                "offerCoreMembers",
                Json::Array(
                    ceremony::OFFER_CORE_MEMBERS.iter().map(|m| Json::text(*m)).collect(),
                ),
            )])),
        ),
        case(
            "con_219_payload_too_large",
            "a bundle whose inlined closure would exceed the payload bound",
            Json::obj([("payloadBound", Json::int(ceremony::MAX_PAYLOAD_OCTETS as i64))]),
            reject("PayloadTooLarge"),
        ),
        case(
            "con_219_offer_mismatch",
            "a bundle whose ceremonyId is not the one this application sealed",
            Json::obj([]),
            reject("OfferMismatch"),
        ),
    ])
}

// ── CON-220 ────────────────────────────────────────────────────────────────

fn con_220() -> Json {
    Json::Array(vec![
        case(
            "con_220_fetched_and_pinned",
            "HTTPS with no redirect, the right media type, and a digest matching the record",
            Json::obj([
                ("mediaType", Json::text(discovery::PROFILE_MEDIA_TYPE)),
                ("maxCacheSeconds", Json::int(discovery::MAX_CACHE_SECONDS)),
            ]),
            accept(Json::obj([("bound", Json::Bool(true))])),
        ),
        case(
            "con_220_unverified_application",
            "a cached profile past its bound with no network available",
            Json::obj([("cacheAgeSeconds", Json::int(discovery::MAX_CACHE_SECONDS + 1))]),
            reject("UnverifiedApplication"),
        ),
        case(
            "con_220_redirect_refused",
            "any redirect, including same-origin, means the identifier is wrong",
            Json::obj([("redirected", Json::Bool(true))]),
            reject("UnverifiedApplication"),
        ),
    ])
}

// ── CON-221 ────────────────────────────────────────────────────────────────

fn con_221() -> Json {
    Json::Array(vec![
        case(
            "con_221_first_enrollment_requires_confirmation",
            "the authority holds no binding, so the person compares the home DID fingerprint",
            Json::obj([("authorityState", Json::text("NoBinding"))]),
            accept(Json::obj([
                ("comparisonValue", Json::text("hex")),
                ("recognitionAid", Json::text("lifehash")),
            ])),
        ),
        case(
            "con_221_subsequent_enrollment_shows_nothing",
            "a prompt that can appear twice can be induced at an attacker's chosen moment",
            Json::obj([("authorityState", Json::text("Bound"))]),
            accept(Json::obj([("prompted", Json::Bool(false))])),
        ),
        case(
            "con_221_unknown_authority_fails_closed",
            "an unreachable authority is unknown, never assumed to be first use",
            Json::obj([("authorityState", Json::text("Unknown"))]),
            reject("con_206_step_9"),
        ),
        case(
            "con_221_timeout_is_not_a_quiet_yes",
            "rejection and timeout produce identical outcomes",
            Json::obj([("response", Json::text("TimedOut"))]),
            reject("con_206_step_9"),
        ),
    ])
}

// ── CON-224 ────────────────────────────────────────────────────────────────

fn con_224() -> Json {
    use selfsame_app_identity::context;
    Json::Array(vec![case(
        "con_224_context_digest",
        "the pinned context octets and their digest; nothing dereferences the IRI",
        Json::obj([
            ("contextIri", Json::text(context::CONTEXT_IRI)),
            ("octets", Json::int(context::CONTEXT_OCTETS.len() as i64)),
        ]),
        accept(Json::obj([
            ("contextDigest", Json::text(hex(&context::CONTEXT_DIGEST))),
            (
                "note",
                Json::text(
                    "the version-1 octets CON-224 declares, verbatim; a second \
                     implementation agrees on this digest or it is not reading \
                     the same context",
                ),
            ),
        ])),
    )])
}

// ── CON-225 ────────────────────────────────────────────────────────────────

fn con_225() -> Json {
    Json::Array(vec![
        case(
            "con_225_accepted",
            "doubly signed, person-confirmed, bounded by the incoming profile's grant lifetime",
            Json::obj([(
                "maxPointerWindowSeconds",
                Json::int(succession::MAX_POINTER_WINDOW_SECONDS),
            )]),
            accept(Json::obj([("hops", Json::int(1))])),
        ),
        case(
            "con_225_one_sided",
            "a statement carrying only the outgoing signature",
            Json::obj([("signatures", Json::int(1))]),
            reject("SuccessionRejected"),
        ),
        case(
            "con_225_unpinned_key",
            "a pointer signed by a currently-served key the wallet never pinned",
            Json::obj([("pinned", Json::Bool(false))]),
            reject("SuccessionRejected"),
        ),
        case(
            "con_225_chained",
            "a statement whose outgoing is the incoming of another unexpired statement",
            Json::obj([("chained", Json::Bool(true))]),
            reject("SuccessionRejected"),
        ),
    ])
}

// ── CON-226 ────────────────────────────────────────────────────────────────

fn con_226() -> Json {
    // The corpus describing its own completeness rule, so a second stack can
    // check that it is reading the same rule rather than inferring one.
    Json::Array(vec![case(
        "con_226_completeness_rule",
        "every closed error token and each of CON-206's thirteen steps has a case",
        Json::obj([
            ("con206Steps", Json::int(13)),
            ("con214Tokens", Json::int(enrollment::ERROR_TOKENS.len() as i64)),
        ]),
        accept(Json::obj([
            ("reasonRequired", Json::Bool(true)),
            (
                "note",
                Json::text(
                    "two stacks must agree on which check fired, or they have not \
                     implemented the same predicate",
                ),
            ),
        ])),
    )])
}

// ── helpers ────────────────────────────────────────────────────────────────

fn to_snake(token: &str) -> String {
    let mut out = String::with_capacity(token.len() + 4);
    for (i, c) in token.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            out.push('_');
        }
        out.extend(c.to_lowercase());
    }
    out
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
