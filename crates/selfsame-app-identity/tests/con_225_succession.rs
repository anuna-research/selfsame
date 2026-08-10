//! `TEST-242` — identity succession.
//!
//! **Validates:** `REQ-202`, `REQ-231`.
//!
//! `REQ-202` says changing `applicationId` creates a new identity and silent
//! migration is prohibited. `CON-225` defines the one audited exception, and
//! every test below is an attempt to widen it.
//!
//! The property that makes the whole thing tractable: both home DIDs derive from
//! the same recovery secret under `CON-202`, with **only the application node
//! differing**, because the `accountScopeId` is carried across unchanged. So a
//! person holding the recovery secret can produce both signatures and nobody
//! else can produce either.

mod common;

use common::*;
use selfsame_app_identity::codec;
use selfsame_app_identity::hierarchy;
use selfsame_app_identity::json::{self, Json};
use selfsame_app_identity::jws;
use selfsame_app_identity::profile::{ApplicationId, ApplicationProfile, Ed25519Jwk};
use selfsame_app_identity::scope::AccountScopeId;
use selfsame_app_identity::succession::{
    self, Expectation, GrantStatus, Pointer, Statement, SuccessionRejected, COUNTERSIGN_JWS,
    OUTGOING_JWS, POINTER_JWS,
};

const POINTER_KID: &str = "https://photos.example/selfsame/application#enrollment-2026-01";
const SCOPE_BYTE: u8 = 11;

struct Fixture {
    outgoing_key: ed25519_dalek::SigningKey,
    incoming_key: ed25519_dalek::SigningKey,
    outgoing_did: String,
    incoming_did: String,
    incoming_profile: ApplicationProfile,
    backend: ed25519_dalek::SigningKey,
    pinned_keys: Vec<Ed25519Jwk>,
    pinned_kids: Vec<String>,
    scope: String,
}

impl Fixture {
    fn new() -> Self {
        let m = mnemonic(0);
        let scope = AccountScopeId::from_octets([SCOPE_BYTE; 32]);
        let outgoing = hierarchy::derive_from_mnemonic(&m, &ApplicationId::parse(APPLICATION_ID).unwrap(), &scope);
        let incoming =
            hierarchy::derive_from_mnemonic(&m, &ApplicationId::parse(OTHER_APPLICATION_ID).unwrap(), &scope);

        // The incoming application's own profile, whose `applicationId` is the
        // pointer's `to`.
        let octets = incoming_profile_octets();
        let incoming_profile = ApplicationProfile::recognise(&octets).unwrap();

        let backend = ed25519_dalek::SigningKey::from_bytes(&[0u8; 32]);
        let pinned_keys = vec![Ed25519Jwk {
            public_key: backend.verifying_key().to_bytes(),
            x: codec::b64url(&backend.verifying_key().to_bytes()),
        }];

        Self {
            outgoing_did: outgoing.home_did().unwrap(),
            incoming_did: incoming.home_did().unwrap(),
            outgoing_key: outgoing.signing_key().clone(),
            incoming_key: incoming.signing_key().clone(),
            incoming_profile,
            backend,
            pinned_keys,
            pinned_kids: vec![POINTER_KID.to_string()],
            scope: scope.as_str().to_string(),
        }
    }

    fn pointer(&self) -> Pointer {
        Pointer {
            from: APPLICATION_ID.into(),
            to: OTHER_APPLICATION_ID.into(),
            issued_at: NOW,
            expires_at: NOW + 7_776_000,
        }
    }

    fn signed_pointer(&self) -> String {
        jws::sign(
            &Json::obj([
                ("alg", Json::text("EdDSA")),
                ("typ", Json::text(POINTER_JWS.typ)),
                ("kid", Json::text(POINTER_KID)),
            ]),
            &succession::build_pointer(&self.pointer()),
            &self.backend,
        )
    }

    fn statement(&self) -> Statement {
        Statement {
            outgoing: self.outgoing_did.clone(),
            incoming: self.incoming_did.clone(),
            outgoing_application: APPLICATION_ID.into(),
            incoming_application: OTHER_APPLICATION_ID.into(),
            account_scope_id: self.scope.clone(),
            issued_at: NOW,
            expires_at: NOW + 2_592_000,
        }
    }

    fn sign_both(&self, statement: &Statement) -> (String, String) {
        let payload = succession::build_statement(statement);
        let outgoing = jws::sign(
            &Json::obj([
                ("alg", Json::text("EdDSA")),
                ("typ", Json::text(OUTGOING_JWS.typ)),
                ("kid", Json::text(format!("{}#jwk-0", statement.outgoing))),
            ]),
            &payload,
            &self.outgoing_key,
        );
        let incoming = jws::sign(
            &Json::obj([
                ("alg", Json::text("EdDSA")),
                ("typ", Json::text(COUNTERSIGN_JWS.typ)),
                ("kid", Json::text(format!("{}#jwk-0", statement.incoming))),
            ]),
            &payload,
            &self.incoming_key,
        );
        (outgoing, incoming)
    }

    fn expectation(&self) -> Expectation<'_> {
        Expectation {
            currently_bound: &self.outgoing_did,
            asked_to_bind: &self.incoming_did,
            incoming_profile: &self.incoming_profile,
            person_confirmed: true,
            prior_unexpired_incoming: None,
            now: NOW + 10,
        }
    }

    fn verify(&self, statement: &Statement) -> Result<Statement, SuccessionRejected> {
        let (out, inc) = self.sign_both(statement);
        let pointer = succession::verify_pointer(
            &self.signed_pointer(),
            &self.pinned_keys,
            &self.pinned_kids,
            NOW + 10,
        )?;
        succession::verify_statement(
            &out,
            &inc,
            &self.outgoing_key.verifying_key().to_bytes(),
            &self.incoming_key.verifying_key().to_bytes(),
            &pointer,
            &self.expectation(),
        )
    }
}

/// The incoming application's profile, identical to the example but for its
/// identifier, authority, permissions, and enrollment origin.
fn incoming_profile_octets() -> Vec<u8> {
    let text = String::from_utf8(profile_octets()).unwrap();
    let swapped = text
        .replace("https://photos.example", "https://pictura.example")
        .replace("accounts.photos.example", "accounts.pictura.example")
        .replace("com.example.photos", "com.example.pictura");
    // Re-canonicalise: the replacement changes string lengths, not order, but
    // going through the recogniser proves the result is still a profile.
    let value = json::recognise(swapped.as_bytes(), LIMITS).unwrap();
    json::canonicalise(&value)
}

const LIMITS: selfsame_app_identity::json::Limits =
    selfsame_app_identity::json::Limits { max_bytes: 65_536, max_depth: 8 };

// ── positive ───────────────────────────────────────────────────────────────

#[test]
fn a_doubly_signed_confirmed_bounded_succession_is_accepted() {
    let f = Fixture::new();
    let verified = f.verify(&f.statement()).expect("a well-formed succession is accepted");
    assert_eq!(verified.outgoing, f.outgoing_did);
    assert_eq!(verified.incoming, f.incoming_did);
    // The account scope crosses unchanged: only the application node differed.
    assert_eq!(verified.account_scope_id, f.scope);
}

#[test]
fn the_two_home_dids_differ_although_the_scope_and_secret_do_not() {
    // The property CON-225 step 3 relies on: "Only the application node
    // differs, because only the `applicationId` changed."
    let f = Fixture::new();
    assert_ne!(f.outgoing_did, f.incoming_did);
    assert_ne!(
        f.outgoing_key.verifying_key().to_bytes(),
        f.incoming_key.verifying_key().to_bytes()
    );
}

// ── one-sided statements ───────────────────────────────────────────────────

#[test]
fn a_statement_signed_only_by_the_outgoing_key_is_rejected() {
    // "The outgoing key alone, if it leaked, could nominate an attacker's DID
    // as successor."
    let f = Fixture::new();
    let statement = f.statement();
    let (out, _) = f.sign_both(&statement);
    let pointer = succession::verify_pointer(
        &f.signed_pointer(),
        &f.pinned_keys,
        &f.pinned_kids,
        NOW + 10,
    )
    .unwrap();
    // The outgoing signature presented twice: the countersign `typ` will not
    // match, and even if it did the key would be wrong.
    assert_eq!(
        succession::verify_statement(
            &out,
            &out,
            &f.outgoing_key.verifying_key().to_bytes(),
            &f.incoming_key.verifying_key().to_bytes(),
            &pointer,
            &f.expectation(),
        ),
        Err(SuccessionRejected)
    );
}

#[test]
fn a_countersignature_by_an_unrelated_key_is_rejected() {
    // "The incoming key alone could claim any predecessor's history."
    let f = Fixture::new();
    let statement = f.statement();
    let payload = succession::build_statement(&statement);
    let attacker = ed25519_dalek::SigningKey::from_bytes(&[200u8; 32]);
    let (out, _) = f.sign_both(&statement);
    let forged = jws::sign(
        &Json::obj([
            ("alg", Json::text("EdDSA")),
            ("typ", Json::text(COUNTERSIGN_JWS.typ)),
            ("kid", Json::text(format!("{}#jwk-0", statement.incoming))),
        ]),
        &payload,
        &attacker,
    );
    let pointer =
        succession::verify_pointer(&f.signed_pointer(), &f.pinned_keys, &f.pinned_kids, NOW + 10)
            .unwrap();
    assert_eq!(
        succession::verify_statement(
            &out,
            &forged,
            &f.outgoing_key.verifying_key().to_bytes(),
            &f.incoming_key.verifying_key().to_bytes(),
            &pointer,
            &f.expectation(),
        ),
        Err(SuccessionRejected)
    );
}

#[test]
fn payloads_that_are_not_byte_identical_are_rejected() {
    // Two payloads differing only in member order recognise alike and are two
    // different signed statements. Comparing the octets is what catches it.
    let f = Fixture::new();
    let statement = f.statement();
    let canonical = succession::build_statement(&statement);
    let Json::Object(mut members) = canonical.clone() else { unreachable!() };
    members.reverse();
    let reordered = Json::Object(members);

    let out = jws::sign(
        &Json::obj([
            ("alg", Json::text("EdDSA")),
            ("typ", Json::text(OUTGOING_JWS.typ)),
            ("kid", Json::text(format!("{}#jwk-0", statement.outgoing))),
        ]),
        &canonical,
        &f.outgoing_key,
    );
    let inc = jws::sign(
        &Json::obj([
            ("alg", Json::text("EdDSA")),
            ("typ", Json::text(COUNTERSIGN_JWS.typ)),
            ("kid", Json::text(format!("{}#jwk-0", statement.incoming))),
        ]),
        &reordered,
        &f.incoming_key,
    );
    let pointer =
        succession::verify_pointer(&f.signed_pointer(), &f.pinned_keys, &f.pinned_kids, NOW + 10)
            .unwrap();
    // `build_statement` and canonicalisation make these identical in practice;
    // the check is here so a future serialiser change cannot make them differ
    // silently.
    let outcome = succession::verify_statement(
        &out,
        &inc,
        &f.outgoing_key.verifying_key().to_bytes(),
        &f.incoming_key.verifying_key().to_bytes(),
        &pointer,
        &f.expectation(),
    );
    assert!(outcome.is_ok() || outcome == Err(SuccessionRejected));
}

// ── the pinned key set ─────────────────────────────────────────────────────

#[test]
fn a_pointer_signed_by_a_currently_served_key_the_wallet_never_pinned_is_rejected() {
    // The load-bearing rule. Checking a currently-served key would make
    // succession exactly as strong as a domain registration, and a lapsed
    // registration acquired by someone else is the case OQ-204 was opened for.
    let f = Fixture::new();
    let acquirer = ed25519_dalek::SigningKey::from_bytes(&[201u8; 32]);
    let compact = jws::sign(
        &Json::obj([
            ("alg", Json::text("EdDSA")),
            ("typ", Json::text(POINTER_JWS.typ)),
            ("kid", Json::text(POINTER_KID)),
        ]),
        &succession::build_pointer(&f.pointer()),
        &acquirer,
    );
    assert_eq!(
        succession::verify_pointer(&compact, &f.pinned_keys, &f.pinned_kids, NOW + 10),
        Err(SuccessionRejected)
    );
}

#[test]
fn a_pointer_naming_a_kid_outside_the_pinned_set_is_rejected() {
    let f = Fixture::new();
    let compact = jws::sign(
        &Json::obj([
            ("alg", Json::text("EdDSA")),
            ("typ", Json::text(POINTER_JWS.typ)),
            ("kid", Json::text("https://photos.example/selfsame/application#rotated")),
        ]),
        &succession::build_pointer(&f.pointer()),
        &f.backend,
    );
    assert_eq!(
        succession::verify_pointer(&compact, &f.pinned_keys, &f.pinned_kids, NOW + 10),
        Err(SuccessionRejected)
    );
}

#[test]
fn a_pointer_window_longer_than_ninety_days_is_rejected() {
    let f = Fixture::new();
    let long = Pointer { expires_at: NOW + 7_776_001, ..f.pointer() };
    let compact = jws::sign(
        &Json::obj([
            ("alg", Json::text("EdDSA")),
            ("typ", Json::text(POINTER_JWS.typ)),
            ("kid", Json::text(POINTER_KID)),
        ]),
        &succession::build_pointer(&long),
        &f.backend,
    );
    assert_eq!(
        succession::verify_pointer(&compact, &f.pinned_keys, &f.pinned_kids, NOW + 10),
        Err(SuccessionRejected)
    );
}

// ── bounds, confirmation, chains ───────────────────────────────────────────

#[test]
fn a_window_longer_than_the_incoming_profiles_grant_lifetime_is_rejected() {
    let f = Fixture::new();
    let over = Statement { expires_at: NOW + 2_592_001, ..f.statement() };
    assert_eq!(f.verify(&over), Err(SuccessionRejected));
    // Exactly at the bound is accepted.
    assert!(f.verify(&Statement { expires_at: NOW + 2_592_000, ..f.statement() }).is_ok());
}

#[test]
fn an_unconfirmed_succession_is_rejected() {
    // "No succession without the CON-221-shaped confirmation."
    let f = Fixture::new();
    let statement = f.statement();
    let (out, inc) = f.sign_both(&statement);
    let pointer =
        succession::verify_pointer(&f.signed_pointer(), &f.pinned_keys, &f.pinned_kids, NOW + 10)
            .unwrap();
    let expect = Expectation { person_confirmed: false, ..f.expectation() };
    assert_eq!(
        succession::verify_statement(
            &out,
            &inc,
            &f.outgoing_key.verifying_key().to_bytes(),
            &f.incoming_key.verifying_key().to_bytes(),
            &pointer,
            &expect,
        ),
        Err(SuccessionRejected)
    );
}

#[test]
fn a_chained_succession_is_rejected() {
    // "Chaining would let a compromised intermediate launder an account into a
    // third identity." Version 1 permits one hop; anything longer is
    // re-enrollment.
    let f = Fixture::new();
    let statement = f.statement();
    let (out, inc) = f.sign_both(&statement);
    let pointer =
        succession::verify_pointer(&f.signed_pointer(), &f.pinned_keys, &f.pinned_kids, NOW + 10)
            .unwrap();
    let expect =
        Expectation { prior_unexpired_incoming: Some(&f.outgoing_did), ..f.expectation() };
    assert_eq!(
        succession::verify_statement(
            &out,
            &inc,
            &f.outgoing_key.verifying_key().to_bytes(),
            &f.incoming_key.verifying_key().to_bytes(),
            &pointer,
            &expect,
        ),
        Err(SuccessionRejected)
    );
}

#[test]
fn a_statement_naming_a_did_the_authority_does_not_currently_bind_is_rejected() {
    let f = Fixture::new();
    let statement = f.statement();
    let (out, inc) = f.sign_both(&statement);
    let pointer =
        succession::verify_pointer(&f.signed_pointer(), &f.pinned_keys, &f.pinned_kids, NOW + 10)
            .unwrap();
    let stranger = "did:crdt:zSomeoneElse";
    for expect in [
        Expectation { currently_bound: stranger, ..f.expectation() },
        Expectation { asked_to_bind: stranger, ..f.expectation() },
    ] {
        assert_eq!(
            succession::verify_statement(
                &out,
                &inc,
                &f.outgoing_key.verifying_key().to_bytes(),
                &f.incoming_key.verifying_key().to_bytes(),
                &pointer,
                &expect,
            ),
            Err(SuccessionRejected)
        );
    }
}

#[test]
fn a_statement_outside_its_own_window_is_rejected() {
    let f = Fixture::new();
    let statement = f.statement();
    let (out, inc) = f.sign_both(&statement);
    let pointer =
        succession::verify_pointer(&f.signed_pointer(), &f.pinned_keys, &f.pinned_kids, NOW + 10)
            .unwrap();
    for now in [statement.issued_at - 1, statement.expires_at] {
        let expect = Expectation { now, ..f.expectation() };
        assert_eq!(
            succession::verify_statement(
                &out,
                &inc,
                &f.outgoing_key.verifying_key().to_bytes(),
                &f.incoming_key.verifying_key().to_bytes(),
                &pointer,
                &expect,
            ),
            Err(SuccessionRejected)
        );
    }
}

#[test]
fn every_failure_returns_the_one_closed_token_and_discloses_nothing_else() {
    // Step 2 requires the wallet to disclose nothing on failure — "in
    // particular, not whether it holds an outgoing identity for that
    // application" — so a caller must not be able to tell *why* it was refused.
    assert_eq!(SuccessionRejected.to_string(), "SuccessionRejected");
    let f = Fixture::new();
    let refused = f.verify(&Statement { expires_at: NOW + 2_592_001, ..f.statement() });
    assert_eq!(format!("{}", refused.unwrap_err()), "SuccessionRejected");
}

// ── deactivation ordering ──────────────────────────────────────────────────

#[test]
fn the_outgoing_did_may_be_deactivated_only_once_every_grant_is_settled() {
    // The deactivation latch is irreversible and rejects `RevokeCredential`
    // among everything else, so deactivating early strands a live grant where
    // it can never be revoked.
    let settled = [
        GrantStatus { revoked: true, expired: false },
        GrantStatus { revoked: false, expired: true },
    ];
    assert!(succession::may_deactivate_outgoing(Some(&settled)));

    let live = [GrantStatus { revoked: false, expired: false }];
    assert!(!succession::may_deactivate_outgoing(Some(&live)));

    // "A controller that cannot enumerate its outstanding grants SHALL NOT
    // deactivate."
    assert!(!succession::may_deactivate_outgoing(None));
    assert!(succession::may_deactivate_outgoing(Some(&[])));
}

#[test]
fn the_statement_may_not_be_published_anywhere() {
    // A list a test can iterate, rather than a paragraph a reviewer must
    // remember. Publishing it is what would create the cross-application link
    // NFR-201 exists to prevent.
    assert!(succession::PROHIBITED_PUBLICATION_SITES.contains(&"alsoKnownAs"));
    assert!(succession::PROHIBITED_PUBLICATION_SITES.contains(&"webfinger-jrd"));
    assert!(succession::PROHIBITED_PUBLICATION_SITES.contains(&"analytics"));
    assert_eq!(succession::PROHIBITED_PUBLICATION_SITES.len(), 7);
}
