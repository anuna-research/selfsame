//! Shared fixtures, built from the examples printed in SPEC-004's contracts.
//!
//! Every fixture is assembled as a [`Json`] value and then serialised with RFC
//! 8785, so it is canonical **by construction**. Writing the fixtures as string
//! literals instead would make `CON-201` step 5 a test of the author's
//! typing — a stray space would fail the round-trip and say nothing about the
//! recogniser.
//!
//! To build a *non*-canonical or otherwise invalid document, mutate the value
//! and re-serialise, or edit the canonical octets directly. Both are done below.

#![allow(dead_code)]

use selfsame_app_identity::codec;
use selfsame_app_identity::json::{self, Json};

/// The `applicationId` used throughout, from `CON-201`'s example.
pub const APPLICATION_ID: &str = "https://photos.example/selfsame/application";
/// A second, unrelated application, from `CON-225`'s example.
pub const OTHER_APPLICATION_ID: &str = "https://pictura.example/selfsame/application";
/// The `accountAuthority` from `CON-201`'s example.
pub const ACCOUNT_AUTHORITY: &str = "accounts.photos.example";
/// The one permission the example profile allows.
pub const PERMISSION: &str = "https://photos.example/selfsame/application#device";

/// An Ed25519 public JWK in the one shape `CON-201` admits.
pub fn jwk(public_key: [u8; 32]) -> Json {
    Json::obj([
        ("kty", Json::text("OKP")),
        ("crv", Json::text("Ed25519")),
        ("x", Json::text(codec::b64url(&public_key))),
    ])
}

/// The example profile as a mutable value.
pub fn profile_value() -> Json {
    Json::obj([
        ("profileVersion", Json::int(1)),
        ("applicationId", Json::text(APPLICATION_ID)),
        ("accountAuthority", Json::text(ACCOUNT_AUTHORITY)),
        ("verifierAudience", Json::text(APPLICATION_ID)),
        ("allowedPermissions", Json::arr([Json::text(PERMISSION)])),
        (
            "enrollment",
            Json::obj([
                (
                    "requestSigningKeys",
                    Json::arr([Json::obj([
                        (
                            "kid",
                            Json::text(
                                "https://photos.example/selfsame/application#enrollment-2026-01",
                            ),
                        ),
                        ("publicKeyJwk", jwk([1u8; 32])),
                    ])]),
                ),
                (
                    "mobileBindings",
                    Json::arr([
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
                        ]),
                        Json::obj([
                            (
                                "id",
                                Json::text("apple:TEAM123456:com.example.photos:https://photos.example"),
                            ),
                            ("platform", Json::text("apple")),
                            ("teamId", Json::text("TEAM123456")),
                            ("bundleId", Json::text("com.example.photos")),
                            (
                                "returnUri",
                                Json::text("https://photos.example/.well-known/selfsame/return"),
                            ),
                        ]),
                    ]),
                ),
            ]),
        ),
        (
            "rendezvous",
            Json::arr([
                descriptor("au-primary", "rendezvous-au.provider.example", "pairing-au.provider.example", "03", 10, 80),
                descriptor("global-secondary", "rendezvous.example.net", "pairing.example.net", "17", 20, 20),
            ]),
        ),
        (
            "pairingRecordRelays",
            Json::arr([
                Json::text("https://records-au.provider.example"),
                Json::text("https://records.example.net"),
            ]),
        ),
        (
            "stateResolvers",
            Json::arr([
                resolver("app-own", "https://api.photos.example"),
                resolver("state-1", "https://state.provider.example"),
                resolver("anuna-public", "https://state.anuna.io"),
            ]),
        ),
        (
            "revocation",
            Json::obj([
                ("method", Json::text("did-crdt-revocations-v1")),
                ("maxGrantLifetimeSeconds", Json::int(2_592_000)),
                ("maxClosureAgeSeconds", Json::int(900)),
                ("propagationSlaSeconds", Json::int(60)),
                (
                    "projection",
                    Json::obj([
                        ("type", Json::text("BitstringStatusList")),
                        (
                            "allocationUrl",
                            Json::text("https://status-cache.provider.example/selfsame/v1/slots"),
                        ),
                        (
                            "credentialBaseUrl",
                            Json::text("https://status-cache.provider.example/selfsame/v1/lists/"),
                        ),
                        ("maxAgeSeconds", Json::int(900)),
                    ]),
                ),
            ]),
        ),
    ])
}

/// One rendezvous descriptor.
pub fn descriptor(
    id: &str,
    mailbox_host: &str,
    pairing_host: &str,
    route: &str,
    priority: i64,
    weight: i64,
) -> Json {
    Json::obj([
        ("id", Json::text(id)),
        ("url", Json::text(format!("https://{mailbox_host}"))),
        ("protocol", Json::text("selfsame-rendezvous-v1")),
        ("pairingUrl", Json::text(format!("https://{pairing_host}"))),
        ("pairingProtocol", Json::text("selfsame-pairing-v1")),
        ("pairingRoute", Json::text(route)),
        ("priority", Json::int(priority)),
        ("weight", Json::int(weight)),
        ("validUntil", Json::text("2027-07-30T00:00:00Z")),
    ])
}

/// One `did:crdt` state resolver.
pub fn resolver(id: &str, url: &str) -> Json {
    Json::obj([
        ("id", Json::text(id)),
        ("url", Json::text(url)),
        ("protocol", Json::text("did-crdt-service-v1")),
    ])
}

/// The example profile, serialised canonically.
pub fn profile_octets() -> Vec<u8> {
    json::canonicalise(&profile_value())
}

/// Replace one top-level member and re-serialise canonically.
pub fn with_member(name: &str, value: Json) -> Vec<u8> {
    let Json::Object(mut members) = profile_value() else { unreachable!() };
    match members.iter_mut().find(|(k, _)| k == name) {
        Some(slot) => slot.1 = value,
        None => members.push((name.to_string(), value)),
    }
    json::canonicalise(&Json::Object(members))
}

/// Remove one top-level member and re-serialise canonically.
pub fn without_member(name: &str) -> Vec<u8> {
    let Json::Object(members) = profile_value() else { unreachable!() };
    let kept: Vec<(String, Json)> = members.into_iter().filter(|(k, _)| k != name).collect();
    json::canonicalise(&Json::Object(kept))
}

/// Replace one member of a nested object, addressed by dotted path, and
/// re-serialise canonically.
pub fn with_nested(path: &str, value: Json) -> Vec<u8> {
    let mut root = profile_value();
    set_path(&mut root, &path.split('.').collect::<Vec<_>>(), value);
    json::canonicalise(&root)
}

fn set_path(node: &mut Json, path: &[&str], value: Json) {
    let Json::Object(members) = node else { panic!("path does not address an object") };
    let (head, rest) = path.split_first().expect("non-empty path");
    if rest.is_empty() {
        match members.iter_mut().find(|(k, _)| k == head) {
            Some(slot) => slot.1 = value,
            None => members.push((head.to_string(), value)),
        }
        return;
    }
    let child = members
        .iter_mut()
        .find(|(k, _)| k == head)
        .map(|(_, v)| v)
        .expect("path names an existing member");
    // An array step addresses element zero, which is all any fixture needs.
    if let Json::Array(items) = child {
        set_path(&mut items[0], rest, value);
    } else {
        set_path(child, rest, value);
    }
}

// ── a complete, accepted ceremony, for CON-206 and CON-207 ─────────────────

use selfsame_app_identity::accept::{
    ClosureSource, Evidence, Expectation, Freshness, IssuerState, VerificationMethod,
};
use selfsame_app_identity::alias::{self, AcctUri, Jrd};
use selfsame_app_identity::hierarchy::{self, Mnemonic};
use selfsame_app_identity::profile::{ApplicationId, ApplicationProfile, Ed25519Jwk};
use selfsame_app_identity::proof::{self, Challenge};
use selfsame_app_identity::scope::AccountScopeId;
use selfsame_app_identity::{didkey, grant};

/// Every value one accepted grant needs, so a test can mutate exactly one.
pub struct Ceremony {
    pub profile: ApplicationProfile,
    pub home_did: String,
    pub home_key: ed25519_dalek::SigningKey,
    pub account: AcctUri,
    pub device_key: ed25519_dalek::SigningKey,
    pub device_did: String,
    pub grant_bytes: Vec<u8>,
    pub issuer: IssuerState,
    pub jrd: Jrd,
    pub challenge: Challenge,
    pub signature: [u8; 64],
    pub now: i64,
}

/// The instant every fixture is built around: `2026-07-30T12:00:00Z`.
pub const NOW: i64 = 1_785_412_800;

pub fn mnemonic(entropy: u8) -> Mnemonic {
    Mnemonic::from_entropy_in(bip39::Language::English, &[entropy; 16])
        .expect("128 bits is a valid BIP-39 entropy length")
}

impl Ceremony {
    /// A ceremony that CON-206 accepts at every step.
    pub fn accepted() -> Self {
        Self::build(0, 1, 3, APPLICATION_ID)
    }

    pub fn build(
        entropy: u8,
        scope_byte: u8,
        device_seed: u8,
        application_id: &str,
    ) -> Self {
        let profile = ApplicationProfile::recognise(&profile_octets())
            .expect("the example profile is recognised");
        let app = ApplicationId::parse(application_id).expect("canonical");
        let scope = AccountScopeId::from_octets([scope_byte; 32]);
        let home = hierarchy::derive(&mnemonic(entropy), &app, &scope);
        let home_did = home.home_did().expect("did:crdt derivation");
        let home_key = home.signing_key().clone();

        let account = AcctUri::parse(&alias::stable_acct_uri(&home_did, ACCOUNT_AUTHORITY))
            .expect("the generated alias is well formed");

        let device_key = ed25519_dalek::SigningKey::from_bytes(&[device_seed; 32]);
        let device_public = device_key.verifying_key().to_bytes();
        let device_did = didkey::encode(&device_public);

        let valid_from = NOW - 3_600;
        let valid_until = valid_from + 2_592_000;
        let grant_bytes = grant::issue(
            &home_key,
            &home_did,
            &[device_seed.wrapping_add(9); 32],
            &device_did,
            &device_public,
            &app,
            &account,
            &[PERMISSION.to_string()],
            valid_from,
            valid_until,
        )
        .into_bytes();

        let issuer = IssuerState {
            did: home_did.clone(),
            did_recomputed_ok: true,
            deltas_verified: true,
            causally_complete: true,
            deactivated: false,
            assertion_methods: vec![VerificationMethod {
                id: format!("{home_did}#jwk-0"),
                kind: "JsonWebKey".into(),
                jwk: Ed25519Jwk {
                    public_key: home.public_key(),
                    x: selfsame_app_identity::codec::b64url(&home.public_key()),
                },
                has_private_component: false,
            }],
            revoked_credential_ids: vec![],
            closure_age_seconds: 10,
            source: ClosureSource::StateResolver,
            also_known_as: vec![account.as_str().to_string()],
        };

        let jrd = Jrd {
            subject: account.as_str().to_string(),
            aliases: vec![home_did.clone()],
        };

        let challenge = Challenge {
            nonce: [42u8; 32],
            application_id: application_id.to_string(),
            account: account.as_str().to_string(),
            grant_hash: proof::grant_hash(&grant_bytes),
            issued_at: NOW - 5,
        };
        let signature = proof::sign(&challenge, &device_key);

        Self {
            profile,
            home_did,
            home_key,
            account,
            device_key,
            device_did,
            grant_bytes,
            issuer,
            jrd,
            challenge,
            signature,
            now: NOW,
        }
    }

    pub fn expectation(&self) -> Expectation<'_> {
        Expectation {
            profile: &self.profile,
            account: &self.account,
            operation_permissions: &[],
            now: self.now,
            clock_skew_seconds: 0,
            freshness: Freshness::SessionEstablishment,
        }
    }

    pub fn evidence(&self) -> Evidence<'_> {
        Evidence {
            issuer: Some(&self.issuer),
            jrd: Some(&self.jrd),
            projection: None,
            proof: Some((&self.challenge, &self.signature)),
        }
    }
}
