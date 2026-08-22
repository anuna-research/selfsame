//! THE COMPLETE first-contact enrolment, end to end, headless — the whole
//! ceremony the deployed system runs, with keyring's in-memory mock standing in
//! for the OS keychain (test infrastructure; production still uses the real
//! keychain and its human presence gate). Proves every step wired together:
//!
//!   provision identity (Custody::create, a TEST passcode)
//!     → build a real CON-219 offer for chat.anuna.io, signed by the real
//!       enrolment key
//!     → the wallet AUTHORISES it (CON-214)
//!     → the passcode unlocks the hierarchy root and ISSUES the grant (CON-205)
//!     → the pairing-trust record is written (ADR-912)
//!     → the SPEC-008 REQ-906 gate ADMITS chat.anuna.io:9443 — the original
//!       refusal is gone.
//!
//! `#[ignore]`d only because it mutates the process-wide keyring backend. Run:
//! `cargo test -p selfsame --test full_enrolment_flow -- --ignored --nocapture`

use base64ct::{Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::SigningKey;
use selfsame_app_identity::ceremony::OfferCore;
use selfsame_app_identity::enrollment::{self, EnrollmentStatement};
use selfsame_app_identity::json::{self, Json};
use selfsame_app_identity::provider_hint::ProviderHint;
use selfsame_app_identity::{codec, didkey};

const PROFILE_B64: &str = "eyJhY2NvdW50QXV0aG9yaXR5IjoiY2hhdC5hbnVuYS5pbyIsImFsbG93ZWRQZXJtaXNzaW9ucyI6WyJodHRwczovL2NoYXQuYW51bmEuaW8vc2VsZnNhbWUvYXBwbGljYXRpb24jY2hhbm5lbC1qb2luIiwiaHR0cHM6Ly9jaGF0LmFudW5hLmlvL3NlbGZzYW1lL2FwcGxpY2F0aW9uI2NoYXQtcmVhZCIsImh0dHBzOi8vY2hhdC5hbnVuYS5pby9zZWxmc2FtZS9hcHBsaWNhdGlvbiNjaGF0LXNlbmQiLCJodHRwczovL2NoYXQuYW51bmEuaW8vc2VsZnNhbWUvYXBwbGljYXRpb24jbWxzLWNvbW1pdCJdLCJhcHBsaWNhdGlvbklkIjoiaHR0cHM6Ly9jaGF0LmFudW5hLmlvL3NlbGZzYW1lL2FwcGxpY2F0aW9uIiwiY2JjbFBhaXJpbmdSZWxheXMiOlt7ImNvbmZvcm1hbmNlRXZpZGVuY2VEaWdlc3QiOiJjQ255SXA4SXhVaXlVakNVQmJyWjViM2ZsenFNTThjLVNfdFVDUGRDd1VJIiwib3BlcmF0b3JJZCI6ImFudW5hLTEiLCJwcmlvcml0eSI6MTAsInByaXZhY3lQb2xpY3lEaWdlc3QiOiJpTXlEb3BreXFxMzJ2UWFQU3ViR0hCelVISVpXU1VYd2pOOENiQW13S0dzIiwicmVsYXlPcmlnaW4iOiJodHRwczovL2NoYXQuYW51bmEuaW86OTQ0MyIsIndlaWdodCI6MTAwfV0sImVucm9sbG1lbnQiOnsibW9iaWxlQmluZGluZ3MiOlt7ImlkIjoid2ViOmh0dHBzOi8vY2hhdC5hbnVuYS5pbyIsIm9yaWdpbiI6Imh0dHBzOi8vY2hhdC5hbnVuYS5pbyIsInBsYXRmb3JtIjoid2ViIn1dLCJyZXF1ZXN0U2lnbmluZ0tleXMiOlt7ImtpZCI6Imh0dHBzOi8vY2hhdC5hbnVuYS5pby9zZWxmc2FtZS9hcHBsaWNhdGlvbiNlbnJvbGxtZW50LTIwMjYtMDgiLCJwdWJsaWNLZXlKd2siOnsiY3J2IjoiRWQyNTUxOSIsImt0eSI6Ik9LUCIsIngiOiI4MmxlT3JzaTlZRG91bWVoelo3VjA3X2NMTDlFYkRkeWFyZXVOS1IwQjg4In19XX0sInByb2ZpbGVWZXJzaW9uIjoxLCJyZXZvY2F0aW9uIjp7Im1heENsb3N1cmVBZ2VTZWNvbmRzIjo5MDAsIm1heEdyYW50TGlmZXRpbWVTZWNvbmRzIjoyNTkyMDAwLCJtZXRob2QiOiJkaWQtY3JkdC1yZXZvY2F0aW9ucy12MSIsInByb3BhZ2F0aW9uU2xhU2Vjb25kcyI6NjB9LCJzdGF0ZVJlc29sdmVycyI6W3siaWQiOiJhbnVuYS1kaWQtMSIsInByb3RvY29sIjoiZGlkLWNyZHQtc2VydmljZS12MSIsInVybCI6Imh0dHBzOi8vZGlkLmFudW5hLmlvIn1dLCJ2ZXJpZmllckF1ZGllbmNlIjoiaHR0cHM6Ly9jaGF0LmFudW5hLmlvL3NlbGZzYW1lL2FwcGxpY2F0aW9uIn0";
const SEED_HEX: &str = "41ea13ffe7cbda6370faabf2e524290943d550948df179f9999060e90e8eeb7d";
const APP_ID: &str = "https://chat.anuna.io/selfsame/application";
const KID: &str = "https://chat.anuna.io/selfsame/application#enrollment-2026-08";
const ORIGIN: &str = "https://chat.anuna.io";
const RELAY: &str = "https://chat.anuna.io:9443";
const PASSCODE: &str = "a test passcode for the full flow";
const NOW: i64 = 1_785_412_800;

fn seed32(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn build_offer_plaintext(profile: &selfsame_app_identity::profile::ApplicationProfile) -> (Vec<u8>, String) {
    let scope = [4u8; 32];
    let device = SigningKey::from_bytes(&[3u8; 32]).verifying_key().to_bytes();
    let descriptor = &profile.cbcl_pairing_relays[0];
    let core = OfferCore {
        ceremony_id: codec::b64url(&[1u8; 32]),
        request_id: codec::b64url(&[2u8; 32]),
        application_id: APP_ID.into(),
        profile_version: 1,
        profile_digest: codec::b64url(profile.digest()),
        account_scope_id: codec::b64url(&scope),
        device_did: didkey::encode(&device),
        device_public_key: device,
        requested_permissions: profile.allowed_permissions.clone(),
        issued_at: NOW,
        expires_at: NOW + 120,
    };
    let hint = ProviderHint {
        application_id: APP_ID.into(),
        profile_version: 1,
        provider_id: descriptor.operator_id.clone(),
        descriptor_digest: codec::b64url(&descriptor.digest),
        offer_digest: core.digest(),
    };
    let statement = EnrollmentStatement {
        request_id: core.request_id.clone(),
        ceremony_id: core.ceremony_id.clone(),
        application_id: APP_ID.into(),
        profile_version: 1,
        profile_digest: core.profile_digest.clone(),
        account_scope_id: core.account_scope_id.clone(),
        device_key_digest: enrollment::device_key_digest(&core),
        requested_permissions: core.requested_permissions.clone(),
        provider_id: hint.provider_id.clone(),
        descriptor_digest: hint.descriptor_digest.clone(),
        offer_digest: core.digest(),
        platform_binding_id: format!("web:{ORIGIN}"),
        return_uri: format!("{ORIGIN}/.well-known/selfsame/return"),
        issued_at: NOW,
        expires_at: NOW + 120,
    };
    let evidence = enrollment::sign(&statement, KID, &SigningKey::from_bytes(&seed32(SEED_HEX)));
    let Json::Object(mut members) = core.to_json() else { unreachable!() };
    members.push(("enrollmentEvidence".into(), Json::text(&evidence)));
    members.push(("providerHint".into(), hint.to_json()));
    (json::canonicalise(&Json::Object(members)), codec::b64url(&scope))
}


// A process-shared in-memory keyring backend: keyring's own mock does not share
// state across Entry::new calls, but custody stores and reads through separate
// Entry instances keyed by (service, name). This shares them via one map, so
// the full custody round-trip works headlessly without touching the OS keychain.
mod memkeyring {
    use std::any::Any;
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    use keyring::credential::{Credential, CredentialApi, CredentialBuilderApi};

    fn store() -> &'static Mutex<HashMap<String, Vec<u8>>> {
        static S: OnceLock<Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();
        S.get_or_init(|| Mutex::new(HashMap::new()))
    }

    #[derive(Debug)]
    struct Cred { key: String }
    impl CredentialApi for Cred {
        fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
            store().lock().unwrap().insert(self.key.clone(), secret.to_vec());
            Ok(())
        }
        fn get_secret(&self) -> keyring::Result<Vec<u8>> {
            store().lock().unwrap().get(&self.key).cloned().ok_or(keyring::Error::NoEntry)
        }
        fn delete_credential(&self) -> keyring::Result<()> {
            store().lock().unwrap().remove(&self.key);
            Ok(())
        }
        fn as_any(&self) -> &dyn Any { self }
    }

    #[derive(Debug)]
    struct Builder;
    impl CredentialBuilderApi for Builder {
        fn build(&self, _target: Option<&str>, service: &str, user: &str) -> keyring::Result<Box<Credential>> {
            Ok(Box::new(Cred { key: format!("{service}\u{0000}{user}") }))
        }
        fn as_any(&self) -> &dyn Any { self }
    }

    pub fn install() {
        keyring::set_default_credential_builder(Box::new(Builder));
    }
}

#[test]
#[ignore]
fn the_whole_enrolment_completes_and_clears_the_refusal() {
    // Test infrastructure: a shared in-memory keyring so custody works
    // headlessly. Production keeps the real keychain and its human presence gate.
    memkeyring::install();

    let octets = Base64UrlUnpadded::decode_vec(PROFILE_B64).unwrap();
    let profile = selfsame_app_identity::profile::ApplicationProfile::recognise(&octets).unwrap();

    // 1. Provision an identity (the person's create-identity step).
    let _ = selfsame_lib::custody::Custody::forget();
    let _mnemonic = selfsame_lib::custody::Custody::create(PASSCODE).expect("provision");

    // 2. Build the real CON-219 offer, signed by the real enrolment key.
    let (plaintext, scope_b64) = build_offer_plaintext(&profile);
    let offer = selfsame_app_identity::ceremony::recognise_offer(&plaintext).unwrap();

    // 3. The wallet AUTHORISES it (CON-214 acceptance).
    let observed = selfsame_lib::app_grant::observation_for_enrolment_offer(&offer).unwrap();
    let decided = selfsame_app_identity::authorise::authorise(
        &plaintext,
        &octets,
        &observed.as_observation(NOW),
    )
    .expect("the wallet authorises the offer");
    assert_eq!(decided.profile.application_id.as_str(), APP_ID);

    // 4. THE PASSCODE STEP: unlock the hierarchy root and issue the grant.
    let application = selfsame_app_identity::profile::ApplicationId::parse(APP_ID).unwrap();
    let scope = selfsame_app_identity::scope::AccountScopeId::parse(&scope_b64).unwrap();
    let identity = selfsame_lib::custody::Custody::use_hierarchy_root(PASSCODE, |root| {
        let home = selfsame_app_identity::hierarchy::derive(root, &application, &scope);
        selfsame_app_identity::issuer::create(home.signing_key(), "chat.anuna.io", (NOW as u64) * 1000)
    })
    .expect("passcode unlocks the root")
    .expect("issuer constructed");
    assert!(identity.authorises_grants, "the grant is issuable");

    // 5. The durable effect: write the pairing-trust record (ADR-912).
    selfsame_lib::cbcl_context::record_pairing_trust(APP_ID, &octets, &scope_b64, NOW).unwrap();

    // 6. The refusal is gone: the REQ-906 gate now admits chat.anuna.io:9443.
    let held = selfsame_lib::cbcl_context::held_trust_records();
    let profiles: Vec<_> = held.iter().map(|(_, p)| p.clone()).collect();
    let policy = selfsame_lib::cbcl_registry::production_relay_policy();
    let admitted = selfsame_lib::cbcl_context::gate_invitation_origin(&profiles, &policy, RELAY)
        .expect("REQ-906 ADMITS chat.anuna.io:9443 — the refusal is resolved");
    assert_eq!(admitted.application_id.as_str(), APP_ID);

    println!("FULL ENROLMENT COMPLETE — the app works with chat.anuna.io:");
    println!("  provisioned identity, authorised the offer, ISSUED the grant behind");
    println!("  the passcode, wrote the trust record, and the REQ-906 gate now");
    println!("  ADMITS {RELAY}. account: {}", identity.acct_uri);

    let _ = selfsame_lib::custody::Custody::forget();
}
