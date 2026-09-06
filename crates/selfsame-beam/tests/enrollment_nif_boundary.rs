//! Loads the built cdylib into a one-scheduler BEAM and exercises the exported
//! NIF. This is intentionally an integration test rather than a direct call to
//! the plain Rust helper: Rustler term decoding and the returned Erlang tuple
//! are part of the contract under test.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cbcl_pairing::credential_v2::{CredentialV2Carrier, CredentialV2CarrierInput};
use ed25519_dalek::{Signer, SigningKey};
use selfsame_app_identity::ceremony::OfferCore;
use selfsame_app_identity::codec;
use selfsame_app_identity::didkey;
use selfsame_app_identity::enrollment::{self, EnrollmentStatement, Observed};
use selfsame_app_identity::json::{self, Json};
use selfsame_app_identity::profile::ApplicationProfile;
use selfsame_app_identity::{alias, grant, issuer, path_b};
use selfsame_pairing::credential_v2::{
    browser_staging_signature_input, build_browser_staging_receipt, device_possession_proof_input,
    finalize_verified_offer, migration_confirmation_digest, prepare_offer_core,
    verify_prepared_offer_device_proof, CredentialV2BrowserStagingInput,
    CredentialV2OfferBuildInput,
};

const APPLICATION_ID: &str = "https://photos.example/selfsame/application";
const KID: &str = "https://photos.example/selfsame/application#enrollment-2026-01";
const PERMISSION: &str = "https://photos.example/selfsame/application#device";
const PLATFORM_BINDING: &str = "apple:TEAM123456:com.example.photos:https://photos.example";
const RETURN_URI: &str = "https://photos.example/.well-known/selfsame/return";
const NOW: i64 = 1_785_412_800;

struct Fixture {
    profile: ApplicationProfile,
    offer: OfferCore,
    statement: EnrollmentStatement,
    statement_octets: Vec<u8>,
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn create() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the system clock must follow the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "selfsame-enrollment-nif-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("the NIF test directory must be created");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn exported_nif_binds_the_declared_key_and_refuses_hostile_beam_terms_opaquely() {
    let fixture = fixture();
    let key = backend_key();
    let other_key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let directory = TestDirectory::create();

    write(directory.path(), "statement.bin", &fixture.statement_octets);
    let invalid_version = EnrollmentStatement {
        profile_version: 2,
        ..fixture.statement.clone()
    };
    write(
        directory.path(),
        "invalid-version.bin",
        &json::canonicalise(&enrollment::build(&invalid_version)),
    );
    write(
        directory.path(),
        "declared-public-key.bin",
        &key.verifying_key().to_bytes(),
    );
    write(
        directory.path(),
        "other-public-key.bin",
        &other_key.verifying_key().to_bytes(),
    );
    write(directory.path(), "seed.bin", key.as_bytes());
    write(directory.path(), "other-seed.bin", other_key.as_bytes());

    compile_erlang_harness(directory.path());
    let staged_nif = stage_nif(directory.path(), &nif_library());
    let output = run_erlang_harness(directory.path(), &staged_nif);
    assert!(
        output.status.success(),
        "BEAM NIF harness failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let compact = fs::read_to_string(directory.path().join("compact.bin"))
        .expect("the accepting NIF call must write its compact JWS");
    let descriptor_digest = codec::b64url(&fixture.profile.cbcl_pairing_relays[0].digest);
    let observed = Observed {
        profile: &fixture.profile,
        offer: &fixture.offer,
        provider_id: &fixture.profile.cbcl_pairing_relays[0].operator_id,
        descriptor_digest: &descriptor_digest,
        platform_binding_id: None,
        now: NOW + 1,
    };
    assert_eq!(
        enrollment::verify(&compact, &observed)
            .expect("the wallet verifier must accept the NIF producer's output"),
        fixture.statement
    );
}

#[test]
fn acceptance_nif_separates_live_verification_time_from_immutable_finalization_time() {
    let directory = TestDirectory::create();
    write_acceptance_fixture(directory.path());
    compile_erlang_harness(directory.path());
    let staged_nif = stage_nif(directory.path(), &nif_library());
    let output = run_erlang_entry(directory.path(), &staged_nif, "run_acceptance()");
    assert!(
        output.status.success(),
        "BEAM acceptance NIF harness failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn compile_erlang_harness(output_directory: &Path) {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/cbcl_selfsame_erl.erl");
    let output = Command::new("erlc")
        .arg("-o")
        .arg(output_directory)
        .arg(source)
        .output()
        .expect("erlc is required for the NIF boundary test");
    assert!(
        output.status.success(),
        "Erlang harness compilation failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_erlang_harness(fixture_directory: &Path, nif: &Path) -> Output {
    run_erlang_entry(fixture_directory, nif, "run()")
}

fn run_erlang_entry(fixture_directory: &Path, nif: &Path, entry: &str) -> Output {
    let expression = format!("case cbcl_selfsame_erl:{entry} of ok -> halt(0); _ -> halt(1) end.");
    let mut child = Command::new("erl")
        .args(["+S", "1:1", "-noshell", "-pa"])
        .arg(fixture_directory)
        .args(["-eval", &expression])
        .env("SELFSAME_NIF_PATH", nif)
        .env("SELFSAME_NIF_FIXTURE_DIR", fixture_directory)
        .env("ERL_CRASH_DUMP", fixture_directory.join("erl_crash.dump"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("erl is required for the NIF boundary test");

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if child
            .try_wait()
            .expect("the BEAM process must remain observable")
            .is_some()
        {
            return child
                .wait_with_output()
                .expect("the BEAM process output must be readable");
        }
        if Instant::now() >= deadline {
            child
                .kill()
                .expect("a stalled BEAM harness must be terminated");
            let output = child
                .wait_with_output()
                .expect("the terminated BEAM output must be readable");
            panic!(
                "BEAM NIF harness exceeded 15 seconds\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn write_acceptance_fixture(directory: &Path) {
    let application_key = backend_key();
    let profile = profile(&application_key.verifying_key().to_bytes());
    let profile_bytes = profile.canonical_bytes().to_vec();
    let device_key = SigningKey::from_bytes(&[0x52; 32]);
    let home_key = SigningKey::from_bytes(&[0x53; 32]);
    let identity = issuer::create(&home_key, &profile.account_authority, (NOW as u64) * 1_000)
        .expect("issuer fixture");
    let grant_token = [0x54; 32];
    let account = alias::stable_acct_uri(&identity.did, &profile.account_authority);
    let account_uri = alias::AcctUri::parse(&account).expect("fixture account");
    let raw_grant = grant::issue(
        &home_key,
        &identity.did,
        &grant_token,
        &didkey::encode(&device_key.verifying_key().to_bytes()),
        &device_key.verifying_key().to_bytes(),
        &profile.application_id,
        &account_uri,
        &[PERMISSION.to_string()],
        NOW - 60,
        NOW + 3_600,
    )
    .into_bytes();
    let carrier = CredentialV2Carrier::new(CredentialV2CarrierInput {
        application_context: profile.application_id.as_str().into(),
        relay_origin: profile.cbcl_pairing_relays[0].relay_origin.clone(),
        mailbox_id: [0x55; 32],
        carrier_ceremony_id: [0x56; 32],
        carrier_nonce: [0x57; 32],
        claim_commitment: [0x58; 32],
        relay_expires_at: (NOW + 900) as u64,
        expected_allocator_key: Some(device_key.verifying_key().to_bytes()),
    })
    .expect("carrier fixture");
    let prepared = prepare_offer_core(
        &profile,
        &carrier,
        &CredentialV2OfferBuildInput {
            request_id: [0x59; 32],
            transcript_hash: [0x5a; 64],
            application_account_id: [0x5b; 32],
            account_scope_id: [0x5c; 32],
            device_public_key: device_key.verifying_key().to_bytes(),
            requested_permissions: vec![PERMISSION.into()],
            intent_nonce: [0x5d; 32],
            issued_at: (NOW - 60) as u64,
            expires_at: (NOW + 540) as u64,
            legacy_handle: "@clock-boundary".into(),
            enrolled_key: [0x5e; 32],
            snapshot_rows: Vec::new(),
            snapshot_nonce: [0x5f; 32],
        },
    )
    .expect("prepared offer");
    let socket_generation = [0x60; 32];
    let possession_input = device_possession_proof_input(
        socket_generation,
        *carrier.carrier_ceremony_id(),
        prepared.offer_core_digest,
    )
    .expect("possession input");
    let verified = verify_prepared_offer_device_proof(
        &profile,
        &prepared,
        socket_generation,
        *carrier.carrier_ceremony_id(),
        device_key.verifying_key().to_bytes(),
        device_key.sign(&possession_input).to_bytes(),
    )
    .expect("device proof");
    let offer =
        finalize_verified_offer(&profile, &verified, KID, &application_key).expect("signed offer");
    let recognised =
        selfsame_pairing::credential_v2::recognise_signed_offer(&profile, &offer.signed_offer)
            .expect("recognised offer");
    let payload_digest = [0x61; 32];
    let recovery_commitment = [0x62; 32];
    let staging = CredentialV2BrowserStagingInput {
        application_id: profile.application_id.as_str().into(),
        carrier_ceremony_id: *carrier.carrier_ceremony_id(),
        account_principal_digest: offer.account_principal_digest,
        account_scope_id: [0x5c; 32],
        device_did: offer.device_did.clone(),
        offer_core_digest: offer.offer_core_digest,
        payload_digest,
        grant_id: grant_token,
        issuer_did: identity.did.clone(),
        profile_digest: *profile.digest(),
        receipt_recovery_commitment: recovery_commitment,
    };
    let staging_receipt = build_browser_staging_receipt(
        &staging,
        device_key.verifying_key().to_bytes(),
        device_key
            .sign(&browser_staging_signature_input(&staging).expect("staging input"))
            .to_bytes(),
    )
    .expect("staging receipt");
    let closure_bytes = serde_json::to_vec(&identity.closure).expect("canonical closure");
    let observation = path_b::replay_resolver_closure(
        identity.closure,
        &identity.did,
        &profile.state_resolvers[0].id,
        NOW + 1,
    )
    .expect("resolver observation");
    assert_eq!(observation.assertion_methods.len(), 1);
    let method = &observation.assertion_methods[0];

    for (name, bytes) in [
        ("accept-profile.bin", profile_bytes.as_slice()),
        ("accept-offer.bin", offer.signed_offer.as_slice()),
        ("accept-grant.bin", raw_grant.as_slice()),
        ("accept-closure.bin", closure_bytes.as_slice()),
        ("accept-payload-digest.bin", payload_digest.as_slice()),
        (
            "accept-migration-digest.bin",
            migration_confirmation_digest(&recognised, &identity.did)
                .expect("migration digest")
                .as_slice(),
        ),
        ("accept-issuer-did.bin", identity.did.as_bytes()),
        ("accept-grant-id.bin", grant_token.as_slice()),
        ("accept-staging-receipt.bin", staging_receipt.as_slice()),
        (
            "accept-recovery-commitment.bin",
            recovery_commitment.as_slice(),
        ),
        ("accept-kid.bin", KID.as_bytes()),
        ("accept-signing-seed.bin", application_key.as_bytes()),
        ("accept-resolver-id.bin", observation.resolver_id.as_bytes()),
        ("accept-method-id.bin", method.id.as_bytes()),
        ("accept-method-kind.bin", method.kind.as_bytes()),
        ("accept-method-key.bin", method.public_key.as_slice()),
        ("accept-account.bin", account.as_bytes()),
    ] {
        write(directory, name, bytes);
    }
}

fn nif_library() -> PathBuf {
    let executable = std::env::current_exe().expect("the integration-test path must be known");
    let directory = executable
        .parent()
        .expect("the integration test must live in target/deps");
    let filename = if cfg!(target_os = "windows") {
        OsString::from("cbcl_selfsame_erl.dll")
    } else if cfg!(target_os = "macos") {
        OsString::from("libcbcl_selfsame_erl.dylib")
    } else {
        OsString::from("libcbcl_selfsame_erl.so")
    };
    let path = directory.join(filename);
    assert!(
        path.is_file(),
        "the selfsame-beam cdylib was not built at {}",
        path.display()
    );
    path
}

fn stage_nif(directory: &Path, library: &Path) -> PathBuf {
    let base = directory.join("libcbcl_selfsame_erl");
    let loadable = if cfg!(target_os = "windows") {
        base.with_extension("dll")
    } else {
        // Erlang uses the `.so` NIF convention on every Unix, including macOS.
        base.with_extension("so")
    };
    fs::copy(library, loadable).expect("the NIF library must be staged with Erlang's suffix");
    base
}

fn write(directory: &Path, name: &str, bytes: &[u8]) {
    fs::write(directory.join(name), bytes).expect("a NIF fixture must be writable");
}

fn backend_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x41; 32])
}

fn fixture() -> Fixture {
    let profile = profile(&backend_key().verifying_key().to_bytes());
    let device_public_key = ed25519_dalek::SigningKey::from_bytes(&[0x23; 32])
        .verifying_key()
        .to_bytes();
    let offer = OfferCore {
        ceremony_id: codec::b64url(&[1; 32]),
        request_id: codec::b64url(&[2; 32]),
        application_id: APPLICATION_ID.to_string(),
        profile_version: 1,
        profile_digest: codec::b64url(profile.digest()),
        account_scope_id: codec::b64url(&[3; 32]),
        device_did: didkey::encode(&device_public_key),
        device_public_key,
        requested_permissions: vec![PERMISSION.to_string()],
        issued_at: NOW,
        expires_at: NOW + 120,
    };
    let descriptor = &profile.cbcl_pairing_relays[0];
    let statement = EnrollmentStatement {
        request_id: offer.request_id.clone(),
        ceremony_id: offer.ceremony_id.clone(),
        application_id: offer.application_id.clone(),
        profile_version: offer.profile_version,
        profile_digest: offer.profile_digest.clone(),
        account_scope_id: offer.account_scope_id.clone(),
        device_key_digest: enrollment::device_key_digest(&offer),
        requested_permissions: offer.requested_permissions.clone(),
        provider_id: descriptor.operator_id.clone(),
        descriptor_digest: codec::b64url(&descriptor.digest),
        offer_digest: offer.digest(),
        platform_binding_id: PLATFORM_BINDING.to_string(),
        return_uri: RETURN_URI.to_string(),
        issued_at: offer.issued_at,
        expires_at: offer.expires_at,
    };
    let statement_octets = json::canonicalise(&enrollment::build(&statement));
    Fixture {
        profile,
        offer,
        statement,
        statement_octets,
    }
}

fn profile(public_key: &[u8; 32]) -> ApplicationProfile {
    let value = Json::obj([
        ("profileVersion", Json::int(1)),
        ("applicationId", Json::text(APPLICATION_ID)),
        ("accountAuthority", Json::text("accounts.photos.example")),
        ("verifierAudience", Json::text(APPLICATION_ID)),
        ("allowedPermissions", Json::arr([Json::text(PERMISSION)])),
        (
            "enrollment",
            Json::obj([
                (
                    "requestSigningKeys",
                    Json::arr([Json::obj([
                        ("kid", Json::text(KID)),
                        (
                            "publicKeyJwk",
                            Json::obj([
                                ("kty", Json::text("OKP")),
                                ("crv", Json::text("Ed25519")),
                                ("x", Json::text(codec::b64url(public_key))),
                            ]),
                        ),
                    ])]),
                ),
                (
                    "mobileBindings",
                    Json::arr([Json::obj([
                        ("id", Json::text(PLATFORM_BINDING)),
                        ("platform", Json::text("apple")),
                        ("teamId", Json::text("TEAM123456")),
                        ("bundleId", Json::text("com.example.photos")),
                        ("returnUri", Json::text(RETURN_URI)),
                    ])]),
                ),
            ]),
        ),
        (
            "cbclPairingRelays",
            Json::arr([Json::obj([
                ("operatorId", Json::text("au-primary")),
                ("relayOrigin", Json::text("https://cbcl.example")),
                ("priority", Json::int(10)),
                ("weight", Json::int(80)),
                (
                    "privacyPolicyDigest",
                    Json::text(codec::b64url(&[11u8; 32])),
                ),
                (
                    "conformanceEvidenceDigest",
                    Json::text(codec::b64url(&[12u8; 32])),
                ),
            ])]),
        ),
        (
            "stateResolvers",
            Json::arr([Json::obj([
                ("id", Json::text("state-1")),
                ("url", Json::text("https://state.example")),
                ("protocol", Json::text("did-crdt-service-v1")),
            ])]),
        ),
        (
            "revocation",
            Json::obj([
                ("method", Json::text("did-crdt-revocations-v1")),
                ("maxGrantLifetimeSeconds", Json::int(2_592_000)),
                ("maxClosureAgeSeconds", Json::int(900)),
                ("propagationSlaSeconds", Json::int(60)),
            ]),
        ),
    ]);
    ApplicationProfile::recognise(&json::canonicalise(&value))
        .expect("the accepting profile fixture must recognise")
}
