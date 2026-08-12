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

use selfsame_app_identity::ceremony::OfferCore;
use selfsame_app_identity::codec;
use selfsame_app_identity::didkey;
use selfsame_app_identity::enrollment::{self, EnrollmentStatement, Observed};
use selfsame_app_identity::json::{self, Json};
use selfsame_app_identity::profile::ApplicationProfile;

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
    let descriptor_digest = codec::b64url(&fixture.profile.rendezvous[0].digest);
    let observed = Observed {
        profile: &fixture.profile,
        offer: &fixture.offer,
        provider_id: &fixture.profile.rendezvous[0].id,
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
    let mut child = Command::new("erl")
        .args(["+S", "1:1", "-noshell", "-pa"])
        .arg(fixture_directory)
        .args([
            "-eval",
            "case cbcl_selfsame_erl:run() of ok -> halt(0); _ -> halt(1) end.",
        ])
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
    let descriptor = &profile.rendezvous[0];
    let statement = EnrollmentStatement {
        request_id: offer.request_id.clone(),
        ceremony_id: offer.ceremony_id.clone(),
        application_id: offer.application_id.clone(),
        profile_version: offer.profile_version,
        profile_digest: offer.profile_digest.clone(),
        account_scope_id: offer.account_scope_id.clone(),
        device_key_digest: enrollment::device_key_digest(&offer),
        requested_permissions: offer.requested_permissions.clone(),
        provider_id: descriptor.id.clone(),
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
            "rendezvous",
            Json::arr([Json::obj([
                ("id", Json::text("au-primary")),
                ("url", Json::text("https://rendezvous.example")),
                ("protocol", Json::text("selfsame-rendezvous-v1")),
                ("pairingUrl", Json::text("https://pairing.example")),
                ("pairingProtocol", Json::text("selfsame-pairing-v1")),
                ("pairingRoute", Json::text("03")),
                ("priority", Json::int(10)),
                ("weight", Json::int(80)),
                ("validUntil", Json::text("2027-07-30T00:00:00Z")),
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
