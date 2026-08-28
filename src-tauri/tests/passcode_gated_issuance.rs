//! The passcode step, exercised — not bypassed. REQ-024 makes the person's
//! passcode the presence gate on every root-key use; this drives that gate with
//! a TEST passcode, exactly as a real one would drive it, to prove the
//! wallet's half of enrolment completes: provision an identity, unlock the
//! SPEC-004 hierarchy root with the passcode, derive the chat.anuna.io
//! application-account home, and produce a grant-issuing issuer identity.
//!
//! This is the `cbcl_enrol_prepare` core: the step where "enter passcode" turns
//! into "grant signed". A wrong passcode yields BadPasscode and no key, which
//! is the gate working. Combined with pairing_gate_resolved (trust record →
//! REQ-906 admits chat.anuna.io:9443) and live_enrol (the wallet authorises the
//! live offer), the whole ceremony is demonstrated end to end.
//!
//! `#[ignore]`d, and it REQUIRES INTERACTIVE PRESENCE: provisioning the root
//! touches the platform keychain, which on macOS/iOS prompts for the device
//! credential — REQ-024's presence gate enforced by the OS itself. Run it on a
//! device where you can answer that prompt:
//! `cargo test -p selfsame --test passcode_gated_issuance -- --ignored --nocapture`
//! On a headless CI box it will block on the keychain prompt, which is the gate
//! working, not a flake.

use selfsame_lib::custody::Custody;

const CHAT_APP_ID: &str = "https://chat.anuna.io/selfsame/application";
const CHAT_AUTHORITY: &str = "chat.anuna.io";
const TEST_PASSCODE: &str = "a test passcode for the harness";

#[test]
#[ignore]
fn the_passcode_unlocks_the_root_and_issues_a_grant_for_chat_anuna_io() {
    // Clean slate, then provision — the person's "create identity" step.
    let _ = Custody::forget();
    let _mnemonic = Custody::create(TEST_PASSCODE).expect("provision a fresh identity");

    let application =
        selfsame_app_identity::profile::ApplicationId::parse(CHAT_APP_ID).unwrap();
    let scope =
        selfsame_app_identity::scope::AccountScopeId::parse(&"A".repeat(43)).unwrap();

    // THE PASSCODE STEP: unlock the hierarchy root and produce the issuer.
    // A wrong passcode cannot open the sealed root — this is REQ-024's gate.
    let identity = Custody::use_hierarchy_root(TEST_PASSCODE, |root| {
        let home = selfsame_app_identity::hierarchy::derive(root, &application, &scope);
        selfsame_app_identity::issuer::create(
            home.signing_key(),
            CHAT_AUTHORITY,
            1_785_412_800_000,
        )
    })
    .expect("the correct passcode unlocks the hierarchy root")
    .expect("the issuer identity is constructed");

    assert!(
        identity.authorises_grants,
        "the derived home issues grants — the wallet can complete enrolment"
    );
    assert!(identity.acct_uri.contains("@chat.anuna.io"));

    // The gate: a WRONG passcode yields no key.
    let wrong = Custody::use_hierarchy_root("the wrong passcode entirely", |_| ());
    assert!(
        matches!(wrong, Err(selfsame_lib::custody::CustodyError::BadPasscode)),
        "a wrong passcode is refused — the presence gate holds"
    );

    println!("PASSCODE-GATED ISSUANCE PROVEN:");
    println!("  the test passcode unlocked the root and derived a grant-issuing");
    println!("  identity for {} ({})", CHAT_APP_ID, identity.acct_uri);
    println!("  a wrong passcode was refused (BadPasscode).");

    let _ = Custody::forget();
}
