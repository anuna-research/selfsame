//! Negative surface tests for the browser/hub trust boundary.
//!
//! Rust has no ordinary runtime assertion for “this public function does not
//! exist”. These tests inspect the crate source so accidentally restoring the
//! removed authorization or raw-key exports fails in CI instead of silently
//! widening the wasm ABI.

const SOURCE: &str = include_str!("../src/lib.rs");

fn public_function_names() -> Vec<&'static str> {
    SOURCE
        .lines()
        .filter_map(|line| line.trim().strip_prefix("pub fn "))
        .filter_map(|rest| rest.split(['(', '<']).next())
        .collect()
}

#[test]
fn replayable_self_acceptance_is_not_a_browser_export() {
    let functions = public_function_names();

    assert!(
        functions.contains(&"proof_input_json"),
        "control: the browser can still construct non-authorizing proof octets"
    );
    assert!(
        !functions.contains(&["accept_grant", "_json"].concat().as_str()),
        "a subject-side facade cannot consume the hub's nonce ledger"
    );
    assert!(
        !functions.contains(&["accept_device", "_grant"].concat().as_str()),
        "the native surface must not hide an authorization API absent from wasm"
    );
    assert!(
        !SOURCE.contains(&["struct Browser", "Challenge"].concat()),
        "the browser must receive only the nonce, not a caller-rebound issuance record"
    );
    assert!(
        !SOURCE.contains(&["verifier", "_session"].concat()),
        "verifier session state must remain in the hub's nonce record"
    );
}

#[test]
fn caller_asserted_resolver_state_cannot_produce_authorization() {
    let functions = public_function_names();

    assert!(
        functions.contains(&"recognise_bundle_json"),
        "control: the browser retains a non-authorizing bundle recognizer"
    );
    assert!(
        !SOURCE.contains(&["struct Browser", "IssuerState"].concat()),
        "the subject-side surface must not deserialize authorization state"
    );
    assert!(
        !SOURCE.contains(&["fn acceptance", "_json"].concat()),
        "caller assertions must not be rendered as an acceptance object"
    );
}

#[test]
fn browser_signing_never_requires_exportable_seed_bytes() {
    let functions = public_function_names();

    assert!(
        functions.contains(&"proof_input_json"),
        "control: proof bytes remain available"
    );
    assert!(
        !functions.contains(&["sign_proof", "_json"].concat().as_str()),
        "WebCrypto must retain custody of the non-extractable signing key"
    );
    assert!(
        !functions.contains(&["sign_", "proof"].concat().as_str()),
        "the native twin must expose the same custody boundary"
    );
}
