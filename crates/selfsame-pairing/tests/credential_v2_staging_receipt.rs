//! Independent cross-boundary vector for cbcl-chat's browser staging receipt.

use ed25519_dalek::{Signer, SigningKey};
use selfsame_app_identity::didkey;
use selfsame_pairing::credential_v2::{
    browser_staging_signature_input, build_browser_staging_receipt,
    recognise_browser_staging_receipt, CredentialV2BrowserStagingInput,
};
use serde_json::{json, Value};
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn encode_hex<const N: usize>(value: [u8; N]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn input(device_public_key: [u8; 32]) -> CredentialV2BrowserStagingInput {
    CredentialV2BrowserStagingInput {
        application_id: "https://chat.anuna.io/selfsame/v2".into(),
        carrier_ceremony_id: [0x11; 32],
        account_principal_digest: [0x22; 32],
        account_scope_id: [0x33; 32],
        device_did: didkey::encode(&device_public_key),
        offer_core_digest: [0x44; 32],
        payload_digest: [0x55; 32],
        grant_id: [0x66; 32],
        issuer_did: "did:crdt:z6MkIssuerForStagingReceipt".into(),
        profile_digest: [0x77; 32],
        receipt_recovery_commitment: [0x88; 32],
    }
}

fn oracle(input: &CredentialV2BrowserStagingInput, signature: [u8; 64]) -> Value {
    let source = json!({
        "application_id": input.application_id,
        "carrier_ceremony_id": encode_hex(input.carrier_ceremony_id),
        "account_principal_digest": encode_hex(input.account_principal_digest),
        "account_scope_id": encode_hex(input.account_scope_id),
        "device_did": input.device_did,
        "offer_core_digest": encode_hex(input.offer_core_digest),
        "payload_digest": encode_hex(input.payload_digest),
        "grant_id": encode_hex(input.grant_id),
        "issuer_did": input.issuer_did,
        "profile_digest": encode_hex(input.profile_digest),
        "receipt_recovery_commitment": encode_hex(input.receipt_recovery_commitment),
        "signature": encode_hex(signature),
    });
    let mut child = Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/credential_v2_staging_oracle.py"
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("python3 staging oracle starts");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(source.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn browser_staging_receipt_matches_independent_cbor_and_refuses_mutation() {
    let key = SigningKey::from_bytes(&[0x99; 32]);
    let input = input(key.verifying_key().to_bytes());
    let first_oracle = oracle(&input, [0_u8; 64]);
    let expected_input: [u8; 32] = decode_hex(first_oracle["signature_input"].as_str().unwrap())
        .try_into()
        .unwrap();
    assert_eq!(browser_staging_signature_input(&input).unwrap(), expected_input);

    let signature = key.sign(&expected_input).to_bytes();
    let expected_receipt =
        decode_hex(oracle(&input, signature)["receipt"].as_str().unwrap());
    let receipt = build_browser_staging_receipt(
        &input,
        key.verifying_key().to_bytes(),
        signature,
    )
    .unwrap();
    assert_eq!(receipt, expected_receipt);
    recognise_browser_staging_receipt(
        &receipt,
        &input,
        key.verifying_key().to_bytes(),
    )
    .unwrap();

    for index in [0, receipt.len() / 2, receipt.len() - 1] {
        let mut changed = receipt.clone();
        changed[index] ^= 1;
        assert!(recognise_browser_staging_receipt(
            &changed,
            &input,
            key.verifying_key().to_bytes(),
        )
        .is_err());
    }
    let mut wrong = input.clone();
    wrong.payload_digest[0] ^= 1;
    assert!(recognise_browser_staging_receipt(
        &receipt,
        &wrong,
        key.verifying_key().to_bytes(),
    )
    .is_err());
}
