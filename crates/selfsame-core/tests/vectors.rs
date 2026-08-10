//! Published cross-runtime test vectors — SPEC-001 TEST-001, gate condition B.
//!
//! > **Condition B:** CON-007 and ADR-010 test vectors MUST be published and
//! > cross-runtime green before any client ships, **or two clients will
//! > disagree about what a mnemonic means.**
//!
//! The vectors live at `test-vectors/spec-001-v1.json` so a second
//! implementation — `cbcl-wasm` in the browser, `cbcl-ffi` on the phone, a
//! future Swift or Kotlin port — can be checked against the same file rather
//! than against this crate's behaviour.
//!
//! Regenerate deliberately, never incidentally:
//!
//! ```sh
//! cargo test -p selfsame-core --test vectors -- --ignored regenerate
//! ```
//!
//! Regenerating after anything has shipped **re-derives every existing
//! identity**. That is why it is a separate, ignored, explicitly-named command
//! and not a fallback the checking test silently takes when the file is
//! missing.

use selfsame_core::{code, derive, fingerprint, identity, mb, record, seal};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

const VECTORS_PATH: &str = "../../test-vectors/spec-001-v1.json";

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Vectors {
    /// Which specification version these vectors fix.
    spec: String,
    /// The `did-crdt` revision ADR-010 pins.
    did_crdt_revision: String,
    con_007_root_derivation: Vec<RootVector>,
    adr_010_did_derivation: Vec<DidVector>,
    con_001_link_code: Vec<CodeVector>,
    con_002_rendezvous: Vec<SlotVector>,
    req_007_fingerprints: Vec<FingerprintVector>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct RootVector {
    entropy_hex: String,
    mnemonic: String,
    persona: u32,
    root_seed_hex: String,
    root_public_key_multibase: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct DidVector {
    root_public_key_multibase: String,
    did: String,
    root_method_id: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct CodeVector {
    application: String,
    secret_hex: String,
    code: String,
    length: usize,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct SlotVector {
    secret_hex: String,
    channel_key_hex: String,
    offer_slot: String,
    bundle_slot: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct FingerprintVector {
    input: String,
    kind: String,
    hex: String,
    label: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The four entropies the vectors are built from: all-zero, all-ones, an
/// alternating pattern, and one arbitrary value. Fixed constants, so the file
/// is reproducible on any machine.
fn entropies() -> Vec<[u8; 16]> {
    vec![
        [0x00; 16],
        [0xff; 16],
        [0xaa; 16],
        [
            0x9f, 0x3a, 0x11, 0xc2, 0xe7, 0x0b, 0x4d, 0x8a, 0x5c, 0x6f, 0x90, 0x12, 0xab, 0x34,
            0xcd, 0x56,
        ],
    ]
}

fn build() -> Vectors {
    let mut con_007 = Vec::new();
    let mut adr_010 = Vec::new();

    for entropy in entropies() {
        let mnemonic = derive::mnemonic_from_entropy(&entropy);
        // TEST-001 requires personas 0, 1 and 2 so the index is exercised
        // before anything depends on it.
        for persona in [0u32, 1, 2] {
            let seed = derive::root_seed(&mnemonic, persona);
            let signing = derive::root_signing_key(&mnemonic, persona);
            let pk = signing.verifying_key().to_bytes();
            con_007.push(RootVector {
                entropy_hex: hex(&entropy),
                mnemonic: mnemonic.to_string(),
                persona,
                root_seed_hex: hex(seed.as_ref()),
                root_public_key_multibase: mb::encode(&pk),
            });
            let did = identity::derive_did(&pk).unwrap();
            adr_010.push(DidVector {
                root_public_key_multibase: mb::encode(&pk),
                root_method_id: identity::root_method_id(&did),
                did: did.to_string(),
            });
        }
    }

    let con_001 = entropies()
        .into_iter()
        .map(|secret| {
            let link = code::LinkCode {
                application: record::Application::CbclChat,
                secret: code::LinkSecret::from_bytes(secret),
            };
            let rendered = link.render();
            CodeVector {
                application: record::Application::CbclChat.slug().to_owned(),
                secret_hex: hex(&secret),
                length: rendered.chars().count(),
                code: rendered,
            }
        })
        .collect();

    let con_002 = entropies()
        .into_iter()
        .map(|secret| SlotVector {
            secret_hex: hex(&secret),
            channel_key_hex: hex(&seal::derive_key(&secret)),
            offer_slot: seal::slot(seal::Role::Offer, &secret),
            bundle_slot: seal::slot(seal::Role::Bundle, &secret),
        })
        .collect();

    let mut req_007 = Vec::new();
    for seed in [0u8, 0x42, 0xff] {
        let pk = SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes();
        let fp = fingerprint::fingerprint_key(&pk);
        req_007.push(FingerprintVector {
            input: mb::encode(&pk),
            kind: "key".to_owned(),
            hex: fp.hex(),
            label: fp.label(),
        });
        let did = identity::derive_did(&pk).unwrap().to_string();
        let fp = fingerprint::fingerprint_did(&did);
        req_007.push(FingerprintVector {
            input: did,
            kind: "did".to_owned(),
            hex: fp.hex(),
            label: fp.label(),
        });
    }

    Vectors {
        spec: "SPEC-001 v0.3.0".to_owned(),
        did_crdt_revision: "9a53bff1ed3eb88680fe19db0366ffd13d6b240a".to_owned(),
        con_007_root_derivation: con_007,
        adr_010_did_derivation: adr_010,
        con_001_link_code: con_001,
        con_002_rendezvous: con_002,
        req_007_fingerprints: req_007,
    }
}

#[test]
fn the_published_vectors_still_describe_this_build() {
    let published = std::fs::read_to_string(VECTORS_PATH).unwrap_or_else(|e| {
        panic!(
            "{VECTORS_PATH} is missing ({e}). Gate condition B requires published \
             vectors; run `cargo test -p selfsame-core --test vectors -- --ignored \
             regenerate` to create them, and understand that doing so after anything \
             has shipped re-derives every existing identity."
        )
    });
    let published: Vectors = serde_json::from_str(&published).expect("vectors file is valid JSON");
    let current = build();

    // Compare section by section so a failure names which contract moved.
    assert_eq!(
        published.did_crdt_revision, current.did_crdt_revision,
        "the ADR-010 pin in the vectors file disagrees with the one this build asserts"
    );
    assert_eq!(published.con_007_root_derivation, current.con_007_root_derivation, "CON-007");
    assert_eq!(published.adr_010_did_derivation, current.adr_010_did_derivation, "ADR-010");
    assert_eq!(published.con_001_link_code, current.con_001_link_code, "CON-001");
    assert_eq!(published.con_002_rendezvous, current.con_002_rendezvous, "CON-002");
    assert_eq!(published.req_007_fingerprints, current.req_007_fingerprints, "REQ-007");
}

#[test]
fn every_published_code_is_the_specified_length() {
    // TEST-031, checked against the published file rather than against a
    // freshly-computed value, so the file itself is the artefact under test.
    let published: Vectors =
        serde_json::from_str(&std::fs::read_to_string(VECTORS_PATH).unwrap()).unwrap();
    for v in &published.con_001_link_code {
        assert_eq!(v.length, code::CODE_CHARS, "{}", v.code);
        assert!(v.length <= 64, "NFR-004 bound");
    }
}

#[test]
#[ignore = "regenerating after anything ships re-derives every existing identity"]
fn regenerate() {
    let json = serde_json::to_string_pretty(&build()).unwrap();
    std::fs::create_dir_all("../../test-vectors").unwrap();
    std::fs::write(VECTORS_PATH, json + "\n").unwrap();
    eprintln!("wrote {VECTORS_PATH}");
}
