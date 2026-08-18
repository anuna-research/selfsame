//! SPEC-007 TEST-809 and TEST-810 legacy rejection evidence.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use selfsame_pairing::{
    decode_selfsame_invitation,
    legacy::{self, LegacyRejectionClass, LegacySurface},
    IntegrationError,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const SOURCE_REVISION: &str = "5f57a586e7dfa5be88c51f36a808fc60faf24c09";
const MANIFEST: &[u8] = include_bytes!("../../../test-vectors/spec-007-legacy/manifest.json");
const GENERATOR: &[u8] = include_bytes!("../../../test-vectors/spec-007-legacy/generate.py");

#[derive(Debug, Deserialize)]
struct Corpus {
    schema: String,
    #[serde(rename = "sourceRevision")]
    source_revision: String,
    generator: Generator,
    entries: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
struct Generator {
    command: String,
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct Entry {
    id: String,
    class: String,
    name: String,
    #[serde(rename = "recognitionSource")]
    recognition_source: String,
    surface: String,
    octets: Octets,
    sha256: String,
    expected: String,
    #[serde(rename = "permittedPreRejectionSideEffects")]
    permitted_effects: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Octets {
    Base64url(String),
    Repeated {
        #[serde(rename = "prefixBase64url")]
        prefix_base64url: String,
        #[serde(rename = "repeatByte")]
        repeat_byte: u8,
        #[serde(rename = "repeatCount")]
        repeat_count: usize,
    },
}

impl Octets {
    fn materialise(&self) -> Vec<u8> {
        match self {
            Self::Base64url(value) => Base64UrlUnpadded::decode_vec(value).expect("fixture b64url"),
            Self::Repeated {
                prefix_base64url,
                repeat_byte,
                repeat_count,
            } => {
                let mut value =
                    Base64UrlUnpadded::decode_vec(prefix_base64url).expect("fixture prefix");
                value.resize(value.len() + repeat_count, *repeat_byte);
                value
            }
        }
    }
}

fn corpus() -> Corpus {
    serde_json::from_slice(MANIFEST).expect("closed legacy manifest")
}

fn digest(input: &[u8]) -> String {
    Sha256::digest(input)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn surface(value: &str) -> LegacySurface {
    match value {
        "carrier" => LegacySurface::Carrier,
        "profile" => LegacySurface::Profile,
        "session-record" => LegacySurface::SessionRecord,
        "transport" => LegacySurface::Transport,
        other => panic!("unknown corpus surface {other}"),
    }
}

fn expected(value: &str) -> LegacyRejectionClass {
    match value {
        "PairingVersionUnsupported" => LegacyRejectionClass::PairingVersionUnsupported,
        "SurfaceUnavailable" => LegacyRejectionClass::SurfaceUnavailable,
        "RecognitionFailed" => LegacyRejectionClass::RecognitionFailed,
        other => panic!("unknown corpus result {other}"),
    }
}

#[test]
fn test_809_every_legacy_carrier_is_hash_bound_and_effect_free() {
    let corpus = corpus();
    for entry in corpus
        .entries
        .iter()
        .filter(|entry| matches!(entry.class.as_str(), "LEGACY-001" | "LEGACY-002"))
    {
        verify_entry(entry);
    }

    let canonical = corpus
        .entries
        .iter()
        .find(|entry| entry.id == "LEGACY-001-001")
        .expect("canonical human carrier")
        .octets
        .materialise();
    assert_eq!(
        decode_selfsame_invitation(&canonical),
        Err(IntegrationError::PairingVersionUnsupported)
    );
}

#[test]
fn test_810_every_legacy_record_and_route_is_hash_bound_and_effect_free() {
    let corpus = corpus();
    for entry in corpus.entries.iter().filter(|entry| {
        matches!(
            entry.class.as_str(),
            "LEGACY-003" | "LEGACY-004" | "LEGACY-005"
        )
    }) {
        verify_entry(entry);
    }
}

#[test]
fn test_809_810_manifest_has_exact_provenance_and_required_coverage() {
    let corpus = corpus();
    assert_eq!(corpus.schema, "selfsame-legacy-rejection-corpus-v1");
    assert_eq!(corpus.source_revision, SOURCE_REVISION);
    assert_eq!(
        corpus.generator.command,
        "python3 test-vectors/spec-007-legacy/generate.py --write"
    );
    assert_eq!(
        corpus.generator.path,
        "test-vectors/spec-007-legacy/generate.py"
    );
    assert_eq!(corpus.generator.sha256, digest(GENERATOR));

    let mut ids = BTreeSet::new();
    let mut class_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for entry in &corpus.entries {
        assert!(
            ids.insert(entry.id.as_str()),
            "duplicate fixture {}",
            entry.id
        );
        assert!(!entry.name.is_empty());
        assert!(!entry.recognition_source.is_empty());
        assert!(entry.permitted_effects.is_empty());
        *class_counts.entry(entry.class.as_str()).or_default() += 1;
    }
    assert_eq!(class_counts.get("LEGACY-001"), Some(&6));
    assert_eq!(class_counts.get("LEGACY-002"), Some(&6));
    assert_eq!(class_counts.get("LEGACY-003"), Some(&5));
    assert_eq!(class_counts.get("LEGACY-004"), Some(&7));
    assert_eq!(class_counts.get("LEGACY-005"), Some(&17));
}

fn verify_entry(entry: &Entry) {
    let octets = entry.octets.materialise();
    assert_eq!(digest(&octets), entry.sha256, "{} hash drift", entry.id);
    let rejection = legacy::reject(surface(&entry.surface), &octets);
    assert_eq!(rejection.class, expected(&entry.expected), "{}", entry.id);
    assert!(
        rejection.effects.is_empty(),
        "{} produced an effect",
        entry.id
    );
    assert!(
        entry.permitted_effects.is_empty(),
        "{} permits an effect",
        entry.id
    );
}
