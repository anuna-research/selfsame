use sha2::{Digest, Sha256};
use std::{path::PathBuf, process::Command};

const CANDIDATE_REVISION: &str = include_str!("../../../cbcl-pairing.sha");

#[test]
fn test_701_compiled_dependency_matches_the_pinned_candidate() {
    let baseline = selfsame_pairing::dependency_baseline();
    assert_eq!(baseline.revision, CANDIDATE_REVISION.trim());
    assert_eq!(
        baseline.bootstrap_source_sha256,
        cbcl_pairing::BOOTSTRAP_SOURCE_SHA256
    );
    assert_eq!(
        baseline.session_source_sha256,
        cbcl_pairing::SESSION_SOURCE_SHA256
    );

    let bootstrap: [u8; 32] = Sha256::digest(cbcl_pairing::BOOTSTRAP_DIALECT_SOURCE).into();
    let session: [u8; 32] = Sha256::digest(cbcl_pairing::SESSION_DIALECT_SOURCE).into();
    assert_eq!(hex(&bootstrap), cbcl_pairing::BOOTSTRAP_SOURCE_SHA256);
    assert_eq!(hex(&session), cbcl_pairing::SESSION_SOURCE_SHA256);

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let sibling = manifest
        .parent()
        .and_then(|crates| crates.parent())
        .and_then(|root| root.parent())
        .expect("workspace has a parent")
        .join("cbcl-pairing");
    let head = git(&sibling, &["rev-parse", "HEAD"]);
    assert!(head.status.success(), "sibling HEAD must be readable");
    assert_eq!(
        String::from_utf8_lossy(&head.stdout).trim(),
        CANDIDATE_REVISION.trim()
    );
    let tracked = git(&sibling, &["status", "--porcelain", "--untracked-files=no"]);
    assert!(
        tracked.status.success(),
        "sibling tracked status must be readable"
    );
    assert!(
        tracked.stdout.is_empty(),
        "pinned sibling checkout has tracked drift"
    );
}

fn git(sibling: &std::path::Path, arguments: &[&str]) -> std::process::Output {
    Command::new("git")
        .arg("-C")
        .arg(sibling)
        .args(arguments)
        .output()
        .expect("git is available for dependency provenance")
}

fn hex(input: &[u8]) -> String {
    input.iter().map(|byte| format!("{byte:02x}")).collect()
}
