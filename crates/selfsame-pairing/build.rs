use std::{env, fs, path::Path, process::Command};

const DEVELOPMENT_OVERRIDE: &str = "SELFSAME_ALLOW_UNPINNED_CBCL_PAIRING";

fn git(repo: &Path, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(arguments)
        .output()
        .map_err(|error| format!("could not execute git: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| format!("git emitted non-UTF-8 output: {error}"))
}

fn main() {
    println!("cargo:rerun-if-env-changed={DEVELOPMENT_OVERRIDE}");

    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest
        .parent()
        .and_then(Path::parent)
        .expect("selfsame-pairing must remain inside the Selfsame workspace");
    let parent = workspace
        .parent()
        .expect("Selfsame must have a parent directory");
    let mut pairing_revision = None;

    for (label, directory, pin_file) in [
        ("cbcl-pairing", "cbcl-pairing", "cbcl-pairing.sha"),
        ("cbcl-rs", "cbcl-rs", "cbcl-rs.sha"),
        ("did-crdt", "did-crdt", "did-crdt.sha"),
    ] {
        let pin_path = workspace.join(pin_file);
        let sibling = parent.join(directory);
        let expected = verify_dependency(label, &sibling, &pin_path);
        if label == "cbcl-pairing" {
            pairing_revision = Some(expected);
        }
    }

    println!(
        "cargo:rustc-env=SELFSAME_CBCL_PAIRING_REVISION={}",
        pairing_revision.expect("cbcl-pairing is in the dependency set")
    );
}

fn verify_dependency(label: &str, sibling: &Path, pin_path: &Path) -> String {
    println!("cargo:rerun-if-changed={}", pin_path.display());
    println!(
        "cargo:rerun-if-changed={}",
        sibling.join(".git/HEAD").display()
    );

    let expected = fs::read_to_string(pin_path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", pin_path.display()));
    let expected = expected.trim().to_owned();
    assert!(
        expected.len() == 40
            && expected
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{} must contain exactly one lowercase 40-hex revision",
        pin_path.display()
    );

    let actual = git(sibling, &["rev-parse", "HEAD"])
        .unwrap_or_else(|error| panic!("cannot identify {}: {error}", sibling.display()));
    let tracked_changes = git(sibling, &["status", "--porcelain", "--untracked-files=no"])
        .unwrap_or_else(|error| panic!("cannot inspect {}: {error}", sibling.display()));

    if actual == expected && tracked_changes.is_empty() {
        return expected;
    }

    let reason = if actual != expected {
        format!("expected {expected}, found {actual}")
    } else {
        "the pinned checkout has tracked modifications".to_owned()
    };

    if env::var(DEVELOPMENT_OVERRIDE).as_deref() == Ok("1") {
        println!(
            "cargo:warning=UNPINNED DEVELOPMENT BUILD: {label} {reason}; release evidence is invalid"
        );
        return expected;
    }

    panic!(
        "{label} source integrity check failed: {reason}. \
         Check out the revision in {} with no tracked modifications. \
         {DEVELOPMENT_OVERRIDE}=1 is permitted only for explicitly labelled local development builds.",
        pin_path.display()
    );
}
