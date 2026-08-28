//! REQ-1005: one source definition governs every profile-version consumer.

use std::{fs, path::Path};

fn rust_sources(path: &Path, files: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(path).expect("read source directory") {
        let entry = entry.expect("read source entry");
        let path = entry.path();
        if path.file_name().is_some_and(|name| name == "target") {
            continue;
        }
        if path.is_dir() {
            rust_sources(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

#[test]
fn req_1005_profile_version_has_one_workspace_definition() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate is inside the workspace");
    let mut files = Vec::new();
    rust_sources(workspace, &mut files);

    let mut definitions = Vec::new();
    for path in files {
        let source = fs::read_to_string(&path).expect("read Rust source");
        for (index, line) in source.lines().enumerate() {
            if line.trim_start().starts_with("pub const PROFILE_VERSION") {
                definitions.push(format!("{}:{}", path.display(), index + 1));
            }
        }
    }

    assert_eq!(
        definitions.len(),
        1,
        "PROFILE_VERSION must have one workspace definition: {definitions:?}"
    );
    assert!(
        definitions[0].contains("selfsame-app-identity/src/profile.rs:"),
        "the sole definition must be profile::PROFILE_VERSION: {definitions:?}"
    );
    assert_eq!(
        selfsame_app_identity::PROFILE_VERSION,
        selfsame_app_identity::profile::PROFILE_VERSION
    );
}
