//! The purity gate — SPEC-001 §13, NFR-006, TEST-033.
//!
//! > `selfsame-core` is `#![forbid(unsafe_code)]` with no `tokio`, `reqwest`,
//! > `std::fs`, or `std::time` in its dependency graph.
//!
//! Stated in the spec, enforced here. The dependency half is checked with
//! `cargo tree`; the source half with a scan of the crate's own modules. Both
//! are cheap and both fail loudly, which is the point: a purity boundary that
//! is only a convention stops being a boundary the first time someone is in a
//! hurry.
//!
//! TEST-033's negative-output — *any network call inside the pure core ⇒ fail* —
//! is what the dependency scan buys: `accept` cannot make a network call if no
//! crate that could make one is linked.

use std::process::Command;

/// Crates whose presence in the graph would contradict SPEC-001 §13.
const FORBIDDEN_CRATES: &[&str] = &[
    "tokio",
    "reqwest",
    "hyper",
    "axum",
    "async-std",
    "smol",
    "mio",
    "socket2",
    "rustls",
    "native-tls",
];

#[test]
fn no_effectful_crate_is_in_the_dependency_graph() {
    let output = Command::new(env!("CARGO"))
        .args([
            "tree",
            "-p",
            "selfsame-core",
            "--edges",
            "normal",
            "--prefix",
            "none",
            "--no-dedupe",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree runs");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let tree = String::from_utf8_lossy(&output.stdout);

    for line in tree.lines() {
        let name = line.split_whitespace().next().unwrap_or_default();
        assert!(
            !FORBIDDEN_CRATES.contains(&name),
            "SPEC-001 §13 purity boundary breached: `{name}` is in selfsame-core's \
             normal dependency graph. The pure core must be linkable into wasm, the \
             phone, and the hub without dragging in I/O."
        );
    }
    // Sanity: the scan actually saw a graph.
    assert!(tree.contains("did-crdt"), "cargo tree produced no recognisable graph");
}

#[test]
fn no_module_reaches_for_a_clock_a_filesystem_or_a_network() {
    // The core never reads a clock: `now` is injected as `UnixSeconds` so every
    // time-dependent decision is reproducible in a test.
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let forbidden = [
        "std::fs",
        "std::net",
        "std::time",
        "SystemTime",
        "Instant::now",
        "std::process",
        "std::env",
    ];

    let mut checked = 0usize;
    for entry in std::fs::read_dir(&src).expect("src/ is readable") {
        let path = entry.expect("readable entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("module is readable");
        // Strip the test module: dev-only code may use whatever it likes, and
        // this very file is proof of that.
        let production = match text.find("\n#[cfg(test)]") {
            Some(i) => &text[..i],
            None => &text[..],
        };
        for needle in forbidden {
            assert!(
                !production.contains(needle),
                "{} uses `{needle}` — SPEC-001 §13 puts effects in the shell",
                path.display()
            );
        }
        checked += 1;
    }
    assert!(checked >= 9, "expected to scan every core module, saw {checked}");
}

#[test]
fn unsafe_code_is_forbidden_at_the_crate_root() {
    let lib = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
    )
    .unwrap();
    assert!(lib.contains("#![forbid(unsafe_code)]"));
}
