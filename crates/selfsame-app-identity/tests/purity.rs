//! The purity gate — inherited from SPEC-001 §13 and load-bearing for SPEC-004.
//!
//! `CON-206` is **one** authorization predicate. A phone, a CLI, an application
//! backend, and a browser verifier must each apply it and reach the same
//! answer, so it is written once and linked everywhere — and that is only
//! possible if it drags in no I/O. This test is what keeps that true.
//!
//! It also underwrites two claims made elsewhere that would otherwise rest on
//! narration:
//!
//! - `TEST-203`'s "zero semantic action on every rejection — no probe, no
//!   derivation, **no network request**". No network-capable crate is in the
//!   graph, so no code path in this crate can make one, accepted or rejected.
//! - `TEST-216`'s "assert that no DNS lookup or connection targets an
//!   Anuna/Selfsame endpoint". The core cannot resolve a name at all, so the
//!   obligation reduces to the shell — where it is a much smaller surface to
//!   audit.
//!
//! `REQ-210`'s prohibition on an undeclared fallback is checked here too, from
//! the other side: no Anuna or Selfsame production endpoint appears as a literal
//! anywhere in the crate's sources, so there is nothing for a degraded profile
//! to fall back *to*.

use std::process::Command;

/// Crates whose presence in the graph would contradict the purity boundary.
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
    "ureq",
    "curl",
];

#[test]
fn no_effectful_crate_is_in_the_dependency_graph() {
    let output = Command::new(env!("CARGO"))
        .args([
            "tree",
            "-p",
            "selfsame-app-identity",
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
            "purity boundary breached: `{name}` is in selfsame-app-identity's normal \
             dependency graph. CON-206 must be linkable into wasm, the phone, and an \
             application backend without dragging in I/O."
        );
    }
    assert!(tree.contains("did-crdt"), "cargo tree produced no recognisable graph");
}

#[test]
fn no_module_reaches_for_a_clock_a_filesystem_or_a_network() {
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
        // this file is proof of that.
        let production = match text.find("\n#[cfg(test)]") {
            Some(i) => &text[..i],
            None => &text[..],
        };
        for needle in forbidden {
            assert!(
                !production.contains(needle),
                "{} uses `{needle}` — the shell owns effects, and `now` is injected as \
                 `UnixSeconds` so every time-dependent decision is reproducible",
                path.display()
            );
        }
        checked += 1;
    }
    assert!(checked >= 7, "expected to scan every core module, saw {checked}");
}

/// `REQ-210`: "The SDK SHALL NOT contain a production Anuna rendezvous,
/// account, state, or status-projection endpoint that is consulted when the
/// application profile is missing or unhealthy."
///
/// `CON-201` permits an application to *declare* `https://state.anuna.io` as one
/// resolver among several — an Anuna node a developer chooses is fine. What is
/// forbidden is one the SDK reaches for on its own. The distinction is a
/// property of where the string lives: a declared resolver arrives inside a
/// recognised profile at runtime, and a fallback would have to be compiled in.
#[test]
fn no_anuna_or_selfsame_endpoint_is_compiled_into_the_core() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    // The credential context IRI is `https://anuna.io/selfsame/credentials/...`
    // and is a *name*, not a locator: CON-224 forbids dereferencing it during
    // verification and NFR-204 forbids verification-time context loading. It is
    // allowed to appear, and `context.rs` is where it lives.
    let naming_only = "context.rs";

    for entry in std::fs::read_dir(&src).expect("src/ is readable") {
        let path = entry.expect("readable entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
        let text = std::fs::read_to_string(&path).expect("module is readable");
        let production = match text.find("\n#[cfg(test)]") {
            Some(i) => &text[..i],
            None => &text[..],
        };
        for line in production.lines() {
            // Comments name these hosts when explaining the rule; only code may
            // not carry them.
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("//!") {
                continue;
            }
            for host in ["anuna.io", "selfsame.dev", "state.anuna.io"] {
                if line.contains(host) && name != naming_only {
                    panic!(
                        "{name} compiles in `{host}`. REQ-210 forbids an endpoint the SDK \
                         consults when a profile is missing or unhealthy; a declared \
                         resolver arrives in a recognised profile at runtime instead."
                    );
                }
            }
        }
    }
}

#[test]
fn unsafe_code_is_forbidden_at_the_crate_root() {
    let lib = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
    )
    .unwrap();
    assert!(lib.contains("#![forbid(unsafe_code)]"));
    assert!(lib.contains("#![deny(missing_docs)]"));
}
