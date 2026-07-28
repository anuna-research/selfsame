//! SPEC-002 TEST-110 — the pinned LifeHash crate still paints what Blockchain
//! Commons' reference implementation paints.
//!
//! `bc-lifehash` is pinned to `=0.1.0` in the workspace manifest, so the only
//! way the picture changes is a deliberate bump. This is the tripwire on that
//! bump: a LifeHash that silently changes is worse than no LifeHash, because it
//! teaches the user that the picture changing is normal — which is the one
//! thing it must never be allowed to mean.
//!
//! # What is compared, and why not the pixels
//!
//! `test-vectors/lifehash-v2.json` records a SHA-256 of each reference image
//! rather than its 3072 bytes. The full corpus is ~135 KB of JSON against ~5 KB
//! this way, for a test whose job is drift detection — and a digest detects
//! drift exactly. The file carries the upstream revision it came from, so the
//! full byte-level corpus can be re-derived by anyone who wants it.
//!
//! All 15 version-2 vectors are covered, including the module-size-2 and alpha
//! shapes Selfsame never asks for: they cost nothing here and they are the ones
//! most likely to catch a change in the crate that our own call shape misses.

use std::path::Path;

use serde_json::Value;
use sha2::{Digest as _, Sha256};

fn vectors() -> Value {
    // `../..` from `crates/selfsame-core` — the vectors sit beside SPEC-001's.
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors/lifehash-v2.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{} is readable: {e}", path.display()));
    serde_json::from_str(&text).expect("the vector file is valid JSON")
}

#[test]
fn the_pinned_crate_reproduces_the_reference_vectors() {
    let doc = vectors();
    assert_eq!(doc["version"], "version2", "this file covers version 2 only");
    let cases = doc["vectors"].as_array().expect("vectors is an array");
    assert_eq!(cases.len(), 15, "the full version-2 reference corpus");

    for (i, case) in cases.iter().enumerate() {
        let input = case["input"].as_str().expect("input is a string");
        let module_size = case["module_size"].as_u64().expect("module_size") as usize;
        let has_alpha = case["has_alpha"].as_bool().expect("has_alpha");

        let image = match case["input_type"].as_str().expect("input_type") {
            "utf8" => bc_lifehash::make_from_utf8(
                input,
                bc_lifehash::Version::Version2,
                module_size,
                has_alpha,
            ),
            "hex" => bc_lifehash::make_from_data(
                &hex::decode(input).expect("a hex vector decodes"),
                bc_lifehash::Version::Version2,
                module_size,
                has_alpha,
            ),
            other => panic!("vector {i}: unknown input_type {other}"),
        };

        assert_eq!(image.width as u64, case["width"].as_u64().unwrap(), "vector {i} width");
        assert_eq!(image.height as u64, case["height"].as_u64().unwrap(), "vector {i} height");

        // The spot check exists so a failure is legible without a hex dump:
        // the head almost always differs when the digest does, and it is the
        // first thing a human can eyeball against the reference.
        let head = hex::encode(&image.colors[..12]);
        assert_eq!(
            head,
            case["colors_head_hex"].as_str().unwrap(),
            "vector {i} ({input:?}): first four pixels diverge from the reference"
        );

        let digest = hex::encode(Sha256::digest(&image.colors));
        assert_eq!(
            digest,
            case["colors_sha256"].as_str().unwrap(),
            "vector {i} ({input:?}): the image diverges from Blockchain Commons' \
             reference implementation. If bc-lifehash was just bumped, that bump \
             changes every user's picture — see SPEC-002 ADR-101."
        );
    }
}

/// The shape Selfsame actually asks for, stated once so a reader of this file
/// knows which of the fifteen vectors above is the live path (SPEC-002 CON-101).
#[test]
fn selfsames_call_shape_is_thirty_two_squared_rgb() {
    use selfsame_core::fingerprint::{self, LIFEHASH_RGB_LEN, LIFEHASH_SIDE};

    let image = bc_lifehash::make_from_data(
        fingerprint::fingerprint_key(&[0u8; 32]).as_bytes(),
        bc_lifehash::Version::Version2,
        1,
        false,
    );
    assert_eq!(image.width, LIFEHASH_SIDE);
    assert_eq!(image.height, LIFEHASH_SIDE);
    assert_eq!(image.colors.len(), LIFEHASH_RGB_LEN);
}
