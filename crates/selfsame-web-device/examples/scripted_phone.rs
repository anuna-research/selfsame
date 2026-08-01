//! The phone, scripted — EXP-002 layer two's counterparty.
//!
//! Layer three replaces this whole program with the real application in an
//! emulator. Until then something has to play the phone, and it has to play it
//! with `selfsame-core` rather than a JavaScript approximation: the point of
//! the harness is that one implementation of the offer format, the slot
//! derivation and the grant is exercised from both ends, and a second phone
//! written in the driver would be exactly the thing `CON-205` forbids.
//!
//! It does what a person does after typing the code: read the offer out of the
//! slot the code addresses, mint an identity, add the offering device to it,
//! publish the deltas, and seal the grant into the reply slot.
//!
//! ```text
//! cargo run -p selfsame-web-device --example scripted_phone -- <base> <code>
//! ```
//!
//! Prints the DID it published, on stdout, alone — so the driver can compare it
//! against what the browser independently reports without parsing prose.

use std::process::ExitCode;

use ed25519_dalek::SigningKey;

use selfsame_core::code::LinkCode;
use selfsame_core::record::Grant;
use selfsame_core::{identity, seal};

/// The root key this fixture mints identities under.
///
/// Fixed, and published in the source. A scripted phone that drew a real key
/// would be creating an identity nobody can account for; a fixed one is
/// obviously a fixture to anyone who finds a DID from it in a log.
const ROOT_SEED: [u8; 32] = [0x41; 32];

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [base, code] = args.as_slice() else {
        eprintln!("usage: scripted_phone <rendezvous-base-url> <link-code>");
        return ExitCode::FAILURE;
    };

    match authorise(base, code) {
        Ok(did) => {
            println!("{did}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("scripted_phone: {e}");
            ExitCode::FAILURE
        }
    }
}

fn authorise(base: &str, code: &str) -> Result<String, String> {
    // The code is recognised by the core's own parser, which is the same
    // parser the wallet uses. A code this refuses is one the wallet would
    // refuse, and finding that out here rather than three steps later is the
    // whole reason to parse before acting.
    let link = LinkCode::parse(code).map_err(|e| format!("the link code is not valid: {e}"))?;
    let secret = *link.secret.as_bytes();

    let http = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("building the HTTP client: {e}"))?;

    // ── read the offer the browser wrote ────────────────────────────────────
    let sealed = http
        .get(format!("{base}/rendezvous/{}", seal::slot(seal::Role::Offer, &secret)))
        .send()
        .map_err(|e| format!("reading the offer: {e}"))?;
    if !sealed.status().is_success() {
        return Err(format!("no offer in the slot ({})", sealed.status()));
    }
    let sealed = sealed.bytes().map_err(|e| format!("reading the offer body: {e}"))?;

    let plaintext = seal::open_offer(&seal::derive_key(&secret), &sealed)
        .map_err(|e| format!("the offer did not open: {e}"))?;
    let offer = selfsame_core::record::Offer::parse(&plaintext)
        .map_err(|e| format!("the offer did not verify: {e}"))?;

    // ── mint an identity and admit the device ───────────────────────────────
    let root = SigningKey::from_bytes(&ROOT_SEED);
    let (mut doc, genesis) =
        identity::sign_genesis(&root).map_err(|e| format!("genesis: {e}"))?;
    let did = doc.did.to_string();

    let add = identity::add_device(&doc, &root, &offer.device_key, "dev-1", now() * 1_000)
        .map_err(|e| format!("adding the device: {e}"))?;
    doc.merge_verified_delta(add.clone()).map_err(|e| format!("merging the add: {e}"))?;

    let method_id = format!("{did}#dev-1");
    let label = identity::set_device_label(
        &doc,
        &root,
        &method_id,
        &offer.device_description,
        now() * 1_000 + 1,
    )
    .map_err(|e| format!("labelling the device: {e}"))?;
    doc.merge_verified_delta(label.clone()).map_err(|e| format!("merging the label: {e}"))?;

    // ── publish, in causal order ────────────────────────────────────────────
    for delta in [&genesis, &add, &label] {
        let response = http
            .post(format!("{base}/dids/{did}/deltas"))
            .json(delta)
            .send()
            .map_err(|e| format!("publishing: {e}"))?;
        if response.status() != 202 {
            return Err(format!("the rendezvous refused a delta ({})", response.status()));
        }
    }

    // ── seal the reply into the *other* slot ────────────────────────────────
    let deltas: Vec<Vec<u8>> = [genesis, add, label]
        .iter()
        .map(|d| serde_json::to_vec(d).expect("a signed delta serialises"))
        .collect();
    let grant = Grant::new(did.clone(), deltas);
    let bundle =
        seal::seal_bundle(&seal::derive_key(&secret), &grant.to_bytes(), &offer.transcript());

    let put = http
        .put(format!("{base}/rendezvous/{}", seal::slot(seal::Role::Bundle, &secret)))
        .body(bundle)
        .send()
        .map_err(|e| format!("writing the reply: {e}"))?;
    if !put.status().is_success() {
        return Err(format!("the rendezvous refused the reply ({})", put.status()));
    }

    Ok(did)
}
