//! Print the deterministic local-demo allocator inputs as one JSON document.
//!
//! A browser allocator (the chat application's invite surface) needs the
//! fixture's transfer claims, credential bundle, profile octets, account, and
//! device key at its wasm boundary. Emitting them from the same
//! `local_demo::credential` the wallet rebuilds keeps both halves of a local
//! ceremony agreeing on one credential without a second fixture encoder.
//!
//! ```sh
//! cargo run -p selfsame-pairing --features local-pairing-demo \
//!   --example local-pairing-fixture -- https://localhost:7443
//! ```

use selfsame_app_identity::codec::b64url;
use selfsame_pairing::local_demo;

fn main() {
    let relay_origin = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://localhost:7443".into());
    let fixture = local_demo::credential(&relay_origin).expect("local demo credential");
    let profile = local_demo::profile_octets(&relay_origin);
    let document = serde_json::json!({
        "relayOrigin": relay_origin,
        "transfer": {
            "applicationId": fixture.transfer.application_id,
            "origin": fixture.transfer.origin,
            "scope": fixture.transfer.scope,
            "recipient": fixture.transfer.recipient,
        },
        "bundleB64u": b64url(&fixture.transfer.bundle),
        "profileB64u": b64url(&profile),
        "account": fixture.verification.account.as_str(),
        "devicePublicKeyB64u": b64url(&fixture.verification.device_public_key),
    });
    println!("{document}");
}
