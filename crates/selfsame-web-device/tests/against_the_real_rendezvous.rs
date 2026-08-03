//! The browser device client, against the real service and a real phone.
//!
//! EXP-002's harness has three layers, and this is the one that needs neither a
//! browser nor an emulator:
//!
//! | Layer | Device side | Phone side | Needs |
//! |---|---|---|---|
//! | this file | [`Device`] | scripted, in Rust | nothing |
//! | the page | [`Device`] in wasm | scripted, in Rust | a browser |
//! | the harness | [`Device`] in wasm | the real application | an emulator |
//!
//! Each layer swaps exactly one thing for its real counterpart, so a failure
//! says which half moved. That ordering is the point: by the time the emulator
//! is involved, everything except the emulator has already been proven, and a
//! red run means the wallet — not the wire, and not the wasm.
//!
//! `crates/selfsame-rendezvous/tests/end_to_end.rs` proves the *service* over
//! real HTTP with the CLI's logic inlined. This file proves the *browser
//! client's* logic against that same service, and it is a distinct claim: the
//! CLI holds a device key in a file and drives its own HTTP, while
//! [`Device`] holds nothing and drives nothing. What is shared is
//! `selfsame-core`, which is the property worth having — one offer format, one
//! slot derivation, one acceptance predicate, no second implementation to
//! disagree with the first.

use ed25519_dalek::SigningKey;

use selfsame_core::record::{Grant, Offer};
use selfsame_core::{identity, seal, OFFER_TTL_SECONDS};
use selfsame_web_device::{Device, DeviceError};

/// The instant every fixture is built around.
const NOW: u64 = 1_800_000_000;

struct Server {
    base: String,
    _handle: tokio::task::JoinHandle<()>,
}

async fn start() -> Server {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let addr = listener.local_addr().expect("has an address");
    let handle = tokio::spawn(async move {
        axum_serve(listener).await;
    });
    Server { base: format!("http://{addr}"), _handle: handle }
}

/// Kept separate so the `axum` version lives in one place.
async fn axum_serve(listener: tokio::net::TcpListener) {
    let router = selfsame_rendezvous::Service::new().router();
    let _ = axum::serve(listener, router).await;
}

/// What the browser does: draw a secret, build the client, write the offer.
///
/// The randomness is fixed here rather than drawn, because a test that cannot
/// reproduce its own failure is worth less than one that can. In the browser
/// this is `crypto.getRandomValues`.
async fn device_writes_its_offer(http: &reqwest::Client, base: &str, secret: [u8; 16]) -> Device {
    let device = Device::new(&secret, &[3u8; 32], "Chrome on a test bench", NOW + OFFER_TTL_SECONDS)
        .expect("well-formed inputs");

    let response = http
        .put(format!("{base}/rendezvous/{}", device.offer_slot()))
        .body(device.sealed_offer())
        .send()
        .await
        .expect("the rendezvous is up");
    assert_eq!(response.status(), 201, "the service accepted the slot name and the body");

    device
}

/// What the phone does, once the person has typed the code and tapped Authorise.
///
/// Lifted from `end_to_end.rs`'s helper, because the phone's behaviour is not
/// what this file is testing and a second version of it would be a second thing
/// to keep true. In layer three this whole function is replaced by the real
/// application in an emulator.
async fn phone_authorises(
    http: &reqwest::Client,
    base: &str,
    root: &SigningKey,
    offer: &Offer,
    secret: &[u8; 16],
) -> String {
    let (mut doc, genesis) = identity::sign_genesis(root).expect("genesis signs");
    let did = doc.did.to_string();

    let add = identity::add_device(&doc, root, &offer.device_key, "dev-1", NOW * 1_000)
        .expect("the device is added");
    doc.merge_verified_delta(add.clone()).expect("the add merges");

    let method_id = format!("{did}#dev-1");
    let label = identity::set_device_label(
        &doc,
        root,
        &method_id,
        &offer.device_description,
        NOW * 1_000 + 1,
    )
    .expect("the label signs");
    doc.merge_verified_delta(label.clone()).expect("the label merges");

    for delta in [&genesis, &add, &label] {
        let response = http
            .post(format!("{base}/dids/{did}/deltas"))
            .json(delta)
            .send()
            .await
            .expect("the rendezvous is up");
        assert_eq!(response.status(), 202, "publishing {:?}", delta.op);
    }

    let deltas: Vec<Vec<u8>> =
        [genesis, add, label].iter().map(|d| serde_json::to_vec(d).expect("serialises")).collect();
    let grant = Grant::new(did.clone(), deltas);
    let sealed =
        seal::seal_bundle(&seal::derive_key(secret), &grant.to_bytes(), &offer.transcript());

    let put = http
        .put(format!("{base}/rendezvous/{}", seal::slot(seal::Role::Bundle, secret)))
        .body(sealed)
        .send()
        .await
        .expect("the rendezvous is up");
    assert_eq!(put.status(), 201);

    did
}

/// Read the offer back out of the slot, the way the phone gets it.
async fn read_offer(http: &reqwest::Client, base: &str, secret: &[u8; 16]) -> Offer {
    let sealed = http
        .get(format!("{base}/rendezvous/{}", seal::slot(seal::Role::Offer, secret)))
        .send()
        .await
        .expect("the rendezvous is up")
        .bytes()
        .await
        .expect("a body");
    let plaintext =
        seal::open_offer(&seal::derive_key(secret), &sealed).expect("the phone holds the secret");
    Offer::parse(&plaintext).expect("REQ-018: the offer verifies on the phone")
}

#[tokio::test]
async fn the_browser_client_completes_a_link_against_the_real_service() {
    let server = start().await;
    let http = reqwest::Client::new();
    let secret = [11u8; 16];
    let root = SigningKey::from_bytes(&[0x41; 32]);

    let device = device_writes_its_offer(&http, &server.base, secret).await;

    // The person reads this off one screen and types it into the other. In the
    // harness the driver carries it between two ar-crawl sessions; here it is
    // asserted to be well formed, because a code no wallet can parse fails the
    // ceremony at a point no later assertion would explain.
    let code = device.link_code();
    assert_eq!(
        selfsame_core::code::LinkCode::parse(&code).expect("the wallet's parser accepts it").secret.as_bytes(),
        &secret,
    );

    let offer = read_offer(&http, &server.base, &secret).await;
    let did = phone_authorises(&http, &server.base, &root, &offer, &secret).await;

    // The device polls its own slot — a *different* slot from the offer's,
    // which is what lets the operator hold H(s) and never s.
    let sealed = http
        .get(format!("{}/rendezvous/{}", server.base, device.bundle_slot()))
        .send()
        .await
        .expect("the rendezvous is up")
        .bytes()
        .await
        .expect("a body");

    let accepted = device.accept(&sealed, NOW).expect("the reply is for this device");

    // Both parties independently arrived at the same identity. This is the
    // assertion the whole harness exists to make; layer three makes it with a
    // real wallet on the other side instead of `phone_authorises`.
    assert!(accepted.contains(&did), "the client resolved the DID the phone published: {accepted}");
    assert!(accepted.contains("\"fingerprintHex\":"), "and the value SCREEN-002 S3 compares");
    assert!(accepted.contains(&format!("{did}#dev-1")), "and its own verification method");
}

#[tokio::test]
async fn a_reply_sealed_for_another_device_is_refused() {
    // The app-side refusal, from the device's end: a bundle that is validly
    // sealed but binds a different offer must not link. `accept` is
    // `selfsame-core`'s and is tested there against every clause; what this
    // asserts is that the browser client actually *calls* it and does not treat
    // a well-formed-looking reply as success.
    let server = start().await;
    let http = reqwest::Client::new();
    let root = SigningKey::from_bytes(&[0x41; 32]);

    // Two devices, two secrets, two offers — and the phone answers the second.
    let ours = [11u8; 16];
    let theirs = [12u8; 16];
    let our_device = device_writes_its_offer(&http, &server.base, ours).await;
    let _their_device = device_writes_its_offer(&http, &server.base, theirs).await;

    let their_offer = read_offer(&http, &server.base, &theirs).await;
    phone_authorises(&http, &server.base, &root, &their_offer, &theirs).await;

    let their_sealed = http
        .get(format!("{}/rendezvous/{}", server.base, seal::slot(seal::Role::Bundle, &theirs)))
        .send()
        .await
        .expect("the rendezvous is up")
        .bytes()
        .await
        .expect("a body");

    assert_eq!(
        our_device.accept(&their_sealed, NOW).unwrap_err(),
        DeviceError::Refused,
        "a reply for another device must not link this one",
    );
}

#[tokio::test]
async fn an_expired_offer_does_not_link() {
    // The bounded half. `OFFER_TTL_SECONDS` is 300, so judging the reply five
    // minutes and one second later must refuse — otherwise a code left on a
    // screen stays live indefinitely, which is the whole reason the offer
    // carries an expiry rather than the rendezvous carrying a timer.
    let server = start().await;
    let http = reqwest::Client::new();
    let secret = [13u8; 16];
    let root = SigningKey::from_bytes(&[0x41; 32]);

    let device = device_writes_its_offer(&http, &server.base, secret).await;
    let offer = read_offer(&http, &server.base, &secret).await;
    phone_authorises(&http, &server.base, &root, &offer, &secret).await;

    let sealed = http
        .get(format!("{}/rendezvous/{}", server.base, device.bundle_slot()))
        .send()
        .await
        .expect("the rendezvous is up")
        .bytes()
        .await
        .expect("a body");

    assert!(device.accept(&sealed, NOW).is_ok(), "inside the window it links");
    assert_eq!(
        device.accept(&sealed, NOW + OFFER_TTL_SECONDS + 1).unwrap_err(),
        DeviceError::Refused,
        "past the window it does not",
    );
}
