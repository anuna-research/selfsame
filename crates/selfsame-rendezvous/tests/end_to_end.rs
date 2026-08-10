//! The whole loop, over HTTP — SPEC-001 TEST-020, TEST-025, TEST-036, HP-2.
//!
//! The unit tests in `selfsame-core` prove the predicate; this file proves the
//! three routes actually carry it. It runs the real axum service on a loopback
//! port and drives both endpoints through it: the client writes an offer, the
//! phone reads it, authorises, replies and publishes, and the client accepts.
//!
//! Integration-first (Constitutional Principle 5): a real server, real HTTP, no
//! mocks. The only thing simulated is the user tapping *Authorise*.

use selfsame_core::{
    accept, identity, profile, record::{Application, Grant, Offer}, seal, LinkContext,
    OFFER_TTL_SECONDS,
};
use selfsame_rendezvous::Service;
use did_crdt::core::delta::SignedDelta;
use ed25519_dalek::SigningKey;

struct Server {
    base: String,
    _handle: tokio::task::JoinHandle<()>,
}

async fn start() -> Server {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, Service::new().router()).await.unwrap();
    });
    Server { base: format!("http://{addr}"), _handle: handle }
}

fn root() -> SigningKey {
    SigningKey::from_bytes(&[0x11; 32])
}

fn device() -> SigningKey {
    SigningKey::from_bytes(&[0x22; 32])
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The phone's whole job: create the identity, authorise a device key, label
/// it, seal the grant, and publish every delta to the resolver (REQ-020).
async fn phone_authorises(
    http: &reqwest::Client,
    base: &str,
    offer: &Offer,
    secret: &[u8; 16],
) -> (String, Vec<u8>) {
    let root = root();
    let (mut doc, genesis) = identity::sign_genesis(&root).unwrap();
    let did = doc.did.to_string();

    let add =
        identity::add_device(&doc, &root, &offer.device_key, "dev-1", now() * 1_000).unwrap();
    doc.merge_verified_delta(add.clone()).unwrap();

    let method_id = format!("{did}#dev-1");
    let label = identity::set_device_label(
        &doc,
        &root,
        &method_id,
        &offer.device_description,
        now() * 1_000 + 1,
    )
    .unwrap();
    doc.merge_verified_delta(label.clone()).unwrap();

    // CON-006 — publication, in causal order, retried until acknowledged.
    for delta in [&genesis, &add, &label] {
        let response = http
            .post(format!("{base}/dids/{did}/deltas"))
            .json(delta)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 202, "publishing {:?}", delta.op);
    }

    let deltas: Vec<Vec<u8>> =
        [genesis, add, label].iter().map(|d| serde_json::to_vec(d).unwrap()).collect();
    let grant = Grant::new(did.clone(), deltas);
    let sealed =
        seal::seal_bundle(&seal::derive_key(secret), &grant.to_bytes(), &offer.transcript());

    let put = http
        .put(format!("{base}/rendezvous/{}", seal::slot(seal::Role::Bundle, secret)))
        .body(sealed.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 201);

    (did, sealed)
}

#[tokio::test]
async fn the_whole_happy_path_runs_over_the_three_routes() {
    let server = start().await;
    let http = reqwest::Client::new();
    let secret = [0x5au8; 16];

    // ── the client asks ──────────────────────────────────────────────────
    let offer = Offer::sign(
        Application::CbclChat,
        &device(),
        "Chrome on macOS",
        now() + OFFER_TTL_SECONDS,
    );
    let key = seal::derive_key(&secret);
    let offer_slot = seal::slot(seal::Role::Offer, &secret);
    let put = http
        .put(format!("{}/rendezvous/{offer_slot}", server.base))
        .body(seal::seal_offer(&key, &offer.to_bytes()))
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 201);

    // ── the phone reads the code and fetches the offer ───────────────────
    let fetched = http
        .get(format!("{}/rendezvous/{offer_slot}", server.base))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let opened = seal::open_offer(&key, &fetched).unwrap();
    let phone_side = Offer::parse(&opened).expect("REQ-018: the offer must verify on the phone");
    assert_eq!(phone_side, offer);
    assert_eq!(phone_side.device_description, "Chrome on macOS");

    // ── the phone authorises, replies, and publishes ─────────────────────
    let (did, _) = phone_authorises(&http, &server.base, &phone_side, &secret).await;

    // ── the client fetches and accepts ───────────────────────────────────
    let sealed = http
        .get(format!("{}/rendezvous/{}", server.base, seal::slot(seal::Role::Bundle, &secret)))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let accepted = accept(&sealed, &LinkContext { secret, offer }, now()).unwrap();
    assert_eq!(accepted.did, did);
    assert_eq!(accepted.own_method_id, format!("{did}#dev-1"));
    assert_eq!(
        accepted.device_labels.get(&accepted.own_method_id).map(String::as_str),
        Some("Chrome on macOS")
    );

    // ── TEST-025: a third party resolves the signed closure and verifies ──
    let closure: serde_json::Value = http
        .get(format!("{}/dids/{did}/closure", server.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let deltas: Vec<SignedDelta> = closure["deltas"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| serde_json::from_value(v.clone()).unwrap())
        .collect();
    assert_eq!(deltas.len(), 3, "TEST-020: every published delta appears in the closure");

    let root_pk = root().verifying_key().to_bytes();
    let document = profile::resolve_closure(&deltas, &root_pk).unwrap();
    let resolved = document.resolve().unwrap().did_document.unwrap();
    let wanted = identity::key_multibase(&device().verifying_key().to_bytes());
    assert!(resolved.verification_method.iter().any(|vm| vm.public_key_multibase.as_deref() == Some(wanted.as_str())));

    // ── HP-5: revoke, and the closure stops authorising the device ───────
    let revoke = identity::revoke_device(
        &document,
        &root(),
        &format!("{did}#dev-1"),
        now() * 1_000 + 2,
    )
    .unwrap();
    let response =
        http.post(format!("{}/dids/{did}/deltas", server.base)).json(&revoke).send().await.unwrap();
    assert_eq!(response.status(), 202);

    let closure: serde_json::Value = http
        .get(format!("{}/dids/{did}/closure", server.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let deltas: Vec<SignedDelta> = closure["deltas"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| serde_json::from_value(v.clone()).unwrap())
        .collect();
    let document = profile::resolve_closure(&deltas, &root_pk).unwrap();
    let resolved = document.resolve().unwrap().did_document.unwrap();
    assert!(
        !resolved.verification_method.iter().any(|vm| vm.public_key_multibase.as_deref() == Some(wanted.as_str())),
        "REQ-010: a revoked method must leave the authorised set"
    );
    // The label survives revocation, so the revoke screen can still name what
    // it revoked (REQ-021).
    assert_eq!(
        identity::device_label(&document, &format!("{did}#dev-1")).as_deref(),
        Some("Chrome on macOS")
    );
}

// ── CON-002 post-conditions ─────────────────────────────────────────────────

#[tokio::test]
async fn a_slot_is_single_write_and_read_once() {
    let server = start().await;
    let http = reqwest::Client::new();
    let slot = seal::slot(seal::Role::Offer, &[1u8; 16]);
    let url = format!("{}/rendezvous/{slot}", server.base);

    assert_eq!(http.put(&url).body("first".as_bytes()).send().await.unwrap().status(), 201);
    // Single-write: the operator cannot overwrite a record mid-exchange.
    assert_eq!(http.put(&url).body("second".as_bytes()).send().await.unwrap().status(), 409);

    let response = http.get(&url).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"first");
    // Read-once.
    assert_eq!(http.get(&url).send().await.unwrap().status(), 404);
}

#[tokio::test]
async fn the_rendezvous_refuses_oversized_and_malformed_slots() {
    let server = start().await;
    let http = reqwest::Client::new();
    let slot = seal::slot(seal::Role::Offer, &[2u8; 16]);

    let too_big = vec![0u8; selfsame_rendezvous::MAX_SLOT_BYTES + 1];
    let response = http
        .put(format!("{}/rendezvous/{slot}", server.base))
        .body(too_big)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);

    for bad in ["short", &"a".repeat(64), "UPPERCASE0123456789abcdef", "..%2f..%2fetc"] {
        let response = http
            .put(format!("{}/rendezvous/{bad}", server.base))
            .body("x".as_bytes())
            .send()
            .await
            .unwrap();
        assert!(
            response.status() == 400 || response.status() == 404,
            "{bad} produced {}",
            response.status()
        );
    }
}

// ── CON-006 post-conditions ─────────────────────────────────────────────────

#[tokio::test]
async fn publication_is_idempotent_and_refuses_a_forged_genesis() {
    let server = start().await;
    let http = reqwest::Client::new();
    let (_, genesis) = identity::sign_genesis(&root()).unwrap();
    let did = genesis.did.to_string();
    let url = format!("{}/dids/{did}/deltas", server.base);

    assert_eq!(http.post(&url).json(&genesis).send().await.unwrap().status(), 202);
    // Re-submitting identical bytes yields no duplicate state.
    assert_eq!(http.post(&url).json(&genesis).send().await.unwrap().status(), 409);

    let closure: serde_json::Value =
        http.get(format!("{}/dids/{did}/closure", server.base)).send().await.unwrap().json().await.unwrap();
    assert_eq!(closure["deltas"].as_array().unwrap().len(), 1);

    // A genesis whose DID does not commit to its own signer key is refused —
    // a structural check the store owes itself, not a trust decision.
    let (_, other) = identity::sign_genesis(&device()).unwrap();
    let response = http.post(&url).json(&other).send().await.unwrap();
    assert_eq!(response.status(), 400);

    // Garbage, and a delta for a DID that has no genesis yet.
    assert_eq!(
        http.post(&url).body("not json".as_bytes()).send().await.unwrap().status(),
        400
    );
    let orphan_did = identity::derive_did(&device().verifying_key().to_bytes()).unwrap();
    let response = http
        .post(format!("{}/dids/{orphan_did}/deltas", server.base))
        .json(&genesis)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400, "a delta must name the DID it is posted under");
}

#[tokio::test]
async fn an_unknown_did_has_no_closure() {
    let server = start().await;
    let http = reqwest::Client::new();
    let did = identity::derive_did(&device().verifying_key().to_bytes()).unwrap();
    let response =
        http.get(format!("{}/dids/{did}/closure", server.base)).send().await.unwrap();
    assert_eq!(response.status(), 404);

    let response =
        http.get(format!("{}/dids/did:web:example.com/closure", server.base)).send().await.unwrap();
    assert_eq!(response.status(), 404);
}
