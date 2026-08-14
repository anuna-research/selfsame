//! A whole `PROTO-003` pairing over real sockets.
//!
//! Everything before this ran in one process with no wire: the ciphersuite
//! agreed with itself, the envelope opened what it sealed, and
//! `crates/selfsame-web-device/tests/both_halves.rs` showed the two halves derive
//! the same secret. None of that is evidence that a frame crosses a socket, and
//! the parts most likely to be wrong — a base URL joined instead of appended, a
//! status mapped to the wrong outcome, a `404` polled forever, a body read before
//! its length is checked — are exactly the parts a same-process test cannot see.
//!
//! So this boots the reference provider on loopback and runs the ceremony
//! through it:
//!
//! ```text
//!   A  allocate ─────────────────▶ POST /pair/v1/sessions
//!   A  publish  ─────────────────▶ PUT  /pairing/records/{address}
//!   A  pA       ─────────────────▶ PUT  /pair/v1/sessions/{n}/pA
//!   B                              POST .../claim ─┐  ← selfsame's own client
//!   B                              GET  .../pA     │     from here down
//!   B  pB       ─────────────────▶ PUT  .../pB     │
//!   A  cA       ─────────────────▶ PUT  .../cA     │
//!   B                              GET  .../cA  ✓  │  verify, then
//!   B  cB       ─────────────────▶ PUT  .../cB     │  mailbox secret
//!   A  offer    ─────────────────▶ PUT  /proto002/rendezvous/{offer slot}
//!   B                              GET  ..............................  ✓ open
//!   B  bundle   ─────────────────▶ PUT  /proto002/rendezvous/{bundle slot}
//!   A                              GET  ..............................  ✓ open
//! ```
//!
//! # What is real and what stands in
//!
//! Role B is **`selfsame`'s own transport** — `pairing_net::Relay` and the
//! mailbox functions `pairing_answer` calls, in `CON-407`'s order, against a
//! server this test did not write into. Role A is the browser's wasm surface
//! driven over `reqwest`.
//!
//! What is NOT here is `read_pairing_code` and `pairing_answer` themselves. Both
//! are `#[tauri::command]`s taking `tauri::State`, and the first additionally
//! fetches an application profile from the canonical `applicationId` origin over
//! HTTPS — which a loopback test has no way to be. So the ceremony's *session
//! handling* is still only type-checked; what runs here is every wire it
//! touches.

use selfsame_core::envelope::EnvelopeKeys;
use selfsame_core::seal;
use selfsame_core::spake2::{Pairing as Spake2, Party};
use selfsame_lib::pairing_net::{self, Frame, Relay, RelayError};
use selfsame_web_device::{seal_offer_envelope_for, PairingCarrier, PairingSession};

/// The application's own profile digest and descriptor selection, which in a
/// real ceremony come from the profile it published. Fixed here because this
/// test is about the wires, and `CON-403` only requires both parties to hold the
/// same nine members — not that a test compute them twice.
const PROFILE_DIGEST: &str = "cHJvZmlsZS1kaWdlc3QtMzItb2N0ZXRzLWhlcmUtb2s";
const APPLICATION_ID: &str = "https://photos.example/selfsame/application";
const PROVIDER_ID: &str = "au-primary";

struct Provider {
    base: String,
    _handle: tokio::task::JoinHandle<()>,
}

async fn provider() -> Provider {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, selfsame_rendezvous::Service::new().router()).await.unwrap();
    });
    Provider { base: format!("http://{addr}"), _handle: handle }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// Role A's side of the relay, over plain `reqwest`.
///
/// Deliberately not `pairing_net`: using the client under test for both ends
/// would make the test agree with itself about anything the client gets wrong,
/// which is the whole failure mode a wire test exists to rule out.
struct Application {
    http: reqwest::Client,
    base: String,
    token: String,
    nameplate: String,
}

impl Application {
    async fn allocate(base: &str) -> Self {
        let http = reqwest::Client::new();
        let response =
            http.post(format!("{base}/pair/v1/sessions")).send().await.expect("allocate");
        assert_eq!(response.status(), 201, "CON-405: allocation is 201 Created");
        let body: serde_json::Value = response.json().await.unwrap();
        // "The object has exactly those four members."
        assert_eq!(body.as_object().unwrap().len(), 4);
        assert_eq!(body["version"], 1);
        assert_eq!(body["expiresInSeconds"], 600);
        let nameplate = body["nameplate"].as_str().unwrap().to_owned();
        assert_eq!(nameplate.len(), 6);
        assert!(nameplate.bytes().all(|b| b.is_ascii_digit()));
        Self {
            http,
            base: base.to_owned(),
            token: body["initiatorToken"].as_str().unwrap().to_owned(),
            nameplate,
        }
    }

    async fn put(&self, frame: &str, value: &[u8]) -> u16 {
        self.http
            .put(format!("{}/pair/v1/sessions/{}/{frame}", self.base, self.nameplate))
            .header("authorization", format!("Bearer {}", self.token))
            .header("content-type", "application/octet-stream")
            .body(value.to_vec())
            .send()
            .await
            .expect("frame write")
            .status()
            .as_u16()
    }

    async fn get(&self, frame: &str) -> Option<[u8; 32]> {
        let response = self
            .http
            .get(format!("{}/pair/v1/sessions/{}/{frame}", self.base, self.nameplate))
            .header("authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .expect("frame read");
        if response.status() != 200 {
            return None;
        }
        Some(response.bytes().await.unwrap().as_ref().try_into().unwrap())
    }
}

/// `CON-403`'s nine members, as both endpoints construct them.
fn binding_hash(nameplate: &str) -> [u8; 32] {
    selfsame_app_identity::pairing::BindingObject {
        application_id: APPLICATION_ID.into(),
        descriptor_digest: "ZGVzY3JpcHRvci1kaWdlc3QtMzItb2N0ZXRzLWhlcmU".into(),
        nameplate: nameplate.into(),
        number: format!("03{nameplate}"),
        profile_digest: PROFILE_DIGEST.into(),
        protocol: "selfsame-pairing-v1".into(),
        provider_id: PROVIDER_ID.into(),
        route: "03".into(),
        version: 1,
    }
    .binding_hash()
}

/// The whole ceremony, honest path, over sockets.
#[tokio::test]
async fn a_pairing_completes_over_real_sockets() {
    let provider = provider().await;
    let mailbox = format!("{}/proto002", provider.base);

    // ── role A: allocate, publish the record, write pA ───────────────────
    let a = Application::allocate(&provider.base).await;
    let carrier = PairingCarrier::from_entropy([0x5au8; 16]);
    let binding = binding_hash(&a.nameplate);

    // CON-409's record, published at an address derived from `C` alone.
    let envelope: serde_json::Value = serde_json::from_str(
        &carrier
            .publish(APPLICATION_ID, PROFILE_DIGEST, PROVIDER_ID, &a.nameplate, now(), 600)
            .expect("a publishable record"),
    )
    .unwrap();
    let published = a
        .http
        .put(format!("{}/pairing/records/{}", provider.base, carrier.meeting_address()))
        .json(&envelope)
        .send()
        .await
        .expect("publish");
    assert_eq!(published.status(), 201);

    // And a wallet resolves it from the code, with nothing passed along. This is
    // the step `read_pairing_code` performs; the command itself cannot run here
    // because its profile fetch needs an HTTPS origin.
    let resolved: serde_json::Value = a
        .http
        .get(format!("{}/pairing/records/{}", provider.base, carrier.meeting_address()))
        .send()
        .await
        .expect("resolve")
        .json()
        .await
        .unwrap();
    {
        use base64ct::Encoding as _;
        let payload =
            base64ct::Base64UrlUnpadded::decode_vec(resolved["payload"].as_str().unwrap()).unwrap();
        let signature: [u8; 64] =
            base64ct::Base64UrlUnpadded::decode_vec(resolved["signature"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
        let address =
            selfsame_app_identity::pairing_code::Code::from_octets([0x5au8; 16])
                .meeting_point()
                .address();
        let record = selfsame_app_identity::pairing_code::recognise_meeting_record(
            &address,
            &payload,
            &signature,
            now() as i64,
        )
        .expect("the record a wallet must accept");
        assert_eq!(record.nameplate, a.nameplate);
        assert_eq!(record.application_id, APPLICATION_ID);
    }

    let mut session_a: PairingSession =
        carrier.begin_pairing(&binding, &[0x22; 64]).expect("role A begins");
    assert_eq!(a.put("pA", &session_a.message()).await, 201);

    // ── role B: selfsame's own client, from here down ────────────────────
    let relay = Relay::at(&provider.base).expect("a relay client");
    relay
        .claim_when_ready(&a.nameplate, std::time::Duration::from_secs(5))
        .await
        .expect("the nameplate claims");

    let p_a = relay.get_frame(&a.nameplate, Frame::PA).await.expect("pA reads");
    let b = Spake2::begin(Party::Wallet, &[0x5au8; 16], &binding, &[0x33; 64]).unwrap();
    relay.put_frame(&a.nameplate, Frame::PB, &b.message()).await.expect("pB writes");

    // ── role A: read pB, write cA ────────────────────────────────────────
    let p_b = a.get("pB").await.expect("pB reads for role A");
    let c_a = session_a.confirm_for(&p_b).expect("role A confirms");
    assert_eq!(a.put("cA", &c_a).await, 201);

    // ── role B: verify cA, then write cB ─────────────────────────────────
    let confirmed = b.confirm(&p_a).expect("role B consumes pA");
    let c_b = confirmed.confirmation();
    let read_c_a = relay
        .await_frame(&a.nameplate, Frame::CA, std::time::Duration::from_secs(5))
        .await
        .expect("cA reads");
    assert_eq!(read_c_a, c_a, "the relay must pass cA through unaltered");
    let mutual = confirmed.verify_peer(&read_c_a).expect("cA verifies");
    relay.put_frame(&a.nameplate, Frame::CB, &c_b).await.expect("cB writes");
    let b_secret = mutual.mailbox_secret();

    // ── role A: verify cB, seal the offer, write it ──────────────────────
    let read_c_b = a.get("cB").await.expect("cB reads for role A");
    let a_secret = session_a.finish_for(&read_c_b).expect("cB verifies");
    assert_eq!(a_secret, b_secret, "CON-408: one secret from one exchange");

    let offer = br#"{"payloadVersion":1,"role":"offer","over":"a socket"}"#;
    let sealed = seal_offer_envelope_for(&a_secret, &binding, offer).unwrap();
    let offer_slot = seal::slot(seal::Role::Offer, &a_secret);
    let written = a
        .http
        .put(format!("{mailbox}/rendezvous/{offer_slot}"))
        .header("content-type", "application/octet-stream")
        .body(sealed.clone())
        .send()
        .await
        .expect("offer write");
    assert_eq!(written.status(), 201, "a 69,632-octet record must fit CON-304's bound");

    // ── role B: read the offer and open it ───────────────────────────────
    let fetched = pairing_net::await_slot(
        &mailbox,
        &seal::slot(seal::Role::Offer, &b_secret),
        std::time::Duration::from_secs(5),
    )
    .await
    .expect("the offer reads");
    assert_eq!(fetched, sealed);
    let opened = EnvelopeKeys::derive(&b_secret, &binding)
        .unwrap()
        .offer
        .open(&fetched)
        .expect("the offer opens");
    assert_eq!(opened, offer, "the wallet read the offer the application sealed");

    // ── role B: seal the bundle back ─────────────────────────────────────
    let bundle = br#"{"payloadVersion":1,"role":"bundle","over":"a socket"}"#;
    let sealed_bundle =
        EnvelopeKeys::derive(&b_secret, &binding).unwrap().bundle.seal(bundle).unwrap();
    pairing_net::put_slot(
        &mailbox,
        &seal::slot(seal::Role::Bundle, &b_secret),
        sealed_bundle.clone(),
    )
    .await
    .expect("the bundle writes");

    // ── role A: read it back and open it ─────────────────────────────────
    let returned = a
        .http
        .get(format!("{mailbox}/rendezvous/{}", seal::slot(seal::Role::Bundle, &a_secret)))
        .send()
        .await
        .expect("bundle read");
    assert_eq!(returned.status(), 200);
    let returned = returned.bytes().await.unwrap().to_vec();
    let opened = selfsame_web_device::open_bundle_envelope_for(&a_secret, &binding, &returned)
        .expect("the bundle opens");
    assert_eq!(opened, bundle, "the application read the bundle the wallet sealed");
}

/// The wallet arrives before the application has written `pA`, and waits.
///
/// The common case in practice — a person scans as soon as the code appears —
/// and the one that cannot be tested without a clock and a socket. `CON-405`
/// makes the pre-`pA` window observationally equal to an unknown nameplate, so
/// the client has nothing to distinguish "not yet" from "never" except its own
/// deadline.
#[tokio::test]
async fn the_wallet_waits_for_the_application_to_be_ready() {
    let provider = provider().await;
    let a = Application::allocate(&provider.base).await;
    let binding = binding_hash(&a.nameplate);
    let carrier = PairingCarrier::from_entropy([0x77u8; 16]);
    let mut session_a = carrier.begin_pairing(&binding, &[0x22; 64]).unwrap();

    // The claim goes out first and finds nothing.
    let relay = Relay::at(&provider.base).unwrap();
    assert_eq!(relay.claim(&a.nameplate).await, Err(RelayError::NotYet));

    let nameplate = a.nameplate.clone();
    let waiting = tokio::spawn(async move {
        relay.claim_when_ready(&nameplate, std::time::Duration::from_secs(10)).await
    });

    // `pA` lands a beat later, and the poll picks it up.
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    assert_eq!(a.put("pA", &session_a.message()).await, 201);

    waiting.await.unwrap().expect("the claim succeeds once pA exists");
    let _ = session_a.confirm_for(&[0u8; 32]);
}

/// A second wallet cannot take a claimed nameplate, and learns nothing by trying.
#[tokio::test]
async fn a_second_responder_is_refused() {
    let provider = provider().await;
    let a = Application::allocate(&provider.base).await;
    let carrier = PairingCarrier::from_entropy([0x99u8; 16]);
    let binding = binding_hash(&a.nameplate);
    let session_a = carrier.begin_pairing(&binding, &[0x22; 64]).unwrap();
    assert_eq!(a.put("pA", &session_a.message()).await, 201);

    let first = Relay::at(&provider.base).unwrap();
    first.claim(&a.nameplate).await.expect("the first claim succeeds");
    // An identical retry with the SAME token is `200`, per CON-405.
    first.claim(&a.nameplate).await.expect("an identical retry succeeds");

    // A different token is `409`, and the client burns rather than retrying.
    let second = Relay::at(&provider.base).unwrap();
    assert_eq!(second.claim(&a.nameplate).await, Err(RelayError::Conflict));
    // And it can read nothing: role tokens are not interchangeable.
    assert_eq!(second.get_frame(&a.nameplate, Frame::PA).await, Err(RelayError::NotYet));
}

/// `CON-405`: "A frame cannot be written before every preceding frame exists."
///
/// The relay enforces this as well as the clients, because a client cannot
/// enforce it against its peer — and a responder that published `cB` before
/// checking `cA` would hand a guesser a free MAC.
#[tokio::test]
async fn a_frame_cannot_jump_the_queue() {
    let provider = provider().await;
    let a = Application::allocate(&provider.base).await;
    let carrier = PairingCarrier::from_entropy([0xa1u8; 16]);
    let binding = binding_hash(&a.nameplate);
    let session_a = carrier.begin_pairing(&binding, &[0x22; 64]).unwrap();

    // `cA` before `pA` and `pB` exist.
    assert_eq!(a.put("cA", &[9u8; 32]).await, 409);
    assert_eq!(a.put("pA", &session_a.message()).await, 201);
    // Still too early: `pB` has not been written.
    assert_eq!(a.put("cA", &[9u8; 32]).await, 409);

    let relay = Relay::at(&provider.base).unwrap();
    relay.claim(&a.nameplate).await.unwrap();
    // And the responder cannot write `cB` before `cA` exists.
    assert_eq!(
        relay.put_frame(&a.nameplate, Frame::CB, &[9u8; 32]).await,
        Err(RelayError::Conflict),
    );
}

/// An immutable frame: identical retries succeed, a different value conflicts.
///
/// This is what makes a dropped response safe to retry, and it is the property
/// `CON-406` leans on when it permits a retry "only when the client can prove it
/// is byte-identical".
#[tokio::test]
async fn a_frame_is_immutable_and_a_retry_is_safe() {
    let provider = provider().await;
    let a = Application::allocate(&provider.base).await;
    let carrier = PairingCarrier::from_entropy([0xb2u8; 16]);
    let binding = binding_hash(&a.nameplate);
    let session_a = carrier.begin_pairing(&binding, &[0x22; 64]).unwrap();
    let p_a = session_a.message();

    assert_eq!(a.put("pA", &p_a).await, 201);
    assert_eq!(a.put("pA", &p_a).await, 200, "an identical retry is 200, not a conflict");
    assert_eq!(a.put("pA", &[0u8; 32]).await, 409, "a different value conflicts");
    // And a wrong length never reaches the store.
    assert_eq!(a.put("pA", &[0u8; 31]).await, 400);
}

/// The mailbox is repeatable, which SPEC-001's route is not.
///
/// `CON-305`: "The server returns the same bytes on every successful read before
/// expiry." A pairing served by a read-once mailbox loses its offer to any client
/// that retried after a dropped response — and the retry is the case the whole
/// polling design exists for.
#[tokio::test]
async fn the_pairing_mailbox_reads_more_than_once() {
    let provider = provider().await;
    let mailbox = format!("{}/proto002", provider.base);
    let secret = [0x3cu8; 16];
    let binding = [0x11u8; 32];
    let slot = seal::slot(seal::Role::Offer, &secret);

    let sealed = seal_offer_envelope_for(&secret, &binding, b"{}").unwrap();
    pairing_net::put_slot(&mailbox, &slot, sealed.clone()).await.expect("first write");
    // CON-304: an identical retry is acknowledged, not refused.
    pairing_net::put_slot(&mailbox, &slot, sealed.clone()).await.expect("identical retry");

    for _ in 0..3 {
        assert_eq!(pairing_net::fetch_slot(&mailbox, &slot).await.unwrap(), sealed);
    }

    // A different record for a written slot is a conflict the ceremony abandons.
    let other = seal_offer_envelope_for(&secret, &binding, b"{\"x\":1}").unwrap();
    assert_eq!(pairing_net::put_slot(&mailbox, &slot, other).await, Err(RelayError::Conflict));
}

/// A `PROTO-004` record is sixteen times SPEC-001's body bound, and the pairing
/// mailbox has to take it.
#[tokio::test]
async fn a_full_sized_record_fits_the_pairing_mailbox() {
    let provider = provider().await;
    let sealed = seal_offer_envelope_for(&[0x44u8; 16], &[0x55u8; 32], b"{}").unwrap();
    assert_eq!(sealed.len(), selfsame_core::envelope::SEALED_OCTETS);
    assert!(sealed.len() > selfsame_rendezvous::MAX_SLOT_BYTES);

    let slot = seal::slot(seal::Role::Offer, &[0x44u8; 16]);
    pairing_net::put_slot(&format!("{}/proto002", provider.base), &slot, sealed.clone())
        .await
        .expect("CON-304 accepts a full-sized record");

    // The SPEC-001 route refuses it, which is correct for that contract and is
    // why the two are served under different base URLs.
    let refused = reqwest::Client::new()
        .put(format!("{}/rendezvous/{slot}", provider.base))
        .body(sealed)
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 400);
}
