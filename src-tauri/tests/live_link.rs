//! The phone half of a link, against a **live** rendezvous — HP-2, end to end.
//!
//! `crates/selfsame-rendezvous/tests/end_to_end.rs` proves the protocol against
//! a server it starts itself. This proves *Selfsame's own* `net`, `identity`,
//! and `session` modules against a server it did not start, driven by a code a
//! real client minted — which is the last gap between "the tests pass" and "the
//! thing works".
//!
//! It is `#[ignore]`d because it needs two other processes running. Run it as:
//!
//! ```sh
//! cargo run -p selfsame-rendezvous &
//! SELFSAME_ENDPOINT=http://127.0.0.1:8787 cargo run -p selfsame-cli --bin selfsame -- link
//! # then, with the code it printed:
//! SELFSAME_ENDPOINT=http://127.0.0.1:8787 SELFSAME_CODE=anuna1… \
//!   cargo test -p selfsame --test live_link -- --ignored --nocapture
//! ```
//!
//! Note that a link code is good for **one** run: CON-002 makes the offer slot
//! read-once, so a second attempt with the same code finds nothing. That is the
//! contract, not a flake — mint a fresh code for each run.
//!
//! `custody` is deliberately not exercised here: it talks to the platform
//! keychain, which a test must not write to. Its own unit tests cover the
//! sealing, and the root key below stands in for the one it would unseal.

use selfsame_lib::{net, session::Session};
use selfsame_core::{
    identity,
    record::{Application, Grant, Offer},
    seal, LinkCode,
};
use ed25519_dalek::SigningKey;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
#[ignore = "needs a running rendezvous and a waiting client — see the module docs"]
async fn authorise_a_waiting_client() {
    let code = std::env::var("SELFSAME_CODE").expect("set SELFSAME_CODE to the client's code");

    // ── read the code ────────────────────────────────────────────────────
    let link = LinkCode::parse(&code).expect("that code isn't valid");
    let secret = *link.secret.as_bytes();
    let app = link.application;
    assert_eq!(app, Application::CbclChat);

    // ── fetch and verify the offer (REQ-018) ─────────────────────────────
    let sealed = net::fetch_offer(app, &secret).await.expect("no offer at that slot");
    let plaintext = seal::open_offer(&seal::derive_key(&secret), &sealed).expect("offer sealed");
    let offer = Offer::parse(&plaintext).expect("REQ-018: the offer must verify under its own key");
    println!("  application  {}", offer.application.slug());
    println!("  purpose      {}", offer.purpose);
    println!("  says it is   {}", offer.device_description);
    println!(
        "  fingerprint  {}",
        selfsame_core::fingerprint_key(&offer.device_key).hex()
    );
    assert!(now() <= offer.expiry, "the offer expired before we got to it");

    // ── the user taps Authorise ──────────────────────────────────────────
    //
    // In the app this is behind the REQ-024 presence check and the root key
    // comes out of the keychain. Here it is derived from the link code, which
    // gives a **fresh identity per run** while writing nothing to the platform
    // keystore. A fixed key would reuse one DID across runs, so the resolver
    // would accumulate deltas from previous links and every assertion about the
    // closure would drift.
    let root = SigningKey::from_bytes(blake3::hash(code.as_bytes()).as_bytes());
    let (mut document, genesis) = identity::sign_genesis(&root).unwrap();
    let did = document.did.to_string();
    println!("  identity     {did}");
    println!(
        "  fingerprint  {}  ← the client must show this",
        selfsame_core::fingerprint_did(&did).hex()
    );

    let ms = now() * 1_000;
    let add = identity::add_device(&document, &root, &offer.device_key, "dev-1", ms).unwrap();
    document.merge_verified_delta(add.clone()).unwrap();
    let method_id = format!("{did}#dev-1");
    let label =
        identity::set_device_label(&document, &root, &method_id, &offer.device_description, ms + 1)
            .unwrap();
    document.merge_verified_delta(label.clone()).unwrap();

    // ── reply, bound to this offer's transcript (REQ-006) ────────────────
    let deltas: Vec<Vec<u8>> =
        [&genesis, &add, &label].iter().map(|d| serde_json::to_vec(d).unwrap()).collect();
    let grant = Grant::new(did.clone(), deltas);
    let bundle =
        seal::seal_bundle(&seal::derive_key(&secret), &grant.to_bytes(), &offer.transcript());
    net::put_bundle(app, &secret, bundle).await.expect("could not write the bundle");
    println!("  bundle written");

    // ── publish (REQ-020) ────────────────────────────────────────────────
    for delta in [&genesis, &add, &label] {
        net::publish(app, &did, delta).await.expect("publication failed");
    }
    println!("  published    3 deltas");

    // ── the closure now answers for us (REQ-025, CON-005) ────────────────
    let closure = net::fetch_closure(app, &did).await.expect("closure not available");
    assert_eq!(closure.len(), 3, "the three deltas just published, and nothing else");
    let resolved = selfsame_core::profile::resolve_closure(&closure, &root.verifying_key().to_bytes())
        .expect("the closure must satisfy the single-controller profile")
        .resolve()
        .unwrap()
        .did_document
        .unwrap();
    let wanted = identity::key_multibase(&offer.device_key);
    assert!(
        resolved.verification_method.iter().any(|vm| vm.public_key_multibase == wanted),
        "REQ-015: the client's key must be authorised in the published closure"
    );
    println!("  verified     the client's key is authorised");

    // The session's own bookkeeping round-trips the same deltas.
    let mut s = Session::default();
    for delta in [&genesis, &add, &label] {
        s.record(delta);
    }
    assert_eq!(s.pending_count(), 3);
    for delta in [&genesis, &add, &label] {
        s.acknowledge(delta);
    }
    assert_eq!(s.pending_count(), 0);
    let devices = s.devices(&root.verifying_key().to_bytes()).unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].label.as_deref(), Some(offer.device_description.as_str()));
    println!("  devices      {} — {}", devices[0].method_id, devices[0].label.clone().unwrap());

    // ── HP-5, optionally, in the same run ────────────────────────────────
    //
    // Set SELFSAME_REVOKE=1 to unlink the device that was just linked. The
    // client is not consulted and does not need to be running: REQ-010's whole
    // point is that revocation needs only the root key.
    if std::env::var_os("SELFSAME_REVOKE").is_some() {
        let revoke = identity::revoke_device(&document, &root, &method_id, ms + 2).unwrap();
        net::publish(app, &did, &revoke).await.expect("revocation publish failed");

        let closure = net::fetch_closure(app, &did).await.unwrap();
        let after = selfsame_core::profile::resolve_closure(&closure, &root.verifying_key().to_bytes())
            .unwrap();
        let resolved = after.resolve().unwrap().did_document.unwrap();
        assert!(
            !resolved.verification_method.iter().any(|vm| vm.public_key_multibase == wanted),
            "REQ-010: a revoked method must leave the authorised set"
        );
        // REQ-021: the label survives revocation, so the revoke screen can name
        // what it revoked even on a phone restored from the mnemonic.
        assert_eq!(
            identity::device_label(&after, &method_id).as_deref(),
            Some(offer.device_description.as_str())
        );
        println!("  revoked      {method_id} — still named, no longer authorised");
    }
}
