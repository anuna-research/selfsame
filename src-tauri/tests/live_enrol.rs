//! The wallet's acceptance decision on a LIVE first-contact enrolment offer.
//!
//! This is the custody-free half of `cbcl_enrol_start`: fetch the offer the
//! browser allocator wrote to the rendezvous, authenticate the application
//! profile live from its own `applicationId` (CON-220), and run the pure
//! `authorise` decision — the same decision the consent screen shows. It stops
//! exactly where REQ-024's presence gate begins: signing the grant needs the
//! person's passcode and the keychain, which is deliberately a human step.
//!
//! `#[ignore]`d because it needs a live link code from the deployed allocator.
//! Run:
//! ```sh
//! # 1. mint a code with the browser allocator against the live hub+rendezvous
//! # 2. then, immediately (the offer slot is read-once):
//! SELFSAME_CODE=anuna1… cargo test -p selfsame --test live_enrol -- --ignored --nocapture
//! ```

use selfsame_core::{code::LinkCode, seal};

#[tokio::test]
#[ignore]
async fn the_wallet_authorises_the_live_offer_to_consent() {
    let code = std::env::var("SELFSAME_CODE").expect("SELFSAME_CODE from the live allocator");
    let link = LinkCode::parse(&code).expect("a well-formed link code");
    let secret = *link.secret.as_bytes();

    // Fetch and open the sealed offer the allocator wrote (net points at the
    // deployed did.anuna.io rendezvous).
    let sealed = selfsame_lib::net::fetch_offer(link.application, &secret)
        .await
        .expect("the offer is present at its slot");
    let plaintext =
        seal::open_offer(&seal::derive_key(&secret), &sealed).expect("the offer opens");

    // Recognise it as a CON-219 offer and authenticate the profile live from the
    // offer's own applicationId — never from the offer or a cache.
    let offer = selfsame_app_identity::ceremony::recognise_offer(&plaintext)
        .expect("a recognised CON-219 offer");
    let application_id =
        selfsame_app_identity::profile::ApplicationId::parse(&offer.core.application_id)
            .expect("a canonical applicationId");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let fetched = selfsame_app_identity_net::profile::fetch(&application_id, now)
        .await
        .expect("the live profile is fetched and CON-220-authenticated");

    // Build the observation the manual path carries, then run the pure decision.
    let observed = selfsame_lib::app_grant::observation_for_enrolment_offer(&offer, &fetched.profile)
        .expect("the observation builds from the offer");
    let decided = selfsame_app_identity::authorise::authorise(
        &plaintext,
        &fetched.octets,
        &observed.as_observation(now),
    )
    .expect("the wallet AUTHORISES the live hub-signed offer to consent");

    println!("WALLET ACCEPTS THE LIVE OFFER:");
    println!("  application: {}", decided.profile.application_id.as_str());
    println!("  permissions: {:?}", decided.offer.requested_permissions);
    println!("  device did:  {}", decided.offer.device_did);
    println!("  (only the passcode-gated grant signature remains — the REQ-024 presence step)");
}
