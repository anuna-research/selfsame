#[path = "../../selfsame-app-identity/tests/common/mod.rs"]
mod fixture;
#[path = "web-demo/server.rs"]
mod server;

use selfsame_app_identity::{accept::Freshness, ceremony};
use selfsame_pairing::{
    CeremonyEntropy, CredentialTransfer, PendingTransfer, SelfsameProof,
    SelfsameVerificationContext,
};
use server::PendingFactory;
use std::{io::Write, sync::Arc};

fn verification(example: &fixture::Ceremony) -> SelfsameVerificationContext {
    SelfsameVerificationContext {
        profile: example.profile.clone(),
        account: example.account.clone(),
        device_public_key: example.device_public_key,
        operation_permissions: vec![fixture::PERMISSION.into()],
        now: example.now,
        clock_skew_seconds: 0,
        freshness: Freshness::SessionEstablishment,
        issuer: Some(example.issuer.clone()),
        jrd: Some(example.jrd.clone()),
        projection: None,
        proof: Some(SelfsameProof {
            challenge: example.challenge.clone(),
            signature: example.signature,
            verifier_session: fixture::VERIFIER_SESSION.into(),
        }),
    }
}

fn pending(
    entropy: CeremonyEntropy,
) -> Result<PendingTransfer, selfsame_pairing::IntegrationError> {
    let example = fixture::Ceremony::accepted();
    let mut grant = example.grant_bytes.clone();
    if std::env::var_os("SELFSAME_DEMO_TEST_VERIFIER_REFUSAL").is_some() {
        let last = grant.last_mut().expect("fixture grant is non-empty");
        *last = if *last == b'A' { b'B' } else { b'A' };
    }
    let bundle = ceremony::build_bundle(
        &selfsame_app_identity::codec::b64url(&[21; 32]),
        &selfsame_app_identity::codec::b64url(&[22; 32]),
        core::str::from_utf8(&grant).expect("fixture grant is UTF-8 JSON"),
        None,
    )
    .expect("fixed demo bundle is valid");
    PendingTransfer::new(
        CredentialTransfer {
            application_id: fixture::APPLICATION_ID.into(),
            origin: "https://photos.example".into(),
            scope: fixture::PERMISSION.into(),
            recipient: example.device_did.clone(),
            bundle,
        },
        verification(&example),
        entropy,
    )
}

#[tokio::main]
async fn main() {
    let mut arguments = std::env::args().skip(1);
    let address = match server::parse_loopback(arguments.next().as_deref()) {
        Ok(address) if arguments.next().is_none() => address,
        Ok(_) => {
            eprintln!("usage: web-demo [127.0.0.1:PORT]");
            std::process::exit(2);
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };
    let listener = match tokio::net::TcpListener::bind(address).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("failed to bind demo: {error}");
            std::process::exit(1);
        }
    };
    let selected = listener
        .local_addr()
        .expect("bound listener has an address");
    println!("Selfsame cbcl-pairing demo: http://{selected}/application");
    println!("Experimental — not production-approved");
    let _ = std::io::stdout().flush();
    let factory: PendingFactory = Arc::new(pending);
    if let Err(error) = server::serve(listener, factory).await {
        eprintln!("demo server failed: {error}");
        std::process::exit(1);
    }
}
