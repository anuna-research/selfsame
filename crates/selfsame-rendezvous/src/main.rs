//! `selfsame-rendezvous` — run the three SPEC-001 routes locally.
//!
//! ```sh
//! cargo run -p selfsame-rendezvous            # binds 127.0.0.1:8787
//! SELFSAME_BIND=0.0.0.0:9000 cargo run -p selfsame-rendezvous
//! ```
//!
//! The default bind is loopback on purpose. This is a development service, and
//! a rendezvous reachable from the network is one more thing to reason about
//! than the SPEC-001 threat model currently covers.

use selfsame_rendezvous::Service;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "selfsame_rendezvous=info,tower_http=info".into()),
        )
        .init();

    let bind = std::env::var("SELFSAME_BIND").unwrap_or_else(|_| "127.0.0.1:8787".to_owned());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(
        %bind,
        "SPEC-001 rendezvous + resolver — blind mailbox, signed-closure resolution, publication"
    );
    axum::serve(listener, Service::new().router()).await?;
    Ok(())
}
