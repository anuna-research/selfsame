//! Rendezvous and resolver access — SPEC-001 CON-002, CON-005, CON-006, REQ-026.
//!
//! # No attacker-supplied endpoints
//!
//! > **REQ-026.** The Rendezvous and Resolver hosts SHALL be resolved from the
//! > `application_id` against a table compiled into Selfsame, and SHALL NOT be
//! > taken from the link code or the offer.
//!
//! [`endpoint`] is that table. A URL in a scanned code is a phishing primitive,
//! so the code carries a secret and an application *identifier* — never an
//! address. The only override is an environment variable, which is a
//! development affordance under the operator's control, not a value that
//! reaches this process from a camera.

use selfsame_core::{record::Application, seal};
use did_crdt::core::delta::SignedDelta;
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("could not reach the {0} service")]
    Unreachable(&'static str),
    #[error("nothing at that address")]
    NotFound,
    #[error("that slot has already been written")]
    Conflict,
    #[error("the service refused the request")]
    Refused,
    #[error("the response was not what this build understands")]
    Malformed,
}

/// The compiled endpoint table (REQ-026).
pub fn endpoint(app: Application) -> String {
    if let Ok(base) = std::env::var("SELFSAME_ENDPOINT") {
        return base;
    }
    match app {
        Application::CbclChat => "https://rendezvous.cbcl.chat".to_owned(),
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("a default HTTP client always builds")
}

// ── CON-002 ─────────────────────────────────────────────────────────────────

/// Read the offer slot addressed by `H(s)`.
pub async fn fetch_offer(app: Application, secret: &[u8; 16]) -> Result<Vec<u8>, NetError> {
    let url = format!("{}/rendezvous/{}", endpoint(app), seal::slot(seal::Role::Offer, secret));
    let response =
        client().get(url).send().await.map_err(|_| NetError::Unreachable("rendezvous"))?;
    match response.status().as_u16() {
        200 => Ok(response.bytes().await.map_err(|_| NetError::Malformed)?.to_vec()),
        404 => Err(NetError::NotFound),
        _ => Err(NetError::Refused),
    }
}

/// Write the sealed credential bundle to the bundle slot.
pub async fn put_bundle(
    app: Application,
    secret: &[u8; 16],
    sealed: Vec<u8>,
) -> Result<(), NetError> {
    let url = format!("{}/rendezvous/{}", endpoint(app), seal::slot(seal::Role::Bundle, secret));
    let response = client()
        .put(url)
        .body(sealed)
        .send()
        .await
        .map_err(|_| NetError::Unreachable("rendezvous"))?;
    match response.status().as_u16() {
        201 => Ok(()),
        409 => Err(NetError::Conflict),
        _ => Err(NetError::Refused),
    }
}

// ── CON-006 ─────────────────────────────────────────────────────────────────

/// Publish one signed delta (REQ-020).
///
/// `409` is success from the caller's point of view: it means the delta is
/// already present, which is exactly what a retried publication should find.
/// Treating it as failure would make the retry loop of REQ-020 run forever.
pub async fn publish(app: Application, did: &str, delta: &SignedDelta) -> Result<(), NetError> {
    let url = format!("{}/dids/{did}/deltas", endpoint(app));
    let response = client()
        .post(url)
        .json(delta)
        .send()
        .await
        .map_err(|_| NetError::Unreachable("resolver"))?;
    match response.status().as_u16() {
        202 | 409 => Ok(()),
        400 => Err(NetError::Refused),
        _ => Err(NetError::Unreachable("resolver")),
    }
}

// ── CON-005 ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ClosureBody {
    deltas: Vec<serde_json::Value>,
}

/// Fetch the **signed delta set** for a DID (REQ-025).
///
/// Not a resolved document: a resolved document carries no signatures, so the
/// single-controller profile could not be applied to it and Selfsame would be
/// trusting the resolver's authorisation decisions. This is the route that
/// makes a restored phone able to list the devices it can revoke (REQ-021).
pub async fn fetch_closure(app: Application, did: &str) -> Result<Vec<SignedDelta>, NetError> {
    let url = format!("{}/dids/{did}/closure", endpoint(app));
    let response =
        client().get(url).send().await.map_err(|_| NetError::Unreachable("resolver"))?;
    match response.status().as_u16() {
        200 => {
            let body: ClosureBody = response.json().await.map_err(|_| NetError::Malformed)?;
            body.deltas
                .into_iter()
                .map(serde_json::from_value)
                .collect::<Result<_, _>>()
                .map_err(|_| NetError::Malformed)
        }
        404 | 410 => Err(NetError::NotFound),
        _ => Err(NetError::Refused),
    }
}
