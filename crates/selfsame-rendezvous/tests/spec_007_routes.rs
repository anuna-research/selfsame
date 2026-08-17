//! SPEC-007 TEST-810 evidence that retired credential-pairing routes stay absent.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use selfsame_rendezvous::Service;
use tower::ServiceExt as _;

#[tokio::test]
async fn removed_credential_pairing_routes_have_no_handler() {
    let application = Service::new().router();
    for (method, path) in [
        ("GET", "/pair/v1/healthz"),
        ("POST", "/pair/v1/sessions"),
        ("POST", "/pair/v1/sessions/123456/claim"),
        (
            "GET",
            "/proto002/rendezvous/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        (
            "GET",
            "/pairing/records/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
    ] {
        let response = application
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
    }
}
