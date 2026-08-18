#[allow(dead_code)]
#[path = "../examples/web-demo/server.rs"]
mod demo_server;
#[path = "../../selfsame-app-identity/tests/common/mod.rs"]
mod fixture;

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, Response, StatusCode},
    Router,
};
use demo_server::{app, DemoConfig, PendingFactory};
use selfsame_app_identity::{accept::Freshness, ceremony};
use selfsame_pairing::{
    CeremonyEntropy, CredentialTransfer, PendingTransfer, SelfsameProof,
    SelfsameVerificationContext,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

const HOST: &str = "127.0.0.1:38123";
const ORIGIN: &str = "http://127.0.0.1:38123";

#[test]
fn test_709_demo_bind_parser_accepts_only_ipv4_loopback() {
    assert!(demo_server::parse_loopback(None).unwrap().ip().is_ipv4());
    assert!(demo_server::parse_loopback(Some("127.0.0.1:8800")).is_ok());
    assert!(demo_server::parse_loopback(Some("0.0.0.0:8800")).is_err());
    assert!(demo_server::parse_loopback(Some("[::1]:8800")).is_err());
}

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

#[derive(Clone, Debug)]
struct BrowserAuthority {
    cookie_name: &'static str,
    cookie: String,
    role: &'static str,
    capability: String,
    ceremony: Option<String>,
}

#[tokio::test]
async fn test_704_application_page_bootstraps_a_bound_session() {
    let router = router();
    let (authority, response, html) = page(&router, "/application").await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(authority.cookie.len(), 43);
    assert_eq!(authority.capability.len(), 43);
    let cookie = response.headers()["set-cookie"].to_str().unwrap();
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Strict"));
    assert!(cookie.contains("Path=/"));
    assert!(html.contains("Experimental"));
    assert!(html.contains("Not production-approved"));
    assert_security_headers(&response);
}

#[tokio::test]
async fn test_704_720_approved_flow_obeys_the_closed_role_matrix() {
    let router = router();
    let (mut application, _, application_html) = page(&router, "/application").await;
    let (mut wallet, _, wallet_html) = page(&router, "/wallet").await;
    assert_ne!(application.cookie, wallet.cookie);
    assert_ne!(application.cookie_name, wallet.cookie_name);
    assert_ne!(application.capability, wallet.capability);
    assert!(!application_html.contains("Review this request"));
    assert!(wallet_html.contains("Review this request"));

    let application_bootstrap = BrowserAuthority {
        cookie_name: application.cookie_name,
        cookie: application.cookie.clone(),
        role: application.role,
        capability: application.capability.clone(),
        ceremony: None,
    };
    let mut same_browser_start = mutation_request("/api/start", &application, "{}");
    same_browser_start.headers_mut().insert(
        header::COOKIE,
        format!("{}; {}", cookie(&application), cookie(&wallet))
            .parse()
            .unwrap(),
    );
    let (status, started) = mutation_response(&router, same_browser_start).await;
    assert_eq!(status, StatusCode::OK);
    adopt(&mut application, &started);
    assert_ne!(application.capability, application_bootstrap.capability);
    assert_eq!(
        mutation(&router, "/api/start", &application_bootstrap, json!({}))
            .await
            .0,
        StatusCode::UNAUTHORIZED,
        "successful start must retire the bootstrap capability"
    );
    let invitation = started["invitation"].as_str().unwrap().to_owned();
    assert_eq!(started["state"]["status"], "invitation-created");
    assert!(started["state"]["intent"].is_null());

    let (status, _) = mutation(&router, "/api/start", &wallet, json!({})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let other_application = page(&router, "/application").await.0;
    for (route, body) in [
        ("/api/claim", json!({ "invitation": invitation })),
        ("/api/start", json!({})),
    ] {
        let authority = if route == "/api/claim" {
            &other_application
        } else {
            &application
        };
        assert_eq!(
            mutation(&router, route, authority, body).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        mutation(
            &router,
            "/api/claim",
            &application,
            json!({ "invitation": invitation })
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );

    let wallet_bootstrap = BrowserAuthority {
        cookie_name: wallet.cookie_name,
        cookie: wallet.cookie.clone(),
        role: wallet.role,
        capability: wallet.capability.clone(),
        ceremony: None,
    };
    let (status, claimed) = mutation(
        &router,
        "/api/claim",
        &wallet,
        json!({ "invitation": invitation }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    adopt(&mut wallet, &claimed);
    assert_ne!(wallet.capability, wallet_bootstrap.capability);
    assert_eq!(
        mutation(
            &router,
            "/api/claim",
            &wallet_bootstrap,
            json!({ "invitation": invitation }),
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED,
        "successful claim must retire the bootstrap capability"
    );
    assert_eq!(wallet.ceremony, application.ceremony);
    assert_eq!(claimed["state"]["status"], "awaiting-decision");
    assert_eq!(claimed["state"]["version"], 2);
    assert_eq!(claimed["state"]["verification"]["selfsame_checks"], 0);
    assert_eq!(claimed["state"]["protocol"]["stage"], "awaiting-decision");
    assert_eq!(claimed["state"]["protocol"]["delivered_payloads"], 0);
    assert_eq!(
        claimed["state"]["protocol"]["allocator_secrets_erased"],
        false
    );
    assert!(
        claimed["state"]["intent"]["fields"]
            .as_array()
            .unwrap()
            .len()
            >= 4
    );

    for route in ["/api/approve", "/api/decline"] {
        assert_eq!(
            mutation(&router, route, &application, json!({ "version": 2 }))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }
    for (route, body) in [
        ("/api/start", json!({})),
        ("/api/claim", json!({ "invitation": invitation })),
    ] {
        assert_eq!(
            mutation(&router, route, &wallet, body).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    let unchanged = state(&router, &wallet).await;
    assert_eq!(unchanged["version"], 2);
    assert_eq!(unchanged["verification"]["selfsame_checks"], 0);

    let (status, _) = mutation_raw(
        &router,
        "/api/approve",
        &wallet,
        "{\"version\":2,\"version\":2}",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(state(&router, &wallet).await["version"], 2);

    let (status, accepted) =
        mutation(&router, "/api/approve", &wallet, json!({ "version": 2 })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(accepted["status"], "accepted");
    assert_eq!(accepted["verification"]["pairing_checks"], 1);
    assert_eq!(accepted["verification"]["selfsame_checks"], 1);
    assert_eq!(accepted["verification"]["accepted_steps"], 13);
    assert_eq!(accepted["protocol"]["stage"], "accepted");
    assert_eq!(accepted["protocol"]["delivered_payloads"], 1);
    assert_eq!(accepted["protocol"]["allocator_secrets_erased"], true);
    assert_eq!(accepted["protocol"]["claimant_secrets_erased"], true);
    assert_eq!(accepted["relay"]["retained_mailboxes"], 0);

    let (status, _) = mutation(&router, "/api/approve", &wallet, json!({ "version": 2 })).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(state(&router, &application).await["status"], "accepted");

    let old_wallet_capability = wallet.capability.clone();
    let (status, reset) = mutation(&router, "/api/reset", &wallet, json!({ "version": 3 })).await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(reset["capability"], old_wallet_capability);
    assert_eq!(
        state_status(&router, &wallet).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        state_status(&router, &application).await,
        StatusCode::UNAUTHORIZED,
        "reset must rotate the linked application capability too"
    );
    let rotated_wallet = BrowserAuthority {
        cookie_name: wallet.cookie_name,
        cookie: wallet.cookie.clone(),
        role: wallet.role,
        capability: reset["capability"].as_str().unwrap().to_owned(),
        ceremony: None,
    };
    assert_eq!(
        mutation(
            &router,
            "/api/claim",
            &rotated_wallet,
            json!({ "invitation": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }),
        )
        .await
        .0,
        StatusCode::BAD_REQUEST,
        "the returned reset capability must authorize the wallet bootstrap role"
    );
}

#[tokio::test]
async fn test_710_decline_is_terminal_and_releases_no_payload() {
    let router = router();
    let (mut application, _, _) = page(&router, "/application").await;
    let (mut wallet, _, _) = page(&router, "/wallet").await;
    let (_, started) = mutation(&router, "/api/start", &application, json!({})).await;
    adopt(&mut application, &started);
    let (_, claimed) = mutation(
        &router,
        "/api/claim",
        &wallet,
        json!({ "invitation": started["invitation"] }),
    )
    .await;
    adopt(&mut wallet, &claimed);

    let (status, declined) =
        mutation(&router, "/api/decline", &wallet, json!({ "version": 2 })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(declined["status"], "declined");
    assert_eq!(declined["verification"]["pairing_checks"], 0);
    assert_eq!(declined["verification"]["selfsame_checks"], 0);
    assert_eq!(declined["protocol"]["stage"], "declined");
    assert_eq!(declined["protocol"]["delivered_payloads"], 0);
    assert_eq!(declined["protocol"]["allocator_secrets_erased"], true);
    assert_eq!(declined["protocol"]["claimant_secrets_erased"], true);
    assert_eq!(declined["relay"]["retained_mailboxes"], 0);

    let outsider = page(&router, "/wallet").await.0;
    let (status, _) = mutation(
        &router,
        "/api/claim",
        &outsider,
        json!({ "invitation": started["invitation"] }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_712_720_invalid_http_inputs_are_effect_free() {
    let router = router();
    let (mut application, _, _) = page(&router, "/application").await;
    let (mut wallet, _, _) = page(&router, "/wallet").await;

    for request in [
        Request::builder()
            .method("POST")
            .uri("/api/start")
            .header(header::HOST, "localhost:38123")
            .header(header::ORIGIN, ORIGIN)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, cookie(&application))
            .header("x-selfsame-capability", &application.capability)
            .body(Body::from("{}"))
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri("/api/start")
            .header(header::HOST, HOST)
            .header(header::ORIGIN, "http://localhost:38123")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, cookie(&application))
            .header("x-selfsame-capability", &application.capability)
            .body(Body::from("{}"))
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri("/api/start")
            .header(header::HOST, HOST)
            .header(header::ORIGIN, ORIGIN)
            .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
            .header(header::COOKIE, cookie(&application))
            .header("x-selfsame-capability", &application.capability)
            .body(Body::from("{}"))
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri("/api/start")
            .header(header::HOST, HOST)
            .header(header::ORIGIN, ORIGIN)
            .header(header::CONTENT_TYPE, "application/json")
            .header(
                header::COOKIE,
                "selfsame_demo_application_session=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            )
            .header("x-selfsame-capability", &application.capability)
            .body(Body::from("{}"))
            .unwrap(),
    ] {
        assert_ne!(
            router.clone().oneshot(request).await.unwrap().status(),
            StatusCode::OK
        );
    }

    let wrong_authority = BrowserAuthority {
        cookie_name: application.cookie_name,
        cookie: application.cookie.clone(),
        role: application.role,
        capability: "wrong-capability".into(),
        ceremony: None,
    };
    let mut wrong_role = mutation_request("/api/start", &application, "{}");
    wrong_role
        .headers_mut()
        .insert("x-selfsame-role", "wallet".parse().unwrap());
    assert_eq!(
        mutation_response(&router, wrong_role).await.0,
        StatusCode::UNAUTHORIZED
    );
    let exact_head = mutation_request_with_head_octets(&wrong_authority, 16 * 1024);
    assert_eq!(request_head_octets(&exact_head), 16 * 1024);
    assert_eq!(
        router.clone().oneshot(exact_head).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let oversized_head = mutation_request_with_head_octets(&wrong_authority, 16 * 1024 + 1);
    assert_eq!(request_head_octets(&oversized_head), 16 * 1024 + 1);
    assert_eq!(
        router
            .clone()
            .oneshot(oversized_head)
            .await
            .unwrap()
            .status(),
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
    );

    let duplicate_cookie = Request::builder()
        .method("POST")
        .uri("/api/start")
        .header(header::HOST, HOST)
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, cookie(&application))
        .header(header::COOKIE, cookie(&application))
        .header("x-selfsame-role", application.role)
        .header("x-selfsame-capability", &application.capability)
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(
        router
            .clone()
            .oneshot(duplicate_cookie)
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );

    let (status, refusal) = mutation_raw(
        &router,
        "/api/start",
        &wrong_authority,
        "{\"unexpected\":1}",
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(refusal["error"], "unauthorized");

    let (status, _) = mutation_raw(&router, "/api/start", &application, "{\"unexpected\":1}").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = mutation_raw(
        &router,
        "/api/start",
        &application,
        &format!("{{\"x\":\"{}\"}}", "a".repeat(4_200)),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    let (status, started) = mutation(&router, "/api/start", &application, json!({})).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "invalid requests must not consume the capability"
    );
    assert_eq!(started["state"]["version"], 1);
    adopt(&mut application, &started);

    let (status, _) = mutation(
        &router,
        "/api/claim",
        &wallet,
        json!({ "invitation": "not-a-canonical-invitation" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, claimed) = mutation(
        &router,
        "/api/claim",
        &wallet,
        json!({ "invitation": started["invitation"] }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "malformed input must not consume wallet authority"
    );
    adopt(&mut wallet, &claimed);
}

#[tokio::test]
async fn test_720_public_bootstrap_sessions_are_hard_bounded() {
    let router = router();
    let mut authorities = vec![page(&router, "/application").await.0];
    for _ in 0..64 {
        authorities.push(page(&router, "/application").await.0);
    }
    let newest = authorities.pop().expect("newest session");
    assert_eq!(
        mutation(&router, "/api/start", &newest, json!({})).await.0,
        StatusCode::OK,
        "the bounded service must remain available"
    );
    let mut unauthorized = 0;
    for authority in authorities {
        unauthorized += usize::from(
            mutation(&router, "/api/start", &authority, json!({}))
                .await
                .0
                == StatusCode::UNAUTHORIZED,
        );
    }
    assert_eq!(
        unauthorized, 1,
        "exactly one unused bootstrap session must be evicted at the hard cap"
    );
}

#[tokio::test]
async fn test_721_concurrent_browser_authorities_cannot_cross() {
    let router = router();
    let (mut app_a, _, _) = page(&router, "/application").await;
    let (mut app_b, _, _) = page(&router, "/application").await;
    let (mut wallet_a, _, _) = page(&router, "/wallet").await;
    let (mut wallet_b, _, _) = page(&router, "/wallet").await;

    let (_, started_a) = mutation(&router, "/api/start", &app_a, json!({})).await;
    adopt(&mut app_a, &started_a);
    let (_, started_b) = mutation(&router, "/api/start", &app_b, json!({})).await;
    adopt(&mut app_b, &started_b);
    assert_ne!(app_a.ceremony, app_b.ceremony);

    let stolen = BrowserAuthority {
        cookie_name: app_a.cookie_name,
        cookie: app_a.cookie.clone(),
        role: app_a.role,
        capability: app_b.capability.clone(),
        ceremony: app_b.ceremony.clone(),
    };
    let (status, _) = mutation(&router, "/api/reset", &stolen, json!({ "version": 1 })).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (_, claimed_a) = mutation(
        &router,
        "/api/claim",
        &wallet_a,
        json!({ "invitation": started_a["invitation"] }),
    )
    .await;
    adopt(&mut wallet_a, &claimed_a);
    let (_, claimed_b) = mutation(
        &router,
        "/api/claim",
        &wallet_b,
        json!({ "invitation": started_b["invitation"] }),
    )
    .await;
    adopt(&mut wallet_b, &claimed_b);

    assert_eq!(
        mutation(&router, "/api/decline", &wallet_a, json!({ "version": 2 }))
            .await
            .1["status"],
        "declined"
    );
    assert_eq!(
        mutation(&router, "/api/approve", &wallet_b, json!({ "version": 2 }))
            .await
            .1["status"],
        "accepted"
    );
    assert_eq!(state(&router, &app_a).await["status"], "declined");
    assert_eq!(state(&router, &app_b).await["status"], "accepted");

    let (mut app_c, _, _) = page(&router, "/application").await;
    let (mut wallet_c, _, _) = page(&router, "/wallet").await;
    let (_, started_c) = mutation(&router, "/api/start", &app_c, json!({})).await;
    adopt(&mut app_c, &started_c);
    let (_, claimed_c) = mutation(
        &router,
        "/api/claim",
        &wallet_c,
        json!({ "invitation": started_c["invitation"] }),
    )
    .await;
    adopt(&mut wallet_c, &claimed_c);

    let approve = router.clone().oneshot(mutation_request(
        "/api/approve",
        &wallet_c,
        "{\"version\":2}",
    ));
    let decline = router.clone().oneshot(mutation_request(
        "/api/decline",
        &wallet_c,
        "{\"version\":2}",
    ));
    let (approve, decline) = tokio::join!(approve, decline);
    let mut statuses = [approve.unwrap().status(), decline.unwrap().status()];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::OK, StatusCode::CONFLICT]);
    let terminal = state(&router, &app_c).await;
    assert_eq!(terminal["version"], 3);
    assert!(matches!(
        terminal["status"].as_str(),
        Some("accepted" | "declined")
    ));
}

fn router() -> Router {
    let factory: PendingFactory = Arc::new(pending);
    app(
        DemoConfig {
            host: HOST.into(),
            origin: ORIGIN.into(),
        },
        factory,
    )
}

fn pending(
    entropy: CeremonyEntropy,
) -> Result<PendingTransfer, selfsame_pairing::IntegrationError> {
    let example = fixture::Ceremony::accepted();
    let bundle = ceremony::build_bundle(
        &selfsame_app_identity::codec::b64url(&[21; 32]),
        &selfsame_app_identity::codec::b64url(&[22; 32]),
        core::str::from_utf8(&example.grant_bytes).unwrap(),
        None,
    )
    .unwrap();
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

async fn page(router: &Router, route: &str) -> (BrowserAuthority, Response<Body>, String) {
    let (cookie_name, role) = match route {
        "/application" => ("selfsame_demo_application_session", "application"),
        "/wallet" => ("selfsame_demo_wallet_session", "wallet"),
        _ => panic!("page helper requires one demo endpoint"),
    };
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(route)
                .header(header::HOST, HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let cookie_pair = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let (actual_cookie_name, cookie_value) = cookie_pair.split_once('=').unwrap();
    assert_eq!(actual_cookie_name, cookie_name);
    let cookie_value = cookie_value.to_owned();
    let (parts, body) = response.into_parts();
    let bytes = to_bytes(body, 64 * 1024).await.unwrap();
    let html = String::from_utf8(bytes.to_vec()).unwrap();
    let marker = "<meta name=\"selfsame-bootstrap\" content=\"";
    let capability = html
        .split(marker)
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    let response = Response::from_parts(parts, Body::empty());
    (
        BrowserAuthority {
            cookie_name,
            cookie: cookie_value,
            role,
            capability,
            ceremony: None,
        },
        response,
        html,
    )
}

fn adopt(authority: &mut BrowserAuthority, response: &Value) {
    authority.capability = response["capability"].as_str().unwrap().to_owned();
    authority.ceremony = Some(response["ceremony_id"].as_str().unwrap().to_owned());
}

async fn mutation(
    router: &Router,
    route: &str,
    authority: &BrowserAuthority,
    value: Value,
) -> (StatusCode, Value) {
    mutation_raw(router, route, authority, &value.to_string()).await
}

async fn mutation_raw(
    router: &Router,
    route: &str,
    authority: &BrowserAuthority,
    body: &str,
) -> (StatusCode, Value) {
    mutation_response(router, mutation_request(route, authority, body)).await
}

async fn mutation_response(router: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    assert_security_headers(&response);
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    if !status.is_success() {
        assert!(
            value.get("error").and_then(Value::as_str).is_some(),
            "every mutation refusal must expose one safe JSON error token"
        );
    }
    (status, value)
}

fn mutation_request(route: &str, authority: &BrowserAuthority, body: &str) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(route)
        .header(header::HOST, HOST)
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, cookie(authority))
        .header("x-selfsame-role", authority.role)
        .header("x-selfsame-capability", &authority.capability);
    if let Some(ceremony) = &authority.ceremony {
        builder = builder.header("x-selfsame-ceremony", ceremony);
    }
    builder.body(Body::from(body.to_owned())).unwrap()
}

fn mutation_request_with_head_octets(authority: &BrowserAuthority, target: usize) -> Request<Body> {
    let mut request = mutation_request("/api/start", authority, "{}");
    request
        .headers_mut()
        .insert("x-padding", "".parse().unwrap());
    let current = request_head_octets(&request);
    let padding = target.checked_sub(current).expect("target fits fixed head");
    request.headers_mut().insert(
        "x-padding",
        "a".repeat(padding).parse().expect("ASCII header value"),
    );
    request
}

fn request_head_octets(request: &Request<Body>) -> usize {
    request.method().as_str().len()
        + request.uri().to_string().len()
        + 14
        + request
            .headers()
            .iter()
            .map(|(name, value)| name.as_str().len() + value.as_bytes().len() + 4)
            .sum::<usize>()
}

async fn state(router: &Router, authority: &BrowserAuthority) -> Value {
    let response = state_response(router, authority).await;
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap()
}

async fn state_status(router: &Router, authority: &BrowserAuthority) -> StatusCode {
    state_response(router, authority).await.status()
}

async fn state_response(router: &Router, authority: &BrowserAuthority) -> Response<Body> {
    router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/state")
                .header(header::HOST, HOST)
                .header(header::COOKIE, cookie(authority))
                .header("x-selfsame-role", authority.role)
                .header("x-selfsame-capability", &authority.capability)
                .header("x-selfsame-ceremony", authority.ceremony.as_ref().unwrap())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

fn cookie(authority: &BrowserAuthority) -> String {
    format!("{}={}", authority.cookie_name, authority.cookie)
}

fn assert_security_headers(response: &Response<Body>) {
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert!(response.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("default-src 'none'"));
}
