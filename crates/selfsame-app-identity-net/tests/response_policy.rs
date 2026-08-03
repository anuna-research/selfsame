//! The response policy, tested against real HTTP responses — `CON-213`,
//! `CON-220`.
//!
//! # The hole this closes
//!
//! `selfsame-app-identity` tests the *predicate*:
//! [`discovery::recognise_profile_response`] is handed an [`HttpResponse`]
//! struct and decides. That is thoroughly covered.
//!
//! What was not covered is the code that **builds** that struct from a
//! `reqwest::Response` — `has_content_encoding`, `media_type`,
//! `carried_cookies`, `bounded_body`, and the status inspection. Every claim
//! this crate makes about refusing redirects, compression, cookies, and
//! oversized bodies runs through those five functions, and until now they were
//! asserted rather than tested.
//!
//! A response is constructible without a server (`reqwest::Response:
//! From<http::Response<_>>`), so these are fast, deterministic, and exercise the
//! exact code path a real fetch takes. That is better than a live server for
//! this purpose: a server would test that *this* server behaves, and what needs
//! testing is that *any* response is read correctly.
//!
//! The one thing a constructed response cannot exercise is the client's
//! connection-level policy — `https_only` and `Policy::none()`. Those are
//! covered by [`refuses_plaintext_http`] against a real listener.

use std::time::Duration;

use selfsame_app_identity::discovery::{
    self, DiscoveryError, HttpResponse, MAX_BODY_OCTETS, PROFILE_MEDIA_TYPE,
};
use selfsame_app_identity::profile::ApplicationId;

/// Build a `reqwest::Response` with an exact status, headers, and body.
fn response(status: u16, headers: &[(&str, &str)], body: Vec<u8>) -> reqwest::Response {
    let mut builder = http::Response::builder().status(status);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    reqwest::Response::from(builder.body(body).expect("a well-formed response"))
}

fn json_headers() -> Vec<(&'static str, &'static str)> {
    vec![("content-type", PROFILE_MEDIA_TYPE)]
}

// ── content encoding ───────────────────────────────────────────────────────

#[tokio::test]
async fn a_compressed_response_is_seen_as_compressed() {
    // CON-213 and CON-220 step 3 both reject content encoding. This crate does
    // not compile in reqwest's decompression features, so an encoded body
    // arrives encoded and is observable — which is the whole reason those
    // features are absent.
    for encoding in ["gzip", "br", "deflate", "zstd", "GZIP", " gzip "] {
        let mut headers = json_headers();
        headers.push(("content-encoding", encoding));
        let r = response(200, &headers, b"{}".to_vec());
        assert!(
            selfsame_app_identity_net::testing::has_content_encoding(&r),
            "`{encoding}` was not seen as a content encoding"
        );
    }
}

#[tokio::test]
async fn identity_is_not_a_content_encoding_in_the_sense_that_matters() {
    for encoding in ["identity", "IDENTITY", " identity "] {
        let mut headers = json_headers();
        headers.push(("content-encoding", encoding));
        let r = response(200, &headers, b"{}".to_vec());
        assert!(
            !selfsame_app_identity_net::testing::has_content_encoding(&r),
            "`{encoding}` should be treated as no encoding at all"
        );
    }
    let r = response(200, &json_headers(), b"{}".to_vec());
    assert!(!selfsame_app_identity_net::testing::has_content_encoding(&r));
}

#[tokio::test]
async fn a_second_content_encoding_field_line_is_not_hidden_by_the_first() {
    // Two field lines are two values in the header map, and reading only the
    // first answered "no encoding" for a body that has one. `identity` first is
    // the shape that hides it, and it is not exotic: a proxy appending its own
    // encoding to a response that declared none produces exactly this.
    for second in ["gzip", "br", "identity, gzip"] {
        let r = response(
            200,
            &[
                ("content-type", PROFILE_MEDIA_TYPE),
                ("content-encoding", "identity"),
                ("content-encoding", second),
            ],
            b"{}".to_vec(),
        );
        assert!(
            selfsame_app_identity_net::testing::has_content_encoding(&r),
            "a second `{second}` field line was not seen"
        );
    }

    // Two field lines that both say `identity` are still no encoding.
    let r = response(
        200,
        &[
            ("content-type", PROFILE_MEDIA_TYPE),
            ("content-encoding", "identity"),
            ("content-encoding", "IDENTITY"),
        ],
        b"{}".to_vec(),
    );
    assert!(!selfsame_app_identity_net::testing::has_content_encoding(&r));
}

#[tokio::test]
async fn a_content_encoding_that_is_not_utf8_counts_as_an_encoding() {
    // A value that cannot be read as a string cannot be compared with
    // `identity`. Treating the read failure as absence made a header nobody
    // could read into evidence that the header said nothing — which is the one
    // reading `CON-213` and `CON-220` step 3 cannot afford, since both refuse
    // encoding outright.
    let mut builder = http::Response::builder().status(200).header("content-type", PROFILE_MEDIA_TYPE);
    builder = builder.header(
        "content-encoding",
        http::HeaderValue::from_bytes(&[0xff, 0xfe, b'g', b'z']).expect("a header value"),
    );
    let r = reqwest::Response::from(builder.body(b"{}".to_vec()).expect("a well-formed response"));
    assert!(selfsame_app_identity_net::testing::has_content_encoding(&r));
}

// ── media type ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_media_type_is_read_without_its_parameters_and_case_folded() {
    // A server that sends `application/selfsame-profile+json; charset=utf-8` is
    // sending the right media type. One that sends `application/json` is not,
    // and CON-220 step 3 refuses it.
    for (header, expected) in [
        (PROFILE_MEDIA_TYPE, PROFILE_MEDIA_TYPE),
        ("application/selfsame-profile+json; charset=utf-8", PROFILE_MEDIA_TYPE),
        ("APPLICATION/SELFSAME-PROFILE+JSON", PROFILE_MEDIA_TYPE),
        ("  application/selfsame-profile+json  ", PROFILE_MEDIA_TYPE),
        ("application/json", "application/json"),
        ("", ""),
    ] {
        let r = response(200, &[("content-type", header)], b"{}".to_vec());
        assert_eq!(
            selfsame_app_identity_net::testing::media_type(&r),
            expected,
            "header `{header}`"
        );
    }
}

#[tokio::test]
async fn a_response_with_no_content_type_reads_as_empty_and_is_refused() {
    let r = response(200, &[], b"{}".to_vec());
    assert_eq!(selfsame_app_identity_net::testing::media_type(&r), "");

    let observed = HttpResponse {
        https_validated: true,
        redirected: false,
        status: 200,
        content_type: "",
        content_encoding: None,
        body: b"{}",
    };
    let id = ApplicationId::parse("https://photos.example/selfsame/application").unwrap();
    assert_eq!(
        discovery::recognise_profile_response(&observed, &id),
        Err(DiscoveryError::BadResponse)
    );
}

// ── cookies ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_set_cookie_header_is_seen() {
    // CON-213 rejects cookies. This crate cannot *store* one — the `cookies`
    // feature is not compiled in — but a server can still send one, and a
    // pairing or mailbox response that tries to set state is refused.
    let r = response(200, &[("set-cookie", "session=abc; Path=/")], b"{}".to_vec());
    assert!(selfsame_app_identity_net::testing::carried_cookies(&r));

    let r = response(200, &json_headers(), b"{}".to_vec());
    assert!(!selfsame_app_identity_net::testing::carried_cookies(&r));
}

// ── the octet bound ────────────────────────────────────────────────────────

#[tokio::test]
async fn a_body_within_the_bound_is_returned_whole() {
    let body = vec![b'a'; 1_000];
    let r = response(200, &json_headers(), body.clone());
    let read = selfsame_app_identity_net::testing::bounded_body(r, 4_096).await.unwrap();
    assert_eq!(read, body);
}

#[tokio::test]
async fn a_body_over_the_bound_is_refused_rather_than_truncated() {
    // The distinction that matters: a truncated body is a *different document*,
    // and a recogniser handed one would either refuse it for the wrong reason
    // or accept a prefix that happens to parse.
    let body = vec![b'a'; 5_000];
    let r = response(200, &json_headers(), body);
    let outcome = selfsame_app_identity_net::testing::bounded_body(r, 4_096).await;
    assert!(outcome.is_err(), "an oversized body must be refused");
}

#[tokio::test]
async fn a_declared_content_length_over_the_bound_is_refused_before_transfer() {
    // Where the server offers a length, an oversized body costs one header read
    // rather than a full transfer.
    let body = vec![b'a'; 5_000];
    let r = response(200, &[("content-length", "5000")], body);
    assert!(selfsame_app_identity_net::testing::bounded_body(r, 4_096).await.is_err());
}

#[tokio::test]
async fn a_chunked_response_with_no_declared_length_is_still_bounded() {
    // The case the second bound check exists for, and the only one that reaches
    // it. Under `Content-Length` framing a client reads exactly the declared
    // number of octets, so an over-long body is impossible; under
    // `Transfer-Encoding: chunked` there is no declared length at all, the
    // pre-transfer check has nothing to test, and the octets actually read are
    // the only thing that can be bounded.
    //
    // Found by a surviving mutant. Removing the post-read check left every
    // constructed-response test passing, because `reqwest` derives an honest
    // Content-Length from the body it was handed — so no response built in
    // memory can ever exercise it. Only a real chunked server can.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            use tokio::io::AsyncWriteExt as _;
            let _ = socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
                      Content-Type: application/selfsame-profile+json\r\n\
                      Transfer-Encoding: chunked\r\n\r\n",
                )
                .await;
            // Five chunks of 1,000 octets: 5,000 total, no declared length.
            for _ in 0..5 {
                let _ = socket.write_all(b"3e8\r\n").await;
                let _ = socket.write_all(&vec![b'a'; 1_000]).await;
                let _ = socket.write_all(b"\r\n").await;
            }
            let _ = socket.write_all(b"0\r\n\r\n").await;
            let _ = socket.flush().await;
        }
    });

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(2_000))
        .build()
        .expect("builds");
    let r = client
        .get(format!("http://127.0.0.1:{port}/selfsame/application"))
        .send()
        .await
        .expect("the chunked response arrives");

    assert!(r.content_length().is_none(), "a chunked response declares no length");
    let outcome = selfsame_app_identity_net::testing::bounded_body(r, 4_096).await;
    assert!(
        outcome.is_err(),
        "an undeclared-length body over the bound must be refused, not truncated"
    );
}

#[tokio::test]
async fn an_endless_chunked_body_is_abandoned_at_the_bound_rather_than_buffered() {
    // The bound has to hold *during* transfer, not after it. Reading the whole
    // body and measuring afterwards refuses the same responses this test's
    // predecessor covers — five bounded chunks — while offering no protection
    // at all against the case that matters: a server that never stops.
    //
    // This server writes 64 KiB chunks until the client goes away, which is
    // unbounded from the client's side. A `bounded_body` that buffered first
    // would keep accepting them until memory ran out; one that checks per chunk
    // returns after the fifth and drops the connection.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let port = listener.local_addr().unwrap().port();

    let written = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = written.clone();
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            use tokio::io::AsyncWriteExt as _;
            let _ = socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
                      Content-Type: application/selfsame-profile+json\r\n\
                      Transfer-Encoding: chunked\r\n\r\n",
                )
                .await;
            let chunk = vec![b'a'; 65_536];
            // Until the write fails, which is what the client dropping the
            // connection looks like from here.
            loop {
                if socket.write_all(b"10000\r\n").await.is_err()
                    || socket.write_all(&chunk).await.is_err()
                    || socket.write_all(b"\r\n").await.is_err()
                {
                    break;
                }
                counter.fetch_add(chunk.len(), std::sync::atomic::Ordering::Relaxed);
                // A ceiling far above the bound: if the client is still reading
                // at 64 MiB it is not enforcing one, and the test should fail
                // rather than run the machine out of memory proving it.
                if counter.load(std::sync::atomic::Ordering::Relaxed) > 64 * 1_024 * 1_024 {
                    break;
                }
            }
        }
    });

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(5_000))
        .build()
        .expect("builds");
    let r = client
        .get(format!("http://127.0.0.1:{port}/selfsame/application"))
        .send()
        .await
        .expect("the chunked response arrives");

    let outcome = selfsame_app_identity_net::testing::bounded_body(r, 4_096).await;
    assert!(outcome.is_err(), "an endless body must be refused");
    assert!(
        written.load(std::sync::atomic::Ordering::Relaxed) < 8 * 1_024 * 1_024,
        "the client kept reading far past its 4,096-octet bound, which means the \
         bound is applied after buffering rather than during transfer"
    );
}

#[tokio::test]
async fn the_bound_is_inclusive_at_its_own_value() {
    let body = vec![b'a'; 4_096];
    let r = response(200, &json_headers(), body.clone());
    assert_eq!(
        selfsame_app_identity_net::testing::bounded_body(r, 4_096).await.unwrap().len(),
        4_096
    );
}

// ── status and redirect ────────────────────────────────────────────────────

#[tokio::test]
async fn every_redirect_status_is_seen_as_a_redirect() {
    // CON-220 step 2 rejects *every* redirect including same-origin. With
    // `Policy::none()` a 3xx arrives as a response rather than being followed,
    // which is what lets the check happen at all.
    for status in [301u16, 302, 303, 307, 308] {
        let r = response(status, &json_headers(), b"{}".to_vec());
        assert!(r.status().is_redirection(), "{status} is a redirect");
    }
    for status in [200u16, 204, 404, 500] {
        let r = response(status, &json_headers(), b"{}".to_vec());
        assert!(!r.status().is_redirection(), "{status} is not a redirect");
    }
}

#[tokio::test]
async fn a_redirected_profile_response_is_refused_by_the_predicate() {
    let id = ApplicationId::parse("https://photos.example/selfsame/application").unwrap();
    let observed = HttpResponse {
        https_validated: true,
        redirected: true,
        status: 301,
        content_type: PROFILE_MEDIA_TYPE,
        content_encoding: None,
        body: b"{}",
    };
    assert_eq!(
        discovery::recognise_profile_response(&observed, &id),
        Err(DiscoveryError::Redirected)
    );
}

// ── the connection-level policy, against a real listener ───────────────────

#[tokio::test]
async fn refuses_plaintext_http() {
    // The one property a constructed response cannot exercise. A real listener
    // is stood up on loopback and the client refuses to speak to it at all,
    // because `https_only(true)` is set — so a profile served over plaintext is
    // not a bad response, it is not a request.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let port = listener.local_addr().unwrap().port();

    // A server that would answer, if anything ever connected.
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            use tokio::io::AsyncWriteExt as _;
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/selfsame-profile+json\r\nContent-Length: 2\r\n\r\n{}")
                .await;
        }
    });

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(2_000))
        .https_only(true)
        .build()
        .expect("builds");

    let outcome = client.get(format!("http://127.0.0.1:{port}/selfsame/application")).send().await;
    assert!(outcome.is_err(), "a plaintext URL must not be fetched at all");
}

#[tokio::test]
async fn a_redirect_is_returned_rather_than_followed() {
    // Proves `Policy::none()` is doing what CON-220 step 2 needs: the 3xx comes
    // back as a response to be refused, rather than being chased to wherever it
    // pointed. Following and checking afterwards would already have made a
    // request somewhere the identifier does not name.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            use tokio::io::AsyncWriteExt as _;
            let _ = socket
                .write_all(
                    b"HTTP/1.1 301 Moved Permanently\r\nLocation: /elsewhere\r\nContent-Length: 0\r\n\r\n",
                )
                .await;
        }
    });

    // `https_only` is relaxed here only so the redirect policy can be observed
    // on loopback; the previous test is what covers the scheme rule.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(2_000))
        .build()
        .expect("builds");

    let r = client
        .get(format!("http://127.0.0.1:{port}/selfsame/application"))
        .send()
        .await
        .expect("the redirect itself is delivered");
    assert_eq!(r.status().as_u16(), 301, "the 3xx was returned, not followed");
    assert!(r.status().is_redirection());
}

// ── the whole path, end to end ─────────────────────────────────────────────

#[tokio::test]
async fn a_well_formed_profile_response_reaches_the_recogniser_and_is_accepted() {
    // The composition: build a real response, read it with the shell's own
    // helpers, hand the result to the core's predicate. If any of the five
    // inspection functions were wrong, this is where it shows.
    let octets = fixture_profile();
    let id = ApplicationId::parse("https://photos.example/selfsame/application").unwrap();

    let r = response(200, &json_headers(), octets.clone());
    let status = r.status().as_u16();
    let redirected = r.status().is_redirection();
    let encoded = selfsame_app_identity_net::testing::has_content_encoding(&r);
    let content_type = selfsame_app_identity_net::testing::media_type(&r);
    let body = selfsame_app_identity_net::testing::bounded_body(r, MAX_BODY_OCTETS).await.unwrap();

    let observed = HttpResponse {
        https_validated: true,
        redirected,
        status,
        content_type: &content_type,
        content_encoding: if encoded { Some("compressed") } else { None },
        body: &body,
    };
    let profile = discovery::recognise_profile_response(&observed, &id)
        .expect("a well-formed response yields a recognised profile");
    assert_eq!(profile.application_id.as_str(), id.as_str());
}

#[tokio::test]
async fn a_compressed_profile_response_is_refused_through_the_same_path() {
    let octets = fixture_profile();
    let id = ApplicationId::parse("https://photos.example/selfsame/application").unwrap();

    let mut headers = json_headers();
    headers.push(("content-encoding", "gzip"));
    let r = response(200, &headers, octets);
    let encoded = selfsame_app_identity_net::testing::has_content_encoding(&r);
    let content_type = selfsame_app_identity_net::testing::media_type(&r);
    let body = selfsame_app_identity_net::testing::bounded_body(r, MAX_BODY_OCTETS).await.unwrap();

    let observed = HttpResponse {
        https_validated: true,
        redirected: false,
        status: 200,
        content_type: &content_type,
        content_encoding: if encoded { Some("compressed") } else { None },
        body: &body,
    };
    assert_eq!(
        discovery::recognise_profile_response(&observed, &id),
        Err(DiscoveryError::BadResponse)
    );
}

/// A minimal recognised profile, built canonically.
fn fixture_profile() -> Vec<u8> {
    use selfsame_app_identity::codec;
    use selfsame_app_identity::json::{self, Json};
    json::canonicalise(&Json::obj([
        ("profileVersion", Json::int(1)),
        ("applicationId", Json::text("https://photos.example/selfsame/application")),
        ("accountAuthority", Json::text("accounts.photos.example")),
        ("verifierAudience", Json::text("https://photos.example/selfsame/application")),
        (
            "allowedPermissions",
            Json::arr([Json::text("https://photos.example/selfsame/application#device")]),
        ),
        (
            "enrollment",
            Json::obj([(
                "requestSigningKeys",
                Json::arr([Json::obj([
                    (
                        "kid",
                        Json::text("https://photos.example/selfsame/application#enrollment-2026-01"),
                    ),
                    (
                        "publicKeyJwk",
                        Json::obj([
                            ("kty", Json::text("OKP")),
                            ("crv", Json::text("Ed25519")),
                            ("x", Json::text(codec::b64url(&[1u8; 32]))),
                        ]),
                    ),
                ])]),
            )]),
        ),
        (
            "rendezvous",
            Json::arr([Json::obj([
                ("id", Json::text("au-primary")),
                ("url", Json::text("https://r.provider.example")),
                ("protocol", Json::text("selfsame-rendezvous-v1")),
                ("pairingUrl", Json::text("https://p.provider.example")),
                ("pairingProtocol", Json::text("selfsame-pairing-v1")),
                ("pairingRoute", Json::text("03")),
                ("priority", Json::int(10)),
                ("weight", Json::int(80)),
                ("validUntil", Json::text("2027-07-30T00:00:00Z")),
            ])]),
        ),
        (
            "stateResolvers",
            Json::arr([Json::obj([
                ("id", Json::text("state-1")),
                ("url", Json::text("https://state.provider.example")),
                ("protocol", Json::text("did-crdt-service-v1")),
            ])]),
        ),
        (
            "revocation",
            Json::obj([
                ("method", Json::text("did-crdt-revocations-v1")),
                ("maxGrantLifetimeSeconds", Json::int(2_592_000)),
                ("maxClosureAgeSeconds", Json::int(900)),
                ("propagationSlaSeconds", Json::int(60)),
            ]),
        ),
    ]))
}
