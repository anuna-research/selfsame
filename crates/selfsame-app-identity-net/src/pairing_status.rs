//! Strict native transport for credential/v2 final-status recovery.

use crate::{bounded_body, carried_cookies, client, has_content_encoding, media_type, NetError};
use selfsame_app_identity::profile::ApplicationId;
use std::time::Duration;

const RECOVERY_PATH: &str = "/selfsame/pairing/v2/status";
const RECOVERY_MEDIA_TYPE: &str = "application/cbor";
const MAX_REQUEST_OCTETS: usize = 2_304;
const MAX_RESPONSE_OCTETS: usize = 9_216;
const FETCH_DEADLINE: Duration = Duration::from_secs(15);

/// Closed HTTP status admitted by the credential/v2 recovery contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingStatusHttpStatus {
    /// Accepted or signed terminal-negative CBOR.
    Terminal,
    /// A live hub transaction remains able to finalize.
    InProgress,
    /// Unknown ceremony or wrong token; no authority is disclosed.
    Unknown,
    /// Busy, unavailable, lock-exhausted, or anonymously rate-limited.
    Unavailable,
}

/// Strictly inspected response bytes and their closed status class.
#[derive(Debug, Eq, PartialEq)]
pub struct PairingStatusHttpResponse {
    /// Closed status classification.
    pub status: PairingStatusHttpStatus,
    /// Complete bounded CBOR body, absent only for typed unavailability.
    pub body: Vec<u8>,
}

/// POST opaque secret-bearing CBOR directly to the authenticated application
/// origin. The caller constructs and zeroizes the body; this transport never
/// parses, logs, redirects, compresses, stores cookies, or puts it in a URL.
pub async fn post(
    application_id: &ApplicationId,
    request: &[u8],
) -> Result<PairingStatusHttpResponse, NetError> {
    if request.is_empty() || request.len() > MAX_REQUEST_OCTETS {
        return Err(NetError::Refused("invalid pairing-status request size"));
    }
    let url = format!("{}{RECOVERY_PATH}", application_id.origin());
    let response = client(FETCH_DEADLINE)?
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, RECOVERY_MEDIA_TYPE)
        .header(reqwest::header::ACCEPT, RECOVERY_MEDIA_TYPE)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .body(request.to_vec())
        .send()
        .await
        .map_err(|error| {
            if error.is_timeout() {
                NetError::Timeout
            } else {
                NetError::Transport(error.to_string())
            }
        })?;
    inspect_response(response).await
}

async fn inspect_response(
    response: reqwest::Response,
) -> Result<PairingStatusHttpResponse, NetError> {
    if response.status().is_redirection()
        || has_content_encoding(&response)
        || carried_cookies(&response)
    {
        return Err(NetError::Refused("invalid pairing-status response policy"));
    }
    let status = match response.status().as_u16() {
        200 => PairingStatusHttpStatus::Terminal,
        202 => PairingStatusHttpStatus::InProgress,
        404 => PairingStatusHttpStatus::Unknown,
        503 => PairingStatusHttpStatus::Unavailable,
        _ => return Err(NetError::Refused("invalid pairing-status response status")),
    };
    if status == PairingStatusHttpStatus::Unavailable {
        if response.content_length().is_some_and(|length| length != 0) {
            return Err(NetError::Refused(
                "pairing-status unavailability carried a body",
            ));
        }
        let body = bounded_body(response, 0).await?;
        return Ok(PairingStatusHttpResponse { status, body });
    }
    if media_type(&response) != RECOVERY_MEDIA_TYPE {
        return Err(NetError::Refused("invalid pairing-status media type"));
    }
    if response
        .headers()
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        != Some("no-store")
    {
        return Err(NetError::Refused("pairing-status response is cacheable"));
    }
    let body = bounded_body(response, MAX_RESPONSE_OCTETS).await?;
    if body.is_empty() {
        return Err(NetError::Refused("empty pairing-status response"));
    }
    Ok(PairingStatusHttpResponse { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: u16, headers: &[(&str, &str)], body: Vec<u8>) -> reqwest::Response {
        let mut builder = http::Response::builder().status(status);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        reqwest::Response::from(builder.body(body).expect("response"))
    }

    fn headers() -> [(&'static str, &'static str); 2] {
        [
            ("content-type", RECOVERY_MEDIA_TYPE),
            ("cache-control", "no-store"),
        ]
    }

    #[tokio::test]
    async fn test_1161_only_closed_bounded_uncacheable_responses_cross_the_boundary() {
        for (status, expected) in [
            (200, PairingStatusHttpStatus::Terminal),
            (202, PairingStatusHttpStatus::InProgress),
            (404, PairingStatusHttpStatus::Unknown),
        ] {
            let inspected = inspect_response(response(status, &headers(), vec![0xa0]))
                .await
                .unwrap();
            assert_eq!(inspected.status, expected);
            assert_eq!(inspected.body, vec![0xa0]);
        }
        let unavailable = inspect_response(response(503, &[], Vec::new()))
            .await
            .unwrap();
        assert_eq!(unavailable.status, PairingStatusHttpStatus::Unavailable);
        assert!(unavailable.body.is_empty());

        for invalid in [
            response(302, &headers(), vec![0xa0]),
            response(200, &[("content-type", RECOVERY_MEDIA_TYPE)], vec![0xa0]),
            response(
                200,
                &[
                    ("content-type", RECOVERY_MEDIA_TYPE),
                    ("cache-control", "no-store"),
                    ("content-encoding", "gzip"),
                ],
                vec![0xa0],
            ),
            response(
                200,
                &[
                    ("content-type", RECOVERY_MEDIA_TYPE),
                    ("cache-control", "no-store"),
                    ("set-cookie", "session=forbidden"),
                ],
                vec![0xa0],
            ),
            response(503, &[], vec![0xa0]),
        ] {
            assert!(inspect_response(invalid).await.is_err());
        }
        assert!(
            inspect_response(response(200, &headers(), vec![0; MAX_RESPONSE_OCTETS + 1],))
                .await
                .is_err()
        );
    }
}
