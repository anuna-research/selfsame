//! Application profile discovery — `CON-220`, `REQ-222`, `REQ-227`.
//!
//! This is how a resolving party obtains a profile and binds it to the
//! `applicationId` **origin**, so that the enrollment-signing key in `CON-214` is
//! never one the caller supplied.
//!
//! # The identifier is the locator
//!
//! The profile is retrieved by dereferencing the canonical `applicationId`
//! itself, not a fixed well-known path. `ADR-201` contemplates one developer
//! hosting several security boundaries on one origin, and a single well-known
//! path would permit only one application per origin.
//!
//! # Why every redirect is rejected, including same-origin
//!
//! `CON-220` step 2 is blunt and easy to get wrong in the permissive direction:
//! *"the `applicationId` is canonical, so a redirect means the identifier is
//! wrong, not that the profile moved."* Following one would let a host serve a
//! profile from a location the identifier does not name, and the identifier is
//! the thing a verifier compares as exact ASCII.
//!
//! # TLS authenticates the origin; authenticated intent pins the profile
//!
//! Step 6 is what makes the fetch trustworthy rather than merely encrypted. TLS
//! says the bytes came from `photos.example`. The `profileDigest` in the
//! authenticated credential intent says *which* profile that origin served. A
//! host that serves a substituted profile passes the first check and fails the
//! second. Together they are why no key ever comes from the caller.
//!
//! # Offline is a failure, not a grace period
//!
//! A cached profile inside its bound may be used with no network request. Beyond
//! it, with no network, the operation fails closed as
//! [`DiscoveryError::UnverifiedApplication`]. `CON-220`: "there is no
//! stale-profile grace period, because the enrollment key is exactly what
//! staleness would put at risk."

use crate::codec;
use crate::json::{self, Json, Limits};
use crate::profile::{ApplicationId, ApplicationProfile, ProfileError};
use crate::uri::{self, UriPolicy};
use crate::UnixSeconds;

/// The one media type a profile response may carry.
pub const PROFILE_MEDIA_TYPE: &str = "application/selfsame-profile+json";

/// `CON-220` step 3: the octet bound on a profile body.
pub const MAX_BODY_OCTETS: usize = 65_536;

/// `CON-220`: a profile may be cached for at most 3,600 seconds.
pub const MAX_CACHE_SECONDS: i64 = 3_600;

/// `CON-220`: the tier-3 enumeration endpoint returns at most 32 entries.
pub const MAX_ENUMERATED_APPLICATIONS: usize = 32;

/// The tier-3 origin-enumeration path.
pub const ENUMERATION_PATH: &str = "/.well-known/selfsame/applications";

/// Why discovery failed.
///
/// `CON-220`'s only named token is `UnverifiedApplication`; the rest name the
/// step so a `CON-226` case can say which check fired.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DiscoveryError {
    /// The operation fails closed: no profile could be authenticated.
    #[error("UnverifiedApplication")]
    UnverifiedApplication,
    /// Step 1: the transport was not HTTPS with a valid certificate.
    #[error("profile was not served over authenticated HTTPS")]
    NotAuthenticatedHttps,
    /// Step 2: the response was a redirect, including a same-origin one.
    #[error("profile response was a redirect")]
    Redirected,
    /// Step 3: content encoding, a wrong media type, a non-200 status, or an
    /// over-long body.
    #[error("profile response is not the one shape CON-220 accepts")]
    BadResponse,
    /// Step 4: the body is not a profile.
    #[error("profile body is not recognised: {0}")]
    Profile(#[from] ProfileError),
    /// Step 5: the profile's own `applicationId` is not the URI dereferenced.
    #[error("profile names a different applicationId than the URI dereferenced")]
    IdentifierMismatch,
    /// Step 6: the profile digest is not the one the record pinned.
    #[error("profile digest does not match the pairing record")]
    DigestMismatch,
    /// The enumeration response is not the closed two-member shape.
    #[error("origin enumeration response is malformed")]
    BadEnumeration,
}

/// What the shell observed when it dereferenced the identifier.
///
/// Every field is something only the shell can know. Making them a struct rather
/// than a trait keeps the decision a pure function of what was seen, so a test
/// can present any response without a server.
#[derive(Clone, Copy, Debug)]
pub struct HttpResponse<'a> {
    /// Whether TLS and certificate validation succeeded.
    pub https_validated: bool,
    /// Whether any redirect occurred, same-origin included.
    pub redirected: bool,
    /// The HTTP status.
    pub status: u16,
    /// The `Content-Type`, without parameters.
    pub content_type: &'a str,
    /// The `Content-Encoding`, when the response carried one.
    pub content_encoding: Option<&'a str>,
    /// The body octets.
    pub body: &'a [u8],
}

/// `CON-220` steps 1 to 5.
///
/// Step 6 is [`check_record_digest`], separate because under tier 3 it runs
/// later, against a profile already held.
pub fn recognise_profile_response(
    response: &HttpResponse<'_>,
    dereferenced: &ApplicationId,
) -> Result<ApplicationProfile, DiscoveryError> {
    // 1.
    if !response.https_validated {
        return Err(DiscoveryError::NotAuthenticatedHttps);
    }
    // 2. Every redirect, including same-origin.
    if response.redirected {
        return Err(DiscoveryError::Redirected);
    }
    // 3.
    if response.status != 200
        || response.content_type != PROFILE_MEDIA_TYPE
        || response
            .content_encoding
            .is_some_and(|e| !e.eq_ignore_ascii_case("identity"))
        || response.body.len() > MAX_BODY_OCTETS
    {
        return Err(DiscoveryError::BadResponse);
    }
    // 4. The complete CON-201 recognition, before any semantic action.
    let profile = ApplicationProfile::recognise(response.body)?;
    // 5. Exact ASCII.
    if profile.application_id.as_str() != dereferenced.as_str() {
        return Err(DiscoveryError::IdentifierMismatch);
    }
    Ok(profile)
}

/// `CON-220` step 6: the authenticated `profileDigest` pins which profile the
/// origin served.
pub fn check_record_digest(
    profile: &ApplicationProfile,
    record_profile_digest: &str,
) -> Result<(), DiscoveryError> {
    if codec::b64url(profile.digest()) != record_profile_digest {
        return Err(DiscoveryError::DigestMismatch);
    }
    Ok(())
}

/// Whether a cached profile may still be used without a request.
///
/// The cache bound is also the window in which a **removed** enrollment key
/// remains usable. It composes with `CON-214`'s 120-second evidence window, so
/// an attacker holding a revoked key has at most the remaining cache lifetime,
/// never indefinite use.
pub fn cache_is_fresh(fetched_at: UnixSeconds, now: UnixSeconds) -> bool {
    now >= fetched_at && now - fetched_at <= MAX_CACHE_SECONDS
}

/// Whether a cached profile may be served at all (`CON-220`).
pub fn cache_is_usable(
    _profile: &ApplicationProfile,
    fetched_at: UnixSeconds,
    now: UnixSeconds,
) -> bool {
    cache_is_fresh(fetched_at, now)
}

/// Recognise the tier-3 origin-enumeration response (`CON-220`).
///
/// Exactly two members, at most 32 entries, every entry an absolute HTTPS URI on
/// the queried origin and canonical under `CON-201`. A party uses this endpoint
/// "only for tier-3 recovery … and SHALL NOT consult it on any other path".
pub fn recognise_application_list(
    body: &[u8],
    queried_origin: &str,
) -> Result<Vec<ApplicationId>, DiscoveryError> {
    let limits = Limits {
        max_bytes: 8_192,
        max_depth: 3,
    };
    let value = json::recognise(body, limits).map_err(|_| DiscoveryError::BadEnumeration)?;
    let members = value.as_object().ok_or(DiscoveryError::BadEnumeration)?;
    if members.len() != 2 {
        return Err(DiscoveryError::BadEnumeration);
    }
    for (name, _) in members {
        if name != "version" && name != "applications" {
            return Err(DiscoveryError::BadEnumeration);
        }
    }
    if value.get("version").and_then(Json::as_i64) != Some(1) {
        return Err(DiscoveryError::BadEnumeration);
    }
    let items = value
        .get("applications")
        .and_then(Json::as_array)
        .ok_or(DiscoveryError::BadEnumeration)?;
    if items.len() > MAX_ENUMERATED_APPLICATIONS {
        return Err(DiscoveryError::BadEnumeration);
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let text = item.as_str().ok_or(DiscoveryError::BadEnumeration)?;
        let id = ApplicationId::parse(text).map_err(|_| DiscoveryError::BadEnumeration)?;
        // "every entry an absolute HTTPS URI **on the queried origin**" — an
        // origin that could enumerate someone else's applications would turn a
        // recovery path into a redirection.
        if id.origin() != queried_origin {
            return Err(DiscoveryError::BadEnumeration);
        }
        out.push(id);
    }
    Ok(out)
}

/// The path to dereference for one application identifier.
///
/// Returned rather than fetched, so the request the shell makes is fixed here
/// and a second implementation can reproduce it.
pub fn profile_request_path(application_id: &ApplicationId) -> Result<String, DiscoveryError> {
    let parts = uri::recognise(application_id.as_str(), UriPolicy::APPLICATION_ID)
        .map_err(|_| DiscoveryError::IdentifierMismatch)?;
    Ok(parts.path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "https://photos.example/selfsame/application";

    fn app() -> ApplicationId {
        ApplicationId::parse(ID).unwrap()
    }

    fn ok_response(body: &[u8]) -> HttpResponse<'_> {
        HttpResponse {
            https_validated: true,
            redirected: false,
            status: 200,
            content_type: PROFILE_MEDIA_TYPE,
            content_encoding: None,
            body,
        }
    }

    #[test]
    fn the_request_path_is_the_identifier_s_own_path() {
        // ADR-201: a fixed well-known path would permit only one application
        // per origin, and one developer may host several security boundaries.
        assert_eq!(
            profile_request_path(&app()).unwrap(),
            "/selfsame/application"
        );
        let other = ApplicationId::parse("https://photos.example/selfsame/beta").unwrap();
        assert_eq!(profile_request_path(&other).unwrap(), "/selfsame/beta");
    }

    #[test]
    fn a_redirect_is_refused_even_when_it_is_same_origin() {
        let body = b"{}";
        let response = HttpResponse {
            redirected: true,
            ..ok_response(body)
        };
        assert_eq!(
            recognise_profile_response(&response, &app()),
            Err(DiscoveryError::Redirected)
        );
    }

    #[test]
    fn an_unvalidated_transport_is_refused_before_anything_is_parsed() {
        let body = b"{}";
        let response = HttpResponse {
            https_validated: false,
            ..ok_response(body)
        };
        assert_eq!(
            recognise_profile_response(&response, &app()),
            Err(DiscoveryError::NotAuthenticatedHttps)
        );
    }

    #[test]
    fn a_wrong_status_media_type_encoding_or_over_long_body_is_refused() {
        let body = b"{}";
        for response in [
            HttpResponse {
                status: 404,
                ..ok_response(body)
            },
            HttpResponse {
                status: 301,
                ..ok_response(body)
            },
            HttpResponse {
                content_type: "application/json",
                ..ok_response(body)
            },
            HttpResponse {
                content_encoding: Some("gzip"),
                ..ok_response(body)
            },
        ] {
            assert_eq!(
                recognise_profile_response(&response, &app()),
                Err(DiscoveryError::BadResponse)
            );
        }
        // `identity` is not a content encoding in the sense that matters.
        let response = HttpResponse {
            content_encoding: Some("identity"),
            ..ok_response(body)
        };
        assert!(matches!(
            recognise_profile_response(&response, &app()),
            Err(DiscoveryError::Profile(_))
        ));

        let huge = vec![b'a'; MAX_BODY_OCTETS + 1];
        let response = ok_response(&huge);
        assert_eq!(
            recognise_profile_response(&response, &app()),
            Err(DiscoveryError::BadResponse)
        );
    }

    #[test]
    fn the_cache_bound_is_one_hour_and_is_not_a_grace_period() {
        assert!(cache_is_fresh(1_000, 1_000));
        assert!(cache_is_fresh(1_000, 1_000 + MAX_CACHE_SECONDS));
        assert!(!cache_is_fresh(1_000, 1_000 + MAX_CACHE_SECONDS + 1));
        // A clock that went backwards is not freshness either.
        assert!(!cache_is_fresh(1_000, 999));
    }

    #[test]
    fn the_enumeration_response_is_a_closed_two_member_language() {
        let body = json::canonicalise(&Json::obj([
            ("version", Json::int(1)),
            ("applications", Json::arr([Json::text(ID)])),
        ]));
        let found = recognise_application_list(&body, "https://photos.example").unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].as_str(), ID);
    }

    #[test]
    fn an_enumeration_naming_another_origin_is_refused() {
        // An origin that could enumerate someone else's applications would turn
        // a recovery path into a redirection.
        let body = json::canonicalise(&Json::obj([
            ("version", Json::int(1)),
            (
                "applications",
                Json::arr([Json::text("https://elsewhere.example/selfsame/application")]),
            ),
        ]));
        assert_eq!(
            recognise_application_list(&body, "https://photos.example"),
            Err(DiscoveryError::BadEnumeration)
        );
    }

    #[test]
    fn an_enumeration_with_an_extra_member_a_wrong_version_or_too_many_entries_is_refused() {
        let with_extra = json::canonicalise(&Json::obj([
            ("version", Json::int(1)),
            ("applications", Json::arr([Json::text(ID)])),
            ("note", Json::text("hello")),
        ]));
        assert_eq!(
            recognise_application_list(&with_extra, "https://photos.example"),
            Err(DiscoveryError::BadEnumeration)
        );

        let wrong_version = json::canonicalise(&Json::obj([
            ("version", Json::int(2)),
            ("applications", Json::arr([Json::text(ID)])),
        ]));
        assert_eq!(
            recognise_application_list(&wrong_version, "https://photos.example"),
            Err(DiscoveryError::BadEnumeration)
        );

        let many: Vec<Json> = (0..33)
            .map(|i| Json::text(format!("https://photos.example/selfsame/a{i}")))
            .collect();
        let too_many = json::canonicalise(&Json::obj([
            ("version", Json::int(1)),
            ("applications", Json::Array(many)),
        ]));
        assert_eq!(
            recognise_application_list(&too_many, "https://photos.example"),
            Err(DiscoveryError::BadEnumeration)
        );
    }
}
