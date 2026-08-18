//! Origin-bound profile discovery — `CON-220`.
//!
//! The fetch half of [`selfsame_app_identity::discovery`]. The identifier is
//! the locator: the profile is retrieved by dereferencing the canonical
//! `applicationId` itself, not a fixed well-known path, because `ADR-201`
//! contemplates one developer hosting several security boundaries on one origin
//! and a single well-known path would permit only one application per origin.
//!
//! # Two things authenticate the result, and neither is sufficient alone
//!
//! TLS says the octets came from `photos.example`. The `profileDigest` in the
//! authenticated credential intent says *which*
//! profile that origin served. A host that serves a substituted profile passes
//! the first and fails the second.
//!
//! This module performs the first and returns a recognised profile; the second
//! is [`selfsame_app_identity::discovery::check_record_digest`], applied by the
//! caller once it has a record. They are separate functions because under
//! `CON-409` tier 3 they happen at different times: the profile is fetched
//! before any credential is accepted
//! until the digest check passes.

use std::time::Duration;

use selfsame_app_identity::discovery::{
    self, DiscoveryError, HttpResponse, MAX_BODY_OCTETS, PROFILE_MEDIA_TYPE,
};
use selfsame_app_identity::profile::{ApplicationId, ApplicationProfile};
use selfsame_app_identity::uri::{self, UriPolicy};
use selfsame_app_identity::UnixSeconds;

use crate::{bounded_body, client, has_content_encoding, media_type, NetError};

/// Deadline for a profile fetch.
///
/// `CON-220` fixes no bound of its own, so this one is chosen: it is the same
/// order as `CON-208`'s 1500 ms probe deadline, generous enough for a
/// cold TLS handshake and short enough that a stalled origin fails rather than
/// hangs a ceremony. Recorded as a chosen value rather than a specified one.
pub const FETCH_DEADLINE: Duration = Duration::from_millis(5_000);

/// A profile fetched and recognised, with the moment it was fetched.
///
/// The timestamp is carried because `CON-220`'s cache bound is also "the window
/// in which a removed key remains usable" — so a cached profile without its
/// fetch time is a profile whose enrollment keys have no expiry.
#[derive(Clone, Debug)]
pub struct FetchedProfile {
    /// The recognised profile.
    pub profile: ApplicationProfile,
    /// The exact octets that were served and recognised.
    ///
    /// Retained because `ApplicationProfile` does not keep them and a caller
    /// cannot re-derive them: the digest `CON-220` step 6 compares is over the
    /// bytes the origin sent, and every downstream consumer — `build_offer`, a
    /// wallet handing a profile to `app_grant_review`, `CON-409`'s digest match —
    /// takes octets rather than the parsed value. Without this the only way to
    /// obtain them is a second fetch, which may return a different document.
    pub octets: Vec<u8>,
    /// When it was fetched, for [`discovery::cache_is_fresh`].
    pub fetched_at: UnixSeconds,
}

/// Dereference a canonical `applicationId` and recognise what comes back
/// (`CON-220` steps 1 to 5).
///
/// Step 6 — the record digest — is the caller's, because under tier 3 it runs
/// later.
pub async fn fetch(
    application_id: &ApplicationId,
    now: UnixSeconds,
) -> Result<FetchedProfile, NetError> {
    let response = client(FETCH_DEADLINE)?
        .get(application_id.as_str())
        .header(reqwest::header::ACCEPT, PROFILE_MEDIA_TYPE)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                NetError::Timeout
            } else {
                // A TLS or certificate failure lands here, which is CON-220
                // step 1 refusing before anything is read.
                NetError::Transport(e.to_string())
            }
        })?;

    // With `Policy::none()` a 3xx arrives as a response rather than being
    // followed, which is what lets step 2 refuse it. Following and checking
    // afterwards would already have made a request to somewhere the identifier
    // does not name.
    let status = response.status().as_u16();
    let redirected = response.status().is_redirection();
    let encoded = has_content_encoding(&response);
    let content_type = media_type(&response);

    let body = bounded_body(response, MAX_BODY_OCTETS).await?;

    // Everything the shell observed is handed to the core's predicate, which
    // decides. This function contains no judgement of its own.
    let observed = HttpResponse {
        https_validated: true, // reqwest refused a non-HTTPS scheme and a bad certificate above
        redirected,
        status,
        content_type: &content_type,
        content_encoding: if encoded { Some("compressed") } else { None },
        body: &body,
    };
    let profile = discovery::recognise_profile_response(&observed, application_id)
        .map_err(|e: DiscoveryError| NetError::Recognition(e.to_string()))?;

    Ok(FetchedProfile {
        profile,
        octets: body.to_vec(),
        fetched_at: now,
    })
}

/// Fetch, or reuse a cached profile that is still inside `CON-220`'s bound.
///
/// `CON-220`: "A cached profile within its bound MAY be used with no network
/// request. Beyond it, and with no network, the operation fails closed as
/// `UnverifiedApplication`; there is no stale-profile grace period, because the
/// enrollment key is exactly what staleness would put at risk."
///
/// That last clause is why this returns an error rather than the stale value
/// when the network is unavailable. A grace period here would extend the life of
/// a revoked enrollment key by exactly the length of the outage.
///
/// Age is not the only reason to evict. `CON-220` also forbids serving a profile
/// "whose `validUntil`-bearing descriptors have all expired", which is a
/// separate condition and comes apart from age in the case that matters: a
/// profile fetched twenty minutes ago whose descriptors expired ten minutes ago
/// is inside its cache bound and useless, and re-fetching may find the
/// replacements the origin has already published. [`discovery::cache_is_usable`]
/// is both conditions.
pub async fn fetch_or_cached(
    application_id: &ApplicationId,
    cached: Option<&FetchedProfile>,
    now: UnixSeconds,
) -> Result<FetchedProfile, NetError> {
    if let Some(held) = cached {
        if discovery::cache_is_usable(&held.profile, held.fetched_at, now)
            && held.profile.application_id == *application_id
        {
            return Ok(held.clone());
        }
    }
    fetch(application_id, now).await
}

/// The tier-3 origin-enumeration request (`CON-220`).
///
/// > A party SHALL use this endpoint **only for tier-3 recovery**, SHALL present
/// > the resulting choice to the person when more than one entry is returned,
/// > and SHALL NOT consult it on any other path.
///
/// The signature carries that restriction as far as a signature can: it takes an
/// origin a *person typed*, which is the only circumstance in which tier 3 is
/// reached, and it returns a list for the person to choose from rather than
/// picking one.
///
/// # A person typed it, so it is recognised before it is used
///
/// The typed value is used twice: to build the request path, and to check that
/// every identifier the origin returns is on that same origin. Both uses need
/// the canonical origin, and neither tolerates the forms a person actually
/// types.
///
/// ```abnf
/// typed-origin = "https://" host [ ":" port ] [ "/" ]
/// ```
///
/// A trailing `/` — the shape a browser address bar shows and a person copies —
/// concatenates to `https://photos.example//.well-known/selfsame/applications`,
/// and then fails every comparison against `ApplicationId::origin()`, which
/// carries none. A typed *path* aims the request somewhere the endpoint is not
/// and makes the response check compare against a string no identifier can
/// equal. Recognising the origin first fixes both, and the empty-path form is
/// admitted because `https://photos.example/` is a spelling of the origin, not a
/// path — nothing else is repaired.
pub async fn enumerate_applications(
    typed_origin: &str,
    now: UnixSeconds,
) -> Result<Vec<ApplicationId>, NetError> {
    let _ = now;
    let parts = uri::recognise(typed_origin, UriPolicy::PROVIDER_URL)
        .map_err(|_| NetError::Refused("the typed value is not an HTTPS origin"))?;
    if !parts.path.is_empty() && parts.path != "/" {
        return Err(NetError::Refused(
            "origin enumeration takes an origin, not a path",
        ));
    }
    let typed_origin = parts.origin;
    let url = format!("{typed_origin}{}", discovery::ENUMERATION_PATH);
    let response = client(FETCH_DEADLINE)?
        .get(&url)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                NetError::Timeout
            } else {
                NetError::Transport(e.to_string())
            }
        })?;

    if response.status().is_redirection() {
        return Err(NetError::Refused("origin enumeration was redirected"));
    }
    if !response.status().is_success() {
        return Err(NetError::Refused("origin enumeration did not succeed"));
    }
    let body = bounded_body(response, 8_192).await?;
    discovery::recognise_application_list(&body, typed_origin)
        .map_err(|e| NetError::Recognition(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_enumeration_path_is_the_well_known_one_con_220_fixes() {
        assert_eq!(
            discovery::ENUMERATION_PATH,
            "/.well-known/selfsame/applications"
        );
    }

    #[test]
    fn a_typed_origin_is_recognised_before_it_becomes_a_request_or_a_comparand() {
        // The same value builds the request path *and* is compared against
        // every returned `ApplicationId::origin()`, which never carries a
        // trailing slash. So the browser-address-bar form a person copies used
        // to request `//.well-known/selfsame/applications` and then reject every
        // otherwise valid answer, and a typed path aimed the request somewhere
        // the endpoint is not.
        let recognised = |text: &str| -> Option<String> {
            let parts = uri::recognise(text, UriPolicy::PROVIDER_URL).ok()?;
            (parts.path.is_empty() || parts.path == "/").then(|| parts.origin.to_string())
        };

        // Both spellings of the origin yield the origin itself.
        assert_eq!(
            recognised("https://photos.example").as_deref(),
            Some("https://photos.example")
        );
        assert_eq!(
            recognised("https://photos.example/").as_deref(),
            Some("https://photos.example")
        );
        assert_eq!(
            recognised("https://photos.example:8443/").as_deref(),
            Some("https://photos.example:8443")
        );

        // …and everything that is not an origin is refused rather than repaired.
        for typed in [
            "https://photos.example/selfsame",
            "https://photos.example/?x=1",
            "https://photos.example#frag",
            "http://photos.example",
            "photos.example",
            "",
        ] {
            assert!(
                recognised(typed).is_none(),
                "`{typed}` was accepted as an origin"
            );
        }

        // The recognised origin is exactly what `recognise_application_list`
        // compares against, so a conforming answer now matches.
        let id = ApplicationId::parse("https://photos.example/selfsame/application").unwrap();
        assert_eq!(
            Some(id.origin().to_string()),
            recognised("https://photos.example/")
        );
    }

    #[test]
    fn the_deadline_is_a_chosen_value_and_is_recorded_as_one() {
        // CON-220 fixes no fetch deadline. This one is ours, and saying so in a
        // test is cheaper than a reader discovering it by reading the constant
        // and assuming the spec required it.
        assert_eq!(FETCH_DEADLINE, Duration::from_millis(5_000));
    }

    #[tokio::test]
    async fn a_cached_profile_inside_the_bound_is_reused_without_a_request() {
        // The test that proves the cache path never touches the network: the
        // application id points at a host that does not resolve, so a fetch
        // would fail. It does not fail, because it does not happen.
        let id = ApplicationId::parse("https://nonexistent.invalid/selfsame/application").unwrap();
        let octets = fixture_profile_octets();
        let profile = ApplicationProfile::recognise(&octets).unwrap();
        // The fixture names photos.example, so build a cache entry whose
        // identifier matches what we ask for.
        let held = FetchedProfile {
            profile,
            octets: octets.clone(),
            fetched_at: 1_000,
        };
        let outcome = fetch_or_cached(&held.profile.application_id.clone(), Some(&held), 1_500)
            .await
            .expect("a fresh cache entry is reused");
        assert_eq!(outcome.fetched_at, 1_000);
        let _ = id;
    }

    #[tokio::test]
    async fn a_cached_profile_past_the_bound_is_not_reused() {
        let octets = fixture_profile_octets();
        let profile = ApplicationProfile::recognise(&octets).unwrap();
        let id = profile.application_id.clone();
        let held = FetchedProfile {
            profile,
            octets: octets.clone(),
            fetched_at: 1_000,
        };
        // Past 3,600 seconds the cache is dead and the fetch is attempted —
        // against `photos.example`, which does not resolve, so this is an
        // error rather than a stale hit. That is the point: no grace period.
        let outcome = fetch_or_cached(&id, Some(&held), 1_000 + 3_601).await;
        assert!(outcome.is_err(), "a stale cache entry must not be served");
    }

    /// The `CON-201` example profile, canonically serialised.
    fn fixture_profile_octets() -> Vec<u8> {
        use selfsame_app_identity::codec;
        use selfsame_app_identity::json::{self, Json};
        let descriptor = |id: &str, origin: &str, weight: i64| {
            Json::obj([
                ("operatorId", Json::text(id)),
                ("relayOrigin", Json::text(origin)),
                ("priority", Json::int(10)),
                ("weight", Json::int(weight)),
                ("privacyPolicyDigest", Json::text(codec::b64url(&[1u8; 32]))),
                (
                    "conformanceEvidenceDigest",
                    Json::text(codec::b64url(&[2u8; 32])),
                ),
            ])
        };
        json::canonicalise(&Json::obj([
            ("profileVersion", Json::int(1)),
            (
                "applicationId",
                Json::text("https://photos.example/selfsame/application"),
            ),
            ("accountAuthority", Json::text("accounts.photos.example")),
            (
                "verifierAudience",
                Json::text("https://photos.example/selfsame/application"),
            ),
            (
                "allowedPermissions",
                Json::arr([Json::text(
                    "https://photos.example/selfsame/application#device",
                )]),
            ),
            (
                "enrollment",
                Json::obj([(
                    "requestSigningKeys",
                    Json::arr([Json::obj([
                        (
                            "kid",
                            Json::text(
                                "https://photos.example/selfsame/application#enrollment-2026-01",
                            ),
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
                "cbclPairingRelays",
                Json::arr([descriptor(
                    "au-primary",
                    "https://cbcl.provider.example",
                    80,
                )]),
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
}
