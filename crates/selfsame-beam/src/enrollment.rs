//! `CON-214` enrollment signing at the CBCL/BEAM boundary.
//!
//! The hub supplies canonical unsigned statement bytes, the declared `kid`,
//! and a 32-octet Ed25519 private seed for each call. This module retains no
//! signing state. Before constructing a signing key it delegates recognition of
//! both the statement and protected header to `selfsame-app-identity`, then
//! delegates compact-JWS production to that same module.

use rustler::types::atom;
use rustler::{Binary, Encoder, Env, OwnedBinary, Term};
use selfsame_app_identity::enrollment;

rustler::atoms! {
    rejected,
}

const REFUSED: &str = "rejected";

/// Recognise and sign one canonical unsigned `CON-214` statement.
///
/// `private_key` is exactly one 32-octet Ed25519 seed. All failures use a fixed
/// opaque error and neither the statement, `kid`, nor key bytes are reflected
/// through it. The signing key exists only inside the signing scope and is
/// zeroised by `ed25519-dalek` when dropped.
pub fn sign_enrollment_statement(
    statement: &[u8],
    kid: &str,
    private_key: &[u8],
) -> Result<String, String> {
    // Recognition deliberately precedes even construction of the secret key.
    // This is the enrollment module's own grammar and protected-header policy,
    // not a BEAM-side restatement of CON-214.
    let recognised =
        enrollment::recognise_unsigned(statement, kid).map_err(|_| String::from(REFUSED))?;

    let seed: &[u8; 32] = private_key.try_into().map_err(|_| String::from(REFUSED))?;
    let (compact, public_key) = {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let compact = enrollment::sign(&recognised, kid, &signing_key);
        (compact, public_key)
    };

    // Refuse producer/recogniser drift at the boundary where it would otherwise
    // turn every valid hub request into a wallet rejection.
    let (round_trip, signed) =
        enrollment::recognise(&compact).map_err(|_| String::from(REFUSED))?;
    if round_trip != recognised || signed.kid != kid {
        return Err(String::from(REFUSED));
    }
    signed
        .verify(&public_key)
        .map_err(|_| String::from(REFUSED))?;

    Ok(compact)
}

/// `cbcl_selfsame_erl:sign_enrollment/3`.
///
/// Arguments are `(canonical_statement_binary, kid_binary,
/// private_seed_binary)`. The result is `{ok, CompactJwsBinary}` or the sole
/// refusal `{error, rejected}`.
#[rustler::nif]
pub fn sign_enrollment<'a>(
    env: Env<'a>,
    statement: Binary<'a>,
    kid: Binary<'a>,
    private_key: Binary<'a>,
) -> Term<'a> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        std::str::from_utf8(kid.as_slice())
            .map_err(|_| String::from(REFUSED))
            .and_then(|kid| {
                sign_enrollment_statement(statement.as_slice(), kid, private_key.as_slice())
            })
            .and_then(|compact| binary(env, compact.as_bytes()))
    }));

    match result {
        Ok(Ok(compact)) => (atom::ok(), compact).encode(env),
        Ok(Err(_)) | Err(_) => (atom::error(), rejected()).encode(env),
    }
}

fn binary<'a>(env: Env<'a>, bytes: &[u8]) -> Result<Term<'a>, String> {
    let mut owned = OwnedBinary::new(bytes.len()).ok_or_else(|| String::from(REFUSED))?;
    owned.as_mut_slice().copy_from_slice(bytes);
    Ok(Binary::from_owned(owned, env).encode(env))
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfsame_app_identity::ceremony::OfferCore;
    use selfsame_app_identity::codec;
    use selfsame_app_identity::didkey;
    use selfsame_app_identity::enrollment::{EnrollmentStatement, Observed};
    use selfsame_app_identity::json::{self, Json};
    use selfsame_app_identity::profile::ApplicationProfile;

    const APPLICATION_ID: &str = "https://photos.example/selfsame/application";
    const KID: &str = "https://photos.example/selfsame/application#enrollment-2026-01";
    const PERMISSION: &str = "https://photos.example/selfsame/application#device";
    const PLATFORM_BINDING: &str = "apple:TEAM123456:com.example.photos:https://photos.example";
    const RETURN_URI: &str = "https://photos.example/.well-known/selfsame/return";
    const NOW: i64 = 1_785_412_800;

    struct Fixture {
        profile: ApplicationProfile,
        offer: OfferCore,
        statement: EnrollmentStatement,
        statement_octets: Vec<u8>,
    }

    fn backend_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[0x41; 32])
    }

    fn fixture() -> Fixture {
        let profile = profile(&backend_key().verifying_key().to_bytes());
        let device_public_key = ed25519_dalek::SigningKey::from_bytes(&[0x23; 32])
            .verifying_key()
            .to_bytes();
        let offer = OfferCore {
            ceremony_id: codec::b64url(&[1; 32]),
            request_id: codec::b64url(&[2; 32]),
            application_id: APPLICATION_ID.to_string(),
            profile_version: 1,
            profile_digest: codec::b64url(profile.digest()),
            account_scope_id: codec::b64url(&[3; 32]),
            device_did: didkey::encode(&device_public_key),
            device_public_key,
            requested_permissions: vec![PERMISSION.to_string()],
            issued_at: NOW,
            expires_at: NOW + 120,
        };
        let descriptor = &profile.rendezvous[0];
        let statement = EnrollmentStatement {
            request_id: offer.request_id.clone(),
            ceremony_id: offer.ceremony_id.clone(),
            application_id: offer.application_id.clone(),
            profile_version: offer.profile_version,
            profile_digest: offer.profile_digest.clone(),
            account_scope_id: offer.account_scope_id.clone(),
            device_key_digest: enrollment::device_key_digest(&offer),
            requested_permissions: offer.requested_permissions.clone(),
            provider_id: descriptor.id.clone(),
            descriptor_digest: codec::b64url(&descriptor.digest),
            offer_digest: offer.digest(),
            platform_binding_id: PLATFORM_BINDING.to_string(),
            return_uri: RETURN_URI.to_string(),
            issued_at: offer.issued_at,
            expires_at: offer.expires_at,
        };
        let statement_octets = json::canonicalise(&enrollment::build(&statement));
        Fixture {
            profile,
            offer,
            statement,
            statement_octets,
        }
    }

    fn profile(public_key: &[u8; 32]) -> ApplicationProfile {
        let value = Json::obj([
            ("profileVersion", Json::int(1)),
            ("applicationId", Json::text(APPLICATION_ID)),
            ("accountAuthority", Json::text("accounts.photos.example")),
            ("verifierAudience", Json::text(APPLICATION_ID)),
            ("allowedPermissions", Json::arr([Json::text(PERMISSION)])),
            (
                "enrollment",
                Json::obj([
                    (
                        "requestSigningKeys",
                        Json::arr([Json::obj([
                            ("kid", Json::text(KID)),
                            (
                                "publicKeyJwk",
                                Json::obj([
                                    ("kty", Json::text("OKP")),
                                    ("crv", Json::text("Ed25519")),
                                    ("x", Json::text(codec::b64url(public_key))),
                                ]),
                            ),
                        ])]),
                    ),
                    (
                        "mobileBindings",
                        Json::arr([Json::obj([
                            ("id", Json::text(PLATFORM_BINDING)),
                            ("platform", Json::text("apple")),
                            ("teamId", Json::text("TEAM123456")),
                            ("bundleId", Json::text("com.example.photos")),
                            ("returnUri", Json::text(RETURN_URI)),
                        ])]),
                    ),
                ]),
            ),
            (
                "rendezvous",
                Json::arr([Json::obj([
                    ("id", Json::text("au-primary")),
                    ("url", Json::text("https://rendezvous.example")),
                    ("protocol", Json::text("selfsame-rendezvous-v1")),
                    ("pairingUrl", Json::text("https://pairing.example")),
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
                    ("url", Json::text("https://state.example")),
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
        ]);
        ApplicationProfile::recognise(&json::canonicalise(&value))
            .expect("the accepting profile fixture must recognise")
    }

    #[test]
    fn accepting_control_round_trips_and_verifies_only_under_the_declared_key() {
        let fixture = fixture();
        let key = backend_key();
        let compact = sign_enrollment_statement(&fixture.statement_octets, KID, key.as_bytes())
            .expect("the accepting fixture must sign");

        let (recognised, signed) =
            enrollment::recognise(&compact).expect("the producer output must recognise");
        assert_eq!(recognised, fixture.statement);
        assert_eq!(signed.payload_octets(), fixture.statement_octets);
        assert!(signed.verify(&key.verifying_key().to_bytes()).is_ok());
        let other = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        assert!(signed.verify(&other.verifying_key().to_bytes()).is_err());

        let descriptor_digest = codec::b64url(&fixture.profile.rendezvous[0].digest);
        let observed = Observed {
            profile: &fixture.profile,
            offer: &fixture.offer,
            provider_id: &fixture.profile.rendezvous[0].id,
            descriptor_digest: &descriptor_digest,
            platform_binding_id: None,
            now: NOW + 1,
        };
        assert_eq!(
            enrollment::verify(&compact, &observed)
                .expect("the module's full verifier must accept its producer"),
            fixture.statement
        );
    }

    #[test]
    fn a_malformed_statement_is_refused_without_a_signed_result() {
        let mut fixture = fixture();
        // The statement is the sole changed input from the accepting control.
        fixture.statement_octets.pop();
        assert_eq!(
            sign_enrollment_statement(&fixture.statement_octets, KID, backend_key().as_bytes()),
            Err(String::from(REFUSED))
        );
    }

    #[test]
    fn a_wrong_length_private_key_is_refused() {
        let fixture = fixture();
        let mut short_key = backend_key().as_bytes().to_vec();
        // The private-key bytes are the sole changed input from the control.
        short_key.pop();
        assert_eq!(
            sign_enrollment_statement(&fixture.statement_octets, KID, &short_key),
            Err(String::from(REFUSED))
        );
    }
}
