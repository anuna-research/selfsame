//! `CON-214` enrollment signing at the CBCL/BEAM boundary.
//!
//! The hub supplies canonical unsigned statement bytes, the declared `kid` and
//! public key, and a 32-octet Ed25519 private seed for each call. This module
//! retains no signing state. Before constructing a signing key it delegates
//! recognition of both the statement and protected header to
//! `selfsame-app-identity`, then requires the seed to derive the independently
//! supplied declared public key before delegating compact-JWS production.

use rustler::types::atom;
use rustler::{Binary, Encoder, Env, OwnedBinary, Term};
use selfsame_app_identity::enrollment;
use selfsame_app_identity::profile::ApplicationProfile;

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
    declared_public_key: &[u8],
    private_key: &[u8],
) -> Result<String, String> {
    // Keep this guard here as well as at the NIF boundary: this helper is a
    // public Rust API, and no caller may reach header construction with an
    // unbounded identifier.
    if kid.len() > enrollment::MAX_ENROLLMENT_KID_OCTETS {
        return Err(String::from(REFUSED));
    }

    // Recognition deliberately precedes even construction of the secret key.
    // This is the enrollment module's own grammar and protected-header policy,
    // not a BEAM-side restatement of CON-214.
    let recognised =
        enrollment::recognise_unsigned(statement, kid).map_err(|_| String::from(REFUSED))?;

    let declared: &[u8; 32] =
        declared_public_key.try_into().map_err(|_| String::from(REFUSED))?;
    let seed: &[u8; 32] = private_key.try_into().map_err(|_| String::from(REFUSED))?;
    let compact = {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
        // This is the declaration check: `declared` came from the caller's
        // authenticated profile/configuration, independently of the seed. It
        // happens before the private key touches the statement.
        if signing_key.verifying_key().to_bytes() != *declared {
            return Err(String::from(REFUSED));
        }
        enrollment::sign(&recognised, kid, &signing_key)
    };

    // Refuse producer/recogniser drift at the boundary where it would otherwise
    // turn every valid hub request into a wallet rejection.
    let (round_trip, signed) =
        enrollment::recognise(&compact).map_err(|_| String::from(REFUSED))?;
    if round_trip != recognised || signed.kid != kid {
        return Err(String::from(REFUSED));
    }

    Ok(compact)
}

/// `cbcl_selfsame_erl:sign_enrollment/4`.
///
/// Arguments are `(canonical_statement_binary, kid_binary,
/// declared_public_key_binary, private_seed_binary)`. The result is
/// `{ok, CompactJwsBinary}` or the sole refusal `{error, rejected}`.
#[rustler::nif]
pub fn sign_enrollment<'a>(
    env: Env<'a>,
    statement: Term<'a>,
    kid: Term<'a>,
    declared_public_key: Term<'a>,
    private_key: Term<'a>,
) -> Term<'a> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Decode the `kid` first and reject its raw binary length before UTF-8
        // scanning, JSON construction, or canonicalisation. Decoding a BEAM
        // binary borrows its storage and does not copy it.
        let kid: Binary<'a> = kid.decode().map_err(|_| String::from(REFUSED))?;
        if kid.len() > enrollment::MAX_ENROLLMENT_KID_OCTETS {
            return Err(String::from(REFUSED));
        }
        let kid = std::str::from_utf8(kid.as_slice()).map_err(|_| String::from(REFUSED))?;

        let statement: Binary<'a> =
            statement.decode().map_err(|_| String::from(REFUSED))?;
        let declared_public_key: Binary<'a> =
            declared_public_key.decode().map_err(|_| String::from(REFUSED))?;
        let private_key: Binary<'a> =
            private_key.decode().map_err(|_| String::from(REFUSED))?;

        sign_enrollment_statement(
            statement.as_slice(),
            kid,
            declared_public_key.as_slice(),
            private_key.as_slice(),
        )
        .and_then(|compact| binary(env, compact.as_bytes()))
    }));

    match result {
        Ok(Ok(compact)) => (atom::ok(), compact).encode(env),
        Ok(Err(_)) | Err(_) => (atom::error(), rejected()).encode(env),
    }
}

/// Recognise and sign one `CON-214` statement, taking the declared key from the
/// PROFILE rather than from the caller.
///
/// `sign_enrollment_statement` proves only that the seed derives the public key
/// it was handed. When both come from one deployment's configuration that is a
/// comparison of configuration with itself: advance configuration to key B while
/// the published profile still declares only A, and signing succeeds while every
/// wallet refuses the result — which is precisely the rollout failure the check
/// is supposed to prevent.
///
/// Here the declared key is read out of recognised profile bytes, so the
/// comparison is against the document a wallet will actually fetch. That makes
/// the rotation overlap mean something: a `kid` the profile does not declare
/// cannot sign, whatever configuration says.
pub fn sign_enrollment_profile_bound(
    statement: &[u8],
    kid: &str,
    profile_bytes: &[u8],
    private_key: &[u8],
) -> Result<String, String> {
    if kid.len() > enrollment::MAX_ENROLLMENT_KID_OCTETS {
        return Err(String::from(REFUSED));
    }
    // Recognition of the profile precedes everything, including any use of the
    // `kid` as a lookup key: an unrecognised profile has no declared set.
    let profile = ApplicationProfile::recognise(profile_bytes).map_err(|_| String::from(REFUSED))?;
    let declared = profile
        .enrollment_keys
        .iter()
        .find(|key| key.kid == kid)
        .ok_or_else(|| String::from(REFUSED))?;

    // Delegate to the existing path with the PROFILE's key as the declared one.
    // Sharing that function keeps one statement recogniser, one header policy
    // and one producer/recogniser round-trip check; only the provenance of the
    // declared key differs, which is the entire point of this entry point.
    sign_enrollment_statement(statement, kid, &declared.jwk.public_key, private_key)
}


/// `cbcl_selfsame_erl:sign_enrollment_profile_bound/4`.
///
/// Arguments are `(canonical_statement_binary, kid_binary,
/// canonical_profile_binary, private_seed_binary)`. The result is
/// `{ok, CompactJwsBinary}` or the sole refusal `{error, rejected}`.
#[rustler::nif(name = "sign_enrollment_profile_bound")]
pub fn sign_enrollment_profile_bound_nif<'a>(
    env: Env<'a>,
    statement: Term<'a>,
    kid: Term<'a>,
    profile: Term<'a>,
    private_key: Term<'a>,
) -> Term<'a> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let kid: Binary<'a> = kid.decode().map_err(|_| String::from(REFUSED))?;
        if kid.len() > enrollment::MAX_ENROLLMENT_KID_OCTETS {
            return Err(String::from(REFUSED));
        }
        let kid = std::str::from_utf8(kid.as_slice()).map_err(|_| String::from(REFUSED))?;
        let statement: Binary<'a> = statement.decode().map_err(|_| String::from(REFUSED))?;
        let profile: Binary<'a> = profile.decode().map_err(|_| String::from(REFUSED))?;
        let private_key: Binary<'a> = private_key.decode().map_err(|_| String::from(REFUSED))?;
        sign_enrollment_profile_bound(
            statement.as_slice(),
            kid,
            profile.as_slice(),
            private_key.as_slice(),
        )
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
        let public_key = key.verifying_key().to_bytes();
        let compact = sign_enrollment_statement(
            &fixture.statement_octets,
            KID,
            &public_key,
            key.as_bytes(),
        )
        .expect("the accepting fixture must sign");

        let (recognised, signed) =
            enrollment::recognise(&compact).expect("the producer output must recognise");
        assert_eq!(recognised, fixture.statement);
        assert_eq!(signed.payload_octets(), fixture.statement_octets);
        assert!(signed.verify(&key.verifying_key().to_bytes()).is_ok());
        let other = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        assert!(signed.verify(&other.verifying_key().to_bytes()).is_err());
        assert_eq!(
            sign_enrollment_statement(
                &fixture.statement_octets,
                KID,
                &public_key,
                other.as_bytes(),
            ),
            Err(String::from(REFUSED)),
            "holding the declaration and kid fixed while varying only the seed must refuse"
        );

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
        let key = backend_key();
        let public_key = key.verifying_key().to_bytes();
        assert_eq!(
            sign_enrollment_statement(
                &fixture.statement_octets,
                KID,
                &public_key,
                key.as_bytes(),
            ),
            Err(String::from(REFUSED))
        );
    }

    #[test]
    fn a_wrong_length_private_key_is_refused() {
        let fixture = fixture();
        let key = backend_key();
        let public_key = key.verifying_key().to_bytes();
        let mut short_key = key.as_bytes().to_vec();
        // The private-key bytes are the sole changed input from the control.
        short_key.pop();
        assert_eq!(
            sign_enrollment_statement(&fixture.statement_octets, KID, &public_key, &short_key),
            Err(String::from(REFUSED))
        );
    }

    // ── profile-bound signing ────────────────────────────────────────────

    // THE FAILURE THE CALLER-SUPPLIED PATH CANNOT SEE.
    //
    // `sign_enrollment_statement` proves the seed derives the key it was
    // handed. A hub that advanced its configuration to key B while its
    // published profile still declares only A supplies a MUTUALLY CONSISTENT
    // {kid, key B, seed B} — so that check passes and every wallet then refuses
    // the request, which is exactly the rollout failure it is credited with
    // preventing. Both halves came from one configuration, so it compared
    // configuration with itself.
    #[test]
    fn profile_bound_signing_refuses_a_key_the_profile_does_not_declare() {
        let f = fixture();
        let rotated = ed25519_dalek::SigningKey::from_bytes(&[0x5b; 32]);

        // The caller-supplied path ACCEPTS the rotated key, because the seed
        // and the declared key it was given agree with each other.
        assert!(sign_enrollment_statement(
            &f.statement_octets,
            KID,
            &rotated.verifying_key().to_bytes(),
            &[0x5b; 32],
        )
        .is_ok());

        // The profile-bound path refuses it: the profile declares the backend
        // key, and this seed does not derive that.
        assert!(sign_enrollment_profile_bound(
            &f.statement_octets,
            KID,
            f.profile.canonical_bytes(),
            &[0x5b; 32],
        )
        .is_err());

        // The control — the key the profile DOES declare still signs, so the
        // refusal above is the declaration check and not a path that refuses
        // everything.
        let compact = sign_enrollment_profile_bound(
            &f.statement_octets,
            KID,
            f.profile.canonical_bytes(),
            &[0x41; 32],
        )
        .expect("the declared key signs");
        assert!(enrollment::recognise(&compact).is_ok());
    }

    // A `kid` absent from the declared set has no key to compare against, and
    // the profile is the only thing that can say so.
    #[test]
    fn profile_bound_signing_refuses_an_undeclared_kid() {
        let f = fixture();
        assert!(sign_enrollment_profile_bound(
            &f.statement_octets,
            "https://photos.example/selfsame/application#enrollment-2026-07",
            f.profile.canonical_bytes(),
            &[0x41; 32],
        )
        .is_err());
    }

    // Unrecognised profile bytes have no declared set at all, so nothing is
    // signed — recognition precedes the `kid` lookup rather than following it.
    #[test]
    fn profile_bound_signing_refuses_unrecognised_profile_bytes() {
        let f = fixture();
        for bytes in [&b""[..], &b"{}"[..], &b"not json at all"[..]] {
            assert!(sign_enrollment_profile_bound(
                &f.statement_octets,
                KID,
                bytes,
                &[0x41; 32],
            )
            .is_err());
        }
    }

}
