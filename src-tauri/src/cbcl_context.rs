//! SPEC-008 `REQ-906` / `CON-902` — profile-anchored origin trust and (in a
//! later slice) real verification-context assembly.
//!
//! The origin gate runs BEFORE any socket opens (`CON-901` pre-condition).
//! A scanned origin is never trusted for being scanned; it is trusted for
//! being pre-declared by an authenticated profile the person already holds
//! (`ADR-902`, acquisition per `IMPL-008` `ADR-912`). Zero matches and
//! multiple matches both refuse, distinctly, with no repair path — the person
//! is never offered a way to enter, choose, or repair a relay origin
//! (inherited `SPEC-007` `REQ-813`).

use selfsame_app_identity::cbcl_relay::{self, RelayPolicy};
use selfsame_app_identity::profile::ApplicationProfile;

/// Closed origin-gate refusals (`REQ-906`). Each surfaces as one distinct,
/// secret-free message and ends the attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginRefusal {
    /// No held authenticated profile pre-declares this origin as an eligible
    /// relay (includes: digest not in the compiled registry, forbidden
    /// operator, loopback in an ordinary build).
    NoEligibleMatch,
    /// More than one held profile pre-declares this origin — ambiguous, and
    /// the wallet never guesses which application the ceremony belongs to.
    AmbiguousMatch,
}

/// Admit an invitation origin only when exactly one held profile lists it as
/// its one eligible relay descriptor, and return that profile.
///
/// Within one profile, `cbcl_relay::verify_invitation_origin` is the one
/// existing eligibility decision (descriptor match + registry digest +
/// operator + loopback policy); relay origins are unique within a profile, so
/// per-profile the match count is 0 or 1. Across the held set this function
/// demands a total of exactly one.
pub fn gate_invitation_origin<'a>(
    held: &'a [ApplicationProfile],
    policy: &RelayPolicy<'_>,
    invitation_origin: &str,
) -> std::result::Result<&'a ApplicationProfile, OriginRefusal> {
    let mut matched = held.iter().filter(|profile| {
        cbcl_relay::verify_invitation_origin(profile, policy, invitation_origin).is_ok()
    });
    match (matched.next(), matched.next()) {
        (Some(only), None) => Ok(only),
        (Some(_), Some(_)) => Err(OriginRefusal::AmbiguousMatch),
        (None, _) => Err(OriginRefusal::NoEligibleMatch),
    }
}

use base64ct::{Base64UrlUnpadded, Encoding as _};
use rand::RngCore as _;
use selfsame_app_identity::accept::{
    ClosureSource, Freshness, IssuerState, VerificationMethod,
};
use selfsame_app_identity::alias::AcctUri;
use selfsame_app_identity::profile::{ApplicationId, Ed25519Jwk};
use selfsame_app_identity::scope::AccountScopeId;
use selfsame_app_identity::{codec, hierarchy, issuer};
use selfsame_pairing::{DeferredProofSigner, SelfsameVerificationContext};

use crate::commands::UiError;
use crate::custody::Custody;
use crate::store;

type Result<T> = std::result::Result<T, UiError>;

/// One recorded pairing-trust entry (`IMPL-008` `ADR-912`): the CON-201
/// authenticated profile octets and the account scope the person's grant for
/// that application used, both captured at grant issuance. The wallet pairs
/// only toward applications recorded here; first contact goes through the
/// LinkCode path first.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PairingTrustRecord {
    /// Canonical `applicationId`.
    pub application_id: String,
    /// Unpadded base64url of the exact recognised profile octets.
    pub profile_b64: String,
    /// The `CON-211` account scope of the person's account with it.
    pub account_scope_id: String,
    /// Unix seconds when the profile octets were fetched/verified — the
    /// `CON-220` cache clock for `fetch_or_cached`.
    pub recorded_at: i64,
}

const TRUST_INDEX_ENTRY: &str = "cbcl-pairing-trust-index";

fn trust_entry_name(application_id: &str) -> String {
    format!(
        "cbcl-pairing-trust-{}",
        codec::b64url(application_id.as_bytes())
    )
}

/// Record (or replace) one application's pairing-trust entry at grant
/// issuance. The octets were CON-201-verified by `authorise` before issuance;
/// nothing unverified reaches this record.
pub fn record_pairing_trust(
    application_id: &str,
    profile_octets: &[u8],
    account_scope_id: &str,
    now: i64,
) -> Result<()> {
    let record = PairingTrustRecord {
        application_id: application_id.to_owned(),
        profile_b64: codec::b64url(profile_octets),
        account_scope_id: account_scope_id.to_owned(),
        recorded_at: now,
    };
    let serialised =
        serde_json::to_string(&record).map_err(|_| UiError::from("StoreWriteFailed"))?;
    store::set(&trust_entry_name(application_id), &serialised)
        .map_err(|_| UiError::from("StoreWriteFailed"))?;
    let mut index = trust_index();
    if !index.iter().any(|id| id == application_id) {
        index.push(application_id.to_owned());
        let serialised =
            serde_json::to_string(&index).map_err(|_| UiError::from("StoreWriteFailed"))?;
        store::set(TRUST_INDEX_ENTRY, &serialised)
            .map_err(|_| UiError::from("StoreWriteFailed"))?;
    }
    Ok(())
}

fn trust_index() -> Vec<String> {
    store::get(TRUST_INDEX_ENTRY)
        .ok()
        .flatten()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// Every held trust record whose profile octets still recognise. A record
/// that fails recognition is skipped rather than repaired — it can only
/// refuse, and the next issuance rewrites it.
pub fn held_trust_records() -> Vec<(PairingTrustRecord, ApplicationProfile)> {
    trust_index()
        .iter()
        .filter_map(|id| {
            let text = store::get(&trust_entry_name(id)).ok().flatten()?;
            let record: PairingTrustRecord = serde_json::from_str(&text).ok()?;
            let octets = Base64UrlUnpadded::decode_vec(&record.profile_b64).ok()?;
            let profile = ApplicationProfile::recognise(&octets).ok()?;
            Some((record, profile))
        })
        .collect()
}

/// `CON-902`'s clock-skew bound: SPEC-004's accepted five minutes.
pub const CLOCK_SKEW_SECONDS: i64 = 300;

/// The one ceremony scope: the matched profile's single allowed permission.
///
/// `recognise_transfer_claims` requires the context's operation permissions
/// to equal the transferred scope exactly, and the transfer does not exist at
/// assembly time — so only a profile declaring exactly one permission names
/// an unambiguous expectation.
// SIMPLIFY: multi-permission application profiles refuse pairing until the
// ceremony wire carries a scope commitment the wallet can pre-verify — an
// upstream cbcl-pairing evolution, recorded in SPEC-008's Open list via
// IMPL-008 ADR-912's amendment note (trace: SPEC-008 CON-902).
pub fn single_permission(profile: &ApplicationProfile) -> Result<String> {
    match profile.allowed_permissions.as_slice() {
        [only] => Ok(only.clone()),
        _ => Err(UiError::from("PairingScopeAmbiguous")),
    }
}

/// Project one verified, locally replayed did-crdt document into the accept
/// layer's issuer state. The three by-construction verdicts follow
/// `replay_closure`'s guarantees, exactly as the Path-B NIF projection does;
/// assertion methods are ordered by id and twinned positionally as
/// `#jwk-{index}` — did-crdt's own numbering rule.
pub fn issuer_state_from_document(
    document: &did_crdt::core::document::Document,
    source: ClosureSource,
    closure_age_seconds: i64,
) -> Result<IssuerState> {
    use did_crdt::core::delta::VerificationRelationship;
    let mut asserting: Vec<_> = document
        .verification_methods()
        .into_iter()
        .filter(|entry| {
            entry
                .relationships
                .contains(&VerificationRelationship::AssertionMethod)
        })
        .collect();
    asserting.sort_by(|a, b| a.id.cmp(&b.id));
    let assertion_methods = asserting
        .into_iter()
        .enumerate()
        .map(|(index, entry)| {
            let raw = entry
                .public_key_multibase
                .strip_prefix('u')
                .ok_or_else(|| UiError::from("PairingIssuerUnavailable"))
                .and_then(|text| {
                    Base64UrlUnpadded::decode_vec(text)
                        .map_err(|_| UiError::from("PairingIssuerUnavailable"))
                })?;
            let public_key: [u8; 32] = raw
                .try_into()
                .map_err(|_| UiError::from("PairingIssuerUnavailable"))?;
            Ok(VerificationMethod {
                id: format!("{}#jwk-{index}", document.did),
                kind: "JsonWebKey".into(),
                jwk: Ed25519Jwk {
                    public_key,
                    x: codec::b64url(&public_key),
                },
                has_private_component: false,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(IssuerState {
        did: document.did.to_string(),
        did_recomputed_ok: true,
        deltas_verified: true,
        locally_closed: true,
        deactivated: document.is_deactivated(),
        assertion_methods,
        revoked_credential_ids: document.revoked_credential_ids(),
        closure_age_seconds,
        source,
        also_known_as: document.also_known_as(),
    })
}

/// Everything the claimant pump needs, assembled per `CON-902`'s table with
/// `proof: None` plus a deferred grant-bound signer.
pub struct AssembledClaimant {
    /// The verification context, complete except for its deferred proof.
    pub context: SelfsameVerificationContext,
    /// Entropy plus a device-key signer for the grant-bound `CON-207` proof.
    pub deferred: DeferredProofSigner,
}

/// Assemble the real verification context for one gated invitation origin.
///
/// Every field maps to its authoritative source, and every missing source
/// refuses before any transport opens, naming the missing capability and
/// never the missing bytes (`CON-902` error model).
pub async fn assemble_claimant(
    record: &PairingTrustRecord,
    passcode: &str,
) -> Result<AssembledClaimant> {
    // Freshness: the held octets seed CON-220's cache rule; past the bound
    // the profile re-fetches or the assembly fails closed.
    let application_id = ApplicationId::parse(&record.application_id)
        .map_err(|_| UiError::from("PairingProfileUnavailable"))?;
    let octets = Base64UrlUnpadded::decode_vec(&record.profile_b64)
        .map_err(|_| UiError::from("PairingProfileUnavailable"))?;
    let held = selfsame_app_identity_net::profile::FetchedProfile {
        profile: ApplicationProfile::recognise(&octets)
            .map_err(|_| UiError::from("PairingProfileUnavailable"))?,
        octets,
        fetched_at: record.recorded_at,
    };
    let now = crate::commands::now() as i64;
    let fresh =
        selfsame_app_identity_net::profile::fetch_or_cached(&application_id, Some(&held), now)
            .await
            .map_err(|_| UiError::from("PairingProfileUnavailable"))?;
    let profile = fresh.profile;

    let permission = single_permission(&profile)?;
    let scope = AccountScopeId::parse(&record.account_scope_id)
        .map_err(|_| UiError::from("ScopeNotCanonical"))?;

    // Presence, then the keys — which exist only inside this closure. The
    // hierarchy home key is the wallet's per-application device identity
    // (`CON-902`: the `Custody::use_hierarchy_root` path).
    let (identity, device_public_key, device_secret) =
        Custody::use_hierarchy_root(passcode, |root| {
            let home = hierarchy::derive(root, &profile.application_id, &scope);
            let identity = issuer::create(
                home.signing_key(),
                &profile.account_authority,
                (now as u64) * 1_000,
            )
            .map_err(|_| UiError::from("PairingIdentityUnavailable"))?;
            Ok::<_, UiError>((
                identity,
                home.public_key(),
                zeroize::Zeroizing::new(home.signing_key().to_bytes()),
            ))
        })??;

    let account =
        AcctUri::parse(&identity.acct_uri).map_err(|_| UiError::from("PairingIdentityUnavailable"))?;

    // CON-221 discipline: the authority either binds this exact account
    // reciprocally or assembly fails closed — never read as first use.
    let jrd = selfsame_app_identity_net::webfinger::fetch_and_verify(
        &account,
        &identity.did,
        &[identity.acct_uri.clone()],
    )
    .await
    .map_err(|_| UiError::from("AuthorityUnreachable"))?;

    // The issuer closure is the person's own home DID, resolved through the
    // profile's declared state resolvers. No bundle stands in here: pairing
    // acceptance is never the degraded first-ceremony bootstrap.
    let resolved = selfsame_app_identity_net::state::resolve_closure(
        &profile,
        &identity.did,
        None,
        selfsame_app_identity_net::state::Acceptance::Repeat,
    )
    .await
    .map_err(|_| UiError::from("PairingIssuerUnavailable"))?;
    let issuer_state = issuer_state_from_document(&resolved.document, resolved.source, 0)?;

    let mut nonce = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mut session_entropy = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut session_entropy);
    let signing = ed25519_dalek::SigningKey::from_bytes(&device_secret);
    let deferred = DeferredProofSigner {
        nonce,
        verifier_session: codec::b64url(&session_entropy),
        signer: Box::new(move |input| {
            use ed25519_dalek::Signer as _;
            signing.sign(input).to_bytes()
        }),
    };

    Ok(AssembledClaimant {
        context: SelfsameVerificationContext {
            profile,
            account,
            device_public_key,
            operation_permissions: vec![permission],
            now,
            clock_skew_seconds: CLOCK_SKEW_SECONDS,
            freshness: Freshness::SessionEstablishment,
            issuer: Some(issuer_state),
            jrd: Some(jrd),
            projection: None,
            proof: None,
        },
        deferred,
    })
}

#[cfg(test)]
#[path = "../../crates/selfsame-app-identity/tests/common/mod.rs"]
mod fixture;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbcl_registry;
    use selfsame_app_identity::json::Json;

    use super::fixture;

    const ORIGIN: &str = "https://relay.example:9443";
    const OTHER_ORIGIN: &str = "https://other.example:9443";

    fn profile_with_relay(operator: &str, origin: &str, digest_byte: u8) -> ApplicationProfile {
        let octets = fixture::with_member(
            "cbclPairingRelays",
            Json::arr([fixture::cbcl_relay(operator, origin, 1, 1, digest_byte)]),
        );
        ApplicationProfile::recognise(&octets).expect("fixture profile recognised")
    }

    fn approving_policy(digests: &'static [[u8; 32]]) -> RelayPolicy<'static> {
        RelayPolicy {
            forbidden_operator_ids: &[],
            approved_conformance: digests,
            allow_loopback: false,
        }
    }

    // TEST-909 (positive): exactly one eligible descriptor proceeds, and the
    // gate returns the owning profile.
    #[test]
    fn one_eligible_match_admits_and_names_the_profile() {
        let held = vec![
            profile_with_relay("op-a", ORIGIN, 3),
            profile_with_relay("op-b", OTHER_ORIGIN, 3),
        ];
        let policy = approving_policy(&[[19; 32]]);
        let admitted = gate_invitation_origin(&held, &policy, ORIGIN).expect("one match admits");
        assert_eq!(
            admitted.cbcl_pairing_relays[0].relay_origin, ORIGIN,
            "the admitted profile is the one that pre-declared the origin"
        );
    }

    // TEST-909 (negative): zero matches refuse — nothing pre-declared the
    // origin. The gate is pure, so no socket can have opened.
    #[test]
    fn zero_matches_refuse() {
        let held = vec![profile_with_relay("op-a", OTHER_ORIGIN, 3)];
        let policy = approving_policy(&[[19; 32]]);
        assert_eq!(
            gate_invitation_origin(&held, &policy, ORIGIN).unwrap_err(),
            OriginRefusal::NoEligibleMatch
        );
        assert_eq!(
            gate_invitation_origin(&[], &policy, ORIGIN).unwrap_err(),
            OriginRefusal::NoEligibleMatch,
            "an empty held set refuses everything"
        );
    }

    // TEST-909 (negative): two held profiles pre-declaring one origin is
    // ambiguous, and the wallet refuses rather than guesses.
    #[test]
    fn two_matches_refuse_as_ambiguous() {
        let held = vec![
            profile_with_relay("op-a", ORIGIN, 3),
            profile_with_relay("op-b", ORIGIN, 3),
        ];
        let policy = approving_policy(&[[19; 32]]);
        assert_eq!(
            gate_invitation_origin(&held, &policy, ORIGIN).unwrap_err(),
            OriginRefusal::AmbiguousMatch
        );
    }

    // TEST-910: a descriptor whose conformance digest is not in the compiled
    // registry refuses, even though the origin matches exactly.
    #[test]
    fn unregistered_digest_refuses() {
        let held = vec![profile_with_relay("op-a", ORIGIN, 7)];
        let policy = approving_policy(&[[19; 32]]);
        assert_eq!(
            gate_invitation_origin(&held, &policy, ORIGIN).unwrap_err(),
            OriginRefusal::NoEligibleMatch
        );
    }

    // TEST-910: the shipped registry is empty, so the production policy
    // refuses every non-loopback origin — the valid fail-closed birth state.
    #[test]
    fn empty_registry_refuses_every_origin() {
        assert!(cbcl_registry::APPROVED_CONFORMANCE.is_empty());
        let held = vec![
            profile_with_relay("op-a", ORIGIN, 3),
            profile_with_relay("op-b", "https://chat.anuna.io:9443", 19),
        ];
        let policy = cbcl_registry::production_relay_policy();
        for origin in [ORIGIN, "https://chat.anuna.io:9443"] {
            assert_eq!(
                gate_invitation_origin(&held, &policy, origin).unwrap_err(),
                OriginRefusal::NoEligibleMatch,
                "{origin} must refuse against an empty registry"
            );
        }
    }

    // CON-902: only a single-permission profile names an unambiguous
    // ceremony expectation; anything else refuses, closed.
    #[test]
    fn single_permission_requires_exactly_one() {
        let one = profile_with_relay("op-a", ORIGIN, 3);
        assert_eq!(single_permission(&one).expect("one permission"), fixture::PERMISSION);
        // The profile grammar itself refuses an empty permission list, so the
        // only refusal single_permission can meet is "more than one".
        let two = ApplicationProfile::recognise(&fixture::with_member(
            "allowedPermissions",
            Json::arr([
                Json::text(fixture::PERMISSION),
                Json::text("https://photos.example/selfsame/application#other"),
            ]),
        ))
        .expect("profile with two permissions");
        assert!(single_permission(&two).is_err());
    }

    // ADR-912: the trust record round-trips through its serialised form and
    // its store entry name is a function of the application id alone.
    #[test]
    fn trust_record_round_trips() {
        let record = PairingTrustRecord {
            application_id: fixture::APPLICATION_ID.into(),
            profile_b64: codec::b64url(b"octets"),
            account_scope_id: "A".repeat(43),
            recorded_at: 1_755_648_000,
        };
        let text = serde_json::to_string(&record).expect("serialise");
        let back: PairingTrustRecord = serde_json::from_str(&text).expect("parse");
        assert_eq!(back.application_id, record.application_id);
        assert_eq!(back.profile_b64, record.profile_b64);
        assert_eq!(back.account_scope_id, record.account_scope_id);
        assert_eq!(
            trust_entry_name(fixture::APPLICATION_ID),
            trust_entry_name(fixture::APPLICATION_ID)
        );
        assert_ne!(
            trust_entry_name(fixture::APPLICATION_ID),
            trust_entry_name(fixture::OTHER_APPLICATION_ID)
        );
    }

    // REQ-908 boundary: the ordinary policy never admits loopback, even when
    // a digest is somehow approved.
    #[test]
    fn production_policy_refuses_loopback() {
        let held = vec![profile_with_relay("op-a", "https://localhost:7443", 3)];
        let policy = RelayPolicy {
            forbidden_operator_ids: &[],
            approved_conformance: &[[19; 32]],
            allow_loopback: false,
        };
        assert_eq!(
            gate_invitation_origin(&held, &policy, "https://localhost:7443").unwrap_err(),
            OriginRefusal::NoEligibleMatch
        );
    }
}
