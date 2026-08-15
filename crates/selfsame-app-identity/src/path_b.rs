//! A NIF-ready, fail-closed adapter for a Path-B device-grant presentation.
//!
//! [`crate::accept::accept_grant`] is the complete `CON-206` predicate.  An
//! adopting application must not reconstruct a looser subset of that predicate
//! around a compact JWS; this module fixes the choices that `SPEC-053` Path B
//! makes for its first device presentation:
//!
//! - verification is always at session-establishment freshness;
//! - the issuer closure must have come from a declared state resolver, never
//!   the presenter or a bundle/cache; and
//! - proof of possession, reciprocal account binding, and an offered device
//!   key are mandatory inputs.
//!
//! The boundary is deliberately typed.  A Rustler NIF decodes BEAM terms into
//! these already-recognised values and calls [`verify_session_establishment`];
//! it does not parse or verify the grant itself.  This keeps the one compact
//! JWS recogniser and the one authorization predicate in `selfsame-app-identity`.

use crate::accept::{
    accept_grant, check_standing, rehydrate_accepted_grant, AcceptError, ClosureSource, Evidence, Expectation, Freshness, IssuerState,
    Projection, VerificationMethod,
};
use crate::alias::{AcctUri, Jrd};
use crate::profile::{ApplicationProfile, Ed25519Jwk};
use crate::proof::Challenge;
use crate::UnixSeconds;

/// Minimum distinct declared resolver observations required by CBCL Path-B
/// admission.
///
/// This is 1, and that is a deliberate, dated reduction rather than the value
/// the security argument wants. One resolver is one party that can withhold a
/// revocation: with a single observation there is nobody to disagree with it, so
/// a resolver that simply omits a revoked credential id is believed, and the
/// grant it should have killed stays live until the closure ages out.
///
/// It was 2 — REQ-032's "independently operated" pair. The deployment has one
/// resolver, and the alternative on offer was a profile declaring two ids that
/// both point at that one host, which this function cannot detect (it dedupes on
/// `resolver_id`, not on the endpoint behind it). That shape passes every check
/// while supplying none of the independence, and it does it invisibly. A quorum
/// of 1 is weaker in exactly the same way and says so.
///
/// RAISE THIS BACK TO 2 when a second independently operated resolver exists.
/// Nothing else has to change: every call site below is written against the
/// constant, and the observation-side checks it guards — undeclared ids and
/// repeated ids are still refused — keep working at either value.
pub const MINIMUM_RESOLVER_QUORUM: usize = 1;

/// One locally verified resolver observation for the Path-B revocation union.
///
/// The signed closure is replayed by the effectful resolver shell before this
/// value exists. This pure core combines already verified observations only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolverRevocations<'a> {
    /// The exact profile-declared resolver identifier.
    pub resolver_id: &'a str,
    /// Credential IDs in that resolver's verified revocation G-Set.
    pub revoked_credential_ids: &'a [String],
}

/// Require [`MINIMUM_RESOLVER_QUORUM`] distinct declared resolver observations
/// and return their sorted, duplicate-free revocation union.
///
/// The caller does not get to substitute a cache, repeat one resolver under two
/// labels, or present an observation from a resolver the profile never declared.
/// Network I/O stays in the shell; this function is the portable, identical
/// decision it must feed.
///
/// At a quorum of 1 the caller CAN choose an answer omitting a revocation,
/// because the single declared resolver is the only source and nothing
/// contradicts it. That is the property the constant's value gives up, and it is
/// documented here rather than only at the constant because this is the function
/// whose name still says "union".
pub fn union_resolver_revocations(
    profile: &ApplicationProfile,
    observations: &[ResolverRevocations<'_>],
) -> Result<Vec<String>, VerifyError> {
    let declared: Vec<&str> = profile.state_resolvers.iter().map(|resolver| resolver.id.as_str()).collect();
    if declared.len() < MINIMUM_RESOLVER_QUORUM {
        return Err(VerifyError::ResolverQuorum);
    }
    let mut seen: Vec<&str> = Vec::with_capacity(observations.len());
    let mut union = Vec::new();
    for observation in observations {
        if !declared.contains(&observation.resolver_id) || seen.contains(&observation.resolver_id) {
            return Err(VerifyError::ResolverQuorum);
        }
        seen.push(observation.resolver_id);
        for credential_id in observation.revoked_credential_ids {
            if !union.contains(credential_id) {
                union.push(credential_id.clone());
            }
        }
    }
    if seen.len() < MINIMUM_RESOLVER_QUORUM {
        return Err(VerifyError::ResolverQuorum);
    }
    union.sort();
    Ok(union)
}

/// The local, authenticated facts a Path-B grant must match.
///
/// This is intentionally not an open-ended request structure: a Path-B device
/// presentation is always a new session establishment, not a continuation.
#[derive(Clone, Copy, Debug)]
pub struct GrantRequest<'a> {
    profile: &'a ApplicationProfile,
    account: &'a AcctUri,
    device_public_key: &'a [u8; 32],
    operation_permissions: &'a [&'a str],
    now: UnixSeconds,
    clock_skew_seconds: i64,
}

impl<'a> GrantRequest<'a> {
    /// Construct the authenticated context for one Path-B device presentation.
    pub fn new(
        profile: &'a ApplicationProfile,
        account: &'a AcctUri,
        device_public_key: &'a [u8; 32],
        operation_permissions: &'a [&'a str],
        now: UnixSeconds,
        clock_skew_seconds: i64,
    ) -> Self {
        Self {
            profile,
            account,
            device_public_key,
            operation_permissions,
            now,
            clock_skew_seconds,
        }
    }

    /// The fixed freshness tier used by Path-B presentation.
    pub fn freshness(&self) -> Freshness {
        Freshness::SessionEstablishment
    }
}

/// Resolver and proof evidence for a Path-B device presentation.
///
/// The constructor accepts an issuer state so that the shell can use its
/// `did:crdt` resolver, but [`verify_session_establishment`] rejects any state
/// not marked [`ClosureSource::StateResolver`] before accepting the grant.
#[derive(Clone, Copy, Debug)]
pub struct GrantEvidence<'a> {
    issuer: &'a IssuerState,
    jrd: &'a Jrd,
    projection: Option<Projection>,
    challenge: &'a Challenge,
    signature: &'a [u8; 64],
    session: &'a str,
}

impl<'a> GrantEvidence<'a> {
    /// Construct the evidence whose provenance and proof are required for
    /// Path-B presentation.
    pub fn new(
        issuer: &'a IssuerState,
        jrd: &'a Jrd,
        projection: Option<Projection>,
        challenge: &'a Challenge,
        signature: &'a [u8; 64],
        session: &'a str,
    ) -> Self {
        Self {
            issuer,
            jrd,
            projection,
            challenge,
            signature,
            session,
        }
    }
}

/// The stable outward outcome of a successful Path-B verification.
///
/// It contains only the facts the hub needs to bind a device grant beneath an
/// account.  The original credential bytes stay with the caller's durable
/// store, where the adopting application controls retention and revalidation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGrant {
    /// The account home DID that issued and owns this device grant.
    pub account_did: String,
    /// The credential identifier, used by a resolver's revocation G-Set.
    pub grant_id: String,
    /// The exact device key the signed credential binds.
    pub device_public_key: [u8; 32],
    /// The declared permissions, already checked against the profile.
    pub permissions: Vec<String>,
    /// Verified exclusive expiry instant, in Unix seconds.
    pub valid_until: UnixSeconds,
    grant: crate::grant::DeviceGrant,
}

/// Authenticated inputs for a Path-B per-frame standing check.
///
/// The checker accepts a [`VerifiedGrant`], never credential bytes.  The only
/// constructor for that sealed type is full session establishment, which
/// includes the device proof.  There is consequently no proof argument or
/// bypass switch on this API.
#[derive(Clone, Copy, Debug)]
pub struct StandingRequest<'a> {
    profile: &'a ApplicationProfile,
    operation_permissions: &'a [&'a str],
    now: UnixSeconds,
    clock_skew_seconds: i64,
}

impl<'a> StandingRequest<'a> {
    /// Construct the local requirements for one frame.
    pub fn new(
        profile: &'a ApplicationProfile,
        operation_permissions: &'a [&'a str],
        now: UnixSeconds,
        clock_skew_seconds: i64,
    ) -> Self {
        Self { profile, operation_permissions, now, clock_skew_seconds }
    }
}

/// Independently resolved state supplied for a standing check.
#[derive(Clone, Copy, Debug)]
pub struct StandingEvidence<'a> {
    issuer: &'a IssuerState,
    projection: Option<Projection>,
}

impl<'a> StandingEvidence<'a> {
    /// Construct standing evidence from a freshly resolved state closure.
    pub fn new(issuer: &'a IssuerState, projection: Option<Projection>) -> Self {
        Self { issuer, projection }
    }
}

/// Why the Path-B adapter refused a presentation.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// Fewer than two distinct declared resolver closures were available, or a
    /// resolver identity was duplicated or undeclared.
    #[error("Path-B resolver quorum was not independently established")]
    ResolverQuorum,
    /// The issuer closure was not freshly resolved through a profile-declared
    /// state resolver.  A Path-B hub never relaxes this to bundle acceptance.
    #[error("issuer closure was not resolved from a declared state resolver")]
    NonResolverClosure,
    /// One of `CON-206`'s thirteen ordered checks rejected the grant.
    #[error(transparent)]
    Grant(#[from] AcceptError),
}

// ── the resolver quorum, in one place ────────────────────────────────────────

/// One resolver's locally verified account of a DID, as the quorum sees it.
///
/// Both adapters decode into this: the Rustler NIF from BEAM terms, the WASM
/// facade from JSON. Neither decides anything about it. That split exists
/// because the two used to carry SEPARATE copies of the agreement rule, and
/// they had already drifted -- the native side compared assertion methods by
/// equality while the browser side compared only their COUNT, so two resolvers
/// reporting different keys in equal numbers read as agreeing in the browser
/// and disagreeing on the hub. A JavaScript layer above had been given a
/// compensating check, which protected one caller and no other.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolverObservation {
    /// The exact profile-declared resolver identifier.
    pub resolver_id: String,
    /// The DID this resolver answered about.
    pub did: String,
    /// The DID was recomputed from its own genesis and matched.
    pub did_recomputed_ok: bool,
    /// Every delta in the replayed closure verified.
    pub deltas_verified: bool,
    /// No delta in the closure dangled a parent.
    pub locally_closed: bool,
    /// The DID's deactivation latch.
    pub deactivated: bool,
    /// Assertion methods the replayed document exposes.
    pub assertion_methods: Vec<ClosureAssertionMethod>,
    /// This resolver's credential-revocation G-Set.
    pub revoked_credential_ids: Vec<String>,
    /// The DID's `alsoKnownAs` entries.
    pub also_known_as: Vec<String>,
    /// Unix seconds at which THIS VERIFIER fetched, never a resolver's claim.
    pub fetched_at_seconds: UnixSeconds,
}

/// One assertion method, with its key already recognised as Ed25519-length.
///
/// `[u8; 32]` rather than a byte vector on purpose: an unvalidated length
/// cannot reach the quorum, so no caller can compare, or fail to compare, keys
/// of differing lengths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosureAssertionMethod {
    /// Method identifier.
    pub id: String,
    /// The exact resolved verification-method kind.
    pub kind: String,
    /// Ed25519 verification key bytes.
    pub public_key: [u8; 32],
    /// Whether the source JWK illegally included private key material.
    pub has_private_component: bool,
}

/// The facts a quorum of resolvers agrees on, plus their unioned revocations.
///
/// Separate from [`IssuerState`] because agreement is clock-free: a caller
/// asking only "what revocations does this quorum establish" has no `now` to
/// offer, and should not have to invent one to obtain an answer that does not
/// depend on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgreedClosure {
    /// The DID every observation answered about.
    pub did: String,
    /// The DID was recomputed from genesis and matched.
    pub did_recomputed_ok: bool,
    /// Every delta in the replayed closure verified.
    pub deltas_verified: bool,
    /// No delta dangled a parent.
    pub locally_closed: bool,
    /// The deactivation latch.
    pub deactivated: bool,
    /// Agreed assertion methods.
    pub assertion_methods: Vec<ClosureAssertionMethod>,
    /// The UNION of every observation's revocation set.
    pub revoked_credential_ids: Vec<String>,
    /// Agreed `alsoKnownAs` entries.
    pub also_known_as: Vec<String>,
    /// The OLDEST fetch in the set.
    pub oldest_fetched_at: UnixSeconds,
}

/// Agree a set of independently fetched resolver observations, and union their
/// revocations.
///
/// Two decisions, neither of which an adapter may repeat:
///
/// 1. **Agreement.** Every observation must match the first on every fact
///    except its own identity and revocation set. Assertion methods are
///    compared by VALUE: comparing counts would let a resolver substitute a key
///    while keeping the list the same length, and the agreed methods are then
///    taken from the first observation, which would adopt the substitution.
/// 2. **Revocation union**, the one place disagreement is expected. A resolver
///    that has not yet seen a revocation is behind, not hostile, so the sets
///    are unioned rather than required to match.
///
/// # Errors
///
/// [`VerifyError::ResolverQuorum`] if the set is empty, the observations
/// disagree, or the union cannot be formed.
pub fn agree_closures(
    profile: &ApplicationProfile,
    observations: &[ResolverObservation],
) -> Result<AgreedClosure, VerifyError> {
    let first = observations.first().ok_or(VerifyError::ResolverQuorum)?;
    if observations.iter().skip(1).any(|o| {
        o.did != first.did
            || o.did_recomputed_ok != first.did_recomputed_ok
            || o.deltas_verified != first.deltas_verified
            || o.locally_closed != first.locally_closed
            || o.deactivated != first.deactivated
            || o.assertion_methods != first.assertion_methods
            || o.also_known_as != first.also_known_as
    }) {
        return Err(VerifyError::ResolverQuorum);
    }

    let revocations: Vec<ResolverRevocations<'_>> = observations
        .iter()
        .map(|o| ResolverRevocations { resolver_id: &o.resolver_id, revoked_credential_ids: &o.revoked_credential_ids })
        .collect();
    let revoked_credential_ids = union_resolver_revocations(profile, &revocations)?;

    // The OLDEST fetch: a union is only as fresh as its stalest member, and
    // taking the newest would let one freshly fetched resolver vouch for the
    // staleness of the rest.
    let oldest_fetched_at = observations.iter().map(|o| o.fetched_at_seconds).min().ok_or(VerifyError::ResolverQuorum)?;

    Ok(AgreedClosure {
        did: first.did.clone(),
        did_recomputed_ok: first.did_recomputed_ok,
        deltas_verified: first.deltas_verified,
        locally_closed: first.locally_closed,
        deactivated: first.deactivated,
        assertion_methods: first.assertion_methods.clone(),
        revoked_credential_ids,
        also_known_as: first.also_known_as.clone(),
        oldest_fetched_at,
    })
}

/// Project an agreed closure into the issuer state `CON-206` reasons over.
///
/// The age is computed here, from the verifier's own clock against its own
/// record of when it fetched. Saturating rather than clamping when the stamp is
/// in the future: a broken clock or an inventing caller must FAIL the age
/// bound, and clamping to zero would present the most suspect input as the
/// freshest.
pub fn issuer_state_of(agreed: &AgreedClosure, now: UnixSeconds) -> IssuerState {
    IssuerState {
        did: agreed.did.clone(),
        did_recomputed_ok: agreed.did_recomputed_ok,
        deltas_verified: agreed.deltas_verified,
        locally_closed: agreed.locally_closed,
        deactivated: agreed.deactivated,
        assertion_methods: agreed
            .assertion_methods
            .iter()
            .map(|m| VerificationMethod {
                id: m.id.clone(),
                kind: m.kind.clone(),
                // `x` is never read by CON-206 once the typed key has crossed
                // the resolver boundary; a fixed marker keeps this boundary from
                // creating another base64 parser.
                jwk: Ed25519Jwk { public_key: m.public_key, x: String::new() },
                has_private_component: m.has_private_component,
            })
            .collect(),
        revoked_credential_ids: agreed.revoked_credential_ids.clone(),
        closure_age_seconds: now
            .checked_sub(agreed.oldest_fetched_at)
            .filter(|age| *age >= 0)
            .unwrap_or(UnixSeconds::MAX),
        source: ClosureSource::StateResolver,
        also_known_as: agreed.also_known_as.clone(),
    }
}

/// Verify one Path-B device-grant presentation.
///
/// This is the sole Path-B adapter entry point.  It forces all thirteen
/// `CON-206` checks through [`accept_grant`] at session-establishment
/// freshness, and additionally refuses the bundle/cache fallback that
/// `SPEC-053` forbids for a hub admission.
pub fn verify_session_establishment(
    request: &GrantRequest<'_>,
    evidence: &GrantEvidence<'_>,
    grant_bytes: &[u8],
) -> Result<VerifiedGrant, VerifyError> {
    if evidence.issuer.source != ClosureSource::StateResolver {
        return Err(VerifyError::NonResolverClosure);
    }

    let acceptance = accept_grant(
        grant_bytes,
        &Expectation {
            profile: request.profile,
            account: request.account,
            device_public_key: request.device_public_key,
            operation_permissions: request.operation_permissions,
            now: request.now,
            clock_skew_seconds: request.clock_skew_seconds,
            freshness: Freshness::SessionEstablishment,
        },
        &Evidence {
            issuer: Some(evidence.issuer),
            jrd: Some(evidence.jrd),
            projection: evidence.projection,
            proof: Some((evidence.challenge, evidence.signature, evidence.session)),
        },
    )?;

    Ok(VerifiedGrant {
        account_did: acceptance.grant.issuer.clone(),
        grant_id: acceptance.grant.id.clone(),
        device_public_key: acceptance.grant.device_public_key,
        permissions: acceptance.grant.permissions.clone(),
        valid_until: acceptance.grant.valid_until,
        grant: acceptance.grant,
    })
}

/// Re-check `CON-206` steps 10--12 for a grant accepted in this session.
///
/// No parsing, JWS verification, account binding, or device proof is exposed
/// here: those occurred before the sealed [`VerifiedGrant`] existed.  Callers
/// must obtain resolver state independently for each invocation.
pub fn verify_standing(
    grant: &VerifiedGrant,
    request: &StandingRequest<'_>,
    evidence: &StandingEvidence<'_>,
) -> Result<(), VerifyError> {
    if evidence.issuer.source != ClosureSource::StateResolver {
        return Err(VerifyError::NonResolverClosure);
    }
    check_standing(
        &grant.grant,
        &Expectation {
            profile: request.profile,
            account: &grant.grant.account,
            device_public_key: &grant.grant.device_public_key,
            operation_permissions: request.operation_permissions,
            now: request.now,
            clock_skew_seconds: request.clock_skew_seconds,
            freshness: Freshness::Continuation,
        },
        evidence.issuer,
        evidence.projection,
    )?;
    Ok(())
}

/// Rehydrate a sealed Path-B grant after process restart.
///
/// Unlike standing, this rechecks the stored compact JWS through steps 1--12
/// before returning a new sealed grant. It has no proof parameter and is not a
/// presentation entry point: the caller must already possess an authenticated
/// session binding established by [`verify_session_establishment`].
pub fn rehydrate_verified_grant(
    request: &GrantRequest<'_>, issuer: &IssuerState, jrd: &Jrd,
    projection: Option<Projection>, grant_bytes: &[u8],
) -> Result<VerifiedGrant, VerifyError> {
    if issuer.source != ClosureSource::StateResolver { return Err(VerifyError::NonResolverClosure); }
    let acceptance = rehydrate_accepted_grant(grant_bytes, &Expectation { profile: request.profile, account: request.account, device_public_key: request.device_public_key, operation_permissions: request.operation_permissions, now: request.now, clock_skew_seconds: request.clock_skew_seconds, freshness: Freshness::SessionEstablishment }, &Evidence { issuer: Some(issuer), jrd: Some(jrd), projection, proof: None })?;
    Ok(VerifiedGrant { account_did: acceptance.grant.issuer.clone(), grant_id: acceptance.grant.id.clone(), device_public_key: acceptance.grant.device_public_key, permissions: acceptance.grant.permissions.clone(), valid_until: acceptance.grant.valid_until, grant: acceptance.grant })
}
