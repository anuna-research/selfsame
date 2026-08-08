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
    Projection,
};
use crate::alias::{AcctUri, Jrd};
use crate::profile::ApplicationProfile;
use crate::proof::Challenge;
use crate::UnixSeconds;

/// Minimum distinct declared resolver observations required by CBCL Path-B
/// admission. One resolver is one party that can withhold a revocation.
pub const MINIMUM_RESOLVER_QUORUM: usize = 2;

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

/// Require two distinct declared resolver observations and return their sorted,
/// duplicate-free revocation union.
///
/// The caller does not get to substitute a cache, repeat one resolver under two
/// labels, or choose the answer omitting a revocation. Network I/O stays in the
/// shell; this function is the portable, identical decision it must feed.
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
