//! The grant acceptance predicate — `CON-206`, `REQ-207`, `NFR-205`.
//!
//! This is the module the rest of the crate exists to support. `REQ-207` states
//! the whole point in one line: **"A valid JWS and a conforming VC alone SHALL
//! NOT authorize the device."** VC Data Model 2.0 deliberately does not define
//! an authorization system; this is the accompanying Selfsame one.
//!
//! # The thirteen steps, in order
//!
//! | # | Step | What it stops |
//! |---|---|---|
//! | 1 | reject input over 64 KiB | a parse turned into a denial of service |
//! | 2 | parse the compact JWS strictly | duplicate members, extra segments, a partial parse |
//! | 3 | require the closed header | `alg:none`, a remote key URL, a caller-chosen key |
//! | 4 | obtain the issuer's signed closure | acting on unverified issuer state |
//! | 5 | recompute the DID and resolve it | a document that does not belong to its DID |
//! | 6 | require `kid` in `assertionMethod` | a key the issuer never authorised to assert |
//! | 7 | verify the JWS over the received octets | a signature over bytes nobody sent |
//! | 8 | validate every VC field and equality | a grant for another application, account, or device |
//! | 9 | verify the reciprocal account binding | a deterministically named but unprovisioned alias |
//! | 10 | enforce closure freshness and the G-Set | a revoked device that still works |
//! | 11 | check validity **and** the lifetime bound | a grant minted to outlive revocation |
//! | 12 | require every permission be declared | scope the profile never granted |
//! | 13 | run the device proof | a stolen credential without the device key |
//!
//! Order is normative and load-bearing. The signature is checked at step 7, so
//! steps 1 to 6 are exactly those that must be safe to run on **unauthenticated
//! input** — bounds, shape, and key resolution — and nothing after step 7 ever
//! reads a value that was not covered by a verified signature.
//!
//! # Two freshness tiers, both derived
//!
//! Step 10's bound is not one number, because the two things a verifier does
//! with a grant carry different costs when the answer is stale:
//!
//! - **Session establishment** — the first acceptance of a grant ID, or any
//!   acceptance beginning a new session — uses
//!   `min(maxClosureAgeSeconds, propagationSlaSeconds)` and prefers a closure
//!   resolved from a declared resolver over one taken from the bundle.
//! - **Continuation** — re-verification inside a session this verifier already
//!   established — uses `maxClosureAgeSeconds`.
//!
//! A verifier that cannot tell which case applies uses the establishment bound,
//! and so does one whose record of accepted grant IDs is lost.
//!
//! The resolver preference is the subtle half. A closure taken from the bundle
//! is *the issuer's own account of its own revocations*, and the issuer is
//! precisely the party a revocation constrains — an issuer that omits its own
//! `RevokeCredential` deltas produces a closure that is internally valid and
//! materially incomplete. Bundle-supplied closure is a bootstrap for a first
//! ceremony on a degraded network, not a standing arrangement, and
//! [`Acceptance::used_bundle_closure`] records when it happened because
//! `CON-206` requires the verifier to record it.
//!
//! # Failure is opaque outward and precise inward
//!
//! `CON-206`: "Diagnostic detail MAY be logged locally but externally visible
//! errors SHOULD collapse to a small stable set so that attackers do not gain a
//! credential oracle." So [`AcceptError`] carries the exact step for the local
//! log and for the `CON-226` corpus, and [`AcceptError::public`] collapses it to
//! three outcomes for anything a caller might return over a wire.

use crate::alias::{self, AcctUri, AliasError};
use crate::grant::{self, DeviceGrant, GrantError, GRANT_JWS};
use crate::json::Json;
use crate::jws::{self, JwsError};
use crate::profile::{ApplicationProfile, Ed25519Jwk};
use crate::proof::{self, Challenge, ProofError};
use crate::UnixSeconds;

/// Which of `CON-206`'s thirteen numbered steps refused the grant.
///
/// `CON-226`'s completeness rule requires the corpus to carry a case for each,
/// named `con_206_step_<n>`, so the discriminants are the step numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum AcceptStep {
    /// 1 — input larger than 64 KiB.
    Size = 1,
    /// 2 — compact JWS parsing.
    Jws = 2,
    /// 3 — the closed protected header.
    Header = 3,
    /// 4 — obtaining the issuer's signed closure.
    Closure = 4,
    /// 5 — recomputing the DID and resolving the document.
    DidResolution = 5,
    /// 6 — `kid` names a `JsonWebKey` in `assertionMethod`.
    IssuerKey = 6,
    /// 7 — the JWS signature over the received octets.
    Signature = 7,
    /// 8 — VC fields, cross-field equality, and the expected account.
    Fields = 8,
    /// 9 — the reciprocal RFC 7565 account binding.
    AccountBinding = 9,
    /// 10 — closure freshness and the revocation G-Set.
    Status = 10,
    /// 11 — the validity window and the lifetime bound.
    Validity = 11,
    /// 12 — every permission declared by the profile and the operation.
    Permissions = 12,
    /// 13 — device proof of possession.
    Proof = 13,
}

impl AcceptStep {
    /// The corpus identifier, `con_206_step_<n>`.
    pub fn corpus_id(self) -> String {
        format!("con_206_step_{}", self as u8)
    }
}

/// The small stable set an attacker is allowed to observe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PublicReason {
    /// The grant is not usable. Every shape, signature, field, binding, status,
    /// and validity failure collapses here.
    Rejected,
    /// The device did not prove possession.
    ProofFailed,
    /// The verifier could not obtain sufficiently fresh issuer state.
    ///
    /// Distinguished because it is the one failure that is the *verifier's*
    /// problem rather than the presenter's, and a caller must be able to retry
    /// rather than discard the grant.
    StateUnavailable,
}

/// Why a grant was refused, with the step that decided it.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("grant rejected at CON-206 step {}: {detail}", *step as u8)]
pub struct AcceptError {
    /// The numbered step.
    pub step: AcceptStep,
    /// Local diagnostic detail. Never returned over a wire.
    pub detail: String,
    /// Whether this refusal is the verifier's inability to obtain sufficiently
    /// fresh issuer state, rather than a defect in what the presenter supplied.
    ///
    /// It is a field rather than a step of its own because `CON-206` numbers the
    /// thirteen steps and `CON-226` requires one corpus case per number, so
    /// staleness cannot be given a fourteenth. It still has to be distinguished:
    /// [`PublicReason::StateUnavailable`] is contracted as the failure a caller
    /// **retries**, and a stale closure collapsed to `Rejected` makes a caller
    /// discard a grant that is very likely still good.
    pub state_unavailable: bool,
}

impl AcceptError {
    fn at(step: AcceptStep, detail: impl Into<String>) -> Self {
        Self { step, detail: detail.into(), state_unavailable: false }
    }

    /// A refusal the caller should retry rather than discard the grant over.
    fn unavailable(step: AcceptStep, detail: impl Into<String>) -> Self {
        Self { step, detail: detail.into(), state_unavailable: true }
    }

    /// Collapse to the small stable set (`CON-206`).
    pub fn public(&self) -> PublicReason {
        if self.state_unavailable {
            return PublicReason::StateUnavailable;
        }
        match self.step {
            AcceptStep::Proof => PublicReason::ProofFailed,
            _ => PublicReason::Rejected,
        }
    }
}

/// Which freshness tier applies (`CON-206` step 10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    /// First acceptance of this grant ID, or any acceptance beginning a new
    /// session. Also the answer whenever the verifier cannot tell.
    SessionEstablishment,
    /// Re-verification inside a session this verifier already established.
    Continuation,
}

/// Where the closure came from (`CON-206` step 10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClosureSource {
    /// Resolved from a profile-declared `stateResolvers` entry.
    StateResolver,
    /// Taken from the `CON-219` bundle or a local cache.
    BundleOrCache,
}

/// A verification method resolved from the issuer's DID document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationMethod {
    /// `did:crdt:<home>#jwk-0`.
    pub id: String,
    /// Must be `JsonWebKey` — `CON-206` step 6.
    pub kind: String,
    /// The Ed25519 public key.
    pub jwk: Ed25519Jwk,
    /// Whether the JWK carried a private `d` component, which step 6 refuses.
    pub has_private_component: bool,
}

/// The issuer state a verifier resolved, injected by the shell.
///
/// Every field is something the core cannot obtain for itself. Making them
/// parameters is what keeps `CON-206` linkable into a browser and a backend
/// alike, and what lets `TEST-211` mutate each check independently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerState {
    /// The DID the closure resolves to, recomputed by the caller from the
    /// genesis using the pinned method (`CON-206` step 5).
    pub did: String,
    /// Whether the recomputed self-certifying DID matched the asserted one.
    pub did_recomputed_ok: bool,
    /// Whether every required delta and authorization rule verified.
    pub deltas_verified: bool,
    /// `did:crdt` SPEC-035 causal validity and completeness.
    pub causally_complete: bool,
    /// Whether the DID has been deactivated.
    pub deactivated: bool,
    /// Verification methods in `assertionMethod`.
    pub assertion_methods: Vec<VerificationMethod>,
    /// The grow-only credential-revocation set.
    pub revoked_credential_ids: Vec<String>,
    /// Age of the closure in seconds at `now`.
    pub closure_age_seconds: i64,
    /// Where it came from.
    pub source: ClosureSource,
    /// `alsoKnownAs` from the resolved document.
    pub also_known_as: Vec<String>,
}

/// A Bitstring projection observation, when the profile enables one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Projection {
    /// A valid, in-date projection whose bit for this grant is set.
    ///
    /// `CON-210`: a set bit "is permanently true. No later state can unset it,
    /// so age never makes it wrong."
    BitSet,
    /// A valid, in-date projection whose bit is unset.
    BitUnset,
    /// Stale, invalid, wrongly issued, or unreachable.
    ///
    /// `CON-210`: past `validUntil` a consumer "SHALL treat the projection as
    /// **unavailable**, never as evidence of non-revocation."
    Unavailable,
}

/// What the verifier expects of this grant.
#[derive(Clone, Copy, Debug)]
pub struct Expectation<'a> {
    /// The authenticated, embedded application profile.
    pub profile: &'a ApplicationProfile,
    /// The exact account the current authenticated context expects.
    pub account: &'a AcctUri,
    /// The device key this context offered, and the only one it may bind.
    ///
    /// `CON-214`'s offer names the device key the grant will be minted for, and
    /// `CON-205` puts that key in the grant's `cnf.jwk`. Without this field
    /// nothing compares the two: issuer, application, and account all match for
    /// a grant this same person holds on a *different* device, and step 13 then
    /// verifies the proof against whichever key the presented grant happened to
    /// name. Any grant on the account would authorise any session offered to any
    /// device on it — which is the binding the offer exists to make.
    ///
    /// A verifier that has an offer takes it from `OfferCore::device_public_key`;
    /// one continuing a session takes it from the key that session was
    /// established under. There is deliberately no "unknown" value: a verifier
    /// that cannot say which device it is talking to has nothing to bind.
    pub device_public_key: &'a [u8; 32],
    /// The permissions the local operation being attempted requires.
    pub operation_permissions: &'a [&'a str],
    /// The current time, injected.
    pub now: UnixSeconds,
    /// The application's explicitly configured clock-skew bound.
    ///
    /// `CON-206` step 11 allows "only the application's explicitly configured
    /// clock-skew bound" — so it is a declared value, never an implicit grace.
    pub clock_skew_seconds: i64,
    /// Which freshness tier applies.
    pub freshness: Freshness,
}

/// Everything the shell resolved on the verifier's behalf.
#[derive(Clone, Copy, Debug)]
pub struct Evidence<'a> {
    /// The issuer's verified closure.
    pub issuer: Option<&'a IssuerState>,
    /// The reciprocal WebFinger record, when one was obtained.
    pub jrd: Option<&'a alias::Jrd>,
    /// The projection observation, when the profile enables one.
    pub projection: Option<Projection>,
    /// The consumed challenge, the device's signature over it, and the verifier
    /// session this acceptance is running in.
    ///
    /// The session is part of the tuple rather than a field of its own so that
    /// a caller cannot supply a proof without saying which session it belongs
    /// to. `CON-207` requires rejecting "a nonce issued for another
    /// application, account, grant, verifier session, or time window", and the
    /// session is the one a verifier with a shared durable nonce ledger would
    /// otherwise never check. A verifier with a single session passes the same
    /// constant it issued the challenge under.
    pub proof: Option<(&'a Challenge, &'a [u8; 64], &'a str)>,
}

/// An accepted grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Acceptance {
    /// The recognised credential.
    pub grant: DeviceGrant,
    /// `CON-206`: a verifier that relied on a bundle-supplied closure "SHALL
    /// record that it did so". This is that record.
    pub used_bundle_closure: bool,
}

/// Apply `CON-206`'s thirteen steps in order.
///
/// Authorization succeeds only if every step succeeds.
pub fn accept_grant(
    grant_bytes: &[u8],
    expect: &Expectation<'_>,
    evidence: &Evidence<'_>,
) -> Result<Acceptance, AcceptError> {
    accept_grant_inner(grant_bytes, expect, evidence, true)
}

/// Re-validate a credential through `CON-206` steps 1--12 only.
///
/// This is intentionally crate-private: it is solely the restart rehydration
/// primitive for a previously proof-bound Path-B session. It cannot be used as
/// a fresh presentation API because the public Path-B entry requires proof.
pub(crate) fn rehydrate_accepted_grant(
    grant_bytes: &[u8], expect: &Expectation<'_>, evidence: &Evidence<'_>,
) -> Result<Acceptance, AcceptError> {
    accept_grant_inner(grant_bytes, expect, evidence, false)
}

fn accept_grant_inner(
    grant_bytes: &[u8], expect: &Expectation<'_>, evidence: &Evidence<'_>, require_proof: bool,
) -> Result<Acceptance, AcceptError> {
    // ── 1 ──────────────────────────────────────────────────────────────────
    if grant_bytes.len() > grant::MAX_GRANT_OCTETS {
        return Err(AcceptError::at(AcceptStep::Size, "grant exceeds 64 KiB"));
    }
    let text = core::str::from_utf8(grant_bytes)
        .map_err(|_| AcceptError::at(AcceptStep::Jws, "grant is not ASCII"))?;

    // ── 2 and 3 ────────────────────────────────────────────────────────────
    // The recogniser applies both: shape and canonical base64url are step 2,
    // and the closed header with its one-algorithm allowlist is step 3.
    let jws = jws::recognise(text, GRANT_JWS, &[]).map_err(|e| match e {
        JwsError::BadAlgorithm | JwsError::BadType | JwsError::BadKid
        | JwsError::ForbiddenHeaderMember => {
            AcceptError::at(AcceptStep::Header, e.to_string())
        }
        JwsError::TooLarge => AcceptError::at(AcceptStep::Size, e.to_string()),
        other => AcceptError::at(AcceptStep::Jws, other.to_string()),
    })?;

    // ── 4 ──────────────────────────────────────────────────────────────────
    let issuer = evidence
        .issuer
        .ok_or_else(|| AcceptError::unavailable(AcceptStep::Closure, "no issuer closure available"))?;

    // ── 5 ──────────────────────────────────────────────────────────────────
    if !issuer.did_recomputed_ok {
        return Err(AcceptError::at(
            AcceptStep::DidResolution,
            "the self-certifying DID does not match the genesis",
        ));
    }
    if !issuer.deltas_verified {
        return Err(AcceptError::at(AcceptStep::DidResolution, "a delta failed verification"));
    }
    if issuer.deactivated {
        return Err(AcceptError::at(AcceptStep::DidResolution, "the issuer DID is deactivated"));
    }

    // ── 6 ──────────────────────────────────────────────────────────────────
    // `kid` must name a `JsonWebKey` in `assertionMethod`. A key that is merely
    // *known* to the document is not enough: assertion is the relationship that
    // says this key may make statements for this DID.
    let method = issuer
        .assertion_methods
        .iter()
        .find(|m| m.id == jws.kid)
        .ok_or_else(|| AcceptError::at(AcceptStep::IssuerKey, "kid is not in assertionMethod"))?;
    if method.kind != "JsonWebKey" {
        return Err(AcceptError::at(AcceptStep::IssuerKey, "verification method is not JsonWebKey"));
    }
    if method.has_private_component {
        return Err(AcceptError::at(AcceptStep::IssuerKey, "issuer JWK carries a private `d`"));
    }
    // The `kid` has to belong to the DID whose closure was resolved, or a valid
    // signature by an unrelated issuer would pass.
    if !jws.kid.strip_prefix(&issuer.did).is_some_and(|suffix| suffix.starts_with('#')) {
        return Err(AcceptError::at(AcceptStep::IssuerKey, "kid does not belong to the issuer DID"));
    }

    // ── 7 ──────────────────────────────────────────────────────────────────
    // Over the octets as received. Nothing below this line reads a value that
    // was not covered by this signature.
    jws.verify(&method.jwk.public_key)
        .map_err(|e| AcceptError::at(AcceptStep::Signature, e.to_string()))?;

    // ── 8 ──────────────────────────────────────────────────────────────────
    let grant = grant::recognise(&jws.payload).map_err(|e: GrantError| {
        AcceptError::at(AcceptStep::Fields, e.to_string())
    })?;
    if grant.issuer != issuer.did {
        return Err(AcceptError::at(AcceptStep::Fields, "issuer does not match the resolved DID"));
    }
    if grant.application != expect.profile.application_id.as_str() {
        return Err(AcceptError::at(AcceptStep::Fields, "application is not the expected one"));
    }
    if grant.account.as_str() != expect.account.as_str() {
        return Err(AcceptError::at(AcceptStep::Fields, "account is not the expected one"));
    }
    // The device the offer named, not merely *a* device of this account. Every
    // check above is satisfied by a sibling device's grant, and step 13 below
    // verifies the proof against the key the grant itself chose — so without
    // this line the presenter picks which key is checked.
    if grant.device_public_key != *expect.device_public_key {
        return Err(AcceptError::at(
            AcceptStep::Fields,
            "grant names a different device key than the one offered",
        ));
    }
    // `CON-205` admits a `BitstringStatusListEntry` beside the mandatory CRDT
    // entry only when the profile enables the projection. `grant::recognise`
    // checks the entry's shape and cannot check that, because it holds no
    // profile — so a grant naming a status list the application never declared
    // reaches here fully recognised.
    if grant.projection_entry.is_some() && expect.profile.revocation.projection.is_none() {
        return Err(AcceptError::at(
            AcceptStep::Fields,
            "grant carries a projection entry the profile does not enable",
        ));
    }
    // The account has to be the CON-203 function of the issuer that signed the
    // grant, so a valid issuer cannot name an alias belonging to a different
    // home DID.
    alias::expected_account_matches(
        &grant.issuer,
        &expect.profile.account_authority,
        grant.account.as_str(),
    )
    .map_err(|e: AliasError| AcceptError::at(AcceptStep::Fields, e.to_string()))?;

    // ── 9 ──────────────────────────────────────────────────────────────────
    // The sole gate on alias provisioning. A deterministically named but
    // unprovisioned alias fails closed here, whatever order issuance and
    // provisioning happened to take.
    let jrd = evidence.jrd.ok_or_else(|| {
        AcceptError::at(AcceptStep::AccountBinding, "no reciprocal account binding available")
    })?;
    alias::verify_reciprocal_binding(jrd, &grant.account, &grant.issuer, &issuer.also_known_as)
        .map_err(|e| AcceptError::at(AcceptStep::AccountBinding, e.to_string()))?;

    // ── 10 ─────────────────────────────────────────────────────────────────
    check_status(&grant, expect, issuer, evidence.projection)?;

    // ── 11 ─────────────────────────────────────────────────────────────────
    check_validity(&grant, expect)?;

    // ── 12 ─────────────────────────────────────────────────────────────────
    for permission in &grant.permissions {
        if !expect.profile.allowed_permissions.iter().any(|p| p == permission) {
            return Err(AcceptError::at(
                AcceptStep::Permissions,
                "grant carries a permission the profile does not declare",
            ));
        }
    }
    for required in expect.operation_permissions {
        if !grant.permissions.iter().any(|p| p == required) {
            return Err(AcceptError::at(
                AcceptStep::Permissions,
                "grant does not carry a permission the operation requires",
            ));
        }
    }

    // ── 13 ─────────────────────────────────────────────────────────────────
    if require_proof {
        let (challenge, signature, session) = evidence
            .proof
            .ok_or_else(|| AcceptError::at(AcceptStep::Proof, "no device proof supplied"))?;
        proof::matches_binding(challenge, &grant.application, grant.account.as_str(), &proof::grant_hash(grant_bytes), session)
            .map_err(|e: ProofError| AcceptError::at(AcceptStep::Proof, e.to_string()))?;
        proof::verify(challenge, signature, &grant.device_public_key)
            .map_err(|e| AcceptError::at(AcceptStep::Proof, e.to_string()))?;
    }

    Ok(Acceptance {
        grant,
        used_bundle_closure: issuer.source == ClosureSource::BundleOrCache,
    })
}

fn check_status(
    grant: &DeviceGrant,
    expect: &Expectation<'_>,
    issuer: &IssuerState,
    projection: Option<Projection>,
) -> Result<(), AcceptError> {
    let policy = &expect.profile.revocation;
    let bound = match expect.freshness {
        Freshness::SessionEstablishment => policy.session_establishment_bound(),
        Freshness::Continuation => policy.max_closure_age_seconds,
    };
    // Stale, not refused. The grant may be perfectly good and this verifier
    // simply holds an old closure, so the caller is told to obtain fresher state
    // and try again rather than to discard the credential.
    if issuer.closure_age_seconds > bound {
        return Err(AcceptError::unavailable(
            AcceptStep::Status,
            "closure is older than the applicable bound",
        ));
    }
    // "causally valid and causally complete" — the most security-critical check
    // in the profile, and the one whose upstream definition is still deferred
    // (`did:crdt` SPEC-035, a Tier-1 gate item). It is a parameter here so the
    // shell that has the method library decides it.
    if !issuer.causally_complete {
        return Err(AcceptError::at(AcceptStep::Status, "closure is not causally complete"));
    }
    // At session establishment a closure from a declared resolver is preferred
    // over the issuer's own account of its own revocations — and the preference
    // is *not* enforced here, deliberately. `CON-206` permits the bundle only
    // when no declared resolver is reachable, and reachability is something the
    // shell observed and this function cannot. A verifier that could have
    // reached one and did not is out of conformance, but the evidence for that
    // lives in `state::ResolvedClosure::outcomes`, not in these parameters.
    //
    // So the record in `Acceptance::used_bundle_closure` is the whole of what
    // this step does about it. Until this sentence, that was written as a
    // three-clause `if` guarding an empty block: five mutants survive it and
    // none can be killed, because a condition whose body is empty has no
    // behaviour to change. It read as a control and enforced nothing, which is
    // the more expensive kind of nothing.

    // A set projection bit rejects early. An unset, stale, invalid, or
    // unavailable one never bypasses the CRDT check — which is why the CRDT
    // check runs regardless of what the projection said.
    if projection == Some(Projection::BitSet) {
        return Err(AcceptError::at(AcceptStep::Status, "projection bit is set"));
    }
    if issuer.revoked_credential_ids.iter().any(|id| id == &grant.id) {
        return Err(AcceptError::at(AcceptStep::Status, "grant id is in the revocation set"));
    }
    Ok(())
}

fn check_validity(grant: &DeviceGrant, expect: &Expectation<'_>) -> Result<(), AcceptError> {
    let skew = expect.clock_skew_seconds;
    if expect.now + skew < grant.valid_from {
        return Err(AcceptError::at(AcceptStep::Validity, "grant is not yet valid"));
    }
    // `[validFrom, validUntil)` — half-open, so a grant is invalid *at* its own
    // expiry instant rather than one second later.
    if expect.now - skew >= grant.valid_until {
        return Err(AcceptError::at(AcceptStep::Validity, "grant has expired"));
    }
    // Independent of the window: a grant minted to outlive revocation is
    // rejected even while the current time sits inside it. Without this,
    // `CON-204`'s fallback to expiry alone would be unbounded, and revocation
    // would be cosmetic in exactly the cases where it matters most.
    if grant.lifetime_seconds() > expect.profile.revocation.max_grant_lifetime_seconds {
        return Err(AcceptError::at(
            AcceptStep::Validity,
            "grant lifetime exceeds the profile's maxGrantLifetimeSeconds",
        ));
    }
    Ok(())
}

/// Re-check the standing-only portion of a previously accepted grant.
///
/// This deliberately contains only `CON-206` steps 10--12.  It is crate
/// private because callers must not be able to manufacture a recognised grant
/// from untrusted credential bytes and then omit signature and proof checks.
pub(crate) fn check_standing(
    grant: &DeviceGrant,
    expect: &Expectation<'_>,
    issuer: &IssuerState,
    projection: Option<Projection>,
) -> Result<(), AcceptError> {
    check_status(grant, expect, issuer, projection)?;
    check_validity(grant, expect)?;
    for permission in &grant.permissions {
        if !expect.profile.allowed_permissions.iter().any(|p| p == permission) {
            return Err(AcceptError::at(
                AcceptStep::Permissions,
                "grant carries a permission the profile does not declare",
            ));
        }
    }
    for required in expect.operation_permissions {
        if !grant.permissions.iter().any(|p| p == required) {
            return Err(AcceptError::at(
                AcceptStep::Permissions,
                "grant does not carry a permission the operation requires",
            ));
        }
    }
    Ok(())
}

/// Recognise a grant far enough to read its `issuer`, without accepting it.
///
/// `CON-204`'s remote-controller ordering needs this: the application reads
/// `issuer` from the grant and recomputes the expected localpart **before** it
/// provisions anything. No signature has been checked at that point, and this
/// signature makes that plain — the value is used to derive a name, never to
/// grant authority.
pub fn peek_issuer(grant_bytes: &[u8]) -> Result<String, AcceptError> {
    let text = core::str::from_utf8(grant_bytes)
        .map_err(|_| AcceptError::at(AcceptStep::Jws, "grant is not ASCII"))?;
    let jws = jws::recognise(text, GRANT_JWS, &[])
        .map_err(|e| AcceptError::at(AcceptStep::Jws, e.to_string()))?;
    jws.payload
        .get("issuer")
        .and_then(Json::as_str)
        .map(str::to_string)
        .ok_or_else(|| AcceptError::at(AcceptStep::Fields, "grant has no issuer"))
}
