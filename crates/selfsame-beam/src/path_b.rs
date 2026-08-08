//! Path-B device-grant verification at the CBCL/BEAM boundary.
//!
//! The public pure function accepts typed resolver facts and opaque credential
//! octets, then delegates *all* credential recognition and authorisation to
//! [`selfsame_app_identity::path_b`].  In particular this module does not
//! split a compact JWS, decode its payload, make network requests, or select a
//! weaker freshness tier.  The NIF translation accepts closed BEAM maps and
//! produces either a small verified-grant map or the opaque atom `rejected`.
//!
//! The resolver shell is responsible for proving the supplied DID closure. The
//! conversion below deliberately hard-codes `StateResolver`; a bundle/cache
//! caller has no term-level switch with which it can claim Path-B admission.

use rustler::types::atom;
use rustler::{Atom, Binary, Encoder, Env, MapIterator, OwnedBinary, Resource, ResourceArc, Term};
use selfsame_app_identity::accept::{IssuerState, Projection, VerificationMethod};
use selfsame_app_identity::alias::{recognise_jrd, AcctUri};
use selfsame_app_identity::path_b::{
    rehydrate_verified_grant, union_resolver_revocations, verify_session_establishment,
    verify_standing, GrantEvidence, GrantRequest, ResolverRevocations, StandingEvidence,
    StandingRequest, VerifiedGrant,
};
use selfsame_app_identity::profile::{ApplicationProfile, Ed25519Jwk};
use selfsame_app_identity::proof::Challenge;

rustler::atoms! {
    rejected,
    grant_atom = "grant",
    profile,
    account,
    device_public_key,
    operation_permissions,
    now,
    clock_skew_seconds,
    jrd,
    nonce,
    grant_hash,
    challenge_session,
    issued_at,
    proof_signature,
    session,
    projection,
    resolver_closures,
    resolver_id,
    did,
    did_recomputed_ok,
    deltas_verified,
    causally_complete,
    deactivated,
    assertion_methods,
    revoked_credential_ids,
    closure_age_seconds,
    also_known_as,
    id,
    kind,
    public_key,
    has_private_component,
    none,
    bit_set,
    bit_unset,
    unavailable,
    account_did,
    grant_id,
    permissions,
    valid_until,
    expires_at,
    standing,
    permission,
}

/// A verified resolver closure, represented without any credential bytes.
///
/// `source` is intentionally absent.  Constructing the core issuer state
/// always marks it `StateResolver`, which means a cached closure cannot cross
/// this Path-B boundary by a caller-selected label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolverClosure {
    /// Exact declared resolver id which supplied this locally verified closure.
    pub resolver_id: String,
    /// The DID whose state the resolver authenticated.
    pub did: String,
    /// The resolver recomputed the self-certifying DID from genesis.
    pub did_recomputed_ok: bool,
    /// All required DID deltas verified.
    pub deltas_verified: bool,
    /// The resolved closure is causally complete.
    pub causally_complete: bool,
    /// The DID's deactivation state.
    pub deactivated: bool,
    /// Assertion methods exposed by the resolved DID document.
    pub assertion_methods: Vec<ResolverAssertionMethod>,
    /// The resolver's current credential-revocation G-Set.
    pub revoked_credential_ids: Vec<String>,
    /// Age of this closure at the supplied `now` value.
    pub closure_age_seconds: i64,
    /// Resolved DID `alsoKnownAs` entries.
    pub also_known_as: Vec<String>,
}

/// One assertion method from a verified resolver closure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolverAssertionMethod {
    /// Method identifier.
    pub id: String,
    /// The exact resolved verification-method kind.
    pub kind: String,
    /// Ed25519 verification key bytes.
    pub public_key: [u8; 32],
    /// Whether the source JWK illegally included private key material.
    pub has_private_component: bool,
}

/// All presentation facts required for a Path-B session establishment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathBPresentation {
    /// Exact compact-JWS credential octets; they remain opaque at this layer.
    pub grant: Vec<u8>,
    /// Canonical `CON-201` profile octets.
    pub profile: Vec<u8>,
    /// Canonical account URI.
    pub account: String,
    /// The offered Ed25519 device key.
    pub device_public_key: [u8; 32],
    /// Local operation permissions.
    pub operation_permissions: Vec<String>,
    /// Shell-injected Unix time.
    pub now: i64,
    /// Explicitly configured clock skew.
    pub clock_skew_seconds: i64,
    /// WebFinger response bytes already obtained by the shell.
    pub jrd: Vec<u8>,
    /// Single-use challenge nonce.
    pub nonce: [u8; 32],
    /// SHA-256 of the exact grant bytes, recorded when the challenge issued.
    pub grant_hash: [u8; 32],
    /// Session to which that challenge was bound.
    pub challenge_session: String,
    /// Challenge issuance time.
    pub issued_at: i64,
    /// Device proof signature.
    pub proof_signature: [u8; 64],
    /// Current verifier session.
    pub session: String,
    /// Optional resolver projection observation.
    pub projection: Option<Projection>,
}

/// Successful Path-B facts safe for the BEAM shell to persist as a binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPathBGrant {
    /// Issuer/account home DID.
    pub account_did: String,
    /// Credential id for revocation tracking.
    pub grant_id: String,
    /// Device key bound by the verified credential.
    pub device_public_key: [u8; 32],
    /// Profile-declared permissions in the verified credential.
    pub permissions: Vec<String>,
    /// Verified exclusive Unix-seconds expiry from the signed credential.
    pub valid_until: i64,
}

/// BEAM-only capability containing a grant authenticated by full Path-B
/// presentation.  It has no decoder from credential bytes, so the standing
/// NIF cannot be called with client-supplied claims or skip the proof step.
pub struct StandingGrantResource {
    grant: VerifiedGrant,
}

/// Derive the sole required SPEC-053 permission for an accepted client
/// performative.  The application id is recognised from canonical profile
/// bytes; callers cannot splice or compose a permission URI themselves.
pub fn derive_operation_permission(profile_bytes: &[u8], performative: &str) -> Result<String, String> {
    let fragment = operation_permission_fragment(performative)?;
    let profile = ApplicationProfile::recognise(profile_bytes).map_err(|_| String::from("profile"))?;
    let permission = format!("{}#{fragment}", profile.application_id.as_str());
    if !profile.allowed_permissions.iter().any(|allowed| allowed == &permission) {
        return Err(String::from("undeclared"));
    }
    Ok(permission)
}

/// Fixed operation-to-fragment table. Every recognised CBCL performative is
/// listed deliberately; unknown or profile-unratified verbs fail closed.
fn operation_permission_fragment(performative: &str) -> Result<&'static str, String> {
    match performative {
        "hello" => Ok("channel-join"),
        "history" | "keyget" | "groupinfoget" | "fetchdialect" | "channels" | "sealedgrantget" | "pairgrantget" => Ok("chat-read"),
        "keypub" | "welcome" | "deliver" | "groupinfo" | "epochclaim" | "epocharm" | "epochrelease" => Ok("mls-commit"),
        "tell" | "ask" | "reply" | "error" | "cite" | "propose" | "vote" | "presence" => Ok("chat-send"),
        // CON-002 must ratify fragments for these accepted membership verbs.
        "bye" | "invite" | "addagent" | "removeagent" | "adddialect" | "removedialect"
        | "sealedgrant" | "pairgrant" | "identityconfirm"
        // Hub- and ceremony-only verbs are never member capabilities.
        | "keypkg" | "invited" | "identityhold" | "identityclear" | "epochgranted"
        | "roomcaps" | "roomcfg" | "agent-removed" | "sealedgrantok" | "paircode"
        | "grant" | "grantchallenge" | "grantproof" | "grantpub" | "account-linked"
        | "other" => Err(String::from("unmapped-performative")),
        _ => Err(String::from("unmapped-performative")),
    }
}

/// `cbcl_selfsame_erl:operation_permission/2`.
#[rustler::nif]
pub fn operation_permission<'a>(env: Env<'a>, profile: Binary<'a>, performative: Binary<'a>) -> Term<'a> {
    let result = std::str::from_utf8(performative.as_slice()).map_err(|_| String::from("utf8"))
        .and_then(|perf| derive_operation_permission(profile.as_slice(), perf));
    match result { Ok(permission_text) => (atom::ok(), binary(env, permission_text.as_bytes())).encode(env), Err(_) => (atom::error(), rejected()).encode(env) }
}

impl Resource for StandingGrantResource {}

/// Verify a typed Path-B presentation with a resolver-derived closure.
///
/// Errors are deliberately collapsed to a stable `rejected` result at the
/// wire-facing NIF.  This pure helper preserves an internal string category so
/// unit tests and local telemetry can distinguish malformed boundary input
/// from a CON-206 refusal without exposing a credential oracle.
pub fn verify_path_b_pure(
    presentation: &PathBPresentation,
    closures: &[ResolverClosure],
) -> Result<VerifiedPathBGrant, String> {
    let accepted = verify_sealed(presentation, closures)?;

    Ok(VerifiedPathBGrant {
        account_did: accepted.account_did,
        grant_id: accepted.grant_id,
        device_public_key: accepted.device_public_key,
        permissions: accepted.permissions,
        valid_until: accepted.valid_until,
    })
}

/// Verify exactly the resolver evidence that can drive a durable revocation.
///
/// This is deliberately narrower than grant acceptance: it has no credential,
/// device key, JRD, proof, or projection input.  Its one output is the sorted
/// revocation union after the profile is recognised, every closure agrees on
/// the named account, the closures form the declared two-resolver quorum, and
/// the closure facts are fresh and usable.  A BEAM caller therefore cannot turn
/// a hand-decoded `revoked_credential_ids` list into an eviction authority.
pub fn verified_revocation_union(
    profile_bytes: &[u8],
    account_did: &str,
    closures: &[ResolverClosure],
) -> Result<Vec<String>, String> {
    let profile = ApplicationProfile::recognise(profile_bytes).map_err(|_| String::from("profile"))?;
    let closure = resolver_quorum(&profile, closures)?;
    if closure.did != account_did
        || !closure.did_recomputed_ok
        || !closure.deltas_verified
        || !closure.causally_complete
        || closure.deactivated
        || closure.closure_age_seconds < 0
        || closure.closure_age_seconds > profile.revocation.max_closure_age_seconds
    {
        return Err(String::from("resolver_closure"));
    }
    Ok(closure.revoked_credential_ids)
}

/// Compute the only permitted expiry for a cached Path-B standing fact.
///
/// The result is an absolute Unix second, never a duration.  It is retained in
/// the Selfsame boundary so an LFE caller cannot parse profile revocation policy
/// or accidentally compare `propagationSlaSeconds` with an absolute grant
/// expiry.  `None` means the fact is already unusable.
pub fn standing_cache_expiry(profile_bytes: &[u8], valid_until: i64, now: i64) -> Result<i64, String> {
    let profile = ApplicationProfile::recognise(profile_bytes).map_err(|_| String::from("profile"))?;
    if now < 0 || valid_until <= now { return Err(String::from("expired")); }
    let propagation_expiry = now
        .checked_add(profile.revocation.propagation_sla_seconds)
        .ok_or_else(|| String::from("overflow"))?;
    Ok(valid_until.min(propagation_expiry))
}

fn verify_sealed(
    presentation: &PathBPresentation,
    closures: &[ResolverClosure],
) -> Result<VerifiedGrant, String> {
    let profile = ApplicationProfile::recognise(&presentation.profile).map_err(|_| String::from("profile"))?;
    let closure = resolver_quorum(&profile, closures)?;
    let account = AcctUri::parse(&presentation.account).map_err(|_| String::from("account"))?;
    let jrd = recognise_jrd(&presentation.jrd).map_err(|_| String::from("jrd"))?;
    let issuer = issuer_state(&closure);
    let challenge = Challenge { nonce: presentation.nonce, application_id: profile.application_id.as_str().to_owned(), account: account.as_str().to_owned(), grant_hash: presentation.grant_hash, session: presentation.challenge_session.clone(), issued_at: presentation.issued_at };
    let permissions: Vec<&str> = presentation.operation_permissions.iter().map(String::as_str).collect();
    verify_session_establishment(
        &GrantRequest::new(&profile, &account, &presentation.device_public_key, &permissions, presentation.now, presentation.clock_skew_seconds),
        &GrantEvidence::new(&issuer, &jrd, presentation.projection, &challenge, &presentation.proof_signature, &presentation.session),
        &presentation.grant,
    ).map_err(|_| String::from("rejected"))
}

/// Enforce the Path-B two-resolver rule and make the union the only revocation
/// set the CON-206 predicate can observe.  All non-revocation resolver facts
/// must agree exactly; choosing one resolver's key set or `alsoKnownAs` while
/// borrowing another's revocations would be a new, unreviewed merge rule.
fn resolver_quorum(
    profile: &ApplicationProfile,
    closures: &[ResolverClosure],
) -> Result<ResolverClosure, String> {
    let first = closures.first().ok_or_else(|| String::from("resolver_quorum"))?;
    if closures.iter().skip(1).any(|closure| {
        closure.did != first.did
            || closure.did_recomputed_ok != first.did_recomputed_ok
            || closure.deltas_verified != first.deltas_verified
            || closure.causally_complete != first.causally_complete
            || closure.deactivated != first.deactivated
            || closure.assertion_methods != first.assertion_methods
            || closure.also_known_as != first.also_known_as
    }) {
        return Err(String::from("resolver_disagreement"));
    }
    let observations: Vec<ResolverRevocations<'_>> = closures
        .iter()
        .map(|closure| ResolverRevocations {
            resolver_id: &closure.resolver_id,
            revoked_credential_ids: &closure.revoked_credential_ids,
        })
        .collect();
    let revoked_credential_ids = union_resolver_revocations(profile, &observations)
        .map_err(|_| String::from("resolver_quorum"))?;
    let closure_age_seconds = closures
        .iter()
        .map(|closure| closure.closure_age_seconds)
        .max()
        .ok_or_else(|| String::from("resolver_quorum"))?;
    Ok(ResolverClosure {
        resolver_id: String::new(),
        did: first.did.clone(),
        did_recomputed_ok: first.did_recomputed_ok,
        deltas_verified: first.deltas_verified,
        causally_complete: first.causally_complete,
        deactivated: first.deactivated,
        assertion_methods: first.assertion_methods.clone(),
        revoked_credential_ids,
        closure_age_seconds,
        also_known_as: first.also_known_as.clone(),
    })
}

fn issuer_state(closure: &ResolverClosure) -> IssuerState {
    IssuerState {
        did: closure.did.clone(),
        did_recomputed_ok: closure.did_recomputed_ok,
        deltas_verified: closure.deltas_verified,
        causally_complete: closure.causally_complete,
        deactivated: closure.deactivated,
        assertion_methods: closure
            .assertion_methods
            .iter()
            .map(|method| VerificationMethod {
                id: method.id.clone(),
                kind: method.kind.clone(),
                jwk: Ed25519Jwk {
                    public_key: method.public_key,
                    // `x` is never read by CON-206 once the typed key has
                    // crossed the resolver boundary; retain a fixed marker so
                    // this boundary cannot create another base64 parser.
                    x: String::new(),
                },
                has_private_component: method.has_private_component,
            })
            .collect(),
        revoked_credential_ids: closure.revoked_credential_ids.clone(),
        closure_age_seconds: closure.closure_age_seconds,
        source: selfsame_app_identity::accept::ClosureSource::StateResolver,
        also_known_as: closure.also_known_as.clone(),
    }
}

/// `cbcl_selfsame_erl:verify_path_b/2`.
///
/// Argument maps are closed at this boundary: unknown or absent members reject
/// before the core receives a partial request.  The second argument is
/// `#{resolver_closures := [ResolverClosureMap, ...]}` and needs two distinct
/// profile-declared `resolver_id` values. Its public return is either
/// `{ok, #{account_did := binary(), grant_id := binary(),
///          device_public_key := binary(), permissions := [binary()]}}`
/// or `{error, rejected}`.  No detailed `CON-206` outcome is reflected to the
/// presenter.
#[rustler::nif]
pub fn verify_path_b<'a>(env: Env<'a>, presentation: Term<'a>, closure: Term<'a>) -> Term<'a> {
    // A panic must not cross from Rust into the BEAM scheduler.  Path-B's
    // outward failures are deliberately one opaque token, so malformed input
    // and an internal panic both safely collapse to `rejected`.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let result = decode_presentation(env, presentation)
            .and_then(|presentation| decode_closures(env, closure).map(|closures| (presentation, closures)))
            .and_then(|(presentation, closures)| verify_path_b_pure(&presentation, &closures));
        match result {
            Ok(grant) => (atom::ok(), encode_verified(env, &grant)).encode(env),
            Err(_) => (atom::error(), rejected()).encode(env),
        }
    })) {
        Ok(term) => term,
        Err(_) => (atom::error(), rejected()).encode(env),
    }
}

/// `cbcl_selfsame_erl:verified_path_b_revocations/2`.
///
/// The request is only the canonical profile bytes and the account DID.  The
/// response is the NIF's verified, sorted union; malformed, stale, deactivated
/// or non-quorum resolver facts collapse to the usual opaque rejection.
#[rustler::nif]
pub fn verified_path_b_revocations<'a>(env: Env<'a>, request: Term<'a>, closure: Term<'a>) -> Term<'a> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let result = decode_revocation_request(env, request)
            .and_then(|request| decode_closures(env, closure).map(|closures| (request, closures)))
            .and_then(|(request, closures)| verified_revocation_union(&request.profile, &request.account_did, &closures));
        match result {
            Ok(ids) => (atom::ok(), ids.into_iter().map(|id| binary(env, id.as_bytes())).collect::<Vec<_>>()).encode(env),
            Err(_) => (atom::error(), rejected()).encode(env),
        }
    })) {
        Ok(term) => term,
        Err(_) => (atom::error(), rejected()).encode(env),
    }
}

/// `cbcl_selfsame_erl:path_b_standing_cache_expiry/1`.
#[rustler::nif]
pub fn path_b_standing_cache_expiry<'a>(env: Env<'a>, request: Term<'a>) -> Term<'a> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let result = decode_cache_expiry_request(env, request)
            .and_then(|request| standing_cache_expiry(&request.profile, request.valid_until, request.now));
        match result {
            Ok(expiry) => (atom::ok(), expiry).encode(env),
            Err(_) => (atom::error(), rejected()).encode(env),
        }
    })) {
        Ok(term) => term,
        Err(_) => (atom::error(), rejected()).encode(env),
    }
}

/// `cbcl_selfsame_erl:verify_path_b_sealed/2`.
///
/// This is session establishment plus an unforgeable BEAM resource used for
/// later per-frame checks.  The public facts remain a map; callers must retain
/// the resource rather than attempting to rebuild it from those facts.
#[rustler::nif]
pub fn verify_path_b_sealed<'a>(env: Env<'a>, presentation: Term<'a>, closure: Term<'a>) -> Term<'a> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let result = decode_presentation(env, presentation)
            .and_then(|presentation| decode_closures(env, closure).map(|closures| (presentation, closures)))
            .and_then(|(presentation, closures)| verify_sealed(&presentation, &closures));
        match result {
            Ok(grant) => {
                let facts = VerifiedPathBGrant { account_did: grant.account_did.clone(), grant_id: grant.grant_id.clone(), device_public_key: grant.device_public_key, permissions: grant.permissions.clone(), valid_until: grant.valid_until };
                (atom::ok(), encode_verified(env, &facts), ResourceArc::new(StandingGrantResource { grant })).encode(env)
            }
            Err(_) => (atom::error(), rejected()).encode(env),
        }
    })) {
        Ok(term) => term,
        Err(_) => (atom::error(), rejected()).encode(env),
    }
}

/// `cbcl_selfsame_erl:verify_path_b_standing/3`.
///
/// The first argument is only accepted when issued by `verify_path_b_sealed/2`.
/// The request contains current local permissions and time; the third argument
/// is a two-resolver closure map.  It intentionally has neither proof nor VC
/// arguments, so it can execute only CON-206 steps 10--12.
#[rustler::nif]
pub fn verify_path_b_standing<'a>(env: Env<'a>, sealed: ResourceArc<StandingGrantResource>, request: Term<'a>, closure: Term<'a>) -> Term<'a> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let result = decode_standing_request(env, request)
            .and_then(|request| decode_closures(env, closure).map(|closures| (request, closures)))
            .and_then(|(request, closures)| verify_standing_pure(&sealed.grant, &request, &closures));
        match result { Ok(()) => atom::ok().encode(env), Err(_) => (atom::error(), rejected()).encode(env) }
    })) {
        Ok(term) => term,
        Err(_) => (atom::error(), rejected()).encode(env),
    }
}

/// `cbcl_selfsame_erl:rehydrate_path_b/2`.
///
/// Recovery after a CBCL restart. It consumes the durable compact VC and fresh
/// resolver/JRD facts, revalidates steps 1--12 (including the JWS), and returns
/// a newly sealed live-session resource. It deliberately has no claims input:
/// stored claims are an index, never an authority.
#[rustler::nif]
pub fn rehydrate_path_b<'a>(env: Env<'a>, recovery: Term<'a>, closure: Term<'a>) -> Term<'a> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let result = decode_rehydration(env, recovery)
            .and_then(|recovery| decode_closures(env, closure).map(|closures| (recovery, closures)))
            .and_then(|(recovery, closures)| rehydrate_pure(&recovery, &closures));
        match result {
            Ok(grant) => {
                let facts = VerifiedPathBGrant { account_did: grant.account_did.clone(), grant_id: grant.grant_id.clone(), device_public_key: grant.device_public_key, permissions: grant.permissions.clone(), valid_until: grant.valid_until };
                (atom::ok(), encode_verified(env, &facts), ResourceArc::new(StandingGrantResource { grant })).encode(env)
            }
            Err(_) => (atom::error(), rejected()).encode(env),
        }
    })) { Ok(term) => term, Err(_) => (atom::error(), rejected()).encode(env) }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StandingInput { profile: Vec<u8>, operation_permissions: Vec<String>, now: i64, clock_skew_seconds: i64, projection: Option<Projection> }

#[derive(Clone, Debug, PartialEq, Eq)]
struct RehydrationInput {
    grant: Vec<u8>, profile: Vec<u8>, account: String, device_public_key: [u8; 32],
    operation_permissions: Vec<String>, now: i64, clock_skew_seconds: i64,
    jrd: Vec<u8>, projection: Option<Projection>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RevocationInput { profile: Vec<u8>, account_did: String }

#[derive(Clone, Debug, PartialEq, Eq)]
struct CacheExpiryInput { profile: Vec<u8>, valid_until: i64, now: i64 }

fn decode_revocation_request<'a>(env: Env<'a>, term: Term<'a>) -> Result<RevocationInput, String> {
    reject_unknown(term, &["profile", "account_did"])?;
    Ok(RevocationInput { profile: bytes(env, term, "profile")?, account_did: utf8(env, term, "account_did")? })
}

fn decode_cache_expiry_request<'a>(env: Env<'a>, term: Term<'a>) -> Result<CacheExpiryInput, String> {
    reject_unknown(term, &["profile", "valid_until", "now"])?;
    Ok(CacheExpiryInput { profile: bytes(env, term, "profile")?, valid_until: value(env, term, "valid_until")?, now: value(env, term, "now")? })
}

fn decode_standing_request<'a>(env: Env<'a>, term: Term<'a>) -> Result<StandingInput, String> {
    reject_unknown(term, &["profile", "operation_permissions", "now", "clock_skew_seconds", "projection"])?;
    Ok(StandingInput { profile: bytes(env, term, "profile")?, operation_permissions: strings(env, term, "operation_permissions")?, now: value(env, term, "now")?, clock_skew_seconds: value(env, term, "clock_skew_seconds")?, projection: decode_projection(env, term)? })
}

fn decode_rehydration<'a>(env: Env<'a>, term: Term<'a>) -> Result<RehydrationInput, String> {
    reject_unknown(term, &["grant", "profile", "account", "device_public_key", "operation_permissions", "now", "clock_skew_seconds", "jrd", "projection"])?;
    Ok(RehydrationInput {
        grant: bytes(env, term, "grant")?, profile: bytes(env, term, "profile")?, account: utf8(env, term, "account")?,
        device_public_key: fixed::<32>(env, term, "device_public_key")?, operation_permissions: strings(env, term, "operation_permissions")?,
        now: value(env, term, "now")?, clock_skew_seconds: value(env, term, "clock_skew_seconds")?,
        jrd: bytes(env, term, "jrd")?, projection: decode_projection(env, term)?,
    })
}

fn verify_standing_pure(grant: &VerifiedGrant, request: &StandingInput, closures: &[ResolverClosure]) -> Result<(), String> {
    let profile = ApplicationProfile::recognise(&request.profile).map_err(|_| String::from("profile"))?;
    let closure = resolver_quorum(&profile, closures)?;
    let issuer = issuer_state(&closure);
    let permissions: Vec<&str> = request.operation_permissions.iter().map(String::as_str).collect();
    verify_standing(grant, &StandingRequest::new(&profile, &permissions, request.now, request.clock_skew_seconds), &StandingEvidence::new(&issuer, request.projection)).map_err(|_| String::from("rejected"))
}

fn rehydrate_pure(recovery: &RehydrationInput, closures: &[ResolverClosure]) -> Result<VerifiedGrant, String> {
    let profile = ApplicationProfile::recognise(&recovery.profile).map_err(|_| String::from("profile"))?;
    let closure = resolver_quorum(&profile, closures)?;
    let issuer = issuer_state(&closure);
    let account = AcctUri::parse(&recovery.account).map_err(|_| String::from("account"))?;
    let jrd = recognise_jrd(&recovery.jrd).map_err(|_| String::from("jrd"))?;
    let permissions: Vec<&str> = recovery.operation_permissions.iter().map(String::as_str).collect();
    rehydrate_verified_grant(
        &GrantRequest::new(&profile, &account, &recovery.device_public_key, &permissions, recovery.now, recovery.clock_skew_seconds),
        &issuer, &jrd, recovery.projection, &recovery.grant,
    ).map_err(|_| String::from("rejected"))
}

fn decode_presentation<'a>(env: Env<'a>, term: Term<'a>) -> Result<PathBPresentation, String> {
    reject_unknown(term, &[
        "grant", "profile", "account", "device_public_key", "operation_permissions", "now",
        "clock_skew_seconds", "jrd", "nonce", "grant_hash", "challenge_session", "issued_at",
        "proof_signature", "session", "projection",
    ])?;
    Ok(PathBPresentation {
        grant: bytes(env, term, "grant")?,
        profile: bytes(env, term, "profile")?,
        account: utf8(env, term, "account")?,
        device_public_key: fixed::<32>(env, term, "device_public_key")?,
        operation_permissions: strings(env, term, "operation_permissions")?,
        now: value(env, term, "now")?,
        clock_skew_seconds: value(env, term, "clock_skew_seconds")?,
        jrd: bytes(env, term, "jrd")?,
        nonce: fixed::<32>(env, term, "nonce")?,
        grant_hash: fixed::<32>(env, term, "grant_hash")?,
        challenge_session: utf8(env, term, "challenge_session")?,
        issued_at: value(env, term, "issued_at")?,
        proof_signature: fixed::<64>(env, term, "proof_signature")?,
        session: utf8(env, term, "session")?,
        projection: decode_projection(env, term)?,
    })
}

fn decode_closures<'a>(env: Env<'a>, term: Term<'a>) -> Result<Vec<ResolverClosure>, String> {
    reject_unknown(term, &["resolver_closures"])?;
    let closures: Vec<Term<'a>> = value(env, term, "resolver_closures")?;
    closures
        .into_iter()
        .map(|closure| decode_closure(env, closure))
        .collect()
}

fn decode_closure<'a>(env: Env<'a>, term: Term<'a>) -> Result<ResolverClosure, String> {
    reject_unknown(term, &[
        "resolver_id", "did", "did_recomputed_ok", "deltas_verified", "causally_complete", "deactivated",
        "assertion_methods", "revoked_credential_ids", "closure_age_seconds", "also_known_as",
    ])?;
    let methods: Vec<Term<'_>> = value(env, term, "assertion_methods")?;
    Ok(ResolverClosure {
        resolver_id: utf8(env, term, "resolver_id")?,
        did: utf8(env, term, "did")?,
        did_recomputed_ok: value(env, term, "did_recomputed_ok")?,
        deltas_verified: value(env, term, "deltas_verified")?,
        causally_complete: value(env, term, "causally_complete")?,
        deactivated: value(env, term, "deactivated")?,
        assertion_methods: methods
            .into_iter()
            .map(|method| decode_method(env, method))
            .collect::<Result<Vec<_>, _>>()?,
        revoked_credential_ids: strings(env, term, "revoked_credential_ids")?,
        closure_age_seconds: value(env, term, "closure_age_seconds")?,
        also_known_as: strings(env, term, "also_known_as")?,
    })
}

fn decode_method<'a>(env: Env<'a>, term: Term<'a>) -> Result<ResolverAssertionMethod, String> {
    reject_unknown(term, &["id", "kind", "public_key", "has_private_component"])?;
    Ok(ResolverAssertionMethod {
        id: utf8(env, term, "id")?,
        kind: utf8(env, term, "kind")?,
        public_key: fixed::<32>(env, term, "public_key")?,
        has_private_component: value(env, term, "has_private_component")?,
    })
}

fn decode_projection<'a>(env: Env<'a>, term: Term<'a>) -> Result<Option<Projection>, String> {
    let atom_name = map_term(env, term, "projection")?
        .atom_to_string()
        .map_err(|_| String::from("projection"))?;
    match atom_name.as_str() {
        "none" => Ok(None),
        "bit_set" => Ok(Some(Projection::BitSet)),
        "bit_unset" => Ok(Some(Projection::BitUnset)),
        "unavailable" => Ok(Some(Projection::Unavailable)),
        _ => Err(String::from("projection")),
    }
}

fn value<'a, T: rustler::Decoder<'a>>(
    env: Env<'a>, term: Term<'a>, key: &str,
) -> Result<T, String> {
    map_term(env, term, key)?
        .decode::<T>()
        .map_err(|_| String::from("type"))
}

fn map_term<'a>(env: Env<'a>, term: Term<'a>, key: &str) -> Result<Term<'a>, String> {
    term.map_get(key_atom(key).encode(env))
        .map_err(|_| String::from("missing"))
}

/// Map keys are the fixed atoms declared above.  This function never converts
/// a caller-controlled string to an atom, so a hostile map cannot exhaust the
/// BEAM atom table through this NIF.
fn key_atom(key: &str) -> Atom {
    match key {
        "grant" => grant_atom(), "profile" => profile(), "account" => account(),
        "device_public_key" => device_public_key(), "operation_permissions" => operation_permissions(),
        "now" => now(), "clock_skew_seconds" => clock_skew_seconds(), "jrd" => jrd(),
        "nonce" => nonce(), "grant_hash" => grant_hash(), "challenge_session" => challenge_session(),
        "issued_at" => issued_at(), "proof_signature" => proof_signature(), "session" => session(),
        "projection" => projection(), "did" => did(), "did_recomputed_ok" => did_recomputed_ok(),
        "resolver_closures" => resolver_closures(), "resolver_id" => resolver_id(),
        "deltas_verified" => deltas_verified(), "causally_complete" => causally_complete(),
        "deactivated" => deactivated(), "assertion_methods" => assertion_methods(),
        "revoked_credential_ids" => revoked_credential_ids(), "closure_age_seconds" => closure_age_seconds(),
        "also_known_as" => also_known_as(), "id" => id(), "kind" => kind(),
        "public_key" => public_key(), "has_private_component" => has_private_component(),
        "account_did" => account_did(), "grant_id" => grant_id(), "permissions" => permissions(), "valid_until" => valid_until(), "expires_at" => expires_at(),
        _ => unreachable!("all map keys are fixed at the call sites"),
    }
}

fn bytes<'a>(env: Env<'a>, term: Term<'a>, key: &str) -> Result<Vec<u8>, String> {
    Ok(value::<Binary<'a>>(env, term, key)?.as_slice().to_vec())
}

fn utf8<'a>(env: Env<'a>, term: Term<'a>, key: &str) -> Result<String, String> {
    String::from_utf8(bytes(env, term, key)?).map_err(|_| String::from("utf8"))
}

fn fixed<'a, const N: usize>(env: Env<'a>, term: Term<'a>, key: &str) -> Result<[u8; N], String> {
    let bytes = bytes(env, term, key)?;
    bytes.try_into().map_err(|_| String::from("length"))
}

fn strings<'a>(env: Env<'a>, term: Term<'a>, key: &str) -> Result<Vec<String>, String> {
    let values: Vec<Binary<'a>> = value(env, term, key)?;
    values
        .into_iter()
        .map(|value| String::from_utf8(value.as_slice().to_vec()).map_err(|_| String::from("utf8")))
        .collect()
}

fn reject_unknown(term: Term<'_>, allowed: &[&str]) -> Result<(), String> {
    let iterator = MapIterator::new(term).ok_or_else(|| String::from("map"))?;
    for (key_term, _) in iterator {
        let _: Atom = key_term.decode().map_err(|_| String::from("key"))?;
        let key = key_term.atom_to_string().map_err(|_| String::from("key"))?;
        if !allowed.contains(&key.as_str()) {
            return Err(String::from("unknown"));
        }
    }
    Ok(())
}

fn encode_verified<'a>(env: Env<'a>, grant: &VerifiedPathBGrant) -> Term<'a> {
    let mut map = rustler::types::map::map_new(env);
    map = map.map_put(account_did().encode(env), binary(env, grant.account_did.as_bytes())).expect("new map");
    map = map.map_put(grant_id().encode(env), binary(env, grant.grant_id.as_bytes())).expect("new map");
    map = map.map_put(device_public_key().encode(env), binary(env, &grant.device_public_key)).expect("new map");
    map = map.map_put(valid_until().encode(env), grant.valid_until.encode(env)).expect("new map");
    let permission_terms: Vec<Term<'a>> = grant
        .permissions
        .iter()
        .map(|permission| binary(env, permission.as_bytes()))
        .collect();
    map.map_put(permissions().encode(env), permission_terms.encode(env)).expect("new map")
}

fn binary<'a>(env: Env<'a>, bytes: &[u8]) -> Term<'a> {
    let mut owned = OwnedBinary::new(bytes.len()).expect("term allocation");
    owned.as_mut_slice().copy_from_slice(bytes);
    Binary::from_owned(owned, env).encode(env)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bad_profile_is_rejected_before_any_grant_interpretation() {
        let presentation = PathBPresentation {
            grant: b"not a compact JWS".to_vec(),
            profile: b"{}".to_vec(),
            account: "acct:x@example.test".to_owned(),
            device_public_key: [0; 32],
            operation_permissions: vec![], now: 0, clock_skew_seconds: 0,
            jrd: b"{}".to_vec(), nonce: [0; 32], grant_hash: [0; 32],
            challenge_session: "s".to_owned(), issued_at: 0,
            proof_signature: [0; 64], session: "s".to_owned(), projection: None,
        };
        let closure = ResolverClosure {
            resolver_id: "state-1".to_owned(), did: "did:crdt:bad".to_owned(), did_recomputed_ok: false,
            deltas_verified: false, causally_complete: false, deactivated: false,
            assertion_methods: vec![], revoked_credential_ids: vec![],
            closure_age_seconds: 0, also_known_as: vec![],
        };
        assert_eq!(verify_path_b_pure(&presentation, &[closure]), Err(String::from("profile")));
    }

    #[test]
    fn issuer_state_hard_codes_resolver_provenance() {
        let closure = ResolverClosure {
            resolver_id: "state-1".to_owned(), did: "did:crdt:x".to_owned(), did_recomputed_ok: true,
            deltas_verified: true, causally_complete: true, deactivated: false,
            assertion_methods: vec![], revoked_credential_ids: vec![],
            closure_age_seconds: 0, also_known_as: vec![],
        };
        assert_eq!(issuer_state(&closure).source, selfsame_app_identity::accept::ClosureSource::StateResolver);
    }

    #[test]
    fn operation_permission_refuses_unknown_and_con_002_unmapped_member_verbs() {
        // This guards CON-002's open fragment assignment from silently becoming
        // `chat-send` at the BEAM authentication boundary.
        for performative in ["future-control", "invite", "addagent", "removeagent", "sealedgrant", "pairgrant"] {
            // The public derivation returns the same refusal before it attempts
            // profile recognition, proving an unmapped verb cannot inherit a
            // permission from any profile contents.
            assert_eq!(derive_operation_permission(b"{}", performative), Err(String::from("unmapped-performative")));
            assert_eq!(operation_permission_fragment(performative), Err(String::from("unmapped-performative")), "{performative} must not inherit a capability");
        }
    }
}
