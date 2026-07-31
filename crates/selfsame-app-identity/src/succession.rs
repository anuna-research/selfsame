//! Application identifier succession — `CON-225`, `REQ-231`, `REQ-202`.
//!
//! `REQ-202` already says that changing `applicationId` creates a new identity
//! and that silent migration is prohibited. This contract does not weaken that;
//! it defines **the one audited path** by which a person may carry an account
//! across the boundary, and keeps every other path closed.
//!
//! # Two signatures, and why one is not enough
//!
//! The per-account statement is **two** compact JWS values over byte-identical
//! payloads: the outgoing home key signs, and the incoming home key
//! countersigns. `CON-225` gives the reason for each half:
//!
//! - the outgoing key alone, if it leaked, "could nominate an attacker's DID as
//!   successor";
//! - the incoming key alone "could claim any predecessor's history".
//!
//! A person holding the recovery secret can produce both, and nobody else can
//! produce either — because both DIDs derive from the same secret under
//! `CON-202`, with only the application node differing.
//!
//! # The pinned key set is the load-bearing rule
//!
//! The developer pointer's `kid` resolves in the `enrollment.requestSigningKeys`
//! set **the wallet recorded at this account's most recent successful
//! enrollment**, not in a set served now by any origin.
//!
//! `CON-225` explains why in one sentence worth keeping: *"Checking a currently
//! served key would make succession exactly as strong as a domain registration,
//! and a lapsed registration acquired by someone else is the case `OQ-204` was
//! opened for."* Checking a key the wallet pinned before the lapse turns a
//! DNS-strength control into a key-strength control, using state the wallet
//! already holds. If the developer rotated away every pinned key, succession
//! fails closed and the person enrols fresh — an availability cost, never an
//! authority one.
//!
//! # Why a signed statement rather than a `did:crdt` delta
//!
//! `CON-210` says plainly that a standalone signature does not revoke a grant,
//! so a reader is right to ask why succession gets to be one. The two operations
//! fail in opposite directions:
//!
//! - a **withheld revocation** means a dead grant keeps working. Withholding is
//!   the threat, so the state must be convergent and unsuppressable.
//! - a **withheld succession** means an old grant is simply not accepted. That
//!   is the fail-closed outcome, so no convergence is needed to make it safe.
//!
//! Convergent public state is mandatory where unavailability grants authority,
//! and merely convenient where unavailability withholds it. Publishing it as a
//! delta would also defeat its privacy property: `SetDocumentData` lands in the
//! resolvable document, so the outgoing DID would announce its successor to
//! every party that resolves it.
//!
//! # `CON-206` is deliberately not amended
//!
//! Succession changes **which expectation a verifier feeds the predicate**, not
//! the predicate. During the window the grant's account is still the *outgoing*
//! alias and its `application` and `aud` are still the outgoing identifier, and
//! `CON-206` runs unchanged against that expectation.

use crate::json::{Json, JsonError};
use crate::jws::{self, JwsPolicy, KidRule};
use crate::profile::{ApplicationProfile, Ed25519Jwk};
use crate::time::{self, TimeError};
use crate::UnixSeconds;

/// `CON-225`: the developer pointer's window ceiling — ninety days.
pub const MAX_POINTER_WINDOW_SECONDS: i64 = 7_776_000;

/// The developer pointer path on the **outgoing** origin.
pub const POINTER_PATH: &str = "/.well-known/selfsame/succession";

/// The JWS policy for the developer succession pointer.
pub const POINTER_JWS: JwsPolicy = JwsPolicy {
    typ: "selfsame-application-succession+jws",
    kid: KidRule::HttpsFragment,
    cty: None,
    max_octets: 4_096,
    max_payload_depth: 3,
};

/// The JWS policy for the outgoing per-account signature.
pub const OUTGOING_JWS: JwsPolicy = JwsPolicy {
    typ: "selfsame-succession+jws",
    kid: KidRule::DidUrl,
    cty: None,
    max_octets: 4_096,
    max_payload_depth: 3,
};

/// The JWS policy for the incoming countersignature.
pub const COUNTERSIGN_JWS: JwsPolicy = JwsPolicy {
    typ: "selfsame-succession-countersign+jws",
    kid: KidRule::DidUrl,
    cty: None,
    max_octets: 4_096,
    max_payload_depth: 3,
};

const POINTER_MEMBERS: &[&str] = &["successionVersion", "from", "to", "issuedAt", "expiresAt"];

const STATEMENT_MEMBERS: &[&str] = &[
    "successionVersion",
    "outgoing",
    "incoming",
    "outgoingApplication",
    "incomingApplication",
    "accountScopeId",
    "issuedAt",
    "expiresAt",
];

/// The single closed token `CON-225` defines.
///
/// "Every failure returns `SuccessionRejected` and leaves the outgoing identity,
/// its alias, its grants, its revocation state, the account scope, and every
/// session unchanged."
///
/// One token, deliberately: step 2 requires the wallet to disclose nothing on
/// failure — "in particular, not whether it holds an outgoing identity for that
/// application" — so a caller must not be able to tell *why* it was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("SuccessionRejected")]
pub struct SuccessionRejected;

impl From<JsonError> for SuccessionRejected {
    fn from(_: JsonError) -> Self {
        SuccessionRejected
    }
}

impl From<TimeError> for SuccessionRejected {
    fn from(_: TimeError) -> Self {
        SuccessionRejected
    }
}

/// The developer's succession pointer, served by the **outgoing** origin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pointer {
    /// The outgoing canonical application identifier.
    pub from: String,
    /// The incoming canonical application identifier.
    pub to: String,
    /// When it was issued.
    pub issued_at: UnixSeconds,
    /// When it expires, at most ninety days later.
    pub expires_at: UnixSeconds,
}

/// The per-account succession statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    /// The outgoing application-account home DID.
    pub outgoing: String,
    /// The incoming application-account home DID.
    pub incoming: String,
    /// The outgoing application identifier.
    pub outgoing_application: String,
    /// The incoming application identifier.
    pub incoming_application: String,
    /// The account scope, carried across unchanged.
    pub account_scope_id: String,
    /// Start of the overlap window.
    pub issued_at: UnixSeconds,
    /// End of the overlap window.
    pub expires_at: UnixSeconds,
}

/// Verify the developer pointer against the **pinned** enrollment key set.
///
/// `pinned_keys` is the set the wallet recorded at this account's most recent
/// successful enrollment under `CON-214` step 2. Passing a currently-served set
/// here would silently reduce succession to the strength of a domain
/// registration, which is the failure `OQ-204` was opened for.
pub fn verify_pointer(
    compact: &str,
    pinned_keys: &[Ed25519Jwk],
    pinned_kids: &[String],
    now: UnixSeconds,
) -> Result<Pointer, SuccessionRejected> {
    let signed = jws::recognise(compact, POINTER_JWS, &[]).map_err(|_| SuccessionRejected)?;
    let index = pinned_kids.iter().position(|k| k == &signed.kid).ok_or(SuccessionRejected)?;
    let key = pinned_keys.get(index).ok_or(SuccessionRejected)?;
    signed.verify(&key.public_key).map_err(|_| SuccessionRejected)?;

    closed(&signed.payload, POINTER_MEMBERS)?;
    if signed.payload.get("successionVersion").and_then(Json::as_i64) != Some(1) {
        return Err(SuccessionRejected);
    }
    let issued_at = stamp(&signed.payload, "issuedAt")?;
    let expires_at = stamp(&signed.payload, "expiresAt")?;
    if expires_at <= issued_at || expires_at - issued_at > MAX_POINTER_WINDOW_SECONDS {
        return Err(SuccessionRejected);
    }
    if now < issued_at || now >= expires_at {
        return Err(SuccessionRejected);
    }
    Ok(Pointer {
        from: text(&signed.payload, "from")?,
        to: text(&signed.payload, "to")?,
        issued_at,
        expires_at,
    })
}

/// What a verifier already knows, against which a statement is checked.
#[derive(Clone, Copy, Debug)]
pub struct Expectation<'a> {
    /// The DID the authority currently binds for this account.
    pub currently_bound: &'a str,
    /// The DID the authority is being asked to bind.
    pub asked_to_bind: &'a str,
    /// The incoming application's own recognised profile.
    pub incoming_profile: &'a ApplicationProfile,
    /// Whether the person confirmed both fingerprints under `CON-221`.
    pub person_confirmed: bool,
    /// Any unexpired statement whose `incoming` is this statement's `outgoing`.
    ///
    /// `CON-225` permits exactly one hop; chaining "would let a compromised
    /// intermediate launder an account into a third identity".
    pub prior_unexpired_incoming: Option<&'a str>,
    /// The current time.
    pub now: UnixSeconds,
}

/// Verify a per-account succession (`CON-225`'s five verifier checks).
///
/// The two JWS must verify **over byte-identical payloads**, which is why the
/// octets are compared rather than the recognised values: two payloads that
/// differ only in member order or whitespace would recognise alike and be two
/// different signed statements.
pub fn verify_statement(
    outgoing_compact: &str,
    countersign_compact: &str,
    outgoing_key: &[u8; 32],
    incoming_key: &[u8; 32],
    pointer: &Pointer,
    expect: &Expectation<'_>,
) -> Result<Statement, SuccessionRejected> {
    let outgoing_jws =
        jws::recognise(outgoing_compact, OUTGOING_JWS, &[]).map_err(|_| SuccessionRejected)?;
    let incoming_jws = jws::recognise(countersign_compact, COUNTERSIGN_JWS, &[])
        .map_err(|_| SuccessionRejected)?;

    // 1. Both verify, over byte-identical payloads.
    if outgoing_jws.payload_octets() != incoming_jws.payload_octets() {
        return Err(SuccessionRejected);
    }
    outgoing_jws.verify(outgoing_key).map_err(|_| SuccessionRejected)?;
    incoming_jws.verify(incoming_key).map_err(|_| SuccessionRejected)?;

    let payload = &outgoing_jws.payload;
    closed(payload, STATEMENT_MEMBERS)?;
    if payload.get("successionVersion").and_then(Json::as_i64) != Some(1) {
        return Err(SuccessionRejected);
    }
    let statement = Statement {
        outgoing: text(payload, "outgoing")?,
        incoming: text(payload, "incoming")?,
        outgoing_application: text(payload, "outgoingApplication")?,
        incoming_application: text(payload, "incomingApplication")?,
        account_scope_id: text(payload, "accountScopeId")?,
        issued_at: stamp(payload, "issuedAt")?,
        expires_at: stamp(payload, "expiresAt")?,
    };

    // Each `kid` resolves in its own DID's `assertionMethod`. The caller
    // resolved the keys; this checks the identifiers belong to the right DIDs.
    if !outgoing_jws.kid.starts_with(&statement.outgoing)
        || !incoming_jws.kid.starts_with(&statement.incoming)
    {
        return Err(SuccessionRejected);
    }

    // 2. `incoming` is the DID the authority is being asked to bind, and
    // `outgoing` is the one it currently binds.
    if statement.incoming != expect.asked_to_bind || statement.outgoing != expect.currently_bound {
        return Err(SuccessionRejected);
    }

    // 3. The pointer's `from`/`to` equal the statement's applications, and the
    // incoming profile's own identifier equals `to`.
    if pointer.from != statement.outgoing_application
        || pointer.to != statement.incoming_application
        || expect.incoming_profile.application_id.as_str() != pointer.to
    {
        return Err(SuccessionRejected);
    }

    // 4. The person confirmed both fingerprints.
    if !expect.person_confirmed {
        return Err(SuccessionRejected);
    }

    // The window is bounded by the **incoming** profile's grant lifetime — a
    // member CON-201 already defines, so version 1 adds no profile member.
    let window = statement.expires_at - statement.issued_at;
    if window <= 0 || window > expect.incoming_profile.revocation.max_grant_lifetime_seconds {
        return Err(SuccessionRejected);
    }
    if expect.now < statement.issued_at || expect.now >= statement.expires_at {
        return Err(SuccessionRejected);
    }

    // No chains. One hop; anything longer is re-enrollment.
    if expect.prior_unexpired_incoming == Some(statement.outgoing.as_str()) {
        return Err(SuccessionRejected);
    }

    Ok(statement)
}

/// Build the per-account statement payload, which both keys sign verbatim.
pub fn build_statement(statement: &Statement) -> Json {
    Json::obj([
        ("successionVersion", Json::int(1)),
        ("outgoing", Json::text(statement.outgoing.clone())),
        ("incoming", Json::text(statement.incoming.clone())),
        ("outgoingApplication", Json::text(statement.outgoing_application.clone())),
        ("incomingApplication", Json::text(statement.incoming_application.clone())),
        ("accountScopeId", Json::text(statement.account_scope_id.clone())),
        ("issuedAt", Json::text(time::format_date_time_stamp(statement.issued_at))),
        ("expiresAt", Json::text(time::format_date_time_stamp(statement.expires_at))),
    ])
}

/// Build the developer pointer payload.
pub fn build_pointer(pointer: &Pointer) -> Json {
    Json::obj([
        ("successionVersion", Json::int(1)),
        ("from", Json::text(pointer.from.clone())),
        ("to", Json::text(pointer.to.clone())),
        ("issuedAt", Json::text(time::format_date_time_stamp(pointer.issued_at))),
        ("expiresAt", Json::text(time::format_date_time_stamp(pointer.expires_at))),
    ])
}

/// Where a succession statement may **never** appear (`CON-225`).
///
/// "It SHALL NOT appear in `alsoKnownAs`, a WebFinger JRD, a status projection,
/// a state-resolver record, a callback, a log, or analytics. It travels in the
/// `CON-219` bundle or the application's authenticated account channel and
/// nowhere else."
///
/// Publishing it is what would create the cross-application link `NFR-201`
/// exists to prevent — which is why this is a list a test can iterate rather
/// than a paragraph a reviewer must remember.
pub const PROHIBITED_PUBLICATION_SITES: &[&str] = &[
    "alsoKnownAs",
    "webfinger-jrd",
    "status-projection",
    "state-resolver-record",
    "callback",
    "log",
    "analytics",
];

/// Whether the outgoing DID may be deactivated yet (`CON-225`).
///
/// The order is normative. The `did:crdt` deactivation latch is irreversible and
/// rejects **all** subsequent mutations, `RevokeCredential` among them, so
/// deactivating early strands any still-live grant in a state where it can never
/// be revoked — leaving expiry as the only remaining control, which is precisely
/// the degraded case `REQ-208` bounds rather than accepts.
///
/// A controller that cannot enumerate its outstanding grants passes `None` and
/// gets `false`: it "SHALL NOT deactivate".
pub fn may_deactivate_outgoing(outstanding_grants: Option<&[GrantStatus]>) -> bool {
    match outstanding_grants {
        None => false,
        Some(grants) => grants.iter().all(|g| g.revoked || g.expired),
    }
}

/// The state of one grant the outgoing identity issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantStatus {
    /// Whether its identifier is in the verified revocation set.
    pub revoked: bool,
    /// Whether it has passed its `validUntil`.
    pub expired: bool,
}

fn closed(value: &Json, allowed: &[&str]) -> Result<(), SuccessionRejected> {
    let members = value.as_object().ok_or(SuccessionRejected)?;
    if members.len() != allowed.len() {
        return Err(SuccessionRejected);
    }
    for (name, _) in members {
        if !allowed.contains(&name.as_str()) {
            return Err(SuccessionRejected);
        }
    }
    Ok(())
}

fn text(value: &Json, name: &str) -> Result<String, SuccessionRejected> {
    value.get(name).and_then(Json::as_str).map(str::to_string).ok_or(SuccessionRejected)
}

fn stamp(value: &Json, name: &str) -> Result<UnixSeconds, SuccessionRejected> {
    Ok(time::parse_date_time_stamp(&text(value, name)?)?)
}
