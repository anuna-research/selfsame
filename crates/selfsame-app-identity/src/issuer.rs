//! Creating the application-account identity — `CON-203`, stages one and two.
//!
//! A grant names its issuer by DID, and `CON-206` step 4 has the verifier
//! obtain that issuer's **signed** `did:crdt` closure before step 5 recomputes
//! the self-certifying identifier from it. So a home key is not enough to issue
//! from: the identity needs a document, and until this module existed the
//! derivation produced a key whose DID nothing had ever published.
//!
//! That was `F3` of the G2 review — a signer for an identity that did not exist
//! as a document, so every grant it produced was unverifiable by any route.
//!
//! # Two stages, and the order is the contract
//!
//! `CON-203` is explicit:
//!
//! 1. create the `did:crdt` genesis and compute `home_did` from the home public
//!    key using the pinned method; **then**
//! 2. compute `acct_uri` from `home_did` and apply a root-signed document-data
//!    update setting `alsoKnownAs` to it.
//!
//! *"This ordering prevents a circular definition in which the alias hashes the
//! DID while the DID hashes the alias."* The alias is never an input to genesis
//! or to identifier derivation, and this module has no parameter through which
//! it could become one — the URI is computed here from the DID that stage one
//! produced, not accepted from a caller.
//!
//! # The closure this produces cannot yet authorise the key its grants name
//!
//! **This is why issuance is gated, and the gate is not a formality.**
//!
//! `CON-206` step 6 requires the grant's `kid` to name a `JsonWebKey` in the
//! issuer's `assertionMethod`, and `grant::header` signs under
//! `{did}#jwk-0`. What genesis creates is `{did}#key-0`, an
//! `Ed25519Signature2020` method in `Authentication` — so every bundle this
//! module could produce fails step 6.
//!
//! It cannot be repaired here. `did_crdt`'s `SuiteType` has two variants,
//! neither of which is `JsonWebKey`, so no delta at the pinned revision creates
//! a method of the required type. `CON-203` says as much in its own words: the
//! projection *"MAY be a deterministic DID resolver representation of the
//! existing root key"* and *"The corresponding `did:crdt` method change is a
//! Tier-1-gated dependency."* That dependency is an open box in this
//! specification's gate.
//!
//! So [`create`] builds what it can and [`IssuerIdentity::authorises_grants`]
//! reports honestly that the result is not yet sufficient. The caller refuses
//! rather than emitting a bundle no verifier can accept — a grant that fails at
//! the recipient is worse than one that was never issued, because the failure
//! surfaces later and somewhere else.
//!
//! # What this does not do
//!
//! It does not publish. `CON-206` step 4 prefers a declared `stateResolvers`
//! entry and treats a bundled closure as *"a bootstrap for a first ceremony on a
//! degraded network, not a standing arrangement"* — a verifier may rely on the
//! bundle only when accepting a grant ID for the first time with no resolver
//! reachable, and must record that it did.
//!
//! So the closure this produces belongs in the bundle **and** the same deltas
//! must reach a resolver. Publication is I/O, it belongs to the shell, and the
//! resolver it needs is `G6` in the Path-B readiness review — undeployed. That
//! gap is real and is not closed here; what is closed is that the identity now
//! exists at all.

use did_crdt::core::delta::SignedDelta;
use did_crdt::core::recon::ClosureBundle;
use selfsame_core::identity;

use crate::alias;

/// A newly created application-account identity, ready to issue from.
pub struct IssuerIdentity {
    /// The `did:crdt` identifier, recomputable by a verifier from the genesis.
    pub did: String,
    /// The RFC 7565 alias stage two published, for `CON-204` provisioning.
    pub acct_uri: String,
    /// Genesis and the `alsoKnownAs` update, in causal order.
    ///
    /// Both must reach a resolver. A closure carrying only the genesis
    /// satisfies step 5 and leaves `alsoKnownAs` absent, and `CON-203` says a
    /// resolver accepts the alias *"only when that document-data update is
    /// present in the verified signed closure"* — so a grant whose account URI
    /// a verifier cannot confirm fails step 9 rather than step 5, which is a
    /// harder failure to read.
    pub deltas: Vec<SignedDelta>,
    /// Whether the closure can authorise the key this account's grants are
    /// signed under.
    ///
    /// `false` at the pinned `did:crdt` revision, always, and the reason is
    /// upstream rather than here: `CON-206` step 6 wants a `JsonWebKey` at
    /// `#jwk-0` in `assertionMethod`, and the method cannot express one. See
    /// this module's header.
    ///
    /// It is a field rather than an assumption so that a caller has to look at
    /// it, and so the day the upstream box closes there is exactly one place
    /// that stops returning `false`.
    pub authorises_grants: bool,
    /// The closure a `CON-219` bundle carries as `issuerClosure`.
    ///
    /// `did_crdt`'s own type, deliberately: the method defines this shape, and
    /// `selfsame-app-identity-net`'s reader says in its own documentation that
    /// it mirrors it. Producing the upstream type is what guarantees the writer
    /// and the reader cannot drift — a wire shape with two definitions is the
    /// parser differential this codebase spends `CON-205` avoiding.
    ///
    /// It is returned unserialised because serialising needs `serde`, which
    /// this crate excludes on purpose: a second, more permissive JSON parser
    /// beside the strict one is the shotgun-parser shape LangSec Principle 5
    /// rules out. The shell serialises it.
    pub closure: ClosureBundle,
}

/// Why an identity could not be created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IssuerError {
    /// The pinned `did:crdt` method refused a construction step.
    #[error("did:crdt construction failed")]
    Construction,
}

/// Build the identity for one application account.
///
/// `home_key` is the account's own controlling key from `CON-202`, and
/// `authority` is the profile's `accountAuthority`. `now_ms` is the wallet's
/// clock in milliseconds, passed rather than read so this stays pure.
pub fn create(
    home_key: &ed25519_dalek::SigningKey,
    authority: &str,
    now_ms: u64,
) -> Result<IssuerIdentity, IssuerError> {
    // Stage one. The DID is a commitment to the public key and to nothing else.
    let (mut doc, genesis) =
        identity::sign_genesis(home_key).map_err(|_| IssuerError::Construction)?;
    let did = doc.did.to_string();

    // Stage two, and only now: the URI is a function of the DID stage one
    // produced. There is no parameter here through which a caller could supply
    // an alias, which is what keeps the ordering from being an instruction
    // somebody can get wrong.
    let acct_uri = alias::stable_acct_uri(&did, authority);

    // The update must commit to a frontier that already contains the genesis,
    // or a verifier holds a delta whose parent it has never seen.
    doc.merge_verified_delta(genesis.clone()).ok();
    let alias_delta = identity::set_also_known_as(&doc, home_key, &acct_uri, now_ms)
        .map_err(|_| IssuerError::Construction)?;

    let target = alias_delta.content_hash().map_err(|_| IssuerError::Construction)?;
    let deltas = vec![genesis, alias_delta];
    let closure = ClosureBundle { target, deltas: deltas.clone() };

    // The genesis authorises `#key-0` for authentication; a grant is signed
    // under `#jwk-0` and step 6 wants a `JsonWebKey` there. No delta at this
    // revision closes that gap — see the module header.
    let authorises_grants = false;

    Ok(IssuerIdentity { did, acct_uri, deltas, closure, authorises_grants })
}
