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
//! # Three deltas, because a genesis key cannot assert
//!
//! `CON-206` step 6 requires the grant's `kid` to name a **`JsonWebKey`** in the
//! issuer's `assertionMethod`, and `grant::header` signs under `{did}#jwk-0`.
//! Genesis creates `{did}#key-0`, an `Ed25519Signature2020` method in
//! `Authentication`, and neither half of that can be changed: the DID is a hash
//! of the genesis operation *including its relationships*, and `did:crdt` has no
//! operation that adds a relationship to an existing method.
//!
//! So the identity authorises its own key a second time under a fresh fragment,
//! carrying `AssertionMethod`. Same key material; what differs is what the
//! document says it may do. The resolver then projects that method into the
//! `JsonWebKey` twin the VC JOSE/COSE profile requires, at `#jwk-0`, because it
//! is the first assertion-capable method — and step 6 resolves there.
//!
//! An earlier version of this module produced only genesis and the alias update
//! and gated issuance, because the projection did not exist upstream. It does
//! now, and the gate opens on evidence rather than on assumption:
//! [`IssuerIdentity::authorises_grants`] is computed by resolving the document
//! and looking for what step 6 will look for, not asserted by a constant.
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

/// The fragment the assertion-capable method is authorised under.
///
/// Not `#jwk-0`: that identifier belongs to the resolver's projection, and a
/// delta claiming it would be asserting a rendering rather than a key. The
/// projection numbers twins by position among asserting methods, so this one
/// becomes `#jwk-0` by being the only one.
const ASSERTION_FRAGMENT: &str = "key-1";

/// Where `CON-206` step 6 expects the issuer's key to resolve.
const GRANT_METHOD_FRAGMENT: &str = "#jwk-0";

/// The verification-method type that step 6 requires.
const JSON_WEB_KEY_TYPE: &str = "JsonWebKey";

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
    /// Whether the resolved document authorises the key this account's grants
    /// are signed under.
    ///
    /// **Computed, not assumed.** [`create`] resolves the document it just built
    /// and looks for exactly what `CON-206` step 6 looks for: a `JsonWebKey` at
    /// `{did}#jwk-0` present in `assertionMethod`. A constant here would be a
    /// claim about the pinned `did:crdt` revision that nothing rechecks; a
    /// resolution is the same question the verifier will ask.
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

    // Stage three: authorise this key to assert, so the resolver has something
    // to project as `#jwk-0`. Genesis cannot carry `AssertionMethod` without
    // changing the identifier, so it is a separate method over the same key.
    doc.merge_verified_delta(alias_delta.clone()).ok();
    let assertion_delta =
        identity::add_assertion_method(&doc, home_key, ASSERTION_FRAGMENT, now_ms + 1)
            .map_err(|_| IssuerError::Construction)?;

    let target = assertion_delta.content_hash().map_err(|_| IssuerError::Construction)?;
    let deltas = vec![genesis, alias_delta, assertion_delta.clone()];
    let closure = ClosureBundle { target, deltas: deltas.clone() };

    // Ask the document the question the verifier will ask, rather than
    // asserting the answer. If `did:crdt`'s projection is absent or changes
    // shape, this reports `false` and the caller refuses — which is how F3's
    // defect should have surfaced the first time.
    doc.merge_verified_delta(assertion_delta).ok();
    let authorises_grants = doc
        .resolve()
        .ok()
        .and_then(|r| r.did_document)
        .is_some_and(|d| {
            let expected = format!("{did}{GRANT_METHOD_FRAGMENT}");
            d.assertion_method.iter().any(|r| r.as_str() == Some(expected.as_str()))
                && d.verification_method
                    .iter()
                    .any(|m| m.id == expected && m.r#type == JSON_WEB_KEY_TYPE)
        });

    Ok(IssuerIdentity { did, acct_uri, deltas, closure, authorises_grants })
}
