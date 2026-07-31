//! The credential vocabulary and its pinned context — `CON-224`, `NFR-204`,
//! `ADR-209`.
//!
//! # The normative artefact is the octets, not the URL
//!
//! `CON-224` is unusually clear about this, and the clarity is the security
//! property: *"Because the digest is the authority and the octets are archived
//! …, loss of `anuna.io` invalidates no issued credential and changes no
//! verification result."* An acquirer of the domain can serve different octets
//! and it has no verification-time effect, because **nothing fetches**.
//!
//! So the context ships as bytes, compiled in, and its digest is a constant.
//! `NFR-204` forbids "arbitrary remote JSON-LD context fetch, schema code
//! execution, dynamic algorithm loading, or plugin discovery" at verification
//! time, and `ADR-209` pins the contexts. A party that fetches the IRI for some
//! other purpose compares the retrieved octets to [`CONTEXT_DIGEST`] and fails
//! closed on mismatch; it never prefers the retrieved bytes or repairs the
//! difference. `CON-224` puts it plainly: *"An implementer who adds a fetch 'for
//! robustness' has added an attack surface and removed none."*
//!
//! # Term IRIs are names, not locations
//!
//! A value under [`VOCAB_BASE`] identifies a term. It need not resolve, and no
//! party dereferences one during verification. The same applies to
//! [`CONTEXT_IRI`]: it appears verbatim in every issued grant as an identifier,
//! and `tests/purity.rs` allows this module — and only this module — to name the
//! host for that reason.
//!
//! # An unresolved gap in the specification
//!
//! `CON-224` states that the version 1 file is **1,045 octets** with
//! `context_digest = 9dba4d06…`. That file was never published: the contract
//! names `contexts/device-grant-v1.jsonld` in the `selfsame` repository, and the
//! repository did not contain it. So the declared digest is unverifiable, and
//! this crate cannot adopt it without asserting agreement with bytes nobody can
//! read.
//!
//! What ships instead is the logical context from `CON-205`, serialised in **RFC
//! 8785 canonical form** — 794 octets, digest [`CONTEXT_DIGEST`]. Canonical form
//! is proposed deliberately: it is regenerable from the specification text
//! alone, so a second implementation can reproduce the octets and therefore the
//! digest, which is what `NFR-202` requires and what a pretty-printed file with
//! an unstated indentation convention could never provide.
//!
//! [`SPEC_004_DECLARED_DIGEST`] records the specification's value so the
//! divergence is visible rather than quietly resolved in this crate's favour.
//! Closing it is a Tier-1 gate item — *"The Selfsame JSON-LD context is
//! published at the `CON-224` IRI with immutable content, its `context_digest`
//! recorded here and in the corpus"* — and is recorded as `FINDING-004` in the
//! `EXP-001` report.

use crate::json::{self, Json, JsonError, Limits};

/// The immutable context identifier, which appears verbatim in every grant.
pub const CONTEXT_IRI: &str = "https://anuna.io/selfsame/credentials/device-grant/v1";

/// The base under which every Selfsame credential term is named.
pub const VOCAB_BASE: &str = "https://anuna.io/selfsame/vocab/device-grant/v1#";

/// The W3C base context, which `CON-205` requires first in the array.
pub const W3C_VC_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";

/// The exact octets of the Selfsame context.
///
/// Compiled in, never fetched. `CON-224`: the octets served at the IRI "SHALL
/// NEVER change", and a change of meaning is a new IRI ending `/v2` with a new
/// `profileVersion`.
pub const CONTEXT_OCTETS: &[u8] = include_bytes!("../../../contexts/device-grant-v1.jsonld");

/// `SHA-256(CONTEXT_OCTETS)` — the authority `CON-224` names.
pub const CONTEXT_DIGEST: [u8; 32] = [
    0x4f, 0x1e, 0xec, 0xe1, 0x61, 0x1f, 0x06, 0x65, 0x7f, 0xca, 0x7d, 0x00, 0xc2, 0x3e, 0x13, 0xe3,
    0x94, 0x31, 0x46, 0x4c, 0x03, 0x98, 0x61, 0x19, 0x2e, 0x0e, 0xa1, 0xd0, 0x5e, 0x5c, 0x1e, 0x20,
];

/// The digest SPEC-004 `CON-224` declares, for a file that was never published.
///
/// Recorded so the divergence is visible. See the module documentation and
/// `FINDING-004`.
pub const SPEC_004_DECLARED_DIGEST: [u8; 32] = [
    0x9d, 0xba, 0x4d, 0x06, 0x5a, 0x9b, 0x7f, 0x54, 0xac, 0xbc, 0xfe, 0x8d, 0x75, 0xe1, 0xf2, 0xc8,
    0xe7, 0xfe, 0x4a, 0xb8, 0xa4, 0xb8, 0x7a, 0x4a, 0xd3, 0xf8, 0x83, 0xc4, 0x5a, 0x3d, 0x11, 0x83,
];

/// `CON-224`: the context file is at most 8,192 octets.
pub const MAX_CONTEXT_OCTETS: usize = 8_192;

/// Why a context was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ContextError {
    /// A credential names a context this build does not pin.
    ///
    /// `NFR-204`: "Unknown context entries SHALL be rejected before
    /// signature-dependent authorization decisions are made."
    #[error("credential names an unknown context")]
    UnknownContext,
    /// The two required contexts are absent, out of order, or accompanied.
    #[error("credential @context is not the two required entries in order")]
    BadContextArray,
    /// Retrieved octets do not match the pinned digest.
    #[error("retrieved context octets do not match the pinned digest")]
    DigestMismatch,
    /// The pinned octets are not recognised JSON.
    #[error("context is not recognised JSON: {0}")]
    Json(#[from] JsonError),
}

/// `SHA-256` of the pinned octets, computed rather than trusted.
pub fn context_digest() -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(CONTEXT_OCTETS).into()
}

/// Recognise a credential's `@context` (`CON-205`, `NFR-204`).
///
/// The credential "MUST contain the two contexts in the stated order and no
/// unknown context". Order matters because the W3C base context defines `aud`
/// and `cnf`, and `CON-205` relies on that: those two members need no
/// declaration in the Selfsame context precisely because the base context is
/// included first.
pub fn recognise_context_array(value: &Json) -> Result<(), ContextError> {
    let items = value.as_array().ok_or(ContextError::BadContextArray)?;
    if items.len() != 2 {
        return Err(ContextError::BadContextArray);
    }
    if items[0].as_str() != Some(W3C_VC_CONTEXT) {
        return Err(ContextError::BadContextArray);
    }
    if items[1].as_str() != Some(CONTEXT_IRI) {
        return Err(ContextError::UnknownContext);
    }
    Ok(())
}

/// Compare octets retrieved from the IRI against the pinned digest.
///
/// The only reason a conforming party ever fetches the IRI is curiosity or
/// mirroring. `CON-224` requires the comparison anyway, and requires failing
/// closed on mismatch rather than preferring the retrieved bytes.
pub fn check_retrieved_octets(octets: &[u8]) -> Result<(), ContextError> {
    use sha2::Digest as _;
    if octets.len() > MAX_CONTEXT_OCTETS {
        return Err(ContextError::DigestMismatch);
    }
    let digest: [u8; 32] = sha2::Sha256::digest(octets).into();
    if digest != CONTEXT_DIGEST {
        return Err(ContextError::DigestMismatch);
    }
    Ok(())
}

/// The recognised context document, for inspection and for the corpus.
pub fn context_document() -> Result<Json, ContextError> {
    let limits = Limits { max_bytes: MAX_CONTEXT_OCTETS, max_depth: 8 };
    Ok(json::recognise(CONTEXT_OCTETS, limits)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    // TEST-241: the context digest and the non-dereference rule.
    #[test]
    fn the_pinned_digest_matches_the_pinned_octets() {
        assert_eq!(context_digest(), CONTEXT_DIGEST);
        assert!(CONTEXT_OCTETS.len() <= MAX_CONTEXT_OCTETS);
    }

    #[test]
    fn the_shipped_context_is_rfc_8785_canonical_and_therefore_regenerable() {
        // This is the property that makes the digest reproducible from the
        // specification text alone: a second implementation builds the logical
        // context CON-205 prints, canonicalises it, and gets these octets.
        let limits = Limits { max_bytes: MAX_CONTEXT_OCTETS, max_depth: 8 };
        assert!(
            json::is_canonical(CONTEXT_OCTETS, limits).unwrap(),
            "the context file must be RFC 8785 canonical"
        );
        assert!(!CONTEXT_OCTETS.starts_with(&[0xEF, 0xBB, 0xBF]), "no byte-order mark");
    }

    #[test]
    fn the_shipped_digest_diverges_from_the_one_spec_004_declares() {
        // Recorded as a test rather than only as prose, so the divergence
        // cannot be lost when someone regenerates the file. CON-224 names a
        // 1,045-octet file that was never published; this ships 794 canonical
        // octets instead. Closing the gap is a Tier-1 gate item, and this
        // assertion is what will fail — loudly, and in the right place — on the
        // day the real file arrives.
        assert_ne!(
            CONTEXT_DIGEST, SPEC_004_DECLARED_DIGEST,
            "CON-224's declared digest now matches: adopt it and delete this test"
        );
        assert_eq!(CONTEXT_OCTETS.len(), 794);
    }

    #[test]
    fn the_context_defines_every_term_con_205_uses() {
        let doc = context_document().unwrap();
        let ctx = doc.get("@context").expect("a single @context member");
        assert_eq!(ctx.get("@protected").and_then(Json::as_bool), Some(true));
        for term in [
            "SelfsameDeviceGrantCredential",
            "application",
            "account",
            "permissions",
            "SelfsameDidCrdtStatusEntry",
        ] {
            assert!(ctx.get(term).is_some(), "the context must define `{term}`");
        }
    }

    #[test]
    fn status_purpose_and_credential_id_are_scoped_inside_the_status_entry() {
        // CON-205: the scoping "is required, not stylistic". The W3C v2 context
        // defines `statusPurpose` only inside `BitstringStatusListEntry`, so a
        // `SelfsameDidCrdtStatusEntry` carrying it at the top level would use an
        // undefined term and fail the conformance REQ-205 asserts.
        let doc = context_document().unwrap();
        let ctx = doc.get("@context").unwrap();
        assert!(ctx.get("statusPurpose").is_none(), "must not be defined at the top level");
        assert!(ctx.get("credentialId").is_none(), "must not be defined at the top level");

        let entry = ctx.get("SelfsameDidCrdtStatusEntry").unwrap();
        let scoped = entry.get("@context").expect("a scoped context");
        assert_eq!(
            scoped.get("statusPurpose").and_then(Json::as_str),
            Some("https://www.w3.org/ns/credentials/status#statusPurpose"),
            "statusPurpose reuses the W3C IRI so both entry types agree on its meaning"
        );
        assert!(scoped.get("credentialId").is_some());
    }

    #[test]
    fn aud_and_cnf_are_deliberately_not_declared_here() {
        // CON-205: both are defined at the top level of the W3C v2 context,
        // `cnf` with its own scoped context covering `kid` and `jwk`. Declaring
        // them again would be a second definition of one term.
        let doc = context_document().unwrap();
        let ctx = doc.get("@context").unwrap();
        assert!(ctx.get("aud").is_none());
        assert!(ctx.get("cnf").is_none());
    }

    #[test]
    fn accepts_the_two_required_contexts_in_order() {
        let value = Json::arr([Json::text(W3C_VC_CONTEXT), Json::text(CONTEXT_IRI)]);
        assert!(recognise_context_array(&value).is_ok());
    }

    #[test]
    fn rejects_a_reordered_extended_or_unknown_context_array() {
        for value in [
            Json::arr([Json::text(CONTEXT_IRI), Json::text(W3C_VC_CONTEXT)]),
            Json::arr([Json::text(W3C_VC_CONTEXT)]),
            Json::arr([
                Json::text(W3C_VC_CONTEXT),
                Json::text(CONTEXT_IRI),
                Json::text("https://attacker.example/ctx"),
            ]),
            Json::text(CONTEXT_IRI),
        ] {
            assert!(recognise_context_array(&value).is_err(), "{value:?}");
        }
        assert_eq!(
            recognise_context_array(&Json::arr([
                Json::text(W3C_VC_CONTEXT),
                Json::text("https://attacker.example/ctx"),
            ])),
            Err(ContextError::UnknownContext)
        );
    }

    #[test]
    fn retrieved_octets_that_differ_by_one_byte_fail_closed() {
        assert!(check_retrieved_octets(CONTEXT_OCTETS).is_ok());
        let mut mutated = CONTEXT_OCTETS.to_vec();
        let last = mutated.len() - 1;
        mutated[last] ^= 0x01;
        assert_eq!(check_retrieved_octets(&mutated), Err(ContextError::DigestMismatch));
        assert_eq!(check_retrieved_octets(b""), Err(ContextError::DigestMismatch));
    }
}
