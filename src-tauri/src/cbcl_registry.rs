//! SPEC-008 `CON-903` — the compiled approved-conformance registry.
//!
//! Each entry is the SHA-256 digest of one operator's published relay
//! conformance evidence. Adding an entry is a reviewed release change with an
//! owner-signed rationale beside it, never runtime configuration
//! (`SPEC-007` `CON-805` release semantics). The registry is EMPTY at
//! introduction: every non-loopback origin refuses, which is the valid,
//! fail-closed state for builds shipped before any operator publishes
//! evidence. The demo digest (`local_demo::LOCAL_CONFORMANCE_DIGEST`) never
//! appears here — it lives behind the `local-pairing-demo` feature and
//! `TEST-904` proves its absence from ordinary binaries.

use selfsame_app_identity::cbcl_relay::RelayPolicy;

/// Approved conformance-evidence digests. One entry per operator evidence
/// document, each traced to the evidence and the operator that produced it.
pub const APPROVED_CONFORMANCE: &[[u8; 32]] = &[
    // (empty — no operator has published relay conformance evidence yet;
    //  the first entry lands with the owner's ratification record,
    //  IMPL-008 `registry-first-entry`)
];

/// The one relay policy ordinary (non-demo) builds consult (`REQ-906`):
/// no forbidden operators yet, only registry digests, and never loopback.
#[must_use]
pub fn production_relay_policy() -> RelayPolicy<'static> {
    RelayPolicy {
        forbidden_operator_ids: &[],
        approved_conformance: APPROVED_CONFORMANCE,
        allow_loopback: false,
    }
}
