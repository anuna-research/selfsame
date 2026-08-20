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
    // `anuna-1` — the chat.anuna.io blind relay, operated by Anuna Research.
    // SHA-256 of the immutable evidence document
    // cbcl-bus `docs/relay-conformance-anuna-1.md` (cbcl-bus PR #97), whose
    // named CI evidence is run #420 (f0cbfa42) on git.anuna.io. Owner-directed
    // ratification 2026-08-20 (IMPL-008 `registry-first-entry`). Single
    // operator under SPEC-007 CON-806's availability exception.
    [
        0x70, 0x29, 0xf2, 0x22, 0x9f, 0x08, 0xc5, 0x48,
        0xb2, 0x52, 0x30, 0x94, 0x05, 0xba, 0xd9, 0xe5,
        0xbd, 0xdf, 0x97, 0x3a, 0x8c, 0x33, 0xc7, 0x3e,
        0x4b, 0xfb, 0x54, 0x08, 0xf7, 0x42, 0xc1, 0x42,
    ],
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
