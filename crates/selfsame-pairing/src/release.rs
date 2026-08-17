//! Compile-time production hold and rollback policy for the SPEC-007 cutover.
//!
//! Development shells expose CBCL pairing. Production invitation allocation is
//! a distinct release decision and is deliberately absent from this revision.

/// Whether this build may allocate production invitations.
///
/// Enabling this is a reviewed source change made only after the complete
/// SPEC-007 production gate has durable evidence. There is no environment,
/// feature, command-line, or runtime override.
pub const PRODUCTION_ALLOCATION_ENABLED: bool = false;

/// Durable production-gate evidence carried by this build.
pub const PRODUCTION_GATE_EVIDENCE_ID: Option<&str> = None;

/// Reviewed CBCL release to which this build can roll back.
pub const REVIEWED_CBCL_ROLLBACK_RELEASE: Option<&str> = None;

/// A production allocation attempt was stopped before creating any effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("ProductionPairingHeld")]
pub struct ProductionPairingHeld;

/// Prove the build-level production hold before an allocation boundary.
///
/// The function has no input capable of overriding policy and performs no I/O,
/// key generation, relay operation, session creation, or identity action.
pub const fn require_production_allocation() -> Result<(), ProductionPairingHeld> {
    if PRODUCTION_ALLOCATION_ENABLED && PRODUCTION_GATE_EVIDENCE_ID.is_some() {
        Ok(())
    } else {
        Err(ProductionPairingHeld)
    }
}

/// The target selected by release rollback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackTarget<'a> {
    /// Deploy the preceding reviewed CBCL-pairing release.
    ReviewedCbclRelease(&'a str),
    /// No reviewed predecessor exists, so every pairing entry point is disabled.
    PairingDisabled,
}

/// Effect-limiting release instructions applied while rolling back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackPlan<'a> {
    /// Release target, or complete pairing disablement before the first review.
    pub target: RollbackTarget<'a>,
    /// Every invitation made by the reverted release must be closed.
    pub close_unfinished_invitations: bool,
    /// The retired Selfsame protocol can never be selected by rollback.
    pub legacy_protocol_enabled: bool,
    /// Identity, credential, revocation, recovery, and device-link functions stay available.
    pub unrelated_identity_functions_enabled: bool,
    /// Rollback itself never enables production allocation.
    pub production_allocation_enabled: bool,
}

/// Derive the closed rollback action from the reviewed-predecessor record.
#[must_use]
pub fn rollback_plan(reviewed_predecessor: Option<&str>) -> RollbackPlan<'_> {
    let target = reviewed_predecessor
        .filter(|release| !release.is_empty())
        .map_or(
            RollbackTarget::PairingDisabled,
            RollbackTarget::ReviewedCbclRelease,
        );
    RollbackPlan {
        target,
        close_unfinished_invitations: true,
        legacy_protocol_enabled: false,
        unrelated_identity_functions_enabled: true,
        production_allocation_enabled: false,
    }
}
