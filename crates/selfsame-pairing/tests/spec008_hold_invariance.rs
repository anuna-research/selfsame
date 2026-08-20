//! SPEC-008 `REQ-907` / `TEST-911` — the scope invariant.
//!
//! This implementation gives the wallet a production claimant. It grants
//! nothing to production ALLOCATION: `SPEC-007` `REQ-809`'s hold and its
//! gate remain exactly as they were, and this suite fails if any SPEC-008
//! change so much as bends them.

use selfsame_pairing::release;

#[test]
fn test_911_production_allocation_hold_is_untouched() {
    assert!(
        !release::PRODUCTION_ALLOCATION_ENABLED,
        "SPEC-008 SHALL NOT enable production allocation"
    );
    assert!(
        release::require_production_allocation().is_err(),
        "the allocation gate still fails closed"
    );
}
