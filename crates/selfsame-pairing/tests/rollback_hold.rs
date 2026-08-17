//! SPEC-007 TEST-810 and TEST-811 production hold and rollback evidence.

use selfsame_pairing::release::{
    require_production_allocation, rollback_plan, RollbackTarget, PRODUCTION_ALLOCATION_ENABLED,
    PRODUCTION_GATE_EVIDENCE_ID, REVIEWED_CBCL_ROLLBACK_RELEASE,
};

#[test]
fn test_810_production_allocation_is_held_before_every_effect_boundary() {
    assert!(!PRODUCTION_ALLOCATION_ENABLED);
    assert_eq!(PRODUCTION_GATE_EVIDENCE_ID, None);
    assert!(require_production_allocation().is_err());

    let policy_source = include_str!("../src/release.rs");
    for override_path in ["std::env", "option_env!", "cfg!(feature", "Command::new"] {
        assert!(
            !policy_source.contains(override_path),
            "production hold has a runtime override through {override_path}"
        );
    }
}

#[test]
fn test_811_first_release_rollback_disables_pairing_without_legacy_fallback() {
    assert_eq!(REVIEWED_CBCL_ROLLBACK_RELEASE, None);
    let plan = rollback_plan(REVIEWED_CBCL_ROLLBACK_RELEASE);
    assert_eq!(plan.target, RollbackTarget::PairingDisabled);
    assert!(plan.close_unfinished_invitations);
    assert!(!plan.legacy_protocol_enabled);
    assert!(plan.unrelated_identity_functions_enabled);
    assert!(!plan.production_allocation_enabled);
}

#[test]
fn test_811_reviewed_predecessor_is_the_only_rollback_target() {
    let plan = rollback_plan(Some("selfsame-cbcl-pairing-0.1.0-reviewed"));
    assert_eq!(
        plan.target,
        RollbackTarget::ReviewedCbclRelease("selfsame-cbcl-pairing-0.1.0-reviewed")
    );
    assert!(plan.close_unfinished_invitations);
    assert!(!plan.legacy_protocol_enabled);
    assert!(!plan.production_allocation_enabled);
}
