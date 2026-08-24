//! Credential/v2 browser staging verifies the grant before the hub provisions
//! reciprocal WebFinger, but must not manufacture an authorized Path-B grant.

mod common;

use common::{Ceremony, PERMISSION};
use selfsame_app_identity::{
    accept::{AcceptStep, ClosureSource},
    path_b::{verify_inactive_staging, GrantRequest, VerifyError},
};

fn request(ceremony: &Ceremony) -> GrantRequest<'_> {
    GrantRequest::new(
        &ceremony.profile,
        &ceremony.account,
        &ceremony.device_public_key,
        &[PERMISSION],
        ceremony.now,
        0,
    )
}

#[test]
fn signed_grant_can_be_verified_for_inactive_staging_without_webfinger_or_proof() {
    let ceremony = Ceremony::accepted();
    let staged = verify_inactive_staging(
        &request(&ceremony),
        &ceremony.issuer,
        None,
        &ceremony.grant_bytes,
    )
    .expect("all pre-provisioning grant checks pass");

    assert_eq!(staged.account_did, ceremony.home_did);
    assert_eq!(staged.account, ceremony.account.as_str());
    assert_eq!(staged.device_did, ceremony.device_did);
    assert_eq!(staged.device_public_key, ceremony.device_public_key);
    assert_eq!(staged.permissions, vec![PERMISSION]);
    assert!(staged
        .grant_id
        .starts_with(&format!("{}#grant-", ceremony.home_did)));
    assert_eq!(
        staged.grant_id,
        format!(
            "{}#grant-{}",
            ceremony.home_did,
            selfsame_app_identity::codec::b64url(&staged.grant_token)
        )
    );
}

#[test]
fn inactive_staging_still_refuses_revocation_and_stale_resolver_state() {
    let ceremony = Ceremony::accepted();

    let staged = verify_inactive_staging(
        &request(&ceremony),
        &ceremony.issuer,
        None,
        &ceremony.grant_bytes,
    )
    .expect("fixture stages");
    let mut revoked = ceremony.issuer.clone();
    revoked.revoked_credential_ids.push(staged.grant_id);
    let err = verify_inactive_staging(&request(&ceremony), &revoked, None, &ceremony.grant_bytes)
        .expect_err("revocation is checked before staging");
    assert!(matches!(err, VerifyError::Grant(ref grant) if grant.step == AcceptStep::Status));

    let mut stale = ceremony.issuer.clone();
    stale.closure_age_seconds = 61;
    let err = verify_inactive_staging(&request(&ceremony), &stale, None, &ceremony.grant_bytes)
        .expect_err("stale state is not staged");
    assert!(matches!(err, VerifyError::Grant(ref grant) if grant.step == AcceptStep::Status));
}

#[test]
fn inactive_staging_requires_resolver_provenance_and_exact_offer_bindings() {
    let ceremony = Ceremony::accepted();
    let mut bundled = ceremony.issuer.clone();
    bundled.source = ClosureSource::BundleOrCache;
    assert_eq!(
        verify_inactive_staging(&request(&ceremony), &bundled, None, &ceremony.grant_bytes,),
        Err(VerifyError::NonResolverClosure)
    );

    let sibling = Ceremony::build(0, 1, 4, common::APPLICATION_ID);
    let err = verify_inactive_staging(
        &request(&ceremony),
        &sibling.issuer,
        None,
        &sibling.grant_bytes,
    )
    .expect_err("a sibling device does not match the offered key");
    assert!(matches!(err, VerifyError::Grant(ref grant) if grant.step == AcceptStep::Fields));
}
