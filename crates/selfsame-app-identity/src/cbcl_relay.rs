//! Authenticated cbcl relay selection for `SPEC-007 CON-806`.

use crate::profile::{ApplicationProfile, CbclRelayDescriptor};

/// Local build and evidence policy applied after profile recognition.
#[derive(Clone, Copy, Debug)]
pub struct RelayPolicy<'a> {
    /// Operators prohibited by local policy.
    pub forbidden_operator_ids: &'a [&'a str],
    /// Conformance-evidence digests approved by this build.
    pub approved_conformance: &'a [[u8; 32]],
    /// Whether development loopback origins may be selected.
    pub allow_loopback: bool,
}

/// Closed selection failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RelaySelectionError {
    /// No descriptor passed the authenticated profile and local policy.
    #[error("no eligible cbcl relay")]
    NoEligibleRelay,
    /// The invitation origin did not identify exactly one eligible descriptor.
    #[error("invitation relay origin is not eligible")]
    InvitationOrigin,
}

/// Select one descriptor from the lowest eligible priority group.
///
/// `random` is a uniformly distributed `u64` drawn by the effectful shell.
pub fn select<'a>(
    profile: &'a ApplicationProfile,
    policy: &RelayPolicy<'_>,
    random: u64,
) -> Result<&'a CbclRelayDescriptor, RelaySelectionError> {
    let eligible: Vec<&CbclRelayDescriptor> = profile
        .cbcl_pairing_relays
        .iter()
        .filter(|descriptor| eligible(descriptor, policy))
        .collect();
    let priority = eligible
        .iter()
        .map(|descriptor| descriptor.priority)
        .min()
        .ok_or(RelaySelectionError::NoEligibleRelay)?;
    let group: Vec<&CbclRelayDescriptor> = eligible
        .into_iter()
        .filter(|descriptor| descriptor.priority == priority)
        .collect();
    let total: u64 = group
        .iter()
        .map(|descriptor| descriptor.weight as u64)
        .sum();
    let mut point = ((u128::from(random) * u128::from(total)) >> 64) as u64;
    for descriptor in &group {
        let weight = descriptor.weight as u64;
        if point < weight {
            return Ok(descriptor);
        }
        point -= weight;
    }
    group
        .last()
        .copied()
        .ok_or(RelaySelectionError::NoEligibleRelay)
}

/// Require an invitation to name exactly one locally eligible profile relay.
pub fn verify_invitation_origin(
    profile: &ApplicationProfile,
    policy: &RelayPolicy<'_>,
    invitation_origin: &str,
) -> Result<(), RelaySelectionError> {
    let mut matches = profile
        .cbcl_pairing_relays
        .iter()
        .filter(|descriptor| descriptor.relay_origin == invitation_origin)
        .filter(|descriptor| eligible(descriptor, policy));
    if matches.next().is_some() && matches.next().is_none() {
        Ok(())
    } else {
        Err(RelaySelectionError::InvitationOrigin)
    }
}

fn eligible(descriptor: &CbclRelayDescriptor, policy: &RelayPolicy<'_>) -> bool {
    !policy
        .forbidden_operator_ids
        .contains(&descriptor.operator_id.as_str())
        && policy
            .approved_conformance
            .contains(&descriptor.conformance_evidence_digest)
        && (policy.allow_loopback || !is_loopback(&descriptor.relay_origin))
}

fn is_loopback(origin: &str) -> bool {
    let authority = origin.strip_prefix("https://").unwrap_or(origin);
    let host = authority.split(':').next().unwrap_or(authority);
    host == "localhost" || host.ends_with(".localhost")
}
