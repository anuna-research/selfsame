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
    // An IPv6 literal keeps its brackets; everything else splits on the port.
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    // Name forms, the whole 127.0.0.0/8 block, and the IPv6 loopback — an
    // ordinary build must refuse every spelling of "this machine" (SPEC-008
    // review finding m-2), not only the ones the demo capability maps. The
    // IPv4 check is hand-decided because this crate's purity gate keeps
    // the standard networking module out entirely; a literal is four decimal
    // octets, so the grammar is small enough to state here directly.
    host == "localhost" || host.ends_with(".localhost") || host == "::1" || {
        let mut octets = host.split('.');
        let first = octets.next() == Some("127");
        first
            && (1..=3).all(|_| {
                octets.next().is_some_and(|part| {
                    !part.is_empty()
                        && part.len() <= 3
                        && part.bytes().all(|b| b.is_ascii_digit())
                        && part.parse::<u16>().is_ok_and(|value| value <= 255)
                })
            })
            && octets.next().is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::is_loopback;

    // SPEC-008 review finding m-2: every spelling of "this machine" is
    // loopback — names, the 127.0.0.0/8 block, and the IPv6 loopback.
    #[test]
    fn every_loopback_spelling_is_loopback() {
        for origin in [
            "https://localhost:7443",
            "https://demo.localhost:7443",
            "https://127.0.0.1:9443",
            "https://127.1.2.3",
            "https://[::1]:9443",
        ] {
            assert!(is_loopback(origin), "{origin} is loopback");
        }
        for origin in [
            "https://chat.anuna.io:9443",
            "https://relay.example",
            "https://127.example.com",
            "https://128.0.0.1",
            "https://127.0.0.1.evil.example",
        ] {
            assert!(!is_loopback(origin), "{origin} is not loopback");
        }
    }
}
