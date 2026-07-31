//! Provider selection and the authenticated hint — `CON-208`, `CON-209`,
//! `REQ-209`, `REQ-212`, `REQ-219`.
//!
//! `REQ-209`'s promise is negative and specific: *"The person SHALL NOT be asked
//! to type, paste, scan, or choose an endpoint during the normal path."* Every
//! endpoint decision comes from the embedded profile, and this is the procedure
//! that makes it.
//!
//! # The split between this module and its shell
//!
//! `CON-208` steps 4 and 5 probe the network, so they cannot live here. The
//! split is drawn where it makes the decision testable:
//!
//! ```text
//!   [pure]  next_group  ──▶  the shell probes them, bounded and in parallel
//!                                        │
//!   [pure]  choose  ◀────────────  ProbeOutcome per descriptor
//! ```
//!
//! [`next_group`] applies steps 2, 3 and 7 — expiry, local policy, protocol,
//! priority grouping, and the fall-through to the next group. [`choose`] applies
//! steps 5, 6 and 8 — eligibility, the weighted draw, and
//! [`SelectionError::NoEligibleRendezvous`]. The shell owns only the probes,
//! whose deadline `CON-208` caps at 1500 ms each.
//!
//! # Why the random input is a parameter, and what it must not be
//!
//! `CON-208`: "Selection MUST NOT use a stable user identifier, home DID,
//! `acct:` URI, device key, or recovery-derived value as the random input. Doing
//! so would create provider-visible cohorts."
//!
//! That is a privacy property, not a fairness one. A draw seeded from anything
//! stable sends the same person to the same provider every time, so the provider
//! learns "these ceremonies are one person" without being told. The core owns no
//! RNG, so the value is injected — and the signature makes it a `u64` rather
//! than any identifier-shaped type, which is the cheapest possible way to make
//! the wrong input awkward to supply.
//!
//! # The hint follows the ceremony, and does not restart it
//!
//! `REQ-212`: the joining client "SHALL follow that choice for the in-progress
//! ceremony. It SHALL NOT independently select a different rendezvous." One
//! election per ceremony, by the initiator. If the selected provider becomes
//! unavailable, the answer is not a second election — it is a **fresh
//! ceremony**, with every dependent value regenerated.

use crate::json::Json;
use crate::profile::{ApplicationProfile, RendezvousDescriptor};
use crate::UnixSeconds;

/// `CON-208` step 4: the per-probe deadline ceiling.
pub const MAX_PROBE_MILLISECONDS: u32 = 1_500;

/// Why selection failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SelectionError {
    /// `CON-208` step 8: every priority group was exhausted.
    ///
    /// `REQ-210`: when no declared provider is usable, "the operation SHALL stop
    /// with an actionable application error. It SHALL NOT silently route through
    /// infrastructure operated by Selfsame, Anuna, or a prior application."
    #[error("no eligible rendezvous")]
    NoEligibleRendezvous,
    /// The caller supplied a different number of probe outcomes than candidates.
    #[error("probe outcomes do not correspond to the candidate set")]
    MalformedProbeSet,
}

/// What the shell observed when it probed one descriptor.
///
/// Both halves are required: `CON-213` step 5 says a descriptor is recognised
/// only when "bounded pairing and mailbox probes return capability objects
/// accepted by" both contracts. A provider may operate both services or only
/// one, and one healthy service is not a usable descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeOutcome {
    /// The PROTO-003 `CON-401` pairing capability probe passed.
    pub pairing_ok: bool,
    /// The PROTO-002 `CON-301` mailbox capability probe passed.
    pub mailbox_ok: bool,
    /// How long the slower of the two took.
    pub elapsed_milliseconds: u32,
}

impl ProbeOutcome {
    /// Both capabilities passed within the deadline.
    ///
    /// `CON-208`: "Health responses are hints, not trust anchors." Passing a
    /// probe makes a descriptor *eligible*; it confers no authority, and all
    /// ceremony confidentiality and authenticity remain end to end.
    pub fn is_eligible(&self) -> bool {
        self.pairing_ok && self.mailbox_ok && self.elapsed_milliseconds <= MAX_PROBE_MILLISECONDS
    }
}

/// The next priority group to probe (`CON-208` steps 2, 3 and 7).
///
/// `after` is the priority of the group already tried, or `None` for the first
/// call. Returns the descriptors in the lowest remaining group, or `None` when
/// every group is exhausted.
pub fn next_group<'a>(
    profile: &'a ApplicationProfile,
    now: UnixSeconds,
    locally_forbidden: &[&str],
    after: Option<i64>,
) -> Option<Vec<&'a RendezvousDescriptor>> {
    // Step 2. Malformed, non-HTTPS, and unsupported-protocol descriptors were
    // already refused by `CON-201` recognition, so what remains here is expiry
    // and local policy — the two that depend on values the profile does not
    // carry.
    let usable: Vec<&RendezvousDescriptor> = profile
        .rendezvous
        .iter()
        .filter(|d| d.valid_until > now)
        .filter(|d| !locally_forbidden.contains(&d.id.as_str()))
        .filter(|d| after.is_none_or(|tried| d.priority > tried))
        .collect();

    // Step 3, then step 7's "repeats steps 4–6 with the next priority group".
    let lowest = usable.iter().map(|d| d.priority).min()?;
    Some(usable.into_iter().filter(|d| d.priority == lowest).collect())
}

/// Choose one descriptor from a probed group (`CON-208` steps 5, 6 and 8).
///
/// `random` is a uniformly distributed value the shell drew from a CSPRNG.
pub fn choose<'a>(
    candidates: &[&'a RendezvousDescriptor],
    probes: &[ProbeOutcome],
    random: u64,
) -> Result<&'a RendezvousDescriptor, SelectionError> {
    if candidates.len() != probes.len() {
        return Err(SelectionError::MalformedProbeSet);
    }
    // Step 5, then step 6's "where zero weight means ineligible". A zero-weight
    // descriptor is excluded here rather than given a zero-width slice, so it
    // can never be drawn by a rounding accident.
    let eligible: Vec<&'a RendezvousDescriptor> = candidates
        .iter()
        .zip(probes)
        .filter(|(_, probe)| probe.is_eligible())
        .filter(|(d, _)| d.weight > 0)
        .map(|(d, _)| *d)
        .collect();
    if eligible.is_empty() {
        return Err(SelectionError::NoEligibleRendezvous);
    }

    let total: u64 = eligible.iter().map(|d| d.weight as u64).sum();
    // Lemire's multiply-shift, rather than `random % total`. The modulo form
    // biases toward low indices whenever `total` does not divide 2^64, and a
    // systematic bias in provider choice is a systematic bias in who sees which
    // ceremonies. The bound is 64 descriptors of weight 65,535, so `total` fits
    // in 22 bits and the product cannot overflow a `u128`.
    let mut point = ((random as u128 * total as u128) >> 64) as u64;
    for descriptor in &eligible {
        let weight = descriptor.weight as u64;
        if point < weight {
            return Ok(descriptor);
        }
        point -= weight;
    }
    // Unreachable: `point < total` by construction. Returning the last eligible
    // descriptor rather than panicking keeps a rounding surprise from becoming
    // an availability failure.
    Ok(eligible[eligible.len() - 1])
}

/// The authenticated provider hint (`CON-209`).
///
/// Confidential inside the sealed offer and authenticated by the envelope tag
/// over additional data containing the PROTO-003 `binding_hash`. Before the
/// offer exists, the PROTO-003 binding already commits both clients to the
/// application ID, profile digest, provider ID, descriptor digest, route, and
/// nameplate — so this is a second commitment, not the only one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderHint {
    /// The canonical application identifier.
    pub application_id: String,
    /// The profile version, which the joiner must support.
    pub profile_version: i64,
    /// The selected provider.
    pub provider_id: String,
    /// `SHA-256` of the canonical descriptor, base64url.
    pub descriptor_digest: String,
    /// The `CON-219` `offerDigest`.
    ///
    /// Placing it here creates no cycle: the hint is one of the two members
    /// `offer_core` excludes, so the hint commits to the offer and the offer
    /// does not commit to the hint.
    pub offer_digest: String,
}

/// Why a hint was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HintError {
    /// A member is absent or the wrong JSON type.
    #[error("provider hint is malformed")]
    Malformed,
    /// The hint carries a member `CON-209` does not define.
    #[error("provider hint carries an unknown member")]
    UnknownMember,
    /// The hint carries an `accountScopeId`.
    ///
    /// Called out separately because it is the one member `CON-209` names
    /// explicitly as forbidden, and because leaking it would hand the
    /// rendezvous provider the private derivation selector.
    #[error("provider hint carries an account scope")]
    CarriesAccountScope,
    /// The application identifier is not the joiner's.
    #[error("provider hint names a different application")]
    ApplicationMismatch,
    /// The profile version is one this build does not speak.
    #[error("provider hint names an unsupported profile version")]
    UnsupportedProfileVersion,
    /// No descriptor in the authenticated profile has that provider ID.
    #[error("provider hint names a provider the profile does not declare")]
    UnknownProvider,
    /// The descriptor digest does not equal the joiner's local descriptor.
    #[error("provider hint descriptor digest does not match")]
    DescriptorMismatch,
    /// The offer digest is not the offer being processed.
    #[error("provider hint offer digest does not match")]
    OfferMismatch,
}

const HINT_MEMBERS: &[&str] =
    &["applicationId", "profileVersion", "providerId", "descriptorDigest", "offerDigest"];

impl ProviderHint {
    /// Serialise for sealing inside the offer.
    pub fn to_json(&self) -> Json {
        Json::obj([
            ("applicationId", Json::text(self.application_id.clone())),
            ("profileVersion", Json::int(self.profile_version)),
            ("providerId", Json::text(self.provider_id.clone())),
            ("descriptorDigest", Json::text(self.descriptor_digest.clone())),
            ("offerDigest", Json::text(self.offer_digest.clone())),
        ])
    }

    /// Recognise a hint as a closed language.
    pub fn recognise(value: &Json) -> Result<Self, HintError> {
        let members = value.as_object().ok_or(HintError::Malformed)?;
        for (name, _) in members {
            if name == "accountScopeId" {
                return Err(HintError::CarriesAccountScope);
            }
            if !HINT_MEMBERS.contains(&name.as_str()) {
                return Err(HintError::UnknownMember);
            }
        }
        let text = |n: &str| value.get(n).and_then(Json::as_str).ok_or(HintError::Malformed);
        Ok(Self {
            application_id: text("applicationId")?.to_string(),
            profile_version: value
                .get("profileVersion")
                .and_then(Json::as_i64)
                .ok_or(HintError::Malformed)?,
            provider_id: text("providerId")?.to_string(),
            descriptor_digest: text("descriptorDigest")?.to_string(),
            offer_digest: text("offerDigest")?.to_string(),
        })
    }

    /// The joiner's five checks (`CON-209`).
    ///
    /// Every one compares against the joiner's **own origin-authenticated
    /// profile**, never against a value the hint supplied. A hint can only ever
    /// select among things the joiner already trusts.
    pub fn verify(
        &self,
        profile: &ApplicationProfile,
        expected_offer_digest: &str,
    ) -> Result<(), HintError> {
        if self.application_id != profile.application_id.as_str() {
            return Err(HintError::ApplicationMismatch);
        }
        if self.profile_version != crate::PROFILE_VERSION {
            return Err(HintError::UnsupportedProfileVersion);
        }
        let descriptor = profile
            .rendezvous
            .iter()
            .find(|d| d.id == self.provider_id)
            .ok_or(HintError::UnknownProvider)?;
        if crate::codec::b64url(&descriptor.digest) != self.descriptor_digest {
            return Err(HintError::DescriptorMismatch);
        }
        if self.offer_digest != expected_offer_digest {
            return Err(HintError::OfferMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> ProbeOutcome {
        ProbeOutcome { pairing_ok: true, mailbox_ok: true, elapsed_milliseconds: 40 }
    }

    fn descriptor(id: &str, priority: i64, weight: i64) -> RendezvousDescriptor {
        RendezvousDescriptor {
            id: id.into(),
            url: format!("https://{id}.example"),
            protocol: "selfsame-rendezvous-v1".into(),
            pairing_url: format!("https://pairing-{id}.example"),
            pairing_protocol: "selfsame-pairing-v1".into(),
            pairing_route: "03".into(),
            priority,
            weight,
            valid_until: 2_000_000_000,
            digest: [0u8; 32],
        }
    }

    #[test]
    fn a_descriptor_is_eligible_only_when_both_probes_pass_within_the_deadline() {
        // CON-213 step 5 requires *both* capability objects. A provider may run
        // only one of the two services, and one healthy service is not a usable
        // descriptor.
        assert!(healthy().is_eligible());
        assert!(!ProbeOutcome { pairing_ok: false, ..healthy() }.is_eligible());
        assert!(!ProbeOutcome { mailbox_ok: false, ..healthy() }.is_eligible());
        assert!(
            !ProbeOutcome { elapsed_milliseconds: MAX_PROBE_MILLISECONDS + 1, ..healthy() }
                .is_eligible()
        );
        assert!(
            ProbeOutcome { elapsed_milliseconds: MAX_PROBE_MILLISECONDS, ..healthy() }
                .is_eligible(),
            "the deadline is inclusive"
        );
    }

    #[test]
    fn the_draw_lands_in_each_descriptor_in_proportion_to_its_weight() {
        // A statistical property, stated deterministically: sweeping the random
        // input across its range must partition it by weight.
        let a = descriptor("a", 10, 80);
        let b = descriptor("b", 10, 20);
        let candidates = [&a, &b];
        let probes = [healthy(), healthy()];

        let mut counts = [0usize; 2];
        const SAMPLES: u64 = 10_000;
        for i in 0..SAMPLES {
            let random = (i as u128 * u64::MAX as u128 / SAMPLES as u128) as u64;
            let chosen = choose(&candidates, &probes, random).unwrap();
            counts[usize::from(chosen.id == "b")] += 1;
        }
        let share_a = counts[0] as f64 / SAMPLES as f64;
        assert!((share_a - 0.80).abs() < 0.01, "weight 80/20 gave {share_a}");
    }

    #[test]
    fn a_zero_weight_descriptor_is_never_drawn() {
        // CON-201 step 6: "zero means ineligible". Excluded from the draw
        // outright rather than given a zero-width slice, so no rounding
        // accident can select it.
        let a = descriptor("a", 10, 0);
        let b = descriptor("b", 10, 1);
        let candidates = [&a, &b];
        let probes = [healthy(), healthy()];
        for i in 0..1_000u64 {
            let random = i.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            assert_eq!(choose(&candidates, &probes, random).unwrap().id, "b");
        }
    }

    #[test]
    fn an_unhealthy_descriptor_never_enters_the_draw() {
        let a = descriptor("a", 10, 90);
        let b = descriptor("b", 10, 10);
        let candidates = [&a, &b];
        let probes = [ProbeOutcome { mailbox_ok: false, ..healthy() }, healthy()];
        for i in 0..100u64 {
            assert_eq!(choose(&candidates, &probes, i << 56).unwrap().id, "b");
        }
    }

    #[test]
    fn an_all_ineligible_group_returns_no_eligible_rendezvous() {
        // REQ-210: the operation stops with an actionable error rather than
        // silently routing through anyone else's infrastructure.
        let a = descriptor("a", 10, 50);
        let candidates = [&a];
        assert_eq!(
            choose(&candidates, &[ProbeOutcome { pairing_ok: false, ..healthy() }], 0),
            Err(SelectionError::NoEligibleRendezvous)
        );
        assert_eq!(choose(&[], &[], 0), Err(SelectionError::NoEligibleRendezvous));
    }

    #[test]
    fn a_mismatched_probe_set_is_refused_rather_than_zipped_short() {
        let a = descriptor("a", 10, 50);
        assert_eq!(
            choose(&[&a], &[healthy(), healthy()], 0),
            Err(SelectionError::MalformedProbeSet)
        );
    }

    #[test]
    fn the_draw_covers_the_whole_range_without_falling_off_either_end() {
        let a = descriptor("a", 10, 1);
        let b = descriptor("b", 10, 1);
        let candidates = [&a, &b];
        let probes = [healthy(), healthy()];
        assert_eq!(choose(&candidates, &probes, 0).unwrap().id, "a");
        assert_eq!(choose(&candidates, &probes, u64::MAX).unwrap().id, "b");
    }
}
