//! Standalone credential/v2 claimant gates before the blind relay socket.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use cbcl_pairing::credential_v2::{
    decode_carrier, CredentialV2Carrier, CredentialV2ClaimantSession,
    CredentialV2ClaimantSessionInput, CredentialV2PresenceCode, CredentialV2TofuState,
};
use selfsame_app_identity::profile::{ApplicationId, ApplicationProfile};
use selfsame_app_identity_net::profile::FetchedProfile;
use serde::Serialize;
use std::{fmt, str::FromStr};

use crate::{
    cbcl_v2_policy::{self, ExactPairState},
    commands::UiError,
};

type Result<T> = std::result::Result<T, UiError>;

/// Non-secret pre-socket projection safe for the relay-consent screen.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayConsentView {
    application_id: String,
    relay_origin: String,
    requires_approval: bool,
}

/// Origin-recognised profile and separate presence input before socket consent.
pub struct RelayConsentPlan {
    carrier: CredentialV2Carrier,
    presence_code: CredentialV2PresenceCode,
    fetched: FetchedProfile,
    pair_state: ExactPairState,
}

impl fmt::Debug for RelayConsentPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayConsentPlan")
            .field(
                "application_id",
                &self.fetched.profile.application_id.as_str(),
            )
            .field("relay_origin", &self.carrier.relay_origin())
            .field("pair_state", &self.pair_state)
            .field("presence", &"[REDACTED]")
            .finish()
    }
}

impl RelayConsentPlan {
    /// Project only the authenticated application, selected relay, and whether
    /// this exact tuple needs its one TOFU decision.
    #[must_use]
    pub fn view(&self) -> RelayConsentView {
        RelayConsentView {
            application_id: self.fetched.profile.application_id.as_str().into(),
            relay_origin: self.carrier.relay_origin().into(),
            requires_approval: self.pair_state == ExactPairState::NewPair,
        }
    }

    /// Return whether the exact pair already exists in person-owned policy.
    #[must_use]
    pub const fn pair_state(&self) -> ExactPairState {
        self.pair_state
    }

    /// Borrow the live-authenticated application identifier.
    #[must_use]
    pub fn application_id(&self) -> &str {
        self.fetched.profile.application_id.as_str()
    }

    /// Borrow the exact declared relay origin selected by the carrier.
    #[must_use]
    pub fn relay_origin(&self) -> &str {
        self.carrier.relay_origin()
    }

    /// Borrow the exact public carrier retained for checkpoint recovery.
    #[must_use]
    pub const fn carrier(&self) -> &CredentialV2Carrier {
        &self.carrier
    }
}

/// Closed command-owned choice for one pre-socket plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayConsentDecision {
    /// Reuse one recognised exact-pair policy row without prompting again.
    ExistingTrust,
    /// The person approved this new exact application-relay tuple.
    Approve,
    /// The person rejected this new exact tuple.
    Decline,
}

/// Single-use authority consumed before the socket is created.
pub struct RelaySocketCapability {
    carrier: CredentialV2Carrier,
    presence_code: CredentialV2PresenceCode,
    fetched: FetchedProfile,
    newly_approved: bool,
}

impl fmt::Debug for RelaySocketCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RelaySocketCapability([REDACTED])")
    }
}

/// In-memory claimant after the pre-socket capability is consumed.
pub struct PreparedClaimant {
    core: CredentialV2ClaimantSession,
    carrier: CredentialV2Carrier,
    profile: ApplicationProfile,
    profile_octets: Vec<u8>,
    newly_approved: bool,
    body_authority: selfsame_pairing::credential_v2::CredentialV2BodyAuthority,
}

impl fmt::Debug for PreparedClaimant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedClaimant([REDACTED])")
    }
}

/// Fully recognise the machine carrier and separate PAIR1 input, fetch the
/// named application directly over authenticated HTTPS, and evaluate only the
/// exact application-relay policy tuple. This function opens no relay socket.
pub async fn recognise_claimant_invitation(
    invitation: &str,
    presence_code: &str,
    now: i64,
) -> Result<RelayConsentPlan> {
    let carrier_bytes = Base64UrlUnpadded::decode_vec(invitation)
        .map_err(|_| UiError::from("RecognitionFailed"))?;
    let carrier = decode_carrier(&carrier_bytes).map_err(|_| UiError::from("RecognitionFailed"))?;
    let presence_code = CredentialV2PresenceCode::from_str(presence_code)
        .and_then(|value| value.bind_to_carrier(&carrier))
        .map_err(|_| UiError::from("PairingPresenceRefused"))?;
    let now_u64 = u64::try_from(now).map_err(|_| UiError::from("RecognitionFailed"))?;
    if now_u64 >= carrier.relay_expires_at() || carrier.expected_allocator_key().is_none() {
        return Err(UiError::from("RecognitionFailed"));
    }
    let application_id = ApplicationId::parse(carrier.application_context())
        .map_err(|_| UiError::from("PairingProfileUnavailable"))?;
    let fetched = selfsame_app_identity_net::profile::fetch(&application_id, now)
        .await
        .map_err(|_| UiError::from("PairingProfileUnavailable"))?;
    recognise_profile_candidate(carrier, presence_code, fetched)
}

fn recognise_profile_candidate(
    carrier: CredentialV2Carrier,
    presence_code: CredentialV2PresenceCode,
    fetched: FetchedProfile,
) -> Result<RelayConsentPlan> {
    let profile = &fetched.profile;
    if profile.application_id.as_str() != carrier.application_context() {
        return Err(UiError::from("PairingProfileUnavailable"));
    }
    let mut descriptors = profile
        .cbcl_pairing_relays
        .iter()
        .filter(|descriptor| descriptor.relay_origin == carrier.relay_origin());
    if descriptors.next().is_none() || descriptors.next().is_some() {
        return Err(UiError::from("PairingRelayRefused"));
    }
    let pair_state =
        cbcl_v2_policy::state(profile.application_id.as_str(), carrier.relay_origin())?;
    Ok(RelayConsentPlan {
        carrier,
        presence_code,
        fetched,
        pair_state,
    })
}

/// Consume the exact plan through either its existing row or the person's new
/// decision. No path here writes policy or opens a socket.
pub fn authorise_claimant_relay(
    plan: RelayConsentPlan,
    decision: RelayConsentDecision,
) -> Result<Option<RelaySocketCapability>> {
    let newly_approved = match (plan.pair_state, decision) {
        (ExactPairState::TrustedPair, RelayConsentDecision::ExistingTrust) => false,
        (ExactPairState::NewPair, RelayConsentDecision::Approve) => true,
        (_, RelayConsentDecision::Decline) => return Ok(None),
        _ => return Err(UiError::from("PairingRelayRefused")),
    };
    Ok(Some(RelaySocketCapability {
        carrier: plan.carrier,
        presence_code: plan.presence_code,
        fetched: plan.fetched,
        newly_approved,
    }))
}

/// Consume the single-use socket authority into a memory-only claimant core.
/// This still opens no socket; the transport shell does so only after return.
pub fn prepare_claimant(
    capability: RelaySocketCapability,
    cpace_scalar: [u8; 32],
) -> Result<PreparedClaimant> {
    let carrier = capability.carrier;
    let profile = capability.fetched.profile;
    let profile_octets = capability.fetched.octets;
    let (body_authority, body_verifier) =
        selfsame_pairing::credential_v2::credential_v2_body_authority();
    let core = CredentialV2ClaimantSession::new(
        CredentialV2ClaimantSessionInput {
            carrier: carrier.clone(),
            presence_code: capability.presence_code,
            cpace_scalar,
            profile_digest: *profile.digest(),
        },
        Box::new(body_verifier),
    )
    .map_err(|_| UiError::from("PairingFailed"))?;
    Ok(PreparedClaimant {
        core,
        carrier,
        profile,
        profile_octets,
        newly_approved: capability.newly_approved,
        body_authority,
    })
}

impl PreparedClaimant {
    /// Mutably borrow the sans-I/O core for the one TLS transport pump.
    pub fn core_mut(&mut self) -> &mut CredentialV2ClaimantSession {
        &mut self.core
    }

    /// Borrow the authenticated Offer object after the typed display gate.
    #[must_use]
    pub fn authenticated_offer(&self) -> Option<&cbcl_pairing::credential_v2::CredentialV2Object> {
        self.core.authenticated_offer()
    }

    /// Borrow the live origin-recognised profile retained for offer authority.
    #[must_use]
    pub const fn profile(&self) -> &ApplicationProfile {
        &self.profile
    }

    /// Borrow the exact live profile bytes for later final-status revalidation.
    #[must_use]
    pub fn profile_octets(&self) -> &[u8] {
        &self.profile_octets
    }

    /// Borrow the exact carrier-selected relay origin.
    #[must_use]
    pub fn relay_origin(&self) -> &str {
        self.carrier.relay_origin()
    }

    /// Borrow the exact public carrier retained for checkpoint recovery.
    #[must_use]
    pub const fn carrier(&self) -> &CredentialV2Carrier {
        &self.carrier
    }

    /// Borrow the sole builder for authenticated Selfsame successor objects.
    #[must_use]
    pub const fn body_authority(
        &self,
    ) -> &selfsame_pairing::credential_v2::CredentialV2BodyAuthority {
        &self.body_authority
    }

    /// After both Finished values, commit or re-check the exact-pair row and
    /// install the only verifier capable of producing the consent display.
    pub fn bind_finished_profile(&mut self, transcript_hash: [u8; 64]) -> Result<()> {
        if !self.core.is_awaiting_profile_authorisation() {
            return Err(UiError::from("PairingFailed"));
        }
        let tofu_state = if self.newly_approved {
            CredentialV2TofuState::NewPair
        } else {
            CredentialV2TofuState::TrustedPair
        };
        let verifier = selfsame_pairing::credential_v2::CredentialV2WalletOfferVerifier::new(
            self.profile.clone(),
            self.carrier.clone(),
            transcript_hash,
            tofu_state,
        )
        .map_err(|_| UiError::from("PairingFailed"))?
        .with_body_authority(self.body_authority.clone());
        let application_id = self.profile.application_id.as_str();
        let relay_origin = self.carrier.relay_origin();
        if self.newly_approved {
            cbcl_v2_policy::insert(application_id, relay_origin)?;
        } else if cbcl_v2_policy::state(application_id, relay_origin)?
            != ExactPairState::TrustedPair
        {
            return Err(UiError::from("PairingPolicyUnavailable"));
        }
        self.core
            .authorise_authenticated_profile(Box::new(verifier))
            .map_err(|_| UiError::from("PairingFailed"))
    }
}

/// Convert exact-pair state into the display's closed authenticated value.
#[must_use]
pub const fn display_tofu_state(state: ExactPairState) -> CredentialV2TofuState {
    match state {
        ExactPairState::NewPair => CredentialV2TofuState::NewPair,
        ExactPairState::TrustedPair => CredentialV2TofuState::TrustedPair,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbcl_pairing::{
        credential_v2::CredentialV2CarrierInput,
        wire::{claim_commitment, decode_client_message, ClaimToken, ClientMessage},
    };
    use ed25519_dalek::SigningKey;

    const RELAY: &str = "https://cbcl-au.provider.example";

    fn profile() -> ApplicationProfile {
        let corpus: serde_json::Value =
            serde_json::from_str(include_str!("../../test-vectors/spec-004-v1.json")).unwrap();
        let profile = corpus["con_201_application_profile"][0]["input"]["profile"]
            .as_str()
            .unwrap();
        ApplicationProfile::recognise(profile.as_bytes()).unwrap()
    }

    fn plan(state: ExactPairState) -> RelayConsentPlan {
        let profile = profile();
        let mailbox_id = [0x31; 32];
        let claim_token = [0x32; 16];
        let carrier = CredentialV2Carrier::new(CredentialV2CarrierInput {
            application_context: profile.application_id.as_str().into(),
            relay_origin: RELAY.into(),
            mailbox_id,
            carrier_ceremony_id: [0x33; 32],
            carrier_nonce: [0x34; 32],
            claim_commitment: claim_commitment(mailbox_id, &ClaimToken::new(claim_token)),
            relay_expires_at: 1_800_000_900,
            expected_allocator_key: Some(
                SigningKey::from_bytes(&[0x35; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
        })
        .unwrap();
        RelayConsentPlan {
            carrier,
            presence_code: CredentialV2PresenceCode::new([0x36; 16], claim_token),
            fetched: FetchedProfile {
                profile,
                octets: vec![0x37],
                fetched_at: 1_800_000_000,
            },
            pair_state: state,
        }
    }

    #[test]
    fn new_pair_needs_approval_and_capability_is_consumed_before_bind() {
        let view = plan(ExactPairState::NewPair).view();
        assert!(view.requires_approval);
        assert_eq!(view.relay_origin, RELAY);
        assert!(authorise_claimant_relay(
            plan(ExactPairState::NewPair),
            RelayConsentDecision::Decline,
        )
        .unwrap()
        .is_none());
        assert!(authorise_claimant_relay(
            plan(ExactPairState::NewPair),
            RelayConsentDecision::ExistingTrust,
        )
        .is_err());

        let capability =
            authorise_claimant_relay(plan(ExactPairState::NewPair), RelayConsentDecision::Approve)
                .unwrap()
                .unwrap();
        let mut claimant = prepare_claimant(capability, [0x38; 32]).unwrap();
        assert_eq!(
            decode_client_message(&claimant.core_mut().start().unwrap()).unwrap(),
            ClientMessage::Bind,
        );
    }

    #[test]
    fn existing_exact_pair_reuses_only_the_existing_trust_edge() {
        assert!(!plan(ExactPairState::TrustedPair).view().requires_approval);
        assert!(authorise_claimant_relay(
            plan(ExactPairState::TrustedPair),
            RelayConsentDecision::ExistingTrust,
        )
        .unwrap()
        .is_some());
        assert!(authorise_claimant_relay(
            plan(ExactPairState::TrustedPair),
            RelayConsentDecision::Approve,
        )
        .is_err());
    }
}
