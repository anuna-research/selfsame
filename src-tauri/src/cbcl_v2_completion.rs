//! Crash-safe credential/v2 claimant completion authority.
//!
//! The secure-store entry is one tagged pending-or-installed union.  The
//! pending arm is written before the final-approval frame is released and
//! contains only public authenticated facts plus cbcl-pairing's already sealed
//! endpoint checkpoint.  It never contains the hierarchy root, a derived key,
//! or an issuer signing key.

use cbcl_pairing::credential_v2::{
    decode_carrier, decode_object, encode_carrier, CredentialV2Carrier, CredentialV2Kind,
    CredentialV2Object, EndpointCheckpointV2,
};
use hkdf::Hkdf;
use selfsame_app_identity::{
    alias::AcctUri,
    codec, didkey, grant,
    hierarchy::HierarchyRoot,
    issuer::{self, IssuerIdentity},
    profile::ApplicationId,
    scope::AccountScopeId,
    uri::{self, UriPolicy},
};
use selfsame_app_identity_net::state::SignedClosure;
use selfsame_pairing::credential_v2::RecognisedCredentialV2Offer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::sync::Mutex;
use zeroize::Zeroizing;

use crate::{commands::UiError, store};

const SLOT_PREFIX: &str = "credential-v2-link-v1-";
const LINK_INDEX_ENTRY: &str = "credential-v2-link-index-v1";
const SLOT_VERSION: u8 = 1;
const LINK_INDEX_VERSION: u8 = 1;
const MAX_LINKS: usize = 256;
const MAX_LINK_INDEX_OCTETS: usize = 530_000;
const CHECKPOINT_LABEL: &[u8] = b"selfsame credential/v2 claimant checkpoint wrapping v1";
const ROOT_GENERATION_LABEL: &[u8] = b"selfsame credential/v2 root generation v1\0";
const MAX_SLOT_OCTETS: usize = 400_000;

// The platform store does not expose compare-and-swap. Selfsame is a
// single-instance application, so one process-wide lock makes each slot's
// read/recognise/write sequence indivisible inside the only writer process.
// A future multi-process client needs a backend CAS primitive instead.
static SLOT_LOCK: Mutex<()> = Mutex::new(());

type Result<T> = std::result::Result<T, UiError>;

pub(crate) struct CredentialV2ProvisioningPlan {
    application: ApplicationId,
    account_authority: String,
    scope: AccountScopeId,
    device_did: String,
    device_public_key: [u8; 32],
    permissions: Vec<String>,
    preview_issuer_did: String,
}

pub(crate) struct CredentialV2IssuerArtifacts {
    pub identity: IssuerIdentity,
    pub resolver_closure: Vec<u8>,
}

pub(crate) struct CredentialV2GrantArtifacts {
    pub grant_id: [u8; 32],
    pub grant: String,
}

impl CredentialV2ProvisioningPlan {
    pub fn from_authenticated_offer(
        profile: &selfsame_app_identity::profile::ApplicationProfile,
        offer: &RecognisedCredentialV2Offer,
        preview_issuer_did: &str,
    ) -> Result<Self> {
        let offer_core_digest: [u8; 32] = Sha256::digest(&offer.offer_core).into();
        if offer.profile_digest != *profile.digest()
            || offer.claims.application_id() != profile.application_id.as_str()
            || offer.claims.offer_core_digest() != &offer_core_digest
            || preview_issuer_did.parse::<did_crdt::Did>().is_err()
        {
            return Err(UiError::from("PairingProvisioningRefused"));
        }
        let device_did = offer.claims.device_binding().device_did();
        let device_public_key =
            didkey::decode(device_did).map_err(|_| UiError::from("PairingProvisioningRefused"))?;
        Ok(Self {
            application: profile.application_id.clone(),
            account_authority: profile.account_authority.clone(),
            scope: AccountScopeId::from_octets(
                *offer.claims.account_provenance().account_scope_id(),
            ),
            device_did: device_did.into(),
            device_public_key,
            permissions: offer.claims.permissions().to_vec(),
            preview_issuer_did: preview_issuer_did.into(),
        })
    }
}

#[cfg(test)]
static IDENTITY_EFFECTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
pub(crate) fn identity_effect_count() -> usize {
    IDENTITY_EFFECTS.load(std::sync::atomic::Ordering::SeqCst)
}

pub(crate) fn build_issuer_artifacts(
    root: &HierarchyRoot,
    plan: &CredentialV2ProvisioningPlan,
    effect_time: i64,
) -> Result<CredentialV2IssuerArtifacts> {
    #[cfg(test)]
    IDENTITY_EFFECTS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let now_ms = u64::try_from(effect_time)
        .ok()
        .and_then(|value| value.checked_mul(1_000))
        .ok_or_else(|| UiError::from("PairingProvisioningRefused"))?;
    let home = selfsame_app_identity::hierarchy::derive(root, &plan.application, &plan.scope);
    let home_did = home
        .home_did()
        .map_err(|_| UiError::from("PairingIdentityUnavailable"))?;
    if home_did != plan.preview_issuer_did {
        return Err(UiError::from("PairingPreviewChanged"));
    }
    let identity = issuer::create(home.signing_key(), &plan.account_authority, now_ms)
        .map_err(|_| UiError::from("PairingProvisioningRefused"))?;
    if identity.did != home_did || !identity.authorises_grants {
        return Err(UiError::from("PairingProvisioningRefused"));
    }
    let resolver_closure = serde_json::to_vec(&SignedClosure {
        target: identity.closure.target.clone(),
        deltas: identity.closure.deltas.clone(),
    })
    .map_err(|_| UiError::from("PairingProvisioningRefused"))?;
    if resolver_closure.is_empty()
        || resolver_closure.len() > selfsame_app_identity_net::state::MAX_CLOSURE_OCTETS
    {
        return Err(UiError::from("PairingProvisioningRefused"));
    }
    Ok(CredentialV2IssuerArtifacts {
        identity,
        resolver_closure,
    })
}

pub(crate) fn build_grant_artifacts(
    root: &HierarchyRoot,
    plan: &CredentialV2ProvisioningPlan,
    issuer: &CredentialV2IssuerArtifacts,
    grant_id: [u8; 32],
    effect_time: i64,
    max_grant_lifetime_seconds: i64,
) -> Result<CredentialV2GrantArtifacts> {
    #[cfg(test)]
    IDENTITY_EFFECTS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let valid_until = effect_time
        .checked_add(max_grant_lifetime_seconds)
        .filter(|value| *value > effect_time)
        .ok_or_else(|| UiError::from("PairingProvisioningRefused"))?;
    let home = selfsame_app_identity::hierarchy::derive(root, &plan.application, &plan.scope);
    let home_did = home
        .home_did()
        .map_err(|_| UiError::from("PairingIdentityUnavailable"))?;
    if home_did != plan.preview_issuer_did || home_did != issuer.identity.did {
        return Err(UiError::from("PairingPreviewChanged"));
    }
    let account = AcctUri::parse(&issuer.identity.acct_uri)
        .map_err(|_| UiError::from("PairingProvisioningRefused"))?;
    let compact = grant::issue(
        home.signing_key(),
        &issuer.identity.did,
        &grant_id,
        &plan.device_did,
        &plan.device_public_key,
        &plan.application,
        &account,
        &plan.permissions,
        effect_time,
        valid_until,
    );
    if compact.len() > 49_152 {
        return Err(UiError::from("PairingProvisioningRefused"));
    }
    Ok(CredentialV2GrantArtifacts {
        grant_id,
        grant: compact,
    })
}

/// Inputs already authenticated by the live claimant ceremony.
pub struct PendingCredentialV2Input<'a> {
    /// Generation of the wallet root that owns this application identity.
    pub root_generation: [u8; 32],
    /// Live authenticated application identifier.
    pub application_id: &'a str,
    /// Exact live authenticated profile digest.
    pub profile_digest: [u8; 32],
    /// Exact CON-220-authenticated profile bytes retained for restart recovery.
    pub offer_profile_octets: &'a [u8],
    /// Public carrier retained for exact endpoint restoration.
    pub carrier: &'a CredentialV2Carrier,
    /// Authenticated allocator Offer object.
    pub offer: &'a CredentialV2Object,
    /// Person-approved preliminary decision.
    pub intent_approve: &'a CredentialV2Object,
    /// Authenticated comparison or binding result.
    pub comparison: &'a CredentialV2Object,
    /// Person-approved final decision.
    pub final_approve: &'a CredentialV2Object,
    /// Locally derived and compared issuer DID.
    pub preview_issuer_did: &'a str,
    /// Exclusive signed offer deadline.
    pub offer_expires_at: u64,
    /// Monotonic cbcl-pairing checkpoint generation.
    pub checkpoint_generation: u64,
    /// Opaque encrypted cbcl-pairing endpoint checkpoint.
    pub checkpoint: &'a EndpointCheckpointV2,
}

/// Durable non-authorising recovery record written before final effects.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingCredentialV2Completion {
    version: u8,
    #[serde(
        default,
        skip_serializing_if = "crate::session::CredentialV2Flow::is_legacy"
    )]
    flow: crate::session::CredentialV2Flow,
    root_generation: String,
    application_id: String,
    relay_origin: String,
    profile_digest: String,
    offer_profile: String,
    carrier: String,
    offer: String,
    intent_approve: String,
    comparison: String,
    final_approve: String,
    preview_issuer_did: String,
    offer_expires_at: u64,
    checkpoint_generation: u64,
    endpoint_checkpoint: String,
    stage: PendingCredentialV2Stage,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "phase",
    content = "facts",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
enum PendingCredentialV2Stage {
    FinalApproval,
    Planned {
        effect_time: i64,
        grant_id: String,
    },
    IssuerCreated {
        effect_time: i64,
        grant_id: String,
        issuer_did: String,
        resolver_closure: String,
    },
    Provisioned {
        effect_time: i64,
        grant_id: String,
        issuer_did: String,
        grant: String,
        resolver_closure: String,
    },
    PayloadPrepared {
        effect_time: i64,
        grant_id: String,
        issuer_did: String,
        grant: String,
        resolver_closure: String,
        payload_content_hash: String,
    },
}

/// Installed capability facts retained only after immutable hub acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstalledCredentialV2Link {
    version: u8,
    #[serde(
        default,
        skip_serializing_if = "crate::session::CredentialV2Flow::is_legacy"
    )]
    flow: crate::session::CredentialV2Flow,
    root_generation: String,
    relay_origin: String,
    /// Immutable profile that authenticated the offer and final hub status.
    profile: String,
    /// Most recently reverified live profile. This may advance without
    /// replacing the historical signing evidence above.
    current_profile: String,
    grant: String,
    grant_digest: String,
    grant_id: String,
    credential_id: String,
    application_id: String,
    account_principal_digest: String,
    account_scope_id: String,
    account: String,
    installation_device_did: String,
    profile_digest: String,
    current_profile_digest: String,
    account_authority: String,
    issuer_did: String,
    resolver_closure: String,
    offer_core_digest: String,
    offer_kid: String,
    carrier_ceremony_id: String,
    request_id: String,
    payload_digest: String,
    receipt_recovery_commitment: String,
    final_status_jws: String,
    final_status_digest: String,
    finalized_at: u64,
}

/// Non-secret row used by the wallet's installed-link list.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledCredentialV2LinkSummary {
    pub application_id: String,
    pub account: String,
    pub relay_origin: String,
    pub issuer_did: String,
}

/// Non-secret row used to make every interrupted local link visible to the
/// person, including phases that are not eligible for terminal recovery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingCredentialV2LinkSummary {
    pub application_id: String,
    pub relay_origin: String,
    pub phase: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CredentialV2ReloadIdentity {
    pub root_generation: [u8; 32],
    pub application_id: String,
    pub account: String,
    pub account_authority: String,
    pub issuer_did: String,
    pub profile_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CredentialV2ReloadObservation {
    Unavailable,
    HubDeleted,
    Verified {
        root_generation: [u8; 32],
        application_id: String,
        observed_account: String,
        account_authority: String,
        issuer_did: String,
        profile_digest: [u8; 32],
        offer_key_retained: bool,
        grant_matches: bool,
        revoked: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CredentialV2ReloadOutcome {
    Usable,
    ProfileRefresh,
    AuthorityRotation,
    IssuerRotation,
    Unavailable,
    Revoked,
    HandleChanged,
    HubDeleted,
    FreshPairingRequired,
}

pub(crate) struct CredentialV2ReloadCheck {
    pub outcome: CredentialV2ReloadOutcome,
    pub replacement: Option<InstalledCredentialV2Link>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CredentialV2UnlinkOutcome {
    ConfirmationRequired,
    Authorised,
}

pub(crate) fn authorise_unlink(confirmation: bool) -> CredentialV2UnlinkOutcome {
    if confirmation {
        CredentialV2UnlinkOutcome::Authorised
    } else {
        CredentialV2UnlinkOutcome::ConfirmationRequired
    }
}

pub(crate) fn classify_reload(
    retained: &CredentialV2ReloadIdentity,
    observation: CredentialV2ReloadObservation,
) -> CredentialV2ReloadOutcome {
    let CredentialV2ReloadObservation::Verified {
        root_generation,
        application_id,
        observed_account,
        account_authority,
        issuer_did,
        profile_digest,
        offer_key_retained,
        grant_matches,
        revoked,
    } = observation
    else {
        return match observation {
            CredentialV2ReloadObservation::Unavailable => CredentialV2ReloadOutcome::Unavailable,
            CredentialV2ReloadObservation::HubDeleted => CredentialV2ReloadOutcome::HubDeleted,
            CredentialV2ReloadObservation::Verified { .. } => unreachable!(),
        };
    };
    if root_generation != retained.root_generation || application_id != retained.application_id {
        CredentialV2ReloadOutcome::FreshPairingRequired
    } else if observed_account != retained.account {
        CredentialV2ReloadOutcome::HandleChanged
    } else if account_authority != retained.account_authority || !offer_key_retained {
        CredentialV2ReloadOutcome::AuthorityRotation
    } else if issuer_did != retained.issuer_did {
        CredentialV2ReloadOutcome::IssuerRotation
    } else if revoked || !grant_matches {
        CredentialV2ReloadOutcome::Revoked
    } else if profile_digest != retained.profile_digest {
        CredentialV2ReloadOutcome::ProfileRefresh
    } else {
        CredentialV2ReloadOutcome::Usable
    }
}

/// Exactly one durable state occupies an application's credential/v2 slot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    content = "value",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
enum CredentialV2LinkSlot {
    Pending(PendingCredentialV2Completion),
    Installed(InstalledCredentialV2Link),
}

/// One fully recognised local application slot and the exact-pair policy state
/// sampled with it for confirmed unlink.
pub(crate) struct LocalCredentialV2Link {
    slot: CredentialV2LinkSlot,
    exact_pair_state: Option<crate::cbcl_v2_policy::ExactPairState>,
}

impl LocalCredentialV2Link {
    pub(crate) const fn is_pending(&self) -> bool {
        matches!(self.slot, CredentialV2LinkSlot::Pending(_))
    }

    pub(crate) fn require_root_generation(&self, expected: [u8; 32]) -> Result<()> {
        match &self.slot {
            CredentialV2LinkSlot::Pending(value) => value.require_root_generation(expected),
            CredentialV2LinkSlot::Installed(value) => value.require_root_generation(expected),
        }
    }
}

/// Bounded discovery index for secure stores that deliberately expose no
/// prefix scan. It contains application identifiers only, never grants,
/// checkpoint bytes, recovery tokens, or other credential material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CredentialV2LinkIndex {
    version: u8,
    applications: Vec<String>,
}

impl PendingCredentialV2Completion {
    pub(crate) fn with_flow(mut self, flow: crate::session::CredentialV2Flow) -> Self {
        self.flow = flow;
        self
    }

    /// Construct a closed pending record from typed ceremony objects.
    pub fn new(input: PendingCredentialV2Input<'_>) -> Result<Self> {
        validate_application_and_relay(input.application_id, input.carrier.relay_origin())?;
        let offer_profile = selfsame_app_identity::profile::ApplicationProfile::recognise(
            input.offer_profile_octets,
        )
        .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        if offer_profile.application_id.as_str() != input.application_id
            || *offer_profile.digest() != input.profile_digest
            || input.carrier.application_context() != input.application_id
            || input.offer.kind() != CredentialV2Kind::Offer
            || input.intent_approve.kind() != CredentialV2Kind::IntentApprove
            || !matches!(
                input.comparison.kind(),
                CredentialV2Kind::ComparisonConfirmed | CredentialV2Kind::BindingConfirmed
            )
            || input.final_approve.kind() != CredentialV2Kind::FinalApprove
            || input.offer.intent_digest() != input.intent_approve.intent_digest()
            || input.offer.intent_digest() != input.comparison.intent_digest()
            || input.offer.intent_digest() != input.final_approve.intent_digest()
            || input.preview_issuer_did.is_empty()
            || input.preview_issuer_did.len() > 512
            || !input.preview_issuer_did.is_ascii()
            || input.preview_issuer_did.parse::<did_crdt::Did>().is_err()
            || input.offer_expires_at == 0
            || input.checkpoint_generation == 0
            || input.checkpoint.as_bytes().is_empty()
        {
            return Err(UiError::from("PairingCheckpointRefused"));
        }
        Ok(Self {
            version: SLOT_VERSION,
            flow: crate::session::CredentialV2Flow::LegacyTwoDecision,
            root_generation: codec::b64url(&input.root_generation),
            application_id: input.application_id.into(),
            relay_origin: input.carrier.relay_origin().into(),
            profile_digest: codec::b64url(&input.profile_digest),
            offer_profile: codec::b64url(input.offer_profile_octets),
            carrier: codec::b64url(&encode_carrier(input.carrier).map_err(checkpoint_error)?),
            offer: codec::b64url(input.offer.as_bytes()),
            intent_approve: codec::b64url(input.intent_approve.as_bytes()),
            comparison: codec::b64url(input.comparison.as_bytes()),
            final_approve: codec::b64url(input.final_approve.as_bytes()),
            preview_issuer_did: input.preview_issuer_did.into(),
            offer_expires_at: input.offer_expires_at,
            checkpoint_generation: input.checkpoint_generation,
            endpoint_checkpoint: codec::b64url(input.checkpoint.as_bytes()),
            stage: PendingCredentialV2Stage::FinalApproval,
        })
    }

    /// Authenticated application owning the exact secure-store slot.
    #[must_use]
    pub fn application_id(&self) -> &str {
        &self.application_id
    }

    /// Exact checkpoint generation covered by this pending value.
    #[must_use]
    pub const fn checkpoint_generation(&self) -> u64 {
        self.checkpoint_generation
    }

    fn phase(&self) -> &'static str {
        match &self.stage {
            PendingCredentialV2Stage::FinalApproval => "final-approval",
            PendingCredentialV2Stage::Planned { .. } => "planned",
            PendingCredentialV2Stage::IssuerCreated { .. } => "issuer-created",
            PendingCredentialV2Stage::Provisioned { .. } => "provisioned",
            PendingCredentialV2Stage::PayloadPrepared { .. } => "payload-prepared",
        }
    }

    fn summary(&self) -> PendingCredentialV2LinkSummary {
        PendingCredentialV2LinkSummary {
            application_id: self.application_id.clone(),
            relay_origin: self.relay_origin.clone(),
            phase: self.phase(),
        }
    }

    fn is_payload_prepared(&self) -> bool {
        matches!(
            &self.stage,
            PendingCredentialV2Stage::PayloadPrepared { .. }
        )
    }

    /// Decode and re-recognise the exact profile authenticated before the
    /// claimant opened its relay socket.
    pub fn offer_profile_octets(&self) -> Result<Vec<u8>> {
        let octets = decode_bounded(
            &self.offer_profile,
            selfsame_app_identity::profile::MAX_PROFILE_OCTETS,
        )?;
        let profile = selfsame_app_identity::profile::ApplicationProfile::recognise(&octets)
            .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        let digest = codec::decode_b64url_32(&self.profile_digest)
            .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        if profile.application_id.as_str() != self.application_id || *profile.digest() != digest {
            return Err(UiError::from("PairingCheckpointRefused"));
        }
        Ok(octets)
    }

    /// Decode the exact carrier retained by this pending authority.
    pub fn carrier(&self) -> Result<CredentialV2Carrier> {
        self.validate()?;
        decode_carrier(&decode_bounded(&self.carrier, 4_096)?).map_err(checkpoint_error)
    }

    /// Decode the exact authenticated Offer object retained by the slot.
    pub fn offer_object(&self) -> Result<CredentialV2Object> {
        self.validate()?;
        decoded_object(&self.offer, CredentialV2Kind::Offer)
    }

    /// Decode the opaque sealed claimant checkpoint for native restoration.
    pub fn endpoint_checkpoint_octets(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        Ok(Zeroizing::new(decode_bounded(
            &self.endpoint_checkpoint,
            80_000,
        )?))
    }

    /// Verify that this pending slot belongs to the currently unlocked root.
    pub fn require_root_generation(&self, expected: [u8; 32]) -> Result<()> {
        self.validate()?;
        if codec::decode_b64url_32(&self.root_generation).ok() != Some(expected) {
            return Err(UiError::from("PairingCheckpointRefused"));
        }
        Ok(())
    }

    /// Return the exact payload-stage grant and closure facts.
    pub(crate) fn payload_facts(&self) -> Result<CredentialV2PayloadFacts> {
        self.validate()?;
        let PendingCredentialV2Stage::PayloadPrepared {
            grant_id,
            issuer_did,
            grant,
            resolver_closure,
            payload_content_hash,
            ..
        } = &self.stage
        else {
            return Err(UiError::from("PairingCheckpointRefused"));
        };
        Ok(CredentialV2PayloadFacts {
            grant_id: codec::decode_b64url_32(grant_id)
                .map_err(|_| UiError::from("PairingCheckpointRefused"))?,
            issuer_did: issuer_did.clone(),
            grant: grant.clone(),
            resolver_closure: decode_bounded(
                resolver_closure,
                selfsame_app_identity_net::state::MAX_CLOSURE_OCTETS,
            )?,
            payload_content_hash: codec::decode_b64url_32(payload_content_hash)
                .map_err(|_| UiError::from("PairingCheckpointRefused"))?,
        })
    }

    pub fn planned(&self, effect_time: i64, grant_id: [u8; 32]) -> Result<Self> {
        if self.stage != PendingCredentialV2Stage::FinalApproval || effect_time <= 0 {
            return Err(UiError::from("PairingCheckpointRefused"));
        }
        let mut next = self.clone();
        next.stage = PendingCredentialV2Stage::Planned {
            effect_time,
            grant_id: codec::b64url(&grant_id),
        };
        next.validate()?;
        Ok(next)
    }

    pub(crate) fn issuer_created(&self, artifacts: &CredentialV2IssuerArtifacts) -> Result<Self> {
        let PendingCredentialV2Stage::Planned {
            effect_time,
            grant_id,
        } = &self.stage
        else {
            return Err(UiError::from("PairingCheckpointRefused"));
        };
        if artifacts.identity.did != self.preview_issuer_did {
            return Err(UiError::from("PairingCheckpointRefused"));
        }
        let mut next = self.clone();
        next.stage = PendingCredentialV2Stage::IssuerCreated {
            effect_time: *effect_time,
            grant_id: grant_id.clone(),
            issuer_did: artifacts.identity.did.clone(),
            resolver_closure: codec::b64url(&artifacts.resolver_closure),
        };
        next.validate()?;
        Ok(next)
    }

    pub(crate) fn provisioned(&self, artifacts: &CredentialV2GrantArtifacts) -> Result<Self> {
        let PendingCredentialV2Stage::IssuerCreated {
            effect_time,
            grant_id,
            issuer_did,
            resolver_closure,
        } = &self.stage
        else {
            return Err(UiError::from("PairingCheckpointRefused"));
        };
        if codec::decode_b64url_32(grant_id).ok() != Some(artifacts.grant_id) {
            return Err(UiError::from("PairingCheckpointRefused"));
        }
        let mut next = self.clone();
        next.stage = PendingCredentialV2Stage::Provisioned {
            effect_time: *effect_time,
            grant_id: grant_id.clone(),
            issuer_did: issuer_did.clone(),
            grant: artifacts.grant.clone(),
            resolver_closure: resolver_closure.clone(),
        };
        next.validate()?;
        Ok(next)
    }

    pub fn payload_prepared(&self, payload_content_hash: [u8; 32]) -> Result<Self> {
        let PendingCredentialV2Stage::Provisioned {
            effect_time,
            grant_id,
            issuer_did,
            grant,
            resolver_closure,
        } = &self.stage
        else {
            return Err(UiError::from("PairingCheckpointRefused"));
        };
        let mut next = self.clone();
        next.stage = PendingCredentialV2Stage::PayloadPrepared {
            effect_time: *effect_time,
            grant_id: grant_id.clone(),
            issuer_did: issuer_did.clone(),
            grant: grant.clone(),
            resolver_closure: resolver_closure.clone(),
            payload_content_hash: codec::b64url(&payload_content_hash),
        };
        next.validate()?;
        Ok(next)
    }

    pub fn with_checkpoint(
        &self,
        generation: u64,
        checkpoint: &EndpointCheckpointV2,
    ) -> Result<Self> {
        if generation <= self.checkpoint_generation || checkpoint.as_bytes().is_empty() {
            return Err(UiError::from("PairingCheckpointRefused"));
        }
        let mut next = self.clone();
        next.checkpoint_generation = generation;
        next.endpoint_checkpoint = codec::b64url(checkpoint.as_bytes());
        next.validate()?;
        Ok(next)
    }

    fn validate(&self) -> Result<()> {
        if self.version != SLOT_VERSION
            || codec::decode_b64url_32(&self.root_generation).is_err()
            || codec::decode_b64url_32(&self.profile_digest).is_err()
            || self.offer_expires_at == 0
            || self.checkpoint_generation == 0
            || self.preview_issuer_did.is_empty()
            || self.preview_issuer_did.len() > 512
            || !self.preview_issuer_did.is_ascii()
            || self.preview_issuer_did.parse::<did_crdt::Did>().is_err()
        {
            return Err(UiError::from("PairingCheckpointRefused"));
        }
        self.offer_profile_octets()?;
        validate_application_and_relay(&self.application_id, &self.relay_origin)?;
        let carrier_bytes = decode_bounded(&self.carrier, 4_096)?;
        let carrier = decode_carrier(&carrier_bytes).map_err(checkpoint_error)?;
        if carrier.application_context() != self.application_id
            || carrier.relay_origin() != self.relay_origin
        {
            return Err(UiError::from("PairingCheckpointRefused"));
        }
        let offer = decoded_object(&self.offer, CredentialV2Kind::Offer)?;
        let intent = decoded_object(&self.intent_approve, CredentialV2Kind::IntentApprove)?;
        let comparison = decoded_object_either(
            &self.comparison,
            CredentialV2Kind::ComparisonConfirmed,
            CredentialV2Kind::BindingConfirmed,
        )?;
        let final_approve = decoded_object(&self.final_approve, CredentialV2Kind::FinalApprove)?;
        if offer.intent_digest() != intent.intent_digest()
            || offer.intent_digest() != comparison.intent_digest()
            || offer.intent_digest() != final_approve.intent_digest()
            || decode_bounded(&self.endpoint_checkpoint, 80_000)?.is_empty()
        {
            return Err(UiError::from("PairingCheckpointRefused"));
        }
        self.stage.validate(&self.preview_issuer_did)?;
        Ok(())
    }
}

/// The executable failure-injection points in the post-final-approval path.
///
/// The production command routes each corresponding fallible operation through
/// [`PrePayloadPendingTransaction`]. TEST-1162 uses the same hooks, so a label
/// cannot stand in for an unobserved production boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrePayloadBoundary {
    FinalApprovalRelease,
    AcknowledgementRead,
    AcknowledgementRecognition,
    AcknowledgementCheckpointReplacement,
    AcknowledgementCheckpointCommit,
    PlanConstruction,
    PlannedStageReplacement,
    IssuerCustody,
    IssuerStageReplacement,
    IssuerPublication,
    ResolverVerification,
    GrantConstruction,
    ProvisionedStageReplacement,
    PayloadConstruction,
    PayloadCheckpointPreparation,
}

pub(crate) trait PrePayloadFaultSink {
    fn before(&mut self, boundary: PrePayloadBoundary) -> Result<()>;
    fn after(&mut self) -> Result<()> {
        Ok(())
    }
}

pub(crate) struct NoPrePayloadFaults;

impl PrePayloadFaultSink for NoPrePayloadFaults {
    fn before(&mut self, _boundary: PrePayloadBoundary) -> Result<()> {
        Ok(())
    }
}

/// Armed before final approval is persisted. Every early return before
/// `PayloadPrepared` best-effort removes the exact latest slot without
/// replacing the protocol error that caused the return. Arming before the
/// store call also compensates a backend that commits and then reports failure.
/// Once the payload checkpoint is durable, recovery owns the slot and the
/// guard is disarmed.
struct PrePayloadPendingCleanup {
    current: Option<PendingCredentialV2Completion>,
}

impl PrePayloadPendingCleanup {
    fn new(current: PendingCredentialV2Completion) -> Self {
        debug_assert!(!current.is_payload_prepared());
        Self {
            current: Some(current),
        }
    }

    fn advance(&mut self, replacement: PendingCredentialV2Completion) {
        debug_assert!(!replacement.is_payload_prepared());
        self.current = Some(replacement);
    }

    fn disarm_after_payload(
        mut self,
        payload_prepared: PendingCredentialV2Completion,
    ) -> PendingCredentialV2Completion {
        debug_assert!(payload_prepared.is_payload_prepared());
        self.current = None;
        payload_prepared
    }
}

/// The only production authority for the durable pre-payload slot.
///
/// `begin` couples compensation to the initial persistence, `replace_at`
/// couples every phase replacement to the injected production boundary, and
/// `commit_payload` couples the last durable replacement to guard disarm. The
/// command cannot move disarm ahead of the store write because neither the
/// guard nor its disarm operation is exposed outside this type.
pub(crate) struct PrePayloadPendingTransaction {
    current: PendingCredentialV2Completion,
    cleanup: PrePayloadPendingCleanup,
}

impl PrePayloadPendingTransaction {
    pub(crate) fn begin(initial: PendingCredentialV2Completion) -> Result<Self> {
        let cleanup = PrePayloadPendingCleanup::new(initial.clone());
        persist_pending(&initial)?;
        Ok(Self {
            current: initial,
            cleanup,
        })
    }

    pub(crate) const fn current(&self) -> &PendingCredentialV2Completion {
        &self.current
    }

    pub(crate) fn try_step<T>(
        &mut self,
        faults: &mut impl PrePayloadFaultSink,
        boundary: PrePayloadBoundary,
        step: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        faults.before(boundary)?;
        let value = step()?;
        faults.after()?;
        Ok(value)
    }

    pub(crate) fn before_async(
        &mut self,
        faults: &mut impl PrePayloadFaultSink,
        boundary: PrePayloadBoundary,
    ) -> Result<()> {
        faults.before(boundary)
    }

    pub(crate) fn replace_at(
        &mut self,
        faults: &mut impl PrePayloadFaultSink,
        boundary: PrePayloadBoundary,
        replacement: PendingCredentialV2Completion,
    ) -> Result<()> {
        faults.before(boundary)?;
        replace_pending(&self.current, &replacement)?;
        self.current = replacement.clone();
        self.cleanup.advance(replacement);
        faults.after()
    }

    pub(crate) fn commit_payload(
        mut self,
        payload_prepared: PendingCredentialV2Completion,
    ) -> Result<PendingCredentialV2Completion> {
        if !payload_prepared.is_payload_prepared() {
            return Err(UiError::from("PairingCheckpointRefused"));
        }
        replace_pending(&self.current, &payload_prepared)?;
        self.current = payload_prepared.clone();
        Ok(self.cleanup.disarm_after_payload(payload_prepared))
    }
}

impl Drop for PrePayloadPendingCleanup {
    fn drop(&mut self) {
        if let Some(current) = self.current.as_ref() {
            let _ = remove_pre_payload_attempt(current);
        }
    }
}

/// Exact locally durable payload facts needed for hub-receipt verification.
pub(crate) struct CredentialV2PayloadFacts {
    pub grant_id: [u8; 32],
    pub issuer_did: String,
    pub grant: String,
    pub resolver_closure: Vec<u8>,
    pub payload_content_hash: [u8; 32],
}

impl InstalledCredentialV2Link {
    /// Private IPC evidence, available only after the normal installed loader
    /// has recognised the slot. No grant, checkpoint or signed receipt bytes.
    #[cfg(test)]
    pub(crate) fn host_evidence(&self) -> serde_json::Value {
        serde_json::json!({
            "applicationId": self.application_id,
            "account": self.account,
            "relayOrigin": self.relay_origin,
            "issuerDid": self.issuer_did,
            "grantId": self.grant_id,
            "grantDigest": self.grant_digest,
            "credentialId": self.credential_id,
            "installationDeviceDid": self.installation_device_did,
            "accountPrincipalDigest": self.account_principal_digest,
            "profileDigest": self.profile_digest,
            "offerCoreDigest": self.offer_core_digest,
            "carrierCeremonyId": self.carrier_ceremony_id,
            "requestId": self.request_id,
            "payloadDigest": self.payload_digest,
            "finalStatusDigest": self.final_status_digest,
            "finalizedAt": self.finalized_at,
        })
    }

    /// Build an installed candidate only from the pending payload and the
    /// endpoint-authenticated allocator Receipt.
    pub(crate) fn from_authenticated_receipt(
        pending: &PendingCredentialV2Completion,
        profile_octets: &[u8],
        receipt: &CredentialV2Object,
        receipt_recovery_commitment: [u8; 32],
    ) -> Result<Self> {
        pending.validate()?;
        let profile = selfsame_app_identity::profile::ApplicationProfile::recognise(profile_octets)
            .map_err(|_| UiError::from("PairingReceiptRefused"))?;
        if profile.application_id.as_str() != pending.application_id
            || *profile.digest()
                != codec::decode_b64url_32(&pending.profile_digest)
                    .map_err(|_| UiError::from("PairingReceiptRefused"))?
        {
            return Err(UiError::from("PairingReceiptRefused"));
        }
        let carrier = pending.carrier()?;
        let offer_object = decoded_object(&pending.offer, CredentialV2Kind::Offer)?;
        let offer =
            selfsame_pairing::credential_v2::recognise_signed_offer(&profile, offer_object.body())
                .map_err(|_| UiError::from("PairingReceiptRefused"))?;
        let facts = pending.payload_facts()?;
        let receipt = selfsame_pairing::credential_v2::recognise_receipt(
            receipt,
            *carrier.carrier_ceremony_id(),
            facts.payload_content_hash,
        )
        .map_err(|_| UiError::from("PairingReceiptRefused"))?;
        let final_status = || selfsame_pairing::credential_v2::CredentialV2FinalStatusInput {
            application_id: profile.application_id.as_str().into(),
            carrier_ceremony_id: *carrier.carrier_ceremony_id(),
            request_id: offer.request_id,
            account_principal_digest: *offer.claims.account_provenance().account_principal_digest(),
            account_scope_id: *offer.claims.account_provenance().account_scope_id(),
            device_did: offer.claims.device_binding().device_did().into(),
            offer_core_digest: *offer.claims.offer_core_digest(),
            payload_digest: facts.payload_content_hash,
            grant_id: facts.grant_id,
            issuer_did: facts.issuer_did.clone(),
            receipt_recovery_commitment,
            finalized_at: 0,
        };
        let finalized_at =
            selfsame_pairing::credential_v2::recognise_final_status_with_embedded_time(
                &profile,
                &receipt.final_status_jws,
                receipt.final_status_digest,
                |finalized_at| selfsame_pairing::credential_v2::CredentialV2FinalStatusInput {
                    finalized_at,
                    ..final_status()
                },
                &offer.kid,
            )
            .map_err(|_| UiError::from("PairingReceiptRefused"))?;

        let compact = selfsame_app_identity::jws::recognise(&facts.grant, grant::GRANT_JWS, &[])
            .map_err(|_| UiError::from("PairingReceiptRefused"))?;
        let recognised_grant = grant::recognise(&compact.payload)
            .map_err(|_| UiError::from("PairingReceiptRefused"))?;
        let account = selfsame_app_identity::alias::stable_acct_uri(
            &facts.issuer_did,
            &profile.account_authority,
        );
        if recognised_grant.issuer != facts.issuer_did
            || recognised_grant.token != codec::b64url(&facts.grant_id)
            || recognised_grant.application != profile.application_id.as_str()
            || recognised_grant.account.as_str() != account
            || recognised_grant.device_did != offer.claims.device_binding().device_did()
            || recognised_grant.permissions != offer.claims.permissions()
        {
            return Err(UiError::from("PairingReceiptRefused"));
        }
        let installed = Self {
            version: SLOT_VERSION,
            flow: pending.flow,
            root_generation: pending.root_generation.clone(),
            relay_origin: carrier.relay_origin().into(),
            profile: codec::b64url(profile_octets),
            current_profile: codec::b64url(profile_octets),
            grant_digest: codec::b64url(&Sha256::digest(facts.grant.as_bytes())),
            grant: facts.grant,
            grant_id: codec::b64url(&facts.grant_id),
            credential_id: recognised_grant.id,
            application_id: pending.application_id.clone(),
            account_principal_digest: codec::b64url(
                offer.claims.account_provenance().account_principal_digest(),
            ),
            account_scope_id: codec::b64url(offer.claims.account_provenance().account_scope_id()),
            account,
            installation_device_did: offer.claims.device_binding().device_did().into(),
            profile_digest: pending.profile_digest.clone(),
            current_profile_digest: pending.profile_digest.clone(),
            account_authority: profile.account_authority,
            issuer_did: facts.issuer_did,
            resolver_closure: codec::b64url(&facts.resolver_closure),
            offer_core_digest: codec::b64url(offer.claims.offer_core_digest()),
            offer_kid: offer.kid,
            carrier_ceremony_id: codec::b64url(carrier.carrier_ceremony_id()),
            request_id: codec::b64url(&offer.request_id),
            payload_digest: codec::b64url(&facts.payload_content_hash),
            receipt_recovery_commitment: codec::b64url(&receipt_recovery_commitment),
            final_status_jws: receipt.final_status_jws,
            final_status_digest: codec::b64url(&receipt.final_status_digest),
            finalized_at,
        };
        installed.validate()?;
        Ok(installed)
    }

    pub(crate) fn account(&self) -> Result<AcctUri> {
        AcctUri::parse(&self.account).map_err(|_| UiError::from("PairingReceiptRefused"))
    }

    pub(crate) fn issuer_did(&self) -> &str {
        &self.issuer_did
    }

    pub(crate) fn application_id(&self) -> &str {
        &self.application_id
    }

    pub(crate) fn account_text(&self) -> &str {
        &self.account
    }

    pub(crate) fn credential_id(&self) -> &str {
        &self.credential_id
    }

    pub(crate) fn grant_bytes(&self) -> &[u8] {
        self.grant.as_bytes()
    }

    pub(crate) fn installation_device_public_key(&self) -> Result<[u8; 32]> {
        didkey::decode(&self.installation_device_did)
            .map_err(|_| UiError::from("PairingCheckpointRefused"))
    }

    pub(crate) fn offer_key_retained_in(
        &self,
        current: &selfsame_app_identity::profile::ApplicationProfile,
    ) -> Result<bool> {
        let historical_octets = decode_bounded(&self.profile, 65_536)?;
        let historical =
            selfsame_app_identity::profile::ApplicationProfile::recognise(&historical_octets)
                .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        let retained = historical
            .enrollment_keys
            .iter()
            .find(|candidate| candidate.kid == self.offer_kid)
            .ok_or_else(|| UiError::from("PairingCheckpointRefused"))?;
        Ok(current
            .enrollment_keys
            .iter()
            .any(|candidate| candidate.kid == self.offer_kid && candidate.jwk == retained.jwk))
    }

    pub(crate) fn account_authority(&self) -> &str {
        &self.account_authority
    }

    pub(crate) fn current_profile_digest(&self) -> &str {
        &self.current_profile_digest
    }

    pub(crate) fn require_root_generation(&self, expected: [u8; 32]) -> Result<()> {
        let retained = codec::decode_b64url_32(&self.root_generation)
            .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        if retained != expected {
            return Err(UiError::from("PairingRootChanged"));
        }
        Ok(())
    }

    pub(crate) fn verify_reload(
        &self,
        observation: CredentialV2ReloadObservation,
        current_profile_octets: Option<&[u8]>,
    ) -> Result<CredentialV2ReloadCheck> {
        self.validate()?;
        let identity = CredentialV2ReloadIdentity {
            root_generation: codec::decode_b64url_32(&self.root_generation)
                .map_err(|_| UiError::from("PairingCheckpointRefused"))?,
            application_id: self.application_id.clone(),
            account: self.account.clone(),
            account_authority: self.account_authority.clone(),
            issuer_did: self.issuer_did.clone(),
            profile_digest: codec::decode_b64url_32(&self.current_profile_digest)
                .map_err(|_| UiError::from("PairingCheckpointRefused"))?,
        };
        let observed_profile_digest = match &observation {
            CredentialV2ReloadObservation::Verified { profile_digest, .. } => Some(*profile_digest),
            CredentialV2ReloadObservation::Unavailable
            | CredentialV2ReloadObservation::HubDeleted => None,
        };
        let outcome = classify_reload(&identity, observation);
        let replacement = if outcome == CredentialV2ReloadOutcome::ProfileRefresh {
            let octets =
                current_profile_octets.ok_or_else(|| UiError::from("PairingProfileUnavailable"))?;
            let current = selfsame_app_identity::profile::ApplicationProfile::recognise(octets)
                .map_err(|_| UiError::from("PairingProfileUnavailable"))?;
            let digest = observed_profile_digest
                .ok_or_else(|| UiError::from("PairingProfileUnavailable"))?;
            if current.application_id.as_str() != self.application_id
                || current.account_authority != self.account_authority
                || *current.digest() != digest
                || !self.offer_key_retained_in(&current)?
            {
                return Err(UiError::from("PairingProfileUnavailable"));
            }
            let mut replacement = self.clone();
            replacement.current_profile = codec::b64url(octets);
            replacement.current_profile_digest = codec::b64url(&digest);
            replacement.validate()?;
            Some(replacement)
        } else {
            None
        };
        Ok(CredentialV2ReloadCheck {
            outcome,
            replacement,
        })
    }

    fn summary(&self) -> InstalledCredentialV2LinkSummary {
        InstalledCredentialV2LinkSummary {
            application_id: self.application_id.clone(),
            account: self.account.clone(),
            relay_origin: self.relay_origin.clone(),
            issuer_did: self.issuer_did.clone(),
        }
    }

    fn validate(&self) -> Result<()> {
        let profile_octets = decode_bounded(&self.profile, 65_536)?;
        let profile =
            selfsame_app_identity::profile::ApplicationProfile::recognise(&profile_octets)
                .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        let current_profile_octets = decode_bounded(&self.current_profile, 65_536)?;
        let current_profile =
            selfsame_app_identity::profile::ApplicationProfile::recognise(&current_profile_octets)
                .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        let root_generation = codec::decode_b64url_32(&self.root_generation)
            .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        let profile_digest = codec::decode_b64url_32(&self.profile_digest)
            .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        let current_profile_digest = codec::decode_b64url_32(&self.current_profile_digest)
            .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        let grant_id = codec::decode_b64url_32(&self.grant_id)
            .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        let account_principal_digest = codec::decode_b64url_32(&self.account_principal_digest)
            .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        let account_scope_id = codec::decode_b64url_32(&self.account_scope_id)
            .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        let offer_core_digest = codec::decode_b64url_32(&self.offer_core_digest)
            .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        let carrier_ceremony_id = codec::decode_b64url_32(&self.carrier_ceremony_id)
            .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        let request_id = codec::decode_b64url_32(&self.request_id)
            .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        let payload_digest = codec::decode_b64url_32(&self.payload_digest)
            .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        let receipt_recovery_commitment =
            codec::decode_b64url_32(&self.receipt_recovery_commitment)
                .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        let final_status_digest = codec::decode_b64url_32(&self.final_status_digest)
            .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        if self.version != SLOT_VERSION
            || root_generation == [0; 32]
            || validate_application_and_relay(&self.application_id, &self.relay_origin).is_err()
            || profile.application_id.as_str() != self.application_id
            || *profile.digest() != profile_digest
            || current_profile.application_id.as_str() != self.application_id
            || *current_profile.digest() != current_profile_digest
            || current_profile.account_authority != self.account_authority
            || profile.account_authority != self.account_authority
            || self.finalized_at == 0
            || self.final_status_jws.is_empty()
            || self.final_status_jws.len() > 8_192
            || Sha256::digest(self.grant.as_bytes()).as_slice()
                != codec::decode_b64url_32(&self.grant_digest)
                    .map_err(|_| UiError::from("PairingCheckpointRefused"))?
        {
            return Err(UiError::from("PairingCheckpointRefused"));
        }
        let account = self.account()?;
        let expected_account = selfsame_app_identity::alias::stable_acct_uri(
            &self.issuer_did,
            &self.account_authority,
        );
        let compact = selfsame_app_identity::jws::recognise(&self.grant, grant::GRANT_JWS, &[])
            .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        let recognised_grant = grant::recognise(&compact.payload)
            .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        if account.as_str() != expected_account
            || recognised_grant.id != self.credential_id
            || recognised_grant.issuer != self.issuer_did
            || recognised_grant.token != codec::b64url(&grant_id)
            || recognised_grant.application != self.application_id
            || recognised_grant.account != account
            || recognised_grant.device_did != self.installation_device_did
        {
            return Err(UiError::from("PairingCheckpointRefused"));
        }
        validate_resolver_closure(&self.resolver_closure, &self.issuer_did)?;
        selfsame_pairing::credential_v2::recognise_final_status(
            &profile,
            &self.final_status_jws,
            final_status_digest,
            &selfsame_pairing::credential_v2::CredentialV2FinalStatusInput {
                application_id: self.application_id.clone(),
                carrier_ceremony_id,
                request_id,
                account_principal_digest,
                account_scope_id,
                device_did: self.installation_device_did.clone(),
                offer_core_digest,
                payload_digest,
                grant_id,
                issuer_did: self.issuer_did.clone(),
                receipt_recovery_commitment,
                finalized_at: self.finalized_at,
            },
            &self.offer_kid,
        )
        .map_err(|_| UiError::from("PairingCheckpointRefused"))
    }
}

impl PendingCredentialV2Stage {
    fn validate(&self, preview_issuer_did: &str) -> Result<()> {
        let facts = match self {
            Self::FinalApproval => return Ok(()),
            Self::Planned {
                effect_time,
                grant_id,
            } => {
                if *effect_time <= 0 || codec::decode_b64url_32(grant_id).is_err() {
                    return Err(UiError::from("PairingCheckpointRefused"));
                }
                return Ok(());
            }
            Self::IssuerCreated {
                effect_time,
                grant_id,
                issuer_did,
                resolver_closure,
            } => {
                if *effect_time <= 0
                    || codec::decode_b64url_32(grant_id).is_err()
                    || issuer_did != preview_issuer_did
                    || issuer_did.parse::<did_crdt::Did>().is_err()
                {
                    return Err(UiError::from("PairingCheckpointRefused"));
                }
                validate_resolver_closure(resolver_closure, issuer_did)?;
                return Ok(());
            }
            Self::Provisioned {
                effect_time,
                grant_id,
                issuer_did,
                grant,
                resolver_closure,
            }
            | Self::PayloadPrepared {
                effect_time,
                grant_id,
                issuer_did,
                grant,
                resolver_closure,
                ..
            } => (effect_time, grant_id, issuer_did, grant, resolver_closure),
        };
        let (effect_time, grant_id, issuer_did, grant, resolver_closure) = facts;
        if *effect_time <= 0
            || codec::decode_b64url_32(grant_id).is_err()
            || issuer_did != preview_issuer_did
            || issuer_did.parse::<did_crdt::Did>().is_err()
            || grant.is_empty()
            || grant.len() > 49_152
        {
            return Err(UiError::from("PairingCheckpointRefused"));
        }
        let compact = selfsame_app_identity::jws::recognise(grant, grant::GRANT_JWS, &[])
            .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        let recognised = grant::recognise(&compact.payload)
            .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        if recognised.issuer != *issuer_did || recognised.token != *grant_id {
            return Err(UiError::from("PairingCheckpointRefused"));
        }
        validate_resolver_closure(resolver_closure, issuer_did)?;
        if let Self::PayloadPrepared {
            payload_content_hash,
            ..
        } = self
        {
            codec::decode_b64url_32(payload_content_hash)
                .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        }
        Ok(())
    }
}

fn validate_resolver_closure(value: &str, issuer_did: &str) -> Result<()> {
    let closure = decode_bounded(value, selfsame_app_identity_net::state::MAX_CLOSURE_OCTETS)?;
    let recognised: SignedClosure =
        serde_json::from_slice(&closure).map_err(|_| UiError::from("PairingCheckpointRefused"))?;
    let mut genesis = recognised
        .deltas
        .iter()
        .filter(|delta| delta.parents.is_empty());
    if recognised.deltas.is_empty()
        || recognised
            .deltas
            .iter()
            .any(|delta| delta.did.as_str() != issuer_did)
        || !matches!((genesis.next(), genesis.next()), (Some(_), None))
        || !recognised
            .deltas
            .iter()
            .any(|delta| delta.content_hash().ok().as_ref() == Some(&recognised.target))
    {
        return Err(UiError::from("PairingCheckpointRefused"));
    }
    Ok(())
}

/// Derive a stable public generation identifier for the current root record.
#[must_use]
pub fn root_generation(root_public_key: &[u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(ROOT_GENERATION_LABEL);
    digest.update(root_public_key);
    digest.finalize().into()
}

/// Derive the distinct claimant checkpoint wrapping child inside custody.
///
/// The returned key is zeroized and callers keep it inside the
/// `Custody::use_hierarchy_root` closure.
pub fn checkpoint_wrapping_key(
    root: &HierarchyRoot,
    application_id: &str,
    carrier_ceremony_id: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    ApplicationId::parse(application_id).map_err(|_| UiError::from("PairingCheckpointRefused"))?;
    let label_len = u32::try_from(CHECKPOINT_LABEL.len())
        .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
    let application = application_id.as_bytes();
    let application_len =
        u32::try_from(application.len()).map_err(|_| UiError::from("PairingCheckpointRefused"))?;
    let mut info = Vec::with_capacity(8 + CHECKPOINT_LABEL.len() + application.len());
    info.extend_from_slice(&label_len.to_be_bytes());
    info.extend_from_slice(CHECKPOINT_LABEL);
    info.extend_from_slice(&application_len.to_be_bytes());
    info.extend_from_slice(application);
    let root_octets = root.expose();
    let hkdf = Hkdf::<Sha512>::new(Some(carrier_ceremony_id), root_octets.as_ref());
    let mut output = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, output.as_mut())
        .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
    Ok(output)
}

/// Occupy an empty application slot with one pending authority.
/// Exact retry is idempotent; another pending or installed value refuses. The
/// read/recognise/write is process-atomic under [`SLOT_LOCK`].
pub fn persist_pending(pending: &PendingCredentialV2Completion) -> Result<()> {
    let _guard = SLOT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    pending.validate()?;
    ensure_indexed_locked(&pending.application_id)?;
    let entry = slot_name(&pending.application_id)?;
    let slot = CredentialV2LinkSlot::Pending(pending.clone());
    let encoded = encode_slot(&slot)?;
    match store::get(&entry).map_err(|_| UiError::from("PairingCheckpointUnavailable"))? {
        None => {
            store::set(&entry, &encoded).map_err(|_| UiError::from("PairingCheckpointUnavailable"))
        }
        Some(existing) => match recognise_slot(&existing)? {
            CredentialV2LinkSlot::Pending(current) if current == *pending => Ok(()),
            CredentialV2LinkSlot::Pending(_) | CredentialV2LinkSlot::Installed(_) => {
                Err(UiError::from("PairingApplicationAlreadyLinked"))
            }
        },
    }
}

/// List every fully recognised post-payload recovery candidate.
///
/// Stale index rows left by a crash between the index and slot writes are
/// pruned. Installed rows remain indexed so root-lifecycle purge can discover
/// and remove every link even though the platform store has no list API.
pub fn pending_application_ids() -> Result<Vec<String>> {
    let _guard = SLOT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut index = load_index_locked()?;
    let mut retained = Vec::with_capacity(index.applications.len());
    let mut pending = Vec::new();
    let now = crate::commands::now();
    for application_id in &index.applications {
        let entry = slot_name(application_id)?;
        match store::get(&entry).map_err(|_| UiError::from("PairingCheckpointUnavailable"))? {
            None => {}
            Some(encoded) => match recognise_slot(&encoded)? {
                CredentialV2LinkSlot::Pending(value) if value.application_id == *application_id => {
                    retained.push(application_id.clone());
                    if matches!(
                        value.stage,
                        PendingCredentialV2Stage::PayloadPrepared { .. }
                    ) && now >= value.carrier()?.relay_expires_at()
                    {
                        pending.push(application_id.clone());
                    }
                }
                CredentialV2LinkSlot::Installed(value)
                    if value.application_id == *application_id =>
                {
                    retained.push(application_id.clone());
                }
                CredentialV2LinkSlot::Pending(_) | CredentialV2LinkSlot::Installed(_) => {
                    return Err(UiError::from("PairingCheckpointRefused"));
                }
            },
        }
    }
    if retained != index.applications {
        index.applications = retained;
        persist_index_locked(&index)?;
    }
    Ok(pending)
}

/// List every installed credential/v2 link without exposing grant bytes,
/// recovery material, scope identifiers, or immutable receipt evidence.
pub fn installed_links() -> Result<Vec<InstalledCredentialV2LinkSummary>> {
    let _guard = SLOT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut index = load_index_locked()?;
    let mut retained = Vec::with_capacity(index.applications.len());
    let mut installed = Vec::new();
    for application_id in &index.applications {
        let entry = slot_name(application_id)?;
        match store::get(&entry).map_err(|_| UiError::from("PairingCheckpointUnavailable"))? {
            None => {}
            Some(encoded) => match recognise_slot(&encoded)? {
                CredentialV2LinkSlot::Installed(value)
                    if value.application_id == *application_id =>
                {
                    retained.push(application_id.clone());
                    installed.push(value.summary());
                }
                CredentialV2LinkSlot::Pending(value) if value.application_id == *application_id => {
                    retained.push(application_id.clone());
                }
                CredentialV2LinkSlot::Pending(_) | CredentialV2LinkSlot::Installed(_) => {
                    return Err(UiError::from("PairingCheckpointRefused"));
                }
            },
        }
    }
    if retained != index.applications {
        index.applications = retained;
        persist_index_locked(&index)?;
    }
    Ok(installed)
}

/// List every recognised pending slot, regardless of whether its terminal
/// recovery window has opened. This is intentionally separate from
/// [`pending_application_ids`]: a pre-payload slot is abandonable but must
/// never be presented as recoverable.
pub fn pending_links() -> Result<Vec<PendingCredentialV2LinkSummary>> {
    let _guard = SLOT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut index = load_index_locked()?;
    let mut retained = Vec::with_capacity(index.applications.len());
    let mut pending = Vec::new();
    for application_id in &index.applications {
        let entry = slot_name(application_id)?;
        match store::get(&entry).map_err(|_| UiError::from("PairingCheckpointUnavailable"))? {
            None => {}
            Some(encoded) => match recognise_slot(&encoded)? {
                CredentialV2LinkSlot::Pending(value) if value.application_id == *application_id => {
                    retained.push(application_id.clone());
                    pending.push(value.summary());
                }
                CredentialV2LinkSlot::Installed(value)
                    if value.application_id == *application_id =>
                {
                    retained.push(application_id.clone());
                }
                CredentialV2LinkSlot::Pending(_) | CredentialV2LinkSlot::Installed(_) => {
                    return Err(UiError::from("PairingCheckpointRefused"));
                }
            },
        }
    }
    if retained != index.applications {
        index.applications = retained;
        persist_index_locked(&index)?;
    }
    Ok(pending)
}

/// Read either kind of local slot for a person-confirmed removal. Recognition
/// occurs before presence is requested; the returned value is then used as the
/// exact compare-and-delete expectation.
pub(crate) fn load_local_link(application_id: &str) -> Result<LocalCredentialV2Link> {
    let _guard = SLOT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let entry = slot_name(application_id)?;
    let encoded = store::get(&entry)
        .map_err(|_| UiError::from("PairingCheckpointUnavailable"))?
        .ok_or_else(|| UiError::from("PairingApplicationNotLinked"))?;
    let slot = recognise_slot(&encoded)?;
    let (slot_application_id, relay_origin) = match &slot {
        CredentialV2LinkSlot::Pending(value) => (&value.application_id, &value.relay_origin),
        CredentialV2LinkSlot::Installed(value) => (&value.application_id, &value.relay_origin),
    };
    if slot_application_id != application_id {
        return Err(UiError::from("PairingApplicationNotLinked"));
    }
    let flow = match &slot {
        CredentialV2LinkSlot::Pending(v) => v.flow,
        CredentialV2LinkSlot::Installed(v) => v.flow,
    };
    let exact_pair_state = match flow {
        crate::session::CredentialV2Flow::SingleLink => None,
        crate::session::CredentialV2Flow::LegacyTwoDecision => {
            Some(crate::cbcl_v2_policy::state(application_id, relay_origin)?)
        }
    };
    Ok(LocalCredentialV2Link {
        slot,
        exact_pair_state,
    })
}

/// Read one fully recognised installed record by its authenticated application
/// identifier. Pending, absent, and cross-application values are not aliases
/// for an installed capability.
/// cbcl-bus SPEC-080 REQ-001: the account scope this wallet already holds for
/// one application, or `None` when nothing is installed there. A pending or
/// foreign slot is not an account. This reads the private installed record
/// only; it mints nothing and never exposes the scope beyond the caller.
pub(crate) fn installed_account_scope(application_id: &str) -> Result<Option<[u8; 32]>> {
    let _guard = SLOT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let entry = slot_name(application_id)?;
    let Some(encoded) =
        store::get(&entry).map_err(|_| UiError::from("PairingCheckpointUnavailable"))?
    else {
        return Ok(None);
    };
    match recognise_slot(&encoded)? {
        CredentialV2LinkSlot::Installed(value) if value.application_id == application_id => {
            codec::decode_b64url_32(&value.account_scope_id)
                .map(Some)
                .map_err(|_| UiError::from("PairingCheckpointRefused"))
        }
        CredentialV2LinkSlot::Pending(_) | CredentialV2LinkSlot::Installed(_) => Ok(None),
    }
}

pub(crate) fn load_installed(application_id: &str) -> Result<InstalledCredentialV2Link> {
    let _guard = SLOT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let entry = slot_name(application_id)?;
    let encoded = store::get(&entry)
        .map_err(|_| UiError::from("PairingCheckpointUnavailable"))?
        .ok_or_else(|| UiError::from("PairingApplicationNotLinked"))?;
    match recognise_slot(&encoded)? {
        CredentialV2LinkSlot::Installed(value) if value.application_id == application_id => {
            Ok(value)
        }
        CredentialV2LinkSlot::Pending(_) | CredentialV2LinkSlot::Installed(_) => {
            Err(UiError::from("PairingApplicationNotLinked"))
        }
    }
}

/// Atomically re-pin one exact installed record after a complete live reload
/// verification. The immutable offer profile and hub acknowledgement remain
/// byte-for-byte unchanged in the replacement.
pub(crate) fn replace_installed(
    expected: &InstalledCredentialV2Link,
    replacement: &InstalledCredentialV2Link,
) -> Result<()> {
    let _guard = SLOT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    expected.validate()?;
    replacement.validate()?;
    let mut immutable_projection = replacement.clone();
    immutable_projection.current_profile = expected.current_profile.clone();
    immutable_projection.current_profile_digest = expected.current_profile_digest.clone();
    if immutable_projection != *expected {
        return Err(UiError::from("PairingCheckpointRefused"));
    }
    let entry = slot_name(&expected.application_id)?;
    let encoded = store::get(&entry)
        .map_err(|_| UiError::from("PairingCheckpointUnavailable"))?
        .ok_or_else(|| UiError::from("PairingApplicationNotLinked"))?;
    match recognise_slot(&encoded)? {
        CredentialV2LinkSlot::Installed(current) if current == *expected => {
            let encoded = encode_slot(&CredentialV2LinkSlot::Installed(replacement.clone()))?;
            store::set(&entry, &encoded).map_err(|_| UiError::from("PairingCheckpointUnavailable"))
        }
        CredentialV2LinkSlot::Installed(current) if current == *replacement => Ok(()),
        CredentialV2LinkSlot::Pending(_) | CredentialV2LinkSlot::Installed(_) => {
            Err(UiError::from("PairingCheckpointRefused"))
        }
    }
}

/// Remove one exact pending or installed local application slot and its exact
/// person-selected `(applicationId, relayOrigin)` policy row. The hierarchy
/// root, sibling applications, and all remote hub state remain untouched.
pub(crate) fn unlink_local(expected: &LocalCredentialV2Link) -> Result<()> {
    let _guard = SLOT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (application_id, relay_origin) = match &expected.slot {
        CredentialV2LinkSlot::Pending(value) => {
            value.validate()?;
            (&value.application_id, &value.relay_origin)
        }
        CredentialV2LinkSlot::Installed(value) => {
            value.validate()?;
            (&value.application_id, &value.relay_origin)
        }
    };
    let entry = slot_name(application_id)?;
    let encoded = store::get(&entry)
        .map_err(|_| UiError::from("PairingCheckpointUnavailable"))?
        .ok_or_else(|| UiError::from("PairingApplicationNotLinked"))?;
    if recognise_slot(&encoded)? != expected.slot {
        return Err(UiError::from("PairingApplicationNotLinked"));
    }
    let removed_policy = if let Some(selected) = expected.exact_pair_state {
        let current = crate::cbcl_v2_policy::state(application_id, relay_origin)?;
        if current != selected {
            return Err(UiError::from("PairingCheckpointRefused"));
        }
        current == crate::cbcl_v2_policy::ExactPairState::TrustedPair
    } else {
        false
    };
    if removed_policy {
        crate::cbcl_v2_policy::remove(application_id, relay_origin)?;
    }
    if store::delete(&entry).is_err() {
        if removed_policy {
            let _ = crate::cbcl_v2_policy::insert(application_id, relay_origin);
        }
        return Err(UiError::from("PairingCheckpointUnavailable"));
    }
    let mut index = load_index_locked()?;
    index
        .applications
        .retain(|candidate| candidate != application_id);
    persist_index_locked(&index)
}

/// Remove one exact verified terminal-negative pending value.
///
/// A changed, installed, absent, or cross-application slot refuses. Deleting
/// the slot before its public index row means a storage failure can leave only
/// a harmless stale row, never a discoverability-losing live credential.
pub fn remove_pending(expected: &PendingCredentialV2Completion) -> Result<()> {
    let _guard = SLOT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    expected.validate()?;
    let entry = slot_name(&expected.application_id)?;
    let encoded = store::get(&entry)
        .map_err(|_| UiError::from("PairingCheckpointUnavailable"))?
        .ok_or_else(|| UiError::from("PairingCheckpointRefused"))?;
    match recognise_slot(&encoded)? {
        CredentialV2LinkSlot::Pending(current) if current == *expected => {}
        CredentialV2LinkSlot::Pending(_) | CredentialV2LinkSlot::Installed(_) => {
            return Err(UiError::from("PairingCheckpointRefused"));
        }
    }
    store::delete(&entry).map_err(|_| UiError::from("PairingCheckpointUnavailable"))?;
    let mut index = load_index_locked()?;
    index
        .applications
        .retain(|application_id| application_id != &expected.application_id);
    persist_index_locked(&index)
}

/// Best-effort compensation for a final-approved attempt that has not reached
/// the recoverable payload boundary. The stored phase may be newer than the
/// guard's copy when a backend commits a replacement but reports an error, so
/// removal compares the immutable ceremony identity and then deletes the exact
/// current recognised value. A durable `PayloadPrepared` value is retained.
fn remove_pre_payload_attempt(anchor: &PendingCredentialV2Completion) -> Result<()> {
    let _guard = SLOT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    anchor.validate()?;
    let entry = slot_name(&anchor.application_id)?;
    let Some(encoded) =
        store::get(&entry).map_err(|_| UiError::from("PairingCheckpointUnavailable"))?
    else {
        return Ok(());
    };
    let CredentialV2LinkSlot::Pending(current) = recognise_slot(&encoded)? else {
        return Err(UiError::from("PairingCheckpointRefused"));
    };
    current.validate()?;
    let same_attempt = current.flow == anchor.flow
        && current.root_generation == anchor.root_generation
        && current.application_id == anchor.application_id
        && current.relay_origin == anchor.relay_origin
        && current.profile_digest == anchor.profile_digest
        && current.offer_profile == anchor.offer_profile
        && current.carrier == anchor.carrier
        && current.offer == anchor.offer
        && current.intent_approve == anchor.intent_approve
        && current.comparison == anchor.comparison
        && current.final_approve == anchor.final_approve
        && current.preview_issuer_did == anchor.preview_issuer_did
        && current.offer_expires_at == anchor.offer_expires_at;
    if !same_attempt {
        return Err(UiError::from("PairingCheckpointRefused"));
    }
    if current.is_payload_prepared() {
        return Ok(());
    }
    store::delete(&entry).map_err(|_| UiError::from("PairingCheckpointUnavailable"))?;
    let mut index = load_index_locked()?;
    index
        .applications
        .retain(|application_id| application_id != &anchor.application_id);
    persist_index_locked(&index)
}

/// Remove every credential/v2 pending or installed slot during root purge.
pub fn purge_all_links() -> Result<()> {
    let _guard = SLOT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let index = load_index_locked()?;
    for application_id in &index.applications {
        store::delete(&slot_name(application_id)?)
            .map_err(|_| UiError::from("PairingCheckpointUnavailable"))?;
    }
    store::delete(LINK_INDEX_ENTRY).map_err(|_| UiError::from("PairingCheckpointUnavailable"))
}

/// Replace one exact pending value with its next crash-safe phase. A stale,
/// installed, or cross-application predecessor cannot advance the slot.
pub fn replace_pending(
    expected: &PendingCredentialV2Completion,
    replacement: &PendingCredentialV2Completion,
) -> Result<()> {
    let _guard = SLOT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    expected.validate()?;
    replacement.validate()?;
    if expected.application_id != replacement.application_id
        || expected.root_generation != replacement.root_generation
        || expected.offer_profile != replacement.offer_profile
        || expected.carrier != replacement.carrier
        || expected.offer != replacement.offer
        || expected.intent_approve != replacement.intent_approve
        || expected.comparison != replacement.comparison
        || expected.final_approve != replacement.final_approve
        || expected.preview_issuer_did != replacement.preview_issuer_did
    {
        return Err(UiError::from("PairingCheckpointRefused"));
    }
    let entry = slot_name(&expected.application_id)?;
    let existing = store::get(&entry)
        .map_err(|_| UiError::from("PairingCheckpointUnavailable"))?
        .ok_or_else(|| UiError::from("PairingCheckpointRefused"))?;
    match recognise_slot(&existing)? {
        CredentialV2LinkSlot::Pending(current) if current == *expected => {
            let encoded = encode_slot(&CredentialV2LinkSlot::Pending(replacement.clone()))?;
            store::set(&entry, &encoded).map_err(|_| UiError::from("PairingCheckpointUnavailable"))
        }
        CredentialV2LinkSlot::Pending(_) | CredentialV2LinkSlot::Installed(_) => {
            Err(UiError::from("PairingCheckpointRefused"))
        }
    }
}

/// Load and fully recognise the exact pending application slot.
pub fn load_pending(application_id: &str) -> Result<PendingCredentialV2Completion> {
    let _guard = SLOT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let entry = slot_name(application_id)?;
    let encoded = store::get(&entry)
        .map_err(|_| UiError::from("PairingCheckpointUnavailable"))?
        .ok_or_else(|| UiError::from("PairingCheckpointRefused"))?;
    match recognise_slot(&encoded)? {
        CredentialV2LinkSlot::Pending(pending) if pending.application_id == application_id => {
            Ok(pending)
        }
        CredentialV2LinkSlot::Pending(_) | CredentialV2LinkSlot::Installed(_) => {
            Err(UiError::from("PairingCheckpointRefused"))
        }
    }
}

/// Atomically replace the exact pending record with an installed link after a
/// freshly fetched reciprocal WebFinger assertion has been verified.
pub fn install(
    expected: &PendingCredentialV2Completion,
    installed: &InstalledCredentialV2Link,
    jrd: &selfsame_app_identity::alias::Jrd,
) -> Result<()> {
    let _guard = SLOT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    expected.validate()?;
    installed.validate()?;
    if expected.application_id != installed.application_id
        || expected.root_generation != installed.root_generation
        || expected.profile_digest != installed.profile_digest
    {
        return Err(UiError::from("PairingReceiptRefused"));
    }
    let account = installed.account()?;
    selfsame_app_identity::alias::verify_reciprocal_binding(
        jrd,
        &account,
        installed.issuer_did(),
        &[account.as_str().to_owned()],
    )
    .map_err(|_| UiError::from("PairingAuthorityRefused"))?;
    let entry = slot_name(&expected.application_id)?;
    let encoded = store::get(&entry)
        .map_err(|_| UiError::from("PairingCheckpointUnavailable"))?
        .ok_or_else(|| UiError::from("PairingCheckpointRefused"))?;
    match recognise_slot(&encoded)? {
        CredentialV2LinkSlot::Pending(current) if current == *expected => {
            let encoded = encode_slot(&CredentialV2LinkSlot::Installed(installed.clone()))?;
            store::set(&entry, &encoded).map_err(|_| UiError::from("PairingCheckpointUnavailable"))
        }
        CredentialV2LinkSlot::Installed(current) if current == *installed => Ok(()),
        CredentialV2LinkSlot::Pending(_) | CredentialV2LinkSlot::Installed(_) => {
            Err(UiError::from("PairingCheckpointRefused"))
        }
    }
}

fn encode_slot(slot: &CredentialV2LinkSlot) -> Result<String> {
    let encoded =
        serde_json::to_string(slot).map_err(|_| UiError::from("PairingCheckpointRefused"))?;
    if encoded.len() > MAX_SLOT_OCTETS {
        return Err(UiError::from("PairingCheckpointRefused"));
    }
    Ok(encoded)
}

fn recognise_slot(encoded: &str) -> Result<CredentialV2LinkSlot> {
    if encoded.is_empty() || encoded.len() > MAX_SLOT_OCTETS {
        return Err(UiError::from("PairingCheckpointRefused"));
    }
    let slot: CredentialV2LinkSlot =
        serde_json::from_str(encoded).map_err(|_| UiError::from("PairingCheckpointRefused"))?;
    if encode_slot(&slot)? != encoded {
        return Err(UiError::from("PairingCheckpointRefused"));
    }
    match &slot {
        CredentialV2LinkSlot::Pending(value) => value.validate()?,
        CredentialV2LinkSlot::Installed(value) => value.validate()?,
    }
    Ok(slot)
}

fn empty_index() -> CredentialV2LinkIndex {
    CredentialV2LinkIndex {
        version: LINK_INDEX_VERSION,
        applications: Vec::new(),
    }
}

fn load_index_locked() -> Result<CredentialV2LinkIndex> {
    let Some(encoded) =
        store::get(LINK_INDEX_ENTRY).map_err(|_| UiError::from("PairingCheckpointUnavailable"))?
    else {
        return Ok(empty_index());
    };
    recognise_index(&encoded)
}

fn ensure_indexed_locked(application_id: &str) -> Result<()> {
    ApplicationId::parse(application_id).map_err(|_| UiError::from("PairingCheckpointRefused"))?;
    let mut index = load_index_locked()?;
    match index
        .applications
        .binary_search_by(|candidate| candidate.as_str().cmp(application_id))
    {
        Ok(_) => Ok(()),
        Err(position) => {
            if index.applications.len() >= MAX_LINKS {
                return Err(UiError::from("PairingCheckpointUnavailable"));
            }
            index.applications.insert(position, application_id.into());
            persist_index_locked(&index)
        }
    }
}

fn persist_index_locked(index: &CredentialV2LinkIndex) -> Result<()> {
    let encoded = encode_index(index)?;
    if index.applications.is_empty() {
        store::delete(LINK_INDEX_ENTRY).map_err(|_| UiError::from("PairingCheckpointUnavailable"))
    } else {
        store::set(LINK_INDEX_ENTRY, &encoded)
            .map_err(|_| UiError::from("PairingCheckpointUnavailable"))
    }
}

fn encode_index(index: &CredentialV2LinkIndex) -> Result<String> {
    validate_index(index)?;
    let encoded =
        serde_json::to_string(index).map_err(|_| UiError::from("PairingCheckpointRefused"))?;
    if encoded.is_empty() || encoded.len() > MAX_LINK_INDEX_OCTETS {
        return Err(UiError::from("PairingCheckpointRefused"));
    }
    Ok(encoded)
}

fn recognise_index(encoded: &str) -> Result<CredentialV2LinkIndex> {
    if encoded.is_empty() || encoded.len() > MAX_LINK_INDEX_OCTETS {
        return Err(UiError::from("PairingCheckpointRefused"));
    }
    let index: CredentialV2LinkIndex =
        serde_json::from_str(encoded).map_err(|_| UiError::from("PairingCheckpointRefused"))?;
    if encode_index(&index)? != encoded {
        return Err(UiError::from("PairingCheckpointRefused"));
    }
    Ok(index)
}

fn validate_index(index: &CredentialV2LinkIndex) -> Result<()> {
    if index.version != LINK_INDEX_VERSION || index.applications.len() > MAX_LINKS {
        return Err(UiError::from("PairingCheckpointRefused"));
    }
    let mut previous: Option<&str> = None;
    for application_id in &index.applications {
        let parsed = ApplicationId::parse(application_id)
            .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        if parsed.as_str() != application_id
            || previous.is_some_and(|candidate| candidate >= application_id.as_str())
        {
            return Err(UiError::from("PairingCheckpointRefused"));
        }
        previous = Some(application_id);
    }
    Ok(())
}

fn slot_name(application_id: &str) -> Result<String> {
    ApplicationId::parse(application_id).map_err(|_| UiError::from("PairingCheckpointRefused"))?;
    Ok(format!(
        "{SLOT_PREFIX}{}",
        codec::b64url(&Sha256::digest(application_id.as_bytes()))
    ))
}

fn validate_application_and_relay(application_id: &str, relay_origin: &str) -> Result<()> {
    ApplicationId::parse(application_id).map_err(|_| UiError::from("PairingCheckpointRefused"))?;
    let relay = uri::recognise(relay_origin, UriPolicy::ORIGIN)
        .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
    if relay.origin != relay_origin {
        return Err(UiError::from("PairingCheckpointRefused"));
    }
    Ok(())
}

fn decode_bounded(value: &str, maximum: usize) -> Result<Vec<u8>> {
    if value.len() > codec::b64url_len(maximum) {
        return Err(UiError::from("PairingCheckpointRefused"));
    }
    let expected = value.len().saturating_mul(3) / 4;
    for length in expected.saturating_sub(2)..=expected.saturating_add(2).min(maximum) {
        if let Ok(decoded) = codec::decode_b64url_exact(value, length) {
            return Ok(decoded);
        }
    }
    Err(UiError::from("PairingCheckpointRefused"))
}

fn decoded_object(value: &str, kind: CredentialV2Kind) -> Result<CredentialV2Object> {
    let bytes = decode_bounded(value, 70_000)?;
    let object = decode_object(&bytes).map_err(checkpoint_error)?;
    if object.kind() != kind {
        return Err(UiError::from("PairingCheckpointRefused"));
    }
    Ok(object)
}

fn decoded_object_either(
    value: &str,
    first: CredentialV2Kind,
    second: CredentialV2Kind,
) -> Result<CredentialV2Object> {
    let bytes = decode_bounded(value, 70_000)?;
    let object = decode_object(&bytes).map_err(checkpoint_error)?;
    if object.kind() != first && object.kind() != second {
        return Err(UiError::from("PairingCheckpointRefused"));
    }
    Ok(object)
}

fn checkpoint_error(_: cbcl_pairing::credential_v2::CredentialV2Error) -> UiError {
    UiError::from("PairingCheckpointRefused")
}

#[cfg(test)]
#[path = "test_memkeyring.rs"]
pub(crate) mod shared_memkeyring;

#[cfg(test)]
mod tests {
    use super::*;
    use cbcl_pairing::credential_v2::CredentialV2CarrierInput;
    use ed25519_dalek::SigningKey;
    use selfsame_app_identity::json::{self, Json};

    const RELOAD_APPLICATION: &str = "https://photos.example/selfsame/application";
    const RELOAD_PERMISSION: &str = "https://photos.example/selfsame/application#device";

    fn reload_jwk(public_key: [u8; 32]) -> Json {
        Json::obj([
            ("kty", Json::text("OKP")),
            ("crv", Json::text("Ed25519")),
            ("x", Json::text(codec::b64url(&public_key))),
        ])
    }

    fn reload_profile(signing_key: &SigningKey, relay_digest_byte: u8) -> Vec<u8> {
        json::canonicalise(&Json::obj([
            ("profileVersion", Json::int(1)),
            ("applicationId", Json::text(RELOAD_APPLICATION)),
            ("accountAuthority", Json::text("accounts.photos.example")),
            ("verifierAudience", Json::text(RELOAD_APPLICATION)),
            (
                "allowedPermissions",
                Json::arr([Json::text(RELOAD_PERMISSION)]),
            ),
            (
                "enrollment",
                Json::obj([
                    (
                        "requestSigningKeys",
                        Json::arr([Json::obj([
                            (
                                "kid",
                                Json::text(
                                    "https://photos.example/selfsame/application#installed-test",
                                ),
                            ),
                            (
                                "publicKeyJwk",
                                reload_jwk(signing_key.verifying_key().to_bytes()),
                            ),
                        ])]),
                    ),
                    (
                        "mobileBindings",
                        Json::arr([Json::obj([
                            ("id", Json::text("web:https://photos.example")),
                            ("platform", Json::text("web")),
                            ("origin", Json::text("https://photos.example")),
                        ])]),
                    ),
                ]),
            ),
            (
                "cbclPairingRelays",
                Json::arr([Json::obj([
                    ("operatorId", Json::text("installed-test")),
                    ("relayOrigin", Json::text("https://photos.example:9443")),
                    ("priority", Json::int(1)),
                    ("weight", Json::int(1)),
                    (
                        "privacyPolicyDigest",
                        Json::text(codec::b64url(&[relay_digest_byte; 32])),
                    ),
                    (
                        "conformanceEvidenceDigest",
                        Json::text(codec::b64url(&[relay_digest_byte + 16; 32])),
                    ),
                ])]),
            ),
            (
                "stateResolvers",
                Json::arr([Json::obj([
                    ("id", Json::text("state-1")),
                    ("url", Json::text("https://state.photos.example")),
                    ("protocol", Json::text("did-crdt-service-v1")),
                ])]),
            ),
            (
                "revocation",
                Json::obj([
                    ("method", Json::text("did-crdt-revocations-v1")),
                    ("maxGrantLifetimeSeconds", Json::int(2_592_000)),
                    ("maxClosureAgeSeconds", Json::int(900)),
                    ("propagationSlaSeconds", Json::int(60)),
                ]),
            ),
        ]))
    }

    fn installed_reload_fixture() -> InstalledCredentialV2Link {
        let signing_key = SigningKey::from_bytes(&[0x31; 32]);
        let profile_octets = reload_profile(&signing_key, 1);
        let profile =
            selfsame_app_identity::profile::ApplicationProfile::recognise(&profile_octets).unwrap();
        let root = HierarchyRoot::from_octets([0x32; 64]);
        let scope = AccountScopeId::from_octets([0x33; 32]);
        let home = selfsame_app_identity::hierarchy::derive(&root, &profile.application_id, &scope);
        let issuer_did = home.home_did().unwrap();
        let device_key = SigningKey::from_bytes(&[0x34; 32])
            .verifying_key()
            .to_bytes();
        let plan = CredentialV2ProvisioningPlan {
            application: profile.application_id.clone(),
            account_authority: profile.account_authority.clone(),
            scope,
            device_did: didkey::encode(&device_key),
            device_public_key: device_key,
            permissions: vec![RELOAD_PERMISSION.into()],
            preview_issuer_did: issuer_did.clone(),
        };
        let issuer = build_issuer_artifacts(&root, &plan, 1_800_000_000).unwrap();
        let grant_id = [0x35; 32];
        let grant =
            build_grant_artifacts(&root, &plan, &issuer, grant_id, 1_800_000_000, 86_400).unwrap();
        let compact =
            selfsame_app_identity::jws::recognise(&grant.grant, grant::GRANT_JWS, &[]).unwrap();
        let recognised_grant = grant::recognise(&compact.payload).unwrap();
        let carrier_ceremony_id = [0x36; 32];
        let request_id = [0x37; 32];
        let account_principal_digest = [0x38; 32];
        let offer_core_digest = [0x39; 32];
        let payload_digest = [0x3a; 32];
        let recovery_commitment = [0x3b; 32];
        let finalized_at = 1_800_000_100;
        let kid = "https://photos.example/selfsame/application#installed-test";
        let final_status_input = selfsame_pairing::credential_v2::CredentialV2FinalStatusInput {
            application_id: profile.application_id.as_str().into(),
            carrier_ceremony_id,
            request_id,
            account_principal_digest,
            account_scope_id: *plan.scope.octets(),
            device_did: plan.device_did.clone(),
            offer_core_digest,
            payload_digest,
            grant_id,
            issuer_did: issuer_did.clone(),
            receipt_recovery_commitment: recovery_commitment,
            finalized_at,
        };
        let final_status = selfsame_pairing::credential_v2::build_final_status(
            &profile,
            &final_status_input,
            kid,
            &signing_key,
        )
        .unwrap();
        let account =
            selfsame_app_identity::alias::stable_acct_uri(&issuer_did, &profile.account_authority);
        let installed = InstalledCredentialV2Link {
            version: SLOT_VERSION,
            flow: crate::session::CredentialV2Flow::LegacyTwoDecision,
            root_generation: codec::b64url(&root_generation(&[0x42; 32])),
            relay_origin: "https://photos.example:9443".into(),
            profile: codec::b64url(&profile_octets),
            current_profile: codec::b64url(&profile_octets),
            grant_digest: codec::b64url(&Sha256::digest(grant.grant.as_bytes())),
            grant: grant.grant,
            grant_id: codec::b64url(&grant_id),
            credential_id: recognised_grant.id,
            application_id: profile.application_id.as_str().into(),
            account_principal_digest: codec::b64url(&account_principal_digest),
            account_scope_id: codec::b64url(plan.scope.octets()),
            account,
            installation_device_did: plan.device_did,
            profile_digest: codec::b64url(profile.digest()),
            current_profile_digest: codec::b64url(profile.digest()),
            account_authority: profile.account_authority,
            issuer_did,
            resolver_closure: codec::b64url(&issuer.resolver_closure),
            offer_core_digest: codec::b64url(&offer_core_digest),
            offer_kid: kid.into(),
            carrier_ceremony_id: codec::b64url(&carrier_ceremony_id),
            request_id: codec::b64url(&request_id),
            payload_digest: codec::b64url(&payload_digest),
            receipt_recovery_commitment: codec::b64url(&recovery_commitment),
            final_status_jws: final_status.jws,
            final_status_digest: codec::b64url(&final_status.digest),
            finalized_at,
        };
        installed.validate().unwrap();
        installed
    }

    fn pending_abandonment_fixture() -> PendingCredentialV2Completion {
        let signing_key = SigningKey::from_bytes(&[0x31; 32]);
        let profile_octets = reload_profile(&signing_key, 1);
        let profile =
            selfsame_app_identity::profile::ApplicationProfile::recognise(&profile_octets).unwrap();
        let carrier = CredentialV2Carrier::new(CredentialV2CarrierInput {
            application_context: profile.application_id.as_str().into(),
            relay_origin: "https://photos.example:9443".into(),
            mailbox_id: [0x81; 32],
            carrier_ceremony_id: [0x82; 32],
            carrier_nonce: [0x83; 32],
            claim_commitment: [0x84; 32],
            relay_expires_at: 1_900_000_000,
            expected_allocator_key: Some(
                SigningKey::from_bytes(&[0x85; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
        })
        .unwrap();
        let intent_digest = [0x86; 32];
        let object = |kind| CredentialV2Object::new(kind, intent_digest, vec![0xa0]).unwrap();
        let pending = PendingCredentialV2Completion {
            version: SLOT_VERSION,
            flow: crate::session::CredentialV2Flow::LegacyTwoDecision,
            root_generation: codec::b64url(&root_generation(&[0x87; 32])),
            application_id: profile.application_id.as_str().into(),
            relay_origin: carrier.relay_origin().into(),
            profile_digest: codec::b64url(profile.digest()),
            offer_profile: codec::b64url(&profile_octets),
            carrier: codec::b64url(&encode_carrier(&carrier).unwrap()),
            offer: codec::b64url(object(CredentialV2Kind::Offer).as_bytes()),
            intent_approve: codec::b64url(object(CredentialV2Kind::IntentApprove).as_bytes()),
            comparison: codec::b64url(object(CredentialV2Kind::ComparisonConfirmed).as_bytes()),
            final_approve: codec::b64url(object(CredentialV2Kind::FinalApprove).as_bytes()),
            preview_issuer_did: installed_reload_fixture().issuer_did,
            offer_expires_at: 1_900_000_000,
            checkpoint_generation: 1,
            endpoint_checkpoint: codec::b64url(b"sealed-test-checkpoint"),
            stage: PendingCredentialV2Stage::FinalApproval,
        };
        pending.validate().unwrap();
        pending
    }

    /// cbcl-bus SPEC-080 REQ-001: the selection reads only an installed slot
    /// of the same application; an absent slot is a new account.
    #[test]
    fn spec_080_installed_account_scope_reads_only_an_installed_slot() {
        assert_eq!(
            installed_account_scope("https://nothing.example/selfsame/application").unwrap(),
            None
        );
        let installed = installed_reload_fixture();
        let application = installed.application_id().to_string();
        overwrite_test_slot(&CredentialV2LinkSlot::Installed(installed.clone()));
        let expected = codec::decode_b64url_32(&installed.account_scope_id).unwrap();
        assert_eq!(installed_account_scope(&application).unwrap(), Some(expected));
        assert_eq!(
            installed_account_scope("https://other.example/selfsame/application").unwrap(),
            None
        );
        let local = load_local_link(&application).unwrap();
        unlink_local(&local).unwrap();
        assert_eq!(installed_account_scope(&application).unwrap(), None);
    }

    fn overwrite_test_slot(slot: &CredentialV2LinkSlot) {
        let application_id = match slot {
            CredentialV2LinkSlot::Pending(value) => &value.application_id,
            CredentialV2LinkSlot::Installed(value) => &value.application_id,
        };
        store::set(
            &slot_name(application_id).unwrap(),
            &encode_slot(slot).unwrap(),
        )
        .unwrap();
    }

    fn pending_stage_fixtures(
        final_approval: &PendingCredentialV2Completion,
    ) -> (
        PendingCredentialV2Completion,
        PendingCredentialV2Completion,
        PendingCredentialV2Completion,
        PendingCredentialV2Completion,
    ) {
        let installed = installed_reload_fixture();
        let mut acknowledged = final_approval.clone();
        acknowledged.checkpoint_generation += 1;
        acknowledged.endpoint_checkpoint = codec::b64url(b"sealed-acknowledged-checkpoint");
        acknowledged.validate().unwrap();

        let planned = acknowledged.planned(1_800_000_000, [0x35; 32]).unwrap();
        let mut issuer_created = planned.clone();
        issuer_created.stage = PendingCredentialV2Stage::IssuerCreated {
            effect_time: 1_800_000_000,
            grant_id: installed.grant_id.clone(),
            issuer_did: installed.issuer_did.clone(),
            resolver_closure: installed.resolver_closure.clone(),
        };
        issuer_created.validate().unwrap();

        let mut provisioned = issuer_created.clone();
        provisioned.stage = PendingCredentialV2Stage::Provisioned {
            effect_time: 1_800_000_000,
            grant_id: installed.grant_id,
            issuer_did: installed.issuer_did,
            grant: installed.grant,
            resolver_closure: installed.resolver_closure,
        };
        provisioned.validate().unwrap();
        (acknowledged, planned, issuer_created, provisioned)
    }

    struct InjectAt(PrePayloadBoundary);

    impl PrePayloadFaultSink for InjectAt {
        fn before(&mut self, boundary: PrePayloadBoundary) -> Result<()> {
            if boundary == self.0 {
                Err(UiError::from("InjectedPrePayloadFailure"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    #[ignore = "installs the process-global in-memory keyring; run alone"]
    fn single_link_transaction_faults_ambiguous_payload_and_policy_free_unlink() {
        use crate::session::CredentialV2Flow::SingleLink;
        shared_memkeyring::install();
        let pending = pending_abandonment_fixture().with_flow(SingleLink);
        let (acknowledged, planned, issuer, provisioned) = pending_stage_fixtures(&pending);
        let baseline_policy = shared_memkeyring::policy_operations();
        let baseline_identity = identity_effect_count();
        for boundary in [
            PrePayloadBoundary::FinalApprovalRelease,
            PrePayloadBoundary::AcknowledgementRead,
            PrePayloadBoundary::AcknowledgementRecognition,
            PrePayloadBoundary::AcknowledgementCheckpointReplacement,
            PrePayloadBoundary::AcknowledgementCheckpointCommit,
            PrePayloadBoundary::PlanConstruction,
            PrePayloadBoundary::PlannedStageReplacement,
            PrePayloadBoundary::IssuerCustody,
            PrePayloadBoundary::IssuerStageReplacement,
            PrePayloadBoundary::IssuerPublication,
            PrePayloadBoundary::ResolverVerification,
            PrePayloadBoundary::GrantConstruction,
            PrePayloadBoundary::ProvisionedStageReplacement,
            PrePayloadBoundary::PayloadConstruction,
            PrePayloadBoundary::PayloadCheckpointPreparation,
        ] {
            let mut transaction = PrePayloadPendingTransaction::begin(pending.clone()).unwrap();
            let error = transaction
                .try_step(&mut InjectAt(boundary), boundary, || Ok(()))
                .unwrap_err();
            assert_eq!(error.to_string(), "InjectedPrePayloadFailure");
            drop(transaction);
            assert!(pending_links().unwrap().is_empty(), "{boundary:?}");
        }
        let prepared = provisioned.payload_prepared([0x3a; 32]).unwrap();
        for after in [false, true] {
            let mut transaction = PrePayloadPendingTransaction::begin(pending.clone()).unwrap();
            for replacement in [&acknowledged, &planned, &issuer, &provisioned] {
                transaction
                    .replace_at(
                        &mut NoPrePayloadFaults,
                        PrePayloadBoundary::PlannedStageReplacement,
                        replacement.clone(),
                    )
                    .unwrap();
            }
            shared_memkeyring::fail_next_set_for_user(
                &slot_name(pending.application_id()).unwrap(),
                if after {
                    shared_memkeyring::SetFailure::AfterCommit
                } else {
                    shared_memkeyring::SetFailure::BeforeCommit
                },
            );
            assert!(transaction.commit_payload(prepared.clone()).is_err());
            if after {
                assert_eq!(load_pending(pending.application_id()).unwrap(), prepared);
                assert_eq!(identity_effect_count(), baseline_identity);
                let selected = load_local_link(pending.application_id()).unwrap();
                assert!(selected.exact_pair_state.is_none());
                unlink_local(&selected).unwrap();
            }
            assert!(pending_links().unwrap().is_empty());
        }
        assert_eq!(shared_memkeyring::policy_operations(), baseline_policy);
        // An independently existing legacy row is untouched even by SingleLink unlink.
        crate::cbcl_v2_policy::insert(pending.application_id(), &pending.relay_origin).unwrap();
        let existing_policy = shared_memkeyring::policy_operations();
        let mut installed = installed_reload_fixture();
        installed.flow = SingleLink;
        overwrite_test_slot(&CredentialV2LinkSlot::Installed(installed.clone()));
        let selected = load_local_link(installed.application_id()).unwrap();
        assert!(selected.exact_pair_state.is_none());
        unlink_local(&selected).unwrap();
        assert_eq!(shared_memkeyring::policy_operations(), existing_policy);
        assert_eq!(
            crate::cbcl_v2_policy::state(pending.application_id(), &pending.relay_origin).unwrap(),
            crate::cbcl_v2_policy::ExactPairState::TrustedPair
        );
        shared_memkeyring::clear();
    }

    #[test]
    #[ignore = "installs the process-global in-memory keyring; run this test alone"]
    fn test_1162_pre_payload_failure_and_person_abandonment_release_the_exact_slot() {
        shared_memkeyring::install();
        let pending = pending_abandonment_fixture();
        crate::cbcl_v2_policy::insert(pending.application_id(), &pending.relay_origin).unwrap();

        let (acknowledged, planned, issuer_created, provisioned) = pending_stage_fixtures(&pending);
        let failure_matrix = [
            (PrePayloadBoundary::FinalApprovalRelease, pending.clone()),
            (PrePayloadBoundary::AcknowledgementRead, pending.clone()),
            (
                PrePayloadBoundary::AcknowledgementRecognition,
                pending.clone(),
            ),
            (
                PrePayloadBoundary::AcknowledgementCheckpointReplacement,
                acknowledged.clone(),
            ),
            (
                PrePayloadBoundary::AcknowledgementCheckpointCommit,
                acknowledged.clone(),
            ),
            (PrePayloadBoundary::PlanConstruction, acknowledged.clone()),
            (PrePayloadBoundary::PlannedStageReplacement, planned.clone()),
            (PrePayloadBoundary::IssuerCustody, planned.clone()),
            (
                PrePayloadBoundary::IssuerStageReplacement,
                issuer_created.clone(),
            ),
            (
                PrePayloadBoundary::IssuerPublication,
                issuer_created.clone(),
            ),
            (
                PrePayloadBoundary::ResolverVerification,
                issuer_created.clone(),
            ),
            (
                PrePayloadBoundary::GrantConstruction,
                issuer_created.clone(),
            ),
            (
                PrePayloadBoundary::ProvisionedStageReplacement,
                provisioned.clone(),
            ),
            (PrePayloadBoundary::PayloadConstruction, provisioned.clone()),
            (
                PrePayloadBoundary::PayloadCheckpointPreparation,
                provisioned.clone(),
            ),
        ];

        // The exact injectable hooks occur once each, in causal order, inside
        // the production final-decision function this test targets.
        let production = include_str!("cbcl_v2_commands.rs");
        let function = production
            .split_once("async fn cbcl_v2_final_decide_with_faults")
            .unwrap()
            .1
            .split_once("pub async fn cbcl_v2_finish")
            .unwrap()
            .0;
        let mut remainder = function;
        for (boundary, _) in &failure_matrix {
            let marker = format!("PrePayloadBoundary::{boundary:?}");
            assert_eq!(
                function.matches(&marker).count(),
                1,
                "production boundary hook must occur exactly once: {marker}"
            );
            let (_, after) = remainder.split_once(&marker).unwrap_or_else(|| {
                panic!("production boundary hook is absent or out of order: {marker}")
            });
            remainder = after;
        }

        for (boundary, stored) in failure_matrix {
            let mut transaction = PrePayloadPendingTransaction::begin(pending.clone()).unwrap();
            overwrite_test_slot(&CredentialV2LinkSlot::Pending(stored));
            let error = transaction
                .try_step(&mut InjectAt(boundary), boundary, || Ok(()))
                .unwrap_err();
            assert_eq!(error.to_string(), "InjectedPrePayloadFailure");
            drop(transaction);
            assert!(
                pending_links().unwrap().is_empty(),
                "{boundary:?} stranded the application slot"
            );
            // Every failure boundary releases the exact application for a new
            // ceremony rather than merely hiding its pending row.
            persist_pending(&pending).unwrap();
            remove_pending(&pending).unwrap();
        }

        let slot_user = slot_name(pending.application_id()).unwrap();

        // Arming is part of begin, before the first store call. A backend that
        // commits the initial slot and then reports failure is compensated.
        shared_memkeyring::fail_next_set_for_user(
            &slot_user,
            shared_memkeyring::SetFailure::AfterCommit,
        );
        let error = PrePayloadPendingTransaction::begin(pending.clone())
            .err()
            .expect("post-commit failure must escape begin");
        assert_eq!(error.to_string(), "PairingCheckpointUnavailable");
        assert!(pending_links().unwrap().is_empty());

        let start_provisioned_transaction = || {
            let mut transaction = PrePayloadPendingTransaction::begin(pending.clone()).unwrap();
            let mut no_faults = NoPrePayloadFaults;
            for (boundary, replacement) in [
                (
                    PrePayloadBoundary::AcknowledgementCheckpointReplacement,
                    acknowledged.clone(),
                ),
                (PrePayloadBoundary::PlannedStageReplacement, planned.clone()),
                (
                    PrePayloadBoundary::IssuerStageReplacement,
                    issuer_created.clone(),
                ),
                (
                    PrePayloadBoundary::ProvisionedStageReplacement,
                    provisioned.clone(),
                ),
            ] {
                transaction
                    .replace_at(&mut no_faults, boundary, replacement)
                    .unwrap();
            }
            transaction
        };

        // commit_payload owns both the final replacement and disarm. If the
        // durable write fails before commit, the still-armed transaction
        // removes Provisioned and preserves the storage error.
        let payload_prepared = provisioned.payload_prepared([0x3a; 32]).unwrap();
        let transaction = start_provisioned_transaction();
        shared_memkeyring::fail_next_set_for_user(
            &slot_user,
            shared_memkeyring::SetFailure::BeforeCommit,
        );
        let error = transaction
            .commit_payload(payload_prepared.clone())
            .unwrap_err();
        assert_eq!(error.to_string(), "PairingCheckpointUnavailable");
        assert!(pending_links().unwrap().is_empty());

        // If the backend commits PayloadPrepared and only then reports an
        // error, cleanup recognises the recovery-owned phase and retains it.
        let transaction = start_provisioned_transaction();
        shared_memkeyring::fail_next_set_for_user(
            &slot_user,
            shared_memkeyring::SetFailure::AfterCommit,
        );
        let error = transaction
            .commit_payload(payload_prepared.clone())
            .unwrap_err();
        assert_eq!(error.to_string(), "PairingCheckpointUnavailable");
        assert_eq!(
            load_pending(pending.application_id()).unwrap(),
            payload_prepared
        );
        remove_pending(&payload_prepared).unwrap();

        // A committed PayloadPrepared value belongs to signed final-status
        // recovery and must survive any later guard cleanup.
        let transaction = PrePayloadPendingTransaction::begin(pending.clone()).unwrap();
        {
            overwrite_test_slot(&CredentialV2LinkSlot::Pending(payload_prepared.clone()));
        }
        drop(transaction);
        assert_eq!(
            load_pending(pending.application_id()).unwrap(),
            payload_prepared
        );
        remove_pending(&payload_prepared).unwrap();

        // Compensation anchored on attempt A must not remove a recognised
        // attempt B that acquired the same application slot.
        let mut other_attempt = pending.clone();
        other_attempt.offer_expires_at += 1;
        other_attempt.validate().unwrap();
        let transaction = PrePayloadPendingTransaction::begin(pending.clone()).unwrap();
        {
            overwrite_test_slot(&CredentialV2LinkSlot::Pending(other_attempt.clone()));
        }
        drop(transaction);
        assert_eq!(
            load_pending(pending.application_id()).unwrap(),
            other_attempt
        );
        remove_pending(&other_attempt).unwrap();

        // Root replacement is an attempt-identity change in its own right;
        // compensation for the old root must retain the new root's slot.
        let mut other_root = pending.clone();
        other_root.root_generation = codec::b64url(&root_generation(&[0x89; 32]));
        other_root.validate().unwrap();
        let transaction = PrePayloadPendingTransaction::begin(pending.clone()).unwrap();
        {
            overwrite_test_slot(&CredentialV2LinkSlot::Pending(other_root.clone()));
        }
        drop(transaction);
        assert_eq!(load_pending(pending.application_id()).unwrap(), other_root);
        remove_pending(&other_root).unwrap();

        // A stale pre-payload guard must never delete a subsequently installed
        // capability for the application.
        let installed = installed_reload_fixture();
        let transaction = PrePayloadPendingTransaction::begin(pending.clone()).unwrap();
        {
            overwrite_test_slot(&CredentialV2LinkSlot::Installed(installed.clone()));
        }
        drop(transaction);
        assert_eq!(load_installed(pending.application_id()).unwrap(), installed);
        let installed_local = load_local_link(pending.application_id()).unwrap();
        unlink_local(&installed_local).unwrap();

        // A failed attempt no longer blocks a fresh ceremony for the same app.
        crate::cbcl_v2_policy::insert(pending.application_id(), &pending.relay_origin).unwrap();
        persist_pending(&pending).unwrap();
        let summaries = pending_links().unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].application_id, pending.application_id());
        assert_eq!(summaries[0].relay_origin, pending.relay_origin);
        assert_eq!(summaries[0].phase, "final-approval");

        let local = load_local_link(pending.application_id()).unwrap();
        assert!(local.is_pending());
        local
            .require_root_generation(root_generation(&[0x87; 32]))
            .unwrap();
        unlink_local(&local).unwrap();
        assert!(pending_links().unwrap().is_empty());
        assert_eq!(
            crate::cbcl_v2_policy::state(pending.application_id(), &pending.relay_origin).unwrap(),
            crate::cbcl_v2_policy::ExactPairState::NewPair
        );

        // Presence can be granted for one exact slot and race with a later
        // replacement. Confirmed unlink must compare-and-delete, refuse the
        // stale selection, and retain the replacement.
        crate::cbcl_v2_policy::insert(pending.application_id(), &pending.relay_origin).unwrap();
        persist_pending(&pending).unwrap();
        let stale_selection = load_local_link(pending.application_id()).unwrap();
        overwrite_test_slot(&CredentialV2LinkSlot::Pending(other_attempt.clone()));
        assert_eq!(
            unlink_local(&stale_selection).unwrap_err().to_string(),
            "PairingApplicationNotLinked"
        );
        assert_eq!(
            load_pending(pending.application_id()).unwrap(),
            other_attempt
        );
        remove_pending(&other_attempt).unwrap();

        // A slot selected while its exact-pair policy was trusted cannot be
        // deleted after that policy changes under the selection.
        crate::cbcl_v2_policy::insert(pending.application_id(), &pending.relay_origin).unwrap();
        persist_pending(&pending).unwrap();
        let stale_policy_selection = load_local_link(pending.application_id()).unwrap();
        crate::cbcl_v2_policy::remove(pending.application_id(), &pending.relay_origin).unwrap();
        assert_eq!(
            unlink_local(&stale_policy_selection)
                .unwrap_err()
                .to_string(),
            "PairingCheckpointRefused"
        );
        assert_eq!(load_pending(pending.application_id()).unwrap(), pending);
        let absent_policy_selection = load_local_link(pending.application_id()).unwrap();
        unlink_local(&absent_policy_selection).unwrap();
        assert!(pending_links().unwrap().is_empty());

        // The confirmed escape also releases the exact app slot for retry.
        persist_pending(&pending).unwrap();
        remove_pending(&pending).unwrap();
    }

    #[test]
    fn checkpoint_info_is_length_prefixed_and_application_separated() {
        let root = HierarchyRoot::from_octets([0x41; 64]);
        let ceremony = [0x22; 32];
        let first =
            checkpoint_wrapping_key(&root, "https://chat.anuna.io/selfsame/v2", &ceremony).unwrap();
        let second =
            checkpoint_wrapping_key(&root, "https://photos.example/selfsame/v2", &ceremony)
                .unwrap();
        assert_ne!(*first, *second);
        assert_eq!(
            codec::b64url(first.as_ref()),
            "XI6TzMRgHxfuh1y-KxXBbWPTm6bxJD1VBe4lrXNK2Ks"
        );
    }

    #[test]
    fn the_slot_is_a_canonical_exclusive_tagged_union() {
        let installed = CredentialV2LinkSlot::Installed(InstalledCredentialV2Link {
            version: 1,
            flow: crate::session::CredentialV2Flow::LegacyTwoDecision,
            root_generation: codec::b64url(&[1; 32]),
            relay_origin: "https://chat.anuna.io:9443".into(),
            profile: codec::b64url(b"{}"),
            current_profile: codec::b64url(b"{}"),
            grant: "a.b.c".into(),
            grant_digest: codec::b64url(&[2; 32]),
            grant_id: codec::b64url(&[9; 32]),
            credential_id: "did:crdt:x#grant-test".into(),
            application_id: "https://chat.anuna.io/selfsame/v2".into(),
            account_principal_digest: codec::b64url(&[3; 32]),
            account_scope_id: codec::b64url(&[4; 32]),
            account: "acct:ss-test@accounts.chat.anuna.io".into(),
            installation_device_did: format!("did:key:z6Mk{}", "1".repeat(44)),
            profile_digest: codec::b64url(&[5; 32]),
            current_profile_digest: codec::b64url(&[5; 32]),
            account_authority: "accounts.chat.anuna.io".into(),
            issuer_did: "did:crdt:z6Mk123".into(),
            resolver_closure: codec::b64url(b"{}"),
            offer_core_digest: codec::b64url(&[6; 32]),
            offer_kid: "https://chat.anuna.io/selfsame/application#test".into(),
            carrier_ceremony_id: codec::b64url(&[7; 32]),
            request_id: codec::b64url(&[10; 32]),
            payload_digest: codec::b64url(&[11; 32]),
            receipt_recovery_commitment: codec::b64url(&[12; 32]),
            final_status_jws: "a.b.c".into(),
            final_status_digest: codec::b64url(&[8; 32]),
            finalized_at: 1_800_000_000,
        });
        let encoded = encode_slot(&installed).unwrap();
        // Existing legacy slots remain byte-for-byte canonical without a mode
        // field. Only the successor writes explicit SingleLink provenance.
        assert!(!encoded.contains("\"flow\""));
        let CredentialV2LinkSlot::Installed(mut successor) = installed.clone() else {
            unreachable!()
        };
        successor.flow = crate::session::CredentialV2Flow::SingleLink;
        let successor = CredentialV2LinkSlot::Installed(successor);
        let encoded_successor = encode_slot(&successor).unwrap();
        assert!(encoded_successor.contains("\"flow\":\"single-link\""));
        assert_eq!(
            serde_json::from_str::<CredentialV2LinkSlot>(&encoded_successor).unwrap(),
            successor
        );
        assert_eq!(
            serde_json::from_str::<CredentialV2LinkSlot>(&encoded).unwrap(),
            installed
        );
        assert!(recognise_slot(&encoded).is_err());
        assert!(recognise_slot(&format!(" {encoded}")).is_err());
        assert!(recognise_slot(&encoded.replace(
            "\"state\":\"installed\"",
            "\"state\":\"installed\",\"extra\":true"
        ))
        .is_err());
    }

    #[test]
    fn application_slot_names_do_not_share_relay_authority() {
        let first = slot_name("https://chat.anuna.io/selfsame/v2").unwrap();
        let second = slot_name("https://photos.example/selfsame/v2").unwrap();
        assert_ne!(first, second);
        assert!(first.starts_with(SLOT_PREFIX));
        assert!(!first.contains("chat.anuna.io"));
    }

    #[test]
    fn test_1161_link_index_is_canonical_bounded_and_secret_free() {
        let first = "https://chat.anuna.io/selfsame/v2";
        let second = "https://photos.example/selfsame/v2";
        let index = CredentialV2LinkIndex {
            version: LINK_INDEX_VERSION,
            applications: vec![first.into(), second.into()],
        };
        let encoded = encode_index(&index).unwrap();
        assert_eq!(recognise_index(&encoded).unwrap(), index);
        assert!(!encoded.contains("token"));
        assert!(!encoded.contains("checkpoint"));

        let mut reversed = index.clone();
        reversed.applications.reverse();
        assert!(encode_index(&reversed).is_err());
        let duplicate = CredentialV2LinkIndex {
            version: LINK_INDEX_VERSION,
            applications: vec![first.into(), first.into()],
        };
        assert!(encode_index(&duplicate).is_err());
        let oversized = CredentialV2LinkIndex {
            version: LINK_INDEX_VERSION,
            applications: (0..=MAX_LINKS)
                .map(|number| format!("https://{number:03}.example/selfsame/v2"))
                .collect(),
        };
        assert!(encode_index(&oversized).is_err());
        assert!(recognise_index(&format!(" {encoded}")).is_err());
    }

    #[test]
    fn post_approval_artifacts_bind_the_preview_scope_device_and_grant() {
        let root = HierarchyRoot::from_octets([0x71; 64]);
        let application = ApplicationId::parse("https://chat.anuna.io/selfsame/v2").unwrap();
        let scope = AccountScopeId::from_octets([0x72; 32]);
        let home = selfsame_app_identity::hierarchy::derive(&root, &application, &scope);
        let preview = home.home_did().unwrap();
        let home_public_key = home.public_key();
        let installation_key = ed25519_dalek::SigningKey::from_bytes(&[0x73; 32])
            .verifying_key()
            .to_bytes();
        let plan = CredentialV2ProvisioningPlan {
            application,
            account_authority: "accounts.chat.anuna.io".into(),
            scope,
            device_did: didkey::encode(&installation_key),
            device_public_key: installation_key,
            permissions: vec!["https://chat.anuna.io/permissions/account".into()],
            preview_issuer_did: preview.clone(),
        };
        let issuer = build_issuer_artifacts(&root, &plan, 1_800_000_000).unwrap();
        assert_eq!(issuer.identity.did, preview);
        let artifacts =
            build_grant_artifacts(&root, &plan, &issuer, [0x74; 32], 1_800_000_000, 86_400)
                .unwrap();
        assert_eq!(artifacts.grant_id, [0x74; 32]);
        let compact =
            selfsame_app_identity::jws::recognise(&artifacts.grant, grant::GRANT_JWS, &[]).unwrap();
        compact.verify(&home_public_key).unwrap();
        let recognised = grant::recognise(&compact.payload).unwrap();
        assert_eq!(recognised.issuer, preview);
        assert_eq!(recognised.device_public_key, installation_key);
        assert_eq!(recognised.application, plan.application.as_str());
        assert_eq!(recognised.token, codec::b64url(&artifacts.grant_id));
        let closure: SignedClosure = serde_json::from_slice(&issuer.resolver_closure).unwrap();
        assert_eq!(closure.deltas.len(), 3);
    }

    #[test]
    fn preview_mismatch_refuses_before_issuer_construction() {
        let root = HierarchyRoot::from_octets([0x61; 64]);
        let application = ApplicationId::parse("https://chat.anuna.io/selfsame/v2").unwrap();
        let scope = AccountScopeId::from_octets([0x62; 32]);
        let installation_key = ed25519_dalek::SigningKey::from_bytes(&[0x63; 32])
            .verifying_key()
            .to_bytes();
        let plan = CredentialV2ProvisioningPlan {
            application,
            account_authority: "accounts.chat.anuna.io".into(),
            scope,
            device_did: didkey::encode(&installation_key),
            device_public_key: installation_key,
            permissions: vec!["https://chat.anuna.io/permissions/account".into()],
            preview_issuer_did: format!("did:crdt:{}", "a".repeat(64)),
        };
        assert!(build_issuer_artifacts(&root, &plan, 1_800_000_000).is_err());
    }

    #[test]
    fn durable_effect_stages_bind_issuer_closure_grant_and_payload() {
        let root = HierarchyRoot::from_octets([0x51; 64]);
        let application = ApplicationId::parse("https://chat.anuna.io/selfsame/v2").unwrap();
        let scope = AccountScopeId::from_octets([0x52; 32]);
        let preview = selfsame_app_identity::hierarchy::derive(&root, &application, &scope)
            .home_did()
            .unwrap();
        let installation_key = ed25519_dalek::SigningKey::from_bytes(&[0x53; 32])
            .verifying_key()
            .to_bytes();
        let plan = CredentialV2ProvisioningPlan {
            application,
            account_authority: "accounts.chat.anuna.io".into(),
            scope,
            device_did: didkey::encode(&installation_key),
            device_public_key: installation_key,
            permissions: vec!["https://chat.anuna.io/permissions/account".into()],
            preview_issuer_did: preview.clone(),
        };
        let issuer = build_issuer_artifacts(&root, &plan, 1_800_000_000).unwrap();
        let grant = build_grant_artifacts(&root, &plan, &issuer, [0x54; 32], 1_800_000_000, 86_400)
            .unwrap();
        let closure = codec::b64url(&issuer.resolver_closure);
        let grant_id = codec::b64url(&grant.grant_id);

        let planned = PendingCredentialV2Stage::Planned {
            effect_time: 1_800_000_000,
            grant_id: grant_id.clone(),
        };
        assert!(planned.validate(&preview).is_ok());
        let issuer_created = PendingCredentialV2Stage::IssuerCreated {
            effect_time: 1_800_000_000,
            grant_id: grant_id.clone(),
            issuer_did: preview.clone(),
            resolver_closure: closure.clone(),
        };
        assert!(issuer_created.validate(&preview).is_ok());
        let provisioned = PendingCredentialV2Stage::Provisioned {
            effect_time: 1_800_000_000,
            grant_id: grant_id.clone(),
            issuer_did: preview.clone(),
            grant: grant.grant.clone(),
            resolver_closure: closure.clone(),
        };
        assert!(provisioned.validate(&preview).is_ok());
        let payload = PendingCredentialV2Stage::PayloadPrepared {
            effect_time: 1_800_000_000,
            grant_id,
            issuer_did: preview.clone(),
            grant: grant.grant,
            resolver_closure: closure,
            payload_content_hash: codec::b64url(&[0x55; 32]),
        };
        assert!(payload.validate(&preview).is_ok());

        let other_root = HierarchyRoot::from_octets([0x56; 64]);
        let other_preview =
            selfsame_app_identity::hierarchy::derive(&other_root, &plan.application, &plan.scope)
                .home_did()
                .unwrap();
        let other_plan = CredentialV2ProvisioningPlan {
            application: plan.application.clone(),
            account_authority: plan.account_authority.clone(),
            scope: plan.scope.clone(),
            device_did: plan.device_did.clone(),
            device_public_key: plan.device_public_key,
            permissions: plan.permissions.clone(),
            preview_issuer_did: other_preview,
        };
        let other_issuer = build_issuer_artifacts(&other_root, &other_plan, 1_800_000_000).unwrap();
        let substituted_closure = PendingCredentialV2Stage::IssuerCreated {
            effect_time: 1_800_000_000,
            grant_id: codec::b64url(&[0x54; 32]),
            issuer_did: preview.clone(),
            resolver_closure: codec::b64url(&other_issuer.resolver_closure),
        };
        assert!(substituted_closure.validate(&preview).is_err());

        let mut malformed_payload = payload;
        let PendingCredentialV2Stage::PayloadPrepared {
            payload_content_hash,
            ..
        } = &mut malformed_payload
        else {
            unreachable!("the fixture is payload-prepared")
        };
        *payload_content_hash = "not-a-32-byte-digest".into();
        assert!(malformed_payload.validate(&preview).is_err());
    }

    #[test]
    fn test_1159_reload_lifecycle_is_closed_over_every_required_state() {
        let retained = CredentialV2ReloadIdentity {
            root_generation: [0x11; 32],
            application_id: "https://chat.anuna.io/selfsame/v2".into(),
            account: "acct:ss-retained@accounts.chat.anuna.io".into(),
            account_authority: "accounts.chat.anuna.io".into(),
            issuer_did: format!("did:crdt:{}", "a".repeat(64)),
            profile_digest: [0x22; 32],
        };
        let verified = |profile_digest| CredentialV2ReloadObservation::Verified {
            root_generation: [0x11; 32],
            application_id: retained.application_id.clone(),
            observed_account: retained.account.clone(),
            account_authority: retained.account_authority.clone(),
            issuer_did: retained.issuer_did.clone(),
            profile_digest,
            offer_key_retained: true,
            grant_matches: true,
            revoked: false,
        };

        assert_eq!(
            classify_reload(&retained, verified([0x22; 32])),
            CredentialV2ReloadOutcome::Usable
        );
        assert_eq!(
            classify_reload(&retained, verified([0x23; 32])),
            CredentialV2ReloadOutcome::ProfileRefresh
        );

        let CredentialV2ReloadObservation::Verified {
            root_generation,
            application_id,
            observed_account,
            issuer_did,
            profile_digest,
            offer_key_retained,
            grant_matches,
            revoked,
            ..
        } = verified([0x22; 32])
        else {
            unreachable!()
        };
        assert_eq!(
            classify_reload(
                &retained,
                CredentialV2ReloadObservation::Verified {
                    root_generation,
                    application_id,
                    observed_account,
                    account_authority: "rotated.chat.anuna.io".into(),
                    issuer_did: issuer_did.clone(),
                    profile_digest,
                    offer_key_retained,
                    grant_matches,
                    revoked,
                }
            ),
            CredentialV2ReloadOutcome::AuthorityRotation
        );
        assert_eq!(
            classify_reload(
                &retained,
                CredentialV2ReloadObservation::Verified {
                    root_generation,
                    application_id: retained.application_id.clone(),
                    observed_account: retained.account.clone(),
                    account_authority: retained.account_authority.clone(),
                    issuer_did: format!("did:crdt:{}", "b".repeat(64)),
                    profile_digest,
                    offer_key_retained: true,
                    grant_matches: false,
                    revoked: false,
                }
            ),
            CredentialV2ReloadOutcome::IssuerRotation
        );
        assert_eq!(
            classify_reload(&retained, CredentialV2ReloadObservation::Unavailable),
            CredentialV2ReloadOutcome::Unavailable
        );

        let CredentialV2ReloadObservation::Verified {
            root_generation,
            application_id,
            observed_account,
            account_authority,
            issuer_did,
            profile_digest,
            offer_key_retained,
            grant_matches,
            ..
        } = verified([0x22; 32])
        else {
            unreachable!()
        };
        assert_eq!(
            classify_reload(
                &retained,
                CredentialV2ReloadObservation::Verified {
                    root_generation,
                    application_id,
                    observed_account,
                    account_authority,
                    issuer_did,
                    profile_digest,
                    offer_key_retained,
                    grant_matches,
                    revoked: true,
                }
            ),
            CredentialV2ReloadOutcome::Revoked
        );

        let CredentialV2ReloadObservation::Verified {
            root_generation,
            application_id,
            account_authority,
            issuer_did,
            profile_digest,
            offer_key_retained,
            grant_matches,
            revoked,
            ..
        } = verified([0x22; 32])
        else {
            unreachable!()
        };
        assert_eq!(
            classify_reload(
                &retained,
                CredentialV2ReloadObservation::Verified {
                    root_generation,
                    application_id,
                    observed_account: "acct:ss-renamed@accounts.chat.anuna.io".into(),
                    account_authority,
                    issuer_did,
                    profile_digest,
                    offer_key_retained,
                    grant_matches,
                    revoked,
                }
            ),
            CredentialV2ReloadOutcome::HandleChanged
        );
        assert_eq!(
            classify_reload(&retained, CredentialV2ReloadObservation::HubDeleted),
            CredentialV2ReloadOutcome::HubDeleted
        );
        assert_eq!(
            authorise_unlink(false),
            CredentialV2UnlinkOutcome::ConfirmationRequired
        );
        assert_eq!(
            authorise_unlink(true),
            CredentialV2UnlinkOutcome::Authorised
        );
    }

    #[test]
    fn test_1159_verified_profile_refresh_repins_only_live_profile_evidence() {
        let installed = installed_reload_fixture();
        let root_generation = codec::decode_b64url_32(&installed.root_generation).unwrap();
        let current_profile = selfsame_app_identity::profile::ApplicationProfile::recognise(
            &reload_profile(&SigningKey::from_bytes(&[0x31; 32]), 1),
        )
        .unwrap();
        let observation = |profile_digest| CredentialV2ReloadObservation::Verified {
            root_generation,
            application_id: installed.application_id.clone(),
            observed_account: installed.account.clone(),
            account_authority: installed.account_authority.clone(),
            issuer_did: installed.issuer_did.clone(),
            profile_digest,
            offer_key_retained: true,
            grant_matches: true,
            revoked: false,
        };
        let unchanged = installed
            .verify_reload(observation(*current_profile.digest()), None)
            .unwrap();
        assert_eq!(unchanged.outcome, CredentialV2ReloadOutcome::Usable);
        assert!(unchanged.replacement.is_none());

        let refreshed_octets = reload_profile(&SigningKey::from_bytes(&[0x31; 32]), 2);
        let refreshed_profile =
            selfsame_app_identity::profile::ApplicationProfile::recognise(&refreshed_octets)
                .unwrap();
        let refreshed = installed
            .verify_reload(
                observation(*refreshed_profile.digest()),
                Some(&refreshed_octets),
            )
            .unwrap();
        assert_eq!(refreshed.outcome, CredentialV2ReloadOutcome::ProfileRefresh);
        let replacement = refreshed.replacement.unwrap();
        assert_eq!(replacement.profile, installed.profile);
        assert_eq!(replacement.profile_digest, installed.profile_digest);
        assert_eq!(replacement.grant, installed.grant);
        assert_eq!(replacement.final_status_jws, installed.final_status_jws);
        assert_eq!(
            replacement.current_profile_digest,
            codec::b64url(refreshed_profile.digest())
        );
        replacement.validate().unwrap();
    }
}
