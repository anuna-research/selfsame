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
const SLOT_VERSION: u8 = 1;
const CHECKPOINT_LABEL: &[u8] = b"selfsame credential/v2 claimant checkpoint wrapping v1";
const ROOT_GENERATION_LABEL: &[u8] = b"selfsame credential/v2 root generation v1\0";
const MAX_SLOT_OCTETS: usize = 180_000;

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

pub(crate) fn build_issuer_artifacts(
    root: &HierarchyRoot,
    plan: &CredentialV2ProvisioningPlan,
    effect_time: i64,
) -> Result<CredentialV2IssuerArtifacts> {
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
    root_generation: String,
    application_id: String,
    relay_origin: String,
    profile_digest: String,
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
    root_generation: String,
    profile: String,
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

impl PendingCredentialV2Completion {
    /// Construct a closed pending record from typed ceremony objects.
    pub fn new(input: PendingCredentialV2Input<'_>) -> Result<Self> {
        validate_application_and_relay(input.application_id, input.carrier.relay_origin())?;
        if input.carrier.application_context() != input.application_id
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
            root_generation: codec::b64url(&input.root_generation),
            application_id: input.application_id.into(),
            relay_origin: input.carrier.relay_origin().into(),
            profile_digest: codec::b64url(&input.profile_digest),
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

    /// Decode the exact carrier retained by this pending authority.
    pub fn carrier(&self) -> Result<CredentialV2Carrier> {
        self.validate()?;
        decode_carrier(&decode_bounded(&self.carrier, 4_096)?).map_err(checkpoint_error)
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

/// Exact locally durable payload facts needed for hub-receipt verification.
pub(crate) struct CredentialV2PayloadFacts {
    pub grant_id: [u8; 32],
    pub issuer_did: String,
    pub grant: String,
    pub resolver_closure: Vec<u8>,
    pub payload_content_hash: [u8; 32],
}

impl InstalledCredentialV2Link {
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
        let offer = selfsame_pairing::credential_v2::recognise_signed_offer(
            &profile,
            offer_object.body(),
        )
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
            account_principal_digest: *offer
                .claims
                .account_provenance()
                .account_principal_digest(),
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

        let compact = selfsame_app_identity::jws::recognise(
            &facts.grant,
            grant::GRANT_JWS,
            &[],
        )
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
            root_generation: pending.root_generation.clone(),
            profile: codec::b64url(profile_octets),
            grant_digest: codec::b64url(&Sha256::digest(facts.grant.as_bytes())),
            grant: facts.grant,
            grant_id: codec::b64url(&facts.grant_id),
            credential_id: recognised_grant.id,
            application_id: pending.application_id.clone(),
            account_principal_digest: codec::b64url(
                offer.claims.account_provenance().account_principal_digest(),
            ),
            account_scope_id: codec::b64url(
                offer.claims.account_provenance().account_scope_id(),
            ),
            account,
            installation_device_did: offer.claims.device_binding().device_did().into(),
            profile_digest: pending.profile_digest.clone(),
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

    fn validate(&self) -> Result<()> {
        let profile_octets = decode_bounded(&self.profile, 65_536)?;
        let profile = selfsame_app_identity::profile::ApplicationProfile::recognise(&profile_octets)
            .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        let root_generation = codec::decode_b64url_32(&self.root_generation)
            .map_err(|_| UiError::from("PairingCheckpointRefused"))?;
        let profile_digest = codec::decode_b64url_32(&self.profile_digest)
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
            || profile.application_id.as_str() != self.application_id
            || *profile.digest() != profile_digest
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
        let compact = selfsame_app_identity::jws::recognise(
            &self.grant,
            grant::GRANT_JWS,
            &[],
        )
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
mod tests {
    use super::*;

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
            root_generation: codec::b64url(&[1; 32]),
            profile: codec::b64url(b"{}"),
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
        assert_eq!(serde_json::from_str::<CredentialV2LinkSlot>(&encoded).unwrap(), installed);
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
}
