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
    codec,
    hierarchy::HierarchyRoot,
    profile::ApplicationId,
    uri::{self, UriPolicy},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use crate::{commands::UiError, store};

const SLOT_PREFIX: &str = "credential-v2-link-v1-";
const SLOT_VERSION: u8 = 1;
const CHECKPOINT_LABEL: &[u8] = b"selfsame credential/v2 claimant checkpoint wrapping v1";
const ROOT_GENERATION_LABEL: &[u8] = b"selfsame credential/v2 root generation v1\0";
const MAX_SLOT_OCTETS: usize = 180_000;

type Result<T> = std::result::Result<T, UiError>;

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
}

/// Installed capability facts retained only after immutable hub acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstalledCredentialV2Link {
    version: u8,
    root_generation: String,
    grant: String,
    grant_digest: String,
    application_id: String,
    account_principal_digest: String,
    account_scope_id: String,
    installation_device_did: String,
    profile_digest: String,
    account_authority: String,
    issuer_did: String,
    offer_core_digest: String,
    carrier_ceremony_id: String,
    final_status_jws: String,
    final_status_digest: String,
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
        Ok(())
    }
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

/// Atomically occupy an empty application slot with one pending authority.
/// Exact retry is idempotent; another pending or installed value refuses.
pub fn persist_pending(pending: &PendingCredentialV2Completion) -> Result<()> {
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
        CredentialV2LinkSlot::Installed(_) => {}
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
            grant: "a.b.c".into(),
            grant_digest: codec::b64url(&[2; 32]),
            application_id: "https://chat.anuna.io/selfsame/v2".into(),
            account_principal_digest: codec::b64url(&[3; 32]),
            account_scope_id: codec::b64url(&[4; 32]),
            installation_device_did: format!("did:key:z6Mk{}", "1".repeat(44)),
            profile_digest: codec::b64url(&[5; 32]),
            account_authority: "accounts.chat.anuna.io".into(),
            issuer_did: "did:crdt:z6Mk123".into(),
            offer_core_digest: codec::b64url(&[6; 32]),
            carrier_ceremony_id: codec::b64url(&[7; 32]),
            final_status_jws: "a.b.c".into(),
            final_status_digest: codec::b64url(&[8; 32]),
        });
        let encoded = encode_slot(&installed).unwrap();
        assert_eq!(recognise_slot(&encoded).unwrap(), installed);
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
}
