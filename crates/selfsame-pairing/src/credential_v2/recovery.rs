//! Closed HTTPS final-status recovery grammar for credential/v2.

use super::{
    decode_canonical_b64, signing_key_declared, text, CredentialV2OfferError, MAX_JSON_SAFE_INTEGER,
};
use ciborium::Value;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use selfsame_app_identity::{
    codec,
    json::{self, Json, Limits},
    profile::{ApplicationId, ApplicationProfile},
};
use sha2::{Digest, Sha256};
use std::io::Cursor;
use zeroize::Zeroizing;

const RECOVERY_COMMITMENT_DOMAIN: &[u8] =
    b"selfsame credential/v2 receipt recovery commitment v1\0";
const RECOVERY_STATUS_TYPE: &str = "selfsame-pairing-recovery-status+jws";
const MAX_RECOVERY_REQUEST_BYTES: usize = 2_304;
const MAX_RECOVERY_RESPONSE_BYTES: usize = 9_216;
const MAX_RECOVERY_STATUS_CORE_BYTES: usize = 4_096;
const MAX_RECOVERY_STATUS_JWS_BYTES: usize = 8_192;

/// Fully recognised secret-bearing recovery request.
pub struct CredentialV2RecoveryRequest {
    application_id: String,
    carrier_ceremony_id: [u8; 32],
    receipt_recovery_token: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for CredentialV2RecoveryRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialV2RecoveryRequest")
            .field("application_id", &self.application_id)
            .field("carrier_ceremony_id", &self.carrier_ceremony_id)
            .field("receipt_recovery_token", &"[REDACTED]")
            .finish()
    }
}

impl CredentialV2RecoveryRequest {
    /// Authenticated application identifier carried by the closed request.
    #[must_use]
    pub fn application_id(&self) -> &str {
        &self.application_id
    }

    /// Exact carrier ceremony used as the immutable-status index.
    #[must_use]
    pub const fn carrier_ceremony_id(&self) -> &[u8; 32] {
        &self.carrier_ceremony_id
    }

    /// Borrow the recovery token only inside the native request boundary.
    #[must_use]
    pub fn receipt_recovery_token(&self) -> &[u8; 32] {
        &self.receipt_recovery_token
    }
}

/// Closed response union returned by the authenticated application origin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialV2RecoveryResponse {
    /// Immutable final status already exists.
    Accepted {
        /// Byte-identical compact final-status JWS.
        final_status_jws: String,
        /// Raw SHA-256 of the canonical final-status core.
        final_status_digest: [u8; 32],
    },
    /// The locked pending transaction can still finalize.
    InProgress {
        /// Bounded delay before another query.
        retry_after_seconds: u8,
    },
    /// Locked evidence proves the ceremony can no longer finalize.
    NotFinalized {
        /// Current-profile-signed negative status JWS.
        recovery_status_jws: String,
        /// Raw SHA-256 of its canonical payload.
        recovery_status_digest: [u8; 32],
    },
    /// No retained terminal authority can be disclosed.
    Unknown,
}

/// Exact facts in a signed `not-finalized` status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialV2RecoveryNegativeInput {
    /// Canonical application identifier.
    pub application_id: String,
    /// Exact carrier ceremony.
    pub carrier_ceremony_id: [u8; 32],
    /// Commitment recomputed transiently from the supplied token.
    pub receipt_recovery_commitment: [u8; 32],
    /// Whole UTC second at the locked observation.
    pub observed_at: u64,
}

/// Signed negative status returned only from locked terminal evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltCredentialV2RecoveryNegative {
    /// Exact RFC-8785 payload.
    pub core: Vec<u8>,
    /// Compact EdDSA JWS.
    pub jws: String,
    /// Raw SHA-256 of `core`.
    pub digest: [u8; 32],
    /// Profile key identifier used to sign.
    pub kid: String,
}

/// Authenticated current-profile authority for one terminal-negative result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecognisedCredentialV2RecoveryNegative {
    /// Current profile key identifier that signed the negative.
    pub kid: String,
    /// Whole UTC second embedded in the authenticated status.
    pub observed_at: u64,
}

/// Encode the deterministic-CBOR HTTPS recovery request.
pub fn encode_receipt_recovery_request(
    application_id: &str,
    carrier_ceremony_id: [u8; 32],
    receipt_recovery_token: &[u8; 32],
) -> Result<Vec<u8>, CredentialV2OfferError> {
    validate_application(application_id)?;
    let value = Value::Map(vec![
        (Value::Text("version".into()), Value::Integer(2.into())),
        (
            Value::Text("application-id".into()),
            Value::Text(application_id.into()),
        ),
        (
            Value::Text("carrier-ceremony-id".into()),
            Value::Bytes(carrier_ceremony_id.to_vec()),
        ),
        (
            Value::Text("receipt-recovery-token".into()),
            Value::Bytes(receipt_recovery_token.to_vec()),
        ),
    ]);
    encode_bounded(value, MAX_RECOVERY_REQUEST_BYTES)
}

/// Recognise one complete, canonical recovery request.
pub fn recognise_receipt_recovery_request(
    bytes: &[u8],
) -> Result<CredentialV2RecoveryRequest, CredentialV2OfferError> {
    let value = decode_bounded(bytes, MAX_RECOVERY_REQUEST_BYTES)?;
    let entries = exact_map(&value, 4)?;
    if unsigned(field(entries, "version")?)? != 2 {
        return Err(CredentialV2OfferError::Refused);
    }
    let application_id = text_value(field(entries, "application-id")?)?.to_owned();
    validate_application(&application_id)?;
    Ok(CredentialV2RecoveryRequest {
        application_id,
        carrier_ceremony_id: fixed(field(entries, "carrier-ceremony-id")?)?,
        receipt_recovery_token: Zeroizing::new(fixed(field(entries, "receipt-recovery-token")?)?),
    })
}

/// Compute the public recovery commitment without retaining the raw token.
pub fn credential_v2_receipt_recovery_commitment(
    receipt_recovery_token: &[u8; 32],
    carrier_ceremony_id: [u8; 32],
    application_id: &str,
) -> Result<[u8; 32], CredentialV2OfferError> {
    validate_application(application_id)?;
    let mut digest = Sha256::new();
    digest.update(RECOVERY_COMMITMENT_DOMAIN);
    digest.update(receipt_recovery_token);
    digest.update(carrier_ceremony_id);
    digest.update(application_id.as_bytes());
    Ok(digest.finalize().into())
}

/// Encode one member of the closed response union.
pub fn encode_receipt_recovery_response(
    response: &CredentialV2RecoveryResponse,
) -> Result<Vec<u8>, CredentialV2OfferError> {
    let value = match response {
        CredentialV2RecoveryResponse::Accepted {
            final_status_jws,
            final_status_digest,
        } => {
            validate_jws(final_status_jws)?;
            Value::Map(vec![
                (Value::Text("status".into()), Value::Text("accepted".into())),
                (
                    Value::Text("final-status-jws".into()),
                    Value::Text(final_status_jws.clone()),
                ),
                (
                    Value::Text("final-status-digest".into()),
                    Value::Bytes(final_status_digest.to_vec()),
                ),
            ])
        }
        CredentialV2RecoveryResponse::InProgress {
            retry_after_seconds,
        } if (1..=30).contains(retry_after_seconds) => Value::Map(vec![
            (
                Value::Text("status".into()),
                Value::Text("in-progress".into()),
            ),
            (
                Value::Text("retry-after-seconds".into()),
                Value::Integer(u64::from(*retry_after_seconds).into()),
            ),
        ]),
        CredentialV2RecoveryResponse::NotFinalized {
            recovery_status_jws,
            recovery_status_digest,
        } => {
            validate_jws(recovery_status_jws)?;
            Value::Map(vec![
                (
                    Value::Text("status".into()),
                    Value::Text("not-finalized".into()),
                ),
                (
                    Value::Text("recovery-status-jws".into()),
                    Value::Text(recovery_status_jws.clone()),
                ),
                (
                    Value::Text("recovery-status-digest".into()),
                    Value::Bytes(recovery_status_digest.to_vec()),
                ),
            ])
        }
        CredentialV2RecoveryResponse::Unknown => Value::Map(vec![
            (Value::Text("status".into()), Value::Text("unknown".into())),
            (Value::Text("padding".into()), Value::Bytes(vec![0; 96])),
        ]),
        CredentialV2RecoveryResponse::InProgress { .. } => {
            return Err(CredentialV2OfferError::Refused);
        }
    };
    encode_bounded(value, MAX_RECOVERY_RESPONSE_BYTES)
}

/// Decode one complete deterministic-CBOR response union.
pub fn decode_receipt_recovery_response(
    bytes: &[u8],
) -> Result<CredentialV2RecoveryResponse, CredentialV2OfferError> {
    let value = decode_bounded(bytes, MAX_RECOVERY_RESPONSE_BYTES)?;
    let entries = value.as_map().ok_or(CredentialV2OfferError::Refused)?;
    match text_value(field(entries, "status")?)? {
        "accepted" if entries.len() == 3 => {
            let jws = text_value(field(entries, "final-status-jws")?)?.to_owned();
            validate_jws(&jws)?;
            Ok(CredentialV2RecoveryResponse::Accepted {
                final_status_jws: jws,
                final_status_digest: fixed(field(entries, "final-status-digest")?)?,
            })
        }
        "in-progress" if entries.len() == 2 => {
            let retry = unsigned(field(entries, "retry-after-seconds")?)?;
            let retry_after_seconds =
                u8::try_from(retry).map_err(|_| CredentialV2OfferError::Refused)?;
            if !(1..=30).contains(&retry_after_seconds) {
                return Err(CredentialV2OfferError::Refused);
            }
            Ok(CredentialV2RecoveryResponse::InProgress {
                retry_after_seconds,
            })
        }
        "not-finalized" if entries.len() == 3 => {
            let jws = text_value(field(entries, "recovery-status-jws")?)?.to_owned();
            validate_jws(&jws)?;
            Ok(CredentialV2RecoveryResponse::NotFinalized {
                recovery_status_jws: jws,
                recovery_status_digest: fixed(field(entries, "recovery-status-digest")?)?,
            })
        }
        "unknown" if entries.len() == 2 => {
            let padding = field(entries, "padding")?
                .as_bytes()
                .ok_or(CredentialV2OfferError::Refused)?;
            if padding.len() != 96 || padding.iter().any(|byte| *byte != 0) {
                return Err(CredentialV2OfferError::Refused);
            }
            Ok(CredentialV2RecoveryResponse::Unknown)
        }
        _ => Err(CredentialV2OfferError::Refused),
    }
}

/// Sign a locked terminal `not-finalized` observation with the current profile.
pub fn build_recovery_not_finalized(
    profile: &ApplicationProfile,
    input: &CredentialV2RecoveryNegativeInput,
    kid: &str,
    signing_key: &SigningKey,
) -> Result<BuiltCredentialV2RecoveryNegative, CredentialV2OfferError> {
    signing_key_declared(profile, kid, signing_key)?;
    let core = recovery_negative_core(profile, input)?;
    let protected = json::canonicalise(&Json::obj([
        ("alg", Json::text("EdDSA")),
        ("kid", Json::text(kid)),
        ("typ", Json::text(RECOVERY_STATUS_TYPE)),
    ]));
    let encoded_header = codec::b64url(&protected);
    let encoded_payload = codec::b64url(&core);
    let signing_input = format!("{encoded_header}.{encoded_payload}");
    let signature = signing_key.sign(signing_input.as_bytes());
    let jws = format!("{signing_input}.{}", codec::b64url(&signature.to_bytes()));
    validate_jws(&jws)?;
    Ok(BuiltCredentialV2RecoveryNegative {
        digest: Sha256::digest(&core).into(),
        core,
        jws,
        kid: kid.into(),
    })
}

/// Verify a current-profile-signed negative against every retained request fact.
pub fn recognise_recovery_not_finalized(
    profile: &ApplicationProfile,
    jws: &str,
    expected_digest: [u8; 32],
    expected: &CredentialV2RecoveryNegativeInput,
    expected_kid: &str,
) -> Result<(), CredentialV2OfferError> {
    validate_jws(jws)?;
    let mut segments = jws.split('.');
    let (Some(encoded_header), Some(encoded_payload), Some(encoded_signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(CredentialV2OfferError::Refused);
    };
    let protected = decode_canonical_b64(encoded_header)?;
    let core = decode_canonical_b64(encoded_payload)?;
    let signature: [u8; 64] = decode_canonical_b64(encoded_signature)?
        .try_into()
        .map_err(|_| CredentialV2OfferError::Refused)?;
    let header = json::recognise(
        &protected,
        Limits {
            max_bytes: 1_024,
            max_depth: 1,
        },
    )
    .map_err(|_| CredentialV2OfferError::Refused)?;
    const MEMBERS: [&str; 3] = ["alg", "kid", "typ"];
    if json::canonicalise(&header) != protected
        || header.member_names() != MEMBERS
        || text(&header, "alg")? != "EdDSA"
        || text(&header, "kid")? != expected_kid
        || text(&header, "typ")? != RECOVERY_STATUS_TYPE
        || Sha256::digest(&core).as_slice() != expected_digest
        || core != recovery_negative_core(profile, expected)?
    {
        return Err(CredentialV2OfferError::Refused);
    }
    let declared = profile
        .enrollment_keys
        .iter()
        .find(|candidate| candidate.kid == expected_kid)
        .ok_or(CredentialV2OfferError::Refused)?;
    VerifyingKey::from_bytes(&declared.jwk.public_key)
        .map_err(|_| CredentialV2OfferError::Refused)?
        .verify(
            format!("{encoded_header}.{encoded_payload}").as_bytes(),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| CredentialV2OfferError::Refused)
}

/// Verify a signed terminal-negative while taking its key identifier and
/// observation time only from the authenticated compact JWS.
///
/// The caller supplies every local binding except those two signed fields.
/// Neither is exposed until the ordinary closed-core, digest, declared-key,
/// and Ed25519 checks all pass.
pub fn recognise_recovery_not_finalized_status(
    profile: &ApplicationProfile,
    jws: &str,
    expected_digest: [u8; 32],
    application_id: &str,
    carrier_ceremony_id: [u8; 32],
    receipt_recovery_commitment: [u8; 32],
) -> Result<RecognisedCredentialV2RecoveryNegative, CredentialV2OfferError> {
    validate_jws(jws)?;
    let mut segments = jws.split('.');
    let (Some(encoded_header), Some(encoded_payload), Some(_), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(CredentialV2OfferError::Refused);
    };
    let protected = decode_canonical_b64(encoded_header)?;
    let core = decode_canonical_b64(encoded_payload)?;
    let header = json::recognise(
        &protected,
        Limits {
            max_bytes: 1_024,
            max_depth: 1,
        },
    )
    .map_err(|_| CredentialV2OfferError::Refused)?;
    let status = json::recognise(
        &core,
        Limits {
            max_bytes: MAX_RECOVERY_STATUS_CORE_BYTES,
            max_depth: 1,
        },
    )
    .map_err(|_| CredentialV2OfferError::Refused)?;
    let kid = text(&header, "kid")?.to_owned();
    let observed_at = status
        .get("observedAt")
        .and_then(Json::as_i64)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(CredentialV2OfferError::Refused)?;
    let expected = CredentialV2RecoveryNegativeInput {
        application_id: application_id.into(),
        carrier_ceremony_id,
        receipt_recovery_commitment,
        observed_at,
    };
    recognise_recovery_not_finalized(profile, jws, expected_digest, &expected, &kid)?;
    Ok(RecognisedCredentialV2RecoveryNegative { kid, observed_at })
}

fn recovery_negative_core(
    profile: &ApplicationProfile,
    input: &CredentialV2RecoveryNegativeInput,
) -> Result<Vec<u8>, CredentialV2OfferError> {
    validate_application(&input.application_id)?;
    if profile.application_id.as_str() != input.application_id
        || input.observed_at > MAX_JSON_SAFE_INTEGER
    {
        return Err(CredentialV2OfferError::Refused);
    }
    let core = json::canonicalise(&Json::obj([
        ("payloadVersion", Json::int(2)),
        ("role", Json::text("recovery-status")),
        ("applicationId", Json::text(&input.application_id)),
        (
            "carrierCeremonyId",
            Json::text(codec::b64url(&input.carrier_ceremony_id)),
        ),
        (
            "receiptRecoveryCommitment",
            Json::text(codec::b64url(&input.receipt_recovery_commitment)),
        ),
        ("status", Json::text("not-finalized")),
        (
            "observedAt",
            Json::int(
                i64::try_from(input.observed_at).map_err(|_| CredentialV2OfferError::Refused)?,
            ),
        ),
    ]));
    if core.is_empty() || core.len() > MAX_RECOVERY_STATUS_CORE_BYTES {
        return Err(CredentialV2OfferError::Refused);
    }
    Ok(core)
}

fn validate_application(application_id: &str) -> Result<(), CredentialV2OfferError> {
    let parsed =
        ApplicationId::parse(application_id).map_err(|_| CredentialV2OfferError::Refused)?;
    if parsed.as_str() != application_id || application_id.len() > 2_048 {
        return Err(CredentialV2OfferError::Refused);
    }
    Ok(())
}

fn validate_jws(jws: &str) -> Result<(), CredentialV2OfferError> {
    if jws.is_empty()
        || jws.len() > MAX_RECOVERY_STATUS_JWS_BYTES
        || !jws.is_ascii()
        || jws.split('.').count() != 3
        || jws.split('.').any(str::is_empty)
    {
        return Err(CredentialV2OfferError::Refused);
    }
    Ok(())
}

fn encode_bounded(value: Value, maximum: usize) -> Result<Vec<u8>, CredentialV2OfferError> {
    let bytes = cbor2::to_canonical_vec(&value).map_err(|_| CredentialV2OfferError::Refused)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(CredentialV2OfferError::Refused);
    }
    Ok(bytes)
}

fn decode_bounded(bytes: &[u8], maximum: usize) -> Result<Value, CredentialV2OfferError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(CredentialV2OfferError::Refused);
    }
    let mut cursor = Cursor::new(bytes);
    let value: Value =
        ciborium::de::from_reader(&mut cursor).map_err(|_| CredentialV2OfferError::Refused)?;
    if usize::try_from(cursor.position()).map_err(|_| CredentialV2OfferError::Refused)?
        != bytes.len()
        || cbor2::to_canonical_vec(&value).map_err(|_| CredentialV2OfferError::Refused)? != bytes
    {
        return Err(CredentialV2OfferError::Refused);
    }
    Ok(value)
}

fn exact_map(value: &Value, length: usize) -> Result<&[(Value, Value)], CredentialV2OfferError> {
    let entries = value.as_map().ok_or(CredentialV2OfferError::Refused)?;
    if entries.len() != length {
        return Err(CredentialV2OfferError::Refused);
    }
    Ok(entries)
}

fn field<'a>(
    entries: &'a [(Value, Value)],
    name: &str,
) -> Result<&'a Value, CredentialV2OfferError> {
    let mut matches = entries
        .iter()
        .filter_map(|(key, value)| (key.as_text() == Some(name)).then_some(value));
    let value = matches.next().ok_or(CredentialV2OfferError::Refused)?;
    if matches.next().is_some() {
        return Err(CredentialV2OfferError::Refused);
    }
    Ok(value)
}

fn text_value(value: &Value) -> Result<&str, CredentialV2OfferError> {
    value.as_text().ok_or(CredentialV2OfferError::Refused)
}

fn fixed<const N: usize>(value: &Value) -> Result<[u8; N], CredentialV2OfferError> {
    value
        .as_bytes()
        .ok_or(CredentialV2OfferError::Refused)?
        .as_slice()
        .try_into()
        .map_err(|_| CredentialV2OfferError::Refused)
}

fn unsigned(value: &Value) -> Result<u64, CredentialV2OfferError> {
    u64::try_from(value.as_integer().ok_or(CredentialV2OfferError::Refused)?)
        .map_err(|_| CredentialV2OfferError::Refused)
}
