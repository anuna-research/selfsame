//! The authenticated relay hint retained in the application credential offer.
//!
//! Relay election belongs to [`crate::cbcl_relay`]. This value only proves that
//! an already-built offer names the same authenticated cbcl relay descriptor
//! and offer digest at both endpoints.

use crate::json::Json;
use crate::profile::ApplicationProfile;

/// The authenticated provider hint carried inside an offer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderHint {
    /// The canonical application identifier.
    pub application_id: String,
    /// The profile version, which the joiner must support.
    pub profile_version: i64,
    /// The selected cbcl relay operator.
    pub provider_id: String,
    /// `SHA-256` of the canonical cbcl relay descriptor, base64url.
    pub descriptor_digest: String,
    /// The credential-offer digest.
    pub offer_digest: String,
}

/// Why a hint was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HintError {
    /// A member is absent or has the wrong JSON type.
    #[error("provider hint is malformed")]
    Malformed,
    /// The hint carries a member the credential contract does not define.
    #[error("provider hint carries an unknown member")]
    UnknownMember,
    /// The hint carries a private account scope.
    #[error("provider hint carries an account scope")]
    CarriesAccountScope,
    /// The application identifier is not the joiner's.
    #[error("provider hint names a different application")]
    ApplicationMismatch,
    /// The profile version is one this build does not speak.
    #[error("provider hint names an unsupported profile version")]
    UnsupportedProfileVersion,
    /// No cbcl relay descriptor has that operator ID.
    #[error("provider hint names an undeclared cbcl relay")]
    UnknownProvider,
    /// The descriptor digest does not equal the joiner's local descriptor.
    #[error("provider hint descriptor digest does not match")]
    DescriptorMismatch,
    /// The offer digest is not the offer being processed.
    #[error("provider hint offer digest does not match")]
    OfferMismatch,
}

const HINT_MEMBERS: &[&str] = &[
    "applicationId",
    "profileVersion",
    "providerId",
    "descriptorDigest",
    "offerDigest",
];

impl ProviderHint {
    /// Serialise the closed hint object.
    pub fn to_json(&self) -> Json {
        Json::obj([
            ("applicationId", Json::text(self.application_id.clone())),
            ("profileVersion", Json::int(self.profile_version)),
            ("providerId", Json::text(self.provider_id.clone())),
            (
                "descriptorDigest",
                Json::text(self.descriptor_digest.clone()),
            ),
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
        let text = |name: &str| {
            value
                .get(name)
                .and_then(Json::as_str)
                .ok_or(HintError::Malformed)
        };
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

    /// Require the hint to name the joiner's exact authenticated cbcl relay.
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
            .cbcl_pairing_relays
            .iter()
            .find(|descriptor| descriptor.operator_id == self.provider_id)
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
