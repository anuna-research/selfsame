//! Person-owned credential/v2 trust for one exact application-relay pair.
//!
//! The platform secure store seals this single closed record. A missing record
//! means no accepted pairs; malformed state refuses instead of becoming a new
//! TOFU prompt.

use selfsame_app_identity::{
    profile::ApplicationId,
    uri::{self, UriPolicy},
};
use serde::{Deserialize, Serialize};

use crate::{commands::UiError, store};

const POLICY_ENTRY: &str = "credential-v2-exact-relay-policy-v1";
const POLICY_VERSION: u8 = 1;
const MAX_ROWS: usize = 256;

type Result<T> = std::result::Result<T, UiError>;

/// Closed lookup result for one exact pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExactPairState {
    /// The exact application-relay tuple has never been accepted.
    NewPair,
    /// The person previously accepted this exact tuple.
    TrustedPair,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExactPairRow {
    application_id: String,
    relay_origin: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExactPairPolicy {
    version: u8,
    rows: Vec<ExactPairRow>,
}

impl ExactPairPolicy {
    fn empty() -> Self {
        Self {
            version: POLICY_VERSION,
            rows: Vec::new(),
        }
    }

    fn recognise(text: &str) -> Result<Self> {
        let value: Self =
            serde_json::from_str(text).map_err(|_| UiError::from("PairingPolicyUnavailable"))?;
        if value.version != POLICY_VERSION || value.rows.len() > MAX_ROWS {
            return Err(UiError::from("PairingPolicyUnavailable"));
        }
        let mut prior: Option<(&str, &str)> = None;
        for row in &value.rows {
            recognise_pair(&row.application_id, &row.relay_origin)?;
            let current = (row.application_id.as_str(), row.relay_origin.as_str());
            if prior.is_some_and(|candidate| candidate >= current) {
                return Err(UiError::from("PairingPolicyUnavailable"));
            }
            prior = Some(current);
        }
        let canonical =
            serde_json::to_string(&value).map_err(|_| UiError::from("PairingPolicyUnavailable"))?;
        if canonical != text {
            return Err(UiError::from("PairingPolicyUnavailable"));
        }
        Ok(value)
    }

    fn state(&self, application_id: &str, relay_origin: &str) -> ExactPairState {
        if self
            .rows
            .binary_search_by(|row| {
                (row.application_id.as_str(), row.relay_origin.as_str())
                    .cmp(&(application_id, relay_origin))
            })
            .is_ok()
        {
            ExactPairState::TrustedPair
        } else {
            ExactPairState::NewPair
        }
    }

    fn insert(&mut self, application_id: &str, relay_origin: &str) -> Result<bool> {
        recognise_pair(application_id, relay_origin)?;
        match self.rows.binary_search_by(|row| {
            (row.application_id.as_str(), row.relay_origin.as_str())
                .cmp(&(application_id, relay_origin))
        }) {
            Ok(_) => Ok(false),
            Err(index) if self.rows.len() < MAX_ROWS => {
                self.rows.insert(
                    index,
                    ExactPairRow {
                        application_id: application_id.into(),
                        relay_origin: relay_origin.into(),
                    },
                );
                Ok(true)
            }
            Err(_) => Err(UiError::from("PairingPolicyUnavailable")),
        }
    }

    fn remove(&mut self, application_id: &str, relay_origin: &str) -> Result<bool> {
        recognise_pair(application_id, relay_origin)?;
        match self.rows.binary_search_by(|row| {
            (row.application_id.as_str(), row.relay_origin.as_str())
                .cmp(&(application_id, relay_origin))
        }) {
            Ok(index) => {
                self.rows.remove(index);
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    fn encode(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|_| UiError::from("PairingPolicyUnavailable"))
    }
}

fn recognise_pair(application_id: &str, relay_origin: &str) -> Result<()> {
    ApplicationId::parse(application_id).map_err(|_| UiError::from("PairingPolicyUnavailable"))?;
    let origin = uri::recognise(relay_origin, UriPolicy::ORIGIN)
        .map_err(|_| UiError::from("PairingPolicyUnavailable"))?;
    if origin.origin != relay_origin {
        return Err(UiError::from("PairingPolicyUnavailable"));
    }
    Ok(())
}

fn load() -> Result<ExactPairPolicy> {
    match store::get(POLICY_ENTRY).map_err(|_| UiError::from("PairingPolicyUnavailable"))? {
        Some(text) => ExactPairPolicy::recognise(&text),
        None => Ok(ExactPairPolicy::empty()),
    }
}

/// Look up only the exact authenticated application and canonical relay pair.
pub fn state(application_id: &str, relay_origin: &str) -> Result<ExactPairState> {
    recognise_pair(application_id, relay_origin)?;
    Ok(load()?.state(application_id, relay_origin))
}

/// Atomically add one newly approved exact pair after matching Finished.
pub fn insert(application_id: &str, relay_origin: &str) -> Result<()> {
    let mut policy = load()?;
    if policy.insert(application_id, relay_origin)? {
        store::set(POLICY_ENTRY, &policy.encode()?)
            .map_err(|_| UiError::from("PairingPolicyUnavailable"))?;
    }
    Ok(())
}

/// Explicitly remove one exact pair without changing any other application.
pub fn remove(application_id: &str, relay_origin: &str) -> Result<()> {
    let mut policy = load()?;
    if policy.remove(application_id, relay_origin)? {
        store::set(POLICY_ENTRY, &policy.encode()?)
            .map_err(|_| UiError::from("PairingPolicyUnavailable"))?;
    }
    Ok(())
}

/// Remove every accepted pair when the root lifecycle is destroyed.
pub fn purge() -> Result<()> {
    store::delete(POLICY_ENTRY).map_err(|_| UiError::from("PairingPolicyUnavailable"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP_A: &str = "https://chat.anuna.io/selfsame/v2";
    const APP_B: &str = "https://photos.example/selfsame/v2";
    const RELAY: &str = "https://chat.anuna.io:9443";

    #[test]
    fn exact_pair_never_authorises_another_application_on_the_same_relay() {
        let mut policy = ExactPairPolicy::empty();
        assert!(policy.insert(APP_A, RELAY).unwrap());
        assert_eq!(policy.state(APP_A, RELAY), ExactPairState::TrustedPair);
        assert_eq!(policy.state(APP_B, RELAY), ExactPairState::NewPair);
        assert!(!policy.insert(APP_A, RELAY).unwrap());
        assert!(policy.remove(APP_A, RELAY).unwrap());
        assert_eq!(policy.state(APP_A, RELAY), ExactPairState::NewPair);
    }

    #[test]
    fn policy_recognition_refuses_corruption_reordering_and_noncanonical_pairs() {
        let mut policy = ExactPairPolicy::empty();
        policy.insert(APP_A, RELAY).unwrap();
        policy.insert(APP_B, RELAY).unwrap();
        let canonical = policy.encode().unwrap();
        assert_eq!(ExactPairPolicy::recognise(&canonical).unwrap(), policy);

        for corrupt in [
            canonical.replace("\"version\":1", "\"version\":2"),
            canonical.replace("https://chat.anuna.io:9443", "http://chat.anuna.io:9443"),
            format!(" {canonical}"),
            serde_json::json!({
                "version": 1,
                "rows": [
                    {"application_id": APP_B, "relay_origin": RELAY},
                    {"application_id": APP_A, "relay_origin": RELAY}
                ]
            })
            .to_string(),
        ] {
            assert!(ExactPairPolicy::recognise(&corrupt).is_err(), "{corrupt}");
        }
    }
}
