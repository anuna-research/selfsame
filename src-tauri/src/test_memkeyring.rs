//! Shared process-local keyring for isolated native tests.
//! Install before any storage access; ignored callers run alone.

use keyring::credential::{Credential, CredentialApi, CredentialBuilderApi};
use std::any::Any;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub enum SetFailure {
    BeforeCommit,
    AfterCommit,
}

fn values() -> &'static Mutex<HashMap<String, Zeroizing<Vec<u8>>>> {
    static VALUES: OnceLock<Mutex<HashMap<String, Zeroizing<Vec<u8>>>>> = OnceLock::new();
    VALUES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_set_failure() -> &'static Mutex<Option<(String, SetFailure)>> {
    static FAILURE: OnceLock<Mutex<Option<(String, SetFailure)>>> = OnceLock::new();
    FAILURE.get_or_init(|| Mutex::new(None))
}

#[derive(Debug)]
struct SharedCredential {
    key: String,
}

impl CredentialApi for SharedCredential {
    fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
        let failure = {
            let mut configured = next_set_failure().lock().unwrap();
            if configured
                .as_ref()
                .is_some_and(|(user, _)| self.key.ends_with(user))
            {
                configured.take().map(|(_, mode)| mode)
            } else {
                None
            }
        };
        if matches!(failure, Some(SetFailure::BeforeCommit)) {
            return Err(keyring::Error::PlatformFailure(Box::new(
                std::io::Error::other("injected pre-commit set failure"),
            )));
        }
        values()
            .lock()
            .unwrap()
            .insert(self.key.clone(), Zeroizing::new(secret.to_vec()));
        if matches!(failure, Some(SetFailure::AfterCommit)) {
            return Err(keyring::Error::PlatformFailure(Box::new(
                std::io::Error::other("injected post-commit set failure"),
            )));
        }
        Ok(())
    }

    fn get_secret(&self) -> keyring::Result<Vec<u8>> {
        values()
            .lock()
            .unwrap()
            .get(&self.key)
            .map(|value| value.to_vec())
            .ok_or(keyring::Error::NoEntry)
    }

    fn delete_credential(&self) -> keyring::Result<()> {
        values().lock().unwrap().remove(&self.key);
        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Debug)]
struct Builder;

impl CredentialBuilderApi for Builder {
    fn build(
        &self,
        _target: Option<&str>,
        service: &str,
        user: &str,
    ) -> keyring::Result<Box<Credential>> {
        Ok(Box::new(SharedCredential {
            key: format!("{service}\u{0000}{user}"),
        }))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub fn install() {
    values().lock().unwrap().clear();
    *next_set_failure().lock().unwrap() = None;
    keyring::set_default_credential_builder(Box::new(Builder));
    assert_active();
}

/// Check the actual process default before any probe or custody operation.
pub fn assert_active() {
    assert!(keyring::Entry::new("spec077-host", "backend-check")
        .expect("memory entry construction")
        .get_credential()
        .is::<SharedCredential>());
}

/// Erase process-local test values. Never addresses an operating-system entry.
pub fn clear() {
    use zeroize::Zeroize;
    let mut stored = values().lock().unwrap();
    for value in stored.values_mut() {
        value.zeroize();
    }
    stored.clear();
    *next_set_failure().lock().unwrap() = None;
}

pub fn fail_next_set_for_user(user: &str, mode: SetFailure) {
    *next_set_failure().lock().unwrap() = Some((user.to_owned(), mode));
}
