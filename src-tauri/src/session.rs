//! Identity state on the phone — SPEC-001 REQ-020, REQ-021, OBS-005.
//!
//! Three things live here and nowhere else:
//!
//! 1. **The signed closure** — every delta this identity has produced, kept so
//!    the devices list works with no network at all.
//! 2. **The publication queue** — deltas signed but not yet acknowledged by the
//!    resolver. REQ-020 requires publication be retried until acknowledged and
//!    that *a pending publication be visible to the user*; the queue is what
//!    makes both true, and OBS-005 is its depth.
//! 3. **The offer under consideration** — the one SCREEN-001 is displaying,
//!    held only between reading the code and the user's decision, and dropped
//!    on cancel so nothing survives (SCREEN-001: *"the screen holds no state
//!    that survives cancellation"*).
//!
//! # Why the closure is cached and the labels are not local
//!
//! REQ-021 puts each device's label in **signed state** rather than in a local
//! list, because a phone restored from the mnemonic holds no local list — and
//! the HP-5 revoke screen cannot name what it is revoking without one. The
//! cache here is a performance and offline affordance over that signed state,
//! never the source of truth: [`Session::adopt_closure`] replaces it wholesale
//! from the resolver, and every read resolves through the profile filter.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex, Weak},
};

use crate::commands::UiError;
use did_crdt::core::delta::SignedDelta;
use did_crdt::core::document::Document;
use selfsame_core::{identity, profile, record::Offer};
use serde::{Deserialize, Serialize};

/// Fixed entry mode. Persisting this provenance grants no live execution authority.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CredentialV2Flow {
    SingleLink,
    #[default]
    LegacyTwoDecision,
}
impl CredentialV2Flow {
    pub(crate) fn is_legacy(&self) -> bool {
        *self == Self::LegacyTwoDecision
    }
}

struct AttemptState {
    terminal: Option<&'static str>,
    mode: CredentialV2Flow,
    tag: String,
    root_generation: Option<[u8; 32]>,
    deadline: Option<crate::cbcl_v2_clock::Deadline>,
    entered: usize,
    custody: Option<selfsame_app_identity::hierarchy::HierarchyRoot>,
    #[cfg(test)]
    clock: Option<Option<crate::cbcl_v2_clock::Snapshot>>,
}

/// Arc identity is the non-wrapping native generation. Revocation and effect
/// entry share this mutex even while a blocking worker owns the socket/root.
#[derive(Clone)]
pub(crate) struct CredentialV2Attempt(Arc<Mutex<AttemptState>>);

impl Default for CredentialV2Attempt {
    fn default() -> Self {
        use rand::RngCore as _;
        let mut bytes = [0; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(Arc::new(Mutex::new(AttemptState {
            terminal: None,
            mode: CredentialV2Flow::LegacyTwoDecision,
            tag: bytes.iter().map(|b| format!("{b:02x}")).collect(),
            root_generation: None,
            deadline: None,
            entered: 0,
            custody: None,
            #[cfg(test)]
            clock: None,
        })))
    }
}

/// An entered effect is owned by its worker/transaction, never a permission to
/// start another effect. Dropping it cannot clear the revocation fence.
pub(crate) struct CredentialV2Effect(CredentialV2Attempt);
impl Drop for CredentialV2Effect {
    fn drop(&mut self) {
        self.0 .0.lock().unwrap_or_else(|p| p.into_inner()).entered -= 1;
    }
}

impl CredentialV2Attempt {
    fn check_locked(state: &mut AttemptState) -> Result<(), UiError> {
        if let Some(error) = state.terminal {
            return Err(UiError::from(error));
        }
        let checked = (|| {
            if let Some(expected) = state.root_generation {
                let key = crate::custody::Custody::root_public_key()
                    .map_err(|_| UiError::from("PairingRootChanged"))?;
                if crate::cbcl_v2_completion::root_generation(&key) != expected {
                    return Err(UiError::from("PairingRootChanged"));
                }
            }
            if state.mode == CredentialV2Flow::SingleLink {
                #[cfg(not(test))]
                let now = crate::cbcl_v2_clock::snapshot()?;
                #[cfg(test)]
                let now = match state.clock {
                    None => crate::cbcl_v2_clock::snapshot()?,
                    Some(Some(now)) => now,
                    Some(None) => return Err(UiError::from("PairingClockUnavailable")),
                };
                if let Some(bound) = state.deadline.as_mut() {
                    bound.check(now)?;
                }
            }
            Ok(())
        })();
        if let Err(ref error) = checked {
            state.custody = None;
            state.terminal = Some(match error.to_string().as_str() {
                "PairingExpired" => "PairingExpired",
                "PairingRootChanged" => "PairingRootChanged",
                _ => "PairingClockUnavailable",
            });
        }
        checked
    }
    pub(crate) fn check(&self) -> Result<(), UiError> {
        Self::check_locked(&mut self.0.lock().unwrap_or_else(|p| p.into_inner()))
    }
    pub(crate) fn enter(&self) -> Result<CredentialV2Effect, UiError> {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        Self::check_locked(&mut state)?;
        state.entered = state
            .entered
            .checked_add(1)
            .ok_or_else(|| UiError::from("PairingFailed"))?;
        Ok(CredentialV2Effect(self.clone()))
    }
    pub(crate) fn run<T>(&self, action: impl FnOnce() -> Result<T, UiError>) -> Result<T, UiError> {
        let _entry = self.enter()?;
        let value = action()?;
        self.check()?;
        Ok(value)
    }
    /// Register I/O before polling it, and refuse every resumed poll after the
    /// fence. A completed future is checked before its result can enable work.
    pub(crate) async fn io<T>(
        &self,
        future: impl std::future::Future<Output = Result<T, UiError>>,
    ) -> Result<T, UiError> {
        let _entry = self.enter()?;
        let mut future = std::pin::pin!(future);
        let mut pulse = Box::pin(tokio::time::sleep(std::time::Duration::from_millis(50)));
        let value = std::future::poll_fn(|cx| {
            if let Err(error) = self.check() {
                return std::task::Poll::Ready(Err(error));
            }
            use std::future::Future as _;
            if pulse.as_mut().poll(cx).is_ready() {
                pulse
                    .as_mut()
                    .reset(tokio::time::Instant::now() + std::time::Duration::from_millis(50));
                let _ = pulse.as_mut().poll(cx);
            }
            future.as_mut().poll(cx)
        })
        .await?;
        self.check()?;
        Ok(value)
    }
    pub(crate) fn mode(&self) -> CredentialV2Flow {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).mode
    }
    pub(crate) fn tag(&self) -> String {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).tag.clone()
    }
    #[cfg(test)]
    pub(crate) fn test_clock(&self, now: Option<crate::cbcl_v2_clock::Snapshot>) {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clock = Some(now);
    }
    #[cfg(test)]
    pub(crate) fn test_has_custody(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .custody
            .is_some()
    }
    pub(crate) fn clear_custody(&self) {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).custody = None;
    }
    pub(crate) fn require_mode(&self, mode: CredentialV2Flow) -> Result<(), UiError> {
        if self.mode() != mode {
            return Err(UiError::from("PairingWrongMode"));
        }
        Ok(())
    }
    pub(crate) fn bind_deadline(
        &self,
        start: crate::cbcl_v2_clock::Snapshot,
        offer: u64,
        relay: u64,
    ) -> Result<(), UiError> {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        Self::check_locked(&mut state)?;
        if state.mode != CredentialV2Flow::SingleLink || state.deadline.is_some() {
            return Err(UiError::from("PairingWrongPhase"));
        }
        state.deadline = Some(crate::cbcl_v2_clock::Deadline::new(start, offer, relay)?);
        Self::check_locked(&mut state)
    }
    fn cancel(&self) {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        state.terminal = Some("PairingCancelled");
        state.custody = None;
    }
    pub(crate) fn retain_custody(
        &self,
        root: selfsame_app_identity::hierarchy::HierarchyRoot,
    ) -> Result<(), UiError> {
        {
            let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
            Self::check_locked(&mut state)?;
            if state.deadline.is_none() || state.custody.is_some() {
                return Err(UiError::from("PairingWrongPhase"));
            }
            state.custody = Some(root);
        }
        let weak = Arc::downgrade(&self.0);
        // This watchdog owns no worker lease or root. Continuous-time checks
        // also run on every effect and wake after OS suspension.
        std::thread::Builder::new()
            .name("pairing-custody-expiry".into())
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_millis(50));
                let Some(inner) = weak.upgrade() else {
                    break;
                };
                let mut state = inner.lock().unwrap_or_else(|p| p.into_inner());
                if Self::check_locked(&mut state).is_err() || state.custody.is_none() {
                    break;
                }
            })
            .map_err(|_| {
                self.cancel();
                UiError::from("PairingFailed")
            })?;
        Ok(())
    }
    pub(crate) fn with_custody<T>(
        &self,
        action: impl FnOnce(&selfsame_app_identity::hierarchy::HierarchyRoot) -> Result<T, UiError>,
    ) -> Result<T, UiError> {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        Self::check_locked(&mut state)?;
        // Synchronous root access and its entry are indivisible with revocation.
        let root = state
            .custody
            .as_ref()
            .ok_or_else(|| UiError::from("PairingExpired"))?;
        let result = action(root)?;
        Self::check_locked(&mut state)?;
        Ok(result)
    }
}

/// Retained even while a command owns the socket. The weak lease bounds work
/// across cancellation, including a spawn_blocking closure whose future died.
#[derive(Default)]
pub(crate) struct CredentialV2Attempts {
    current: Option<CredentialV2Attempt>,
    worker: Weak<()>,
    background: bool,
    root_change: Arc<std::sync::atomic::AtomicBool>,
}

/// Shared with a root-writing blocking worker so dropping its caller cannot
/// admit a new ceremony while the old root is being replaced.
pub(crate) struct CredentialV2RootChange(Arc<std::sync::atomic::AtomicBool>);
impl Drop for CredentialV2RootChange {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

pub(crate) struct CredentialV2Operation {
    pub(crate) attempt: CredentialV2Attempt,
    lease: Arc<()>,
    retained: bool,
}

impl CredentialV2Operation {
    pub(crate) fn lease(&self) -> Arc<()> {
        self.lease.clone()
    }

    pub(crate) fn retain(mut self) {
        self.retained = true;
    }
}

impl Drop for CredentialV2Operation {
    fn drop(&mut self) {
        if !self.retained {
            self.attempt.cancel();
        }
    }
}

impl CredentialV2Attempts {
    pub(crate) fn begin(&mut self) -> Result<CredentialV2Operation, UiError> {
        self.require_stable_root()?;
        if self.background {
            return Err(UiError::from("PairingCancelled"));
        }
        if self.worker.upgrade().is_some()
            || self.current.as_ref().is_some_and(|attempt| {
                attempt
                    .0
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .terminal
                    .is_none()
            })
        {
            return Err(UiError::from("PairingAlreadyActive"));
        }
        self.current = Some(CredentialV2Attempt::default());
        self.start_work()
    }

    pub(crate) fn require_entry_mode(&self, mode: CredentialV2Flow) -> Result<(), UiError> {
        if let Some(current) = &self.current {
            if current
                .0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .terminal
                .is_none()
                || self.worker.upgrade().is_some()
            {
                current.require_mode(mode)?;
            }
        }
        Ok(())
    }
    pub(crate) fn begin_single_link(&mut self) -> Result<CredentialV2Operation, UiError> {
        self.require_entry_mode(CredentialV2Flow::SingleLink)?;
        self.require_stable_root()?;
        crate::cbcl_v2_clock::snapshot()?;
        let root = crate::custody::Custody::root_public_key()?;
        let operation = self.begin()?;
        {
            let mut state = operation
                .attempt
                .0
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            state.mode = CredentialV2Flow::SingleLink;
            state.root_generation = Some(crate::cbcl_v2_completion::root_generation(&root));
        }
        operation.attempt.check()?;
        Ok(operation)
    }
    pub(crate) fn require_mode(&self, mode: CredentialV2Flow) -> Result<(), UiError> {
        if let Some(current) = &self.current {
            current.require_mode(mode)?;
        }
        Ok(())
    }
    pub(crate) fn tagged(&self, tag: &str) -> Result<CredentialV2Attempt, UiError> {
        let current = self
            .current
            .as_ref()
            .ok_or_else(|| UiError::from("PairingStaleAttempt"))?;
        current.require_mode(CredentialV2Flow::SingleLink)?;
        if current.tag() != tag {
            return Err(UiError::from("PairingStaleAttempt"));
        }
        Ok(current.clone())
    }
    pub(crate) fn foreground(&mut self, foreground: bool) {
        self.background = !foreground;
        if !foreground {
            self.cancel();
        }
    }

    fn require_stable_root(&self) -> Result<(), UiError> {
        if self.root_change.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(UiError::from("PairingRootChanged"));
        }
        Ok(())
    }

    fn begin_root_change(&mut self) -> Result<Arc<CredentialV2RootChange>, UiError> {
        use std::sync::atomic::Ordering::SeqCst;
        self.root_change
            .compare_exchange(false, true, SeqCst, SeqCst)
            .map_err(|_| UiError::from("PairingRootChanged"))?;
        self.cancel();
        Ok(Arc::new(CredentialV2RootChange(self.root_change.clone())))
    }

    pub(crate) fn start_work(&mut self) -> Result<CredentialV2Operation, UiError> {
        if self.worker.upgrade().is_some() {
            return Err(UiError::from("PairingAlreadyActive"));
        }
        let attempt = self
            .current
            .clone()
            .ok_or_else(|| UiError::from("PairingNotStarted"))?;
        attempt.check()?;
        let lease = Arc::new(());
        self.worker = Arc::downgrade(&lease);
        Ok(CredentialV2Operation {
            attempt,
            lease,
            retained: false,
        })
    }

    /// Caller holds the Session mutex through this check and state insertion.
    pub(crate) fn ensure_current(&self, attempt: &CredentialV2Attempt) -> Result<(), UiError> {
        if !self
            .current
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(&current.0, &attempt.0))
        {
            return Err(UiError::from("PairingCancelled"));
        }
        attempt.check()
    }

    pub(crate) fn cancel(&mut self) {
        if let Some(attempt) = &self.current {
            attempt.cancel();
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("no identity on this device")]
    NoIdentity,
    #[error("stored state is not readable: {0}")]
    Unreadable(String),
    #[error("stored state failed the single-controller profile: {0}")]
    Profile(String),
}

/// What is written to disk. **No key material of any kind.**
#[derive(Default, Serialize, Deserialize)]
struct Persisted {
    /// Multibase-`u` deltas, in the exact bytes the signer produced — REQ-003
    /// hashes those bytes, so a re-serialisation is not the same artefact.
    closure: Vec<String>,
    /// Deltas signed but not yet acknowledged (REQ-020, OBS-005).
    pending: Vec<String>,
    /// Local-only, explicitly not reconstructible from signed state (REQ-021).
    last_seen: std::collections::BTreeMap<String, u64>,
}

/// The in-process session.
#[derive(Default)]
pub struct Session {
    path: Option<PathBuf>,
    state: Persisted,
    /// The offer SCREEN-001 is currently displaying, with the secret that
    /// reached it. Dropped on cancel, on authorise, and on expiry.
    pub pending_offer: Option<PendingOffer>,
    /// A `SPEC-004` grant that is signed and waiting on `CON-221`'s comparison.
    ///
    /// Held rather than re-derived so the person meets one presence prompt
    /// rather than two, and dropped on rejection — it was never transmitted, so
    /// having signed it conferred nothing.
    pub pending_issuance: Option<crate::app_grant::PendingIssuance>,
    /// The live one-sided cbcl claimant. Never persisted or exposed to the
    /// page. One type for every build (SPEC-008 `REQ-903`): ordinary builds
    /// hold a live session over TLS, the demo build over its loopback socket.
    pub pending_cbcl_pairing: Option<crate::cbcl_pairing::PendingCbclPairing>,
    /// Pre-socket standalone credential/v2 relay decision. The PAIR1 value is
    /// memory-only and is consumed before any relay connection is created.
    pub pending_cbcl_v2_relay: Option<crate::cbcl_v2_claimant::RelayConsentPlan>,
    /// Live standalone credential/v2 claimant after the exact relay decision.
    pub pending_cbcl_v2: Option<crate::cbcl_v2_commands::PendingCredentialV2Pairing>,
    pub(crate) cbcl_v2_attempts: CredentialV2Attempts,
    pub(crate) pending_cbcl_v2_entry: Option<crate::cbcl_v2_claimant::RecognisedCredentialV2Entry>,
    pub(crate) pending_cbcl_v2_execution:
        Option<crate::cbcl_v2_commands::single_link::LinkExecution>,
    /// A first-contact CON-219 enrolment fetched from the rendezvous and
    /// reviewed, held between the consent screen and the person's decision
    /// (`IMPL-008` `ADR-913`). Never exposed to the page: the offer plaintext
    /// carries the private account scope. Dropped on cancel, on confirm, and
    /// when a fresh enrolment displaces it.
    pub pending_enrolment: Option<crate::app_grant::PendingEnrolment>,
}

/// An offer that has been fetched, recognised, and signature-verified, and is
/// now waiting for the user's decision.
pub struct PendingOffer {
    pub offer: Offer,
    pub secret: [u8; 16],
    /// Wall-clock second at which the offer stops being authorisable.
    pub expires_at: u64,
}

impl Session {
    pub(crate) fn begin_cbcl_v2_root_change(
        &mut self,
    ) -> Result<Arc<CredentialV2RootChange>, UiError> {
        let guard = self.cbcl_v2_attempts.begin_root_change()?;
        self.revoke_cbcl_v2();
        Ok(guard)
    }
    pub(crate) fn revoke_cbcl_v2(&mut self) {
        self.cbcl_v2_attempts.cancel();
        self.pending_cbcl_v2_entry = None;
        self.pending_cbcl_v2_execution = None;
        self.pending_cbcl_v2_relay = None;
        self.pending_cbcl_v2 = None;
    }

    /// The caller owns the Session mutex through both generation validation
    /// and the update. Used for profile results and live-socket reinsertion.
    pub(crate) fn update_cbcl_v2_attempt<T>(
        &mut self,
        attempt: &CredentialV2Attempt,
        update: impl FnOnce(&mut Self) -> Result<T, UiError>,
    ) -> Result<T, UiError> {
        self.cbcl_v2_attempts.ensure_current(attempt)?;
        update(self)
    }

    /// Load persisted state from the app data directory.
    pub fn load(dir: PathBuf) -> Self {
        let path = dir.join("identity-state.json");
        let state = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Self {
            path: Some(path),
            state,
            pending_offer: None,
            pending_issuance: None,
            pending_cbcl_pairing: None,
            pending_cbcl_v2_relay: None,
            pending_cbcl_v2: None,
            cbcl_v2_attempts: CredentialV2Attempts::default(),
            pending_cbcl_v2_entry: None,
            pending_cbcl_v2_execution: None,
            pending_enrolment: None,
        }
    }

    fn save(&self) {
        let Some(path) = &self.path else { return };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&self.state) {
            // Write-then-rename so a crash cannot leave half a closure.
            let tmp = path.with_extension("tmp");
            if std::fs::write(&tmp, json).is_ok() {
                let _ = std::fs::rename(&tmp, path);
            }
        }
    }

    /// Is there a closure at all?
    pub fn is_empty(&self) -> bool {
        self.state.closure.is_empty()
    }

    fn decode(list: &[String]) -> Result<Vec<SignedDelta>, SessionError> {
        list.iter()
            .map(|s| {
                let bytes = selfsame_core::mb::decode(s)
                    .map_err(|e| SessionError::Unreadable(e.to_string()))?;
                serde_json::from_slice(&bytes).map_err(|e| SessionError::Unreadable(e.to_string()))
            })
            .collect()
    }

    /// Every delta this identity has, published or not.
    ///
    /// Pending deltas are included: from the user's point of view they have
    /// happened — the phone signed them — and the devices list must show a
    /// just-linked device even while its publication is still in flight.
    pub fn all_deltas(&self) -> Result<Vec<SignedDelta>, SessionError> {
        let mut out = Self::decode(&self.state.closure)?;
        out.extend(Self::decode(&self.state.pending)?);
        Ok(out)
    }

    /// Resolve the identity locally, through the single-controller profile.
    pub fn document(&self, root_public_key: &[u8; 32]) -> Result<Document, SessionError> {
        if self.is_empty() {
            return Err(SessionError::NoIdentity);
        }
        profile::resolve_closure(&self.all_deltas()?, root_public_key)
            .map_err(|e| SessionError::Profile(e.to_string()))
    }

    /// Record a freshly signed delta and queue it for publication (REQ-020).
    pub fn record(&mut self, delta: &SignedDelta) {
        if let Ok(bytes) = serde_json::to_vec(delta) {
            self.state.pending.push(selfsame_core::mb::encode(&bytes));
            self.save();
        }
    }

    /// The deltas still awaiting acknowledgement — OBS-005's gauge, and what
    /// SCREEN-002's *"1 change still publishing"* line counts.
    pub fn pending(&self) -> Result<Vec<SignedDelta>, SessionError> {
        Self::decode(&self.state.pending)
    }

    pub fn pending_count(&self) -> usize {
        self.state.pending.len()
    }

    /// Mark a delta acknowledged: move it from pending into the closure.
    pub fn acknowledge(&mut self, delta: &SignedDelta) {
        let Ok(bytes) = serde_json::to_vec(delta) else {
            return;
        };
        let encoded = selfsame_core::mb::encode(&bytes);
        if let Some(i) = self.state.pending.iter().position(|p| *p == encoded) {
            let acknowledged = self.state.pending.remove(i);
            if !self.state.closure.contains(&acknowledged) {
                self.state.closure.push(acknowledged);
            }
            self.save();
        }
    }

    /// Replace the cached closure from the resolver — the restore path.
    ///
    /// Pending deltas are kept: they are ours, they are signed, and the
    /// resolver simply has not caught up yet.
    pub fn adopt_closure(&mut self, deltas: &[SignedDelta]) {
        self.state.closure = deltas
            .iter()
            .filter_map(|d| serde_json::to_vec(d).ok())
            .map(|b| selfsame_core::mb::encode(&b))
            .collect();
        self.state
            .pending
            .retain(|p| !self.state.closure.contains(p));
        self.save();
    }

    /// Local-only UX, explicitly not reconstructible (REQ-021).
    pub fn note_seen(&mut self, method_id: &str, at: u64) {
        self.state.last_seen.insert(method_id.to_owned(), at);
        self.save();
    }

    pub fn last_seen(&self, method_id: &str) -> Option<u64> {
        self.state.last_seen.get(method_id).copied()
    }

    /// Forget everything local. Does not revoke — revocation needs the root key
    /// and a published delta, which is a different act entirely.
    pub fn clear(&mut self) {
        self.state = Persisted::default();
        self.pending_offer = None;
        self.save();
    }

    /// The next unused device fragment — `dev-1`, `dev-2`, …
    ///
    /// Derived from the document rather than from a counter, so a restored
    /// phone continues the sequence instead of colliding with a method id that
    /// already exists in signed state.
    /// A fresh device fragment: `dev-` and 64 random bits.
    ///
    /// # Why not a counter
    ///
    /// This was `dev-N`, allocated by counting the methods already present, and
    /// counting is where the whole difficulty lived. `RevokeVerificationMethod`
    /// is a 2P-Set remove and the pinned method computes
    /// `authorized = added \ revoked`, so a revoked id is retired **for good**:
    /// re-adding it puts it back in `added`, leaves it in `revoked`, and the
    /// difference still excludes it. An allocator therefore has to count
    /// history rather than live methods — and the first version counted the
    /// resolved document, which by that same rule no longer lists a revoked
    /// method. So unlinking `dev-1` freed the number, the next device was handed
    /// an id that was already revoked, and it arrived dead. Every retry did the
    /// same, so an identity that had ever unlinked its only device could never
    /// link another.
    ///
    /// Counting history fixes it — but only while the history is complete, and
    /// this design does not promise that. `restore_identity` fetches the closure
    /// inside an `if let Ok(...)` and completes regardless, because the cache is
    /// "a performance and offline affordance". Restore with the resolver
    /// unreachable and the phone holds no deltas, so a derived counter says
    /// `dev-1` on an identity that already has one: dead if that id was revoked,
    /// and colliding with a *live* device if it was not. A locally stored
    /// counter is worse still, since `REQ-021` exists precisely because a
    /// restored phone holds no local state.
    ///
    /// Not counting removes the condition rather than satisfying it. A random
    /// fragment is correct with no history at all.
    ///
    /// # Why 64 bits and not more
    ///
    /// This is an identifier inside one identity's verification-method set, not
    /// a secret. It has to be unique among the handful of ids that identity will
    /// ever hold, revoked ones included — it does not have to be unguessable,
    /// because it is published in the DID document the moment it exists.
    /// At 64 bits the birthday bound over a hundred devices is about 3e-16.
    ///
    /// The first version used 128, copied from the link secret without thinking
    /// about it. That secret is drawn against an attacker who gets to try;
    /// this is drawn against coincidence. Same generator, different question,
    /// and the answer is half the width on a line a person reads.
    ///
    /// # Why not the key
    ///
    /// Deriving the fragment from the device's public key is the other obvious
    /// way to avoid a counter, and it is worse than either. `ADR-004` has a
    /// relinking device present the *same* key — "linking adds no new key
    /// material" — so a key-derived fragment is the same fragment, which is the
    /// revoked one, and there is no next one to pick. That makes the defect
    /// above permanent by construction rather than by accident.
    ///
    /// It also publishes a correlation handle. Two identities that both link
    /// one device would each carry `#<H(key)>`, and these documents go to
    /// resolvers — so anyone reading both learns they share a device. A random
    /// fragment says nothing about the key it names.
    pub fn new_device_fragment() -> String {
        use rand::RngCore as _;
        let mut octets = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut octets);
        let mut out = String::with_capacity(4 + 16);
        out.push_str("dev-");
        for b in octets {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    /// Every verification method, revoked ones included, as the devices list
    /// needs them (SCREEN-002).
    pub fn devices(&self, root_public_key: &[u8; 32]) -> Result<Vec<DeviceRow>, SessionError> {
        let document = self.document(root_public_key)?;
        let did = document.did.to_string();
        let root_id = identity::root_method_id(&document.did);

        // The resolved document excludes revoked methods (2P-Set semantics), so
        // walk the deltas for the full history: HP-5's list shows what *was*
        // linked, marked as unlinked, not a gap where a device used to be.
        let mut rows: Vec<DeviceRow> = Vec::new();
        for delta in self.all_deltas()? {
            if let did_crdt::core::delta::DeltaOp::AddVerificationMethod {
                id,
                public_key_multibase,
                ..
            } = &delta.op
            {
                if *id == root_id {
                    continue;
                }
                // The row's nickname and its picture. SCREEN-002 names a device
                // by its label — a recognition aid, exactly the job
                // `Fingerprint::label` is for. Nothing here is compared, so the
                // ≈18.6 bits it carries are the right size rather than a
                // shortfall.
                //
                // The picture rides along for SPEC-002 REQ-101: a recognition
                // aid the user meets only on the authorise screen has had no
                // chance to become recognisable. The device list is where they
                // see these most often, and therefore where the recognition is
                // actually built.
                let fingerprint = selfsame_core::mb::decode_exact::<32>(public_key_multibase)
                    .ok()
                    .map(|pk| selfsame_core::fingerprint::fingerprint_key(&pk));
                rows.push(DeviceRow {
                    method_id: id.clone(),
                    label: identity::device_label(&document, id),
                    nickname: fingerprint.map(|f| f.label()),
                    lifehash: fingerprint.map(|f| f.lifehash().base64()),
                    revoked: document.is_vm_revoked(id),
                    last_seen: self.last_seen(id),
                    pending: self.is_pending(&delta),
                });
            }
        }
        let _ = did;
        Ok(rows)
    }

    fn is_pending(&self, delta: &SignedDelta) -> bool {
        serde_json::to_vec(delta)
            .map(|b| self.state.pending.contains(&selfsame_core::mb::encode(&b)))
            .unwrap_or(false)
    }
}

/// One row of the devices list.
#[derive(Serialize)]
pub struct DeviceRow {
    pub method_id: String,
    pub label: Option<String>,
    /// `Fingerprint::label` of this device's key — `copper-lynx-42`. Names the
    /// row; never compared. `None` if the stored key is unreadable, which the
    /// UI renders by simply omitting it rather than showing a placeholder.
    pub nickname: Option<String>,
    /// The LifeHash of this device's key, Base64 (SPEC-002 CON-102). `None` on
    /// the same unreadable-key path as `nickname`, and omitted the same way:
    /// the row still has its name and its state, which is what the list is for.
    pub lifehash: Option<String>,
    pub revoked: bool,
    pub last_seen: Option<u64>,
    /// True while this device's `AddVerificationMethod` is still unpublished —
    /// SCREEN-002's *"publishing — others can't see it yet"*.
    pub pending: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn scan_preview_cancelled_generation_cannot_restore_or_replace_new_attempt() {
        let mut session = Session::default();
        let work = session.cbcl_v2_attempts.begin().unwrap();
        let stale = work.attempt.clone();
        session
            .update_cbcl_v2_attempt(&stale, |session| {
                session.state.last_seen.insert("test-view".into(), 1);
                Ok(())
            })
            .unwrap();
        session.cbcl_v2_attempts.cancel();
        drop(work);
        assert!(session
            .update_cbcl_v2_attempt(&stale, |session| {
                session.state.last_seen.insert("test-view".into(), 9);
                Ok(())
            })
            .is_err());
        let fresh = session.cbcl_v2_attempts.begin().unwrap();
        session
            .update_cbcl_v2_attempt(&fresh.attempt, |session| {
                session.state.last_seen.insert("test-view".into(), 2);
                Ok(())
            })
            .unwrap();
        assert!(session
            .update_cbcl_v2_attempt(&stale, |session| {
                session.state.last_seen.insert("test-view".into(), 9);
                Ok(())
            })
            .is_err());
        assert_eq!(session.last_seen("test-view"), Some(2));
        assert!(session
            .cbcl_v2_attempts
            .ensure_current(&CredentialV2Attempt::default())
            .is_err());
        session
            .cbcl_v2_attempts
            .ensure_current(&fresh.attempt)
            .unwrap();
        assert!(stale.run(|| Ok(())).is_err());
    }

    #[test]
    fn scan_preview_profile_wait_and_aborted_worker_hold_one_attempt() {
        let mut attempts = CredentialV2Attempts::default();
        let recognition = attempts.begin().unwrap();
        assert!(attempts.begin().is_err());
        let worker_lease = recognition.lease();
        let stale = recognition.attempt.clone();
        attempts.cancel();
        drop(recognition);
        assert!(attempts.begin().is_err());
        drop(worker_lease);
        let current = attempts.begin().unwrap();
        assert!(attempts.ensure_current(&stale).is_err());
        attempts.ensure_current(&current.attempt).unwrap();
    }

    /// A fragment is never reissued, so a revoked one can never come back.
    ///
    /// This is the property the counter kept getting wrong. It is stated over
    /// the generator rather than over an allocator, because there is no longer
    /// an allocator to state it over — which is the point of the change.
    #[test]
    fn every_fragment_is_new() {
        let seen: HashSet<String> = (0..10_000)
            .map(|_| Session::new_device_fragment())
            .collect();
        assert_eq!(
            seen.len(),
            10_000,
            "64 random bits collided, which they do not"
        );
    }

    /// The shape a DID URL fragment has to have.
    ///
    /// `dev-` and 16 lower-case hex characters. Asserted because the fragment is
    /// concatenated into `did:crdt:…#<fragment>` and that identifier is compared
    /// as text by every verifier — a character outside the fragment grammar
    /// would produce an id that is signed here and rejected elsewhere.
    #[test]
    fn a_fragment_is_dev_and_sixteen_hex_characters() {
        for _ in 0..100 {
            let f = Session::new_device_fragment();
            let rest = f
                .strip_prefix("dev-")
                .expect("the `dev-` prefix names what it is");
            assert_eq!(rest.len(), 16, "64 bits as hex: {f}");
            assert!(
                rest.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "lower-case hex only, so the id is stable under any case handling: {f}"
            );
        }
    }
}
