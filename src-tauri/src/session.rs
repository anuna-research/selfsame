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

use std::path::PathBuf;

use selfsame_core::{identity, profile, record::Offer};
use did_crdt::core::delta::SignedDelta;
use did_crdt::core::document::Document;
use serde::{Deserialize, Serialize};

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
    /// Load persisted state from the app data directory.
    pub fn load(dir: PathBuf) -> Self {
        let path = dir.join("identity-state.json");
        let state = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Self { path: Some(path), state, pending_offer: None }
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
        let Ok(bytes) = serde_json::to_vec(delta) else { return };
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
        self.state.pending.retain(|p| !self.state.closure.contains(p));
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
    pub fn next_device_fragment(&self, document: &Document) -> String {
        let did = document.did.to_string();
        let used: Vec<u32> = document
            .resolve()
            .ok()
            .and_then(|r| r.did_document)
            .map(|d| {
                d.verification_method
                    .iter()
                    .filter_map(|vm| {
                        vm.id.strip_prefix(&format!("{did}#dev-")).and_then(|n| n.parse().ok())
                    })
                    .collect()
            })
            .unwrap_or_default();
        format!("dev-{}", used.iter().max().map(|n| n + 1).unwrap_or(1))
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
                // The row's nickname. SCREEN-002 names a device by its label —
                // a recognition aid, exactly the job `Fingerprint::label` is
                // for. Nothing here is compared, so the ≈18.6 bits it carries
                // are the right size rather than a shortfall.
                let nickname = selfsame_core::mb::decode_exact::<32>(public_key_multibase)
                    .ok()
                    .map(|pk| selfsame_core::fingerprint::fingerprint_key(&pk).label());
                rows.push(DeviceRow {
                    method_id: id.clone(),
                    label: identity::device_label(&document, id),
                    nickname,
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
    pub revoked: bool,
    pub last_seen: Option<u64>,
    /// True while this device's `AddVerificationMethod` is still unpublished —
    /// SCREEN-002's *"publishing — others can't see it yet"*.
    pub pending: bool,
}
