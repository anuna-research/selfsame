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
    /// The next free `dev-N`, counted over the **whole history**.
    ///
    /// Not over the resolved document, which is what this did and is what made
    /// relinking impossible. `RevokeVerificationMethod` is a 2P-Set remove and
    /// the pinned method computes `authorized = added \ revoked`, so the
    /// resolved document stops listing a revoked method — and an allocator
    /// reading it concludes the number is free. It is not free. Re-adding a
    /// revoked id puts it back in `added` and leaves it in `revoked`, and the
    /// difference still excludes it.
    ///
    /// So unlinking `dev-1` and linking again handed the new device `dev-1`,
    /// which arrived already revoked and rendered as Unlinked the instant it
    /// linked. Every retry did the same thing, so an identity that had ever
    /// unlinked its only device could never link another.
    ///
    /// [`Self::devices`] below already walks the deltas rather than the
    /// resolved document, and says why in as many words. This is the same
    /// distinction, and the same source of truth.
    pub fn next_device_fragment(&self, document: &Document) -> String {
        let did = document.did.to_string();
        let prefix = format!("{did}#dev-");
        let highest = self
            .all_deltas()
            .unwrap_or_default()
            .iter()
            .filter_map(|delta| match &delta.op {
                did_crdt::core::delta::DeltaOp::AddVerificationMethod { id, .. } => {
                    id.strip_prefix(&prefix).and_then(|n| n.parse::<u32>().ok())
                }
                _ => None,
            })
            .max();
        format!("dev-{}", highest.map(|n| n + 1).unwrap_or(1))
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
    use ed25519_dalek::SigningKey;

    fn root() -> SigningKey {
        SigningKey::from_bytes(&[0x31; 32])
    }

    /// A session holding one identity with `count` devices added.
    ///
    /// `name` gives each test its own directory. `Session::load` reads whatever
    /// is already persisted there, so a shared path lets one test's deltas be
    /// counted by another's allocator — which is exactly the confusion this
    /// module is testing, arriving from the wrong direction.
    fn session_with_devices(name: &str, count: usize) -> (Session, Document, SigningKey) {
        let root = root();
        let (mut doc, genesis) = identity::sign_genesis(&root).expect("genesis signs");
        let dir = std::env::temp_dir().join(format!("selfsame-session-test-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        let mut session = Session::load(dir);
        session.record(&genesis);

        for n in 1..=count {
            let key = SigningKey::from_bytes(&[0x40 + n as u8; 32]).verifying_key().to_bytes();
            let add =
                identity::add_device(&doc, &root, &key, &format!("dev-{n}"), 1_000 + n as u64)
                    .expect("the device is added");
            doc.merge_verified_delta(add.clone()).expect("the add merges");
            session.record(&add);
        }
        (session, doc, root)
    }

    /// Unlinking a device must not free its method id for the next one.
    ///
    /// `RevokeVerificationMethod` is a 2P-Set remove and the pinned method
    /// computes `authorized = added \ revoked`, so a revoked id is gone for
    /// good: re-adding it puts it back in `added` and leaves it in `revoked`,
    /// and the difference still excludes it.
    ///
    /// The allocator used to count the methods in the **resolved** document,
    /// which by that same 2P-Set rule no longer contains the revoked one. So
    /// after unlinking `dev-1` the next device was offered `dev-1` again, was
    /// added to an id that was already revoked, and appeared as Unlinked the
    /// moment it linked. Every subsequent attempt did the same, so an identity
    /// that had ever unlinked its only device could never link one again.
    #[test]
    fn a_revoked_fragment_is_never_offered_again() {
        let (mut session, mut doc, root) = session_with_devices("revoked-fragment", 1);
        assert_eq!(session.next_device_fragment(&doc), "dev-2", "with dev-1 live");

        let revoke = identity::revoke_device(
            &doc,
            &root,
            &format!("{}#dev-1", doc.did),
            2_000,
        )
        .expect("the device is revoked");
        doc.merge_verified_delta(revoke.clone()).expect("the revoke merges");
        session.record(&revoke);

        assert_eq!(
            session.next_device_fragment(&doc),
            "dev-2",
            "dev-1 is revoked, and a revoked id can never be authorised again",
        );
    }

    /// The allocator counts history, so gaps do not reopen either.
    #[test]
    fn fragments_do_not_reopen_when_a_middle_device_is_revoked() {
        let (mut session, mut doc, root) = session_with_devices("middle-revoked", 3);
        let revoke =
            identity::revoke_device(&doc, &root, &format!("{}#dev-2", doc.did), 4_000)
                .expect("the device is revoked");
        doc.merge_verified_delta(revoke.clone()).expect("the revoke merges");
        session.record(&revoke);

        assert_eq!(
            session.next_device_fragment(&doc),
            "dev-4",
            "the hole left by dev-2 is not a free slot",
        );
    }
}
