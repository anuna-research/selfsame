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
    /// A `SPEC-004` grant that is signed and waiting on `CON-221`'s comparison.
    ///
    /// Held rather than re-derived so the person meets one presence prompt
    /// rather than two, and dropped on rejection — it was never transmitted, so
    /// having signed it conferred nothing.
    pub pending_issuance: Option<crate::app_grant::PendingIssuance>,
    /// The live `PROTO-003` ceremony, if there is one.
    ///
    /// `CON-407` requires the binding, the code, the role token and the terminal
    /// state to be held "in process-private memory". This field is that memory,
    /// and it is why the pairing commands take a `binding_hash` rather than the
    /// code: the page names the ceremony, and holds none of it.
    ///
    /// Never persisted. [`Session::save`] writes `state` alone, and `NFR-403`
    /// requires pairing metadata to be ephemeral.
    pub pending_pairing: Option<crate::pairing::PendingPairing>,
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
        Self {
            path: Some(path),
            state,
            pending_offer: None,
            pending_issuance: None,
            pending_pairing: None,
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

    /// A fragment is never reissued, so a revoked one can never come back.
    ///
    /// This is the property the counter kept getting wrong. It is stated over
    /// the generator rather than over an allocator, because there is no longer
    /// an allocator to state it over — which is the point of the change.
    #[test]
    fn every_fragment_is_new() {
        let seen: HashSet<String> = (0..10_000).map(|_| Session::new_device_fragment()).collect();
        assert_eq!(seen.len(), 10_000, "64 random bits collided, which they do not");
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
            let rest = f.strip_prefix("dev-").expect("the `dev-` prefix names what it is");
            assert_eq!(rest.len(), 16, "64 bits as hex: {f}");
            assert!(
                rest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "lower-case hex only, so the id is stable under any case handling: {f}"
            );
        }
    }
}
