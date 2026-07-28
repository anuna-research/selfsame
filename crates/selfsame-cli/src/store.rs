//! Local state for a linking client — the effectful half of ADR-004.
//!
//! Two files under `~/.config/selfsame/`:
//!
//! | File | Contents | Mode |
//! |---|---|---|
//! | `device.key` | the 32-byte Ed25519 seed — *the client's existing wire key* | `0600` |
//! | `identity.json` | the accepted DID and its signed deltas | `0600` |
//!
//! NFR-002 governs the first: the device private key is generated on the device
//! that uses it (REQ-004) and never leaves it. The mode is set at creation, not
//! afterwards, so there is no window in which it is world-readable.
//!
//! REQ-017's atomicity reaches down here too: `identity.json` is written to a
//! temporary file and renamed, so a crash mid-write cannot leave a client
//! holding half an identity.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use selfsame_core::AcceptedIdentity;
use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

pub struct Store {
    dir: PathBuf,
}

/// The on-disk form of an accepted identity.
///
/// The signed deltas are kept verbatim so the client can re-verify offline
/// (NFR-006) without asking anyone anything.
#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    did: String,
    own_method_id: String,
    root_public_key_multibase: String,
    /// Base64url-no-pad, one per delta — the same spelling the wire uses
    /// (REQ-027), so there is one binary encoding in the whole system.
    deltas: Vec<String>,
}

impl Store {
    pub fn open() -> Result<Self> {
        let dir = match std::env::var_os("SELFSAME_HOME") {
            Some(dir) => PathBuf::from(dir),
            None => {
                let base = std::env::var_os("XDG_CONFIG_HOME")
                    .map(PathBuf::from)
                    .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
                    .context("neither SELFSAME_HOME, XDG_CONFIG_HOME, nor HOME is set")?;
                base.join("selfsame")
            }
        };
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).ok();
        Ok(Self { dir })
    }

    /// Load the device key, generating it on first use.
    ///
    /// REQ-004: generated **on the device that will use it**, and its private
    /// half is never transmitted, exported, or escrowed — including to Anuna
    /// Key, which authorises the public half and never sees the private one.
    pub fn load_or_create_device_key(&self) -> Result<SigningKey> {
        let path = self.dir.join("device.key");
        if path.exists() {
            let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            let seed: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("{} is not a 32-byte seed", path.display()))?;
            return Ok(SigningKey::from_bytes(&seed));
        }

        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);

        // 0600 at creation: never a window where the key is world-readable.
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("creating {}", path.display()))?;
        file.write_all(&seed).with_context(|| format!("writing {}", path.display()))?;
        file.sync_all().ok();
        Ok(SigningKey::from_bytes(&seed))
    }

    pub fn load_identity(&self) -> Result<Option<AcceptedIdentity>> {
        let path = self.dir.join("identity.json");
        if !path.exists() {
            return Ok(None);
        }
        let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        let stored: StoredIdentity = serde_json::from_str(&text)
            .with_context(|| format!("{} is not a stored identity", path.display()))?;

        let root_public_key = selfsame_core::mb::decode_exact::<32>(&stored.root_public_key_multibase)
            .map_err(|e| anyhow::anyhow!("stored root key is not canonical: {e}"))?;
        let mut deltas = Vec::with_capacity(stored.deltas.len());
        for d in &stored.deltas {
            deltas.push(
                selfsame_core::mb::decode(d)
                    .map_err(|e| anyhow::anyhow!("stored delta is not canonical: {e}"))?,
            );
        }

        // Re-verify on load rather than trusting our own file: a client that
        // believes a tampered `identity.json` would render attribution it never
        // actually checked (REQ-009 fail-closed).
        let signed: Vec<did_crdt::core::delta::SignedDelta> = deltas
            .iter()
            .map(|b| serde_json::from_slice(b))
            .collect::<Result<_, _>>()
            .context("stored deltas are not signed deltas")?;
        let derived = selfsame_core::identity::derive_did(&root_public_key)?;
        if derived.as_str() != stored.did {
            bail!("stored identity does not commit to its own genesis — refusing to load it");
        }
        selfsame_core::profile::resolve_closure(&signed, &root_public_key)
            .map_err(|e| anyhow::anyhow!("stored identity fails the profile: {e}"))?;

        Ok(Some(AcceptedIdentity {
            fingerprint: selfsame_core::fingerprint_did(&stored.did),
            did: stored.did,
            root_public_key,
            own_method_id: stored.own_method_id,
            deltas,
            device_labels: Default::default(),
            declared_profile: None,
            dropped_document_data: Vec::new(),
        }))
    }

    pub fn save_identity(&self, identity: &AcceptedIdentity) -> Result<()> {
        let stored = StoredIdentity {
            did: identity.did.clone(),
            own_method_id: identity.own_method_id.clone(),
            root_public_key_multibase: selfsame_core::mb::encode(&identity.root_public_key),
            deltas: identity.deltas.iter().map(|d| selfsame_core::mb::encode(d)).collect(),
        };
        let json = serde_json::to_string_pretty(&stored)?;

        // Write-then-rename: REQ-017's atomicity, one layer down.
        let tmp = self.dir.join("identity.json.tmp");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(json.as_bytes())?;
        file.sync_all().ok();
        fs::rename(&tmp, self.dir.join("identity.json"))?;
        Ok(())
    }

    pub fn clear_identity(&self) -> Result<()> {
        let path = self.dir.join("identity.json");
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }
}
