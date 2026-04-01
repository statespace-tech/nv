//! Per-project encrypted secrets store.
//!
//! Secrets are stored in `.nenv/secrets.enc` encrypted with AES-256-GCM.
//! The project key lives in `~/.config/nv/keys/<project-id>` (mode 0600),
//! or is supplied via the `NV_KEY` environment variable (base64-encoded).
//!
//! File format: `[ nonce: 12 bytes ][ AES-256-GCM ciphertext + 16-byte tag ]`
//! The plaintext is a JSON-serialized `HashMap<String, String>` keyed as
//! `"<host>:<field>"` (e.g. `"api.openai.com:token"`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use rand::RngCore;

use crate::error::{Error, Result};

// ── Store ────────────────────────────────────────────────────────────────────

/// In-memory decrypted secrets, loaded from `.nenv/secrets.enc`.
#[derive(Debug, Default)]
pub(crate) struct SecretsStore {
    map: HashMap<String, String>,
}

impl SecretsStore {
    fn map_key(host: &str, field: &str) -> String {
        format!("{host}:{field}")
    }

    pub(crate) fn get(&self, host: &str, field: &str) -> Option<&str> {
        self.map.get(&Self::map_key(host, field)).map(String::as_str)
    }

    pub(crate) fn set(&mut self, host: &str, field: &str, secret: String) {
        self.map.insert(Self::map_key(host, field), secret);
    }

    /// Remove all fields for `host`.
    pub(crate) fn remove_host(&mut self, host: &str) {
        let prefix = format!("{host}:");
        self.map.retain(|k, _| !k.starts_with(&prefix));
    }

    /// Decrypt and load from `path`. Returns an empty store if the file does not exist.
    pub(crate) fn load(path: &Path, key: &[u8; 32]) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read(path)?;
        if data.len() < 12 {
            return Err(Error::cli("secrets.enc is malformed (too short)"));
        }
        let k = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(k);
        let nonce = Nonce::from_slice(&data[..12]);
        let plaintext = cipher
            .decrypt(nonce, &data[12..])
            .map_err(|_| Error::cli("Failed to decrypt .nenv/secrets.enc — wrong key or corrupted file"))?;
        let map: HashMap<String, String> = serde_json::from_slice(&plaintext)
            .map_err(|e| Error::cli(format!("Failed to parse secrets store: {e}")))?;
        Ok(Self { map })
    }

    /// Encrypt and write to `path` atomically (write to `.tmp`, then rename).
    pub(crate) fn save(&self, path: &Path, key: &[u8; 32]) -> Result<()> {
        let k = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(k);
        let nonce = Aes256Gcm::generate_nonce(&mut rand::rngs::OsRng);
        let plaintext = serde_json::to_vec(&self.map)
            .map_err(|e| Error::cli(format!("Failed to serialize secrets: {e}")))?;
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_slice())
            .map_err(|_| Error::cli("Failed to encrypt secrets"))?;
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        // Atomic write
        let tmp = path.with_extension("enc.tmp");
        std::fs::write(&tmp, &out)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

// ── Key helpers ───────────────────────────────────────────────────────────────

/// Generate a random 32-byte project key.
pub(crate) fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

/// Generate a UUID v4 string to use as a project ID.
pub(crate) fn generate_project_id() -> String {
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant bits
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3],
        b[4], b[5],
        b[6], b[7],
        b[8], b[9],
        b[10], b[11], b[12], b[13], b[14], b[15],
    )
}

/// `~/.config/nv/keys/<project-id>`
pub(crate) fn key_path(project_id: &str) -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("nv/keys").join(project_id))
}

/// Write a 32-byte key to `~/.config/nv/keys/<project-id>` with mode 0600.
pub(crate) fn store_key(project_id: &str, key: &[u8; 32]) -> Result<()> {
    let path = key_path(project_id)
        .ok_or_else(|| Error::cli("Cannot determine config directory"))?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, key.as_slice())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Load the project key.
///
/// Resolution order:
/// 1. `NV_KEY` environment variable (base64-encoded 32 bytes)
/// 2. `~/.config/nv/keys/<project-id>` (raw 32 bytes)
pub(crate) fn load_key(project_id: &str) -> Result<[u8; 32]> {
    if let Ok(b64) = std::env::var("NV_KEY") {
        let bytes = B64
            .decode(b64.trim())
            .map_err(|e| Error::cli(format!("Invalid NV_KEY (expected base64): {e}")))?;
        return bytes_to_key(&bytes, "NV_KEY");
    }
    let path = key_path(project_id)
        .ok_or_else(|| Error::cli("Cannot determine config directory"))?;
    let bytes = std::fs::read(&path).map_err(|_| {
        Error::cli(format!(
            "No project key found at {}. Run `nv init` or set NV_KEY.",
            path.display()
        ))
    })?;
    bytes_to_key(&bytes, &path.display().to_string())
}

fn bytes_to_key(bytes: &[u8], source: &str) -> Result<[u8; 32]> {
    if bytes.len() != 32 {
        return Err(Error::cli(format!(
            "{source} must be exactly 32 bytes (got {})",
            bytes.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(bytes);
    Ok(key)
}
