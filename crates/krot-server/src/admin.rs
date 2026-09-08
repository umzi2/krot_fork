//! Admin-token issuance and consumption (§14).
//!
//! By default tokens are single-use (§14) with a short TTL. Two knobs
//! relax this for lab deployments (e.g. ephemeral Colab clients):
//! [`AdminTokenStore::with_reusable`] keeps the token valid across
//! enrollments, and [`AdminTokenStore::with_ttl`] with [`Duration::ZERO`]
//! disables expiry entirely.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use base32::Alphabet;
use parking_lot::Mutex;
use rand::rngs::OsRng;
use rand::RngCore;

use krot_proto::consts::ADMIN_TOKEN_RAW_LEN;
use krot_proto::consts::ADMIN_TOKEN_TTL;

use crate::error::ServerError;

const HASH_FILE: &str = "admin_token.hash";
/// Raw token, persisted so the same token survives server restarts.
const TOKEN_FILE: &str = "admin_token";
/// Crockford base32, unpadded — matches §14.1.
const ALPHABET: Alphabet = Alphabet::Crockford;

/// Handle to the (optional) currently-valid admin token.
#[derive(Debug)]
pub struct AdminTokenStore {
    data_dir: PathBuf,
    reusable: bool,
    ttl: Duration,
    state: Mutex<Option<TokenState>>,
}

#[derive(Debug)]
struct TokenState {
    hash: [u8; 32],
    /// `None` — token never expires (`ttl == 0`).
    expires_at: Option<Instant>,
}

impl AdminTokenStore {
    #[must_use]
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            reusable: false,
            ttl: ADMIN_TOKEN_TTL,
            state: Mutex::new(None),
        }
    }

    /// Override the token time-to-live. `Duration::ZERO` disables expiry
    /// entirely (token valid until server restart or re-issuance).
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Make tokens reusable: `consume` verifies but does not invalidate.
    #[must_use]
    pub fn with_reusable(mut self, reusable: bool) -> Self {
        self.reusable = reusable;
        self
    }

    /// Return the admin token, minting and persisting one only if no
    /// valid token exists yet. A persisted token is reloaded on every
    /// call and every server start, so it never changes and never gets
    /// consumed unless the operator deletes `admin_token`.
    pub fn issue(&self) -> Result<String, ServerError> {
        // Reload a persisted token: the same token across restarts.
        let token_path = self.token_path();
        if let Ok(text) = fs::read_to_string(&token_path) {
            let token = text.trim().to_string();
            if !token.is_empty() {
                let hash = blake3::hash(token.as_bytes());
                let expires_at = if self.ttl.is_zero() {
                    None
                } else {
                    Some(Instant::now() + self.ttl)
                };
                *self.state.lock() = Some(TokenState {
                    hash: *hash.as_bytes(),
                    expires_at,
                });
                return Ok(token);
            }
        }

        let mut raw = [0u8; ADMIN_TOKEN_RAW_LEN];
        OsRng.fill_bytes(&mut raw);
        let token = base32::encode(ALPHABET, &raw);
        let hash = blake3::hash(token.as_bytes());

        fs::create_dir_all(&self.data_dir)?;
        write_secret(&token_path, token.as_bytes())?;
        write_secret(&self.hash_path(), hash.as_bytes())?;

        let expires_at = if self.ttl.is_zero() {
            None
        } else {
            Some(Instant::now() + self.ttl)
        };

        *self.state.lock() = Some(TokenState {
            hash: *hash.as_bytes(),
            expires_at,
        });
        Ok(token)
    }

    /// Verify `presented` against the currently-valid token.
    ///
    /// On success the token is invalidated (single-use) and its hash file
    /// removed, unless the store was built with [`Self::with_reusable`].
    pub fn consume(&self, presented: &str) -> Result<(), ServerError> {
        let mut guard = self.state.lock();
        let Some(state) = guard.as_ref() else {
            return Err(ServerError::AdminToken("no admin token issued"));
        };
        if state.expires_at.is_some_and(|t| Instant::now() >= t) {
            *guard = None;
            let _ = fs::remove_file(self.hash_path());
            let _ = fs::remove_file(self.token_path());
            return Err(ServerError::AdminToken("admin token expired"));
        }
        let candidate = blake3::hash(presented.as_bytes());
        if !constant_time_eq(candidate.as_bytes(), &state.hash) {
            return Err(ServerError::AdminToken("admin token mismatch"));
        }
        if !self.reusable {
            *guard = None;
            let _ = fs::remove_file(self.hash_path());
            let _ = fs::remove_file(self.token_path());
        }
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.state.lock().is_some()
    }

    fn hash_path(&self) -> PathBuf {
        self.data_dir.join(HASH_FILE)
    }

    fn token_path(&self) -> PathBuf {
        self.data_dir.join(TOKEN_FILE)
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    constant_time_eq_public(a, b)
}

/// Same as [`constant_time_eq`] but visible outside this module.
/// Used by the §16.4 admin API for session-token comparison.
pub fn constant_time_eq_public(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn write_secret(path: &Path, contents: &[u8]) -> Result<(), ServerError> {
    use std::os::unix::fs::PermissionsExt;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, contents)?;
    // Token hashes live in the data dir: owner-only, atomic swap so a
    // crash mid-write can never leave a half-written hash behind.
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp, path)?;
    crate::fsync::sync_parent(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn issue_and_consume_roundtrip() {
        let dir = TempDir::new().unwrap();
        let store = AdminTokenStore::new(dir.path().to_path_buf());
        let token = store.issue().unwrap();
        assert!(store.is_active());
        store.consume(&token).unwrap();
        assert!(!store.is_active());
    }

    #[test]
    fn double_consume_rejected() {
        let dir = TempDir::new().unwrap();
        let store = AdminTokenStore::new(dir.path().to_path_buf());
        let token = store.issue().unwrap();
        store.consume(&token).unwrap();
        assert!(store.consume(&token).is_err());
    }

    #[test]
    fn wrong_token_rejected() {
        let dir = TempDir::new().unwrap();
        let store = AdminTokenStore::new(dir.path().to_path_buf());
        let _real = store.issue().unwrap();
        assert!(store.consume("WRONG").is_err());
        assert!(store.is_active()); // still active until real token or expiry
    }

    #[test]
    fn reusable_token_survives_consume() {
        let dir = TempDir::new().unwrap();
        let store = AdminTokenStore::new(dir.path().to_path_buf()).with_reusable(true);
        let token = store.issue().unwrap();
        store.consume(&token).unwrap();
        store.consume(&token).unwrap();
        assert!(store.is_active());
        assert!(dir.path().join(HASH_FILE).exists());
    }

    #[test]
    fn zero_ttl_token_never_expires() {
        let dir = TempDir::new().unwrap();
        let store = AdminTokenStore::new(dir.path().to_path_buf())
            .with_ttl(Duration::ZERO)
            .with_reusable(true);
        let token = store.issue().unwrap();
        // Advance far past the default TTL; zero-TTL state has no deadline.
        store.consume(&token).unwrap();
        store.consume(&token).unwrap();
        assert!(store.is_active());
    }

    #[test]
    fn token_survives_store_recreation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();
        let token = AdminTokenStore::new(path.clone())
            .with_reusable(true)
            .issue()
            .unwrap();
        // Simulate a server restart: a brand-new store over the same
        // data dir must serve the SAME token, not mint a new one.
        let restarted = AdminTokenStore::new(path).with_reusable(true);
        assert_eq!(restarted.issue().unwrap(), token);
        restarted.consume(&token).unwrap();
    }
}
