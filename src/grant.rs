use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::error::Error;

/// An active grant allowing a user to run `just` on a specific file.
#[derive(Debug, Clone)]
pub struct Grant {
    /// SHA-256 hash of the file at the time it was allowed.
    pub sha256: String,
    /// When this grant expires.
    pub expires_at: SystemTime,
}

/// Key for looking up grants: (uid, canonical path).
type GrantKey = (u32, PathBuf);

/// In-memory store of active grants.
///
/// Grants are keyed by `(uid, canonicalized_path)` and have an expiry time.
/// The store is not persisted — a daemon restart clears all grants.
#[derive(Debug, Default)]
pub struct GrantStore {
    grants: HashMap<GrantKey, Grant>,
}

impl GrantStore {
    /// Create a new empty grant store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a grant for a user/file combination.
    pub fn insert(
        &mut self,
        uid: u32,
        path: PathBuf,
        sha256: String,
        duration: Duration,
    ) -> SystemTime {
        let expires_at = SystemTime::now() + duration;
        let grant = Grant { sha256, expires_at };
        self.grants.insert((uid, path), grant);
        expires_at
    }

    /// Remove a grant for a user/file combination.
    ///
    /// Returns `true` if a grant was removed, `false` if none existed.
    pub fn remove(&mut self, uid: u32, path: &Path) -> bool {
        let key = (uid, path.to_path_buf());
        self.grants.remove(&key).is_some()
    }

    /// Return all active (non-expired) grants, pruning expired entries.
    ///
    /// Each entry is `(uid, path, grant)`.
    pub fn list_active(&mut self) -> Vec<(u32, &Path, &Grant)> {
        let now = SystemTime::now();
        self.grants.retain(|_, grant| grant.expires_at > now);
        self.grants
            .iter()
            .map(|((uid, path), grant)| (*uid, path.as_path(), grant))
            .collect()
    }

    /// Return grants expiring within the given duration.
    ///
    /// Also prunes already-expired grants.
    pub fn expiring_within(&mut self, threshold: Duration) -> Vec<(u32, &Path, &Grant)> {
        let now = SystemTime::now();
        self.grants.retain(|_, grant| grant.expires_at > now);
        let deadline = now + threshold;
        self.grants
            .iter()
            .filter(|(_, grant)| grant.expires_at <= deadline)
            .map(|((uid, path), grant)| (*uid, path.as_path(), grant))
            .collect()
    }

    /// Extend an existing grant's duration from now.
    ///
    /// # Errors
    ///
    /// - [`Error::NoGrantToRenew`] if no active (non-expired) grant exists.
    pub fn renew(
        &mut self,
        uid: u32,
        path: &Path,
        duration: Duration,
    ) -> Result<SystemTime, Error> {
        let key = (uid, path.to_path_buf());

        let grant = self
            .grants
            .get_mut(&key)
            .ok_or_else(|| Error::NoGrantToRenew {
                uid,
                path: path.to_path_buf(),
            })?;

        if SystemTime::now() > grant.expires_at {
            self.grants.remove(&key);
            return Err(Error::NoGrantToRenew {
                uid,
                path: path.to_path_buf(),
            });
        }

        let new_expires = SystemTime::now() + duration;
        grant.expires_at = new_expires;
        Ok(new_expires)
    }

    /// Look up and validate a grant.
    ///
    /// Returns the stored SHA-256 hash if the grant exists and has not expired.
    ///
    /// # Errors
    ///
    /// - [`Error::NoGrant`] if no grant exists for this user/path.
    /// - [`Error::GrantExpired`] if the grant has expired (also removes it).
    pub fn validate(&mut self, uid: u32, path: &Path) -> Result<String, Error> {
        let key = (uid, path.to_path_buf());

        let grant = self.grants.get(&key).ok_or_else(|| Error::NoGrant {
            uid,
            path: path.to_path_buf(),
        })?;

        if SystemTime::now() > grant.expires_at {
            self.grants.remove(&key);
            return Err(Error::GrantExpired {
                path: path.to_path_buf(),
            });
        }

        Ok(grant.sha256.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use super::GrantStore;

    #[test]
    fn insert_and_validate_grant() {
        let mut store = GrantStore::new();
        let path = PathBuf::from("/tmp/test/Justfile");
        let sha256 = String::from("abc123");

        store.insert(
            1000,
            path.clone(),
            sha256.clone(),
            Duration::from_secs(3600),
        );

        let result = store.validate(1000, &path);
        assert!(result.is_ok());
        assert_eq!(result.ok().as_deref(), Some(sha256.as_str()));
    }

    #[test]
    fn no_grant_returns_error() {
        let mut store = GrantStore::new();
        let path = PathBuf::from("/tmp/test/Justfile");

        let result = store.validate(1000, &path);
        assert!(result.is_err());
    }

    #[test]
    fn expired_grant_returns_error() {
        let mut store = GrantStore::new();
        let path = PathBuf::from("/tmp/test/Justfile");

        store.insert(
            1000,
            path.clone(),
            String::from("abc123"),
            Duration::from_secs(0),
        );

        // Sleep briefly to ensure expiry
        std::thread::sleep(Duration::from_millis(10));

        let result = store.validate(1000, &path);
        assert!(result.is_err());
    }

    #[test]
    fn revoke_existing_grant() {
        let mut store = GrantStore::new();
        let path = PathBuf::from("/tmp/test/Justfile");

        store.insert(
            1000,
            path.clone(),
            String::from("abc123"),
            Duration::from_secs(3600),
        );

        assert!(store.remove(1000, &path));
        // Grant should be gone now.
        let result = store.validate(1000, &path);
        assert!(result.is_err());
    }

    #[test]
    fn revoke_nonexistent_returns_false() {
        let mut store = GrantStore::new();
        let path = PathBuf::from("/tmp/test/Justfile");

        assert!(!store.remove(1000, &path));
    }

    #[test]
    fn list_active_grants() {
        let mut store = GrantStore::new();
        let path1 = PathBuf::from("/tmp/test/Justfile1");
        let path2 = PathBuf::from("/tmp/test/Justfile2");

        store.insert(1000, path1, String::from("aaa"), Duration::from_secs(3600));
        store.insert(1001, path2, String::from("bbb"), Duration::from_secs(3600));

        let active = store.list_active();
        assert_eq!(active.len(), 2);
    }

    #[test]
    fn list_excludes_expired() {
        let mut store = GrantStore::new();
        let path_active = PathBuf::from("/tmp/test/Active");
        let path_expired = PathBuf::from("/tmp/test/Expired");

        store.insert(
            1000,
            path_active,
            String::from("aaa"),
            Duration::from_secs(3600),
        );
        store.insert(
            1000,
            path_expired,
            String::from("bbb"),
            Duration::from_secs(0),
        );

        // Sleep briefly to ensure expiry
        std::thread::sleep(Duration::from_millis(10));

        let active = store.list_active();
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn expiring_within_threshold() {
        let mut store = GrantStore::new();
        let soon = PathBuf::from("/tmp/test/Soon");
        let later = PathBuf::from("/tmp/test/Later");

        store.insert(
            1000,
            soon.clone(),
            String::from("aaa"),
            Duration::from_secs(30),
        );
        store.insert(1001, later, String::from("bbb"), Duration::from_secs(7200));

        let expiring = store.expiring_within(Duration::from_secs(60));
        assert_eq!(expiring.len(), 1);
        assert_eq!(
            expiring.first().map(|(_, p, _)| p.to_path_buf()),
            Some(soon)
        );
    }

    #[test]
    fn renew_extends_grant() {
        let mut store = GrantStore::new();
        let path = PathBuf::from("/tmp/test/Justfile");

        store.insert(
            1000,
            path.clone(),
            String::from("abc123"),
            Duration::from_secs(60),
        );

        let new_expires = store.renew(1000, &path, Duration::from_secs(3600));
        assert!(new_expires.is_ok());

        // Grant should still be valid.
        let result = store.validate(1000, &path);
        assert!(result.is_ok());
    }

    #[test]
    fn renew_nonexistent_returns_error() {
        let mut store = GrantStore::new();
        let path = PathBuf::from("/tmp/test/Justfile");

        let result = store.renew(1000, &path, Duration::from_secs(3600));
        assert!(result.is_err());
    }

    #[test]
    fn renew_expired_returns_error() {
        let mut store = GrantStore::new();
        let path = PathBuf::from("/tmp/test/Justfile");

        store.insert(
            1000,
            path.clone(),
            String::from("abc123"),
            Duration::from_secs(0),
        );

        std::thread::sleep(Duration::from_millis(10));

        let result = store.renew(1000, &path, Duration::from_secs(3600));
        assert!(result.is_err());
    }

    #[test]
    fn wrong_user_returns_error() {
        let mut store = GrantStore::new();
        let path = PathBuf::from("/tmp/test/Justfile");

        store.insert(
            1000,
            path.clone(),
            String::from("abc123"),
            Duration::from_secs(3600),
        );

        let result = store.validate(1001, &path);
        assert!(result.is_err());
    }
}
