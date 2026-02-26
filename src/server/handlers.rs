use std::path::Path;
use std::time::Duration;

use crate::audit::{self, AuditEntry, AuditEvent};
use crate::error::Error;
use crate::grant::GrantStore;
use crate::hash;
use crate::protocol::{GrantInfo, Response};

use super::ServerState;
use super::time::format_system_time;

/// Parameters for an allow request (avoids too many function arguments).
pub(crate) struct AllowParams {
    pub justfile: std::path::PathBuf,
    pub sha256: String,
    pub target_uid: u32,
    pub duration_secs: u64,
}

/// Process an Allow request: only root (uid 0) may register grants.
pub(crate) fn handle_allow(
    state: &mut ServerState,
    params: AllowParams,
    peer_uid: u32,
) -> Response {
    if peer_uid != 0 {
        return Response::Error {
            message: String::from("only root can register grants"),
        };
    }

    let duration = Duration::from_secs(params.duration_secs);
    let expires_at = state.grants.insert(
        params.target_uid,
        params.justfile.clone(),
        params.sha256,
        duration,
    );

    let formatted = format_system_time(expires_at);
    log::info!(
        "granted uid={} access to {} until {formatted}",
        params.target_uid,
        params.justfile.display()
    );

    state.audit.log(&AuditEntry {
        timestamp: audit::now_epoch_secs(),
        peer_uid,
        event: AuditEvent::Allowed,
        uid: params.target_uid,
        path: params.justfile.display().to_string(),
        detail: None,
    });

    Response::Allowed {
        expires_at: formatted,
    }
}

/// Process a Revoke request: only root may revoke grants.
pub(crate) fn handle_revoke(
    state: &mut ServerState,
    justfile: &Path,
    uid: u32,
    peer_uid: u32,
) -> Response {
    if peer_uid != 0 {
        return Response::Error {
            message: String::from("only root can revoke grants"),
        };
    }

    if state.grants.remove(uid, justfile) {
        log::info!("revoked grant for uid={uid} on {}", justfile.display());
        state.audit.log(&AuditEntry {
            timestamp: audit::now_epoch_secs(),
            peer_uid,
            event: AuditEvent::Revoked,
            uid,
            path: justfile.display().to_string(),
            detail: None,
        });
        Response::Revoked
    } else {
        Response::Error {
            message: format!("no active grant for uid={uid} on {}", justfile.display()),
        }
    }
}

/// Process a Renew request: only root may renew grants.
pub(crate) fn handle_renew(
    state: &mut ServerState,
    justfile: &Path,
    uid: u32,
    duration_secs: u64,
    peer_uid: u32,
) -> Response {
    if peer_uid != 0 {
        return Response::Error {
            message: String::from("only root can renew grants"),
        };
    }

    let duration = Duration::from_secs(duration_secs);
    match state.grants.renew(uid, justfile, duration) {
        Ok(new_expires) => {
            let formatted = format_system_time(new_expires);
            log::info!(
                "renewed grant for uid={uid} on {} until {formatted}",
                justfile.display()
            );
            state.audit.log(&AuditEntry {
                timestamp: audit::now_epoch_secs(),
                peer_uid,
                event: AuditEvent::Renewed,
                uid,
                path: justfile.display().to_string(),
                detail: None,
            });
            Response::Renewed {
                expires_at: formatted,
            }
        }
        Err(err) => Response::Error {
            message: err.to_string(),
        },
    }
}

/// Process a List request: only root may list grants.
pub(crate) fn handle_list(store: &mut GrantStore, peer_uid: u32) -> Response {
    if peer_uid != 0 {
        return Response::Error {
            message: String::from("only root can list grants"),
        };
    }

    let active = store.list_active();
    let grants = active
        .into_iter()
        .map(|(uid, path, grant)| GrantInfo {
            uid,
            path: path.to_path_buf(),
            sha256: grant.sha256.clone(),
            expires_at: format_system_time(grant.expires_at),
        })
        .collect();

    Response::Grants { grants }
}

/// Arguments that must not appear in user-supplied `args` to prevent
/// overriding the server-controlled `--justfile` flag.
const FORBIDDEN_ARGS: &[&str] = &["--justfile", "-f", "--working-directory", "-d"];

/// Check that the grant is valid, the file hash matches, and args are safe.
pub(crate) fn validate_run(
    grants: &mut GrantStore,
    justfile: &Path,
    args: &[String],
    peer_uid: u32,
) -> Result<(), Error> {
    for arg in args {
        for forbidden in FORBIDDEN_ARGS {
            if arg == *forbidden || arg.starts_with(&format!("{forbidden}=")) {
                return Err(Error::ForbiddenArg(arg.clone()));
            }
        }
    }

    let stored_hash = grants.validate(peer_uid, justfile)?;
    let current_hash = hash::sha256_file(justfile)?;

    if stored_hash != current_hash {
        return Err(Error::HashMismatch {
            path: justfile.to_path_buf(),
            expected: stored_hash,
            actual: current_hash,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use crate::audit::AuditLog;
    use crate::grant::GrantStore;
    use crate::protocol::Response;

    use super::{
        AllowParams, ServerState, handle_allow, handle_list, handle_renew, handle_revoke,
        validate_run,
    };

    fn test_state() -> ServerState {
        ServerState {
            grants: GrantStore::new(),
            audit: AuditLog::open(None).expect("noop audit"),
        }
    }

    // --- handle_allow ---

    #[test]
    fn allow_as_root_succeeds() {
        let mut state = test_state();
        let params = AllowParams {
            justfile: PathBuf::from("/tmp/Justfile"),
            sha256: String::from("abc123"),
            target_uid: 1000,
            duration_secs: 3600,
        };
        let resp = handle_allow(&mut state, params, 0);
        assert!(matches!(resp, Response::Allowed { .. }));
    }

    #[test]
    fn allow_as_non_root_denied() {
        let mut state = test_state();
        let params = AllowParams {
            justfile: PathBuf::from("/tmp/Justfile"),
            sha256: String::from("abc123"),
            target_uid: 1000,
            duration_secs: 3600,
        };
        let resp = handle_allow(&mut state, params, 1000);
        match resp {
            Response::Error { message } => {
                assert!(message.contains("only root"));
            }
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn allow_creates_valid_grant() {
        let mut state = test_state();
        let path = PathBuf::from("/tmp/Justfile");
        let params = AllowParams {
            justfile: path.clone(),
            sha256: String::from("abc123"),
            target_uid: 1000,
            duration_secs: 3600,
        };
        handle_allow(&mut state, params, 0);

        let result = state.grants.validate(1000, &path);
        assert!(result.is_ok());
    }

    // --- handle_revoke ---

    #[test]
    fn revoke_as_root_succeeds() {
        let mut state = test_state();
        let path = PathBuf::from("/tmp/Justfile");
        state.grants.insert(
            1000,
            path.clone(),
            String::from("abc"),
            Duration::from_secs(3600),
        );

        let resp = handle_revoke(&mut state, &path, 1000, 0);
        assert!(matches!(resp, Response::Revoked));
    }

    #[test]
    fn revoke_as_non_root_denied() {
        let mut state = test_state();
        let path = PathBuf::from("/tmp/Justfile");
        let resp = handle_revoke(&mut state, &path, 1000, 1000);
        assert!(matches!(resp, Response::Error { .. }));
    }

    #[test]
    fn revoke_nonexistent_returns_error() {
        let mut state = test_state();
        let path = PathBuf::from("/tmp/Justfile");
        let resp = handle_revoke(&mut state, &path, 1000, 0);
        match resp {
            Response::Error { message } => {
                assert!(message.contains("no active grant"));
            }
            _ => panic!("expected Error"),
        }
    }

    // --- handle_renew ---

    #[test]
    fn renew_as_root_succeeds() {
        let mut state = test_state();
        let path = PathBuf::from("/tmp/Justfile");
        state.grants.insert(
            1000,
            path.clone(),
            String::from("abc"),
            Duration::from_secs(60),
        );

        let resp = handle_renew(&mut state, &path, 1000, 7200, 0);
        assert!(matches!(resp, Response::Renewed { .. }));
    }

    #[test]
    fn renew_as_non_root_denied() {
        let mut state = test_state();
        let path = PathBuf::from("/tmp/Justfile");
        let resp = handle_renew(&mut state, &path, 1000, 7200, 1000);
        assert!(matches!(resp, Response::Error { .. }));
    }

    #[test]
    fn renew_nonexistent_returns_error() {
        let mut state = test_state();
        let path = PathBuf::from("/tmp/Justfile");
        let resp = handle_renew(&mut state, &path, 1000, 7200, 0);
        assert!(matches!(resp, Response::Error { .. }));
    }

    // --- handle_list ---

    #[test]
    fn list_as_root_returns_grants() {
        let mut state = test_state();
        state.grants.insert(
            1000,
            PathBuf::from("/tmp/A"),
            String::from("aaa"),
            Duration::from_secs(3600),
        );
        state.grants.insert(
            1001,
            PathBuf::from("/tmp/B"),
            String::from("bbb"),
            Duration::from_secs(3600),
        );

        let resp = handle_list(&mut state.grants, 0);
        match resp {
            Response::Grants { grants } => assert_eq!(grants.len(), 2),
            _ => panic!("expected Grants"),
        }
    }

    #[test]
    fn list_as_non_root_denied() {
        let mut state = test_state();
        let resp = handle_list(&mut state.grants, 1000);
        assert!(matches!(resp, Response::Error { .. }));
    }

    #[test]
    fn list_empty_returns_empty_grants() {
        let mut state = test_state();
        let resp = handle_list(&mut state.grants, 0);
        match resp {
            Response::Grants { grants } => assert!(grants.is_empty()),
            _ => panic!("expected Grants"),
        }
    }

    // --- validate_run ---

    #[test]
    fn validate_run_no_grant_returns_error() {
        let mut store = GrantStore::new();
        let path = PathBuf::from("/tmp/Justfile");
        let result = validate_run(&mut store, &path, &[], 1000);
        assert!(result.is_err());
    }

    #[test]
    fn validate_run_matching_hash_succeeds() {
        let mut store = GrantStore::new();

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Justfile");
        std::fs::write(&path, b"hello: echo hello").expect("write");

        let hash = crate::hash::sha256_file(&path).expect("hash");
        store.insert(1000, path.clone(), hash, Duration::from_secs(3600));

        let result = validate_run(&mut store, &path, &[], 1000);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_run_mismatched_hash_returns_error() {
        let mut store = GrantStore::new();

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Justfile");
        std::fs::write(&path, b"original content").expect("write");

        store.insert(
            1000,
            path.clone(),
            String::from("wrong_hash"),
            Duration::from_secs(3600),
        );

        let result = validate_run(&mut store, &path, &[], 1000);
        assert!(result.is_err());
        let err_msg = result.expect_err("should fail").to_string();
        assert!(err_msg.contains("modified"));
    }

    // --- validate_run arg injection ---

    #[test]
    fn validate_run_rejects_justfile_flag() {
        let mut store = GrantStore::new();
        let path = PathBuf::from("/tmp/Justfile");
        let args = vec![String::from("--justfile"), String::from("/etc/shadow")];
        let result = validate_run(&mut store, &path, &args, 1000);
        assert!(result.is_err());
        let msg = result.expect_err("should fail").to_string();
        assert!(msg.contains("forbidden"));
    }

    #[test]
    fn validate_run_rejects_short_justfile_flag() {
        let mut store = GrantStore::new();
        let path = PathBuf::from("/tmp/Justfile");
        let args = vec![String::from("-f"), String::from("/etc/shadow")];
        let result = validate_run(&mut store, &path, &args, 1000);
        assert!(result.is_err());
    }

    #[test]
    fn validate_run_rejects_justfile_equals() {
        let mut store = GrantStore::new();
        let path = PathBuf::from("/tmp/Justfile");
        let args = vec![String::from("--justfile=/etc/shadow")];
        let result = validate_run(&mut store, &path, &args, 1000);
        assert!(result.is_err());
    }

    #[test]
    fn validate_run_rejects_working_directory_flag() {
        let mut store = GrantStore::new();
        let path = PathBuf::from("/tmp/Justfile");
        let args = vec![String::from("--working-directory"), String::from("/tmp")];
        let result = validate_run(&mut store, &path, &args, 1000);
        assert!(result.is_err());
        let msg = result.expect_err("should fail").to_string();
        assert!(msg.contains("forbidden"));
    }

    #[test]
    fn validate_run_rejects_short_working_directory_flag() {
        let mut store = GrantStore::new();
        let path = PathBuf::from("/tmp/Justfile");
        let args = vec![String::from("-d"), String::from("/tmp")];
        let result = validate_run(&mut store, &path, &args, 1000);
        assert!(result.is_err());
    }

    #[test]
    fn validate_run_rejects_working_directory_equals() {
        let mut store = GrantStore::new();
        let path = PathBuf::from("/tmp/Justfile");
        let args = vec![String::from("--working-directory=/tmp")];
        let result = validate_run(&mut store, &path, &args, 1000);
        assert!(result.is_err());
    }
}
