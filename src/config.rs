use std::path::{Path, PathBuf};

/// Default socket directory.
const DEFAULT_SOCKET_DIR: &str = "/run/jusdo";

/// Default socket file name.
const DEFAULT_SOCKET_NAME: &str = "jusdo.sock";

/// Default grant duration in minutes.
const DEFAULT_GRANT_DURATION_MINS: u64 = 60;

/// Default expiry warning threshold in seconds.
const DEFAULT_EXPIRY_WARN_SECS: u64 = 300;

/// Runtime configuration for the daemon and client.
#[derive(Debug, Clone)]
pub struct Config {
    /// Directory containing the socket.
    pub socket_dir: PathBuf,
    /// Full path to the Unix domain socket.
    pub socket_path: PathBuf,
    /// Default grant duration in minutes (used by `allow`).
    pub default_duration_mins: u64,
    /// Seconds before expiry to start warning in logs.
    pub expiry_warn_secs: u64,
    /// Path for the append-only audit log (`None` = disabled).
    pub audit_log_path: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        let socket_dir = PathBuf::from(DEFAULT_SOCKET_DIR);
        let socket_path = socket_dir.join(DEFAULT_SOCKET_NAME);
        Self {
            socket_dir,
            socket_path,
            default_duration_mins: DEFAULT_GRANT_DURATION_MINS,
            expiry_warn_secs: DEFAULT_EXPIRY_WARN_SECS,
            audit_log_path: None,
        }
    }
}

impl Config {
    /// Build configuration for the server from CLI arguments.
    pub fn for_server(
        socket_dir: &Path,
        default_duration_mins: u64,
        expiry_warn_secs: u64,
        audit_log_path: Option<PathBuf>,
    ) -> Self {
        let socket_path = socket_dir.join(DEFAULT_SOCKET_NAME);
        Self {
            socket_dir: socket_dir.to_path_buf(),
            socket_path,
            default_duration_mins,
            expiry_warn_secs,
            audit_log_path,
        }
    }

    /// Build configuration for a client that only needs the socket path.
    pub fn for_client(socket_path: &Path) -> Self {
        let socket_dir = socket_path
            .parent()
            .map_or_else(|| PathBuf::from(DEFAULT_SOCKET_DIR), Path::to_path_buf);
        Self {
            socket_dir,
            socket_path: socket_path.to_path_buf(),
            default_duration_mins: DEFAULT_GRANT_DURATION_MINS,
            expiry_warn_secs: DEFAULT_EXPIRY_WARN_SECS,
            audit_log_path: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn default_config_has_expected_values() {
        let cfg = Config::default();
        assert_eq!(cfg.socket_dir.to_str(), Some("/run/jusdo"));
        assert_eq!(cfg.socket_path.to_str(), Some("/run/jusdo/jusdo.sock"));
        assert_eq!(cfg.default_duration_mins, 60);
        assert_eq!(cfg.expiry_warn_secs, 300);
        assert!(cfg.audit_log_path.is_none());
    }

    #[test]
    fn for_server_builds_socket_path() {
        let cfg = Config::for_server(
            std::path::Path::new("/tmp/jusdo-sock"),
            120,
            600,
            Some(std::path::PathBuf::from("/tmp/audit.log")),
        );
        assert_eq!(cfg.socket_dir.to_str(), Some("/tmp/jusdo-sock"));
        assert_eq!(cfg.socket_path.to_str(), Some("/tmp/jusdo-sock/jusdo.sock"));
        assert_eq!(cfg.default_duration_mins, 120);
        assert_eq!(cfg.expiry_warn_secs, 600);
        assert_eq!(
            cfg.audit_log_path.as_ref().and_then(|p| p.to_str()),
            Some("/tmp/audit.log")
        );
    }

    #[test]
    fn for_client_derives_socket_dir() {
        let cfg = Config::for_client(std::path::Path::new("/tmp/jusdo-sock/jusdo.sock"));
        assert_eq!(cfg.socket_dir.to_str(), Some("/tmp/jusdo-sock"));
        assert_eq!(cfg.socket_path.to_str(), Some("/tmp/jusdo-sock/jusdo.sock"));
        assert_eq!(cfg.default_duration_mins, 60);
        assert!(cfg.audit_log_path.is_none());
    }
}
