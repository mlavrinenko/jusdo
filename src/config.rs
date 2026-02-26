use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::Error;

/// Default path to the configuration file.
const DEFAULT_CONFIG_PATH: &str = "/etc/jusdo/config.toml";

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

/// Raw TOML representation (all fields optional).
#[derive(Debug, Deserialize, Default)]
struct RawConfig {
    #[serde(default)]
    socket_dir: Option<PathBuf>,
    #[serde(default)]
    default_duration_mins: Option<u64>,
    #[serde(default)]
    expiry_warn_secs: Option<u64>,
    #[serde(default)]
    audit_log_path: Option<PathBuf>,
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
    /// Load configuration from the default path, falling back to defaults.
    ///
    /// If the config file does not exist, all defaults are used.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be read or parsed.
    pub fn load() -> Result<Self, Error> {
        Self::load_from(Path::new(DEFAULT_CONFIG_PATH))
    }

    /// Load configuration from a specific path, falling back to defaults.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be read or parsed.
    pub fn load_from(path: &Path) -> Result<Self, Error> {
        let raw = match std::fs::read_to_string(path) {
            Ok(contents) => {
                let parsed: RawConfig =
                    toml::from_str(&contents).map_err(|err| Error::ConfigParse(err.to_string()))?;
                parsed
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => RawConfig::default(),
            Err(err) => return Err(Error::Io(err)),
        };

        let socket_dir = raw
            .socket_dir
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_DIR));
        let socket_path = socket_dir.join(DEFAULT_SOCKET_NAME);

        Ok(Self {
            socket_dir,
            socket_path,
            default_duration_mins: raw
                .default_duration_mins
                .unwrap_or(DEFAULT_GRANT_DURATION_MINS),
            expiry_warn_secs: raw.expiry_warn_secs.unwrap_or(DEFAULT_EXPIRY_WARN_SECS),
            audit_log_path: raw.audit_log_path,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

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
    fn load_missing_file_returns_defaults() {
        let cfg = Config::load_from(std::path::Path::new("/nonexistent/config.toml"));
        assert!(cfg.is_ok());
        let cfg = cfg.expect("should be Ok");
        assert_eq!(cfg.default_duration_mins, 60);
    }

    #[test]
    fn load_valid_toml_overrides_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");

        {
            let mut file = std::fs::File::create(&path).expect("create config");
            writeln!(
                file,
                r#"
socket_dir = "/tmp/jusdo-sock"
default_duration_mins = 120
expiry_warn_secs = 600
audit_log_path = "/tmp/audit.log"
"#
            )
            .expect("write config");
        }

        let cfg = Config::load_from(&path).expect("load_from");
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
    fn load_partial_toml_fills_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");

        {
            let mut file = std::fs::File::create(&path).expect("create config");
            writeln!(file, "default_duration_mins = 30").expect("write");
        }

        let cfg = Config::load_from(&path).expect("load_from");
        assert_eq!(cfg.default_duration_mins, 30);
        // Other fields should use defaults
        assert_eq!(cfg.socket_dir.to_str(), Some("/run/jusdo"));
        assert_eq!(cfg.expiry_warn_secs, 300);
        assert!(cfg.audit_log_path.is_none());
    }

    #[test]
    fn load_invalid_toml_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");

        {
            let mut file = std::fs::File::create(&path).expect("create config");
            writeln!(file, "not valid {{{{ toml").expect("write");
        }

        let result = Config::load_from(&path);
        assert!(result.is_err());
    }
}
