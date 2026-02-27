use std::path::PathBuf;

/// Errors that can occur within `jusdo`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The current user is not root.
    #[error("this command must be run as root (try: sudo jusdo ...)")]
    NotRoot,

    /// `SUDO_USER` environment variable is not set.
    #[error("SUDO_USER environment variable is not set")]
    NoSudoUser,

    /// Could not resolve a username to a UID.
    #[error("could not resolve user '{0}' to a UID")]
    UserNotFound(String),

    /// The specified justfile does not exist.
    #[error("justfile not found: {0}")]
    JustfileNotFound(PathBuf),

    /// SHA-256 hash mismatch — the file was modified after being allowed.
    #[error(
        "justfile has been modified since it was allowed (expected {expected}, got {actual}). \
         Run: sudo jusdo allow {path}"
    )]
    HashMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },

    /// No active grant for this user/file combination.
    #[error("no active grant for {path} (user uid={uid}). Run: sudo jusdo allow {path}")]
    NoGrant { uid: u32, path: PathBuf },

    /// The grant has expired.
    #[error("grant for {path} has expired. Run: sudo jusdo allow {path}")]
    GrantExpired { path: PathBuf },

    /// Attempted to renew a grant that does not exist.
    #[error("no active grant to renew for {path} (user uid={uid})")]
    NoGrantToRenew { uid: u32, path: PathBuf },

    /// Could not connect to the daemon socket.
    #[error("could not connect to jusdo daemon at {path}: {source}")]
    DaemonConnection {
        path: PathBuf,
        source: std::io::Error,
    },

    /// Client passed forbidden arguments (e.g. `--justfile` override).
    #[error("forbidden argument: {0}")]
    ForbiddenArg(String),

    /// `just` is not installed or not found in PATH.
    #[error(
        "`just` is not installed or not found in PATH. \
         Install it via: cargo install just, or nix profile install nixpkgs#just"
    )]
    JustNotFound,

    /// The user declined the interactive prompt.
    #[error("user declined — file was not allowed")]
    Declined,

    /// I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization error.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Error from the daemon (forwarded message).
    #[error("daemon error: {0}")]
    Daemon(String),
}
