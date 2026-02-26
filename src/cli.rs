use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Scoped, time-limited `sudo just` delegation.
///
/// jusdo lets an administrator pre-approve specific Justfiles so that
/// unprivileged users can execute their recipes with root privileges,
/// without giving them blanket sudo access.
///
/// Typical workflow:
///   1. Start the daemon:       sudo jusdo serve
///   2. Approve a Justfile:     sudo jusdo allow ./Justfile
///   3. Run a recipe:           jusdo run ./Justfile -- build
#[derive(Debug, Parser)]
#[command(name = "jusdo", version, about, long_about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Start the daemon (must run as root).
    #[command(long_about = "Start the jusdo daemon. Must be run as root.\n\n\
        The daemon listens on a Unix socket and processes grant/run requests.\n\n\
        Example:\n  sudo jusdo serve")]
    Serve,

    /// Allow a Justfile for a user (must run via sudo).
    #[command(long_about = "Review and approve a Justfile for execution.\n\n\
        The file contents are displayed for confirmation (unless -y is passed),\n\
        then a time-limited grant is registered with the daemon.\n\n\
        Examples:\n  sudo jusdo allow ./Justfile\n  \
        sudo jusdo allow ./Justfile -d 120\n  \
        sudo jusdo allow ./Justfile -y")]
    Allow {
        /// Path to the Justfile to allow.
        justfile: PathBuf,

        /// Duration in minutes before the grant expires.
        #[arg(short, long, default_value = "60")]
        duration: u64,

        /// Skip interactive confirmation.
        #[arg(short, long)]
        yes: bool,
    },

    /// Revoke a grant for a Justfile (must run via sudo).
    #[command(long_about = "Remove a previously granted Justfile permission.\n\n\
        Example:\n  sudo jusdo revoke ./Justfile")]
    Revoke {
        /// Path to the Justfile to revoke.
        justfile: PathBuf,
    },

    /// List all active grants (must run via sudo).
    #[command(long_about = "Show all active grants with their expiry times.\n\n\
        Example:\n  sudo jusdo list")]
    List,

    /// Renew (extend) a grant for a Justfile (must run via sudo).
    #[command(long_about = "Extend the duration of an existing grant.\n\n\
        Examples:\n  sudo jusdo renew ./Justfile\n  \
        sudo jusdo renew ./Justfile -d 120")]
    Renew {
        /// Path to the Justfile to renew.
        justfile: PathBuf,

        /// Duration in minutes to extend the grant.
        #[arg(short, long, default_value = "60")]
        duration: u64,
    },

    /// Run a recipe from an allowed Justfile.
    #[command(
        long_about = "Execute a recipe from a previously allowed Justfile.\n\n\
        This command does not require sudo — the daemon verifies the grant\n\
        and runs `just` as root on behalf of the caller.\n\n\
        Examples:\n  jusdo run ./Justfile -- build\n  \
        jusdo run ./Justfile -- deploy --release"
    )]
    Run {
        /// Path to the Justfile.
        justfile: PathBuf,

        /// Arguments to pass to `just` (after `--`).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}
