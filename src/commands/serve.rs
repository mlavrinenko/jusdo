use crate::config::Config;
use crate::error::Error;
use crate::server;

use super::util::require_root;

/// Run the `serve` subcommand: start the daemon.
///
/// # Errors
///
/// Returns an error if the current user is not root, or if the server
/// fails to start.
pub fn execute(config: &Config) -> Result<(), Error> {
    require_root()?;
    server::run(config)
}
