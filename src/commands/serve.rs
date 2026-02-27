use crate::config::Config;
use crate::error::Error;
use crate::server;

use super::util::{require_just, require_root};

/// Run the `serve` subcommand: start the daemon.
///
/// # Errors
///
/// Returns an error if `just` is not installed, the current user is not
/// root, or if the server fails to start.
pub fn execute(config: &Config) -> Result<(), Error> {
    require_root()?;
    require_just()?;
    server::run(config)
}
