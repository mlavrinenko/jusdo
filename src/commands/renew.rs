use std::path::Path;

use crate::client;
use crate::config::Config;
use crate::error::Error;
use crate::protocol::{Request, Response};

use super::util::{require_root, resolve_sudo_user};

/// Run the `renew` subcommand: extend a grant's duration.
///
/// # Errors
///
/// Returns an error if the user is not root, the file is missing,
/// or communication with the daemon fails.
pub fn execute(config: &Config, justfile: &Path, duration_mins: u64) -> Result<(), Error> {
    require_root()?;

    let canonical = justfile
        .canonicalize()
        .map_err(|_| Error::JustfileNotFound(justfile.to_path_buf()))?;

    let target_uid = resolve_sudo_user()?;
    let duration_secs = duration_mins * 60;

    let request = Request::Renew {
        justfile: canonical.clone(),
        uid: target_uid,
        duration_secs,
    };

    let response = client::send_request(config, &request)?;
    match response {
        Response::Renewed { expires_at } => {
            eprintln!(
                "Renewed: uid={target_uid} grant for {} (expires: {expires_at})",
                canonical.display()
            );
            Ok(())
        }
        Response::Error { message } => Err(Error::Daemon(message)),
        _ => Err(Error::Daemon(String::from("unexpected response"))),
    }
}
