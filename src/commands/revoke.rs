use std::path::Path;

use crate::client;
use crate::config::Config;
use crate::error::Error;
use crate::protocol::{Request, Response};

use super::util::{require_root, resolve_sudo_user};

/// Run the `revoke` subcommand: remove a grant for a Justfile.
///
/// # Errors
///
/// Returns an error if the user is not root, the file is missing,
/// or communication with the daemon fails.
pub fn execute(config: &Config, justfile: &Path) -> Result<(), Error> {
    require_root()?;

    let canonical = justfile
        .canonicalize()
        .map_err(|_| Error::JustfileNotFound(justfile.to_path_buf()))?;

    let target_uid = resolve_sudo_user()?;

    let request = Request::Revoke {
        justfile: canonical.clone(),
        uid: target_uid,
    };

    let response = client::send_request(config, &request)?;
    match response {
        Response::Revoked => {
            eprintln!(
                "Revoked: uid={target_uid} grant for {}",
                canonical.display()
            );
            Ok(())
        }
        Response::Error { message } => Err(Error::Daemon(message)),
        _ => Err(Error::Daemon(String::from("unexpected response"))),
    }
}
