use std::io::{self, Write};
use std::path::Path;

use crate::client;
use crate::config::Config;
use crate::error::Error;
use crate::hash;
use crate::protocol::{Request, Response};

use super::util::{require_root, resolve_sudo_user};

/// Run the `allow` subcommand: register a grant for a Justfile.
///
/// # Errors
///
/// Returns an error if the user is not root, the file is missing,
/// the user declines, or communication with the daemon fails.
pub fn execute(
    config: &Config,
    justfile: &Path,
    duration_mins: u64,
    skip_confirm: bool,
) -> Result<(), Error> {
    require_root()?;

    let canonical = justfile
        .canonicalize()
        .map_err(|_| Error::JustfileNotFound(justfile.to_path_buf()))?;

    let target_uid = resolve_sudo_user()?;

    if !skip_confirm {
        interactive_confirm(&canonical)?;
    }

    let sha256 = hash::sha256_file(&canonical)?;
    let duration_secs = duration_mins * 60;

    let request = Request::Allow {
        justfile: canonical.clone(),
        sha256,
        uid: target_uid,
        duration_secs,
    };

    let response = client::send_request(config, &request)?;
    match response {
        Response::Allowed { expires_at } => {
            eprintln!(
                "Granted: uid={target_uid} may run {}  (expires: {expires_at})",
                canonical.display()
            );
            Ok(())
        }
        Response::Error { message } => Err(Error::Daemon(message)),
        _ => Err(Error::Daemon(String::from("unexpected response"))),
    }
}

/// Display the Justfile and ask the user for confirmation.
fn interactive_confirm(path: &Path) -> Result<(), Error> {
    let contents = std::fs::read_to_string(path)?;

    eprintln!("=== Contents of {} ===", path.display());
    eprintln!("{contents}");
    eprintln!("=== End of file ===");
    eprint!("Allow this file? [y/N] ");
    io::stderr().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;

    let trimmed = answer.trim().to_lowercase();
    if trimmed == "y" || trimmed == "yes" {
        Ok(())
    } else {
        Err(Error::Declined)
    }
}
