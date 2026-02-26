use crate::client;
use crate::config::Config;
use crate::error::Error;
use crate::protocol::{Request, Response};

use super::util::require_root;

/// Run the `list` subcommand: display all active grants.
///
/// # Errors
///
/// Returns an error if the user is not root or communication with the daemon fails.
pub fn execute(config: &Config) -> Result<(), Error> {
    require_root()?;

    let response = client::send_request(config, &Request::List)?;
    match response {
        Response::Grants { grants } => {
            if grants.is_empty() {
                eprintln!("No active grants.");
            } else {
                eprintln!("{:<8} {:<25} PATH", "UID", "EXPIRES");
                for grant in &grants {
                    eprintln!(
                        "{:<8} {:<25} {}",
                        grant.uid,
                        grant.expires_at,
                        grant.path.display()
                    );
                }
            }
            Ok(())
        }
        Response::Error { message } => Err(Error::Daemon(message)),
        _ => Err(Error::Daemon(String::from("unexpected response"))),
    }
}
