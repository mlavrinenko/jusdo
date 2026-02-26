use std::os::unix::net::UnixStream;

use crate::config::Config;
use crate::error::Error;
use crate::protocol::{self, Request, Response};

/// Open a raw connection to the daemon socket.
///
/// # Errors
///
/// Returns [`Error::DaemonConnection`] if the socket is unreachable.
pub fn connect(config: &Config) -> Result<UnixStream, Error> {
    let socket_path = &config.socket_path;
    UnixStream::connect(socket_path).map_err(|source| Error::DaemonConnection {
        path: socket_path.clone(),
        source,
    })
}

/// Connect to the daemon and send a request, returning a single response.
///
/// # Errors
///
/// Returns [`Error::DaemonConnection`] if the socket is unreachable,
/// or a protocol error if communication fails.
pub fn send_request(config: &Config, request: &Request) -> Result<Response, Error> {
    let mut stream = connect(config)?;

    protocol::send(&mut stream, request)?;
    protocol::recv(&stream)
}
