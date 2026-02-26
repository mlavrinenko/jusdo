mod exec;
mod handlers;
mod time;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nix::sys::socket::getsockopt;
use nix::sys::socket::sockopt::PeerCredentials;

use crate::audit::AuditLog;
use crate::config::Config;
use crate::error::Error;
use crate::grant::GrantStore;
use crate::protocol::{self, Request, Response};

use handlers::{AllowParams, handle_allow, handle_list, handle_renew, handle_revoke};

/// Bundled server state: grant store + audit log.
pub(crate) struct ServerState {
    pub grants: GrantStore,
    pub audit: AuditLog,
}

/// How often the expiry watcher checks for soon-to-expire grants.
const EXPIRY_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// Maximum time a client connection may remain idle before being dropped.
/// Prevents a single client from blocking the single-threaded accept loop.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Start the daemon: bind socket and enter the accept loop.
///
/// Installs signal handlers for `SIGTERM` and `SIGINT` so that the
/// socket file is cleaned up on graceful shutdown.
///
/// # Errors
///
/// Returns an error if the socket cannot be created or bound.
pub fn run(config: &Config) -> Result<(), Error> {
    let listener = bind_socket(config)?;
    log::info!("jusdo daemon listening on {}", config.socket_path.display());

    let shutdown = Arc::new(AtomicBool::new(false));
    install_signal_handler(Arc::clone(&shutdown), config.socket_path.clone());

    // Set a timeout on `accept` so we can check the shutdown flag
    // periodically instead of blocking forever.
    listener.set_nonblocking(false)?;

    let audit = AuditLog::open(config.audit_log_path.as_deref())?;
    let state = Arc::new(Mutex::new(ServerState {
        grants: GrantStore::new(),
        audit,
    }));
    let warn_threshold = Duration::from_secs(config.expiry_warn_secs);

    spawn_expiry_watcher(Arc::clone(&state), warn_threshold);

    for stream in listener.incoming() {
        if shutdown.load(Ordering::Relaxed) {
            log::info!("shutdown signal received, exiting");
            break;
        }

        let stream = match stream {
            Ok(stream) => stream,
            Err(err) => {
                log::error!("accept error: {err}");
                continue;
            }
        };

        let mut locked = match state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::warn!("state lock was poisoned, recovering");
                poisoned.into_inner()
            }
        };

        if let Err(err) = handle_connection(stream, &mut locked) {
            log::error!("request error: {err}");
        }
    }

    cleanup_socket(&config.socket_path);
    log::info!("daemon shut down cleanly");
    Ok(())
}

/// Install signal handlers for `SIGTERM` and `SIGINT`.
///
/// Blocks both signals on the current (main) thread, then spawns a
/// dedicated thread that calls `sigwait`. When a signal arrives the
/// shutdown flag is set and a dummy connection is made to the socket
/// to unblock the accept loop.
fn install_signal_handler(shutdown: Arc<AtomicBool>, socket_path: std::path::PathBuf) {
    use nix::sys::signal::{SigSet, Signal};

    let mut mask = SigSet::empty();
    mask.add(Signal::SIGTERM);
    mask.add(Signal::SIGINT);

    // Block these signals in all threads so only our handler thread
    // receives them via sigwait.
    mask.thread_block().ok();

    std::thread::spawn(move || {
        if let Ok(sig) = mask.wait() {
            log::info!("received signal {sig}, shutting down");
            shutdown.store(true, Ordering::Relaxed);
            // Make a dummy connection to unblock the accept loop.
            let _ = std::os::unix::net::UnixStream::connect(&socket_path);
        }
    });
}

/// Remove the socket file on shutdown.
fn cleanup_socket(path: &std::path::Path) {
    if let Err(err) = fs::remove_file(path) {
        if err.kind() != std::io::ErrorKind::NotFound {
            log::warn!("failed to remove socket: {err}");
        }
    }
}

/// Spawn a background thread that logs warnings for soon-to-expire grants.
fn spawn_expiry_watcher(state: Arc<Mutex<ServerState>>, threshold: Duration) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(EXPIRY_CHECK_INTERVAL);

            let mut locked = match state.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };

            let expiring = locked.grants.expiring_within(threshold);
            for (uid, path, grant) in &expiring {
                let remaining = grant
                    .expires_at
                    .duration_since(std::time::SystemTime::now())
                    .unwrap_or(Duration::ZERO);
                log::warn!(
                    "grant expiring soon: uid={uid} path={} ({} seconds left)",
                    path.display(),
                    remaining.as_secs()
                );
            }
        }
    });
}

/// Create the socket directory and bind the listener.
///
/// # Security: socket permissions
///
/// The socket is created with mode `0o666` (world-read/write) so that
/// unprivileged users can connect for `Run` requests. Authorization is
/// enforced per-request via `SO_PEERCRED`: only root (uid 0) may call
/// `Allow`, `Revoke`, `Renew`, or `List`; any user may call `Run` but
/// only for their own grants.
fn bind_socket(config: &Config) -> Result<UnixListener, Error> {
    fs::create_dir_all(&config.socket_dir)?;
    fs::set_permissions(&config.socket_dir, fs::Permissions::from_mode(0o755))?;

    // Remove stale socket from a previous run.
    let _ = fs::remove_file(&config.socket_path);

    let listener = UnixListener::bind(&config.socket_path)?;
    fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(0o666))?;

    Ok(listener)
}

/// Handle a single client connection: read request, process, respond.
fn handle_connection(mut stream: UnixStream, state: &mut ServerState) -> Result<(), Error> {
    stream.set_read_timeout(Some(CONNECTION_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_TIMEOUT))?;

    let peer_uid = get_peer_uid(&stream)?;
    let request: Request = protocol::recv(&stream)?;

    log::info!("request from uid={peer_uid}: {request:?}");

    match request {
        Request::Allow {
            justfile,
            sha256,
            uid,
            duration_secs,
        } => {
            let canonical = canonicalize_or_error(&mut stream, &justfile)?;
            let params = AllowParams {
                justfile: canonical,
                sha256,
                target_uid: uid,
                duration_secs,
            };
            let response = handle_allow(state, params, peer_uid);
            protocol::send(&mut stream, &response)?;
        }
        Request::Run { justfile, args } => {
            let canonical = canonicalize_or_error(&mut stream, &justfile)?;
            exec::handle_run_streaming(&mut stream, state, &canonical, &args, peer_uid)?;
        }
        Request::Revoke { justfile, uid } => {
            let canonical = canonicalize_or_error(&mut stream, &justfile)?;
            let response = handle_revoke(state, &canonical, uid, peer_uid);
            protocol::send(&mut stream, &response)?;
        }
        Request::Renew {
            justfile,
            uid,
            duration_secs,
        } => {
            let canonical = canonicalize_or_error(&mut stream, &justfile)?;
            let response = handle_renew(state, &canonical, uid, duration_secs, peer_uid);
            protocol::send(&mut stream, &response)?;
        }
        Request::List => {
            let response = handle_list(&mut state.grants, peer_uid);
            protocol::send(&mut stream, &response)?;
        }
    }

    Ok(())
}

/// Canonicalize a path, sending an error response if it fails.
///
/// Returns `Ok(canonical)` on success. On failure, sends an error response
/// to the client and returns `Err` to abort further processing.
fn canonicalize_or_error(
    stream: &mut UnixStream,
    path: &std::path::Path,
) -> Result<std::path::PathBuf, Error> {
    if let Ok(canonical) = path.canonicalize() {
        return Ok(canonical);
    }
    let response = Response::Error {
        message: format!("justfile not found: {}", path.display()),
    };
    protocol::send(stream, &response)?;
    Err(Error::JustfileNotFound(path.to_path_buf()))
}

/// Get the effective UID of the connected peer via `SO_PEERCRED`.
fn get_peer_uid(stream: &UnixStream) -> Result<u32, Error> {
    use std::os::unix::io::AsFd;
    let creds = getsockopt(&stream.as_fd(), PeerCredentials).map_err(std::io::Error::other)?;
    Ok(creds.uid())
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::ops::ControlFlow;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use crate::audit::AuditLog;
    use crate::grant::GrantStore;
    use crate::hash;
    use crate::protocol::{self, Request, Response};

    use super::{ServerState, handle_connection};

    fn test_state() -> ServerState {
        ServerState {
            grants: GrantStore::new(),
            audit: AuditLog::open(None).expect("noop audit"),
        }
    }

    fn my_uid() -> u32 {
        nix::unistd::getuid().as_raw()
    }

    #[test]
    fn handle_connection_run_with_valid_grant() {
        let dir = tempfile::tempdir().expect("tempdir");
        let justfile_path = dir.path().join("Justfile");

        {
            let mut file = std::fs::File::create(&justfile_path).expect("create");
            writeln!(file, "hello:\n    echo hi").expect("write");
        }

        let sha256 = hash::sha256_file(&justfile_path).expect("hash");
        let uid = my_uid();

        let mut state = test_state();
        state.grants.insert(
            uid,
            justfile_path.clone(),
            sha256,
            Duration::from_secs(3600),
        );

        let (mut client, server_end) = UnixStream::pair().expect("pair");
        let request = Request::Run {
            justfile: justfile_path.clone(),
            args: vec![String::from("hello")],
        };
        protocol::send(&mut client, &request).expect("send");
        // Shut down writing so the server can read EOF after the msg.
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown");

        handle_connection(server_end, &mut state).expect("handle");

        let mut got_output = false;
        let mut got_exit = false;

        let _ = protocol::recv_each::<Response, _>(&client, |resp| match resp {
            Response::OutputLine { .. } => {
                got_output = true;
                ControlFlow::Continue(())
            }
            Response::Exit { exit_code } => {
                assert_eq!(exit_code, 0);
                got_exit = true;
                ControlFlow::Break(())
            }
            _ => ControlFlow::Continue(()),
        });

        assert!(got_output, "should have received output");
        assert!(got_exit, "should have received exit");
    }

    #[test]
    fn handle_connection_run_denied_no_grant() {
        let dir = tempfile::tempdir().expect("tempdir");
        let justfile_path = dir.path().join("Justfile");
        std::fs::write(&justfile_path, b"hello:\n    echo hi").expect("write");

        let (mut client, server_end) = UnixStream::pair().expect("pair");
        let request = Request::Run {
            justfile: justfile_path,
            args: vec![],
        };
        protocol::send(&mut client, &request).expect("send");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown");

        let mut state = test_state();
        // handle_connection may return Ok or Err depending on the error path;
        // the important thing is the client receives an Error response.
        let _ = handle_connection(server_end, &mut state);

        let mut got_error = false;
        let _ = protocol::recv_each::<Response, _>(&client, |resp| {
            if matches!(resp, Response::Error { .. }) {
                got_error = true;
            }
            ControlFlow::Break(())
        });
        assert!(got_error);
    }

    #[test]
    fn handle_connection_allow_denied_non_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let justfile_path = dir.path().join("Justfile");
        std::fs::write(&justfile_path, b"hello:\n    echo hi").expect("write");

        let (mut client, server_end) = UnixStream::pair().expect("pair");
        let request = Request::Allow {
            justfile: justfile_path,
            sha256: String::from("abc"),
            uid: 1000,
            duration_secs: 60,
        };
        protocol::send(&mut client, &request).expect("send");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown");

        let mut state = test_state();
        handle_connection(server_end, &mut state).expect("handle");

        let resp: Response = protocol::recv(&client).expect("recv");
        assert!(matches!(resp, Response::Error { .. }));
    }
}
