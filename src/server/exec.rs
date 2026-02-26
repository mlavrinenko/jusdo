use std::io::BufRead;
use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::sync::mpsc;

use crate::audit::{self, AuditEntry, AuditEvent};
use crate::error::Error;
use crate::protocol::{self, Response};

use super::ServerState;
use super::handlers;

/// Validate a Run request then stream output back over the socket.
pub(crate) fn handle_run_streaming(
    stream: &mut UnixStream,
    state: &mut ServerState,
    justfile: &std::path::Path,
    args: &[String],
    peer_uid: u32,
) -> Result<(), Error> {
    if let Err(err) = handlers::validate_run(&mut state.grants, justfile, args, peer_uid) {
        state.audit.log(&AuditEntry {
            timestamp: audit::now_epoch_secs(),
            peer_uid,
            event: AuditEvent::RunDenied,
            uid: peer_uid,
            path: justfile.display().to_string(),
            detail: Some(err.to_string()),
        });
        let response = Response::Error {
            message: err.to_string(),
        };
        protocol::send(stream, &response)?;
        return Ok(());
    }

    state.audit.log(&AuditEntry {
        timestamp: audit::now_epoch_secs(),
        peer_uid,
        event: AuditEvent::RunOk,
        uid: peer_uid,
        path: justfile.display().to_string(),
        detail: None,
    });

    execute_just_streaming(stream, justfile, args)
}

/// A line read from the child process.
enum OutputMsg {
    Line { stream: String, line: String },
    Done,
}

/// Read lines from a child pipe and forward them as [`OutputMsg`]s.
fn pipe_reader(pipe: Option<impl std::io::Read>, name: &str, tx: &mpsc::Sender<OutputMsg>) {
    if let Some(reader) = pipe {
        for line in BufReader::new(reader).lines() {
            match line {
                Ok(text) => {
                    let _ = tx.send(OutputMsg::Line {
                        stream: String::from(name),
                        line: text,
                    });
                }
                Err(err) => {
                    log::warn!("{name} read error: {err}");
                    break;
                }
            }
        }
    }
    let _ = tx.send(OutputMsg::Done);
}

/// Spawn `just`, stream stdout/stderr line-by-line over the socket.
///
/// # Security notes
///
/// - **Runs as root**: The daemon (and thus the child `just` process) runs
///   as root. Recipes in the Justfile execute with full root privileges.
///   This is by design — the purpose of `jusdo` is delegated `sudo just`.
///
/// - **TOCTOU**: There is an inherent race between `validate_run` (which
///   hashes the file) and `Command::new("just")` (which reads it again).
///   A determined attacker with write access could modify the file between
///   these two operations. Mitigating this fully would require `just` to
///   accept an already-open file descriptor or read from stdin, which it
///   currently does not support.
///
/// - **Environment**: The child's environment is cleared via `env_clear()`
///   to prevent the daemon's root environment from leaking (e.g.
///   `LD_PRELOAD`, `LD_LIBRARY_PATH`). Only `PATH`, `HOME`, and `LANG`
///   are set to minimal safe values.
fn execute_just_streaming(
    stream: &mut UnixStream,
    justfile: &std::path::Path,
    args: &[String],
) -> Result<(), Error> {
    log::info!(
        "executing: just --justfile {} {}",
        justfile.display(),
        args.join(" ")
    );

    let justfile_dir = justfile.parent().unwrap_or(std::path::Path::new("/"));

    // Clear the entire environment to prevent the daemon's root env from
    // leaking to child processes (e.g. LD_PRELOAD, credentials, tokens).
    // Only minimal, safe variables are added back.
    let mut child = Command::new("just")
        .arg("--justfile")
        .arg(justfile)
        .arg("--working-directory")
        .arg(justfile_dir)
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", "/root")
        .env("LANG", "C.UTF-8")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let (tx, rx) = mpsc::channel::<OutputMsg>();
    let child_stdout = child.stdout.take();
    let child_stderr = child.stderr.take();

    std::thread::scope(|scope| -> Result<(), Error> {
        let tx_out = tx.clone();
        scope.spawn(move || pipe_reader(child_stdout, "stdout", &tx_out));

        let tx_err = tx.clone();
        scope.spawn(move || pipe_reader(child_stderr, "stderr", &tx_err));

        drop(tx);

        for msg in &rx {
            if let OutputMsg::Line { stream: name, line } = msg {
                let response = Response::OutputLine { stream: name, line };
                protocol::send(stream, &response)?;
            }
        }

        let exit_code = child.wait()?.code().unwrap_or(-1);
        protocol::send(stream, &Response::Exit { exit_code })?;
        Ok(())
    })
}
