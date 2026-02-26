use std::io::{BufRead, BufReader, Read, Write};
use std::ops::ControlFlow;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::Error;

/// Maximum message size (64 KiB) to prevent abuse.
const MAX_MSG_BYTES: u64 = 64 * 1024;

/// Summary of a single active grant (used by the List response).
#[derive(Debug, Serialize, Deserialize)]
pub struct GrantInfo {
    /// User ID the grant belongs to.
    pub uid: u32,
    /// Canonical path to the Justfile.
    pub path: PathBuf,
    /// SHA-256 hash at the time the file was allowed.
    pub sha256: String,
    /// Expiration time as seconds since the Unix epoch.
    pub expires_at: String,
}

/// A request from a client to the daemon.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Request {
    /// Register a grant (sent by `sudo jusdo allow`).
    Allow {
        justfile: PathBuf,
        sha256: String,
        uid: u32,
        duration_secs: u64,
    },
    /// Execute `just` under an existing grant (sent by `jusdo run`).
    Run {
        justfile: PathBuf,
        args: Vec<String>,
    },
    /// Revoke a grant (sent by `sudo jusdo revoke`).
    Revoke { justfile: PathBuf, uid: u32 },
    /// List all active grants (sent by `sudo jusdo list`).
    List,
    /// Extend a grant's duration (sent by `sudo jusdo renew`).
    Renew {
        justfile: PathBuf,
        uid: u32,
        duration_secs: u64,
    },
}

/// A response from the daemon to a client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Response {
    /// Grant was registered successfully.
    Allowed { expires_at: String },
    /// A single line of output from `just` (streamed).
    OutputLine {
        /// Which stream: `"stdout"` or `"stderr"`.
        stream: String,
        /// The line content (including trailing newline).
        line: String,
    },
    /// The `just` process has exited.
    Exit { exit_code: i32 },
    /// A grant was revoked.
    Revoked,
    /// A grant was renewed (extended).
    Renewed { expires_at: String },
    /// List of active grants.
    Grants { grants: Vec<GrantInfo> },
    /// An error occurred.
    Error { message: String },
}

/// Send a JSON message over a Unix stream (newline-delimited).
///
/// # Errors
///
/// Returns an error if serialization or writing fails.
pub fn send(stream: &mut UnixStream, msg: &impl Serialize) -> Result<(), Error> {
    let mut buf = serde_json::to_vec(msg)?;
    buf.push(b'\n');
    stream.write_all(&buf)?;
    stream.flush()?;
    Ok(())
}

/// Read a single JSON message from a Unix stream (newline-delimited).
///
/// Note: this consumes the stream via `take()`, so it can only be called
/// once per stream. For reading multiple messages, use [`recv_each`].
///
/// # Errors
///
/// Returns an error if the stream is empty, exceeds the size limit,
/// or contains invalid JSON.
pub fn recv<T: for<'de> Deserialize<'de>>(stream: &UnixStream) -> Result<T, Error> {
    let limited = stream.take(MAX_MSG_BYTES);
    let mut reader = BufReader::new(limited);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line.is_empty() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "client disconnected",
        )));
    }
    let msg = serde_json::from_str(line.trim())?;
    Ok(msg)
}

/// Read multiple JSON messages from a stream, calling `handler` for each.
///
/// Each individual line is capped at 64 KiB to prevent unbounded
/// memory allocation from a malicious peer.
///
/// The handler returns [`ControlFlow::Continue`] to keep reading or
/// [`ControlFlow::Break`] to stop. This is designed for streaming
/// responses (e.g. `OutputLine` followed by `Exit`).
///
/// # Errors
///
/// Returns an error if reading or deserialization fails, or if a single
/// line exceeds the size limit.
pub fn recv_each<T, F>(stream: &UnixStream, mut handler: F) -> Result<(), Error>
where
    T: for<'de> Deserialize<'de>,
    F: FnMut(T) -> ControlFlow<()>,
{
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let max_line: usize = 64 * 1024;

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line)?;
        if bytes_read == 0 {
            break;
        }
        if line.len() > max_line {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "message exceeds maximum size",
            )));
        }
        let msg: T = serde_json::from_str(line.trim())?;
        if handler(msg).is_break() {
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ops::ControlFlow;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;

    use super::{GrantInfo, Request, Response, recv, recv_each, send};

    #[test]
    fn send_and_recv_request() {
        let (mut writer, reader) = UnixStream::pair().expect("pair");
        let request = Request::Allow {
            justfile: PathBuf::from("/tmp/Justfile"),
            sha256: String::from("abc123"),
            uid: 1000,
            duration_secs: 3600,
        };

        send(&mut writer, &request).expect("send");
        drop(writer);

        let received: Request = recv(&reader).expect("recv");
        match received {
            Request::Allow {
                justfile,
                sha256,
                uid,
                duration_secs,
            } => {
                assert_eq!(justfile, PathBuf::from("/tmp/Justfile"));
                assert_eq!(sha256, "abc123");
                assert_eq!(uid, 1000);
                assert_eq!(duration_secs, 3600);
            }
            _ => panic!("expected Allow"),
        }
    }

    #[test]
    fn send_and_recv_list_request() {
        let (mut writer, reader) = UnixStream::pair().expect("pair");
        let request = Request::List;
        send(&mut writer, &request).expect("send");
        drop(writer);

        let received: Request = recv(&reader).expect("recv");
        assert!(matches!(received, Request::List));
    }

    #[test]
    fn send_and_recv_response_error() {
        let (mut writer, reader) = UnixStream::pair().expect("pair");
        let response = Response::Error {
            message: String::from("test error"),
        };
        send(&mut writer, &response).expect("send");
        drop(writer);

        let received: Response = recv(&reader).expect("recv");
        match received {
            Response::Error { message } => assert_eq!(message, "test error"),
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn send_and_recv_grants_response() {
        let (mut writer, reader) = UnixStream::pair().expect("pair");
        let response = Response::Grants {
            grants: vec![GrantInfo {
                uid: 1000,
                path: PathBuf::from("/tmp/Justfile"),
                sha256: String::from("abc"),
                expires_at: String::from("9999999"),
            }],
        };
        send(&mut writer, &response).expect("send");
        drop(writer);

        let received: Response = recv(&reader).expect("recv");
        match received {
            Response::Grants { grants } => {
                assert_eq!(grants.len(), 1);
                assert_eq!(grants.first().map(|g| g.uid), Some(1000));
            }
            _ => panic!("expected Grants"),
        }
    }

    #[test]
    fn recv_empty_stream_returns_error() {
        let (writer, reader) = UnixStream::pair().expect("pair");
        drop(writer);

        let result: Result<Request, _> = recv(&reader);
        assert!(result.is_err());
    }

    #[test]
    fn recv_each_streams_multiple_messages() {
        let (mut writer, reader) = UnixStream::pair().expect("pair");

        let msgs = vec![
            Response::OutputLine {
                stream: String::from("stdout"),
                line: String::from("hello"),
            },
            Response::OutputLine {
                stream: String::from("stderr"),
                line: String::from("warn"),
            },
            Response::Exit { exit_code: 0 },
        ];

        for msg in &msgs {
            send(&mut writer, msg).expect("send");
        }
        drop(writer);

        let mut collected = Vec::new();
        recv_each::<Response, _>(&reader, |resp| {
            collected.push(resp);
            ControlFlow::Continue(())
        })
        .expect("recv_each");

        assert_eq!(collected.len(), 3);
    }

    #[test]
    fn recv_each_stops_on_break() {
        let (mut writer, reader) = UnixStream::pair().expect("pair");

        send(
            &mut writer,
            &Response::OutputLine {
                stream: String::from("stdout"),
                line: String::from("first"),
            },
        )
        .expect("send");
        send(&mut writer, &Response::Exit { exit_code: 0 }).expect("send");
        send(
            &mut writer,
            &Response::OutputLine {
                stream: String::from("stdout"),
                line: String::from("should not reach"),
            },
        )
        .expect("send");
        drop(writer);

        let mut count = 0;
        recv_each::<Response, _>(&reader, |resp| {
            count += 1;
            if matches!(resp, Response::Exit { .. }) {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })
        .expect("recv_each");

        assert_eq!(count, 2);
    }

    #[test]
    fn roundtrip_revoke_request() {
        let (mut writer, reader) = UnixStream::pair().expect("pair");
        let request = Request::Revoke {
            justfile: PathBuf::from("/tmp/Justfile"),
            uid: 1000,
        };
        send(&mut writer, &request).expect("send");
        drop(writer);

        let received: Request = recv(&reader).expect("recv");
        match received {
            Request::Revoke { justfile, uid } => {
                assert_eq!(justfile, PathBuf::from("/tmp/Justfile"));
                assert_eq!(uid, 1000);
            }
            _ => panic!("expected Revoke"),
        }
    }

    #[test]
    fn roundtrip_renew_request() {
        let (mut writer, reader) = UnixStream::pair().expect("pair");
        let request = Request::Renew {
            justfile: PathBuf::from("/tmp/Justfile"),
            uid: 1000,
            duration_secs: 1800,
        };
        send(&mut writer, &request).expect("send");
        drop(writer);

        let received: Request = recv(&reader).expect("recv");
        match received {
            Request::Renew {
                justfile,
                uid,
                duration_secs,
            } => {
                assert_eq!(justfile, PathBuf::from("/tmp/Justfile"));
                assert_eq!(uid, 1000);
                assert_eq!(duration_secs, 1800);
            }
            _ => panic!("expected Renew"),
        }
    }

    #[test]
    fn roundtrip_run_request() {
        let (mut writer, reader) = UnixStream::pair().expect("pair");
        let request = Request::Run {
            justfile: PathBuf::from("/tmp/Justfile"),
            args: vec![String::from("build"), String::from("--release")],
        };
        send(&mut writer, &request).expect("send");
        drop(writer);

        let received: Request = recv(&reader).expect("recv");
        match received {
            Request::Run { justfile, args } => {
                assert_eq!(justfile, PathBuf::from("/tmp/Justfile"));
                assert_eq!(args, vec!["build", "--release"]);
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn roundtrip_allowed_response() {
        let (mut writer, reader) = UnixStream::pair().expect("pair");
        let response = Response::Allowed {
            expires_at: String::from("1700000000"),
        };
        send(&mut writer, &response).expect("send");
        drop(writer);

        let received: Response = recv(&reader).expect("recv");
        match received {
            Response::Allowed { expires_at } => assert_eq!(expires_at, "1700000000"),
            _ => panic!("expected Allowed"),
        }
    }

    #[test]
    fn roundtrip_revoked_response() {
        let (mut writer, reader) = UnixStream::pair().expect("pair");
        send(&mut writer, &Response::Revoked).expect("send");
        drop(writer);

        let received: Response = recv(&reader).expect("recv");
        assert!(matches!(received, Response::Revoked));
    }

    #[test]
    fn roundtrip_renewed_response() {
        let (mut writer, reader) = UnixStream::pair().expect("pair");
        let response = Response::Renewed {
            expires_at: String::from("1700000000"),
        };
        send(&mut writer, &response).expect("send");
        drop(writer);

        let received: Response = recv(&reader).expect("recv");
        match received {
            Response::Renewed { expires_at } => assert_eq!(expires_at, "1700000000"),
            _ => panic!("expected Renewed"),
        }
    }
}
