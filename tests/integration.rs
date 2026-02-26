use std::ops::ControlFlow;
use std::time::Duration;

use jusdo::client;
use jusdo::config::Config;
use jusdo::protocol::{self, Request, Response};

/// Create a [`Config`] that uses a temporary socket path.
fn temp_config() -> (Config, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_dir = dir.path().to_path_buf();
    let socket_path = socket_dir.join("jusdo.sock");
    let config = Config {
        socket_dir,
        socket_path,
        default_duration_mins: 60,
        expiry_warn_secs: 300,
        audit_log_path: None,
    };
    (config, dir)
}

/// Create a config with audit logging enabled.
fn temp_config_with_audit() -> (Config, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_dir = dir.path().to_path_buf();
    let socket_path = socket_dir.join("jusdo.sock");
    let audit_path = dir.path().join("audit.jsonl");
    let config = Config {
        socket_dir,
        socket_path,
        default_duration_mins: 60,
        expiry_warn_secs: 300,
        audit_log_path: Some(audit_path),
    };
    (config, dir)
}

/// Create a temporary Justfile that can be canonicalized by the server.
fn temp_justfile(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let path = dir.path().join("Justfile");
    std::fs::write(&path, "hello:\n    echo hi").expect("write justfile");
    path
}

/// Start the server in a background thread and return the config.
///
/// The server runs until the socket is removed or the thread is dropped.
fn start_server(config: &Config) {
    let cfg = config.clone();
    std::thread::spawn(move || {
        let _ = jusdo::server::run(&cfg);
    });
    // Give the server a moment to bind the socket.
    std::thread::sleep(Duration::from_millis(100));
}

// --- Tests (non-root, so all privileged operations are denied) ---

#[test]
fn server_allow_denied_for_non_root() {
    let (config, dir) = temp_config();
    start_server(&config);
    let justfile = temp_justfile(&dir);

    let request = Request::Allow {
        justfile,
        sha256: String::from("abc123"),
        uid: 1000,
        duration_secs: 3600,
    };
    let response = client::send_request(&config, &request).expect("send_request");
    match response {
        Response::Error { message } => {
            assert!(message.contains("only root"));
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[test]
fn server_revoke_denied_for_non_root() {
    let (config, dir) = temp_config();
    start_server(&config);
    let justfile = temp_justfile(&dir);

    let request = Request::Revoke {
        justfile,
        uid: 1000,
    };
    let response = client::send_request(&config, &request).expect("send_request");
    match response {
        Response::Error { message } => {
            assert!(message.contains("only root"));
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[test]
fn server_renew_denied_for_non_root() {
    let (config, dir) = temp_config();
    start_server(&config);
    let justfile = temp_justfile(&dir);

    let request = Request::Renew {
        justfile,
        uid: 1000,
        duration_secs: 3600,
    };
    let response = client::send_request(&config, &request).expect("send_request");
    match response {
        Response::Error { message } => {
            assert!(message.contains("only root"));
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[test]
fn server_list_denied_for_non_root() {
    let (config, _dir) = temp_config();
    start_server(&config);

    let response = client::send_request(&config, &Request::List).expect("send_request");
    match response {
        Response::Error { message } => {
            assert!(message.contains("only root"));
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[test]
fn server_run_no_grant_returns_error() {
    let (config, dir) = temp_config();
    start_server(&config);
    let justfile = temp_justfile(&dir);

    let request = Request::Run {
        justfile,
        args: vec![],
    };

    let mut stream = client::connect(&config).expect("connect");
    protocol::send(&mut stream, &request).expect("send");

    let mut got_error = false;
    let _ = protocol::recv_each::<Response, _>(&stream, |resp| match resp {
        Response::Error { message } => {
            assert!(
                message.contains("no active grant"),
                "unexpected error: {message}"
            );
            got_error = true;
            ControlFlow::Break(())
        }
        _ => ControlFlow::Continue(()),
    });
    assert!(got_error);
}

#[test]
fn server_handles_multiple_requests_sequentially() {
    let (config, _dir) = temp_config();
    start_server(&config);

    for _ in 0..3 {
        let response = client::send_request(&config, &Request::List).expect("send_request");
        assert!(matches!(response, Response::Error { .. }));
    }
}

#[test]
fn client_connect_to_missing_socket_returns_error() {
    let (config, _dir) = temp_config();
    // Don't start the server — socket doesn't exist.
    let result = client::connect(&config);
    assert!(result.is_err());
}

#[test]
fn client_send_request_to_missing_socket_returns_error() {
    let (config, _dir) = temp_config();
    let result = client::send_request(&config, &Request::List);
    assert!(result.is_err());
}

#[test]
fn server_with_audit_log_records_events() {
    let (config, dir) = temp_config_with_audit();
    start_server(&config);
    let justfile = temp_justfile(&dir);

    // Allow request — denied (non-root), but server still processes it.
    let request = Request::Allow {
        justfile: justfile.clone(),
        sha256: String::from("abc123"),
        uid: 1000,
        duration_secs: 3600,
    };
    let _ = client::send_request(&config, &request);

    // Run request — denied (no grant). This logs a run_denied event.
    let run_req = Request::Run {
        justfile,
        args: vec![],
    };
    let mut stream = client::connect(&config).expect("connect");
    protocol::send(&mut stream, &run_req).expect("send");
    let _ = protocol::recv_each::<Response, _>(&stream, |_| ControlFlow::Break(()));

    // The server handles requests synchronously and flushes the audit log
    // before sending the response, so the file must exist by now.
    let audit_path = dir.path().join("audit.jsonl");
    assert!(
        audit_path.exists(),
        "audit log file should have been created"
    );
    let contents = std::fs::read_to_string(&audit_path).expect("read audit");
    assert!(
        contents.contains("run_denied"),
        "audit log should contain run_denied, got: {contents}"
    );
}
