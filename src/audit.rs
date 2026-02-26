use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::error::Error;

/// The kind of event being logged.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEvent {
    Allowed,
    Renewed,
    Revoked,
    RunOk,
    RunDenied,
}

/// A single audit log entry.
#[derive(Debug, Serialize)]
pub struct AuditEntry {
    /// Unix timestamp (seconds since epoch).
    pub timestamp: u64,
    /// UID of the peer that sent the request.
    pub peer_uid: u32,
    /// What happened.
    pub event: AuditEvent,
    /// Target user UID (for allow/renew/revoke).
    pub uid: u32,
    /// Path to the justfile.
    pub path: String,
    /// Extra detail (e.g. error message for denied runs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Append-only audit log writer.
///
/// When the inner writer is `None`, all logging is a no-op.
pub struct AuditLog {
    writer: Option<BufWriter<File>>,
}

impl AuditLog {
    /// Open an audit log file in append mode.
    ///
    /// If `path` is `None`, returns a no-op logger.
    ///
    /// # Security
    ///
    /// The audit log path should be owned by root and not writable by
    /// unprivileged users. If an attacker can place a symlink at the
    /// configured path before the daemon starts, they could redirect
    /// audit output. Ensure the parent directory is root-owned with
    /// restrictive permissions (e.g. `/var/log/jusdo/`).
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened.
    pub fn open(path: Option<&Path>) -> Result<Self, Error> {
        let writer = match path {
            Some(path) => {
                let file = OpenOptions::new().create(true).append(true).open(path)?;
                Some(BufWriter::new(file))
            }
            None => None,
        };
        Ok(Self { writer })
    }

    /// Write an audit entry as a single JSON line.
    ///
    /// Does nothing if the audit log is disabled.
    pub fn log(&mut self, entry: &AuditEntry) {
        let Some(writer) = self.writer.as_mut() else {
            return;
        };

        // Best-effort: log errors but don't fail the request.
        let Ok(json) = serde_json::to_string(entry) else {
            log::error!("failed to serialize audit entry");
            return;
        };

        if writeln!(writer, "{json}").is_err() || writer.flush().is_err() {
            log::error!("failed to write audit log entry");
        }
    }
}

/// Get the current Unix timestamp in seconds.
pub fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{AuditEntry, AuditEvent, AuditLog};

    #[test]
    fn noop_logger_does_not_panic() {
        let mut log = AuditLog::open(None).expect("noop should succeed");
        let entry = AuditEntry {
            timestamp: 1_000_000,
            peer_uid: 0,
            event: AuditEvent::Allowed,
            uid: 1000,
            path: String::from("/tmp/Justfile"),
            detail: None,
        };
        log.log(&entry);
    }

    #[test]
    fn writes_json_line_to_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");

        {
            let mut log = AuditLog::open(Some(&path)).expect("open should succeed");
            let entry = AuditEntry {
                timestamp: 1_000_000,
                peer_uid: 0,
                event: AuditEvent::Revoked,
                uid: 1000,
                path: String::from("/tmp/Justfile"),
                detail: Some(String::from("test detail")),
            };
            log.log(&entry);
        }

        let contents = std::fs::read_to_string(&path).expect("read should succeed");
        assert!(contents.contains("\"event\":\"revoked\""));
        assert!(contents.contains("\"detail\":\"test detail\""));
        assert_eq!(contents.lines().count(), 1);
    }

    #[test]
    fn now_epoch_secs_returns_nonzero() {
        let secs = super::now_epoch_secs();
        assert!(secs > 1_000_000_000);
    }

    #[test]
    fn appends_multiple_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");

        {
            let mut log = AuditLog::open(Some(&path)).expect("open");
            for event in &[
                AuditEvent::Allowed,
                AuditEvent::RunOk,
                AuditEvent::RunDenied,
            ] {
                log.log(&AuditEntry {
                    timestamp: 1_000_000,
                    peer_uid: 0,
                    event: event.clone(),
                    uid: 1000,
                    path: String::from("/tmp/Justfile"),
                    detail: None,
                });
            }
        }

        let contents = std::fs::read_to_string(&path).expect("read");
        assert_eq!(contents.lines().count(), 3);
        assert!(contents.contains("\"event\":\"allowed\""));
        assert!(contents.contains("\"event\":\"run_ok\""));
        assert!(contents.contains("\"event\":\"run_denied\""));
    }

    #[test]
    fn detail_field_omitted_when_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");

        {
            let mut log = AuditLog::open(Some(&path)).expect("open");
            log.log(&AuditEntry {
                timestamp: 1_000_000,
                peer_uid: 0,
                event: AuditEvent::Renewed,
                uid: 1000,
                path: String::from("/tmp/Justfile"),
                detail: None,
            });
        }

        let contents = std::fs::read_to_string(&path).expect("read");
        assert!(!contents.contains("\"detail\""));
        assert!(contents.contains("\"event\":\"renewed\""));
    }
}
