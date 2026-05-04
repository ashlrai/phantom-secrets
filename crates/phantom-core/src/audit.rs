//! Opt-in audit log for vault and sync operations.
//!
//! Writes one JSON object per line to `~/.phantom/audit.log`. Disabled by
//! default; turn on by exporting `PHANTOM_AUDIT=1`. The log records the
//! **name** of secrets accessed (for forensics) but never the **value** —
//! values must never appear in the log under any circumstance.
//!
//! Schema (per line):
//! ```json
//! {"ts": 1714794600, "op": "vault.store", "name": "OPENAI_API_KEY",
//!  "process": "phantom", "pid": 12345}
//! ```
//!
//! `ts` is seconds since the UNIX epoch. `name` is omitted for ops that
//! don't operate on a single named secret (e.g. `cloud.push`).

use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Returns true if audit logging is currently enabled.
pub fn enabled() -> bool {
    std::env::var("PHANTOM_AUDIT")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "True"))
        .unwrap_or(false)
}

/// Log an audit event. Best-effort: errors are swallowed so audit failures
/// can never break a vault op. No-op when [`enabled`] is false.
///
/// # Important
/// `name` MUST be a secret name (e.g. `OPENAI_API_KEY`), never a secret
/// value. Callers in security-sensitive code paths must not pass values.
pub fn log(op: &str, name: Option<&str>) {
    if !enabled() {
        return;
    }
    let _ = write_event(op, name);
}

fn write_event(op: &str, name: Option<&str>) -> std::io::Result<()> {
    let path = log_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let event = AuditEvent {
        ts: now_unix(),
        op: op.to_string(),
        name: name.map(|s| s.to_string()),
        process: process_name(),
        pid: std::process::id(),
    };

    let mut line = serde_json::to_vec(&event)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    line.push(b'\n');

    // OpenOptions::append on Linux/macOS gives O_APPEND atomicity for
    // writes <= PIPE_BUF (~4096 bytes) which our JSONL lines easily fit
    // under, so we don't take an explicit lock. Windows append semantics
    // are similar with FILE_APPEND_DATA.
    let mut f = OpenOptions::new().append(true).create(true).open(&path)?;
    f.write_all(&line)?;
    Ok(())
}

#[derive(Serialize)]
struct AuditEvent {
    ts: u64,
    op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    process: String,
    pid: u32,
}

pub fn log_path() -> std::io::Result<PathBuf> {
    if let Some(home) = dirs_home_dir() {
        Ok(home.join(".phantom").join("audit.log"))
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "could not resolve home directory",
        ))
    }
}

fn dirs_home_dir() -> Option<PathBuf> {
    if let Ok(h) = std::env::var("HOME") {
        if !h.is_empty() {
            return Some(PathBuf::from(h));
        }
    }
    if let Ok(h) = std::env::var("USERPROFILE") {
        if !h.is_empty() {
            return Some(PathBuf::from(h));
        }
    }
    None
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn process_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "phantom".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::sync::Mutex;
    use tempfile::tempdir;

    /// All tests in this module mutate process-wide env vars
    /// (`PHANTOM_AUDIT`, `HOME`). cargo runs unit tests in parallel by
    /// default within a test binary, so we serialize via this mutex to
    /// keep them deterministic without a `serial_test` dependency.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_temp_home<F: FnOnce()>(env: &str, val: &str, f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var(env).ok();
        // SAFETY: env mutation is serialized via ENV_LOCK above.
        unsafe {
            std::env::set_var(env, val);
        }
        f();
        unsafe {
            match prev {
                Some(p) => std::env::set_var(env, p),
                None => std::env::remove_var(env),
            }
        }
    }

    #[test]
    fn disabled_by_default() {
        with_temp_home("PHANTOM_AUDIT", "", || {
            assert!(!enabled());
        });
    }

    #[test]
    fn enabled_when_env_set_to_one() {
        with_temp_home("PHANTOM_AUDIT", "1", || {
            assert!(enabled());
        });
    }

    #[test]
    fn writes_jsonl_line_when_enabled() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let prev_home = std::env::var("HOME").ok();
        let prev_audit = std::env::var("PHANTOM_AUDIT").ok();
        unsafe {
            std::env::set_var("HOME", tmp.path());
            std::env::set_var("PHANTOM_AUDIT", "1");
        }

        log("vault.store", Some("OPENAI_API_KEY"));
        log("cloud.push", None);

        let path = tmp.path().join(".phantom").join("audit.log");
        let content = std::fs::read_to_string(&path).expect("audit.log should exist");
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        let line0: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(line0["op"], "vault.store");
        assert_eq!(line0["name"], "OPENAI_API_KEY");
        assert!(line0["pid"].is_number());
        assert!(line0["ts"].is_number());

        let line1: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(line1["op"], "cloud.push");
        assert!(
            line1.get("name").is_none(),
            "name should be omitted for None"
        );

        unsafe {
            match prev_home {
                Some(p) => std::env::set_var("HOME", p),
                None => std::env::remove_var("HOME"),
            }
            match prev_audit {
                Some(p) => std::env::set_var("PHANTOM_AUDIT", p),
                None => std::env::remove_var("PHANTOM_AUDIT"),
            }
        }
    }

    #[test]
    fn no_file_written_when_disabled() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let prev_home = std::env::var("HOME").ok();
        let prev_audit = std::env::var("PHANTOM_AUDIT").ok();
        unsafe {
            std::env::set_var("HOME", tmp.path());
            std::env::remove_var("PHANTOM_AUDIT");
        }

        log("vault.store", Some("X"));
        let path = tmp.path().join(".phantom").join("audit.log");
        assert!(!path.exists(), "should not write when disabled");

        unsafe {
            match prev_home {
                Some(p) => std::env::set_var("HOME", p),
                None => std::env::remove_var("HOME"),
            }
            match prev_audit {
                Some(p) => std::env::set_var("PHANTOM_AUDIT", p),
                None => std::env::remove_var("PHANTOM_AUDIT"),
            }
        }
    }

    /// Defensive sanity: log() should NEVER write the value. We don't have
    /// a typed "value" parameter to begin with, but assert the schema's
    /// serialized form has no `value` key.
    #[test]
    fn schema_has_no_value_field() {
        let event = AuditEvent {
            ts: 0,
            op: "vault.store".to_string(),
            name: Some("KEY".to_string()),
            process: "phantom".to_string(),
            pid: 1,
        };
        let json = serde_json::to_value(&event).unwrap();
        assert!(json.get("value").is_none());
    }
}
