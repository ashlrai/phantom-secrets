//! Value-free Locus pin checks. A matching pin is an additional restriction,
//! never a credential grant or a replacement for Phantom's approval gates.
//!
//! Projects declare ownership in `.phantom.toml`:
//! ```toml
//! [phantom.locus]
//! binding = "client-a"
//! tenant = "client-a-tenant"
//! ```
//! MCP compares both fields with the primary pin, including for copy targets.
//! It never infers ownership from secret names or provider names. Global Cloud
//! and notification identities cannot be attested by this status contract and
//! are refused while pinned. A successful probe does not grant provider access
//! or implement an atomic, continuously revocable Locus credential lease.
//! Missing Locus preserves legacy behavior; a broken installed probe fails
//! closed. No runtime override accepts caller-supplied status JSON.

use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;

const MAX_STATUS_BYTES: usize = 64 * 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Explicit project ownership metadata; no credential locators or values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocusBinding {
    pub binding: String,
    pub tenant: String,
}

impl LocusBinding {
    /// Aliases follow Locus's name-component grammar. Tenant labels may contain
    /// spaces/punctuation, but cannot carry control characters or excess bytes.
    pub fn is_valid(&self) -> bool {
        !self.binding.is_empty()
            && self.binding.len() <= 128
            && self
                .binding
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            && !self.tenant.is_empty()
            && self.tenant.len() <= 256
            && self.tenant.trim() == self.tenant
            && !self.tenant.chars().any(char::is_control)
    }
}

/// Static diagnostics deliberately exclude subprocess output and JSON excerpts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LocusError {
    #[error("Locus status unavailable; run `locus status --json` in the trusted terminal before using provider secrets")]
    Unavailable,
    #[error("Locus status was invalid; provider secret use refused")]
    InvalidStatus,
    #[error("Locus pin is unhealthy or its authority is unverified; repair the pin in the trusted terminal before using provider secrets")]
    UnhealthyPin,
    #[error("Locus requires a pin; ask the operator to run `locus enter <alias>` before using provider secrets")]
    PinRequired,
    #[error("Locus status exceeded its time or output limit; provider secret use refused")]
    LimitExceeded,
}

#[derive(Deserialize)]
struct Status {
    pinned: bool,
    require_pin: bool,
    binding: Option<String>,
    tenant: Option<String>,
    seal_ok: Option<bool>,
    frozen: Option<bool>,
    expired: Option<bool>,
    ok: Option<bool>,
    authority_verified: Option<bool>,
}

/// Parse the value-free `locus status --json` contract. Unknown additive fields
/// are allowed, but omitted/duplicate decision fields never become approval.
pub fn parse_status_json(bytes: &[u8]) -> Result<Option<LocusBinding>, LocusError> {
    if bytes.len() > MAX_STATUS_BYTES {
        return Err(LocusError::LimitExceeded);
    }
    let status: Status = serde_json::from_slice(bytes).map_err(|_| LocusError::InvalidStatus)?;
    if !status.pinned {
        if status.require_pin {
            return Err(LocusError::PinRequired);
        }
        if status.binding.is_some()
            || status.tenant.is_some()
            || status.seal_ok.is_some()
            || status.frozen.is_some()
            || status.expired.is_some()
            || status.ok.is_some()
            || status.authority_verified.is_some()
        {
            return Err(LocusError::InvalidStatus);
        }
        return Ok(None);
    }
    if status.seal_ok != Some(true)
        || status.frozen != Some(false)
        || status.expired != Some(false)
        || status.ok != Some(true)
        || status.authority_verified != Some(true)
    {
        return Err(LocusError::UnhealthyPin);
    }
    let identity = LocusBinding {
        binding: status.binding.ok_or(LocusError::InvalidStatus)?,
        tenant: status.tenant.ok_or(LocusError::InvalidStatus)?,
    };
    if !identity.is_valid() {
        return Err(LocusError::InvalidStatus);
    }
    Ok(Some(identity))
}

fn context_present(keys: &[&str]) -> bool {
    keys.iter()
        .any(|key| std::env::var_os(key).is_some_and(|value| !value.is_empty()))
}

// Presence-only check: a removed executable must not turn a known persisted
// pin into the legacy no-Locus case. Never read sealed session contents.
fn persisted_pin_present() -> bool {
    dirs::home_dir().is_some_and(|home| {
        !matches!(
            std::fs::symlink_metadata(home.join(".locus/sessions/active.json")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        )
    })
}

fn require_selected_pin(
    binding: Option<LocusBinding>,
    selected: bool,
) -> Result<Option<LocusBinding>, LocusError> {
    if selected && binding.is_none() {
        return Err(LocusError::PinRequired);
    }
    Ok(binding)
}

/// Recheck the active pin for each guarded call. This synchronous API is also
/// safe inside an existing Tokio runtime: a dedicated current-thread runtime
/// bounds both pipe reads and process lifetime, without detached reader threads.
/// Locus may freeze a drifted pin as part of its own status check.
pub fn probe() -> Result<Option<LocusBinding>, LocusError> {
    let context = context_present(&[
        "LOCUS_HOME",
        "LOCUS_SESSION_ID",
        "LOCUS_BINDING",
        "LOCUS_CI_BINDING",
        "LOCUS_CONTROL_CAPABILITY",
        "LOCUS_EXECUTOR_CAPABILITY",
    ]) || persisted_pin_present();
    let selected = context_present(&["LOCUS_SESSION_ID", "LOCUS_BINDING", "LOCUS_CI_BINDING"]);
    std::thread::Builder::new()
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| LocusError::Unavailable)?;
            let binding =
                runtime.block_on(probe_program(OsStr::new("locus"), context, PROBE_TIMEOUT))?;
            require_selected_pin(binding, selected)
        })
        .map_err(|_| LocusError::Unavailable)?
        .join()
        .map_err(|_| LocusError::Unavailable)?
}

async fn probe_program(
    program: &OsStr,
    explicit: bool,
    deadline: Duration,
) -> Result<Option<LocusBinding>, LocusError> {
    let mut child = match tokio::process::Command::new(program)
        .args(["status", "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !explicit => {
            return Ok(None);
        }
        Err(_) => return Err(LocusError::Unavailable),
    };
    let output = child.stdout.take().ok_or(LocusError::Unavailable)?;
    let result = tokio::time::timeout(deadline, async {
        let mut bytes = Vec::new();
        output
            .take((MAX_STATUS_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| LocusError::Unavailable)?;
        if bytes.len() > MAX_STATUS_BYTES {
            return Err(LocusError::LimitExceeded);
        }
        let status = child.wait().await.map_err(|_| LocusError::Unavailable)?;
        if !status.success() {
            return Err(LocusError::Unavailable);
        }
        parse_status_json(&bytes)
    })
    .await
    .unwrap_or(Err(LocusError::LimitExceeded));
    if result.is_err() {
        // kill() also reaps. Bound cleanup separately so even a broken child
        // cannot hold the MCP server indefinitely; kill_on_drop is the fallback.
        let _ = tokio::time::timeout(Duration::from_secs(1), child.kill()).await;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pinned() -> serde_json::Value {
        json!({
            "pinned": true, "require_pin": false, "binding": "client-a",
            "tenant": "tenant-a", "seal_ok": true, "frozen": false,
            "expired": false, "ok": true, "authority_verified": true,
            "mode": "exclusive", "namespaces": ["client-a"]
        })
    }

    fn parse(value: &serde_json::Value) -> Result<Option<LocusBinding>, LocusError> {
        parse_status_json(&serde_json::to_vec(value).unwrap())
    }

    #[test]
    fn parses_value_free_pin_and_unpinned_status() {
        assert_eq!(
            parse(&pinned()).unwrap(),
            Some(LocusBinding {
                binding: "client-a".into(),
                tenant: "tenant-a".into()
            })
        );
        assert_eq!(
            parse(&json!({"pinned": false, "require_pin": false})),
            Ok(None)
        );
        assert_eq!(
            parse(&json!({"pinned": false, "require_pin": true})),
            Err(LocusError::PinRequired)
        );
    }

    #[test]
    fn unhealthy_and_incomplete_pins_fail_closed() {
        for key in ["seal_ok", "frozen", "expired", "ok", "authority_verified"] {
            let mut status = pinned();
            status[key] = json!(!status[key].as_bool().unwrap());
            assert_eq!(parse(&status), Err(LocusError::UnhealthyPin), "{key}");
            status.as_object_mut().unwrap().remove(key);
            assert!(parse(&status).is_err(), "missing {key}");
        }
        for key in ["pinned", "require_pin", "binding", "tenant"] {
            let mut status = pinned();
            status.as_object_mut().unwrap().remove(key);
            assert!(parse(&status).is_err(), "missing {key}");
        }
    }

    #[test]
    fn malformed_and_ambiguous_status_is_never_unpinned() {
        for bytes in [
            b"".as_slice(),
            b"null",
            b"{}",
            b"not json",
            br#"{"pinned":false,"pinned":true,"require_pin":false}"#,
        ] {
            assert!(parse_status_json(bytes).is_err());
        }
        assert!(parse(&json!({"pinned": false, "require_pin": false, "binding": "a"})).is_err());
        assert_eq!(
            parse_status_json(&vec![b' '; MAX_STATUS_BYTES + 1]),
            Err(LocusError::LimitExceeded)
        );
        for (key, value) in [
            ("binding", ""),
            ("tenant", ""),
            ("binding", "../a"),
            ("tenant", "a\nb"),
        ] {
            let mut status = pinned();
            status[key] = json!(value);
            assert!(parse(&status).is_err());
        }
        let mut status = pinned();
        status["binding"] = json!("a".repeat(129));
        assert!(parse(&status).is_err());
    }

    #[test]
    fn diagnostics_do_not_echo_untrusted_output() {
        let error = parse_status_json(b"private-output-must-not-be-echoed").unwrap_err();
        assert!(!error.to_string().contains("private-output"));
    }

    #[test]
    fn explicit_session_selection_cannot_fall_through_to_unpinned() {
        assert_eq!(
            require_selected_pin(None, true),
            Err(LocusError::PinRequired)
        );
        assert_eq!(require_selected_pin(None, false), Ok(None));
        let pin = parse(&pinned()).unwrap();
        assert_eq!(require_selected_pin(pin.clone(), true), Ok(pin));
    }

    #[cfg(unix)]
    fn executable(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake-locus");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        (dir, path)
    }

    #[tokio::test]
    async fn missing_executable_only_allows_absent_context() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing-locus");
        assert_eq!(
            probe_program(path.as_os_str(), false, PROBE_TIMEOUT).await,
            Ok(None)
        );
        assert_eq!(
            probe_program(path.as_os_str(), true, PROBE_TIMEOUT).await,
            Err(LocusError::Unavailable)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fake_locus_checks_arguments_and_fresh_status() {
        let (dir, path) = executable(&format!(
            "[ \"$#\" = 2 ] && [ \"$1\" = status ] && [ \"$2\" = --json ] || exit 9\nprintf '%s' '{}'", pinned()
        ));
        assert_eq!(
            probe_program(path.as_os_str(), true, PROBE_TIMEOUT)
                .await
                .unwrap()
                .unwrap()
                .binding,
            "client-a"
        );
        std::fs::write(
            dir.path().join("fake-locus"),
            "#!/bin/sh\nprintf '%s' '{\"pinned\":false,\"require_pin\":false}'\n",
        )
        .unwrap();
        assert_eq!(
            probe_program(path.as_os_str(), false, PROBE_TIMEOUT).await,
            Ok(None)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn subprocess_failures_and_limits_fail_closed() {
        let (_dir, path) =
            executable("printf '%s' '{\"pinned\":false,\"require_pin\":false}'; exit 2");
        assert_eq!(
            probe_program(path.as_os_str(), false, PROBE_TIMEOUT).await,
            Err(LocusError::Unavailable)
        );
        let (_dir, path) = executable("printf 'not-json'");
        assert_eq!(
            probe_program(path.as_os_str(), false, PROBE_TIMEOUT).await,
            Err(LocusError::InvalidStatus)
        );
        let (_dir, path) = executable("while :; do :; done");
        assert_eq!(
            probe_program(path.as_os_str(), false, Duration::from_millis(30)).await,
            Err(LocusError::LimitExceeded)
        );
        let (_dir, path) = executable("while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; done");
        assert_eq!(
            probe_program(path.as_os_str(), false, PROBE_TIMEOUT).await,
            Err(LocusError::LimitExceeded)
        );
    }
}
