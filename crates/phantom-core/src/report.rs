//! Machine-readable, value-blind report shapes shared by `phantom check --json`,
//! `phantom doctor --json`, and the MCP `phantom_check` / `phantom_doctor` tools.
//!
//! Every field carries names, paths, labels, or fixed diagnostic text. Secret
//! values and phantom token values are never recorded in these types.

use serde::Serialize;

/// One unprotected-secret finding.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct CheckFinding {
    /// `dotenv`, `staged_dotenv`, `staged_code`, or `runtime_env`.
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<&'static str>,
}

/// A risky `.phantom.toml` service route found in the staged config.
#[derive(Debug, Serialize)]
pub struct CheckConfigWarning {
    pub path: String,
    pub service: String,
    pub message: String,
}

/// A scanned file whose protection status could not be determined (for
/// example a malformed dotenv). The CLI fails closed with an error instead;
/// the MCP tool reports it here and never marks the scan clean.
#[derive(Debug, Serialize)]
pub struct CheckIndeterminate {
    pub path: String,
    pub reason: String,
}

/// The `check` report. `indeterminate` is omitted when empty and
/// `proxy_session` when false, so CLI output keeps exactly the
/// `{mode, clean, findings, warnings}` shape outside a proxy session.
#[derive(Debug, Serialize)]
pub struct CheckReport<'a> {
    pub mode: &'a str,
    pub clean: bool,
    pub findings: &'a [CheckFinding],
    pub warnings: &'a [CheckConfigWarning],
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub indeterminate: &'a [CheckIndeterminate],
    /// Runtime mode only: the scan ran inside a `phantom exec` / `phantom
    /// start` proxy session, whose own `phm_` values are expected.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub proxy_session: bool,
}

/// The variables `phantom exec` and `phantom start` set for a proxy session.
/// With both present, `phm_` values in the environment are that session's
/// own tokens, served by its proxy, not tokens left without one.
pub const PROXY_SESSION_VARS: [&str; 2] = ["PHANTOM_PROXY_PORT", "PHANTOM_PROXY_TOKEN"];

/// A runtime scan of an environment for phantom tokens.
#[derive(Debug, PartialEq, Eq)]
pub struct RuntimeEnvScan {
    /// One `runtime_env` finding per variable holding a phantom token, by
    /// name, sorted. Empty inside a proxy session.
    pub findings: Vec<CheckFinding>,
    /// Both [`PROXY_SESSION_VARS`] are set and non-empty.
    pub proxy_session: bool,
}

/// Scan every variable of an environment for a phantom token.
///
/// `phantom check --runtime` and the MCP `phantom_check` used to look only at
/// a fixed list of well-known names (and two different lists), so a token in
/// any other variable, such as one `phantom init` wrote for a custom key,
/// was reported clean. Names are recorded; values never are.
pub fn scan_runtime_env<I>(vars: I) -> RuntimeEnvScan
where
    I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
{
    let mut names = std::collections::BTreeSet::new();
    let mut session = [false; PROXY_SESSION_VARS.len()];
    for (key, raw) in vars {
        if let Some(slot) = PROXY_SESSION_VARS.iter().position(|var| key == *var) {
            session[slot] = !raw.is_empty();
        }
        if raw
            .as_encoded_bytes()
            .starts_with(crate::token::PHANTOM_PREFIX.as_bytes())
        {
            names.insert(key.to_string_lossy().into_owned());
        }
    }
    let proxy_session = session.iter().all(|set| *set);
    let findings = if proxy_session {
        Vec::new()
    } else {
        names
            .into_iter()
            .map(|name| CheckFinding {
                kind: "runtime_env",
                path: None,
                name: Some(name),
                label: None,
                pattern: None,
            })
            .collect()
    };
    RuntimeEnvScan {
        findings,
        proxy_session,
    }
}

/// One doctor line. Messages are the same value-blind text the human report
/// prints; a following `Fix:`/`Fixed:` hint attaches to the check it explains.
#[derive(Debug, Serialize)]
pub struct DoctorCheck {
    /// `pass`, `fail`, `warn`, or `info`.
    pub status: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DoctorMcpClient {
    pub client: String,
    pub path: String,
    /// `local_runtime`, `stale`, `unreadable`, `not_phantom`, or `not_configured`.
    pub state: &'static str,
}

#[derive(Debug, Default, Serialize)]
pub struct DoctorReport {
    pub ok: bool,
    pub issues: usize,
    pub fixed: usize,
    pub checks: Vec<DoctorCheck>,
    pub mcp_clients: Vec<DoctorMcpClient>,
}

impl DoctorReport {
    /// Record a new check line.
    pub fn push(&mut self, status: &'static str, message: &str) {
        self.checks.push(DoctorCheck {
            status,
            message: message.to_string(),
            fix: None,
            fixed: None,
        });
    }

    /// Attach a `Fix:` hint. One hint can follow a run of findings (each
    /// risky service route is its own warning), so it explains every trailing
    /// finding that has no hint yet.
    pub fn attach_fix(&mut self, msg: &str) {
        let mut trailing = self.checks.iter_mut().rev();
        let Some(last) = trailing.next() else { return };
        let finding = matches!(last.status, "warn" | "fail");
        last.fix = Some(msg.to_string());
        if finding {
            for check in trailing {
                if check.fix.is_some() || !matches!(check.status, "warn" | "fail") {
                    break;
                }
                check.fix = Some(msg.to_string());
            }
        }
    }

    /// Attach a `Fixed:` note to the most recent check.
    pub fn attach_fixed(&mut self, msg: &str) {
        if let Some(last) = self.checks.last_mut() {
            last.fixed = Some(msg.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_report_omits_empty_indeterminate() {
        let report = CheckReport {
            mode: "worktree",
            clean: true,
            findings: &[],
            warnings: &[],
            indeterminate: &[],
            proxy_session: false,
        };
        assert_eq!(
            serde_json::to_value(&report).unwrap(),
            serde_json::json!({"mode":"worktree","clean":true,"findings":[],"warnings":[]})
        );
    }

    fn env(pairs: &[(&str, &str)]) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
        pairs
            .iter()
            .map(|(key, raw)| ((*key).into(), (*raw).into()))
            .collect()
    }

    fn names(scan: &RuntimeEnvScan) -> Vec<&str> {
        scan.findings
            .iter()
            .map(|finding| finding.name.as_deref().unwrap_or_default())
            .collect()
    }

    #[test]
    fn runtime_scan_finds_a_phantom_token_under_any_name() {
        let placeholder = crate::token::PhantomToken::generate();
        let scan = scan_runtime_env(env(&[
            ("BILLING_SERVICE_KEY", placeholder.as_str()),
            ("OPENAI_API_KEY", placeholder.as_str()),
            ("NODE_ENV", "development"),
        ]));
        assert_eq!(names(&scan), ["BILLING_SERVICE_KEY", "OPENAI_API_KEY"]);
        assert!(!scan.proxy_session);
        assert!(scan.findings.iter().all(|f| f.kind == "runtime_env"));
    }

    #[test]
    fn runtime_scan_inside_a_proxy_session_reports_no_stray_tokens() {
        let placeholder = crate::token::PhantomToken::generate();
        let scan = scan_runtime_env(env(&[
            ("OPENAI_API_KEY", placeholder.as_str()),
            ("PHANTOM_PROXY_PORT", "43123"),
            ("PHANTOM_PROXY_TOKEN", "session"),
        ]));
        assert!(scan.proxy_session);
        assert!(scan.findings.is_empty());
    }

    #[test]
    fn runtime_scan_needs_both_session_variables() {
        let placeholder = crate::token::PhantomToken::generate();
        for partial in [
            &[("PHANTOM_PROXY_PORT", "43123")][..],
            &[("PHANTOM_PROXY_PORT", "43123"), ("PHANTOM_PROXY_TOKEN", "")][..],
        ] {
            let mut pairs = vec![("OPENAI_API_KEY", placeholder.as_str())];
            pairs.extend_from_slice(partial);
            let scan = scan_runtime_env(env(&pairs));
            assert!(!scan.proxy_session);
            assert_eq!(names(&scan), ["OPENAI_API_KEY"]);
        }
    }

    #[test]
    fn fix_hint_covers_trailing_findings_only() {
        let mut report = DoctorReport::default();
        report.push("pass", "a");
        report.push("warn", "b");
        report.push("warn", "c");
        report.attach_fix("do it");
        report.attach_fixed("done");
        assert_eq!(report.checks[0].fix, None);
        assert_eq!(report.checks[1].fix.as_deref(), Some("do it"));
        assert_eq!(report.checks[2].fix.as_deref(), Some("do it"));
        assert_eq!(report.checks[2].fixed.as_deref(), Some("done"));
    }
}
