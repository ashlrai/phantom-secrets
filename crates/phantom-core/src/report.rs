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

/// The `check` report. `indeterminate` is omitted when empty, so CLI output
/// keeps exactly the `{mode, clean, findings, warnings}` shape.
#[derive(Debug, Serialize)]
pub struct CheckReport<'a> {
    pub mode: &'a str,
    pub clean: bool,
    pub findings: &'a [CheckFinding],
    pub warnings: &'a [CheckConfigWarning],
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub indeterminate: &'a [CheckIndeterminate],
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
        };
        assert_eq!(
            serde_json::to_value(&report).unwrap(),
            serde_json::json!({"mode":"worktree","clean":true,"findings":[],"warnings":[]})
        );
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
