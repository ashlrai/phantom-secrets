//! Insert a `schema` name into an existing pretty-printed JSON object.
//!
//! The bytes after the opening brace stay as the command already printed them.
//! Callers use this so `--json` gains an envelope id without reordering fields
//! or copying secret values into the new line.

use anyhow::{bail, Result};

pub(crate) const DOCTOR_SCHEMA: &str = "phantom.doctor.v1";
pub(crate) const WHY_SCHEMA: &str = "phantom.why.v1";
pub(crate) const CHECK_SCHEMA: &str = "phantom.check.v1";
pub(crate) const AGENT_DOCTOR_SCHEMA: &str = "phantom.agent.doctor.v1";
pub(crate) const FLEET_STATUS_SCHEMA: &str = "phantom.fleet_status.v1";

/// Shared `--strict` status for `phantom doctor`, `phantom why`, and
/// `phantom agent doctor`.
///
/// | Code | Meaning |
/// | --- | --- |
/// | 0 | No issues. Doctor found none, why says the key is protected, or the agent doctor verdict is `ready`. |
/// | 1 | Command failure (usage, IO, parse, or another error). This is not an issues-found result. |
/// | 2 | Issues found, only when `--strict` is set. |
///
/// A usage error also exits 2 and prints no report. An issues-found result
/// prints the report, then exits 2. Doctor counts every issue the same. A warning counts. There is no severity
/// weighting. Why uses code 2 when the JSON report is not protected, and when
/// the human view classifies the key as not protected. A missing key in the
/// human view is still a command error (code 1) because that path prints no
/// report. Agent doctor maps `degraded`, `blocked`, and `unknown` to code 2.
///
/// Without `--strict`, doctor and why keep their previous exits, and
/// `phantom agent doctor --json` stays 0. The human `phantom agent doctor`
/// view still uses the readiness report's own exit code.
pub(crate) const STRICT_ISSUES_FOUND: i32 = 2;

/// Prepend `"schema"` to a pretty-printed JSON object.
///
/// `pretty` must be `serde_json::to_string_pretty` output for an object. The
/// remainder of that text is copied unchanged.
pub(crate) fn with_schema_pretty(pretty: String, schema: &str) -> Result<String> {
    let quoted = serde_json::to_string(schema)?;
    let Some(rest) = pretty.strip_prefix("{\n") else {
        bail!("JSON report was not a pretty-printed object");
    };
    Ok(format!("{{\n  \"schema\": {quoted},\n{rest}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_line_is_inserted_without_rewriting_the_rest_or_inventing_a_value() {
        let canary = "sk-schema-canary-should-stay-put";
        let pretty = serde_json::to_string_pretty(&serde_json::json!({
            "note": canary,
            "ok": false,
        }))
        .unwrap();
        let stamped = with_schema_pretty(pretty.clone(), DOCTOR_SCHEMA).unwrap();
        let rest = pretty.strip_prefix("{\n").unwrap();
        assert!(stamped.ends_with(rest), "{stamped}");
        assert!(stamped.contains("\"schema\": \"phantom.doctor.v1\""));
        assert_eq!(stamped.matches(canary).count(), 1);
        assert!(!stamped.contains("sk-schema-canary-should-stay-put-extra"));
    }
}
