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
