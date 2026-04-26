// ── Package.json helpers ────────────────────────────────────────────

use rmcp::ErrorData as McpError;

use crate::tools::helpers::internal_err;

pub fn read_package_scripts(
    pkg_path: &std::path::Path,
) -> Result<
    (
        serde_json::Value,
        serde_json::Map<String, serde_json::Value>,
    ),
    McpError,
> {
    let content = std::fs::read_to_string(pkg_path)
        .map_err(|e| internal_err(format!("Failed to read package.json: {e}")))?;
    let pkg: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| internal_err(format!("Failed to parse package.json: {e}")))?;
    let scripts = pkg
        .get("scripts")
        .and_then(|s| s.as_object())
        .cloned()
        .unwrap_or_default();
    Ok((pkg, scripts))
}

pub fn write_package_json(
    pkg_path: &std::path::Path,
    pkg: &serde_json::Value,
) -> Result<(), McpError> {
    let pretty = serde_json::to_string_pretty(pkg)
        .map_err(|e| internal_err(format!("Failed to serialize package.json: {e}")))?;
    std::fs::write(pkg_path, format!("{pretty}\n"))
        .map_err(|e| internal_err(format!("Failed to write package.json: {e}")))?;
    Ok(())
}
