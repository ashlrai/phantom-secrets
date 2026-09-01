// ── Package.json helpers ────────────────────────────────────────────

use rmcp::ErrorData as McpError;

use crate::tools::helpers::internal_err;

pub fn read_package_scripts(
    pkg_path: &std::path::Path,
) -> Result<(serde_json::Value, Vec<u8>), McpError> {
    let content = phantom_core::fs::read_regular_file(pkg_path)
        .map_err(|e| internal_err(format!("Failed to safely read package.json: {e}")))?
        .ok_or_else(|| internal_err("No package.json found in project directory."))?;
    let pkg: serde_json::Value = serde_json::from_slice(&content)
        .map_err(|e| internal_err(format!("Failed to parse package.json: {e}")))?;
    Ok((pkg, content))
}

pub fn write_package_json(
    pkg_path: &std::path::Path,
    pkg: &serde_json::Value,
    expected_before: &[u8],
) -> Result<(), McpError> {
    let pretty = serde_json::to_string_pretty(pkg)
        .map_err(|e| internal_err(format!("Failed to serialize package.json: {e}")))?;
    phantom_core::fs::atomic_write_if_unchanged(
        pkg_path,
        Some(expected_before),
        format!("{pretty}\n").as_bytes(),
    )
    .map_err(|e| {
        internal_err(format!(
            "package.json changed after it was read; refusing to overwrite it: {e}"
        ))
    })?;
    Ok(())
}
