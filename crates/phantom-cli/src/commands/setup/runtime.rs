//! Local executable discovery. Setup never downloads a runtime.
use super::{home_dir, McpCommand};
use anyhow::Result;
use std::path::{Path, PathBuf};

/// Resolve the command + args we want each MCP client to invoke.
///
/// Resolution order:
///   1. Current executable + `["mcp", "serve"]` — the bundled in-process server
///      (always preferred: one binary, no PATH dependency).
///   2. A verified local `phantom-mcp` binary on PATH, next to the current
///      executable, or in Cargo's default bin directory — legacy standalone.
///
/// Setup deliberately has no network fallback. Downloading an unpinned npm
/// package here could silently configure a different release than the CLI the
/// user reviewed and installed.
pub(crate) fn mcp_command_spec() -> Result<McpCommand> {
    let current_exe = std::env::current_exe().ok();
    let standalone = find_mcp_binary(current_exe.as_deref());
    resolve_mcp_command(current_exe.as_deref(), standalone.as_deref())
}

fn resolve_mcp_command(
    current_exe: Option<&Path>,
    standalone: Option<&Path>,
) -> Result<McpCommand> {
    // (1) Prefer the bundled subcommand in the current binary.
    if let Some(exe) = current_exe.filter(|path| is_runnable_file(path)) {
        return Ok(McpCommand {
            command: exe.to_string_lossy().into_owned(),
            args: vec!["mcp".to_string(), "serve".to_string()],
        });
    }

    // (2) Fall back to a separate phantom-mcp binary on disk / PATH.
    if let Some(path) = standalone.filter(|path| is_runnable_file(path)) {
        return Ok(McpCommand {
            command: path.to_string_lossy().into_owned(),
            args: vec![],
        });
    }

    anyhow::bail!(
        "Phantom MCP runtime not found. Reinstall both `phantom` and `phantom-mcp` \
         from the same v{} release (https://github.com/ashlrai/phantom-secrets/releases/tag/v{}) \
         and ensure the installed binaries are executable. `phantom setup` will not download \
         or execute an unpinned registry package.",
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_VERSION")
    )
}

fn find_mcp_binary(current_exe: Option<&Path>) -> Option<PathBuf> {
    let path_match = which::which("phantom-mcp").ok();
    let cargo_bin = home_dir().ok().map(|home| home.join(".cargo").join("bin"));
    find_mcp_binary_from(current_exe, path_match, cargo_bin.as_deref())
}

fn find_mcp_binary_from(
    current_exe: Option<&Path>,
    path_match: Option<PathBuf>,
    cargo_bin: Option<&Path>,
) -> Option<PathBuf> {
    let binary_name = format!("phantom-mcp{}", std::env::consts::EXE_SUFFIX);
    let sibling = current_exe.and_then(|exe| exe.parent().map(|dir| dir.join(&binary_name)));
    let cargo_candidate = cargo_bin.map(|dir| dir.join(&binary_name));

    [path_match, sibling, cargo_candidate]
        .into_iter()
        .flatten()
        .find(|path| is_runnable_file(path))
}

fn is_runnable_file(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }

    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(test)]
mod tests;
