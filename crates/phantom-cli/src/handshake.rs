//! Static companion metadata: never inspect configuration, environment or vault.
use std::ffi::OsString;

pub(crate) fn requested(args: impl Iterator<Item = OsString>) -> bool {
    // Only inspect root boolean flags. A subcommand, option value or `--`
    // ends the probe: child argv and credential input must never trigger it.
    args.take_while(|arg| {
        matches!(
            arg.to_str(),
            Some("--ashlr-handshake" | "--json" | "--verbose" | "-v" | "--quiet" | "-q")
        )
    })
    .any(|arg| arg == "--ashlr-handshake")
}

pub(crate) fn print() -> anyhow::Result<()> {
    let report = serde_json::json!({
        "kind": "ashlr.handshake",
        "schema_version": 1,
        "name": "phantom-secrets",
        "command": "phantom",
        "version": env!("CARGO_PKG_VERSION"),
        "protocols": {"ashlr.handshake": 1, "mcp": 1, "phantom.agent.preflight": 1},
        "capabilities": ["secret-protection", "local-proxy", "mcp-server", "agent-setup"],
        // This probe establishes capabilities, not operational/vault readiness.
        "health": {"status": "unknown", "checks": []},
        "edits": ["~/.phantom/", ".phantom.toml", ".env", ".env.example",
            ".gitignore", ".git/hooks/pre-commit", "package.json", ".mcp.json", ".claude/settings.json",
            "~/.cursor/mcp.json", "~/.codeium/windsurf/mcp_config.json",
            "~/.codex/config.toml", "~/.gemini/settings.json"],
        "receipts": []
    });
    use std::io::Write;
    writeln!(std::io::stdout().lock(), "{report}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_root_flags_trigger_probe() {
        for args in [
            vec!["--ashlr-handshake"],
            vec!["--json", "--ashlr-handshake"],
        ] {
            assert!(requested(args.into_iter().map(OsString::from)));
        }
        for args in [
            vec!["exec", "--ashlr-handshake"],
            vec!["exec", "--", "--ashlr-handshake"],
            vec!["--", "--ashlr-handshake"],
            vec!["add", "NAME", "--value", "--ashlr-handshake"],
            vec!["--ashlr-handshake-x"],
        ] {
            assert!(!requested(args.into_iter().map(OsString::from)));
        }
    }
}
