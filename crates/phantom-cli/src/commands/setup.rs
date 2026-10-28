//! Setup command facade. Client transactions and runtime discovery live in
//! private modules; existing callers keep the same setup API.
mod claude;
mod global;
mod runtime;

use super::start::{detect_shell_syntax, format_export, ShellSyntax};
use anyhow::Result;
use clap::ValueEnum;
use claude::setup_claude_code;
pub(crate) use claude::{prepare_claude_settings, print_claude_changes, ClaudeSettingsPlan};
use colored::Colorize;
use global::{setup_codex, setup_cursor, setup_gemini, setup_windsurf};
pub(crate) use runtime::mcp_command_spec;
use std::path::{Path, PathBuf};

/// Audit mode to configure via `phantom setup --audit-mode`.
#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum AuditMode {
    /// Disable audit encryption (default).
    None,
    /// Encrypt context with local file-vault key (AES-256-GCM).
    Local,
    /// Reserved protocol mode. Hosted delivery is not commissioned.
    #[value(name = "cloud-signed")]
    CloudSigned,
}

/// AI client whose MCP config we know how to write.
#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum Client {
    /// Claude Code — registers .mcp.json and hardens project-local settings
    #[value(name = "claude", alias = "claude-code")]
    ClaudeCode,
    /// Cursor — writes ~/.cursor/mcp.json
    Cursor,
    /// Windsurf — writes ~/.codeium/windsurf/mcp_config.json
    Windsurf,
    /// Codex (OpenAI) — patches ~/.codex/config.toml
    Codex,
    /// Gemini CLI — writes `mcpServers` in ~/.gemini/settings.json
    #[value(name = "gemini", alias = "gemini-cli")]
    Gemini,
}

impl Client {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Client::ClaudeCode => "Claude Code",
            Client::Cursor => "Cursor",
            Client::Windsurf => "Windsurf",
            Client::Codex => "Codex",
            Client::Gemini => "Gemini CLI",
        }
    }
}

/// The command spec we write into each client's MCP config.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct McpCommand {
    pub(crate) command: String,
    pub(crate) args: Vec<String>,
}

#[cfg(test)]
impl McpCommand {
    pub(crate) fn for_test(command: &str, args: &[&str]) -> Self {
        Self {
            command: command.to_string(),
            args: args.iter().map(|a| a.to_string()).collect(),
        }
    }
}

impl McpCommand {
    fn toml_entry(&self) -> toml::Value {
        toml::Value::Table(toml::Table::from_iter([
            (
                "command".to_string(),
                toml::Value::String(self.command.clone()),
            ),
            (
                "args".to_string(),
                toml::Value::Array(self.args.iter().cloned().map(toml::Value::String).collect()),
            ),
        ]))
    }

    fn args_json(&self) -> serde_json::Value {
        serde_json::Value::Array(
            self.args
                .iter()
                .map(|a| serde_json::Value::String(a.clone()))
                .collect(),
        )
    }
}

pub fn run(
    client: Option<Client>,
    print: bool,
    audit_mode: Option<AuditMode>,
    replace: bool,
) -> Result<()> {
    // Handle --audit-mode independently of client setup.
    if let Some(mode) = audit_mode {
        return run_audit_mode_setup(mode);
    }

    let client = client.unwrap_or(Client::ClaudeCode);
    if replace && client == Client::ClaudeCode {
        anyhow::bail!(
            "--replace applies to Cursor, Windsurf, Gemini CLI and Codex; the Claude Code setup merges into its files and does not use it"
        );
    }
    // Resolve the MCP executable before touching any client configuration. A
    // missing local runtime must fail closed instead of leaving a config that
    // downloads and executes whatever version a package registry serves.
    let mcp = mcp_command_spec()?;

    if print {
        return print_snippet(client, &mcp);
    }

    println!(
        "{} Setting up Phantom for {}...",
        "->".blue().bold(),
        client.label().bold()
    );
    if mcp.args.first().map(|a| a == "mcp").unwrap_or(false) {
        println!(
            "   {} using bundled MCP server ({} mcp serve)",
            "note".dimmed(),
            mcp.command.dimmed()
        );
    }

    match client {
        Client::ClaudeCode => setup_claude_code(&mcp),
        Client::Cursor => setup_cursor(&mcp, replace),
        Client::Windsurf => setup_windsurf(&mcp, replace),
        Client::Codex => setup_codex(&mcp, replace),
        Client::Gemini => setup_gemini(&mcp, replace),
    }
}

// ──────────────────────────── --print ──────────────────────────

fn print_snippet(client: Client, mcp: &McpCommand) -> Result<()> {
    match client {
        Client::ClaudeCode | Client::Cursor | Client::Windsurf | Client::Gemini => {
            let body = serde_json::json!({
                "mcpServers": {
                    "phantom": {
                        "command": mcp.command,
                        "args": mcp.args_json(),
                    }
                }
            });
            let target = match client {
                Client::ClaudeCode => ".mcp.json (project; approve this server in Claude Code)",
                Client::Cursor => "~/.cursor/mcp.json",
                Client::Windsurf => "~/.codeium/windsurf/mcp_config.json",
                Client::Gemini => "~/.gemini/settings.json (merge into mcpServers)",
                _ => unreachable!(),
            };
            println!("# {} — {}", client.label(), target);
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        Client::Codex => {
            let mut servers = toml::Table::new();
            servers.insert("phantom".to_string(), mcp.toml_entry());
            let mut doc = toml::Table::new();
            doc.insert("mcp_servers".to_string(), toml::Value::Table(servers));
            println!("# Codex — ~/.codex/config.toml");
            println!("{}", toml::to_string_pretty(&doc)?);
        }
    }
    Ok(())
}

// ─────────────────────────── Helpers ───────────────────────────

// ──────────────────────────────────────────────────────────────────────────────
// Audit mode setup
// ──────────────────────────────────────────────────────────────────────────────

fn run_audit_mode_setup(mode: AuditMode) -> Result<()> {
    match mode {
        AuditMode::None => {
            println!(
                "{} Audit encryption {} (set PHANTOM_AUDIT_ENCRYPTION=none or unset it).",
                "->".blue().bold(),
                "disabled".yellow()
            );
            println!("   Remove PHANTOM_AUDIT_ENCRYPTION from your shell profile to revert.");
        }
        AuditMode::Local => {
            println!(
                "{} Audit encryption set to {} (AES-256-GCM, keyed from local HMAC key).",
                "->".blue().bold(),
                "local".cyan().bold()
            );
            println!(
                "   Add to your shell profile: {}",
                audit_mode_profile_command(detect_shell_syntax()).cyan()
            );
            println!("   Use `phantom audit verify --with-context` to decrypt event metadata.");
        }
        AuditMode::CloudSigned => {
            anyhow::bail!(
                "cloud-signed audit delivery is not commissioned in this release; no key, file, or network state was changed. Use `phantom setup --audit-mode local` for supported local audit encryption"
            );
        }
    }
    Ok(())
}

fn audit_mode_profile_command(syntax: ShellSyntax) -> String {
    format_export(syntax, "PHANTOM_AUDIT_ENCRYPTION", "local")
        .trim_start()
        .to_string()
}

fn home_dir() -> Result<PathBuf> {
    phantom_core::home::home_dir_with_platform_fallback().map_err(Into::into)
}

fn display(path: &Path) -> String {
    phantom_core::home::display_home_relative(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn audit_mode_profile_command_uses_native_fish_syntax() {
        assert_eq!(
            audit_mode_profile_command(ShellSyntax::Fish),
            "set -gx PHANTOM_AUDIT_ENCRYPTION 'local'"
        );
        assert_eq!(
            audit_mode_profile_command(ShellSyntax::Bash),
            "export PHANTOM_AUDIT_ENCRYPTION='local'"
        );
    }
}
