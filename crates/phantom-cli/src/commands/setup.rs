use anyhow::{Context, Result};
use clap::ValueEnum;
use colored::Colorize;
use std::path::{Path, PathBuf};

/// Audit mode to configure via `phantom setup --audit-mode`.
#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum AuditMode {
    /// Disable audit encryption (default).
    None,
    /// Encrypt context with local file-vault key (AES-256-GCM).
    Local,
    /// Sign events with ED25519 + upload to phm.dev asynchronously.
    #[value(name = "cloud-signed")]
    CloudSigned,
}

/// AI client whose MCP config we know how to write.
#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum Client {
    /// Claude Code — writes .claude/settings.local.json in the project
    #[value(name = "claude", alias = "claude-code")]
    ClaudeCode,
    /// Cursor — writes ~/.cursor/mcp.json
    Cursor,
    /// Windsurf — writes ~/.codeium/windsurf/mcp_config.json
    Windsurf,
    /// Codex (OpenAI) — patches ~/.codex/config.toml
    Codex,
}

impl Client {
    fn label(self) -> &'static str {
        match self {
            Client::ClaudeCode => "Claude Code",
            Client::Cursor => "Cursor",
            Client::Windsurf => "Windsurf",
            Client::Codex => "Codex",
        }
    }
}

/// The command spec we write into each client's MCP config.
#[derive(Debug, PartialEq, Eq)]
struct McpCommand {
    command: String,
    args: Vec<String>,
}

/// Remove only the two dotenv read grants emitted by older Phantom releases.
/// Other allow rules and every deny rule are user-owned and must survive setup.
/// Returns whether the permission map changed.
pub(crate) fn remove_legacy_dotenv_read_grants(
    permissions: &mut serde_json::Map<String, serde_json::Value>,
) -> bool {
    let Some(allow) = permissions
        .get_mut("allow")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return false;
    };

    let before = allow.len();
    allow.retain(|value| !matches!(value.as_str(), Some("Read(./.env)" | "Read(./.env.*)")));
    allow.len() != before
}

impl McpCommand {
    fn args_json(&self) -> serde_json::Value {
        serde_json::Value::Array(
            self.args
                .iter()
                .map(|a| serde_json::Value::String(a.clone()))
                .collect(),
        )
    }
}

pub fn run(client: Option<Client>, print: bool, audit_mode: Option<AuditMode>) -> Result<()> {
    // Handle --audit-mode independently of client setup.
    if let Some(mode) = audit_mode {
        return run_audit_mode_setup(mode);
    }

    let client = client.unwrap_or(Client::ClaudeCode);
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
        Client::Cursor => setup_cursor(&mcp),
        Client::Windsurf => setup_windsurf(&mcp),
        Client::Codex => setup_codex(&mcp),
    }
}

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
fn mcp_command_spec() -> Result<McpCommand> {
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

// ───────────────────────── Claude Code ─────────────────────────

fn setup_claude_code(mcp: &McpCommand) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let claude_dir = project_dir.join(".claude");
    let settings_path = claude_dir.join("settings.local.json");

    std::fs::create_dir_all(&claude_dir)?;

    let mut settings: serde_json::Value = if settings_path.exists() {
        let content = std::fs::read_to_string(&settings_path)?;
        serde_json::from_str(&content).context("Failed to parse .claude/settings.local.json")?
    } else {
        serde_json::json!({})
    };

    let obj = settings
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("settings.local.json is not a JSON object"))?;

    let mcp_servers = obj
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));

    if let Some(servers) = mcp_servers.as_object_mut() {
        if !servers.contains_key("phantom") {
            servers.insert(
                "phantom".to_string(),
                serde_json::json!({
                    "command": mcp.command,
                    "args": mcp.args_json(),
                }),
            );
            println!(
                "   {} MCP server: {} -> {}",
                "+".green().bold(),
                "phantom".bold(),
                mcp.command.dimmed()
            );
        } else {
            println!("   {} MCP server already configured", "-".dimmed());
        }
    }

    // Remove legacy Phantom-managed dotenv read grants. Deny rules remain in
    // force because `.env.*` can include plaintext backups from other tools.
    let permissions = obj
        .entry("permissions")
        .or_insert_with(|| serde_json::json!({}));

    if let Some(perms) = permissions.as_object_mut() {
        if remove_legacy_dotenv_read_grants(perms) {
            println!(
                "   {} Removed legacy dotenv read permissions",
                "+".green().bold()
            );
        }

        if let Some(deny) = perms.get("deny") {
            if let Some(deny_arr) = deny.as_array() {
                let has_env_deny = deny_arr
                    .iter()
                    .any(|v| v.as_str().is_some_and(|s| s.contains(".env")));
                if has_env_deny {
                    println!(
                        "   {} Preserving dotenv deny rules as a defense-in-depth boundary",
                        "ok".green().bold()
                    );
                }
            }
        }
    }

    let content =
        serde_json::to_string_pretty(&settings).context("Failed to serialize settings")?;
    std::fs::write(&settings_path, content)?;

    println!("\n{} Claude Code configured!", "ok".green().bold());
    println!(
        "{} Phantom MCP tools are now available. {} to activate.",
        "->".blue().bold(),
        "Restart Claude Code".bold()
    );

    Ok(())
}

// ─────────────────────────── Cursor ────────────────────────────

fn setup_cursor(mcp: &McpCommand) -> Result<()> {
    let path = home_path(".cursor/mcp.json")?;
    upsert_mcp_servers_json(&path, mcp)?;
    println!(
        "\n{} Cursor configured at {}",
        "ok".green().bold(),
        display(&path).dimmed()
    );
    println!(
        "{} {} to activate.",
        "->".blue().bold(),
        "Restart Cursor".bold()
    );
    Ok(())
}

// ─────────────────────────── Windsurf ──────────────────────────

fn setup_windsurf(mcp: &McpCommand) -> Result<()> {
    let path = home_path(".codeium/windsurf/mcp_config.json")?;
    upsert_mcp_servers_json(&path, mcp)?;
    println!(
        "\n{} Windsurf configured at {}",
        "ok".green().bold(),
        display(&path).dimmed()
    );
    println!(
        "{} {} to activate.",
        "->".blue().bold(),
        "Restart Windsurf".bold()
    );
    Ok(())
}

// ──────────────────────────── Codex ────────────────────────────

fn setup_codex(mcp: &McpCommand) -> Result<()> {
    let path = home_path(".codex/config.toml")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut doc: toml::Table = if path.exists() {
        let content = std::fs::read_to_string(&path)?;
        toml::from_str(&content).context("Failed to parse ~/.codex/config.toml")?
    } else {
        toml::Table::new()
    };

    // Get-or-create [mcp_servers]
    let mcp_servers = doc
        .entry("mcp_servers".to_string())
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    let servers = mcp_servers
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("[mcp_servers] is not a table in ~/.codex/config.toml"))?;

    let already = servers.contains_key("phantom");
    let mut entry = toml::Table::new();
    entry.insert(
        "command".to_string(),
        toml::Value::String(mcp.command.clone()),
    );
    entry.insert(
        "args".to_string(),
        toml::Value::Array(
            mcp.args
                .iter()
                .map(|a| toml::Value::String(a.clone()))
                .collect(),
        ),
    );
    servers.insert("phantom".to_string(), toml::Value::Table(entry));

    let serialized = toml::to_string_pretty(&doc).context("Failed to serialize codex config")?;
    std::fs::write(&path, serialized)?;

    if already {
        println!(
            "   {} MCP server already configured -> {}",
            "-".dimmed(),
            mcp.command.dimmed()
        );
    } else {
        println!(
            "   {} MCP server: {} -> {}",
            "+".green().bold(),
            "phantom".bold(),
            mcp.command.dimmed()
        );
    }
    println!(
        "\n{} Codex configured at {}",
        "ok".green().bold(),
        display(&path).dimmed()
    );
    println!(
        "{} {} to activate.",
        "->".blue().bold(),
        "Restart Codex".bold()
    );

    Ok(())
}

// ─────────────────────── Shared JSON writer ────────────────────

/// Read-or-create a JSON file with `mcpServers.phantom = {command, args}`.
/// Used by Cursor and Windsurf, which share the same MCP config schema.
fn upsert_mcp_servers_json(path: &Path, mcp: &McpCommand) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut value: serde_json::Value = if path.exists() {
        let content = std::fs::read_to_string(path)?;
        if content.trim().is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_str(&content)
                .with_context(|| format!("Failed to parse {}", path.display()))?
        }
    } else {
        serde_json::json!({})
    };

    let obj = value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("{} is not a JSON object", path.display()))?;

    let servers = obj
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));
    let servers_obj = servers
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("mcpServers is not an object in {}", path.display()))?;

    let already = servers_obj.contains_key("phantom");
    servers_obj.insert(
        "phantom".to_string(),
        serde_json::json!({
            "command": mcp.command,
            "args": mcp.args_json(),
        }),
    );

    let content = serde_json::to_string_pretty(&value).context("Failed to serialize MCP config")?;
    std::fs::write(path, content)?;

    println!(
        "   {} MCP server: {} -> {}",
        if already {
            "-".dimmed()
        } else {
            "+".green().bold()
        },
        "phantom".bold(),
        mcp.command.dimmed()
    );

    Ok(())
}

// ──────────────────────────── --print ──────────────────────────

fn print_snippet(client: Client, mcp: &McpCommand) -> Result<()> {
    match client {
        Client::ClaudeCode | Client::Cursor | Client::Windsurf => {
            let body = serde_json::json!({
                "mcpServers": {
                    "phantom": {
                        "command": mcp.command,
                        "args": mcp.args_json(),
                    }
                }
            });
            let target = match client {
                Client::ClaudeCode => ".claude/settings.local.json (project)",
                Client::Cursor => "~/.cursor/mcp.json",
                Client::Windsurf => "~/.codeium/windsurf/mcp_config.json",
                _ => unreachable!(),
            };
            println!("# {} — {}", client.label(), target);
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        Client::Codex => {
            let mut servers = toml::Table::new();
            let mut entry = toml::Table::new();
            entry.insert(
                "command".to_string(),
                toml::Value::String(mcp.command.clone()),
            );
            entry.insert(
                "args".to_string(),
                toml::Value::Array(
                    mcp.args
                        .iter()
                        .map(|a| toml::Value::String(a.clone()))
                        .collect(),
                ),
            );
            servers.insert("phantom".to_string(), toml::Value::Table(entry));
            let mut doc = toml::Table::new();
            doc.insert("mcp_servers".to_string(), toml::Value::Table(servers));
            println!("# Codex — ~/.codex/config.toml");
            println!("{}", toml::to_string_pretty(&doc)?);
        }
    }
    Ok(())
}

// ─────────────────────────── Helpers ───────────────────────────

fn find_mcp_binary(current_exe: Option<&Path>) -> Option<PathBuf> {
    let path_match = which::which("phantom-mcp").ok();
    let cargo_bin = dirs::home_dir().map(|home| home.join(".cargo").join("bin"));
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
                "export PHANTOM_AUDIT_ENCRYPTION=local".cyan()
            );
            println!("   Use `phantom audit verify --with-context` to decrypt event metadata.");
        }
        AuditMode::CloudSigned => {
            println!(
                "{} Setting up {} audit mode...",
                "->".blue().bold(),
                "cloud-signed".cyan().bold()
            );

            match phantom_core::audit::setup_ed25519_keypair() {
                Ok((_, pubkey_hash)) => {
                    println!("   {} ED25519 keypair generated.", "+".green().bold());
                    println!(
                        "   {} Private key stored in OS keychain.",
                        "+".green().bold()
                    );
                    println!(
                        "   {} Public key written to ~/.phantom/audit-ed25519.pub",
                        "+".green().bold()
                    );
                    println!();
                    println!(
                        "   {} Public key hash (SHA-256): {}",
                        "->".blue().bold(),
                        pubkey_hash.cyan().bold()
                    );
                    println!(
                        "   Register this hash with your compliance auditor at {}",
                        "https://phm.dev/compliance".dimmed()
                    );
                    println!();
                    println!(
                        "   Add to your shell profile: {}",
                        "export PHANTOM_AUDIT_ENCRYPTION=cloud-signed".cyan()
                    );
                    println!(
                        "   Audit events will be signed and uploaded to phm.dev asynchronously."
                    );
                    println!(
                        "\n{} Cloud-signed audit mode configured!",
                        "ok".green().bold()
                    );
                }
                Err(e) => {
                    eprintln!(
                        "{} Failed to generate ED25519 keypair: {}",
                        "error".red().bold(),
                        e
                    );
                    eprintln!("   Ensure your OS keychain is accessible and try again.");
                    return Err(anyhow::anyhow!("ED25519 keypair setup failed: {e}"));
                }
            }
        }
    }
    Ok(())
}

fn home_path(rel: &str) -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not resolve home dir"))?;
    Ok(home.join(rel))
}

fn display(path: &Path) -> String {
    if let Some(home) = dirs::home_dir() {
        if let Ok(suffix) = path.strip_prefix(&home) {
            return format!("~/{}", suffix.display());
        }
    }
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use tempfile::tempdir;

    fn fake_mcp() -> McpCommand {
        McpCommand {
            command: "/usr/local/bin/phantom-mcp".to_string(),
            args: vec![],
        }
    }

    #[test]
    fn cursor_writer_creates_config_when_missing() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("mcp.json");
        upsert_mcp_servers_json(&path, &fake_mcp()).unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            v["mcpServers"]["phantom"]["command"],
            "/usr/local/bin/phantom-mcp"
        );
        assert_eq!(
            v["mcpServers"]["phantom"]["args"].as_array().unwrap().len(),
            0
        );
    }

    #[test]
    fn cursor_writer_preserves_other_settings() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("mcp.json");
        std::fs::write(
            &path,
            r#"{"mcpServers": {"other": {"command": "x"}}, "extra": 42}"#,
        )
        .unwrap();
        upsert_mcp_servers_json(&path, &fake_mcp()).unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["mcpServers"]["other"]["command"], "x");
        assert_eq!(
            v["mcpServers"]["phantom"]["command"],
            "/usr/local/bin/phantom-mcp"
        );
        assert_eq!(v["extra"], 42);
    }

    #[test]
    fn cursor_writer_replaces_existing_phantom_entry() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("mcp.json");
        std::fs::write(
            &path,
            r#"{"mcpServers": {"phantom": {"command": "/old/path", "args": ["x"]}}}"#,
        )
        .unwrap();
        upsert_mcp_servers_json(&path, &fake_mcp()).unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            v["mcpServers"]["phantom"]["command"],
            "/usr/local/bin/phantom-mcp"
        );
        assert_eq!(
            v["mcpServers"]["phantom"]["args"].as_array().unwrap().len(),
            0
        );
    }

    fn mark_executable(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(path, permissions).unwrap();
        }
    }

    #[test]
    fn standalone_resolution_prefers_path_then_current_exe_sibling() {
        let tmp = tempdir().unwrap();
        let current_exe = tmp
            .path()
            .join(format!("phantom{}", std::env::consts::EXE_SUFFIX));
        let sibling = tmp
            .path()
            .join(format!("phantom-mcp{}", std::env::consts::EXE_SUFFIX));
        let path_match = tmp
            .path()
            .join(format!("path-phantom-mcp{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&sibling, b"test").unwrap();
        std::fs::write(&path_match, b"test").unwrap();
        mark_executable(&sibling);
        mark_executable(&path_match);

        assert_eq!(
            find_mcp_binary_from(
                Some(&current_exe),
                Some(path_match.clone()),
                Some(tmp.path())
            ),
            Some(path_match)
        );
        assert_eq!(
            find_mcp_binary_from(Some(&current_exe), None, Some(tmp.path())),
            Some(sibling)
        );
    }

    #[test]
    fn standalone_resolution_rejects_non_executable_files() {
        let tmp = tempdir().unwrap();
        let current_exe = tmp
            .path()
            .join(format!("phantom{}", std::env::consts::EXE_SUFFIX));
        let sibling = tmp
            .path()
            .join(format!("phantom-mcp{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&sibling, b"test").unwrap();

        #[cfg(unix)]
        assert_eq!(find_mcp_binary_from(Some(&current_exe), None, None), None);

        #[cfg(not(unix))]
        assert_eq!(
            find_mcp_binary_from(Some(&current_exe), None, None),
            Some(sibling)
        );
    }

    #[test]
    fn command_resolution_fails_closed_without_a_local_runtime() {
        let error = resolve_mcp_command(None, None).unwrap_err().to_string();
        assert!(error.contains("Phantom MCP runtime not found"));
        assert!(error.contains("releases/tag/v0.7.3"));
        assert!(error.contains("will not download"));
        assert!(!error.contains("npx"));
    }

    #[test]
    fn legacy_dotenv_grant_removal_is_exact_and_preserves_denies() {
        let mut permissions = serde_json::json!({
            "allow": [
                "Read(./.env)",
                "Read(./.env.*)",
                "Read(./.env.example)",
                "Bash(cargo test:*)"
            ],
            "deny": ["Read(./.env)", "Read(./.env.*)", "Read(./secrets/**)"]
        });
        let expected_denies = permissions["deny"].clone();
        let permissions = permissions.as_object_mut().unwrap();

        assert!(remove_legacy_dotenv_read_grants(permissions));
        assert_eq!(
            permissions["allow"],
            serde_json::json!(["Read(./.env.example)", "Bash(cargo test:*)"])
        );
        assert_eq!(permissions["deny"], expected_denies);
        assert!(!remove_legacy_dotenv_read_grants(permissions));
    }
}
