use super::start::{detect_shell_syntax, format_export, ShellSyntax};
use anyhow::{Context, Result};
use clap::ValueEnum;
use colored::Colorize;
use phantom_core::fs::{
    AnchoredCreatedDirectory, AnchoredDirectoryCreation, AnchoredEffect, AnchoredFilePermissions,
    AnchoredLock, AnchoredRead, AnchoredTarget, TrustedAnchor,
};
use phantom_vault::{ProjectDirectoryPreparation, ProjectTransactionLock};
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
pub(crate) struct McpCommand {
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

// ───────────────────────── Claude Code ─────────────────────────

fn setup_claude_code(mcp: &McpCommand) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let plan = setup_claude_code_in(&project_dir, mcp, || {})?;
    print_claude_changes(&plan, mcp);

    println!("\n{} Claude Code configured!", "ok".green().bold());
    println!(
        "{} Restart Claude Code and approve the project MCP server to activate. {}",
        "->".blue().bold(),
        "Project approval remains under your control.".bold()
    );

    Ok(())
}

fn setup_claude_code_in(
    project_dir: &Path,
    mcp: &McpCommand,
    after_lock: impl FnOnce(),
) -> Result<ClaudeSettingsPlan> {
    let lock = phantom_vault::acquire_project_transaction_lock(project_dir)
        .context("Failed to acquire the project transaction lock")?;
    after_lock();
    let preparation = prepare_project_child(&lock, ".claude", "Claude settings")?;
    let settings_path = project_dir.join(".claude/settings.local.json");
    let operation = (|| {
        let settings_target = preparation
            .anchor()
            .expect("known Claude directory preparation retains its anchor")
            .target("settings.local.json")?;
        let reviewed = settings_target
            .read_regular()
            .with_context(|| format!("Failed to safely read {}", settings_path.display()))?;
        let mcp_path = project_dir.join(".mcp.json");
        let mcp_target = lock.target(&mcp_path)?;
        let mcp_reviewed = mcp_target.read_regular()?;
        let plan = build_claude_settings_plan(&settings_path, reviewed, mcp_reviewed, mcp)?;
        apply_claude_targets(&plan, &settings_target, &mcp_target)?;
        Ok::<_, anyhow::Error>(plan)
    })();
    match operation {
        Ok(plan) => Ok(plan),
        Err(error) => {
            if let Err(cleanup_error) = cleanup_project_child(preparation, "Claude settings") {
                return Err(error).context(format!(
                    "Claude settings directory cleanup was not completed: {cleanup_error}"
                ));
            }
            Err(error)
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum McpEntryChange {
    Added,
    Updated,
    Unchanged,
}

/// A fully validated, value-free Claude settings update. Preparing a plan
/// performs every fallible read/parse/serialize step without touching disk, so
/// callers such as `phantom init` can fail before rewriting the vault or .env.
pub(crate) struct ClaudeSettingsPlan {
    settings_path: PathBuf,
    before: Option<AnchoredRead>,
    content: String,
    mcp_path: PathBuf,
    mcp_before: Option<AnchoredRead>,
    mcp_content: String,
    mcp_change: McpEntryChange,
    removed_legacy_grants: bool,
    preserves_env_deny: bool,
    changed: bool,
}

impl ClaudeSettingsPlan {
    pub(crate) fn transaction_files(&self) -> Vec<phantom_vault::InitFile> {
        let mut files = Vec::new();
        if self.mcp_change != McpEntryChange::Unchanged {
            files.push(phantom_vault::InitFile::replace_if_exact_snapshot(
                &self.mcp_path,
                self.mcp_before.as_ref(),
                self.mcp_content.as_bytes().to_vec(),
            ));
        }
        if self.changed {
            files.push(phantom_vault::InitFile::replace_if_exact_snapshot(
                &self.settings_path,
                self.before.as_ref(),
                self.content.as_bytes().to_vec(),
            ));
        }
        files
    }
}

pub(crate) fn prepare_claude_settings(
    settings_path: &Path,
    mcp: &McpCommand,
) -> Result<ClaudeSettingsPlan> {
    let project_root = claude_project_root(settings_path)?;
    let lock = phantom_vault::acquire_project_transaction_lock(project_root)
        .context("Failed to acquire the project transaction lock")?;
    let before = lock
        .target(settings_path)?
        .read_regular()
        .with_context(|| format!("Failed to safely read {}", settings_path.display()))?;
    let mcp_before = lock
        .target(project_root.join(".mcp.json"))?
        .read_regular()?;
    build_claude_settings_plan(settings_path, before, mcp_before, mcp)
}

fn build_claude_settings_plan(
    settings_path: &Path,
    before: Option<AnchoredRead>,
    mcp_before: Option<AnchoredRead>,
    mcp: &McpCommand,
) -> Result<ClaudeSettingsPlan> {
    let existed = before.is_some();
    let mut settings: serde_json::Value = if let Some(content) = before.as_ref() {
        serde_json::from_slice(content.bytes())
            .with_context(|| format!("Failed to parse {}", settings_path.display()))?
    } else {
        serde_json::json!({})
    };

    let obj = settings
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("{} is not a JSON object", settings_path.display()))?;
    // General settings are not a Claude MCP registration surface. Remove only
    // the entry owned by Phantom; preserve every unrelated setting and server.
    let removed_legacy_mcp = if let Some(servers) = obj.get_mut("mcpServers") {
        servers
            .as_object_mut()
            .ok_or_else(|| {
                anyhow::anyhow!("mcpServers is not an object in {}", settings_path.display())
            })?
            .remove("phantom")
            .is_some()
    } else {
        false
    };
    let mcp_path = claude_project_root(settings_path)?.join(".mcp.json");
    let mut mcp_config: serde_json::Value = match mcp_before.as_ref() {
        Some(before) => serde_json::from_slice(before.bytes())
            .with_context(|| format!("Failed to parse {}", mcp_path.display()))?,
        None => serde_json::json!({}),
    };
    let servers = mcp_config
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("{} is not a JSON object", mcp_path.display()))?
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("mcpServers is not an object in {}", mcp_path.display()))?;

    let desired = serde_json::json!({
        "command": mcp.command,
        "args": mcp.args_json(),
    });
    let mcp_change = match servers.get("phantom") {
        None => McpEntryChange::Added,
        Some(existing) if existing == &desired => McpEntryChange::Unchanged,
        Some(_) => McpEntryChange::Updated,
    };
    if mcp_change != McpEntryChange::Unchanged {
        servers.insert("phantom".to_string(), desired);
    }

    // Remove legacy Phantom-managed dotenv read grants. Deny rules remain in
    // force because `.env.*` can include plaintext backups from other tools.
    let permissions = obj
        .entry("permissions")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "permissions is not an object in {}",
                settings_path.display()
            )
        })?;
    let removed_legacy_grants = remove_legacy_dotenv_read_grants(permissions);
    let preserves_env_deny = permissions
        .get("deny")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|deny| {
            deny.iter()
                .any(|value| value.as_str().is_some_and(|rule| rule.contains(".env")))
        });

    let content =
        serde_json::to_string_pretty(&settings).context("Failed to serialize Claude settings")?;
    Ok(ClaudeSettingsPlan {
        settings_path: settings_path.to_path_buf(),
        before,
        content,
        mcp_path,
        mcp_before,
        mcp_content: serde_json::to_string_pretty(&mcp_config)?,
        mcp_change,
        removed_legacy_grants,
        preserves_env_deny,
        changed: !existed || removed_legacy_mcp || removed_legacy_grants,
    })
}

#[cfg(test)]
fn apply_claude_settings(plan: &ClaudeSettingsPlan) -> Result<bool> {
    let project_root = claude_project_root(&plan.settings_path)?;
    let lock = phantom_vault::acquire_project_transaction_lock(project_root)
        .context("Failed to acquire the project transaction lock")?;
    apply_claude_targets(
        plan,
        &lock.target(&plan.settings_path)?,
        &lock.target(&plan.mcp_path)?,
    )
}

fn apply_claude_targets(
    plan: &ClaudeSettingsPlan,
    settings_target: &AnchoredTarget,
    mcp_target: &AnchoredTarget,
) -> Result<bool> {
    apply_claude_targets_with(plan, settings_target, mcp_target, || {})
}

fn apply_claude_targets_with(
    plan: &ClaudeSettingsPlan,
    settings_target: &AnchoredTarget,
    mcp_target: &AnchoredTarget,
    before_settings_write: impl FnOnce(),
) -> Result<bool> {
    let updates = [
        (
            mcp_target,
            &plan.mcp_path,
            plan.mcp_before.as_ref(),
            plan.mcp_content.as_bytes(),
            plan.mcp_change != McpEntryChange::Unchanged,
        ),
        (
            settings_target,
            &plan.settings_path,
            plan.before.as_ref(),
            plan.content.as_bytes(),
            plan.changed,
        ),
    ];
    // Both files are validated before the first effect. Exact snapshots bind
    // identity and permissions as well as content, including unchanged files.
    for (target, path, before, _, _) in &updates {
        if target.read_regular()?.as_ref() != *before {
            anyhow::bail!(
                "{} changed after setup read it; refusing to overwrite the concurrent edit",
                path.display()
            );
        }
    }
    let mut committed: Vec<(&AnchoredTarget, Option<&AnchoredRead>, AnchoredRead)> = Vec::new();
    let mut before_settings_write = Some(before_settings_write);
    for (index, (target, path, before, content, changed)) in updates.into_iter().enumerate() {
        if !changed {
            continue;
        }
        if index == 1 {
            before_settings_write
                .take()
                .expect("settings write hook runs once")();
        }
        let permissions = before
            .map(AnchoredRead::permissions)
            .unwrap_or_else(AnchoredFilePermissions::private);
        match target.replace_if_exact_with_permissions(before, content, permissions) {
            Ok(AnchoredEffect::Durable(after)) => committed.push((target, before, after)),
            Ok(AnchoredEffect::CommittedVerifiedButDurabilityUncertain { value: after }) => {
                eprintln!("warning: Claude configuration replacement committed and was verified, but directory crash durability is not provable on this platform");
                committed.push((target, before, after));
            }
            Ok(AnchoredEffect::CommittedButUncertain { error, .. }) => {
                anyhow::bail!("Partial Claude setup: {} was replaced, but verification or durability is uncertain: {error}. Reconcile both configuration files before retrying.", path.display());
            }
            Err(error) => {
                let mut restored = true;
                for (target, before, after) in committed.iter().rev() {
                    restored &= rollback_claude_target(target, *before, after);
                }
                if !restored {
                    anyhow::bail!("Partial Claude setup: {} failed: {error}; exact rollback could not restore every configuration file. Reconcile both files before retrying.", path.display());
                }
                return Err(error).with_context(|| {
                    format!(
                        "Claude setup failed at {}; previous configuration changes were restored",
                        path.display()
                    )
                });
            }
        }
    }
    Ok(!committed.is_empty())
}

fn rollback_claude_target(
    target: &AnchoredTarget,
    before: Option<&AnchoredRead>,
    after: &AnchoredRead,
) -> bool {
    let effect = match before {
        Some(before) => target
            .replace_if_exact_with_permissions(Some(after), before.bytes(), before.permissions())
            .map(|effect| match effect {
                AnchoredEffect::Durable(_) => AnchoredEffect::Durable(()),
                AnchoredEffect::CommittedVerifiedButDurabilityUncertain { .. } => {
                    AnchoredEffect::CommittedVerifiedButDurabilityUncertain { value: () }
                }
                AnchoredEffect::CommittedButUncertain { error, .. } => {
                    AnchoredEffect::CommittedButUncertain { value: (), error }
                }
            }),
        None => target.unlink_if_exact(after),
    };
    match effect {
        Ok(AnchoredEffect::Durable(())) => true,
        Ok(AnchoredEffect::CommittedVerifiedButDurabilityUncertain { .. }) => {
            eprintln!("warning: Claude configuration rollback committed and was verified, but directory crash durability is not provable on this platform");
            true
        }
        Ok(AnchoredEffect::CommittedButUncertain { .. }) | Err(_) => false,
    }
}

fn claude_project_root(settings_path: &Path) -> Result<&Path> {
    if settings_path.file_name().and_then(|name| name.to_str()) != Some("settings.local.json") {
        anyhow::bail!(
            "Claude project settings must be named settings.local.json: {}",
            settings_path.display()
        );
    }
    let claude_dir = settings_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Claude settings path has no parent"))?;
    if claude_dir.file_name().and_then(|name| name.to_str()) != Some(".claude") {
        anyhow::bail!(
            "Claude project settings must be inside a direct .claude directory: {}",
            settings_path.display()
        );
    }
    claude_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Claude settings path has no project root"))
}

fn prepare_project_child(
    lock: &ProjectTransactionLock,
    name: &str,
    label: &str,
) -> Result<ProjectDirectoryPreparation> {
    match lock.prepare_private_child(name)? {
        ProjectDirectoryPreparation::CreatedVerifiedButDurabilityUncertain(receipt) => {
            eprintln!(
                "warning: {label} directory creation committed and was verified, but directory crash durability is not provable on this platform"
            );
            Ok(ProjectDirectoryPreparation::Created(receipt))
        }
        ProjectDirectoryPreparation::CommittedButUncertain { receipt, error } => {
            let cleanup = receipt.map(AnchoredCreatedDirectory::remove_if_empty_exact);
            match cleanup {
                Some(Ok(
                    AnchoredEffect::Durable(())
                    | AnchoredEffect::CommittedVerifiedButDurabilityUncertain { value: () },
                )) => {
                    eprintln!(
                        "warning: {label} directory rollback committed and was verified, but directory crash durability is not provable on this platform"
                    );
                    Err(error)
                        .with_context(|| format!("{label} directory creation was rolled back"))
                }
                _ => anyhow::bail!(
                    "{label} directory creation may have committed and exact cleanup could not be verified: {error}"
                ),
            }
        }
        preparation => Ok(preparation),
    }
}

fn cleanup_project_child(preparation: ProjectDirectoryPreparation, label: &str) -> Result<()> {
    let receipt = match preparation {
        ProjectDirectoryPreparation::Created(receipt) => receipt,
        ProjectDirectoryPreparation::CreatedVerifiedButDurabilityUncertain(receipt) => {
            eprintln!(
                "warning: {label} directory creation was verified, but directory crash durability is not provable on this platform"
            );
            receipt
        }
        ProjectDirectoryPreparation::Existing(_)
        | ProjectDirectoryPreparation::CommittedButUncertain { .. } => return Ok(()),
    };
    match receipt.remove_if_empty_exact()? {
        AnchoredEffect::Durable(()) => Ok(()),
        AnchoredEffect::CommittedVerifiedButDurabilityUncertain { value: () } => {
            eprintln!(
                "warning: {label} directory cleanup committed and was verified, but directory crash durability is not provable on this platform"
            );
            Ok(())
        }
        AnchoredEffect::CommittedButUncertain { error, .. } => anyhow::bail!(
            "{label} directory was removed, but cleanup durability could not be verified: {error}"
        ),
    }
}

pub(crate) fn print_claude_changes(plan: &ClaudeSettingsPlan, mcp: &McpCommand) {
    match plan.mcp_change {
        McpEntryChange::Added => println!(
            "   {} MCP server: {} -> {}",
            "+".green().bold(),
            "phantom".bold(),
            mcp.command.dimmed()
        ),
        McpEntryChange::Updated => println!(
            "   {} MCP server updated: {} -> {}",
            "+".green().bold(),
            "phantom".bold(),
            mcp.command.dimmed()
        ),
        McpEntryChange::Unchanged => {
            println!("   {} MCP server already configured", "-".dimmed())
        }
    }
    if plan.removed_legacy_grants {
        println!(
            "   {} Removed legacy dotenv read permissions",
            "+".green().bold()
        );
    }
    if plan.preserves_env_deny {
        println!(
            "   {} Preserving dotenv deny rules as a defense-in-depth boundary",
            "ok".green().bold()
        );
    }
}

// ─────────────────────────── Cursor ────────────────────────────

fn setup_cursor(mcp: &McpCommand) -> Result<()> {
    let home = home_dir()?;
    let path = home.join(".cursor/mcp.json");
    upsert_global_mcp_servers_json(&home, Path::new(".cursor/mcp.json"), mcp, || {})?;
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
    let home = home_dir()?;
    let path = home.join(".codeium/windsurf/mcp_config.json");
    upsert_global_mcp_servers_json(
        &home,
        Path::new(".codeium/windsurf/mcp_config.json"),
        mcp,
        || {},
    )?;
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
    let home = home_dir()?;
    setup_codex_at(&home, Path::new(".codex/config.toml"), mcp, || {})
}

fn setup_codex_at(
    home: &Path,
    relative: &Path,
    mcp: &McpCommand,
    after_lock: impl FnOnce(),
) -> Result<()> {
    let path = home.join(relative);
    let capability = retain_global_config(home, relative, after_lock)?;
    let operation = (|| {
        let before = capability
            .target
            .read_regular()
            .with_context(|| format!("Failed to safely read {}", path.display()))?;
        let mut doc: toml::Table = if let Some(content) = before.as_ref() {
            let content = std::str::from_utf8(content.bytes())
                .context("~/.codex/config.toml is not valid UTF-8")?;
            toml::from_str(content).context("Failed to parse ~/.codex/config.toml")?
        } else {
            toml::Table::new()
        };

        // Get-or-create [mcp_servers]
        let mcp_servers = doc
            .entry("mcp_servers".to_string())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        let servers = mcp_servers.as_table_mut().ok_or_else(|| {
            anyhow::anyhow!("[mcp_servers] is not a table in ~/.codex/config.toml")
        })?;

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

        let serialized =
            toml::to_string_pretty(&doc).context("Failed to serialize codex config")?;
        let permissions = before
            .as_ref()
            .map(AnchoredRead::permissions)
            .unwrap_or_else(AnchoredFilePermissions::private);
        let effect = capability.target.replace_if_exact_with_permissions(
            before.as_ref(),
            serialized.as_bytes(),
            permissions,
        )?;
        Ok::<_, anyhow::Error>((already, effect))
    })();
    let already = finish_global_operation(capability, operation, &path)?;

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
#[cfg(test)]
fn upsert_mcp_servers_json(path: &Path, mcp: &McpCommand) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Configuration path has no parent: {}", path.display()))?;
    let leaf = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Configuration path has no filename: {}", path.display()))?;
    upsert_global_mcp_servers_json(parent, Path::new(leaf), mcp, || {})
}

fn upsert_global_mcp_servers_json(
    home: &Path,
    relative: &Path,
    mcp: &McpCommand,
    after_lock: impl FnOnce(),
) -> Result<()> {
    let path = home.join(relative);
    let capability = retain_global_config(home, relative, after_lock)?;
    let operation = (|| {
        let before = capability
            .target
            .read_regular()
            .with_context(|| format!("Failed to safely read {}", path.display()))?;
        let mut value: serde_json::Value = if let Some(content) = before.as_ref() {
            serde_json::from_slice(content.bytes())
                .with_context(|| format!("Failed to parse {}", path.display()))?
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

        let content =
            serde_json::to_string_pretty(&value).context("Failed to serialize MCP config")?;
        let permissions = before
            .as_ref()
            .map(AnchoredRead::permissions)
            .unwrap_or_else(AnchoredFilePermissions::private);
        let effect = capability.target.replace_if_exact_with_permissions(
            before.as_ref(),
            content.as_bytes(),
            permissions,
        )?;
        Ok::<_, anyhow::Error>((already, effect))
    })();
    let already = finish_global_operation(capability, operation, &path)?;

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

enum RetainedConfigDirectory {
    Existing(TrustedAnchor),
    Created(AnchoredCreatedDirectory),
}

impl RetainedConfigDirectory {
    fn anchor(&self) -> &TrustedAnchor {
        match self {
            Self::Existing(anchor) => anchor,
            Self::Created(receipt) => receipt.anchor(),
        }
    }
}

struct GlobalConfigCapability {
    _lock: AnchoredLock,
    target: AnchoredTarget,
    created_directories: Vec<AnchoredCreatedDirectory>,
}

impl GlobalConfigCapability {
    fn cleanup(self, label: &Path) -> Result<()> {
        let Self {
            _lock,
            target,
            created_directories,
        } = self;
        drop(target);
        drop(_lock);
        cleanup_global_directories(created_directories, label)
    }
}

fn retain_global_config(
    home: &Path,
    relative: &Path,
    after_lock: impl FnOnce(),
) -> Result<GlobalConfigCapability> {
    let portable = relative.to_str().ok_or_else(|| {
        anyhow::anyhow!(
            "Global client config path must be valid UTF-8 beneath the authorized home root: {}",
            relative.display()
        )
    })?;
    if portable.contains('\\') || portable.contains(':') {
        anyhow::bail!(
            "Global client config must use a portable relative path beneath the authorized home root: {}",
            relative.display()
        );
    }
    let mut components = Vec::new();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(component) => components.push(component.to_os_string()),
            _ => anyhow::bail!(
                "Global client config must be one normal relative path beneath the authorized home root: {}",
                relative.display()
            ),
        }
    }
    let leaf = components.pop().ok_or_else(|| {
        anyhow::anyhow!(
            "Global client config path has no filename: {}",
            relative.display()
        )
    })?;

    let lock_home = TrustedAnchor::open_canonical(home)
        .with_context(|| format!("Failed to retain authorized home root {}", home.display()))?;
    let traversal_home = TrustedAnchor::open_canonical(home)
        .with_context(|| format!("Failed to retain authorized home root {}", home.display()))?;
    if lock_home.identity() != traversal_home.identity() {
        anyhow::bail!(
            "Authorized home root changed while it was retained: {}",
            home.display()
        );
    }
    let lock = acquire_global_setup_lock(&lock_home)?;

    let mut current = RetainedConfigDirectory::Existing(traversal_home);
    let mut created = Vec::new();
    for component in components {
        let next = match current.anchor().open_subdirectory(Path::new(&component)) {
            Ok(anchor) => RetainedConfigDirectory::Existing(anchor),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match current.anchor().create_private_child(Path::new(&component)) {
                    Ok(AnchoredDirectoryCreation::Durable(receipt)) => {
                        RetainedConfigDirectory::Created(receipt)
                    }
                    Ok(AnchoredDirectoryCreation::CommittedVerifiedButDurabilityUncertain {
                        receipt,
                    }) => {
                        eprintln!(
                            "warning: global client directory creation committed and was verified, but directory crash durability is not provable on this platform"
                        );
                        RetainedConfigDirectory::Created(receipt)
                    }
                    Ok(AnchoredDirectoryCreation::CommittedButUncertain {
                        receipt: None,
                        error,
                    }) => {
                        append_created_directory(&mut created, current);
                        let prior_cleanup = cleanup_global_directories(created, relative);
                        anyhow::bail!(
                            "Global client directory creation may have committed without an exact receipt; the attempted directory cannot be cleaned up safely: {error}; prior cleanup: {}",
                            prior_cleanup
                                .err()
                                .map_or_else(|| "complete".to_string(), |cleanup| cleanup.to_string())
                        );
                    }
                    Ok(AnchoredDirectoryCreation::CommittedButUncertain {
                        receipt: Some(receipt),
                        error,
                    }) => {
                        append_created_directory(&mut created, current);
                        created.push(receipt);
                        return match cleanup_global_directories(created, relative) {
                            Ok(()) => Err(error)
                                .context("Global client directory creation was rolled back exactly"),
                            Err(cleanup) => anyhow::bail!(
                                "Global client directory creation may have committed and exact cleanup could not be verified: {error}; cleanup: {cleanup}"
                            ),
                        };
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        match current.anchor().open_subdirectory(Path::new(&component)) {
                            Ok(anchor) => RetainedConfigDirectory::Existing(anchor),
                            Err(open_error) => {
                                append_created_directory(&mut created, current);
                                cleanup_global_directories(created, relative)?;
                                return Err(open_error).with_context(|| {
                                    format!(
                                        "Global client config directory raced with another owner beneath {}",
                                        home.display()
                                    )
                                });
                            }
                        }
                    }
                    Err(error) => {
                        append_created_directory(&mut created, current);
                        cleanup_global_directories(created, relative)?;
                        return Err(error).with_context(|| {
                            format!(
                                "Failed to create global client config directory beneath {}",
                                home.display()
                            )
                        });
                    }
                }
            }
            Err(error) => {
                append_created_directory(&mut created, current);
                cleanup_global_directories(created, relative)?;
                return Err(error).with_context(|| {
                    format!(
                        "Refusing unsafe global client config directory beneath {}",
                        home.display()
                    )
                });
            }
        };
        append_created_directory(&mut created, current);
        current = next;
    }

    after_lock();
    let target = match current.anchor().target(Path::new(&leaf)) {
        Ok(target) => target,
        Err(error) => {
            drop(lock);
            append_created_directory(&mut created, current);
            cleanup_global_directories(created, relative)?;
            return Err(error).with_context(|| {
                format!(
                    "Failed to retain global client config {}",
                    relative.display()
                )
            });
        }
    };
    append_created_directory(&mut created, current);
    Ok(GlobalConfigCapability {
        _lock: lock,
        target,
        created_directories: created,
    })
}

fn acquire_global_setup_lock(home: &TrustedAnchor) -> Result<AnchoredLock> {
    let directory = match home.open_subdirectory(".phantom") {
        Ok(anchor) => RetainedConfigDirectory::Existing(anchor),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match home.create_private_child(".phantom") {
                Ok(AnchoredDirectoryCreation::Durable(receipt)) => {
                    RetainedConfigDirectory::Created(receipt)
                }
                Ok(
                    AnchoredDirectoryCreation::CommittedVerifiedButDurabilityUncertain {
                        receipt,
                    },
                ) => {
                    eprintln!(
                        "warning: global setup-state directory creation committed and was verified, but directory crash durability is not provable on this platform"
                    );
                    RetainedConfigDirectory::Created(receipt)
                }
                Ok(AnchoredDirectoryCreation::CommittedButUncertain {
                    receipt: Some(receipt),
                    error,
                }) => {
                    return match receipt.remove_if_empty_exact() {
                        Ok(
                            AnchoredEffect::Durable(())
                            | AnchoredEffect::CommittedVerifiedButDurabilityUncertain {
                                value: (),
                            },
                        ) => {
                            eprintln!(
                                "warning: global setup-state directory rollback committed and was verified, but directory crash durability is not provable on this platform"
                            );
                            Err(error).context(
                                "Global setup-state directory creation was rolled back exactly",
                            )
                        }
                        _ => anyhow::bail!(
                            "Global setup-state directory creation may have committed and exact cleanup could not be verified: {error}"
                        ),
                    };
                }
                Ok(AnchoredDirectoryCreation::CommittedButUncertain {
                    receipt: None,
                    error,
                }) => anyhow::bail!(
                    "Global setup-state directory creation may have committed without an exact receipt and cannot be cleaned up safely: {error}"
                ),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    RetainedConfigDirectory::Existing(
                        home.open_subdirectory(".phantom").with_context(|| {
                            "Global setup-state directory raced with another owner"
                        })?,
                    )
                }
                Err(error) => {
                    return Err(error).context("Failed to create global setup-state directory")
                }
            }
        }
        Err(error) => return Err(error).context("Refusing unsafe global setup-state directory"),
    };
    match directory.anchor().acquire_lock("client-setup.lock") {
        Ok(lock) => Ok(lock),
        Err(error) => {
            if let RetainedConfigDirectory::Created(receipt) = directory {
                match receipt.remove_if_empty_exact()? {
                    AnchoredEffect::Durable(()) => {}
                    AnchoredEffect::CommittedVerifiedButDurabilityUncertain { value: () } => {
                        eprintln!(
                            "warning: global setup-state cleanup committed and was verified, but directory crash durability is not provable on this platform"
                        );
                    }
                    AnchoredEffect::CommittedButUncertain { error, .. } => anyhow::bail!(
                        "Global setup-state cleanup committed, but durability could not be verified: {error}"
                    ),
                }
            }
            Err(error).context("Failed to acquire the global client setup lock")
        }
    }
}

fn append_created_directory(
    receipts: &mut Vec<AnchoredCreatedDirectory>,
    directory: RetainedConfigDirectory,
) {
    if let RetainedConfigDirectory::Created(receipt) = directory {
        receipts.push(receipt);
    }
}

fn cleanup_global_directories(
    mut receipts: Vec<AnchoredCreatedDirectory>,
    label: &Path,
) -> Result<()> {
    while let Some(receipt) = receipts.pop() {
        match receipt.remove_if_empty_exact()? {
            AnchoredEffect::Durable(()) => {}
            AnchoredEffect::CommittedVerifiedButDurabilityUncertain { value: () } => {
                eprintln!(
                    "warning: global client directory cleanup committed and was verified, but directory crash durability is not provable on this platform"
                );
            }
            AnchoredEffect::CommittedButUncertain { error, .. } => anyhow::bail!(
                "{} directory cleanup committed, but durability could not be verified: {error}",
                label.display()
            ),
        }
    }
    Ok(())
}

fn finish_global_operation<T>(
    capability: GlobalConfigCapability,
    operation: Result<(T, AnchoredEffect<AnchoredRead>)>,
    path: &Path,
) -> Result<T> {
    match operation {
        Ok((value, AnchoredEffect::Durable(_))) => Ok(value),
        Ok((value, AnchoredEffect::CommittedVerifiedButDurabilityUncertain { .. })) => {
            eprintln!(
                "warning: global client configuration replacement committed and was verified, but directory crash durability is not provable on this platform"
            );
            Ok(value)
        }
        Ok((_, AnchoredEffect::CommittedButUncertain { error, .. })) => anyhow::bail!(
            "{} was replaced, but durability could not be verified: {error}",
            path.display()
        ),
        Err(error) => {
            capability.cleanup(path)?;
            Err(error)
        }
    }
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
                Client::ClaudeCode => ".mcp.json (project; approve this server in Claude Code)",
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
    if let Ok(home) = home_dir() {
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

    #[test]
    fn claude_writer_migrates_stale_registry_entry_and_preserves_settings() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join(".claude/settings.local.json");
        std::fs::create_dir(tmp.path().join(".claude")).unwrap();
        std::fs::write(
            &path,
            r#"{
                "mcpServers": {
                    "phantom": {"command": "npx", "args": ["-y", "phantom-secrets-mcp"]},
                    "other": {"command": "other-server"}
                },
                "theme": "dark"
            }"#,
        )
        .unwrap();

        let mcp = McpCommand {
            command: "/opt/phantom/bin/phantom".to_string(),
            args: vec!["mcp".to_string(), "serve".to_string()],
        };
        let plan = prepare_claude_settings(&path, &mcp).unwrap();
        assert!(apply_claude_settings(&plan).unwrap());

        let value: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let registration: Value =
            serde_json::from_str(&std::fs::read_to_string(tmp.path().join(".mcp.json")).unwrap())
                .unwrap();
        assert_eq!(
            registration["mcpServers"]["phantom"],
            serde_json::json!({
                "command": "/opt/phantom/bin/phantom",
                "args": ["mcp", "serve"]
            })
        );
        assert_eq!(value["mcpServers"]["other"]["command"], "other-server");
        assert_eq!(value["theme"], "dark");
        assert!(value["mcpServers"].get("phantom").is_none());
        assert!(!value.to_string().contains("npx"));
        let repeated = prepare_claude_settings(&path, &mcp).unwrap();
        assert!(!apply_claude_settings(&repeated).unwrap());
    }

    #[test]
    fn claude_writer_rejects_concurrent_edit() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join(".claude/settings.local.json");
        std::fs::create_dir(tmp.path().join(".claude")).unwrap();
        std::fs::write(&path, r#"{"theme":"before"}"#).unwrap();
        let plan = prepare_claude_settings(&path, &fake_mcp()).unwrap();
        let concurrent = br#"{"theme":"concurrent-owner"}"#;
        std::fs::write(&path, concurrent).unwrap();

        let error = apply_claude_settings(&plan).unwrap_err();
        assert!(error.to_string().contains("changed after setup read it"));
        assert_eq!(std::fs::read(&path).unwrap(), concurrent);
        assert!(!tmp.path().join(".mcp.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn claude_setup_uses_retained_project_after_rename() {
        let container = tempdir().unwrap();
        let project = container.path().join("project");
        let moved = container.path().join("moved");
        std::fs::create_dir(&project).unwrap();

        setup_claude_code_in(&project, &fake_mcp(), || {
            std::fs::rename(&project, &moved).unwrap();
            std::fs::create_dir(&project).unwrap();
            std::fs::write(project.join("owner"), b"decoy").unwrap();
        })
        .unwrap();

        assert!(moved.join(".claude/settings.local.json").exists());
        assert!(moved.join(".mcp.json").exists());
        assert!(!project.join(".claude/settings.local.json").exists());
        assert!(!project.join(".mcp.json").exists());
        assert_eq!(std::fs::read(project.join("owner")).unwrap(), b"decoy");
    }

    #[test]
    fn claude_writer_rolls_back_registration_after_settings_drift() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join(".claude/settings.local.json");
        std::fs::create_dir(tmp.path().join(".claude")).unwrap();
        std::fs::write(&path, r#"{"permissions":{"allow":["Read(./.env)"]}}"#).unwrap();
        let plan = prepare_claude_settings(&path, &fake_mcp()).unwrap();
        let lock = phantom_vault::acquire_project_transaction_lock(tmp.path()).unwrap();
        let concurrent = br#"{"theme":"concurrent-owner"}"#;
        let error = apply_claude_targets_with(
            &plan,
            &lock.target(&path).unwrap(),
            &lock.target(&plan.mcp_path).unwrap(),
            || {
                std::fs::write(&path, concurrent).unwrap();
            },
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("previous configuration changes were restored"));
        assert_eq!(std::fs::read(&path).unwrap(), concurrent);
        assert!(!plan.mcp_path.exists());
    }

    #[test]
    fn claude_writer_preserves_existing_project_servers() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join(".claude/settings.local.json");
        std::fs::create_dir(tmp.path().join(".claude")).unwrap();
        std::fs::write(&path, "{}").unwrap();
        let mcp_path = tmp.path().join(".mcp.json");
        std::fs::write(
            &mcp_path,
            r#"{"mcpServers":{"other":{"command":"other","env":{"MODE":"test"}}},"owner":"team"}"#,
        )
        .unwrap();
        let plan = prepare_claude_settings(&path, &fake_mcp()).unwrap();
        apply_claude_settings(&plan).unwrap();
        let value: Value = serde_json::from_slice(&std::fs::read(&mcp_path).unwrap()).unwrap();
        assert_eq!(value["mcpServers"]["other"]["env"]["MODE"], "test");
        assert_eq!(value["owner"], "team");
        assert!(value["mcpServers"].get("phantom").is_some());
        assert_eq!(std::fs::read(&path).unwrap(), b"{}");
    }

    #[cfg(unix)]
    #[test]
    fn global_json_setup_uses_retained_config_root_after_rename() {
        let home = tempdir().unwrap();
        let cursor = home.path().join(".cursor");
        let moved = home.path().join("cursor-moved");
        std::fs::create_dir(&cursor).unwrap();
        std::fs::write(cursor.join("mcp.json"), br#"{"owner":"original"}"#).unwrap();

        upsert_global_mcp_servers_json(
            home.path(),
            Path::new(".cursor/mcp.json"),
            &fake_mcp(),
            || {
                std::fs::rename(&cursor, &moved).unwrap();
                std::fs::create_dir(&cursor).unwrap();
                std::fs::write(cursor.join("mcp.json"), br#"{"owner":"decoy"}"#).unwrap();
            },
        )
        .unwrap();

        let actual: Value =
            serde_json::from_slice(&std::fs::read(moved.join("mcp.json")).unwrap()).unwrap();
        assert_eq!(actual["owner"], "original");
        assert_eq!(
            actual["mcpServers"]["phantom"]["command"],
            fake_mcp().command
        );
        assert_eq!(
            std::fs::read(cursor.join("mcp.json")).unwrap(),
            br#"{"owner":"decoy"}"#
        );
    }

    #[test]
    fn global_nested_root_is_created_capability_relatively() {
        let home = tempdir().unwrap();
        upsert_global_mcp_servers_json(
            home.path(),
            Path::new(".codeium/windsurf/mcp_config.json"),
            &fake_mcp(),
            || {},
        )
        .unwrap();

        assert!(home
            .path()
            .join(".codeium/windsurf/mcp_config.json")
            .is_file());
        assert!(!home.path().join(".phantom-client-setup.lock").exists());
        assert!(home.path().join(".phantom/client-setup.lock").is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(home.path().join(".codeium/windsurf"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(home.path().join(".codeium/windsurf/mcp_config.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn codex_global_config_preserves_existing_tables() {
        let home = tempdir().unwrap();
        std::fs::create_dir(home.path().join(".codex")).unwrap();
        std::fs::write(
            home.path().join(".codex/config.toml"),
            "[features]\nreview = true\n",
        )
        .unwrap();

        setup_codex_at(
            home.path(),
            Path::new(".codex/config.toml"),
            &fake_mcp(),
            || {},
        )
        .unwrap();

        let doc: toml::Table = toml::from_str(
            &std::fs::read_to_string(home.path().join(".codex/config.toml")).unwrap(),
        )
        .unwrap();
        assert_eq!(doc["features"]["review"].as_bool(), Some(true));
        assert_eq!(
            doc["mcp_servers"]["phantom"]["command"].as_str(),
            Some("/usr/local/bin/phantom-mcp")
        );
    }

    #[test]
    fn global_config_refuses_paths_outside_authorized_root() {
        let container = tempdir().unwrap();
        let home = container.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let outside = container.path().join("outside.json");

        for path in [
            "../outside.json",
            "/tmp/outside.json",
            r"C:\outside.json",
            r"\\server\share\outside.json",
        ] {
            assert!(
                upsert_global_mcp_servers_json(&home, Path::new(path), &fake_mcp(), || {}).is_err()
            );
        }
        assert!(!outside.exists());
    }

    #[test]
    fn unresolved_global_directory_effect_never_claims_exact_rollback() {
        let source = include_str!("setup.rs");
        assert!(source.contains("receipt: None"));
        assert!(source.contains("may have committed without an exact receipt"));
        assert!(source.contains("attempted directory cannot be cleaned up safely"));
    }

    #[cfg(unix)]
    #[test]
    fn global_config_refuses_symlinked_parent_component() {
        use std::os::unix::fs::symlink;

        let container = tempdir().unwrap();
        let home = container.path().join("home");
        let outside = container.path().join("outside");
        std::fs::create_dir(&home).unwrap();
        std::fs::create_dir(&outside).unwrap();
        symlink(&outside, home.join(".cursor")).unwrap();

        assert!(upsert_global_mcp_servers_json(
            &home,
            Path::new(".cursor/mcp.json"),
            &fake_mcp(),
            || {},
        )
        .is_err());
        assert!(!outside.join("mcp.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn cursor_writer_rejects_symlink_target() {
        use std::os::unix::fs::symlink;

        let tmp = tempdir().unwrap();
        let owner = tmp.path().join("owner.json");
        let path = tmp.path().join("mcp.json");
        std::fs::write(&owner, br#"{"owner":true}"#).unwrap();
        symlink(&owner, &path).unwrap();

        let error = upsert_mcp_servers_json(&path, &fake_mcp()).unwrap_err();
        assert!(error.to_string().contains("safely read"));
        assert_eq!(std::fs::read(&owner).unwrap(), br#"{"owner":true}"#);
    }

    #[test]
    fn invalid_existing_json_is_preserved_byte_for_byte() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("mcp.json");
        let original = b"{ invalid json\n";
        std::fs::write(&path, original).unwrap();

        let error = upsert_mcp_servers_json(&path, &fake_mcp())
            .unwrap_err()
            .to_string();

        assert!(error.contains("Failed to parse"));
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn empty_existing_json_is_invalid_and_preserved() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("mcp.json");
        std::fs::write(&path, b"").unwrap();

        assert!(upsert_mcp_servers_json(&path, &fake_mcp()).is_err());
        assert!(std::fs::read(&path).unwrap().is_empty());
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
        assert!(error.contains(&format!("releases/tag/v{}", env!("CARGO_PKG_VERSION"))));
        assert!(error.contains("will not download"));
        assert!(!error.contains("npx"));
    }

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
