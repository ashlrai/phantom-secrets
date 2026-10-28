//! Project-local Claude registration and exact two-file transaction.
use super::McpCommand;
use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::fs::{
    AnchoredCreatedDirectory, AnchoredEffect, AnchoredFilePermissions, AnchoredRead, AnchoredTarget,
};
use phantom_vault::{ProjectDirectoryPreparation, ProjectTransactionLock};
use std::path::{Path, PathBuf};

/// Remove only the two dotenv read grants emitted by older Phantom releases.
/// Other allow rules and every deny rule are user-owned and must survive setup.
/// Returns whether the permission map changed.
fn remove_legacy_dotenv_read_grants(
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

pub(super) fn setup_claude_code(mcp: &McpCommand) -> Result<()> {
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

#[cfg(test)]
mod tests;
