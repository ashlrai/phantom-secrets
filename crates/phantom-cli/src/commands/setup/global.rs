//! User-level client writers, retained filesystem capabilities, and backups.
use super::super::setup_backup::{self, ManifestEntry};
use super::super::setup_plan::{self, Action};
use super::{display, home_dir, McpCommand};
use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::fs::{
    AnchoredCreatedDirectory, AnchoredDirectoryCreation, AnchoredEffect, AnchoredFilePermissions,
    AnchoredLock, AnchoredRead, AnchoredTarget, TrustedAnchor,
};
use std::path::Path;

// ─────────────────────────── Cursor ────────────────────────────

pub(super) fn setup_cursor(mcp: &McpCommand, replace: bool) -> Result<()> {
    let home = home_dir()?;
    let path = home.join(".cursor/mcp.json");
    upsert_global_mcp_servers_json(&home, Path::new(".cursor/mcp.json"), mcp, replace, || {})?;
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

pub(super) fn setup_windsurf(mcp: &McpCommand, replace: bool) -> Result<()> {
    let home = home_dir()?;
    let path = home.join(".codeium/windsurf/mcp_config.json");
    upsert_global_mcp_servers_json(
        &home,
        Path::new(".codeium/windsurf/mcp_config.json"),
        mcp,
        replace,
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

// ────────────────────────── Gemini CLI ─────────────────────────

/// Gemini CLI reads user MCP servers from the top-level `mcpServers` object
/// in `~/.gemini/settings.json`, the same `{command, args}` shape as Cursor.
/// Every other setting in that file is preserved.
pub(super) fn setup_gemini(mcp: &McpCommand, replace: bool) -> Result<()> {
    let home = home_dir()?;
    let path = home.join(".gemini/settings.json");
    upsert_global_mcp_servers_json(
        &home,
        Path::new(".gemini/settings.json"),
        mcp,
        replace,
        || {},
    )?;
    println!(
        "\n{} Gemini CLI configured at {}",
        "ok".green().bold(),
        display(&path).dimmed()
    );
    println!(
        "{} {} to activate (`/mcp` lists connected servers).",
        "->".blue().bold(),
        "Restart Gemini CLI".bold()
    );
    Ok(())
}

// ──────────────────────────── Codex ────────────────────────────

pub(super) fn setup_codex(mcp: &McpCommand, replace: bool) -> Result<()> {
    let home = home_dir()?;
    setup_codex_at(&home, Path::new(".codex/config.toml"), mcp, replace, || {})
}

fn setup_codex_at(
    home: &Path,
    relative: &Path,
    mcp: &McpCommand,
    replace: bool,
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

        let judged = setup_plan::judge(
            servers
                .get("phantom")
                .map(setup_plan::entry_from_toml_value),
            mcp,
        );
        servers.insert("phantom".to_string(), mcp.toml_entry());

        let serialized =
            toml::to_string_pretty(&doc).context("Failed to serialize codex config")?;
        let Some(manifest_entry) = gate_and_backup(
            home,
            &path,
            "mcp_servers.phantom",
            &judged,
            replace,
            before.as_ref(),
            serialized.as_bytes(),
        )?
        else {
            return Ok((Written::unchanged(), None));
        };
        let permissions = before
            .as_ref()
            .map(AnchoredRead::permissions)
            .unwrap_or_else(AnchoredFilePermissions::private);
        let effect = capability.target.replace_if_exact_with_permissions(
            before.as_ref(),
            serialized.as_bytes(),
            permissions,
        )?;
        Ok::<_, anyhow::Error>((Written::changed(manifest_entry), Some(effect)))
    })();
    let written = finish_global_operation(capability, operation, &path)?;
    let unchanged = written.entry.is_none();
    finish_manifest(home, written)?;

    if unchanged {
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
    upsert_mcp_servers_json_with(path, mcp, false)
}

#[cfg(test)]
fn upsert_mcp_servers_json_with(path: &Path, mcp: &McpCommand, replace: bool) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Configuration path has no parent: {}", path.display()))?;
    let leaf = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Configuration path has no filename: {}", path.display()))?;
    upsert_global_mcp_servers_json(parent, Path::new(leaf), mcp, replace, || {})
}

fn upsert_global_mcp_servers_json(
    home: &Path,
    relative: &Path,
    mcp: &McpCommand,
    replace: bool,
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

        let judged = setup_plan::judge(
            servers_obj
                .get("phantom")
                .map(setup_plan::entry_from_json_value),
            mcp,
        );
        servers_obj.insert(
            "phantom".to_string(),
            serde_json::json!({
                "command": mcp.command,
                "args": mcp.args_json(),
            }),
        );

        let content =
            serde_json::to_string_pretty(&value).context("Failed to serialize MCP config")?;
        let Some(manifest_entry) = gate_and_backup(
            home,
            &path,
            "mcpServers.phantom",
            &judged,
            replace,
            before.as_ref(),
            content.as_bytes(),
        )?
        else {
            return Ok((Written::unchanged(), None));
        };
        let permissions = before
            .as_ref()
            .map(AnchoredRead::permissions)
            .unwrap_or_else(AnchoredFilePermissions::private);
        let effect = capability.target.replace_if_exact_with_permissions(
            before.as_ref(),
            content.as_bytes(),
            permissions,
        )?;
        Ok::<_, anyhow::Error>((Written::changed(manifest_entry), Some(effect)))
    })();
    let written = finish_global_operation(capability, operation, &path)?;
    let already = written.entry.is_none();
    finish_manifest(home, written)?;

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

/// Outcome of one config write: `entry` is `None` when nothing was written
/// because the existing entry already matched.
struct Written {
    entry: Option<ManifestEntry>,
}

impl Written {
    fn unchanged() -> Self {
        Self { entry: None }
    }
    fn changed(entry: ManifestEntry) -> Self {
        Self { entry: Some(entry) }
    }
}

/// Decide whether a config write may proceed and, if it may, take the backup.
///
/// - `Unchanged`: returns `None`, nothing is written or recorded.
/// - A differing `phantom` entry without `--replace`: refuses and names the
///   entry. Values (including `env`) are never printed.
/// - Otherwise, an existing file is copied byte for byte to a sibling backup
///   first. The returned entry is recorded in the manifest after the write.
fn gate_and_backup(
    home: &Path,
    path: &Path,
    entry_name: &str,
    action: &Action,
    replace: bool,
    before: Option<&AnchoredRead>,
    new_bytes: &[u8],
) -> Result<Option<ManifestEntry>> {
    let action_name = match action {
        Action::Unchanged => return Ok(None),
        Action::Add => "add",
        Action::Conflict { extra_keys, .. } => {
            if !replace {
                let extra = if extra_keys.is_empty() {
                    String::new()
                } else {
                    format!(
                        " (it also has {} extra key(s) that would be dropped)",
                        extra_keys.len()
                    )
                };
                anyhow::bail!(
                    "{entry_name} in {} already exists and differs from what Phantom would write{extra}. \
                     Nothing was changed. Run `phantom setup --client <client> --dry-run` to see the difference, \
                     or re-run with --replace to overwrite it (a backup is written first).",
                    path.display()
                );
            }
            "replace"
        }
        Action::Invalid(why) => anyhow::bail!("{}: {why}", path.display()),
    };
    // Validate the manifest before touching anything.
    setup_backup::load(home)?;
    let backup = match before {
        Some(read) => Some(setup_backup::write_backup(path, read.bytes())?),
        None => None,
    };
    Ok(Some(ManifestEntry {
        path: path.to_path_buf(),
        backup,
        timestamp_ms: setup_backup::now_ms(),
        action: action_name.to_string(),
        sha256_before: before.map(|read| setup_backup::sha256_hex(read.bytes())),
        sha256_after: setup_backup::sha256_hex(new_bytes),
        undone_ms: None,
    }))
}

/// Record the manifest entry after a committed write and say where the backup is.
fn finish_manifest(home: &Path, written: Written) -> Result<()> {
    let Some(entry) = written.entry else {
        return Ok(());
    };
    let backup = entry.backup.clone();
    setup_backup::record(home, entry).with_context(|| match &backup {
        Some(b) => format!(
            "The client config was updated and backed up to {}, but the setup manifest could not be written (--undo will not know about this change)",
            b.display()
        ),
        None => "The client config was created, but the setup manifest could not be written (--undo will not know about this change)".to_string(),
    })?;
    if let Some(b) = backup {
        println!("   {} backup: {}", "+".green().bold(), display(&b).dimmed());
    }
    println!(
        "   {} manifest: {}",
        "+".green().bold(),
        display(&setup_backup::manifest_path(home)).dimmed()
    );
    Ok(())
}

fn finish_global_operation<T>(
    capability: GlobalConfigCapability,
    operation: Result<(T, Option<AnchoredEffect<AnchoredRead>>)>,
    path: &Path,
) -> Result<T> {
    match operation {
        Ok((value, None)) => Ok(value),
        Ok((value, Some(AnchoredEffect::Durable(_)))) => Ok(value),
        Ok((value, Some(AnchoredEffect::CommittedVerifiedButDurabilityUncertain { .. }))) => {
            eprintln!(
                "warning: global client configuration replacement committed and was verified, but directory crash durability is not provable on this platform"
            );
            Ok(value)
        }
        Ok((_, Some(AnchoredEffect::CommittedButUncertain { error, .. }))) => anyhow::bail!(
            "{} was replaced, but durability could not be verified: {error}",
            path.display()
        ),
        Err(error) => {
            capability.cleanup(path)?;
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests;
