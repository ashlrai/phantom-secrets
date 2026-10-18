use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::agent::{self, AgentReadinessOptions, AgentReadinessReport, VaultProbe};
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;

pub fn report(json: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let report = readiness_report(&project_dir);

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_human_report(&report);
    }

    if report.exit_code != 0 {
        std::process::exit(report.exit_code);
    }
    Ok(())
}

/// `phantom agent status`: value-free, read-only view of MCP approval state.
///
/// Reads `~/.phantom/mcp-approvals.jsonl` without locking or creating anything.
/// Never prints nonces, argument hashes, parameter summaries, or key material.
pub fn status(json: bool) -> Result<()> {
    use phantom_core::mcp_approval;
    let entries = mcp_approval::read_approval_status().context("reading MCP approval state")?;
    let key_present = mcp_approval::approval_key_present().unwrap_or(false);
    let pending = entries.iter().filter(|e| !e.approved && !e.expired).count();
    let approved_unused = entries.iter().filter(|e| e.approved && !e.expired).count();
    let expired = entries.iter().filter(|e| e.expired).count();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if json {
        let approvals: Vec<_> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "tool_name": e.tool_name,
                    "project_id": e.project_id,
                    "state": approval_state(e),
                    "created_at": e.created_at,
                    "expires_at": e.expires_at,
                    "remaining_secs": e.expires_at.map(|x| x.saturating_sub(now)),
                    "approved_at": e.approved_at,
                })
            })
            .collect();
        let out = serde_json::json!({
            "approvals": {
                "pending": pending,
                "approved_unused": approved_unused,
                "expired": expired,
                "key_present": key_present,
                "records": approvals,
            },
            "leases": {
                "available": false,
                "reason": "the lease broker is not wired into the CLI; no lease state is read",
            },
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    println!("{}", "Phantom Agent Status".bold().underline());
    println!();
    println!(
        "  {} {} pending, {} approved and unused, {} expired",
        "mcp approvals:".dimmed(),
        pending,
        approved_unused,
        expired
    );
    println!(
        "  {} {}",
        "approval key:".dimmed(),
        if key_present {
            "present"
        } else {
            "not created yet"
        }
    );
    for e in &entries {
        let left = e
            .expires_at
            .map(|x| format!("{}s left", x.saturating_sub(now)))
            .unwrap_or_else(|| "no expiry".to_string());
        println!(
            "    {} {} ({}, {})",
            "-".dimmed(),
            e.tool_name,
            approval_state(e),
            left
        );
    }
    println!(
        "  {} not available (the lease broker is not wired into the CLI)",
        "leases:".dimmed()
    );
    println!();
    println!("Approve a pending request yourself with: phantom mcp-approve <NONCE>");
    Ok(())
}

fn approval_state(e: &phantom_core::mcp_approval::ApprovalStatusEntry) -> &'static str {
    if e.expired {
        "expired"
    } else if e.approved {
        "approved_unused"
    } else {
        "pending"
    }
}

pub fn doctor() -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let report = readiness_report(&project_dir);
    print_human_report(&report);

    if report.exit_code != 0 {
        std::process::exit(report.exit_code);
    }
    Ok(())
}

pub fn setup(dry_run: bool, apply: bool) -> Result<()> {
    if !dry_run && !apply {
        anyhow::bail!(
            "Choose either `phantom agent setup --dry-run` or `phantom agent setup --apply`."
        );
    }

    let project_dir = std::env::current_dir()?;
    let before = readiness_report(&project_dir);

    if dry_run {
        println!("{}", "Phantom Agent Setup Dry Run".bold().underline());
        println!();
        if before.commands.is_empty() {
            println!("{} No setup actions needed.", "ok".green().bold());
        } else {
            println!("Would run:");
            for command in &before.commands {
                println!("  {} {}", "-".dimmed(), command.cyan());
            }
        }
        println!();
        println!("{}", serde_json::to_string_pretty(&before)?);
        return Ok(());
    }

    apply_setup(&project_dir, &before)?;

    let after = readiness_report(&project_dir);
    println!();
    println!("{}", "Agent readiness report".bold());
    println!("{}", serde_json::to_string_pretty(&after)?);

    if after.exit_code != 0 {
        std::process::exit(after.exit_code);
    }
    Ok(())
}

fn readiness_report(project_dir: &std::path::Path) -> AgentReadinessReport {
    let base = agent::build_report(
        project_dir,
        AgentReadinessOptions {
            vault: None,
            cloud_logged_in: phantom_core::auth::load_token().is_some(),
            audit_enabled: phantom_core::audit::enabled(),
        },
    );
    if base
        .findings
        .iter()
        .any(|finding| finding.id == "env-parse-error")
    {
        return base;
    }
    agent::build_report(
        project_dir,
        AgentReadinessOptions {
            vault: vault_probe(project_dir),
            cloud_logged_in: phantom_core::auth::load_token().is_some(),
            audit_enabled: phantom_core::audit::enabled(),
        },
    )
}

fn vault_probe(project_dir: &std::path::Path) -> Option<VaultProbe> {
    let config_path = project_dir.join(".phantom.toml");
    let config = PhantomConfig::load(&config_path).ok()?;
    let vault = match crate::util::open_vault(config.local_project_id()) {
        Ok(vault) => vault,
        Err(error) => {
            return Some(VaultProbe {
                accessible: false,
                backend: None,
                secret_count: None,
                error: Some(error.to_string()),
            });
        }
    };
    let backend = vault.backend_name().to_string();
    match vault.list() {
        // The project's encrypted-file vault cannot be opened here, so the
        // secrets agents run with are not reachable: not accessible, whether
        // the keychain this process selected is empty or not.
        Ok(names) => match crate::util::inventory_guard(
            vault.as_ref(),
            config.local_project_id(),
            names.len(),
        ) {
            Ok(None) => Some(VaultProbe {
                accessible: true,
                backend: Some(backend),
                secret_count: Some(names.len()),
                error: None,
            }),
            Ok(Some(note)) => Some(VaultProbe {
                accessible: false,
                backend: Some(backend),
                secret_count: Some(names.len()),
                error: Some(note),
            }),
            Err(locked) => Some(VaultProbe {
                accessible: false,
                backend: Some(backend),
                secret_count: None,
                error: Some(locked.to_string()),
            }),
        },
        Err(err) => Some(VaultProbe {
            accessible: false,
            backend: Some(backend),
            secret_count: None,
            error: Some(err.to_string()),
        }),
    }
}

fn apply_setup(project_dir: &std::path::Path, before: &AgentReadinessReport) -> Result<()> {
    println!("{}", "Applying Phantom agent setup".bold().underline());
    println!();

    if before
        .findings
        .iter()
        .any(|finding| finding.id == "env-parse-error")
    {
        anyhow::bail!(
            "Managed dotenv is malformed; agent setup made no gitignore, example, config, vault, or client changes"
        );
    }

    if before
        .findings
        .iter()
        .any(|finding| finding.id == "invalid-config")
    {
        anyhow::bail!(
            ".phantom.toml exists but could not be loaded; agent setup made no gitignore, example, config, vault, or client changes. Fix or restore it, then run `phantom doctor`"
        );
    }

    let config_path = project_dir.join(".phantom.toml");
    let config = crate::util::load_config_if_present(&config_path)
        .context("Failed to load .phantom.toml; agent setup made no changes")?;
    let env_path = match config.as_ref() {
        Some(config) => {
            phantom_core::managed_dotenv::resolve_dotenv(project_dir, config, &[])?.path
        }
        None => project_dir.join(".env"),
    };

    if env_path.exists()
        && (!config_path.exists()
            || before
                .findings
                .iter()
                .any(|f| f.id == "unprotected-env-secrets"))
    {
        println!(
            "{} Protecting env secrets with phantom tokens",
            "->".blue().bold()
        );
        crate::commands::init::run(env_path.to_string_lossy().as_ref())?;
        println!(
            "{} Re-run `phantom agent setup --apply` to apply the next reviewed setup action",
            "next".blue().bold()
        );
        return Ok(());
    } else {
        println!(
            "{} Env protection already initialized or no .env found",
            "-".dimmed()
        );
    }

    if ensure_gitignore(project_dir)? || ensure_env_example(project_dir)? {
        println!(
            "{} Re-run `phantom agent setup --apply` to apply the next reviewed setup action",
            "next".blue().bold()
        );
        return Ok(());
    }

    println!("{} Wiring Claude Code MCP defaults", "->".blue().bold());
    crate::commands::setup::run(
        Some(crate::commands::setup::Client::ClaudeCode),
        false,
        None,
    )?;

    if project_dir.join("package.json").exists() {
        println!(
            "{} package.json detected; review `phantom wrap` before changing scripts",
            "note".yellow().bold()
        );
    }

    Ok(())
}

fn agent_dotenv_guard(
    lock: &phantom_vault::ProjectTransactionLock,
    project_dir: &std::path::Path,
    config: Option<&PhantomConfig>,
) -> Result<(
    phantom_core::fs::AnchoredTarget,
    Option<phantom_core::fs::AnchoredRead>,
)> {
    let env_path = match config {
        Some(config) => super::env::resolve_dotenv_anchored(lock, project_dir, config)?.0,
        None => project_dir.join(".env"),
    };
    let target = lock.target(&env_path)?;
    let before = target
        .read_regular()
        .with_context(|| format!("Failed to retain managed dotenv {}", env_path.display()))?;
    if let Some(bytes) = before.as_ref() {
        let text = std::str::from_utf8(bytes.bytes())
            .context("Managed dotenv is not valid UTF-8; agent setup made no changes")?;
        DotenvFile::parse_str(text)
            .validate_for_mutation()
            .context("Managed dotenv is malformed; agent setup made no changes")?;
    }
    Ok((target, before))
}

fn ensure_agent_dotenv_unchanged(
    target: &phantom_core::fs::AnchoredTarget,
    expected: Option<&phantom_core::fs::AnchoredRead>,
) -> Result<()> {
    let current = target
        .read_regular()
        .context("Failed to re-read managed dotenv before agent setup mutation")?;
    let matches = match (expected, current.as_ref()) {
        (Some(expected), Some(current)) => {
            expected.identity() == current.identity()
                && expected.bytes() == current.bytes()
                && expected.permissions() == current.permissions()
        }
        (None, None) => true,
        _ => false,
    };
    if !matches {
        anyhow::bail!(
            "Managed dotenv changed after agent setup preflight; no further change was attempted"
        );
    }
    Ok(())
}

fn ensure_gitignore(project_dir: &std::path::Path) -> Result<bool> {
    let path = project_dir.join(".gitignore");
    let lock = phantom_vault::acquire_project_transaction_lock(project_dir)
        .context("Failed to acquire the project transaction lock")?;
    let config_path = project_dir.join(".phantom.toml");
    let config = lock
        .target(&config_path)?
        .read_regular()?
        .map(|bytes| PhantomConfig::load_from_bytes(&config_path, bytes.bytes()))
        .transpose()
        .context("Failed to load .phantom.toml; agent setup made no changes")?;
    let (dotenv_target, dotenv_before) = agent_dotenv_guard(&lock, project_dir, config.as_ref())?;
    let target = lock.target(&path)?;
    let before = target
        .read_regular()
        .with_context(|| format!("Refusing unsafe .gitignore target {}", path.display()))?;
    let mut content = match before.as_ref().map(phantom_core::fs::AnchoredRead::bytes) {
        Some(bytes) => {
            String::from_utf8(bytes.to_vec()).context("Refusing to rewrite non-UTF-8 .gitignore")?
        }
        None => String::new(),
    };
    if content.lines().any(|line| line.trim() == ".env") {
        return Ok(false);
    }
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(".env\n.env.local\n.env.*.local\n.env.backup\n");
    ensure_agent_dotenv_unchanged(&dotenv_target, dotenv_before.as_ref())?;
    replace_agent_target(&target, before.as_ref(), content.as_bytes(), &path)?;
    println!(
        "{} Updated .gitignore with env patterns",
        "ok".green().bold()
    );
    Ok(true)
}

fn ensure_env_example(project_dir: &std::path::Path) -> Result<bool> {
    let lock = phantom_vault::acquire_project_transaction_lock(project_dir)
        .context("Failed to acquire the project transaction lock")?;
    let config_path = project_dir.join(".phantom.toml");
    let config = lock
        .target(&config_path)?
        .read_regular()?
        .map(|bytes| PhantomConfig::load_from_bytes(&config_path, bytes.bytes()))
        .transpose()
        .context("Failed to load .phantom.toml; agent setup made no changes")?;
    let (dotenv_target, dotenv_before) = agent_dotenv_guard(&lock, project_dir, config.as_ref())?;
    let Some(dotenv_before) = dotenv_before else {
        return Ok(false);
    };
    let dotenv = DotenvFile::parse_str(
        std::str::from_utf8(dotenv_before.bytes()).context("Failed to read managed dotenv")?,
    );
    let example_path = project_dir.join(".env.example");
    let example_target = lock.target(&example_path)?;
    let example_before = example_target.read_regular().with_context(|| {
        format!(
            "Refusing unsafe .env.example target {}",
            example_path.display()
        )
    })?;
    if example_before.is_some() {
        return Ok(false);
    }

    let content = dotenv
        .generate_example_content(config.as_ref())
        .context("Managed dotenv is malformed; no agent example was written")?;
    ensure_agent_dotenv_unchanged(&dotenv_target, Some(&dotenv_before))?;
    replace_agent_target(&example_target, None, content.as_bytes(), &example_path)?;
    println!("{} Generated .env.example", "ok".green().bold());
    Ok(true)
}

#[cfg(test)]
fn write_agent_file_exact(
    project_dir: &std::path::Path,
    path: &std::path::Path,
    before: Option<&[u8]>,
    content: &[u8],
) -> Result<()> {
    write_agent_file_exact_with(project_dir, path, before, content, || {})
}

#[cfg(test)]
fn write_agent_file_exact_with(
    project_dir: &std::path::Path,
    path: &std::path::Path,
    before: Option<&[u8]>,
    content: &[u8],
    before_commit: impl FnOnce(),
) -> Result<()> {
    let lock = phantom_vault::acquire_project_transaction_lock(project_dir)
        .context("Failed to acquire the project transaction lock")?;
    let target = lock.target(path)?;
    let reviewed = target.read_regular().with_context(|| {
        format!(
            "Failed to inspect {} through the retained project root",
            path.display()
        )
    })?;
    if reviewed.as_ref().map(phantom_core::fs::AnchoredRead::bytes) != before {
        anyhow::bail!(
            "{} changed during agent setup; refusing to overwrite it",
            path.display()
        );
    }
    before_commit();
    replace_agent_target(&target, reviewed.as_ref(), content, path)
}

fn replace_agent_target(
    target: &phantom_core::fs::AnchoredTarget,
    reviewed: Option<&phantom_core::fs::AnchoredRead>,
    content: &[u8],
    path: &std::path::Path,
) -> Result<()> {
    let permissions = reviewed
        .map(phantom_core::fs::AnchoredRead::permissions)
        .unwrap_or_else(phantom_core::fs::AnchoredFilePermissions::private);
    match target.replace_if_exact_with_permissions(reviewed, content, permissions)? {
        phantom_core::fs::AnchoredEffect::Durable(_) => Ok(()),
        phantom_core::fs::AnchoredEffect::CommittedVerifiedButDurabilityUncertain { .. } => {
            eprintln!(
                "warning: {} was replaced and verified, but directory crash durability is not provable on this platform",
                path.display()
            );
            Ok(())
        }
        phantom_core::fs::AnchoredEffect::CommittedButUncertain { error, .. } => {
            anyhow::bail!(
                "{} was replaced, but durability could not be verified: {error}",
                path.display()
            )
        }
    }
}

fn print_human_report(report: &AgentReadinessReport) {
    println!("{}", "Phantom Agent Readiness".bold().underline());
    println!();
    println!(
        "  {} {:?}  {} {:?}",
        "status:".dimmed(),
        report.status,
        "risk:".dimmed(),
        report.risk_level
    );
    println!();

    if report.findings.is_empty() {
        println!("{} No findings.", "ok".green().bold());
    } else {
        for finding in &report.findings {
            let label = match finding.severity {
                phantom_core::agent::FindingSeverity::Critical => "fail".red().bold(),
                phantom_core::agent::FindingSeverity::Warning => "warn".yellow().bold(),
                phantom_core::agent::FindingSeverity::Info => "info".blue().bold(),
            };
            println!("  {} {}", label, finding.message);
            if let Some(command) = &finding.command {
                println!("       {} {}", "Run:".dimmed(), command.cyan());
            }
        }
    }

    if !report.files.is_empty() {
        println!();
        println!("{} {}", "files:".dimmed(), report.files.join(", "));
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn malformed_dotenv_blocks_all_agent_setup_mutations() {
        let project = tempfile::tempdir().unwrap();
        let source = b"API_KEY=plaintext-must-not-escape\nBROKEN_RECORD\n";
        std::fs::write(project.path().join(".env"), source).unwrap();
        let report = super::readiness_report(project.path());

        let error = super::apply_setup(project.path(), &report).unwrap_err();

        assert!(error.to_string().contains("malformed"));
        assert_eq!(std::fs::read(project.path().join(".env")).unwrap(), source);
        for path in [".gitignore", ".env.example", ".phantom.toml", ".claude"] {
            assert!(
                !project.path().join(path).exists(),
                "unexpected mutation: {path}"
            );
        }
    }

    /// A `.phantom.toml` that exists but does not parse read as "not
    /// initialized": `agent setup --apply` judged `./.env` and wrote
    /// `.gitignore`. It now refuses before any change, and the helpers that
    /// read the config under the project lock refuse too.
    #[test]
    fn malformed_config_blocks_all_agent_setup_mutations() {
        let project = tempfile::tempdir().unwrap();
        let config = b"[phantom\nversion = ";
        std::fs::write(project.path().join(".phantom.toml"), config).unwrap();
        std::fs::write(project.path().join(".env"), b"APP_NAME=demo\n").unwrap();
        let report = super::readiness_report(project.path());
        assert!(report.findings.iter().any(|f| f.id == "invalid-config"));

        let error = super::apply_setup(project.path(), &report).unwrap_err();

        assert!(
            error.to_string().contains("could not be loaded"),
            "unexpected refusal"
        );
        assert!(super::ensure_gitignore(project.path()).is_err());
        assert!(super::ensure_env_example(project.path()).is_err());
        assert_eq!(
            std::fs::read(project.path().join(".phantom.toml")).unwrap(),
            config
        );
        for path in [".gitignore", ".env.example", ".claude", ".mcp.json"] {
            assert!(
                !project.path().join(path).exists(),
                "unexpected mutation: {path}"
            );
        }
    }

    #[test]
    fn agent_writer_preserves_concurrent_owner() {
        let project = tempfile::tempdir().unwrap();
        let target = project.path().join(".gitignore");
        std::fs::write(&target, b"before\n").unwrap();
        let before = phantom_core::fs::read_regular_file(&target)
            .unwrap()
            .unwrap();
        std::fs::write(&target, b"concurrent\n").unwrap();

        assert!(super::write_agent_file_exact(
            project.path(),
            &target,
            Some(&before),
            b"phantom\n"
        )
        .is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"concurrent\n");
    }

    #[cfg(unix)]
    #[test]
    fn agent_writer_refuses_symlink_target() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        let owner = project.path().join("owner");
        let target = project.path().join(".gitignore");
        std::fs::write(&owner, b"owner").unwrap();
        symlink(&owner, &target).unwrap();

        assert!(super::write_agent_file_exact(project.path(), &target, None, b"phantom").is_err());
        assert_eq!(std::fs::read(owner).unwrap(), b"owner");
    }

    #[cfg(unix)]
    #[test]
    fn agent_writer_uses_retained_root_after_rename() {
        let container = tempfile::tempdir().unwrap();
        let project = container.path().join("project");
        let moved = container.path().join("moved");
        std::fs::create_dir(&project).unwrap();
        let target = project.join(".gitignore");
        std::fs::write(&target, b"before\n").unwrap();

        super::write_agent_file_exact_with(
            &project,
            &target,
            Some(b"before\n"),
            b"after\n",
            || {
                std::fs::rename(&project, &moved).unwrap();
                std::fs::create_dir(&project).unwrap();
                std::fs::write(project.join(".gitignore"), b"decoy\n").unwrap();
            },
        )
        .unwrap();

        assert_eq!(std::fs::read(moved.join(".gitignore")).unwrap(), b"after\n");
        assert_eq!(
            std::fs::read(project.join(".gitignore")).unwrap(),
            b"decoy\n"
        );
    }
}

#[cfg(all(test, unix))]
mod locked_vault_tests {
    use crate::util::test_seam::{empty_keychain, keychain_with_one, LockedProject};

    /// `phantom agent report` called a locked file vault accessible (status
    /// Protected) because the keychain it fell back to listed without error.
    #[test]
    fn vault_probe_reports_a_locked_file_vault_as_not_accessible() {
        for make in [empty_keychain, keychain_with_one] {
            let project = LockedProject::new(make);
            let probe = super::vault_probe(&project.dir).unwrap();
            assert!(!probe.accessible);
            let error = probe.error.unwrap();
            assert!(error.contains("PHANTOM_VAULT_PASSPHRASE"), "{error}");
        }
    }
}
