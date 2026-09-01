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
    let vault = vault_probe(project_dir);
    agent::build_report(
        project_dir,
        AgentReadinessOptions {
            vault,
            cloud_logged_in: phantom_core::auth::load_token().is_some(),
            audit_enabled: phantom_core::audit::enabled(),
        },
    )
}

fn vault_probe(project_dir: &std::path::Path) -> Option<VaultProbe> {
    let config_path = project_dir.join(".phantom.toml");
    let config = PhantomConfig::load(&config_path).ok()?;
    let vault = match phantom_vault::try_create_vault(config.local_project_id()) {
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
        Ok(names) => Some(VaultProbe {
            accessible: true,
            backend: Some(backend),
            secret_count: Some(names.len()),
            error: None,
        }),
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

    let config_path = project_dir.join(".phantom.toml");
    let config = PhantomConfig::load(&config_path).ok();
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

fn ensure_gitignore(project_dir: &std::path::Path) -> Result<bool> {
    let path = project_dir.join(".gitignore");
    let lock = phantom_vault::acquire_project_transaction_lock(project_dir)
        .context("Failed to acquire the project transaction lock")?;
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
        .and_then(|bytes| PhantomConfig::load_from_bytes(&config_path, bytes.bytes()).ok());
    let (_env_path, dotenv) = match config.as_ref() {
        Some(config) => super::env::resolve_dotenv_anchored(&lock, project_dir, config)?,
        None => {
            let path = project_dir.join(".env");
            let Some(bytes) = lock.target(&path)?.read_regular()? else {
                return Ok(false);
            };
            let content = std::str::from_utf8(bytes.bytes()).context("Failed to read .env")?;
            (path, Some(DotenvFile::parse_str(content)))
        }
    };
    let Some(dotenv) = dotenv else {
        return Ok(false);
    };
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

    let content = dotenv.generate_example_content(config.as_ref());
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
