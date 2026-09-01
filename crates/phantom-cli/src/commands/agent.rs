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

    let env_path = project_dir.join(".env");
    let config_path = project_dir.join(".phantom.toml");

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
        crate::commands::init::run(".env")?;
    } else {
        println!(
            "{} Env protection already initialized or no .env found",
            "-".dimmed()
        );
    }

    ensure_gitignore(project_dir)?;
    ensure_env_example(project_dir)?;

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

fn ensure_gitignore(project_dir: &std::path::Path) -> Result<()> {
    let path = project_dir.join(".gitignore");
    let mut content = std::fs::read_to_string(&path).unwrap_or_default();
    if content.lines().any(|line| line.trim() == ".env") {
        return Ok(());
    }
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(".env\n.env.local\n.env.*.local\n.env.backup\n");
    std::fs::write(&path, content)?;
    println!(
        "{} Updated .gitignore with env patterns",
        "ok".green().bold()
    );
    Ok(())
}

fn ensure_env_example(project_dir: &std::path::Path) -> Result<()> {
    let env_path = project_dir.join(".env");
    let example_path = project_dir.join(".env.example");
    if example_path.exists() || !env_path.exists() {
        return Ok(());
    }

    let dotenv = DotenvFile::parse_file(&env_path).context("Failed to read .env")?;
    let config = PhantomConfig::load(&project_dir.join(".phantom.toml")).ok();
    let content = dotenv.generate_example_content(config.as_ref());
    std::fs::write(&example_path, content)?;
    println!("{} Generated .env.example", "ok".green().bold());
    Ok(())
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
