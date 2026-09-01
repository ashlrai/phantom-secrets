use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;

pub fn run(oneline: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        if oneline {
            println!("not initialized");
        } else {
            println!(
                "{} Not initialized. Run {} to get started.",
                "!".yellow().bold(),
                "phantom init".cyan().bold()
            );
        }
        return Ok(());
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::try_create_vault(config.local_project_id())?;
    let names = vault.list().context("Failed to list secrets")?;
    let proxy_active = super::start::foreground_proxy_active(&project_dir)?;

    if oneline {
        // Compact output for shell prompts
        println!(
            "{} secret{} · {}",
            names.len(),
            if names.len() == 1 { "" } else { "s" },
            if proxy_active {
                "foreground proxy active"
            } else {
                "foreground proxy inactive"
            }
        );
        return Ok(());
    }

    println!("{}", "Phantom Status".bold().underline());
    println!();
    println!("  Project ID:  {}", config.portable_project_id().dimmed());
    println!("  Vault:       {}", vault.backend_name().cyan());
    println!("  Secrets:     {}", names.len().to_string().green().bold());
    println!(
        "  Proxy:       {}",
        if proxy_active {
            "foreground session active; port and bearer intentionally not persisted".green()
        } else {
            "no foreground session owns the project lock".yellow()
        }
    );

    if !names.is_empty() {
        println!();
        println!("  {}", "Protected secrets:".dimmed());
        for name in &names {
            println!("    {} {}", "-".dimmed(), name);
        }
    }

    let proxy_services = config.proxy_services();
    let conn_services = config.connection_string_services();

    println!();
    println!("  {}", "Service mappings:".dimmed());
    for (name, svc) in &proxy_services {
        println!(
            "    {} {} -> {} ({})",
            "-".dimmed(),
            svc.secret_key,
            svc.pattern.as_deref().unwrap_or("n/a"),
            name.cyan()
        );
    }
    for (_name, svc) in &conn_services {
        println!(
            "    {} {} ({})",
            "-".dimmed(),
            svc.secret_key,
            "env var injection".yellow()
        );
    }

    Ok(())
}
