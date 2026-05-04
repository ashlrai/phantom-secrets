use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::env_scope::{split_key, DEFAULT_ENV};

pub fn run(oneline: bool, env: Option<&str>) -> Result<()> {
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
    let vault = phantom_vault::create_vault(&config.phantom.project_id);
    let all_keys = vault.list().context("Failed to list secrets")?;

    let active_env = crate::commands::env_scope::effective_env(&project_dir, env);

    // Filter names for the active environment
    let names: Vec<String> = all_keys
        .iter()
        .filter_map(|k| {
            if let Some((e, name)) = split_key(k) {
                if e == active_env {
                    return Some(name.to_string());
                }
            } else if active_env == DEFAULT_ENV {
                return Some(k.clone());
            }
            None
        })
        .collect();

    if oneline {
        println!(
            "{} secret{} · proxy off · env:{}",
            names.len(),
            if names.len() == 1 { "" } else { "s" },
            active_env
        );
        return Ok(());
    }

    println!("{}", "Phantom Status".bold().underline());
    println!();
    println!("  Project ID:  {}", config.phantom.project_id.dimmed());
    println!("  Vault:       {}", vault.backend_name().cyan());
    println!("  Environment: {}", active_env.cyan().bold());
    println!("  Secrets:     {}", names.len().to_string().green().bold());
    println!("  Proxy:       {}", "not running".yellow());

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
