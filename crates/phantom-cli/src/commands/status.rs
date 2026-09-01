use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;

use super::proxy_state::{read_proxy_state, ProxyState};

pub fn run(oneline: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");
    let pid_path = project_dir.join(".phantom.pid");

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
    let proxy_state = read_proxy_state(&pid_path);

    if oneline {
        // Compact output for shell prompts
        println!(
            "{} secret{} · {}",
            names.len(),
            if names.len() == 1 { "" } else { "s" },
            proxy_oneline(&proxy_state)
        );
        return Ok(());
    }

    println!("{}", "Phantom Status".bold().underline());
    println!();
    println!("  Project ID:  {}", config.portable_project_id().dimmed());
    println!("  Vault:       {}", vault.backend_name().cyan());
    println!("  Secrets:     {}", names.len().to_string().green().bold());
    println!("  Proxy:       {}", proxy_human(&proxy_state));

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

fn proxy_oneline(state: &ProxyState) -> String {
    match state {
        ProxyState::Running(pid) => format!("proxy on :{}", pid.port),
        ProxyState::Stale(_) => "proxy stale".to_string(),
        ProxyState::Malformed(_) => "proxy malformed".to_string(),
        ProxyState::Unknown(pid) => format!("proxy unknown :{}", pid.port),
        ProxyState::Missing => "proxy off".to_string(),
    }
}

fn proxy_human(state: &ProxyState) -> String {
    match state {
        ProxyState::Running(pid) => {
            format!("running on 127.0.0.1:{} (PID {})", pid.port, pid.pid).green()
        }
        ProxyState::Stale(pid) => {
            format!("stale pid file for PID {} on port {}", pid.pid, pid.port).yellow()
        }
        ProxyState::Malformed(reason) => format!("malformed pid file ({reason})").yellow(),
        ProxyState::Unknown(pid) => {
            format!("unknown state for 127.0.0.1:{} (PID {})", pid.port, pid.pid).yellow()
        }
        ProxyState::Missing => "not running".yellow(),
    }
    .to_string()
}
