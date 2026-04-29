use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use serde::Serialize;

#[derive(Serialize)]
struct SecretEntry<'a> {
    name: &'a str,
    detected_service: Option<&'a str>,
}

pub fn run(json: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(&config.phantom.project_id);

    let names = vault.list().context("Failed to list secrets")?;

    if json {
        let entries: Vec<SecretEntry> = names
            .iter()
            .map(|name| SecretEntry {
                name,
                detected_service: config
                    .services
                    .iter()
                    .find(|(_, c)| c.secret_key == *name)
                    .map(|(svc, _)| svc.as_str()),
            })
            .collect();
        let out = serde_json::to_string_pretty(&entries)
            .context("Failed to serialize secret list to JSON")?;
        println!("{}", out);
        return Ok(());
    }

    if names.is_empty() {
        println!("{} No secrets stored.", "!".yellow().bold());
        return Ok(());
    }

    println!(
        "{} {} secret(s) in vault ({}):\n",
        "->".blue().bold(),
        names.len(),
        vault.backend_name().dimmed()
    );

    for name in &names {
        // Check if this name has a service mapping
        let service = config
            .services
            .iter()
            .find(|(_, c)| c.secret_key == *name)
            .map(|(name, _)| name.as_str());

        if let Some(svc) = service {
            println!("   {} {} ({})", "-".dimmed(), name.bold(), svc.cyan());
        } else {
            println!("   {} {}", "-".dimmed(), name.bold());
        }
    }

    println!(
        "\n{} Values are never displayed. Use {} to manage.",
        "note".dimmed(),
        "phantom add/remove".cyan()
    );

    Ok(())
}
