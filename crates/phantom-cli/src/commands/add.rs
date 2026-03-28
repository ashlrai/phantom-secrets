use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;

pub fn run(name: &str, value: &str) -> Result<()> {
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

    // Warn if secret already exists
    if vault.exists(name).unwrap_or(false) {
        eprintln!(
            "{} Secret {} already exists — overwriting with new value",
            "warn".yellow(),
            name.bold()
        );
    }

    vault
        .store(name, value)
        .context(format!("Failed to store secret: {name}"))?;

    println!(
        "{} Stored {} in vault ({})",
        "ok".green().bold(),
        name.bold(),
        vault.backend_name().dimmed()
    );

    // Also update .env if it exists
    let env_path = project_dir.join(".env");
    if env_path.exists() {
        let content = std::fs::read_to_string(&env_path)?;
        let token = phantom_core::token::PhantomToken::generate();

        if content
            .lines()
            .any(|l| l.trim().starts_with(&format!("{name}=")))
        {
            // Key exists, update its value to the phantom token
            let new_content: String = content
                .lines()
                .map(|line| {
                    if line.trim().starts_with(&format!("{name}=")) {
                        format!("{name}={token}")
                    } else {
                        line.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            std::fs::write(&env_path, new_content)?;
        } else {
            // Append new entry
            let mut content = content;
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            content.push_str(&format!("{name}={token}\n"));
            std::fs::write(&env_path, content)?;
        }

        println!(
            "{} Updated .env with phantom token for {}",
            "ok".green().bold(),
            name.bold()
        );
    }

    Ok(())
}
