use std::collections::BTreeMap;

use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;

pub fn run(file: &str, passphrase: &str, force: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    // Read encrypted file
    let file_path = std::path::Path::new(file);
    if !file_path.exists() {
        anyhow::bail!("Import file not found: {}", file);
    }

    let encrypted = std::fs::read(file_path).context(format!("Failed to read file: {file}"))?;

    // Decrypt
    let decrypted = phantom_vault::crypto::decrypt(&encrypted, passphrase)
        .context("Failed to decrypt import file — wrong passphrase or corrupt data")?;

    // Deserialize JSON
    let secrets: BTreeMap<String, String> = serde_json::from_slice(&decrypted)
        .context("Failed to parse import data — file may be corrupt")?;

    if secrets.is_empty() {
        println!("{} No secrets found in import file.", "!".yellow().bold());
        return Ok(());
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(&config.phantom.project_id);

    let mut imported = 0usize;
    let mut skipped = 0usize;

    for (name, value) in &secrets {
        if vault.exists(name).unwrap_or(false) && !force {
            println!(
                "{} Skipping {} (already exists, use {} to overwrite)",
                "warn".yellow().bold(),
                name.bold(),
                "--force".cyan()
            );
            skipped += 1;
            continue;
        }

        vault
            .store(name, value)
            .context(format!("Failed to store secret: {name}"))?;
        imported += 1;
    }

    println!(
        "{} Imported {} secret(s) ({} skipped)",
        "ok".green().bold(),
        imported,
        skipped
    );

    Ok(())
}
