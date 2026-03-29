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
    let mut failed = Vec::new();

    for (name, value) in &secrets {
        if vault.exists(name).unwrap_or(false) && !force {
            skipped += 1;
            continue;
        }

        match vault.store(name, value) {
            Ok(()) => imported += 1,
            Err(e) => {
                failed.push(format!("{name}: {e}"));
            }
        }
    }

    if !failed.is_empty() {
        for f in &failed {
            println!("  {} {}", "FAIL".red().bold(), f);
        }
    }

    println!(
        "{} Imported {} secret(s) ({} skipped, {} failed)",
        if failed.is_empty() {
            "ok".green().bold()
        } else {
            "warn".yellow().bold()
        },
        imported,
        skipped,
        failed.len()
    );

    Ok(())
}
