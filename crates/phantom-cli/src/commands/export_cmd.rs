use std::collections::BTreeMap;

use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;

pub fn run(output: &str, passphrase: &str) -> Result<()> {
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

    if names.is_empty() {
        println!("{} No secrets to export.", "!".yellow().bold());
        return Ok(());
    }

    // Collect all secrets into a sorted map
    let mut secrets = BTreeMap::new();
    for name in &names {
        let value = vault
            .retrieve(name)
            .context(format!("Failed to retrieve secret: {name}"))?;
        secrets.insert(name.clone(), value);
    }

    // Serialize to JSON
    let json = serde_json::to_string(&secrets).context("Failed to serialize secrets")?;

    // Encrypt with passphrase
    let encrypted = phantom_vault::crypto::encrypt(json.as_bytes(), passphrase)
        .context("Failed to encrypt export data")?;

    // Write to output file
    let output_path = project_dir.join(output);
    std::fs::write(&output_path, &encrypted)
        .context(format!("Failed to write export file: {output}"))?;

    println!(
        "{} Exported {} secret(s) to {}",
        "ok".green().bold(),
        names.len(),
        output.bold()
    );

    Ok(())
}
