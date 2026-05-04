use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;

/// Legacy import: read phantom's own encrypted backup format (`phantom-export.enc`).
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

/// Competitor-format import: `phantom import --from <source> --file <path>`.
///
/// Supported sources: `doppler`, `infisical`, `dotenvx`, `1password`, `env`.
pub fn run_from(source: &str, file: &str, force: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let file_path = Path::new(file);
    if !file_path.exists() {
        anyhow::bail!("Import file not found: {}", file);
    }

    println!(
        "{} Importing secrets from {} ({})",
        "->".cyan().bold(),
        source.bold(),
        file
    );

    // Parse using the appropriate importer
    let secrets = phantom_core::importers::import_from(source, file_path)
        .with_context(|| format!("Failed to parse {source} export file: {file}"))?;

    if secrets.is_empty() {
        println!(
            "{} No secrets found in {} file.",
            "!".yellow().bold(),
            source
        );
        return Ok(());
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(&config.phantom.project_id);

    // Check for existing secrets and prompt unless --force
    let existing: Vec<String> = secrets
        .keys()
        .filter(|k: &&String| vault.exists(k.as_str()).unwrap_or(false))
        .cloned()
        .collect();

    if !existing.is_empty() && !force {
        println!(
            "{} {} secret(s) already exist in the vault:",
            "warn".yellow().bold(),
            existing.len()
        );
        for k in &existing {
            println!("  - {k}");
        }
        println!(
            "\nOverwrite them? Run with {} to skip this prompt.",
            "--force".cyan()
        );
        // Interactive confirmation
        let answer = prompt_confirm("Overwrite existing secrets? [y/N] ")?;
        if !answer {
            println!("{} Import cancelled.", "!".yellow().bold());
            return Ok(());
        }
    }

    let mut imported = 0usize;
    let mut skipped = 0usize;
    let mut failed: Vec<String> = Vec::new();

    for (name, value) in &secrets {
        if vault.exists(name).unwrap_or(false) && !force {
            // This branch is only reached if the user declined the interactive prompt above
            // or if a new duplicate appears mid-iteration (shouldn't happen, but be safe).
            skipped += 1;
            continue;
        }

        match vault.store(name, value.as_ref()) {
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
        "{} Imported {} secret(s) from {} ({} skipped, {} failed)",
        if failed.is_empty() {
            "ok".green().bold()
        } else {
            "warn".yellow().bold()
        },
        imported,
        source,
        skipped,
        failed.len()
    );

    // Suggest phantom init if a .env with plaintext secrets exists nearby
    let env_path = project_dir.join(".env");
    if env_path.exists() {
        if let Ok(dotenv) = phantom_core::dotenv::DotenvFile::parse_file(&env_path) {
            if !dotenv.real_secret_entries().is_empty() {
                println!(
                    "\n{} Your {} still contains plaintext secrets.",
                    "!".yellow().bold(),
                    ".env".cyan()
                );
                println!(
                    "   Run {} to replace them with phantom tokens.",
                    "phantom init".cyan().bold()
                );
            }
        }
    }

    Ok(())
}

/// Read a yes/no confirmation from stdin (TTY).
fn prompt_confirm(prompt: &str) -> Result<bool> {
    use std::io::{self, Write};
    print!("{prompt}");
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let answer = buf.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}
