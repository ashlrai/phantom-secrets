use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use zeroize::{Zeroize, Zeroizing};

use super::export_cmd::{self, PassphrasePurpose, MAX_ENCRYPTED_BACKUP_BYTES};

/// Import Phantom's encrypted backup format (`phantom-export.enc`).
pub fn run(
    file: &str,
    legacy_passphrase: Option<String>,
    passphrase_file: Option<&str>,
    force: bool,
) -> Result<()> {
    export_cmd::reject_legacy_passphrase(legacy_passphrase)?;
    let passphrase = export_cmd::acquire_passphrase(passphrase_file, PassphrasePurpose::Import)?;
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let file_path = Path::new(file);
    let encrypted = read_encrypted_backup(file_path)?;

    let decrypted = Zeroizing::new(
        phantom_vault::crypto::decrypt(&encrypted, passphrase.as_str())
            .context("Failed to decrypt import file — wrong passphrase or corrupt data")?,
    );

    let secrets = ImportedSecrets(
        serde_json::from_slice(&decrypted)
            .context("Failed to parse import data — file may be corrupt")?,
    );

    if secrets.0.is_empty() {
        println!("{} No secrets found in import file.", "!".yellow().bold());
        return Ok(());
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(&config.phantom.project_id);

    let mut imported = 0usize;
    let mut skipped = 0usize;
    let mut failed = Vec::new();

    for (name, value) in &secrets.0 {
        if !force {
            match vault.exists(name) {
                Ok(true) => {
                    skipped += 1;
                    continue;
                }
                Ok(false) => {}
                Err(error) => {
                    failed.push(format!("{name}: failed to inspect destination: {error}"));
                    continue;
                }
            }
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

    if !failed.is_empty() {
        anyhow::bail!(
            "Encrypted restore was only partially applied: {} imported, {} skipped, {} failed. Fix the reported destination errors and retry with --force only if overwriting successfully restored entries is intended.",
            imported,
            skipped,
            failed.len()
        );
    }

    Ok(())
}

struct ImportedSecrets(BTreeMap<String, String>);

impl Drop for ImportedSecrets {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}

fn read_encrypted_backup(path: &Path) -> Result<Vec<u8>> {
    let before = std::fs::symlink_metadata(path)
        .with_context(|| format!("Failed to inspect encrypted backup: {}", path.display()))?;
    if before.file_type().is_symlink() || !before.is_file() {
        anyhow::bail!(
            "Encrypted backup must be a regular file and must not be a symlink: {}",
            path.display()
        );
    }
    if before.len() > MAX_ENCRYPTED_BACKUP_BYTES {
        anyhow::bail!(
            "Encrypted backup exceeds the {}-byte safety limit",
            MAX_ENCRYPTED_BACKUP_BYTES
        );
    }

    let mut file = File::open(path)
        .with_context(|| format!("Failed to open encrypted backup: {}", path.display()))?;
    ensure_opened_same_backup(path, &before, &file.metadata()?)?;

    let mut encrypted = Vec::with_capacity(before.len() as usize);
    file.by_ref()
        .take(MAX_ENCRYPTED_BACKUP_BYTES + 1)
        .read_to_end(&mut encrypted)
        .with_context(|| format!("Failed to read encrypted backup: {}", path.display()))?;
    if encrypted.len() as u64 > MAX_ENCRYPTED_BACKUP_BYTES {
        anyhow::bail!(
            "Encrypted backup exceeds the {}-byte safety limit",
            MAX_ENCRYPTED_BACKUP_BYTES
        );
    }
    Ok(encrypted)
}

#[cfg(unix)]
fn ensure_opened_same_backup(
    path: &Path,
    before: &std::fs::Metadata,
    opened: &std::fs::Metadata,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    if before.dev() != opened.dev() || before.ino() != opened.ino() || !opened.is_file() {
        anyhow::bail!(
            "Encrypted backup changed while it was being opened: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn ensure_opened_same_backup(
    path: &Path,
    before: &std::fs::Metadata,
    opened: &std::fs::Metadata,
) -> Result<()> {
    use std::os::windows::fs::MetadataExt;

    // Rust 1.95 still keeps Windows volume_serial_number/file_index behind the
    // unstable `windows_by_handle` feature. Compare several stable on-disk
    // fingerprint field instead; a regular-file check alone would miss swaps.
    if !opened.is_file()
        || before.file_attributes() != opened.file_attributes()
        || before.creation_time() != opened.creation_time()
        || before.last_write_time() != opened.last_write_time()
        || before.file_size() != opened.file_size()
    {
        anyhow::bail!(
            "Encrypted backup changed while it was being opened: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn ensure_opened_same_backup(
    path: &Path,
    _before: &std::fs::Metadata,
    opened: &std::fs::Metadata,
) -> Result<()> {
    if !opened.is_file() {
        anyhow::bail!(
            "Encrypted backup changed while it was being opened: {}",
            path.display()
        );
    }
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
