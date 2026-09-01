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
    let vault = phantom_vault::try_create_vault(config.local_project_id())?;

    let mut skipped = 0usize;
    let mut mutations = Vec::new();
    for (name, value) in &secrets.0 {
        let before = snapshot_destination_secret(vault.as_ref(), name)?;
        if before.is_some() && !force {
            skipped += 1;
            continue;
        }
        mutations.push(secret_mutation(name, value, before.as_ref()));
    }
    let imported = mutations.len();
    phantom_vault::commit_init(&project_dir, vault.as_ref(), mutations, Vec::new())
        .context("Encrypted restore transaction failed")?;

    println!(
        "{} Imported {} secret(s) ({} skipped, {} failed)",
        "ok".green().bold(),
        imported,
        skipped,
        0
    );

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
    let vault = phantom_vault::try_create_vault(config.local_project_id())?;

    // Snapshot exact destination before-images before presenting overwrite
    // consent. The transaction rejects any change after this review.
    let mut before_images = BTreeMap::new();
    let mut existing = Vec::new();
    for name in secrets.keys() {
        let before = snapshot_destination_secret(vault.as_ref(), name)?;
        if before.is_some() {
            existing.push(name.clone());
        }
        before_images.insert(name.clone(), before);
    }

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

    let mut mutations = Vec::with_capacity(secrets.len());
    for (name, value) in &secrets {
        let before = before_images
            .get(name)
            .expect("every parsed secret has a destination snapshot");
        mutations.push(secret_mutation(name, value.as_ref(), before.as_ref()));
    }
    let imported = mutations.len();
    phantom_vault::commit_init(&project_dir, vault.as_ref(), mutations, Vec::new())
        .context("Competitor import transaction failed")?;

    println!(
        "{} Imported {} secret(s) from {} ({} skipped, {} failed)",
        "ok".green().bold(),
        imported,
        source,
        0,
        0
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

fn snapshot_destination_secret(
    vault: &dyn phantom_vault::VaultBackend,
    name: &str,
) -> Result<Option<Zeroizing<String>>> {
    match vault.retrieve(name) {
        Ok(value) => Ok(Some(value)),
        Err(phantom_core::error::PhantomError::SecretNotFound(_)) => Ok(None),
        Err(error) => Err(anyhow::anyhow!(
            "Failed to inspect destination secret '{name}' before import: {error}"
        )),
    }
}

fn secret_mutation(
    name: &str,
    value: &str,
    before: Option<&Zeroizing<String>>,
) -> phantom_vault::InitSecret {
    phantom_vault::InitSecret::replace_if_unchanged(
        name,
        before.map(|value| value.as_str().to_string()),
        value,
    )
}

#[cfg(test)]
mod fail_closed_tests {
    use super::*;
    use phantom_core::error::{PhantomError, Result as PhantomResult};
    use zeroize::Zeroizing;

    struct ListFailingVault;

    impl phantom_vault::VaultBackend for ListFailingVault {
        fn store(&self, _name: &str, _value: &str) -> PhantomResult<()> {
            panic!("store must not run after destination inspection fails")
        }

        fn retrieve(&self, _name: &str) -> PhantomResult<Zeroizing<String>> {
            Err(PhantomError::VaultError(
                "injected destination read failure".to_string(),
            ))
        }

        fn delete(&self, _name: &str) -> PhantomResult<()> {
            Ok(())
        }

        fn list(&self) -> PhantomResult<Vec<String>> {
            Ok(Vec::new())
        }

        fn backend_name(&self) -> &str {
            "list-failing"
        }
    }

    #[test]
    fn competitor_import_propagates_destination_inspection_errors() {
        let error = snapshot_destination_secret(&ListFailingVault, "EXISTING")
            .expect_err("backend failure must not be interpreted as an absent secret");
        assert!(error
            .to_string()
            .contains("Failed to inspect destination secret 'EXISTING'"));
        assert!(error
            .to_string()
            .contains("injected destination read failure"));
    }

    #[test]
    fn import_mutation_debug_never_contains_secret_values() {
        let mutation = secret_mutation("NEW_VALUE", "plaintext-never-print", None);
        let debug = format!("{mutation:?}");
        assert!(debug.contains("NEW_VALUE"));
        assert!(!debug.contains("plaintext-never-print"));
    }
}
