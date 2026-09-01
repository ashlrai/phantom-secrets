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

    let secrets = ImportedSecrets::parse(&decrypted)
        .context("Failed to parse import data — file may be corrupt")?;

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
        mutations.push(secret_mutation(name, value.as_str(), before.as_ref()));
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

#[derive(serde::Deserialize)]
struct ParsedImportedSecret(String);

impl ParsedImportedSecret {
    fn into_zeroizing(mut self) -> Zeroizing<String> {
        Zeroizing::new(std::mem::take(&mut self.0))
    }
}

impl Drop for ParsedImportedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct ImportedSecrets(BTreeMap<String, Zeroizing<String>>);

impl ImportedSecrets {
    fn parse(bytes: &[u8]) -> serde_json::Result<Self> {
        let parsed: BTreeMap<String, ParsedImportedSecret> = serde_json::from_slice(bytes)?;
        Ok(Self(
            parsed
                .into_iter()
                .map(|(name, value)| (name, value.into_zeroizing()))
                .collect(),
        ))
    }
}

impl Drop for ImportedSecrets {
    fn drop(&mut self) {
        self.0.clear();
    }
}

fn read_encrypted_backup(path: &Path) -> Result<Vec<u8>> {
    // Open the authoritative handle first with no-follow semantics. Metadata
    // obtained before open cannot identify which bytes are ultimately read.
    let mut file = match open_encrypted_backup(path) {
        Ok(file) => file,
        #[cfg(unix)]
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            anyhow::bail!("Encrypted backup must not be a symlink: {}", path.display())
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Failed to open encrypted backup: {}", path.display()))
        }
    };
    ensure_opened_backup_is_safe(path, &file)?;
    let opened_metadata = file.metadata()?;
    if opened_metadata.len() > MAX_ENCRYPTED_BACKUP_BYTES {
        anyhow::bail!(
            "Encrypted backup exceeds the {}-byte safety limit",
            MAX_ENCRYPTED_BACKUP_BYTES
        );
    }

    let mut encrypted = Vec::with_capacity(opened_metadata.len() as usize);
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
    ensure_backup_path_still_names_open_file(path, &file)?;
    Ok(encrypted)
}

#[cfg(unix)]
fn open_encrypted_backup(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    options.open(path)
}

#[cfg(all(not(unix), not(windows)))]
fn open_encrypted_backup(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

#[cfg(windows)]
fn open_encrypted_backup(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path)
}

#[cfg(unix)]
fn ensure_opened_backup_is_safe(path: &Path, opened: &File) -> Result<()> {
    let opened = opened.metadata()?;
    if !opened.is_file() {
        anyhow::bail!(
            "Encrypted backup must be a regular non-symlink file: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn ensure_opened_backup_is_safe(path: &Path, opened: &File) -> Result<()> {
    let info = windows_file_information(opened)?;
    if info.dwFileAttributes & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
        || !opened.metadata()?.is_file()
    {
        anyhow::bail!(
            "Encrypted backup is a reparse point or is not a regular file: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn ensure_opened_backup_is_safe(path: &Path, opened: &File) -> Result<()> {
    if !opened.metadata()?.is_file() {
        anyhow::bail!(
            "Encrypted backup changed while it was being opened: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_backup_path_still_names_open_file(path: &Path, opened: &File) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let original = opened.metadata()?;
    let current = open_encrypted_backup(path)
        .with_context(|| format!("Failed to re-open encrypted backup: {}", path.display()))?;
    let current = current.metadata()?;
    if original.dev() != current.dev() || original.ino() != current.ino() {
        anyhow::bail!(
            "Encrypted backup path changed while it was being read: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn ensure_backup_path_still_names_open_file(_path: &Path, _opened: &File) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
fn ensure_backup_path_still_names_open_file(path: &Path, opened: &File) -> Result<()> {
    let original = windows_file_information(opened)?;
    let current = open_encrypted_backup(path).with_context(|| {
        format!(
            "Failed to re-open encrypted backup for identity verification: {}",
            path.display()
        )
    })?;
    let current = windows_file_information(&current)?;
    if current.dwFileAttributes
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
        || original.dwVolumeSerialNumber != current.dwVolumeSerialNumber
        || original.nFileIndexHigh != current.nFileIndexHigh
        || original.nFileIndexLow != current.nFileIndexLow
    {
        anyhow::bail!(
            "Encrypted backup path changed while it was being read: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn windows_file_information(
    file: &File,
) -> Result<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION> {
    use std::os::windows::io::AsRawHandle;

    let mut information = unsafe { std::mem::zeroed() };
    let result = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(
            file.as_raw_handle(),
            &mut information,
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error())
            .context("GetFileInformationByHandle failed for encrypted backup");
    }
    Ok(information)
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
    let vault_names = vault.list().context("Failed to list local vault secrets")?;
    let env_path =
        phantom_core::managed_dotenv::resolve_dotenv(&project_dir, &config, &vault_names)
            .context("Failed to resolve the managed dotenv for import")?
            .path;

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

    // Suggest phantom init if the managed dotenv contains plaintext secrets.
    if env_path.exists() {
        if let Ok(dotenv) = phantom_core::dotenv::DotenvFile::parse_file(&env_path) {
            if !dotenv.real_secret_entries().is_empty() {
                println!(
                    "\n{} Your {} still contains plaintext secrets.",
                    "!".yellow().bold(),
                    env_path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("managed dotenv")
                        .cyan()
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

    #[test]
    fn windows_backup_open_contract_is_handle_bound_and_reparse_safe() {
        let source = include_str!("import_cmd.rs");
        assert!(source.contains("FILE_FLAG_OPEN_REPARSE_POINT"));
        assert!(source.contains("GetFileInformationByHandle"));
        assert!(source.contains("dwVolumeSerialNumber"));
        assert!(source.contains("nFileIndexHigh"));
        assert!(source.contains("nFileIndexLow"));
        assert!(source.contains("FILE_ATTRIBUTE_REPARSE_POINT"));
    }
}
