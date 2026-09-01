use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

#[cfg(not(windows))]
use std::io::Read;

use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

const MAX_PASSPHRASE_BYTES: u64 = 4 * 1024;
const MIN_PASSPHRASE_BYTES: usize = 12;
pub(crate) const MAX_ENCRYPTED_BACKUP_BYTES: u64 = 64 * 1024 * 1024;
const TEMP_CREATE_ATTEMPTS: usize = 32;
#[cfg(any(windows, test))]
const WINDOWS_PASSPHRASE_FILE_ERROR: &str = "--passphrase-file is disabled on Windows because Phantom cannot yet verify a no-reparse opened handle and its effective private ACL safely. Omit --passphrase-file and enter the passphrase at the hidden terminal prompt.";

#[derive(Clone, Copy)]
pub(crate) enum PassphrasePurpose {
    Export,
    Import,
}

impl PassphrasePurpose {
    fn verb(self) -> &'static str {
        match self {
            Self::Export => "encrypt",
            Self::Import => "decrypt",
        }
    }
}

/// Export an encrypted backup. Passphrases come from a trusted terminal or a
/// private bounded file; the legacy argv option is accepted only to fail closed.
pub fn run(
    output: Option<&str>,
    legacy_passphrase: Option<String>,
    passphrase_file: Option<&str>,
    json: bool,
    allow_plaintext: bool,
) -> Result<()> {
    reject_legacy_passphrase(legacy_passphrase)?;

    if json {
        return run_json(allow_plaintext);
    }

    let output = output.unwrap_or("phantom-export.enc");
    let passphrase = acquire_passphrase(passphrase_file, PassphrasePurpose::Export)?;
    run_encrypted(output, passphrase.as_str())
}

/// The argv form cannot be made confidential: even immediate zeroization cannot
/// erase copies held by the shell or operating system process table.
pub(crate) fn reject_legacy_passphrase(legacy_passphrase: Option<String>) -> Result<()> {
    if let Some(mut passphrase) = legacy_passphrase {
        passphrase.zeroize();
        anyhow::bail!(
            "--passphrase is no longer supported because command-line arguments can be exposed by process inspection. Omit it for a hidden terminal prompt. On non-Windows platforms, bounded automation may use --passphrase-file with a private regular file."
        );
    }
    Ok(())
}

pub(crate) fn acquire_passphrase(
    passphrase_file: Option<&str>,
    purpose: PassphrasePurpose,
) -> Result<Zeroizing<String>> {
    if let Some(path) = passphrase_file {
        return read_passphrase_file(Path::new(path));
    }

    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        #[cfg(windows)]
        anyhow::bail!(
            "A hidden passphrase prompt requires attached stdin and stderr terminals. --passphrase-file is disabled on Windows; rerun from an attached terminal."
        );
        #[cfg(not(windows))]
        anyhow::bail!(
            "A hidden passphrase prompt requires attached stdin and stderr terminals. For bounded automation, use --passphrase-file with a private regular file (mode 0600 on Unix)."
        );
    }

    let prompt = format!("Passphrase to {} backup: ", purpose.verb());
    let passphrase = Zeroizing::new(
        rpassword::prompt_password(prompt).context("Failed to read passphrase from terminal")?,
    );
    validate_passphrase(passphrase.as_str())?;

    if matches!(purpose, PassphrasePurpose::Export) {
        let confirmation = Zeroizing::new(
            rpassword::prompt_password("Confirm backup passphrase: ")
                .context("Failed to confirm passphrase from terminal")?,
        );
        if passphrase.as_str() != confirmation.as_str() {
            anyhow::bail!("Backup passphrases did not match");
        }
    }

    Ok(passphrase)
}

#[cfg(windows)]
fn read_passphrase_file(_path: &Path) -> Result<Zeroizing<String>> {
    // CreateFileW's FILE_FLAG_OPEN_REPARSE_POINT covers only the final path
    // component, while raw DACL enumeration cannot reliably establish
    // effective read access for every conditional, callback, and object ACE.
    // Until Phantom has a handle-relative no-reparse open plus a complete
    // effective-access check, accepting secret-bearing files here would make
    // a platform security promise that the implementation cannot uphold.
    anyhow::bail!(WINDOWS_PASSPHRASE_FILE_ERROR)
}

#[cfg(not(windows))]
fn read_passphrase_file(path: &Path) -> Result<Zeroizing<String>> {
    if path.as_os_str() == "-" {
        anyhow::bail!(
            "--passphrase-file does not accept stdin; use a private regular file so secret input remains separate from command streams"
        );
    }

    let before = std::fs::symlink_metadata(path)
        .with_context(|| format!("Failed to inspect passphrase file: {}", path.display()))?;
    if before.file_type().is_symlink() || !before.is_file() {
        anyhow::bail!(
            "Passphrase file must be a regular file and must not be a symlink: {}",
            path.display()
        );
    }
    if before.len() > MAX_PASSPHRASE_BYTES {
        anyhow::bail!(
            "Passphrase file exceeds the {}-byte limit",
            MAX_PASSPHRASE_BYTES
        );
    }
    ensure_private_permissions(path, &before)?;

    let mut file = File::open(path)
        .with_context(|| format!("Failed to open passphrase file: {}", path.display()))?;
    ensure_opened_same_file(path, &before, &file.metadata()?)?;

    let mut bytes = Zeroizing::new(Vec::with_capacity(before.len() as usize + 1));
    Read::by_ref(&mut file)
        .take(MAX_PASSPHRASE_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("Failed to read passphrase file: {}", path.display()))?;
    if bytes.len() as u64 > MAX_PASSPHRASE_BYTES {
        anyhow::bail!(
            "Passphrase file exceeds the {}-byte limit",
            MAX_PASSPHRASE_BYTES
        );
    }

    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.contains(&b'\n') || bytes.contains(&b'\r') || bytes.contains(&0) {
        anyhow::bail!("Passphrase file must contain exactly one text line without NUL bytes");
    }

    let text = std::str::from_utf8(&bytes).context("Passphrase file is not valid UTF-8")?;
    validate_passphrase(text)?;
    Ok(Zeroizing::new(text.to_owned()))
}

fn validate_passphrase(passphrase: &str) -> Result<()> {
    if passphrase.len() < MIN_PASSPHRASE_BYTES {
        anyhow::bail!(
            "Backup passphrase must be at least {} bytes; use a dedicated high-entropy passphrase",
            MIN_PASSPHRASE_BYTES
        );
    }
    if passphrase.len() as u64 > MAX_PASSPHRASE_BYTES {
        anyhow::bail!(
            "Backup passphrase exceeds the {}-byte limit",
            MAX_PASSPHRASE_BYTES
        );
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_private_permissions(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "Passphrase file permissions are {:03o}; expected 0600 or stricter: {}",
            mode,
            path.display()
        );
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn ensure_private_permissions(_path: &Path, _metadata: &std::fs::Metadata) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn ensure_opened_same_file(
    path: &Path,
    before: &std::fs::Metadata,
    opened: &std::fs::Metadata,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    if before.dev() != opened.dev() || before.ino() != opened.ino() || !opened.is_file() {
        anyhow::bail!(
            "Passphrase file changed while it was being opened: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn ensure_opened_same_file(
    path: &Path,
    _before: &std::fs::Metadata,
    opened: &std::fs::Metadata,
) -> Result<()> {
    if !opened.is_file() {
        anyhow::bail!(
            "Passphrase file changed while it was being opened: {}",
            path.display()
        );
    }
    Ok(())
}

/// Legacy plaintext mode is retained only to return a stable fail-closed error.
fn run_json(_allow_plaintext: bool) -> Result<()> {
    anyhow::bail!(
        "{} Plaintext JSON export is disabled. Use an encrypted backup instead.",
        "!".red().bold(),
    )
}

struct SecretMap(BTreeMap<String, String>);

impl Drop for SecretMap {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}

fn run_encrypted(output: &str, passphrase: &str) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");
    let output_path = project_dir.join(output);

    validate_new_destination(&output_path)?;

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::try_create_vault(config.local_project_id())?;
    let names = vault.list().context("Failed to list secrets")?;

    if names.is_empty() {
        println!("{} No secrets to export.", "!".yellow().bold());
        return Ok(());
    }

    let mut secrets = SecretMap(BTreeMap::new());
    for name in &names {
        let value = vault
            .retrieve(name)
            .with_context(|| format!("Failed to retrieve secret: {name}"))?;
        secrets.0.insert(name.clone(), String::from(value.as_str()));
    }

    let json = Zeroizing::new(
        serde_json::to_vec(&secrets.0).context("Failed to serialize secrets for backup")?,
    );
    let encrypted = phantom_vault::crypto::encrypt(&json, passphrase)
        .context("Failed to encrypt backup data")?;
    if encrypted.len() as u64 > MAX_ENCRYPTED_BACKUP_BYTES {
        anyhow::bail!(
            "Encrypted backup exceeds the supported {}-byte recovery limit",
            MAX_ENCRYPTED_BACKUP_BYTES
        );
    }

    atomic_create_private(&output_path, &encrypted)
        .with_context(|| format!("Failed to create backup file: {}", output_path.display()))?;

    phantom_core::audit::log_result("vault.export_encrypted", None).with_context(|| {
        format!(
            "Backup exists at {}, but its encrypted export audit event could not be written",
            output_path.display()
        )
    })?;

    println!(
        "{} Exported {} secret(s) to {}",
        "ok".green().bold(),
        names.len(),
        output.bold()
    );

    Ok(())
}

fn validate_new_destination(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_meta = std::fs::metadata(parent).with_context(|| {
        format!(
            "Backup parent directory does not exist: {}",
            parent.display()
        )
    })?;
    if !parent_meta.is_dir() {
        anyhow::bail!("Backup parent is not a directory: {}", parent.display());
    }
    if path.file_name().is_none() {
        anyhow::bail!("Backup output must name a file");
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!("Refusing symlink backup target: {}", path.display())
        }
        Ok(_) => anyhow::bail!(
            "Backup target already exists; refusing to overwrite it: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Failed to inspect {}", path.display())),
    }
}

struct TempBackup {
    path: PathBuf,
}

impl Drop for TempBackup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn atomic_create_private(path: &Path, contents: &[u8]) -> Result<()> {
    validate_new_destination(path)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let (mut file, temp) = create_private_temp(parent)?;
    file.write_all(contents)
        .context("Failed to write backup data")?;
    file.sync_all().context("Failed to sync backup data")?;
    drop(file);

    std::fs::hard_link(&temp.path, path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow::anyhow!(
                "Backup target appeared during creation; refusing to overwrite it: {}",
                path.display()
            )
        } else {
            anyhow::Error::new(error).context(format!(
                "Failed to publish backup without overwriting {}",
                path.display()
            ))
        }
    })?;

    std::fs::remove_file(&temp.path).context("Failed to remove backup staging link")?;
    sync_directory(parent).context("Failed to sync backup directory")?;
    Ok(())
}

fn create_private_temp(parent: &Path) -> Result<(File, TempBackup)> {
    for _ in 0..TEMP_CREATE_ATTEMPTS {
        let mut random = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut random);
        let path = parent.join(format!(".phantom-backup-{}.tmp", hex::encode(random)));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((file, TempBackup { path })),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "Failed to create private backup staging file in {}",
                        parent.display()
                    )
                })
            }
        }
    }
    anyhow::bail!("Unable to allocate a unique backup staging file")
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    // The file itself has already been flushed. Stable Rust does not expose a
    // portable directory handle with which to durably flush the new link.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn legacy_argv_passphrase_is_rejected() {
        let err = run(
            Some("out.enc"),
            Some("secret".to_string()),
            None,
            false,
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("no longer supported"));
    }

    #[test]
    fn json_mode_always_refuses() {
        assert!(run(None, None, None, true, false).is_err());
        assert!(run(None, None, None, true, true).is_err());
    }

    #[test]
    fn weak_backup_passphrase_is_rejected() {
        let err = validate_passphrase("short").unwrap_err();
        assert!(err.to_string().contains("at least 12 bytes"));
    }

    #[cfg(not(windows))]
    #[test]
    fn windows_passphrase_file_contract_is_fail_closed_and_actionable() {
        assert!(WINDOWS_PASSPHRASE_FILE_ERROR.contains("disabled on Windows"));
        assert!(WINDOWS_PASSPHRASE_FILE_ERROR.contains("no-reparse opened handle"));
        assert!(WINDOWS_PASSPHRASE_FILE_ERROR.contains("effective private ACL"));
        assert!(WINDOWS_PASSPHRASE_FILE_ERROR.contains("hidden terminal prompt"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_passphrase_file_fails_before_path_traversal() {
        let err =
            read_passphrase_file(Path::new(r"C:\\definitely-missing\\passphrase.txt")).unwrap_err();
        assert_eq!(err.to_string(), WINDOWS_PASSPHRASE_FILE_ERROR);
    }

    #[test]
    fn atomic_writer_refuses_existing_target_and_cleans_staging() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("backup.enc");
        std::fs::write(&target, b"existing").unwrap();

        let err = atomic_create_private(&target, b"ciphertext").unwrap_err();
        assert!(err.to_string().contains("already exists"));
        assert_eq!(std::fs::read(&target).unwrap(), b"existing");
        assert_no_staging_files(dir.path());
    }

    #[cfg(unix)]
    #[test]
    fn atomic_writer_refuses_symlink_target() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let victim = dir.path().join("victim");
        let target = dir.path().join("backup.enc");
        std::fs::write(&victim, b"do-not-touch").unwrap();
        symlink(&victim, &target).unwrap();

        let err = atomic_create_private(&target, b"ciphertext").unwrap_err();
        assert!(err.to_string().contains("symlink"));
        assert_eq!(std::fs::read(&victim).unwrap(), b"do-not-touch");
        assert_no_staging_files(dir.path());
    }

    #[cfg(unix)]
    #[test]
    fn atomic_writer_creates_private_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let target = dir.path().join("backup.enc");
        atomic_create_private(&target, b"ciphertext").unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"ciphertext");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_no_staging_files(dir.path());
    }

    #[test]
    fn staging_guard_cleans_abandoned_file() {
        let dir = tempdir().unwrap();
        let (file, staging) = create_private_temp(dir.path()).unwrap();
        let path = staging.path.clone();
        drop(file);
        assert!(path.exists());
        drop(staging);
        assert!(!path.exists());
    }

    fn assert_no_staging_files(dir: &Path) {
        let names = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(
            names
                .iter()
                .all(|name| !name.starts_with(".phantom-backup-")),
            "staging files remained: {names:?}"
        );
    }
}
