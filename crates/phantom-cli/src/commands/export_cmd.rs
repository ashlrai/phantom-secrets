use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Component, Path, PathBuf};

#[cfg(not(windows))]
use std::io::Read;

use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const MAX_PASSPHRASE_BYTES: u64 = 4 * 1024;
const MIN_PASSPHRASE_BYTES: usize = 12;
pub(crate) const MAX_ENCRYPTED_BACKUP_BYTES: u64 = 64 * 1024 * 1024;
const TEMP_CREATE_ATTEMPTS: usize = 32;
const MAX_CONSENT_NAMES: usize = 10_000;
const MAX_CONSENT_NAME_BYTES: usize = 512;
const MAX_CONSENT_SET_BYTES: usize = 32 * 1024;
const MAX_CONSENT_TEXT_BYTES: usize = 256 * 1024;
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

/// Export an encrypted backup after an informed trusted-terminal ceremony.
/// Export passphrases are accepted only through the hidden terminal prompt.
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

    if passphrase_file.is_some() {
        anyhow::bail!(
            "--passphrase-file is disabled for export because it can make the resulting backup agent-decryptable. Omit it and enter a dedicated passphrase at the hidden trusted-terminal prompt."
        );
    }

    let output = output.unwrap_or("phantom-export.enc");
    require_attached_terminals("Encrypted backup export")?;
    let plan = prepare_export(output)?;
    require_trusted_terminal_effect(&plan.effect, &plan.challenge)?;
    verify_export_plan(&plan)?;
    let passphrase = acquire_passphrase(None, PassphrasePurpose::Export)?;
    verify_export_plan(&plan)?;
    run_encrypted(&plan, passphrase.as_str())
}

/// The argv form cannot be made confidential: even immediate zeroization cannot
/// erase copies held by the shell or operating system process table.
pub(crate) fn reject_legacy_passphrase(legacy_passphrase: Option<String>) -> Result<()> {
    if let Some(mut passphrase) = legacy_passphrase {
        passphrase.zeroize();
        anyhow::bail!(
            "--passphrase is no longer supported because command-line arguments can be exposed by process inspection. Omit it for a hidden terminal prompt. Encrypted export also rejects --passphrase-file; import may use a private bounded file on supported platforms only after trusted-terminal consent."
        );
    }
    Ok(())
}

pub(crate) fn acquire_passphrase(
    passphrase_file: Option<&str>,
    purpose: PassphrasePurpose,
) -> Result<Zeroizing<String>> {
    if let Some(path) = passphrase_file {
        if matches!(purpose, PassphrasePurpose::Export) {
            anyhow::bail!(
                "--passphrase-file is disabled for export because it can make the resulting backup agent-decryptable. Omit it and enter a dedicated passphrase at the hidden trusted-terminal prompt."
            );
        }
        return read_passphrase_file(Path::new(path));
    }

    if !terminals_attached() {
        #[cfg(windows)]
        anyhow::bail!(
            "A hidden passphrase prompt requires attached stdin, stdout, and stderr terminals. --passphrase-file is disabled on Windows; rerun from an attached trusted terminal."
        );
        #[cfg(not(windows))]
        anyhow::bail!(
            "A hidden passphrase prompt requires attached stdin, stdout, and stderr terminals. Import may use --passphrase-file with a private regular file (mode 0600 on Unix), but export requires terminal entry."
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

    let mut file = match open_passphrase_file(path) {
        Ok(file) => file,
        #[cfg(unix)]
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            anyhow::bail!("Passphrase file must not be a symlink: {}", path.display())
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Failed to open passphrase file: {}", path.display()))
        }
    };
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

#[cfg(unix)]
fn open_passphrase_file(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    options.open(path)
}

#[cfg(all(not(unix), not(windows)))]
fn open_passphrase_file(path: &Path) -> std::io::Result<File> {
    File::open(path)
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

struct ExportPlan {
    project_dir: PathBuf,
    output_request: String,
    config_path: PathBuf,
    config_before: Vec<u8>,
    local_project_id: String,
    output_path: PathBuf,
    names: Vec<String>,
    names_digest: String,
    effect: String,
    challenge: String,
}

fn prepare_export(output: &str) -> Result<ExportPlan> {
    let project_dir = std::env::current_dir()?.canonicalize()?;
    let config_path = project_dir.join(".phantom.toml");
    let config_before = phantom_core::fs::read_regular_file(&config_path)
        .context("Failed to safely read .phantom.toml")?
        .ok_or_else(|| anyhow::anyhow!("No .phantom.toml found. Run `phantom init` first."))?;
    let config = PhantomConfig::load_from_bytes(&config_path, &config_before)
        .context("Failed to parse the reviewed .phantom.toml snapshot")?;
    recheck_exact_file(&config_path, &config_before, ".phantom.toml")?;
    let local_project_id = config.local_project_id().to_string();
    let output_path = resolve_export_destination(&project_dir, output)?;
    let vault = phantom_vault::try_create_vault(&local_project_id)?;
    let mut names = vault.list().context("Failed to list secrets")?;
    names.sort();
    names.dedup();
    validate_consent_names(&names)?;
    let names_digest = digest_names(&names);
    let rendered_names = render_names(&names)?;
    let config_digest = digest_bytes(&config_before);
    let output_digest = digest_path(&output_path);
    let effect = format!(
        "Export {} secret name(s) (set sha256 {}) from project {} at {} to a new encrypted file {}. Exact secret-name set: {}. Passphrase source: hidden trusted-terminal entry only.",
        names.len(), names_digest, local_project_id, project_dir.display(), output_path.display(), rendered_names
    );
    let challenge = format!(
        "export {} {} {} {}",
        local_project_id, config_digest, names_digest, output_digest
    );
    validate_consent_text(&challenge)?;
    Ok(ExportPlan {
        project_dir,
        output_request: output.to_string(),
        config_path,
        config_before,
        local_project_id,
        output_path,
        names,
        names_digest,
        effect,
        challenge,
    })
}

fn verify_export_plan(plan: &ExportPlan) -> Result<()> {
    recheck_exact_file(&plan.config_path, &plan.config_before, ".phantom.toml")?;
    let current_output = resolve_export_destination(&plan.project_dir, &plan.output_request)?;
    if current_output != plan.output_path {
        anyhow::bail!("Backup output identity changed after export review; no backup was written");
    }
    let vault = phantom_vault::try_create_vault(&plan.local_project_id)?;
    let mut current_names = vault.list().context("Failed to recheck secret names")?;
    current_names.sort();
    current_names.dedup();
    validate_consent_names(&current_names)?;
    if digest_names(&current_names) != plan.names_digest || current_names != plan.names {
        anyhow::bail!(
            "Vault secret-name set changed after export review; no secret values were read"
        );
    }
    Ok(())
}

fn run_encrypted(plan: &ExportPlan, passphrase: &str) -> Result<()> {
    if plan.names.is_empty() {
        println!("{} No secrets to export.", "!".yellow().bold());
        return Ok(());
    }

    verify_export_plan(plan)?;
    let vault = phantom_vault::try_create_vault(&plan.local_project_id)?;

    let mut secrets = SecretMap(BTreeMap::new());
    for name in &plan.names {
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

    verify_export_plan(plan)?;
    atomic_create_private(&plan.output_path, &encrypted).with_context(|| {
        format!(
            "Failed to create backup file: {}",
            plan.output_path.display()
        )
    })?;

    phantom_core::audit::log_result("vault.export_encrypted", None).with_context(|| {
        format!(
            "Backup exists at {}, but its encrypted export audit event could not be written",
            plan.output_path.display()
        )
    })?;

    println!(
        "{} Exported {} secret(s) to {}",
        "ok".green().bold(),
        plan.names.len(),
        plan.output_path.display().to_string().bold()
    );

    Ok(())
}

fn terminals_attached() -> bool {
    std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal()
        && std::io::stderr().is_terminal()
}

pub(crate) fn require_attached_terminals(effect: &str) -> Result<()> {
    if !terminals_attached() {
        anyhow::bail!(
            "{effect} requires stdin, stdout, and stderr attached to a trusted terminal before reading secret-bearing input or vault values"
        );
    }
    Ok(())
}

pub(crate) fn require_trusted_terminal_effect(effect: &str, challenge: &str) -> Result<()> {
    require_attached_terminals(effect)?;
    let stdin = std::io::stdin();
    let stderr = std::io::stderr();
    confirm_effect(
        effect,
        challenge,
        true,
        &mut stdin.lock(),
        &mut stderr.lock(),
    )
}

pub(crate) fn confirm_effect(
    effect: &str,
    challenge: &str,
    attached: bool,
    reader: &mut impl BufRead,
    writer: &mut impl Write,
) -> Result<()> {
    if !attached {
        anyhow::bail!(
            "This secret transfer requires stdin, stdout, and stderr attached to a trusted terminal before secret access"
        );
    }
    validate_consent_text(effect)?;
    validate_consent_text(challenge)?;
    writeln!(writer, "Secret transfer: {effect}")?;
    writeln!(writer, "Approve only if this terminal is outside the requesting agent's authority; a same-user shell or agent-controlled PTY can automate this ceremony.")?;
    write!(writer, "Type `{challenge}` to continue: ")?;
    writer.flush()?;
    let mut response = String::new();
    reader.read_line(&mut response)?;
    if response.trim_end_matches(['\r', '\n']) != challenge {
        anyhow::bail!("Secret transfer cancelled: typed confirmation did not match");
    }
    Ok(())
}

fn validate_consent_text(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_CONSENT_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        anyhow::bail!(
            "Consent identifiers must be non-empty, bounded, and contain no control characters"
        );
    }
    Ok(())
}

pub(crate) fn validate_consent_names(names: &[String]) -> Result<()> {
    let total = names.iter().map(String::len).sum::<usize>();
    if names.len() > MAX_CONSENT_NAMES
        || total > MAX_CONSENT_SET_BYTES
        || names.iter().any(|name| {
            name.is_empty()
                || name.len() > MAX_CONSENT_NAME_BYTES
                || name.chars().any(char::is_control)
        })
    {
        anyhow::bail!("Secret-name set is too large or contains unsafe consent text");
    }
    Ok(())
}

pub(crate) fn digest_names(names: &[String]) -> String {
    let mut hasher = Sha256::new();
    for name in names {
        hasher.update((name.len() as u64).to_be_bytes());
        hasher.update(name.as_bytes());
    }
    hex::encode(hasher.finalize())
}

pub(crate) fn render_names(names: &[String]) -> Result<String> {
    validate_consent_names(names)?;
    serde_json::to_string(names).context("Failed to render the value-blind secret-name set")
}

pub(crate) fn digest_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(unix)]
pub(crate) fn digest_path(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;

    digest_bytes(path.as_os_str().as_bytes())
}

#[cfg(windows)]
pub(crate) fn digest_path(path: &Path) -> String {
    use std::os::windows::ffi::OsStrExt;

    let mut bytes = Vec::new();
    for unit in path.as_os_str().encode_wide() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    digest_bytes(&bytes)
}

#[cfg(all(not(unix), not(windows)))]
pub(crate) fn digest_path(path: &Path) -> String {
    digest_bytes(path.as_os_str().to_string_lossy().as_bytes())
}

fn recheck_exact_file(path: &Path, before: &[u8], label: &str) -> Result<()> {
    if phantom_core::fs::read_regular_file(path)
        .with_context(|| format!("Failed to safely recheck {label}"))?
        .as_deref()
        != Some(before)
    {
        anyhow::bail!("{label} changed during secret-transfer review; no transfer was committed");
    }
    Ok(())
}

fn resolve_export_destination(project_dir: &Path, output: &str) -> Result<PathBuf> {
    validate_consent_text(output)?;
    let relative = Path::new(output);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        anyhow::bail!(
            "Backup output must be a relative path inside the current project without '..'"
        );
    }
    let file_name = relative
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Backup output must name a file"))?;
    let mut current = project_dir.to_path_buf();
    if let Some(parent) = relative.parent() {
        for component in parent.components() {
            let Component::Normal(component) = component else {
                continue;
            };
            current.push(component);
            let metadata = std::fs::symlink_metadata(&current).with_context(|| {
                format!(
                    "Backup parent directory does not exist: {}",
                    current.display()
                )
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                anyhow::bail!(
                    "Backup parent components must be real directories, not symlinks: {}",
                    current.display()
                );
            }
        }
    }
    let canonical_parent = current.canonicalize()?;
    if !canonical_parent.starts_with(project_dir) {
        anyhow::bail!("Backup output must remain inside the current project");
    }
    let path = canonical_parent.join(file_name);
    validate_new_destination(&path)?;
    Ok(path)
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

    #[test]
    fn export_passphrase_file_is_denied_before_path_access() {
        let error = acquire_passphrase(
            Some("/definitely/missing/agent-readable-passphrase"),
            PassphrasePurpose::Export,
        )
        .unwrap_err();
        assert!(error.to_string().contains("disabled for export"));
        assert!(error.to_string().contains("agent-decryptable"));
    }

    #[test]
    fn headless_consent_fails_before_reading_a_response() {
        let mut reader = std::io::Cursor::new(b"exact challenge\n");
        let mut writer = Vec::new();
        let error = confirm_effect(
            "Export reviewed names",
            "exact challenge",
            false,
            &mut reader,
            &mut writer,
        )
        .unwrap_err();
        assert!(error.to_string().contains("trusted terminal"));
        assert_eq!(reader.position(), 0, "headless denial must not read stdin");
        assert!(writer.is_empty());
    }

    #[test]
    fn consent_requires_the_exact_value_blind_challenge() {
        let mut reader = std::io::Cursor::new(b"different challenge\n");
        let mut writer = Vec::new();
        let error = confirm_effect(
            "Export one reviewed name",
            "export project digest output",
            true,
            &mut reader,
            &mut writer,
        )
        .unwrap_err();
        assert!(error.to_string().contains("did not match"));
        let output = String::from_utf8(writer).unwrap();
        assert!(output.contains("same-user shell"));
        assert!(!output.contains("different challenge"));
    }

    #[test]
    fn export_destination_must_be_new_and_inside_project() {
        let dir = tempdir().unwrap();
        let project = dir.path().canonicalize().unwrap();
        assert!(resolve_export_destination(&project, "../escape.enc").is_err());
        assert!(resolve_export_destination(&project, "/tmp/escape.enc").is_err());

        let nested = project.join("backups");
        std::fs::create_dir(&nested).unwrap();
        let resolved = resolve_export_destination(&project, "backups/safe.enc").unwrap();
        assert_eq!(resolved, nested.canonicalize().unwrap().join("safe.enc"));
        std::fs::write(&resolved, b"existing").unwrap();
        assert!(resolve_export_destination(&project, "backups/safe.enc").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn export_destination_rejects_symlinked_parent() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        symlink(outside.path(), dir.path().join("linked")).unwrap();
        let project = dir.path().canonicalize().unwrap();
        let error = resolve_export_destination(&project, "linked/escape.enc").unwrap_err();
        assert!(error.to_string().contains("not symlinks"));
        assert!(!outside.path().join("escape.enc").exists());
    }

    #[test]
    fn name_digest_is_order_and_boundary_sensitive() {
        assert_ne!(
            digest_names(&["AB".to_string(), "C".to_string()]),
            digest_names(&["A".to_string(), "BC".to_string()])
        );
        assert_ne!(
            digest_names(&["A".to_string(), "B".to_string()]),
            digest_names(&["B".to_string(), "A".to_string()])
        );
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
