use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::importers::Importer;
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
    export_cmd::require_attached_terminals("Encrypted backup import")?;
    let project = load_import_project_exact()?;
    let passphrase_policy = if passphrase_file.is_some() {
        "private bounded passphrase file"
    } else {
        "hidden trusted-terminal prompt"
    };
    let passphrase = export_cmd::acquire_passphrase(passphrase_file, PassphrasePurpose::Import)?;
    let source = read_import_source(Path::new(file), "encrypted backup")?;

    let decrypted = Zeroizing::new(
        phantom_vault::crypto::decrypt(&source.bytes, passphrase.as_str())
            .context("Failed to decrypt import file — wrong passphrase or corrupt data")?,
    );

    let secrets = ImportedSecrets::parse(&decrypted)
        .context("Failed to parse import data — file may be corrupt")?;

    if secrets.0.is_empty() {
        println!("{} No secrets found in import file.", "!".yellow().bold());
        return Ok(());
    }

    let vault = phantom_vault::try_create_vault(&project.local_project_id)?;
    let mut vault_names = vault
        .list()
        .context("Failed to list destination secret names")?;
    vault_names.sort();
    vault_names.dedup();
    export_cmd::validate_consent_names(&vault_names)?;
    let existing = vault_names.iter().cloned().collect::<BTreeSet<_>>();
    let incoming = secrets.0.keys().cloned().collect::<Vec<_>>();
    export_cmd::validate_consent_names(&incoming)?;
    let destination_names = incoming
        .iter()
        .filter(|name| force || !existing.contains(*name))
        .cloned()
        .collect::<Vec<_>>();
    let overwrite_names = incoming
        .iter()
        .filter(|name| force && existing.contains(*name))
        .cloned()
        .collect::<Vec<_>>();
    let skipped_names = incoming
        .iter()
        .filter(|name| !force && existing.contains(*name))
        .cloned()
        .collect::<Vec<_>>();
    let consent = import_consent_plan(
        "encrypted-backup",
        &source,
        &project,
        &incoming,
        &destination_names,
        &overwrite_names,
        &skipped_names,
        force,
        passphrase_policy,
    )?;
    export_cmd::require_trusted_terminal_effect(&consent.effect, &consent.challenge)?;
    verify_import_preflight(&project, &source, &vault_names, vault.as_ref())?;

    let mut mutations = Vec::with_capacity(destination_names.len());
    for name in &destination_names {
        let value = secrets
            .0
            .get(name)
            .expect("every reviewed destination has an imported value");
        let before = snapshot_destination_secret(vault.as_ref(), name)?;
        mutations.push(secret_mutation(name, value.as_str(), before.as_ref()));
    }
    let imported = mutations.len();
    recheck_project(&project)?;
    verify_import_source(&source)?;
    phantom_vault::commit_init(
        &project.project_dir,
        vault.as_ref(),
        mutations,
        vec![config_transaction_guard(&project)],
    )
    .context("Encrypted restore transaction failed")?;

    println!(
        "{} Imported {} secret(s) ({} skipped, {} failed)",
        "ok".green().bold(),
        imported,
        skipped_names.len(),
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

struct ImportSource {
    requested_path: PathBuf,
    canonical_path: PathBuf,
    identity: String,
    digest: String,
    bytes: Zeroizing<Vec<u8>>,
}

fn read_import_source(path: &Path, label: &str) -> Result<ImportSource> {
    // Open the authoritative handle first with no-follow semantics. Metadata
    // obtained before open cannot identify which bytes are ultimately read.
    let mut file = match open_encrypted_backup(path) {
        Ok(file) => file,
        #[cfg(unix)]
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            anyhow::bail!("{label} must not be a symlink: {}", path.display())
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Failed to open {label}: {}", path.display()))
        }
    };
    ensure_opened_backup_is_safe(path, &file)?;
    let opened_metadata = file.metadata()?;
    if opened_metadata.len() > MAX_ENCRYPTED_BACKUP_BYTES {
        anyhow::bail!(
            "Import source exceeds the {}-byte safety limit",
            MAX_ENCRYPTED_BACKUP_BYTES
        );
    }

    let identity = opened_source_identity(&file)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(opened_metadata.len() as usize));
    file.by_ref()
        .take(MAX_ENCRYPTED_BACKUP_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("Failed to read {label}: {}", path.display()))?;
    if bytes.len() as u64 > MAX_ENCRYPTED_BACKUP_BYTES {
        anyhow::bail!(
            "Import source exceeds the {}-byte safety limit",
            MAX_ENCRYPTED_BACKUP_BYTES
        );
    }
    ensure_backup_path_still_names_open_file(path, &file)?;
    let canonical_path = path
        .canonicalize()
        .with_context(|| format!("Failed to canonicalize {label}: {}", path.display()))?;
    let digest = export_cmd::digest_bytes(&bytes);
    Ok(ImportSource {
        requested_path: path.to_path_buf(),
        canonical_path,
        identity,
        digest,
        bytes,
    })
}

fn verify_import_source(expected: &ImportSource) -> Result<()> {
    let current = read_import_source(&expected.requested_path, "import source")?;
    if current.canonical_path != expected.canonical_path
        || current.identity != expected.identity
        || current.digest != expected.digest
    {
        anyhow::bail!(
            "Import source changed after trusted-terminal review; no destination mutation was committed"
        );
    }
    Ok(())
}

#[cfg(unix)]
fn opened_source_identity(opened: &File) -> Result<String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = opened.metadata()?;
    Ok(format!("unix:{}:{}", metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
fn opened_source_identity(opened: &File) -> Result<String> {
    let information = windows_file_information(opened)?;
    Ok(format!(
        "windows:{}:{}:{}",
        information.dwVolumeSerialNumber, information.nFileIndexHigh, information.nFileIndexLow
    ))
}

#[cfg(all(not(unix), not(windows)))]
fn opened_source_identity(opened: &File) -> Result<String> {
    let metadata = opened.metadata()?;
    Ok(format!("portable:{}", metadata.len()))
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
    export_cmd::require_attached_terminals("Competitor secret import")?;
    let project = load_import_project_exact()?;
    let source_snapshot = read_import_source(Path::new(file), "competitor import source")?;
    let secrets = parse_competitor_source(source, &source_snapshot.bytes)
        .with_context(|| format!("Failed to parse {source} export file: {file}"))?;

    if secrets.is_empty() {
        println!(
            "{} No secrets found in {} file.",
            "!".yellow().bold(),
            source
        );
        return Ok(());
    }

    let vault = phantom_vault::try_create_vault(&project.local_project_id)?;
    let mut vault_names = vault.list().context("Failed to list local vault secrets")?;
    vault_names.sort();
    vault_names.dedup();
    export_cmd::validate_consent_names(&vault_names)?;
    let env_path = phantom_core::managed_dotenv::resolve_dotenv(
        &project.project_dir,
        &project.config,
        &vault_names,
    )
    .context("Failed to resolve the managed dotenv for import")?
    .path;

    let existing = vault_names.iter().cloned().collect::<BTreeSet<_>>();
    let incoming = secrets.keys().cloned().collect::<Vec<_>>();
    export_cmd::validate_consent_names(&incoming)?;
    let overwrite_names = incoming
        .iter()
        .filter(|name| existing.contains(*name))
        .cloned()
        .collect::<Vec<_>>();
    let consent = import_consent_plan(
        source,
        &source_snapshot,
        &project,
        &incoming,
        &incoming,
        &overwrite_names,
        &[],
        force,
        "not applicable",
    )?;
    export_cmd::require_trusted_terminal_effect(&consent.effect, &consent.challenge)?;
    verify_import_preflight(&project, &source_snapshot, &vault_names, vault.as_ref())?;

    let mut mutations = Vec::with_capacity(secrets.len());
    for (name, value) in &secrets {
        let before = snapshot_destination_secret(vault.as_ref(), name)?;
        mutations.push(secret_mutation(name, value.as_ref(), before.as_ref()));
    }
    let imported = mutations.len();
    recheck_project(&project)?;
    verify_import_source(&source_snapshot)?;
    phantom_vault::commit_init(
        &project.project_dir,
        vault.as_ref(),
        mutations,
        vec![config_transaction_guard(&project)],
    )
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

fn parse_competitor_source(
    source: &str,
    bytes: &[u8],
) -> Result<BTreeMap<String, Zeroizing<String>>> {
    match source {
        "doppler" => phantom_core::importers::doppler::DopplerImporter::parse(bytes),
        "infisical" => phantom_core::importers::infisical::InfisicalImporter::parse(bytes),
        "dotenvx" => phantom_core::importers::dotenvx::DotenvxImporter::parse(bytes),
        "1password" => phantom_core::importers::onepassword::OnePasswordImporter::parse(bytes),
        "env" => parse_env_source(bytes),
        other => anyhow::bail!(
            "Unknown import source '{}'. Supported: doppler, infisical, dotenvx, 1password, env",
            other
        ),
    }
}

fn parse_env_source(bytes: &[u8]) -> Result<BTreeMap<String, Zeroizing<String>>> {
    let content = std::str::from_utf8(bytes).context("File is not valid UTF-8")?;
    let dotenv = phantom_core::dotenv::DotenvFile::parse_str(content);
    let mut secrets = BTreeMap::new();
    for entry in dotenv.entries() {
        if !entry.value.is_empty() {
            secrets.insert(entry.key.clone(), Zeroizing::new(entry.value.clone()));
        }
    }
    Ok(secrets)
}

struct ImportProject {
    project_dir: PathBuf,
    config_path: PathBuf,
    config_before: Vec<u8>,
    config: PhantomConfig,
    local_project_id: String,
}

struct ImportConsentPlan {
    effect: String,
    challenge: String,
}

fn load_import_project_exact() -> Result<ImportProject> {
    let project_dir = std::env::current_dir()?.canonicalize()?;
    let config_path = project_dir.join(".phantom.toml");
    let config_before = phantom_core::fs::read_regular_file(&config_path)
        .context("Failed to safely read .phantom.toml")?
        .ok_or_else(|| anyhow::anyhow!("No .phantom.toml found. Run `phantom init` first."))?;
    let config = PhantomConfig::load_from_bytes(&config_path, &config_before)
        .context("Failed to parse the reviewed .phantom.toml snapshot")?;
    let local_project_id = config.local_project_id().to_string();
    let project = ImportProject {
        project_dir,
        config_path,
        config_before,
        config,
        local_project_id,
    };
    recheck_project(&project)?;
    Ok(project)
}

fn recheck_project(project: &ImportProject) -> Result<()> {
    if phantom_core::fs::read_regular_file(&project.config_path)
        .context("Failed to safely recheck .phantom.toml")?
        .as_deref()
        != Some(project.config_before.as_slice())
    {
        anyhow::bail!(
            ".phantom.toml changed during import review; no destination mutation was committed"
        );
    }
    Ok(())
}

fn config_transaction_guard(project: &ImportProject) -> phantom_vault::InitFile {
    // commit_init has no assert-only file participant. Replacing the exact
    // reviewed bytes with themselves is the narrow no-op that keeps config
    // identity inside the same project lock and rollback transaction as the
    // vault CAS operations.
    phantom_vault::InitFile::replace_if_unchanged(
        project.config_path.clone(),
        Some(project.config_before.clone()),
        project.config_before.clone(),
    )
}

#[allow(clippy::too_many_arguments)]
fn import_consent_plan(
    import_type: &str,
    source: &ImportSource,
    project: &ImportProject,
    incoming_names: &[String],
    destination_names: &[String],
    overwrite_names: &[String],
    skipped_names: &[String],
    force: bool,
    passphrase_policy: &str,
) -> Result<ImportConsentPlan> {
    for names in [
        incoming_names,
        destination_names,
        overwrite_names,
        skipped_names,
    ] {
        export_cmd::validate_consent_names(names)?;
    }
    let incoming_digest = export_cmd::digest_names(incoming_names);
    let destination_digest = export_cmd::digest_names(destination_names);
    let overwrite_digest = export_cmd::digest_names(overwrite_names);
    let skipped_digest = export_cmd::digest_names(skipped_names);
    let rendered_incoming = export_cmd::render_names(incoming_names)?;
    let rendered_destinations = export_cmd::render_names(destination_names)?;
    let rendered_overwrites = export_cmd::render_names(overwrite_names)?;
    let rendered_skipped = export_cmd::render_names(skipped_names)?;
    let config_digest = export_cmd::digest_bytes(&project.config_before);
    let source_path_digest = export_cmd::digest_path(&source.canonical_path);
    let source_binding = export_cmd::digest_bytes(
        format!(
            "{}\0{}\0{}",
            source_path_digest, source.identity, source.digest
        )
        .as_bytes(),
    );
    let overwrite_policy = if overwrite_names.is_empty() {
        "no reviewed destination is overwritten"
    } else {
        "the exact reviewed overwrite set is replaced; --force never bypasses this ceremony"
    };
    let effect = format!(
        "Import type {import_type} from canonical source {} (identity {}, sha256 {}, binding sha256 {}) into canonical project {} (vault {}, config sha256 {}). Incoming set: {} name(s), sha256 {}, exact names {}. Destination set: {} name(s), sha256 {}, exact names {}. Overwrite set: {} name(s), sha256 {}, exact names {}. Skipped set: {} name(s), sha256 {}, exact names {}. Overwrite policy: {overwrite_policy}. Force requested: {force}. Passphrase source policy: {passphrase_policy}.",
        source.canonical_path.display(),
        source.identity,
        source.digest,
        source_binding,
        project.project_dir.display(),
        project.local_project_id,
        config_digest,
        incoming_names.len(),
        incoming_digest,
        rendered_incoming,
        destination_names.len(),
        destination_digest,
        rendered_destinations,
        overwrite_names.len(),
        overwrite_digest,
        rendered_overwrites,
        skipped_names.len(),
        skipped_digest,
        rendered_skipped,
    );
    let challenge = format!(
        "import {} {} {} {} {} {} {} {}",
        import_type,
        source_binding,
        project.local_project_id,
        config_digest,
        destination_digest,
        overwrite_digest,
        skipped_digest,
        force,
    );
    Ok(ImportConsentPlan { effect, challenge })
}

fn verify_import_preflight(
    project: &ImportProject,
    source: &ImportSource,
    expected_vault_names: &[String],
    vault: &dyn phantom_vault::VaultBackend,
) -> Result<()> {
    recheck_project(project)?;
    verify_import_source(source)?;
    let mut current_names = vault
        .list()
        .context("Failed to recheck destination secret names")?;
    current_names.sort();
    current_names.dedup();
    export_cmd::validate_consent_names(&current_names)?;
    if current_names != expected_vault_names {
        anyhow::bail!(
            "Destination secret-name set changed after trusted-terminal review; no destination values were read or mutated"
        );
    }
    Ok(())
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

    #[test]
    fn source_change_after_review_invalidates_import() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.enc");
        std::fs::write(&path, b"reviewed ciphertext").unwrap();
        let reviewed = read_import_source(&path, "test source").unwrap();

        std::fs::write(&path, b"different ciphertext").unwrap();
        let error = verify_import_source(&reviewed).unwrap_err();
        assert!(error
            .to_string()
            .contains("changed after trusted-terminal review"));
    }

    #[cfg(unix)]
    #[test]
    fn import_source_symlink_is_rejected_without_following() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.env");
        let linked = dir.path().join("linked.env");
        std::fs::write(&real, b"TOKEN=secret").unwrap();
        symlink(&real, &linked).unwrap();
        let error = read_import_source(&linked, "competitor import source")
            .err()
            .expect("symlink import source must be rejected");
        assert!(error.to_string().contains("must not be a symlink"));
    }

    #[test]
    fn consent_binds_source_target_destination_and_overwrite_sets() {
        let dir = tempfile::tempdir().unwrap();
        let project_dir = dir.path().canonicalize().unwrap();
        let config_path = project_dir.join(".phantom.toml");
        let config_before = br#"[phantom]
version = "1"
project_id = "portable-test"
"#
        .to_vec();
        std::fs::write(&config_path, &config_before).unwrap();
        let config = PhantomConfig::load_from_bytes(&config_path, &config_before).unwrap();
        let project = ImportProject {
            local_project_id: config.local_project_id().to_string(),
            project_dir: project_dir.clone(),
            config_path,
            config_before,
            config,
        };
        let source_path = project_dir.join("input.env");
        std::fs::write(&source_path, b"TOKEN=secret").unwrap();
        let source = read_import_source(&source_path, "test source").unwrap();
        let incoming = vec!["TOKEN".to_string()];
        let first = import_consent_plan(
            "env",
            &source,
            &project,
            &incoming,
            &incoming,
            &[],
            &[],
            false,
            "not applicable",
        )
        .unwrap();
        let overwrite = import_consent_plan(
            "env",
            &source,
            &project,
            &incoming,
            &incoming,
            &incoming,
            &[],
            false,
            "not applicable",
        )
        .unwrap();
        assert_ne!(first.challenge, overwrite.challenge);
        assert!(first.effect.contains("exact names [\"TOKEN\"]"));
        assert!(overwrite.effect.contains("Overwrite set: 1 name(s)"));

        std::fs::write(&source_path, b"TOKEN=different").unwrap();
        let changed_source = read_import_source(&source_path, "test source").unwrap();
        let changed = import_consent_plan(
            "env",
            &changed_source,
            &project,
            &incoming,
            &incoming,
            &[],
            &[],
            false,
            "not applicable",
        )
        .unwrap();
        assert_ne!(first.challenge, changed.challenge);
        assert!(!first.effect.contains("secret"));
        assert!(!changed.effect.contains("different"));
    }

    #[test]
    fn config_snapshot_parsing_does_not_follow_a_later_path_swap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".phantom.toml");
        let reviewed = br#"[phantom]
version = "1"
project_id = "reviewed-project"
"#;
        std::fs::write(
            &path,
            br#"[phantom]
version = "1"
project_id = "swapped-project"
"#,
        )
        .unwrap();
        let parsed = PhantomConfig::load_from_bytes(&path, reviewed).unwrap();
        assert_eq!(parsed.phantom.project_id, "reviewed-project");
        assert_ne!(
            phantom_core::fs::read_regular_file(&path).unwrap().unwrap(),
            reviewed
        );
    }

    #[test]
    fn force_cannot_bypass_headless_consent() {
        let mut reader = std::io::Cursor::new(b"import env digest project config set overwrite\n");
        let mut writer = Vec::new();
        let error = export_cmd::confirm_effect(
            "Import with force requested: true",
            "import env digest project config set overwrite",
            false,
            &mut reader,
            &mut writer,
        )
        .unwrap_err();
        assert!(error.to_string().contains("trusted terminal"));
        assert_eq!(reader.position(), 0);
        assert!(writer.is_empty());
    }
}
