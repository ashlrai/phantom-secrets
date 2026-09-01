//! Recoverable initialization across vault entries and project files.
//!
//! Initialization cannot rely on a sequence of independent `store` and
//! `write` calls: a later failure would otherwise leave an environment file
//! tokenized without its vault entries, or overwrite an existing credential.
//! This module snapshots every target in memory, uses atomic file replacement,
//! verifies before-images immediately before and after writes, and restores only
//! state identified by this transaction's exact effect receipts. The project
//! lock retains the canonical project root and every payload ancestor from
//! snapshot through commit or rollback, so renaming the ambient project path
//! cannot redirect an effect. An uncooperative same-user process can still race
//! a final leaf between verification and rename; post-write verification and
//! explicit committed-effect receipts fail closed but are not an OS-level
//! filesystem CAS. Secret values are never serialized or formatted.

use crate::{
    acquire_project_transaction_lock, ProjectTransactionLock, SecretMetadata, VaultBackend,
};
use phantom_core::error::PhantomError;
use phantom_core::fs::{
    AnchoredCreatedDirectory, AnchoredDirectoryCreation, AnchoredEffect, AnchoredFilePermissions,
    AnchoredRead, AnchoredTarget, TrustedAnchor,
};
use phantom_core::validator::ValidationMetadata;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub struct InitSecret {
    name: String,
    replacement: Option<Zeroizing<String>>,
    expected_before: Option<Option<Zeroizing<String>>>,
}

impl InitSecret {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            replacement: Some(Zeroizing::new(value.into())),
            expected_before: None,
        }
    }

    /// Require the destination to still match an exact before-image.
    ///
    /// `None` means the secret must still be absent. This is used by import
    /// and pull transactions so an uncooperative concurrent writer cannot turn
    /// a previously reviewed create into an overwrite.
    pub fn replace_if_unchanged(
        name: impl Into<String>,
        expected_before: Option<impl Into<String>>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            replacement: Some(Zeroizing::new(value.into())),
            expected_before: Some(expected_before.map(|value| Zeroizing::new(value.into()))),
        }
    }

    /// Delete an existing entry only while its value still equals the exact
    /// before-image. The backend CAS also removes its lifecycle and validation
    /// metadata in the same encrypted-vault/keychain transaction.
    pub fn delete_if_unchanged(
        name: impl Into<String>,
        expected_before: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            replacement: None,
            expected_before: Some(Some(Zeroizing::new(expected_before.into()))),
        }
    }
}

impl fmt::Debug for InitSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InitSecret")
            .field("name", &self.name)
            .field("replacement", &"[REDACTED]")
            .finish()
    }
}

pub struct InitFile {
    path: PathBuf,
    content: Zeroizing<Vec<u8>>,
    expected_before: Option<Option<Zeroizing<Vec<u8>>>>,
    executable: bool,
    commit_last: bool,
}

impl InitFile {
    pub fn replace(path: impl Into<PathBuf>, content: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            content: Zeroizing::new(content.into()),
            expected_before: None,
            executable: false,
            commit_last: false,
        }
    }

    /// Require the file to still match an exact before-image before writing.
    ///
    /// `None` means the path must still be absent. Symlinks and non-regular
    /// files are rejected independently by the transaction preflight.
    pub fn replace_if_unchanged(
        path: impl Into<PathBuf>,
        expected_before: Option<impl Into<Vec<u8>>>,
        content: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            path: path.into(),
            content: Zeroizing::new(content.into()),
            expected_before: Some(expected_before.map(|value| Zeroizing::new(value.into()))),
            executable: false,
            commit_last: false,
        }
    }

    pub fn executable(mut self, executable: bool) -> Self {
        self.executable = executable;
        self
    }

    /// Mark a file as the final commit point after every value-free file and
    /// vault entry is durable. The tokenized dotenv uses this so interruption
    /// before the last atomic rename always leaves retryable plaintext rather
    /// than unusable tokens.
    pub fn commit_last(mut self) -> Self {
        self.commit_last = true;
        self
    }
}

impl fmt::Debug for InitFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InitFile")
            .field("path", &self.path)
            .field("content", &"[REDACTED]")
            .field("executable", &self.executable)
            .field("commit_last", &self.commit_last)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitReceipt {
    pub secret_names: Vec<String>,
    pub file_paths: Vec<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum InitTransactionError {
    #[error("init preflight failed at {target}: {reason}")]
    Preflight { target: String, reason: String },
    #[error("init state changed concurrently at {target}; no changes were committed")]
    ConcurrentChange { target: String },
    #[error("init commit failed at {target}: {reason}; all changes were restored")]
    Commit { target: String, reason: String },
    #[error("init commit failed at {target}, and rollback could not safely restore every target")]
    RollbackIncomplete { target: String },
}

struct SecretSnapshot {
    name: String,
    before: Option<Zeroizing<String>>,
    metadata: Option<SecretMetadata>,
    validation: Option<ValidationMetadata>,
    after: Option<Zeroizing<String>>,
    touched: bool,
}

struct FileSnapshot {
    path: PathBuf,
    target: Option<AnchoredTarget>,
    parent_anchor: Option<TrustedAnchor>,
    existing_parent_path: PathBuf,
    missing_parent_paths: Vec<PathBuf>,
    leaf: OsString,
    before: Option<AnchoredRead>,
    after: Zeroizing<Vec<u8>>,
    executable: bool,
    commit_last: bool,
    touched: bool,
    committed: Option<AnchoredRead>,
}

trait FileWriter {
    fn write(
        &self,
        target: &AnchoredTarget,
        expected: Option<&AnchoredRead>,
        content: &[u8],
        permissions: AnchoredFilePermissions,
    ) -> std::io::Result<AnchoredEffect<AnchoredRead>>;
}

struct AtomicFileWriter;

impl FileWriter for AtomicFileWriter {
    fn write(
        &self,
        target: &AnchoredTarget,
        expected: Option<&AnchoredRead>,
        content: &[u8],
        permissions: AnchoredFilePermissions,
    ) -> std::io::Result<AnchoredEffect<AnchoredRead>> {
        target.replace_if_exact_with_permissions(expected, content, permissions)
    }
}

/// Commit a complete initialization plan, restoring its exact before-images
/// on any observable failure. Vault entries use backend atomic CAS. Files use
/// the retained project capability plus identity-bound before/after
/// verification; rollback only restores a file while it still equals the
/// transaction's exact committed-effect receipt.
pub fn commit_init(
    project_dir: &Path,
    vault: &dyn VaultBackend,
    secrets: Vec<InitSecret>,
    files: Vec<InitFile>,
) -> Result<InitReceipt, InitTransactionError> {
    commit_init_with(project_dir, vault, secrets, files, &AtomicFileWriter)
}

fn commit_init_with(
    project_dir: &Path,
    vault: &dyn VaultBackend,
    mut secrets: Vec<InitSecret>,
    mut files: Vec<InitFile>,
    writer: &dyn FileWriter,
) -> Result<InitReceipt, InitTransactionError> {
    let transaction_lock = acquire_project_transaction_lock(project_dir).map_err(|error| {
        InitTransactionError::Preflight {
            target: project_dir.display().to_string(),
            reason: format!("could not acquire project transaction lock: {error}"),
        }
    })?;
    let mut names = BTreeSet::new();
    for secret in &secrets {
        if secret.name.is_empty() || !names.insert(secret.name.clone()) {
            return Err(InitTransactionError::Preflight {
                target: secret.name.clone(),
                reason: "secret names must be non-empty and unique".to_string(),
            });
        }
    }
    let mut paths = BTreeSet::new();
    for file in &files {
        let relative = transaction_lock
            .relative_project_path(&file.path)
            .map_err(|error| InitTransactionError::Preflight {
                target: file.path.display().to_string(),
                reason: error.to_string(),
            })?;
        if !paths.insert(relative) {
            return Err(InitTransactionError::Preflight {
                target: file.path.display().to_string(),
                reason: "file targets must be unique".to_string(),
            });
        }
    }

    let mut secret_snapshots = Vec::with_capacity(secrets.len());
    for secret in secrets.drain(..) {
        let existed = vault
            .exists(&secret.name)
            .map_err(|error| preflight_vault(&secret.name, error))?;
        let before = if existed {
            Some(
                vault
                    .retrieve(&secret.name)
                    .map_err(|error| preflight_vault(&secret.name, error))?,
            )
        } else {
            None
        };
        if let Some(expected_before) = secret.expected_before.as_ref() {
            let matches = before.as_ref().map(|value| value.as_str())
                == expected_before.as_ref().map(|value| value.as_str());
            if !matches {
                return Err(InitTransactionError::ConcurrentChange {
                    target: secret.name,
                });
            }
        }
        let metadata = vault
            .get_metadata(&secret.name)
            .map_err(|error| preflight_vault(&secret.name, error))?;
        let validation = vault
            .get_validation_metadata_exact(&secret.name)
            .map_err(|error| preflight_vault(&secret.name, error))?;
        secret_snapshots.push(SecretSnapshot {
            name: secret.name,
            before,
            metadata,
            validation,
            after: secret.replacement,
            touched: false,
        });
    }

    let mut file_snapshots = Vec::with_capacity(files.len());
    for file in files.drain(..) {
        file_snapshots.push(snapshot_file(&transaction_lock, file)?);
    }

    let mut created_directories = BTreeMap::new();
    let mut unresolved_directory_effect = false;
    let commit_result = (|| {
        for snapshot in file_snapshots
            .iter_mut()
            .filter(|snapshot| !snapshot.commit_last)
        {
            commit_file(
                snapshot,
                &transaction_lock,
                &mut created_directories,
                &mut unresolved_directory_effect,
                writer,
            )?;
        }

        for snapshot in &mut secret_snapshots {
            let expected = snapshot.before.as_ref().map(|value| value.as_str());
            let replacement = snapshot.after.as_ref().map(|value| value.as_str());
            match vault.compare_and_swap(&snapshot.name, expected, replacement) {
                Ok(true) => snapshot.touched = true,
                Ok(false) => {
                    return Err((
                        snapshot.name.clone(),
                        InitTransactionError::ConcurrentChange {
                            target: snapshot.name.clone(),
                        }
                        .to_string(),
                    ));
                }
                Err(_error) => {
                    let current_is_after = ensure_secret_state(vault, snapshot, true).is_ok();
                    let current_is_before = ensure_secret_state(vault, snapshot, false).is_ok();
                    // A backend may report failure after mutating, or another
                    // writer may race the operation. Mark ambiguous state as
                    // touched so rollback fails closed instead of claiming a
                    // complete restoration.
                    snapshot.touched = current_is_after || !current_is_before;
                    return Err((
                        snapshot.name.clone(),
                        "atomic vault compare-and-swap failed".to_string(),
                    ));
                }
            }
            ensure_secret_state(vault, snapshot, true)
                .map_err(|error| (snapshot.name.clone(), error.to_string()))?;
            ensure_secret_metadata(vault, snapshot)
                .map_err(|error| (snapshot.name.clone(), error.to_string()))?;
        }

        for snapshot in file_snapshots
            .iter_mut()
            .filter(|snapshot| snapshot.commit_last)
        {
            commit_file(
                snapshot,
                &transaction_lock,
                &mut created_directories,
                &mut unresolved_directory_effect,
                writer,
            )?;
        }
        Ok::<(), (String, String)>(())
    })();

    if let Err((target, reason)) = commit_result {
        let files_ok = rollback_files(&mut file_snapshots);
        release_file_capabilities(&mut file_snapshots);
        let directories_ok = rollback_directories(created_directories, unresolved_directory_effect);
        let vault_ok = rollback_secrets(vault, &mut secret_snapshots);
        return if files_ok && directories_ok && vault_ok {
            Err(InitTransactionError::Commit { target, reason })
        } else {
            Err(InitTransactionError::RollbackIncomplete { target })
        };
    }

    let receipt = InitReceipt {
        secret_names: secret_snapshots.iter().map(|s| s.name.clone()).collect(),
        file_paths: file_snapshots.iter().map(|f| f.path.clone()).collect(),
    };
    Ok(receipt)
}

fn commit_file(
    snapshot: &mut FileSnapshot,
    transaction_lock: &ProjectTransactionLock,
    created_directories: &mut BTreeMap<PathBuf, AnchoredCreatedDirectory>,
    unresolved_directory_effect: &mut bool,
    writer: &dyn FileWriter,
) -> Result<(), (String, String)> {
    create_missing_parents(
        snapshot,
        transaction_lock,
        created_directories,
        unresolved_directory_effect,
    )
    .map_err(|error| (snapshot.path.display().to_string(), error.to_string()))?;
    ensure_file_state(snapshot, false)
        .map_err(|error| (snapshot.path.display().to_string(), error.to_string()))?;
    let permissions = if snapshot.executable {
        AnchoredFilePermissions::executable()
    } else {
        snapshot
            .before
            .as_ref()
            .map(AnchoredRead::permissions)
            .unwrap_or_else(AnchoredFilePermissions::private)
    };
    let target = snapshot
        .target
        .as_ref()
        .expect("missing parents are resolved before file commit");
    match writer.write(
        target,
        snapshot.before.as_ref(),
        snapshot.after.as_slice(),
        permissions,
    ) {
        Ok(AnchoredEffect::Durable(committed)) => {
            snapshot.touched = true;
            snapshot.committed = Some(committed);
        }
        Ok(AnchoredEffect::CommittedButUncertain { value, error }) => {
            snapshot.touched = true;
            snapshot.committed = Some(value);
            return Err((snapshot.path.display().to_string(), error.to_string()));
        }
        Err(error) => {
            classify_failed_file_write(snapshot);
            return Err((snapshot.path.display().to_string(), error.to_string()));
        }
    }
    ensure_file_state(snapshot, true)
        .map_err(|error| (snapshot.path.display().to_string(), error.to_string()))
}

fn preflight_vault(name: &str, _error: PhantomError) -> InitTransactionError {
    InitTransactionError::Preflight {
        target: name.to_string(),
        reason: "vault snapshot failed".to_string(),
    }
}

fn snapshot_file(
    transaction_lock: &ProjectTransactionLock,
    mut file: InitFile,
) -> Result<FileSnapshot, InitTransactionError> {
    let relative = transaction_lock
        .relative_project_path(&file.path)
        .map_err(|error| InitTransactionError::Preflight {
            target: file.path.display().to_string(),
            reason: error.to_string(),
        })?;
    let components = relative
        .components()
        .map(|component| match component {
            std::path::Component::Normal(value) => Ok(value.to_os_string()),
            _ => Err(InitTransactionError::Preflight {
                target: file.path.display().to_string(),
                reason: "project file target must contain only normal relative components"
                    .to_string(),
            }),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (leaf, parents) =
        components
            .split_last()
            .ok_or_else(|| InitTransactionError::Preflight {
                target: file.path.display().to_string(),
                reason: "project file target cannot name the project root".to_string(),
            })?;

    let mut parent_anchor = None;
    let mut existing_parent_path = PathBuf::new();
    let mut missing_parent_paths = Vec::new();
    for (index, component) in parents.iter().enumerate() {
        let anchor = parent_anchor
            .as_ref()
            .unwrap_or_else(|| transaction_lock.project_anchor());
        match anchor.open_subdirectory(Path::new(component.as_os_str())) {
            Ok(next) => {
                existing_parent_path.push(component);
                parent_anchor = Some(next);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut missing_path = existing_parent_path.clone();
                for missing in &parents[index..] {
                    missing_path.push(missing);
                    missing_parent_paths.push(missing_path.clone());
                }
                break;
            }
            Err(error) => {
                return Err(InitTransactionError::Preflight {
                    target: file.path.display().to_string(),
                    reason: error.to_string(),
                });
            }
        }
    }

    let target = if missing_parent_paths.is_empty() {
        let anchor = parent_anchor
            .as_ref()
            .unwrap_or_else(|| transaction_lock.project_anchor());
        Some(
            anchor
                .target(Path::new(leaf.as_os_str()))
                .map_err(|error| InitTransactionError::Preflight {
                    target: file.path.display().to_string(),
                    reason: error.to_string(),
                })?,
        )
    } else {
        None
    };
    let before = match target.as_ref() {
        Some(target) => target
            .read_regular()
            .map_err(|error| InitTransactionError::Preflight {
                target: file.path.display().to_string(),
                reason: error.to_string(),
            })?,
        None => None,
    };
    if let Some(expected_before) = file.expected_before.as_ref() {
        let matches = before.as_ref().map(AnchoredRead::bytes)
            == expected_before.as_ref().map(|value| value.as_slice());
        if !matches {
            return Err(InitTransactionError::ConcurrentChange {
                target: file.path.display().to_string(),
            });
        }
    }

    Ok(FileSnapshot {
        path: file.path,
        target,
        parent_anchor,
        existing_parent_path,
        missing_parent_paths,
        leaf: leaf.clone(),
        before,
        after: std::mem::take(&mut file.content),
        executable: file.executable,
        commit_last: file.commit_last,
        touched: false,
        committed: None,
    })
}

fn create_missing_parents(
    snapshot: &mut FileSnapshot,
    transaction_lock: &ProjectTransactionLock,
    created_directories: &mut BTreeMap<PathBuf, AnchoredCreatedDirectory>,
    unresolved_directory_effect: &mut bool,
) -> std::io::Result<()> {
    for path in &snapshot.missing_parent_paths {
        if created_directories.contains_key(path) {
            continue;
        }
        let parent_path = path.parent().unwrap_or_else(|| Path::new(""));
        let leaf = path
            .file_name()
            .ok_or_else(|| std::io::Error::other("planned parent has no directory name"))?;
        let creation = {
            let anchor = if parent_path.as_os_str().is_empty() {
                transaction_lock.project_anchor()
            } else if let Some(created) = created_directories.get(parent_path) {
                created.anchor()
            } else if parent_path == snapshot.existing_parent_path {
                snapshot
                    .parent_anchor
                    .as_ref()
                    .unwrap_or_else(|| transaction_lock.project_anchor())
            } else {
                return Err(std::io::Error::other(
                    "planned parent capability is unavailable",
                ));
            };
            anchor.create_private_child(Path::new(leaf))?
        };
        record_directory_creation(
            path,
            creation,
            created_directories,
            unresolved_directory_effect,
        )?;
    }
    if snapshot.target.is_none() {
        let anchor = snapshot
            .missing_parent_paths
            .last()
            .and_then(|path| created_directories.get(path))
            .map(AnchoredCreatedDirectory::anchor)
            .or(snapshot.parent_anchor.as_ref())
            .unwrap_or_else(|| transaction_lock.project_anchor());
        snapshot.target = Some(anchor.target(Path::new(snapshot.leaf.as_os_str()))?);
    }
    Ok(())
}

fn record_directory_creation(
    path: &Path,
    creation: AnchoredDirectoryCreation,
    created_directories: &mut BTreeMap<PathBuf, AnchoredCreatedDirectory>,
    unresolved_directory_effect: &mut bool,
) -> std::io::Result<()> {
    match creation {
        AnchoredDirectoryCreation::Durable(created) => {
            created_directories.insert(path.to_path_buf(), created);
            Ok(())
        }
        AnchoredDirectoryCreation::CommittedButUncertain { receipt, error } => {
            if let Some(created) = receipt {
                created_directories.insert(path.to_path_buf(), created);
            } else {
                *unresolved_directory_effect = true;
            }
            Err(error)
        }
    }
}

fn classify_failed_file_write(snapshot: &mut FileSnapshot) {
    let Some(target) = snapshot.target.as_ref() else {
        return;
    };
    match target.read_regular() {
        Ok(current) if current.as_ref() == snapshot.before.as_ref() => {}
        _ => snapshot.touched = true,
    }
}

fn ensure_secret_state(
    vault: &dyn VaultBackend,
    snapshot: &SecretSnapshot,
    after: bool,
) -> Result<(), InitTransactionError> {
    let expected = if after {
        snapshot.after.as_ref().map(|value| value.as_str())
    } else {
        snapshot.before.as_ref().map(|value| value.as_str())
    };
    let current = match vault.retrieve(&snapshot.name) {
        Ok(value) => Some(value),
        Err(PhantomError::SecretNotFound(_)) => None,
        Err(_error) => {
            return Err(InitTransactionError::Preflight {
                target: snapshot.name.clone(),
                reason: "vault state verification failed".to_string(),
            });
        }
    };
    if current.as_ref().map(|value| value.as_str()) == expected {
        Ok(())
    } else {
        Err(InitTransactionError::ConcurrentChange {
            target: snapshot.name.clone(),
        })
    }
}

fn ensure_secret_metadata(
    vault: &dyn VaultBackend,
    snapshot: &SecretSnapshot,
) -> Result<(), InitTransactionError> {
    if snapshot.after.is_none() {
        let metadata_absent = vault
            .get_metadata(&snapshot.name)
            .map_err(|_| InitTransactionError::Preflight {
                target: snapshot.name.clone(),
                reason: "vault metadata verification failed".to_string(),
            })?
            .is_none();
        let validation_absent = vault
            .get_validation_metadata_exact(&snapshot.name)
            .map_err(|_| InitTransactionError::Preflight {
                target: snapshot.name.clone(),
                reason: "vault validation metadata verification failed".to_string(),
            })?
            .is_none();
        return if metadata_absent && validation_absent {
            Ok(())
        } else {
            Err(InitTransactionError::ConcurrentChange {
                target: snapshot.name.clone(),
            })
        };
    }
    // New entries intentionally receive backend-generated creation metadata.
    // Deleting the entry during rollback also deletes that metadata.
    if snapshot.before.is_none() {
        return Ok(());
    }
    let metadata_matches =
        vault
            .get_metadata(&snapshot.name)
            .map_err(|_| InitTransactionError::Preflight {
                target: snapshot.name.clone(),
                reason: "vault metadata verification failed".to_string(),
            })?
            == snapshot.metadata;
    let validation_matches = vault
        .get_validation_metadata_exact(&snapshot.name)
        .map_err(|_| InitTransactionError::Preflight {
            target: snapshot.name.clone(),
            reason: "vault validation metadata verification failed".to_string(),
        })?
        == snapshot.validation;
    if metadata_matches && validation_matches {
        Ok(())
    } else {
        Err(InitTransactionError::ConcurrentChange {
            target: snapshot.name.clone(),
        })
    }
}

fn ensure_file_state(snapshot: &FileSnapshot, after: bool) -> Result<(), InitTransactionError> {
    let expected = if after {
        snapshot.committed.as_ref()
    } else {
        snapshot.before.as_ref()
    };
    let current = snapshot
        .target
        .as_ref()
        .expect("file target is retained before state verification")
        .read_regular();
    if matches!(current, Ok(current) if current.as_ref() == expected) {
        Ok(())
    } else {
        Err(InitTransactionError::ConcurrentChange {
            target: snapshot.path.display().to_string(),
        })
    }
}

fn rollback_files(snapshots: &mut [FileSnapshot]) -> bool {
    let mut ok = true;
    for snapshot in snapshots
        .iter_mut()
        .rev()
        .filter(|snapshot| snapshot.touched)
    {
        let Some(committed) = snapshot.committed.take() else {
            ok = false;
            continue;
        };
        let Some(target) = snapshot.target.as_ref() else {
            ok = false;
            continue;
        };
        let restored = match &snapshot.before {
            Some(before) => matches!(
                target.replace_if_exact_with_permissions(
                    Some(&committed),
                    before.bytes(),
                    before.permissions(),
                ),
                Ok(AnchoredEffect::Durable(_))
            ),
            None => matches!(
                target.unlink_if_exact(&committed),
                Ok(AnchoredEffect::Durable(()))
            ),
        };
        if !restored {
            ok = false;
        } else {
            snapshot.touched = false;
        }
    }
    ok
}

fn release_file_capabilities(snapshots: &mut [FileSnapshot]) {
    for snapshot in snapshots {
        // On Windows every retained descendant handle intentionally omits
        // FILE_SHARE_DELETE. Close all file-target and pre-existing-parent
        // handles before consuming exact created-directory removal receipts.
        snapshot.target.take();
        snapshot.parent_anchor.take();
    }
}

fn rollback_directories(
    created: BTreeMap<PathBuf, AnchoredCreatedDirectory>,
    unresolved_directory_effect: bool,
) -> bool {
    let mut directories = created.into_iter().collect::<Vec<_>>();
    directories.sort_by_key(|(path, _)| path.components().count());
    let mut ok = !unresolved_directory_effect;
    while let Some((_, directory)) = directories.pop() {
        match directory.remove_if_empty_exact() {
            Ok(AnchoredEffect::Durable(())) => {}
            Ok(AnchoredEffect::CommittedButUncertain { .. }) | Err(_) => ok = false,
        }
    }
    ok
}

fn rollback_secrets(vault: &dyn VaultBackend, snapshots: &mut [SecretSnapshot]) -> bool {
    let mut ok = true;
    for snapshot in snapshots
        .iter_mut()
        .rev()
        .filter(|snapshot| snapshot.touched)
    {
        let replacement = snapshot.before.as_ref().map(|before| before.as_str());
        let expected_after = snapshot.after.as_ref().map(|after| after.as_str());
        let result = vault.compare_and_swap(&snapshot.name, expected_after, replacement);
        let metadata_restored = if matches!(result, Ok(true)) && snapshot.after.is_none() {
            restore_deleted_metadata(vault, snapshot)
        } else {
            matches!(result, Ok(true))
        };
        if !metadata_restored
            || (snapshot.before.is_some() && ensure_secret_metadata(vault, snapshot).is_err())
        {
            ok = false;
        } else {
            snapshot.touched = false;
        }
    }
    ok
}

fn restore_deleted_metadata(vault: &dyn VaultBackend, snapshot: &SecretSnapshot) -> bool {
    let current_metadata = match vault.get_metadata(&snapshot.name) {
        Ok(metadata) => metadata,
        Err(_) => return false,
    };
    if !matches!(
        vault.compare_and_swap_metadata(
            &snapshot.name,
            current_metadata.as_ref(),
            snapshot.metadata.clone()
        ),
        Ok(true)
    ) {
        return false;
    }
    let current_validation = match vault.get_validation_metadata_exact(&snapshot.name) {
        Ok(metadata) => metadata,
        Err(_) => return false,
    };
    matches!(
        vault.compare_and_swap_validation_metadata(
            &snapshot.name,
            current_validation.as_ref(),
            snapshot.validation.clone()
        ),
        Ok(true)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::FileVault;
    use phantom_core::error::Result as PhantomResult;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;

    struct FailingVault {
        inner: FileVault,
        stores: AtomicUsize,
        fail_store: usize,
    }

    impl VaultBackend for FailingVault {
        fn store(&self, name: &str, value: &str) -> PhantomResult<()> {
            let call = self.stores.fetch_add(1, Ordering::SeqCst) + 1;
            if call == self.fail_store {
                return Err(PhantomError::VaultError("injected store failure".into()));
            }
            self.inner.store(name, value)
        }
        fn retrieve(&self, name: &str) -> PhantomResult<Zeroizing<String>> {
            self.inner.retrieve(name)
        }
        fn delete(&self, name: &str) -> PhantomResult<()> {
            self.inner.delete(name)
        }
        fn compare_and_swap(
            &self,
            name: &str,
            expected: Option<&str>,
            replacement: Option<&str>,
        ) -> PhantomResult<bool> {
            let call = self.stores.fetch_add(1, Ordering::SeqCst) + 1;
            if call == self.fail_store {
                return Err(PhantomError::VaultError("injected CAS failure".into()));
            }
            self.inner.compare_and_swap(name, expected, replacement)
        }
        fn list(&self) -> PhantomResult<Vec<String>> {
            self.inner.list()
        }
        fn backend_name(&self) -> &str {
            "failing"
        }
        fn get_metadata(&self, name: &str) -> PhantomResult<Option<SecretMetadata>> {
            self.inner.get_metadata(name)
        }
        fn set_metadata(&self, name: &str, meta: SecretMetadata) -> PhantomResult<()> {
            self.inner.set_metadata(name, meta)
        }
        fn get_validation_metadata(&self, name: &str) -> PhantomResult<ValidationMetadata> {
            self.inner.get_validation_metadata(name)
        }
        fn set_validation_metadata(
            &self,
            name: &str,
            meta: ValidationMetadata,
        ) -> PhantomResult<()> {
            self.inner.set_validation_metadata(name, meta)
        }
    }

    struct FailingWriter {
        calls: AtomicUsize,
        fail: usize,
    }
    impl FileWriter for FailingWriter {
        fn write(
            &self,
            target: &AnchoredTarget,
            expected: Option<&AnchoredRead>,
            content: &[u8],
            permissions: AnchoredFilePermissions,
        ) -> std::io::Result<AnchoredEffect<AnchoredRead>> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call == self.fail {
                Err(std::io::Error::other("injected write failure"))
            } else {
                target.replace_if_exact_with_permissions(expected, content, permissions)
            }
        }
    }

    struct WriteThenFail;
    impl FileWriter for WriteThenFail {
        fn write(
            &self,
            target: &AnchoredTarget,
            expected: Option<&AnchoredRead>,
            content: &[u8],
            permissions: AnchoredFilePermissions,
        ) -> std::io::Result<AnchoredEffect<AnchoredRead>> {
            let value =
                match target.replace_if_exact_with_permissions(expected, content, permissions)? {
                    AnchoredEffect::Durable(value)
                    | AnchoredEffect::CommittedButUncertain { value, .. } => value,
                };
            Ok(AnchoredEffect::CommittedButUncertain {
                value,
                error: std::io::Error::other("ambiguous write result"),
            })
        }
    }

    struct ConcurrentWriter;
    impl FileWriter for ConcurrentWriter {
        fn write(
            &self,
            target: &AnchoredTarget,
            expected: Option<&AnchoredRead>,
            _content: &[u8],
            permissions: AnchoredFilePermissions,
        ) -> std::io::Result<AnchoredEffect<AnchoredRead>> {
            let _ = target.replace_if_exact_with_permissions(
                expected,
                b"CONCURRENT=owner\n",
                permissions,
            )?;
            Err(std::io::Error::other("connection lost after write"))
        }
    }

    #[cfg(unix)]
    struct SwapRootBeforeWrite {
        original: PathBuf,
        moved: PathBuf,
    }

    #[cfg(unix)]
    impl FileWriter for SwapRootBeforeWrite {
        fn write(
            &self,
            target: &AnchoredTarget,
            expected: Option<&AnchoredRead>,
            content: &[u8],
            permissions: AnchoredFilePermissions,
        ) -> std::io::Result<AnchoredEffect<AnchoredRead>> {
            std::fs::rename(&self.original, &self.moved)?;
            std::fs::create_dir(&self.original)?;
            std::fs::write(self.original.join("state"), b"decoy")?;
            target.replace_if_exact_with_permissions(expected, content, permissions)
        }
    }

    #[cfg(unix)]
    struct SwapAfterFirstThenFailSecond {
        calls: AtomicUsize,
        original: PathBuf,
        moved: PathBuf,
    }

    #[cfg(unix)]
    impl FileWriter for SwapAfterFirstThenFailSecond {
        fn write(
            &self,
            target: &AnchoredTarget,
            expected: Option<&AnchoredRead>,
            content: &[u8],
            permissions: AnchoredFilePermissions,
        ) -> std::io::Result<AnchoredEffect<AnchoredRead>> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call == 1 {
                let effect =
                    target.replace_if_exact_with_permissions(expected, content, permissions)?;
                std::fs::rename(&self.original, &self.moved)?;
                std::fs::create_dir(&self.original)?;
                std::fs::write(self.original.join("first"), b"decoy-first")?;
                std::fs::write(self.original.join("second"), b"decoy-second")?;
                Ok(effect)
            } else {
                Err(std::io::Error::other("injected second write failure"))
            }
        }
    }

    fn vault(dir: &TempDir) -> FileVault {
        FileVault::new(
            &dir.path().canonicalize().unwrap(),
            "init-test",
            "passphrase".to_string(),
        )
        .unwrap()
    }

    #[test]
    fn unreceipted_directory_effect_forces_incomplete_rollback() {
        let mut created = BTreeMap::new();
        let mut unresolved = false;
        let error = record_directory_creation(
            Path::new("nested"),
            AnchoredDirectoryCreation::CommittedButUncertain {
                receipt: None,
                error: std::io::Error::other("injected post-create uncertainty"),
            },
            &mut created,
            &mut unresolved,
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("injected post-create uncertainty"));
        assert!(unresolved);
        assert!(created.is_empty());
        assert!(!rollback_directories(created, unresolved));
    }

    #[test]
    fn windows_directory_rollback_closes_no_delete_handles_first() {
        let source = include_str!("init_transaction.rs");
        let rollback = source
            .find("let files_ok = rollback_files(&mut file_snapshots);")
            .expect("file rollback must run first");
        let release = source[rollback..]
            .find("release_file_capabilities(&mut file_snapshots);")
            .map(|offset| rollback + offset)
            .expect("retained file capabilities must be released");
        let directories = source[release..]
            .find("rollback_directories(created_directories")
            .map(|offset| release + offset)
            .expect("directory rollback must run after handle release");
        assert!(rollback < release && release < directories);

        let core_source = include_str!("../../phantom-core/src/fs/anchored.rs");
        assert!(core_source.contains("Intentionally omit FILE_SHARE_DELETE"));
    }

    #[test]
    fn outside_project_file_is_rejected_without_effect() {
        let project = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let target = outside.path().join("owner");
        std::fs::write(&target, b"preserve").unwrap();
        let vault_dir = TempDir::new().unwrap();
        let vault = vault(&vault_dir);

        let error = commit_init(
            project.path(),
            &vault,
            Vec::new(),
            vec![InitFile::replace(&target, b"overwrite".to_vec())],
        )
        .unwrap_err();

        assert!(matches!(error, InitTransactionError::Preflight { .. }));
        assert!(error.to_string().contains("outside canonical project root"));
        assert_eq!(std::fs::read(target).unwrap(), b"preserve");
    }

    #[test]
    fn shared_created_parent_is_rolled_back_once() {
        let project = TempDir::new().unwrap();
        let vault_dir = TempDir::new().unwrap();
        let vault = vault(&vault_dir);
        let writer = FailingWriter {
            calls: AtomicUsize::new(0),
            fail: 2,
        };

        let error = commit_init_with(
            project.path(),
            &vault,
            Vec::new(),
            vec![
                InitFile::replace(project.path().join("nested/first"), b"first".to_vec()),
                InitFile::replace(project.path().join("nested/second"), b"second".to_vec()),
            ],
            &writer,
        )
        .unwrap_err();

        assert!(matches!(error, InitTransactionError::Commit { .. }));
        assert!(!project.path().join("nested").exists());
    }

    #[cfg(unix)]
    #[test]
    fn root_swap_between_snapshot_and_commit_never_touches_decoy() {
        let container = TempDir::new().unwrap();
        let original = container.path().join("project");
        let moved = container.path().join("moved");
        std::fs::create_dir(&original).unwrap();
        std::fs::write(original.join("state"), b"before").unwrap();
        let vault_dir = TempDir::new().unwrap();
        let vault = vault(&vault_dir);

        commit_init_with(
            &original,
            &vault,
            Vec::new(),
            vec![InitFile::replace(
                original.join("state"),
                b"committed".to_vec(),
            )],
            &SwapRootBeforeWrite {
                original: original.clone(),
                moved: moved.clone(),
            },
        )
        .unwrap();

        assert_eq!(std::fs::read(moved.join("state")).unwrap(), b"committed");
        assert_eq!(std::fs::read(original.join("state")).unwrap(), b"decoy");
    }

    #[cfg(unix)]
    #[test]
    fn rollback_after_root_swap_restores_retained_tree_and_preserves_decoy() {
        let container = TempDir::new().unwrap();
        let original = container.path().join("project");
        let moved = container.path().join("moved");
        std::fs::create_dir(&original).unwrap();
        std::fs::write(original.join("first"), b"before-first").unwrap();
        std::fs::write(original.join("second"), b"before-second").unwrap();
        let vault_dir = TempDir::new().unwrap();
        let vault = vault(&vault_dir);

        let error = commit_init_with(
            &original,
            &vault,
            Vec::new(),
            vec![
                InitFile::replace(original.join("first"), b"after-first".to_vec()),
                InitFile::replace(original.join("second"), b"after-second".to_vec()),
            ],
            &SwapAfterFirstThenFailSecond {
                calls: AtomicUsize::new(0),
                original: original.clone(),
                moved: moved.clone(),
            },
        )
        .unwrap_err();

        assert!(matches!(error, InitTransactionError::Commit { .. }));
        assert_eq!(std::fs::read(moved.join("first")).unwrap(), b"before-first");
        assert_eq!(
            std::fs::read(moved.join("second")).unwrap(),
            b"before-second"
        );
        assert_eq!(
            std::fs::read(original.join("first")).unwrap(),
            b"decoy-first"
        );
        assert_eq!(
            std::fs::read(original.join("second")).unwrap(),
            b"decoy-second"
        );
    }

    #[test]
    fn nth_vault_store_failure_restores_existing_and_deletes_new_entries() {
        let dir = TempDir::new().unwrap();
        let env = dir.path().join(".env");
        std::fs::write(&env, b"A=old\nB=plain\n").unwrap();
        let inner = vault(&dir);
        inner.store("A", "prior").unwrap();
        let prior_metadata = inner.get_metadata("A").unwrap();
        let prior_validation = inner.get_validation_metadata("A").unwrap();
        let failing = FailingVault {
            inner,
            stores: AtomicUsize::new(0),
            fail_store: 2,
        };
        let error = commit_init(
            dir.path(),
            &failing,
            vec![InitSecret::new("A", "new-a"), InitSecret::new("B", "new-b")],
            vec![InitFile::replace(&env, b"A=phm_a\nB=phm_b\n".to_vec())],
        )
        .unwrap_err();
        assert!(
            matches!(error, InitTransactionError::Commit { .. }),
            "unexpected error: {error:?}"
        );
        assert_eq!(failing.retrieve("A").unwrap().as_str(), "prior");
        assert_eq!(failing.get_metadata("A").unwrap(), prior_metadata);
        assert_eq!(
            failing.get_validation_metadata("A").unwrap(),
            prior_validation
        );
        assert!(!failing.exists("B").unwrap());
        assert_eq!(std::fs::read(&env).unwrap(), b"A=old\nB=plain\n");
    }

    #[test]
    fn every_file_boundary_rolls_back_vault_and_prior_files() {
        for fail in 1..=5 {
            let dir = TempDir::new().unwrap();
            let paths = [
                dir.path().join(".env"),
                dir.path().join(".phantom.toml"),
                dir.path().join(".env.example"),
                dir.path().join("hooks/pre-commit"),
                dir.path().join("CLAUDE.md"),
            ];
            std::fs::write(&paths[0], b"KEY=plain\n").unwrap();
            let vault = vault(&dir);
            let writer = FailingWriter {
                calls: AtomicUsize::new(0),
                fail,
            };
            let error = commit_init_with(
                dir.path(),
                &vault,
                vec![InitSecret::new("KEY", "plain")],
                vec![
                    InitFile::replace(&paths[0], b"KEY=phm_token\n".to_vec()).commit_last(),
                    InitFile::replace(&paths[1], b"[phantom]\n".to_vec()),
                    InitFile::replace(&paths[2], b"KEY=\n".to_vec()),
                    InitFile::replace(&paths[3], b"#!/bin/sh\nphantom check\n".to_vec())
                        .executable(true),
                    InitFile::replace(&paths[4], b"# Guidance\n".to_vec()),
                ],
                &writer,
            )
            .unwrap_err();
            assert!(matches!(error, InitTransactionError::Commit { .. }));
            assert!(!vault.exists("KEY").unwrap());
            assert_eq!(std::fs::read(&paths[0]).unwrap(), b"KEY=plain\n");
            for path in &paths[1..] {
                assert!(!path.exists(), "{} survived rollback", path.display());
            }
            assert!(!dir.path().join("hooks").exists());
        }
    }

    #[test]
    fn success_is_retry_idempotent_and_debug_output_is_value_free() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join(".env");
        std::fs::write(&file, b"KEY=plain-secret-value\n").unwrap();
        let vault = vault(&dir);
        let run = || {
            commit_init(
                dir.path(),
                &vault,
                vec![InitSecret::new("KEY", "plain-secret-value")],
                vec![InitFile::replace(&file, b"KEY=phm_token\n".to_vec())],
            )
        };
        run().unwrap();
        run().unwrap();
        assert_eq!(
            vault.retrieve("KEY").unwrap().as_str(),
            "plain-secret-value"
        );
        assert_eq!(std::fs::read(&file).unwrap(), b"KEY=phm_token\n");
        let debug = format!("{:?}", InitSecret::new("KEY", "plain-secret-value"));
        assert!(!debug.contains("plain-secret-value"));
    }

    #[test]
    fn exact_absent_before_image_never_overwrites_a_concurrent_create() {
        let dir = TempDir::new().unwrap();
        let vault = vault(&dir);
        // The caller reviewed an absent destination, then another writer
        // created it before this transaction acquired the project lock.
        vault.store("TARGET", "concurrent-owner").unwrap();

        let error = commit_init(
            dir.path(),
            &vault,
            vec![InitSecret::replace_if_unchanged(
                "TARGET",
                None::<String>,
                "imported-value",
            )],
            Vec::new(),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            InitTransactionError::ConcurrentChange { .. }
        ));
        assert_eq!(
            vault.retrieve("TARGET").unwrap().as_str(),
            "concurrent-owner"
        );
    }

    #[test]
    fn exact_transactions_roll_back_prior_creates_when_a_later_cas_fails() {
        let dir = TempDir::new().unwrap();
        let failing = FailingVault {
            inner: vault(&dir),
            stores: AtomicUsize::new(0),
            fail_store: 2,
        };

        let error = commit_init(
            dir.path(),
            &failing,
            vec![
                InitSecret::replace_if_unchanged("A", None::<String>, "one"),
                InitSecret::replace_if_unchanged("B", None::<String>, "two"),
            ],
            Vec::new(),
        )
        .unwrap_err();

        assert!(matches!(error, InitTransactionError::Commit { .. }));
        assert!(!failing.exists("A").unwrap());
        assert!(!failing.exists("B").unwrap());
    }

    #[test]
    fn exact_transaction_rolls_back_vault_when_final_file_write_fails() {
        let dir = TempDir::new().unwrap();
        let env = dir.path().join(".env");
        std::fs::write(&env, b"BEFORE=reviewed\n").unwrap();
        let vault = vault(&dir);
        let writer = FailingWriter {
            calls: AtomicUsize::new(0),
            fail: 1,
        };

        let error = commit_init_with(
            dir.path(),
            &vault,
            vec![InitSecret::replace_if_unchanged(
                "TARGET",
                None::<String>,
                "provider-value",
            )],
            vec![InitFile::replace_if_unchanged(
                &env,
                Some(b"BEFORE=reviewed\n".to_vec()),
                b"TARGET=phm_token\n".to_vec(),
            )
            .commit_last()],
            &writer,
        )
        .unwrap_err();

        assert!(matches!(error, InitTransactionError::Commit { .. }));
        assert!(!vault.exists("TARGET").unwrap());
        assert_eq!(std::fs::read(&env).unwrap(), b"BEFORE=reviewed\n");
    }

    #[test]
    fn exact_file_before_image_rejects_concurrent_replacement_without_vault_changes() {
        let dir = TempDir::new().unwrap();
        let env = dir.path().join(".env");
        std::fs::write(&env, b"BEFORE=reviewed\n").unwrap();
        let vault = vault(&dir);
        std::fs::write(&env, b"OWNER=concurrent\n").unwrap();

        let error = commit_init(
            dir.path(),
            &vault,
            vec![InitSecret::replace_if_unchanged(
                "TARGET",
                None::<String>,
                "imported-value",
            )],
            vec![InitFile::replace_if_unchanged(
                &env,
                Some(b"BEFORE=reviewed\n".to_vec()),
                b"TARGET=phm_token\n".to_vec(),
            )],
        )
        .unwrap_err();

        assert!(matches!(
            error,
            InitTransactionError::ConcurrentChange { .. }
        ));
        assert!(!vault.exists("TARGET").unwrap());
        assert_eq!(std::fs::read(&env).unwrap(), b"OWNER=concurrent\n");
    }

    #[test]
    fn delete_rollback_restores_value_and_exact_metadata_after_late_file_failure() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(&dir);
        vault.store("A", "one").unwrap();
        let mut metadata = vault.get_metadata("A").unwrap().unwrap();
        metadata.expires_at = Some(42);
        vault.set_metadata("A", metadata.clone()).unwrap();
        let validation = ValidationMetadata::mark_valid("test");
        vault
            .set_validation_metadata("A", validation.clone())
            .unwrap();
        let target = dir.path().join("managed.env");
        phantom_core::fs::atomic_write(&target, b"A=phm_before\n").unwrap();

        let error = commit_init_with(
            dir.path(),
            &vault,
            vec![InitSecret::delete_if_unchanged("A", "one")],
            vec![InitFile::replace_if_unchanged(
                &target,
                Some(b"A=phm_before\n".to_vec()),
                b"".to_vec(),
            )
            .commit_last()],
            &FailingWriter {
                calls: AtomicUsize::new(0),
                fail: 1,
            },
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                InitTransactionError::Commit { .. }
                    | InitTransactionError::RollbackIncomplete { .. }
            ),
            "unexpected delete rollback error: {error:?}"
        );
        assert_eq!(vault.retrieve("A").unwrap().as_str(), "one");
        assert_eq!(vault.get_metadata("A").unwrap(), Some(metadata));
        assert_eq!(
            vault.get_validation_metadata_exact("A").unwrap(),
            Some(validation)
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"A=phm_before\n");
    }

    #[test]
    fn ambiguous_successful_write_is_detected_and_restored() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join(".env");
        std::fs::write(&file, b"KEY=plain\n").unwrap();
        let vault = vault(&dir);

        let error = commit_init_with(
            dir.path(),
            &vault,
            vec![InitSecret::new("KEY", "plain")],
            vec![InitFile::replace(&file, b"KEY=phm_token\n".to_vec())],
            &WriteThenFail,
        )
        .unwrap_err();

        assert!(matches!(error, InitTransactionError::Commit { .. }));
        assert_eq!(std::fs::read(&file).unwrap(), b"KEY=plain\n");
        assert!(!vault.exists("KEY").unwrap());
    }

    #[test]
    fn ambiguous_concurrent_file_is_never_overwritten_by_rollback() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join(".env");
        std::fs::write(&file, b"KEY=plain\n").unwrap();
        let vault = vault(&dir);

        let error = commit_init_with(
            dir.path(),
            &vault,
            vec![InitSecret::new("KEY", "plain")],
            vec![InitFile::replace(&file, b"KEY=phm_token\n".to_vec())],
            &ConcurrentWriter,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            InitTransactionError::RollbackIncomplete { .. }
        ));
        assert_eq!(std::fs::read(&file).unwrap(), b"CONCURRENT=owner\n");
        assert!(!vault.exists("KEY").unwrap());
    }
}
