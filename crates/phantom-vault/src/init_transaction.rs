//! Recoverable initialization across vault entries and project files.
//!
//! Initialization cannot rely on a sequence of independent `store` and
//! `write` calls: a later failure would otherwise leave an environment file
//! tokenized without its vault entries, or overwrite an existing credential.
//! This module snapshots every target in memory, uses atomic file replacement,
//! verifies before-images immediately before and after writes, and restores only
//! state written by this transaction. The project lock coordinates Phantom
//! writers. An uncooperative same-user process can still replace a pathname in
//! the interval between verification and rename; post-write verification detects
//! observable interference but is not an OS-level filesystem CAS. Secret values
//! are never serialized or formatted.

use crate::{acquire_project_transaction_lock, SecretMetadata, VaultBackend};
use phantom_core::error::PhantomError;
use phantom_core::validator::ValidationMetadata;
use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

pub struct InitSecret {
    name: String,
    value: Zeroizing<String>,
    expected_before: Option<Option<Zeroizing<String>>>,
}

impl InitSecret {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: Zeroizing::new(value.into()),
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
            value: Zeroizing::new(value.into()),
            expected_before: Some(expected_before.map(|value| Zeroizing::new(value.into()))),
        }
    }
}

impl fmt::Debug for InitSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InitSecret")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
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
    validation: ValidationMetadata,
    after: Zeroizing<String>,
    touched: bool,
}

struct FileSnapshot {
    path: PathBuf,
    before: Option<Zeroizing<Vec<u8>>>,
    permissions: Option<std::fs::Permissions>,
    after: Zeroizing<Vec<u8>>,
    executable: bool,
    commit_last: bool,
    touched: bool,
    created_parents: Vec<PathBuf>,
}

trait FileWriter {
    fn write(&self, path: &Path, content: &[u8]) -> std::io::Result<()>;
}

struct AtomicFileWriter;

impl FileWriter for AtomicFileWriter {
    fn write(&self, path: &Path, content: &[u8]) -> std::io::Result<()> {
        phantom_core::fs::atomic_write(path, content)
    }
}

/// Commit a complete initialization plan, restoring its exact before-images
/// on any observable failure. Vault entries use backend atomic CAS. Files use
/// the cooperative project lock plus before/after verification; rollback only
/// restores a file while it still equals the transaction's exact after-image.
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
    let _transaction_lock = acquire_project_transaction_lock(project_dir).map_err(|error| {
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
        if !paths.insert(file.path.clone()) {
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
            .get_validation_metadata(&secret.name)
            .map_err(|error| preflight_vault(&secret.name, error))?;
        secret_snapshots.push(SecretSnapshot {
            name: secret.name,
            before,
            metadata,
            validation,
            after: secret.value,
            touched: false,
        });
    }

    let mut file_snapshots = Vec::with_capacity(files.len());
    for mut file in files.drain(..) {
        let created_parents = preflight_path(&file.path)?;
        let (before, permissions) = match std::fs::symlink_metadata(&file.path) {
            Ok(metadata) => (
                Some(Zeroizing::new(std::fs::read(&file.path).map_err(
                    |error| InitTransactionError::Preflight {
                        target: file.path.display().to_string(),
                        reason: error.to_string(),
                    },
                )?)),
                Some(metadata.permissions()),
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (None, None),
            Err(error) => {
                return Err(InitTransactionError::Preflight {
                    target: file.path.display().to_string(),
                    reason: error.to_string(),
                });
            }
        };
        if let Some(expected_before) = file.expected_before.as_ref() {
            let matches = before.as_ref().map(|value| value.as_slice())
                == expected_before.as_ref().map(|value| value.as_slice());
            if !matches {
                return Err(InitTransactionError::ConcurrentChange {
                    target: file.path.display().to_string(),
                });
            }
        }
        file_snapshots.push(FileSnapshot {
            path: file.path,
            before,
            permissions,
            after: std::mem::take(&mut file.content),
            executable: file.executable,
            commit_last: file.commit_last,
            touched: false,
            created_parents,
        });
    }

    let commit_result = (|| {
        for snapshot in file_snapshots
            .iter_mut()
            .filter(|snapshot| !snapshot.commit_last)
        {
            commit_file(snapshot, writer)?;
        }

        for snapshot in &mut secret_snapshots {
            let expected = snapshot.before.as_ref().map(|value| value.as_str());
            match vault.compare_and_swap(&snapshot.name, expected, Some(snapshot.after.as_str())) {
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
                    let current_is_after = vault
                        .retrieve(&snapshot.name)
                        .map(|current| current.as_str() == snapshot.after.as_str())
                        .unwrap_or(false);
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
            commit_file(snapshot, writer)?;
        }
        Ok::<(), (String, String)>(())
    })();

    if let Err((target, reason)) = commit_result {
        let files_ok = rollback_files(&mut file_snapshots, writer);
        let directories_ok = rollback_directories(&mut file_snapshots);
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
    for snapshot in &mut file_snapshots {
        if let Some(before) = snapshot.before.as_mut() {
            before.zeroize();
        }
    }
    Ok(receipt)
}

fn commit_file(
    snapshot: &mut FileSnapshot,
    writer: &dyn FileWriter,
) -> Result<(), (String, String)> {
    create_missing_parents(snapshot)
        .map_err(|error| (snapshot.path.display().to_string(), error.to_string()))?;
    ensure_file_state(snapshot, false)
        .map_err(|error| (snapshot.path.display().to_string(), error.to_string()))?;
    if let Err(error) = writer.write(&snapshot.path, snapshot.after.as_slice()) {
        let current_is_after = file_matches(&snapshot.path, Some(snapshot.after.as_slice()));
        let current_is_before = snapshot
            .before
            .as_ref()
            .map(|before| file_matches(&snapshot.path, Some(before.as_slice())))
            .unwrap_or_else(|| file_matches(&snapshot.path, None));
        snapshot.touched = current_is_after || !current_is_before;
        return Err((snapshot.path.display().to_string(), error.to_string()));
    }
    snapshot.touched = true;
    apply_permissions(snapshot)
        .map_err(|error| (snapshot.path.display().to_string(), error.to_string()))?;
    ensure_file_state(snapshot, true)
        .map_err(|error| (snapshot.path.display().to_string(), error.to_string()))
}

fn preflight_vault(name: &str, _error: PhantomError) -> InitTransactionError {
    InitTransactionError::Preflight {
        target: name.to_string(),
        reason: "vault snapshot failed".to_string(),
    }
}

fn preflight_path(path: &Path) -> Result<Vec<PathBuf>, InitTransactionError> {
    let parent = path
        .parent()
        .ok_or_else(|| InitTransactionError::Preflight {
            target: path.display().to_string(),
            reason: "target has no parent directory".to_string(),
        })?;
    let mut missing = Vec::new();
    let mut cursor = parent;
    loop {
        match std::fs::symlink_metadata(cursor) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(InitTransactionError::Preflight {
                    target: path.display().to_string(),
                    reason: "every parent must be a real directory".to_string(),
                });
            }
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(cursor.to_path_buf());
                cursor = cursor
                    .parent()
                    .ok_or_else(|| InitTransactionError::Preflight {
                        target: path.display().to_string(),
                        reason: "could not find an existing parent directory".to_string(),
                    })?;
            }
            Err(error) => {
                return Err(InitTransactionError::Preflight {
                    target: path.display().to_string(),
                    reason: error.to_string(),
                });
            }
        }
    }
    missing.reverse();
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(InitTransactionError::Preflight {
                target: path.display().to_string(),
                reason: "target must be a regular file or absent".to_string(),
            })
        }
        Ok(_) => Ok(missing),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(missing),
        Err(error) => Err(InitTransactionError::Preflight {
            target: path.display().to_string(),
            reason: error.to_string(),
        }),
    }
}

fn create_missing_parents(snapshot: &mut FileSnapshot) -> std::io::Result<()> {
    let planned = std::mem::take(&mut snapshot.created_parents);
    for path in planned {
        match std::fs::create_dir(&path) {
            Ok(()) => snapshot.created_parents.push(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = std::fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(std::io::Error::other(
                        "planned parent became an unsafe filesystem object",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn ensure_secret_state(
    vault: &dyn VaultBackend,
    snapshot: &SecretSnapshot,
    after: bool,
) -> Result<(), InitTransactionError> {
    let expected = if after {
        Some(snapshot.after.as_str())
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
    let validation_matches = vault.get_validation_metadata(&snapshot.name).map_err(|_| {
        InitTransactionError::Preflight {
            target: snapshot.name.clone(),
            reason: "vault validation metadata verification failed".to_string(),
        }
    })? == snapshot.validation;
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
        Some(snapshot.after.as_slice())
    } else {
        snapshot.before.as_ref().map(|value| value.as_slice())
    };
    if file_matches(&snapshot.path, expected) {
        Ok(())
    } else {
        Err(InitTransactionError::ConcurrentChange {
            target: snapshot.path.display().to_string(),
        })
    }
}

fn file_matches(path: &Path, expected: Option<&[u8]>) -> bool {
    match (std::fs::read(path), expected) {
        (Ok(current), Some(expected)) => current == expected,
        (Err(error), None) if error.kind() == std::io::ErrorKind::NotFound => true,
        _ => false,
    }
}

fn apply_permissions(snapshot: &FileSnapshot) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = if snapshot.executable {
            std::fs::Permissions::from_mode(0o755)
        } else if let Some(existing) = &snapshot.permissions {
            existing.clone()
        } else {
            std::fs::Permissions::from_mode(0o600)
        };
        std::fs::set_permissions(&snapshot.path, permissions)?;
    }
    #[cfg(not(unix))]
    if let Some(existing) = &snapshot.permissions {
        std::fs::set_permissions(&snapshot.path, existing.clone())?;
    }
    Ok(())
}

fn rollback_files(snapshots: &mut [FileSnapshot], writer: &dyn FileWriter) -> bool {
    let mut ok = true;
    for snapshot in snapshots
        .iter_mut()
        .rev()
        .filter(|snapshot| snapshot.touched)
    {
        if !file_matches(&snapshot.path, Some(snapshot.after.as_slice())) {
            ok = false;
            continue;
        }
        let restored = match &snapshot.before {
            Some(before) => {
                let write_result = writer.write(&snapshot.path, before.as_slice());
                if write_result.is_err() && !file_matches(&snapshot.path, Some(before.as_slice())) {
                    false
                } else if let Some(permissions) = &snapshot.permissions {
                    std::fs::set_permissions(&snapshot.path, permissions.clone()).is_ok()
                } else {
                    true
                }
            }
            None => match std::fs::remove_file(&snapshot.path) {
                Ok(()) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
                Err(_) => false,
            },
        };
        if !restored {
            ok = false;
        } else {
            snapshot.touched = false;
        }
    }
    ok
}

fn rollback_directories(snapshots: &mut [FileSnapshot]) -> bool {
    let mut directories = snapshots
        .iter_mut()
        .flat_map(|snapshot| snapshot.created_parents.drain(..))
        .collect::<Vec<_>>();
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    directories.dedup();
    let mut ok = true;
    for directory in directories {
        match std::fs::remove_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => ok = false,
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
        let result =
            vault.compare_and_swap(&snapshot.name, Some(snapshot.after.as_str()), replacement);
        if !matches!(result, Ok(true))
            || (snapshot.before.is_some() && ensure_secret_metadata(vault, snapshot).is_err())
        {
            ok = false;
        } else {
            snapshot.touched = false;
        }
    }
    ok
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
        fn write(&self, path: &Path, content: &[u8]) -> std::io::Result<()> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call == self.fail {
                Err(std::io::Error::other("injected write failure"))
            } else {
                phantom_core::fs::atomic_write(path, content)
            }
        }
    }

    struct WriteThenFail;
    impl FileWriter for WriteThenFail {
        fn write(&self, path: &Path, content: &[u8]) -> std::io::Result<()> {
            phantom_core::fs::atomic_write(path, content)?;
            Err(std::io::Error::other("ambiguous write result"))
        }
    }

    struct ConcurrentWriter;
    impl FileWriter for ConcurrentWriter {
        fn write(&self, path: &Path, _content: &[u8]) -> std::io::Result<()> {
            phantom_core::fs::atomic_write(path, b"CONCURRENT=owner\n")?;
            Err(std::io::Error::other("connection lost after write"))
        }
    }

    fn vault(dir: &TempDir) -> FileVault {
        FileVault::new(dir.path(), "init-test", "passphrase".to_string()).unwrap()
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
        assert!(matches!(error, InitTransactionError::Commit { .. }));
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
