//! Recoverable initialization across vault entries and project files.
//!
//! Initialization cannot rely on a sequence of independent `store` and
//! `write` calls: a later failure would otherwise leave an environment file
//! tokenized without its vault entries, or overwrite an existing credential.
//! This module snapshots every target in memory, uses atomic file replacement,
//! verifies compare-and-swap preconditions, and restores only state written by
//! this transaction. Secret values are never serialized or formatted.

use crate::{SecretMetadata, VaultBackend};
use phantom_core::error::PhantomError;
use phantom_core::validator::ValidationMetadata;
use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

pub struct InitSecret {
    name: String,
    value: Zeroizing<String>,
}

impl InitSecret {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: Zeroizing::new(value.into()),
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
    executable: bool,
}

impl InitFile {
    pub fn replace(path: impl Into<PathBuf>, content: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            content: Zeroizing::new(content.into()),
            executable: false,
        }
    }

    pub fn executable(mut self, executable: bool) -> Self {
        self.executable = executable;
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
    touched: bool,
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
/// on any observable failure. Files and vault entries are guarded by
/// compare-and-swap checks so rollback never overwrites unrelated concurrent
/// changes.
pub fn commit_init(
    vault: &dyn VaultBackend,
    secrets: Vec<InitSecret>,
    files: Vec<InitFile>,
) -> Result<InitReceipt, InitTransactionError> {
    commit_init_with(vault, secrets, files, &AtomicFileWriter)
}

fn commit_init_with(
    vault: &dyn VaultBackend,
    mut secrets: Vec<InitSecret>,
    mut files: Vec<InitFile>,
    writer: &dyn FileWriter,
) -> Result<InitReceipt, InitTransactionError> {
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
        preflight_path(&file.path)?;
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
        file_snapshots.push(FileSnapshot {
            path: file.path,
            before,
            permissions,
            after: std::mem::take(&mut file.content),
            executable: file.executable,
            touched: false,
        });
    }

    let commit_result = (|| {
        for snapshot in &mut secret_snapshots {
            ensure_secret_state(vault, snapshot, false)
                .map_err(|error| (snapshot.name.clone(), error.to_string()))?;
            match vault.store(&snapshot.name, snapshot.after.as_str()) {
                Ok(()) => snapshot.touched = true,
                Err(error) => {
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
                    return Err((snapshot.name.clone(), error.to_string()));
                }
            }
            ensure_secret_state(vault, snapshot, true)
                .map_err(|error| (snapshot.name.clone(), error.to_string()))?;
        }

        for snapshot in &mut file_snapshots {
            ensure_file_state(snapshot, false)
                .map_err(|error| (snapshot.path.display().to_string(), error.to_string()))?;
            if let Err(error) = writer.write(&snapshot.path, snapshot.after.as_slice()) {
                let current_is_after =
                    file_matches(&snapshot.path, Some(snapshot.after.as_slice()));
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
                .map_err(|error| (snapshot.path.display().to_string(), error.to_string()))?;
        }
        Ok::<(), (String, String)>(())
    })();

    if let Err((target, reason)) = commit_result {
        let files_ok = rollback_files(&mut file_snapshots, writer);
        let vault_ok = rollback_secrets(vault, &mut secret_snapshots);
        return if files_ok && vault_ok {
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

fn preflight_vault(name: &str, error: PhantomError) -> InitTransactionError {
    InitTransactionError::Preflight {
        target: name.to_string(),
        reason: error.to_string(),
    }
}

fn preflight_path(path: &Path) -> Result<(), InitTransactionError> {
    let parent = path
        .parent()
        .ok_or_else(|| InitTransactionError::Preflight {
            target: path.display().to_string(),
            reason: "target has no parent directory".to_string(),
        })?;
    let parent_metadata =
        std::fs::symlink_metadata(parent).map_err(|error| InitTransactionError::Preflight {
            target: path.display().to_string(),
            reason: error.to_string(),
        })?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(InitTransactionError::Preflight {
            target: path.display().to_string(),
            reason: "parent must be a real directory".to_string(),
        });
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(InitTransactionError::Preflight {
                target: path.display().to_string(),
                reason: "target must be a regular file or absent".to_string(),
            })
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(InitTransactionError::Preflight {
            target: path.display().to_string(),
            reason: error.to_string(),
        }),
    }
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
        Err(error) => {
            return Err(InitTransactionError::Preflight {
                target: snapshot.name.clone(),
                reason: error.to_string(),
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

fn rollback_secrets(vault: &dyn VaultBackend, snapshots: &mut [SecretSnapshot]) -> bool {
    let mut ok = true;
    for snapshot in snapshots
        .iter_mut()
        .rev()
        .filter(|snapshot| snapshot.touched)
    {
        let current_is_after = vault
            .retrieve(&snapshot.name)
            .map(|value| value.as_str() == snapshot.after.as_str())
            .unwrap_or(false);
        if !current_is_after {
            ok = false;
            continue;
        }
        let result = match &snapshot.before {
            Some(before) => vault.store(&snapshot.name, before.as_str()).and_then(|_| {
                if let Some(metadata) = &snapshot.metadata {
                    vault.set_metadata(&snapshot.name, metadata.clone())?;
                }
                vault.set_validation_metadata(&snapshot.name, snapshot.validation.clone())
            }),
            None => vault.delete(&snapshot.name),
        };
        if result.is_err() {
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
        let failing = FailingVault {
            inner,
            stores: AtomicUsize::new(0),
            fail_store: 2,
        };
        let error = commit_init(
            &failing,
            vec![InitSecret::new("A", "new-a"), InitSecret::new("B", "new-b")],
            vec![InitFile::replace(&env, b"A=phm_a\nB=phm_b\n".to_vec())],
        )
        .unwrap_err();
        assert!(matches!(error, InitTransactionError::Commit { .. }));
        assert_eq!(failing.retrieve("A").unwrap().as_str(), "prior");
        assert!(!failing.exists("B").unwrap());
        assert_eq!(std::fs::read(&env).unwrap(), b"A=old\nB=plain\n");
    }

    #[test]
    fn every_file_boundary_rolls_back_vault_and_prior_files() {
        for fail in 1..=2 {
            let dir = TempDir::new().unwrap();
            let first = dir.path().join(".env");
            let second = dir.path().join(".phantom.toml");
            std::fs::write(&first, b"KEY=plain\n").unwrap();
            let vault = vault(&dir);
            let writer = FailingWriter {
                calls: AtomicUsize::new(0),
                fail,
            };
            let error = commit_init_with(
                &vault,
                vec![InitSecret::new("KEY", "plain")],
                vec![
                    InitFile::replace(&first, b"KEY=phm_token\n".to_vec()),
                    InitFile::replace(&second, b"[phantom]\n".to_vec()),
                ],
                &writer,
            )
            .unwrap_err();
            assert!(matches!(error, InitTransactionError::Commit { .. }));
            assert!(!vault.exists("KEY").unwrap());
            assert_eq!(std::fs::read(&first).unwrap(), b"KEY=plain\n");
            assert!(!second.exists());
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
    fn ambiguous_successful_write_is_detected_and_restored() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join(".env");
        std::fs::write(&file, b"KEY=plain\n").unwrap();
        let vault = vault(&dir);

        let error = commit_init_with(
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
