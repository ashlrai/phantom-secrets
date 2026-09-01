//! Cooperative project transaction serialization for Phantom writers.
//!
//! The OS releases the advisory lock if a process crashes. This is not a data
//! durability primitive and does not fsync transaction payloads. On Windows the
//! lock directory inherits its surrounding ACL; this module does not claim that
//! the ACL is user-only, so same-user or otherwise-authorized processes remain
//! outside the coordination guarantee.

use phantom_core::error::{PhantomError, Result};
use sha2::{Digest, Sha256};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

const PROCESS_LOCK_SHARDS: usize = 64;

/// An advisory project lock shared by init and token-remap transactions.
/// Keeping the guard alive spans snapshot, commit, verification, and rollback.
pub struct ProjectTransactionLock {
    _process: MutexGuard<'static, ()>,
    _file: std::fs::File,
}

fn process_lock_for(identity: &Path) -> MutexGuard<'static, ()> {
    static LOCKS: OnceLock<Vec<Mutex<()>>> = OnceLock::new();
    let locks = LOCKS.get_or_init(|| (0..PROCESS_LOCK_SHARDS).map(|_| Mutex::new(())).collect());
    let mut hasher = DefaultHasher::new();
    identity.hash(&mut hasher);
    let index = hasher.finish() as usize % locks.len();
    locks[index]
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn lock_anchor() -> PathBuf {
    // ProjectDirs and home_dir consult process-wide environment state. Tests in
    // other Phantom crates temporarily override HOME, so take the same shared
    // mutex they use while resolving the complete root. The guard is released
    // before any filesystem or transaction lock is acquired, avoiding lock
    // order inversions with callers that later enter a project transaction.
    let _environment = phantom_core::PROCESS_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    directories::ProjectDirs::from("ai", "phantom", "phantom-secrets")
        .map(|dirs| dirs.data_dir().to_path_buf())
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(std::env::temp_dir)
                .join(".phantom")
        })
}

fn lock_path_at(project_dir: &Path, anchor: &Path) -> Result<(PathBuf, PathBuf, PathBuf)> {
    let canonical = project_dir.canonicalize().map_err(|error| {
        PhantomError::VaultError(format!(
            "Cannot resolve project directory {} for transaction locking: {error}",
            project_dir.display()
        ))
    })?;
    if !canonical.is_dir() {
        return Err(PhantomError::VaultError(format!(
            "Transaction lock root is not a directory: {}",
            canonical.display()
        )));
    }
    let mut digest = Sha256::new();
    digest.update(canonical.as_os_str().to_string_lossy().as_bytes());
    let name = hex::encode(digest.finalize());
    Ok((
        canonical,
        anchor.to_path_buf(),
        Path::new("transaction-locks").join(format!("{name}.lock")),
    ))
}

fn lock_path(project_dir: &Path) -> Result<(PathBuf, PathBuf, PathBuf)> {
    lock_path_at(project_dir, &lock_anchor())
}

/// Acquire the process-local and cross-process lock for one canonical project.
pub fn acquire_project_transaction_lock(project_dir: &Path) -> Result<ProjectTransactionLock> {
    let (identity, anchor, relative_path) = lock_path(project_dir)?;
    acquire_project_transaction_lock_at(identity, anchor, relative_path)
}

fn acquire_project_transaction_lock_at(
    identity: PathBuf,
    anchor: PathBuf,
    relative_path: PathBuf,
) -> Result<ProjectTransactionLock> {
    let process = process_lock_for(&identity);
    let file = crate::lock_file::acquire_exclusive_lock_file(
        &anchor,
        &relative_path,
        "project transaction lock",
        true,
    )?;
    Ok(ProjectTransactionLock {
        _process: process,
        _file: file,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use tempfile::tempdir;

    #[test]
    fn project_transaction_lock_serializes_threads() {
        let project = tempdir().unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let path = project.path().to_path_buf();
            let barrier = Arc::clone(&barrier);
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                let _lock = acquire_project_transaction_lock(&path).unwrap();
                let now = active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                peak.fetch_max(now, std::sync::atomic::Ordering::SeqCst);
                std::thread::yield_now();
                active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(peak.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn windows_lock_contract_opens_reparse_point_and_checks_handle_identity() {
        let source = include_str!("lock_file.rs");
        assert!(source.contains("FILE_FLAG_OPEN_REPARSE_POINT"));
        assert!(source.contains("FILE_ATTRIBUTE_REPARSE_POINT"));
        assert!(source.contains("GetFileInformationByHandle"));
        assert!(source.contains("dwVolumeSerialNumber"));
        assert!(source.contains("nFileIndexHigh"));
        assert!(source.contains("nFileIndexLow"));
        assert!(source.contains("nNumberOfLinks"));
        assert!(source.contains("file_attributes"));
        let transaction_source = include_str!("transaction_lock.rs");
        assert!(transaction_source.contains("crate::lock_file::acquire_exclusive_lock_file"));
        assert!(transaction_source.contains("project transaction lock"));
        assert!(transaction_source.contains("true"));
        let source = include_str!("transaction_lock.rs");
        assert!(source.contains("does not claim that\n//! the ACL is user-only"));
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_lock_root_symlink_is_rejected_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let project = tempdir().unwrap();
        let container = tempdir().unwrap();
        let owner = container.path().join("owner-state");
        std::fs::create_dir(&owner).unwrap();
        let sentinel = owner.join("sentinel");
        std::fs::write(&sentinel, b"owner-state").unwrap();
        let anchor = container.path().canonicalize().unwrap();
        let redirected = anchor.join("transaction-locks");
        symlink(&owner, &redirected).unwrap();
        let (identity, anchor, relative_path) = lock_path_at(project.path(), &anchor).unwrap();

        let error = acquire_project_transaction_lock_at(identity, anchor, relative_path)
            .err()
            .expect("symlinked lock root must be rejected");
        assert!(error.to_string().contains("ancestor"));
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"owner-state");
        assert_eq!(std::fs::read_dir(&owner).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_symlink_is_rejected_without_overwriting_owner_state() {
        use std::os::unix::fs::symlink;

        let project = tempdir().unwrap();
        let lock_root = tempdir().unwrap();
        let root = lock_root.path().canonicalize().unwrap();
        let victim = root.join("owner-state");
        std::fs::write(&victim, b"preserve").unwrap();
        let (identity, anchor, relative_path) = lock_path_at(project.path(), &root).unwrap();
        std::fs::create_dir(root.join("transaction-locks")).unwrap();
        let path = root.join(&relative_path);
        symlink(&victim, &path).unwrap();

        assert!(acquire_project_transaction_lock_at(identity, anchor, relative_path).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"preserve");
    }

    #[cfg(unix)]
    #[test]
    fn hardlinked_lock_file_is_rejected_without_chmod_or_overwrite() {
        use std::os::unix::fs::PermissionsExt;

        let project = tempdir().unwrap();
        let lock_root = tempdir().unwrap();
        let root = lock_root.path().canonicalize().unwrap();
        let victim = root.join("owner-state");
        std::fs::write(&victim, b"preserve").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o640)).unwrap();
        let (identity, anchor, relative_path) = lock_path_at(project.path(), &root).unwrap();
        std::fs::create_dir(root.join("transaction-locks")).unwrap();
        let path = root.join(&relative_path);
        std::fs::hard_link(&victim, &path).unwrap();

        assert!(acquire_project_transaction_lock_at(identity, anchor, relative_path).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"preserve");
        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }
}
