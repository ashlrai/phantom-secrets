//! Cooperative project transaction serialization for Phantom writers.
//!
//! The OS releases the advisory lock if a process crashes. This is not a data
//! durability primitive and does not fsync transaction payloads. On Windows the
//! lock directory inherits its surrounding ACL; this module does not claim that
//! the ACL is user-only, so same-user or otherwise-authorized processes remain
//! outside the coordination guarantee. Current writers coordinate on a stable
//! direct child of the trusted app-data anchor and also take the historical
//! descendant lock as a one-release compatibility bridge.

use phantom_core::error::{PhantomError, Result};
use phantom_core::fs::{AnchoredLock, TrustedAnchor};
use sha2::{Digest, Sha256};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

const PROCESS_LOCK_SHARDS: usize = 64;

/// An advisory project lock shared by init and token-remap transactions.
/// Keeping the guard alive spans snapshot, commit, verification, and rollback.
pub struct ProjectTransactionLock {
    _process: MutexGuard<'static, ()>,
    _stable: AnchoredLock,
    _legacy: AnchoredLock,
}

struct ProjectLockPaths {
    identity: PathBuf,
    anchor: PathBuf,
    stable: PathBuf,
    legacy: PathBuf,
}

struct ProjectFilesystemLocks {
    stable: AnchoredLock,
    legacy: AnchoredLock,
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

fn lock_paths_at(project_dir: &Path, anchor: &Path) -> Result<ProjectLockPaths> {
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
    Ok(ProjectLockPaths {
        identity: canonical,
        anchor: anchor.to_path_buf(),
        stable: PathBuf::from(format!(".project-transaction-{name}.lock")),
        legacy: Path::new("transaction-locks").join(format!("{name}.lock")),
    })
}

fn lock_paths(project_dir: &Path) -> Result<ProjectLockPaths> {
    lock_paths_at(project_dir, &lock_anchor())
}

/// Acquire the process-local and cross-process lock for one canonical project.
pub fn acquire_project_transaction_lock(project_dir: &Path) -> Result<ProjectTransactionLock> {
    acquire_project_transaction_lock_at(lock_paths(project_dir)?)
}

fn open_lock_anchor(path: &Path) -> Result<TrustedAnchor> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|error| {
        PhantomError::VaultError(format!(
            "Cannot create trusted project-lock anchor {}: {error}",
            path.display()
        ))
    })?;
    TrustedAnchor::open_canonical_private(path).map_err(|error| {
        PhantomError::VaultError(format!(
            "Cannot retain trusted project-lock anchor {}: {error}",
            path.display()
        ))
    })
}

fn acquire_filesystem_locks(paths: &ProjectLockPaths) -> Result<ProjectFilesystemLocks> {
    let anchor = open_lock_anchor(&paths.anchor)?;

    // The direct-child lock is the durable coordination identity. Acquiring it
    // first means replacing the legacy descendant directory cannot split two
    // current Phantom writers into different lock domains.
    let stable = anchor.acquire_lock(&paths.stable).map_err(|error| {
        PhantomError::VaultError(format!(
            "Cannot acquire stable project transaction lock {}: {error}",
            paths.stable.display()
        ))
    })?;

    // One-release bridge for Phantom versions that only know the historical
    // transaction-locks/<digest>.lock location. Always take it second to keep
    // lock ordering deterministic. Do not remove the legacy file on drop.
    let legacy = anchor.acquire_lock(&paths.legacy).map_err(|error| {
        PhantomError::VaultError(format!(
            "Cannot acquire legacy project transaction lock {}: {error}",
            paths.legacy.display()
        ))
    })?;
    Ok(ProjectFilesystemLocks { stable, legacy })
}

fn acquire_project_transaction_lock_at(paths: ProjectLockPaths) -> Result<ProjectTransactionLock> {
    let process = process_lock_for(&paths.identity);
    let filesystem = acquire_filesystem_locks(&paths)?;
    Ok(ProjectTransactionLock {
        _process: process,
        _stable: filesystem.stable,
        _legacy: filesystem.legacy,
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
    fn retained_lock_contract_is_visible_to_cross_platform_review() {
        let transaction_source = include_str!("transaction_lock.rs");
        assert!(transaction_source.contains("TrustedAnchor::open_canonical_private"));
        assert!(transaction_source.contains("let stable = anchor.acquire_lock"));
        assert!(transaction_source.contains("let legacy = anchor.acquire_lock"));
        assert!(transaction_source.contains("_stable: AnchoredLock"));
        assert!(transaction_source.contains("_legacy: AnchoredLock"));
        assert!(transaction_source.contains("does not claim that\n//! the ACL is user-only"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_project_lock_guard_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<ProjectTransactionLock>();
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
        let paths = lock_paths_at(project.path(), &anchor).unwrap();

        let error = acquire_project_transaction_lock_at(paths)
            .err()
            .expect("symlinked lock root must be rejected");
        assert!(error
            .to_string()
            .contains("legacy project transaction lock"));
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
        let paths = lock_paths_at(project.path(), &root).unwrap();
        std::fs::create_dir(root.join("transaction-locks")).unwrap();
        let path = root.join(&paths.stable);
        symlink(&victim, &path).unwrap();

        assert!(acquire_project_transaction_lock_at(paths).is_err());
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
        let paths = lock_paths_at(project.path(), &root).unwrap();
        std::fs::create_dir(root.join("transaction-locks")).unwrap();
        let path = root.join(&paths.stable);
        std::fs::hard_link(&victim, &path).unwrap();

        assert!(acquire_project_transaction_lock_at(paths).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"preserve");
        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[cfg(unix)]
    #[test]
    fn stable_lock_blocks_before_a_swapped_legacy_decoy_is_touched() {
        use fs2::FileExt;
        use std::os::unix::fs::{symlink, PermissionsExt};

        let project = tempdir().unwrap();
        let lock_root = tempdir().unwrap();
        let root = lock_root.path().canonicalize().unwrap();
        let first_paths = lock_paths_at(project.path(), &root).unwrap();
        let first = acquire_filesystem_locks(&first_paths).unwrap();

        let legacy_directory = root.join("transaction-locks");
        std::fs::rename(&legacy_directory, root.join("moved-locks")).unwrap();
        std::fs::create_dir(&legacy_directory).unwrap();
        let victim = root.join("owner-state");
        std::fs::write(&victim, b"preserve").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o640)).unwrap();
        symlink(&victim, root.join(&first_paths.legacy)).unwrap();

        let contender = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join(&first_paths.stable))
            .unwrap();
        assert!(contender.try_lock_exclusive().is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"preserve");

        drop(first);
        contender.try_lock_exclusive().unwrap();
        contender.unlock().unwrap();

        let second_paths = lock_paths_at(project.path(), &root).unwrap();
        assert!(acquire_filesystem_locks(&second_paths).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"preserve");
        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }
}
