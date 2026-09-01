use fs2::FileExt;
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

fn lock_root() -> PathBuf {
    directories::ProjectDirs::from("ai", "phantom", "phantom-secrets")
        .map(|dirs| dirs.data_dir().join("transaction-locks"))
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(std::env::temp_dir)
                .join(".phantom")
                .join("transaction-locks")
        })
}

fn lock_path(project_dir: &Path) -> Result<(PathBuf, PathBuf)> {
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
    Ok((canonical, lock_root().join(format!("{name}.lock"))))
}

/// Acquire the process-local and cross-process lock for one canonical project.
pub fn acquire_project_transaction_lock(project_dir: &Path) -> Result<ProjectTransactionLock> {
    let (identity, path) = lock_path(project_dir)?;
    let process = process_lock_for(&identity);
    let parent = path.parent().expect("transaction lock path has a parent");
    std::fs::create_dir_all(parent)?;
    let parent_metadata = std::fs::symlink_metadata(parent)?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(PhantomError::VaultError(format!(
            "Project transaction lock directory is not a real directory: {}",
            parent.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }

    let mut options = std::fs::OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(&path).map_err(|error| {
        PhantomError::VaultError(format!(
            "Cannot open project transaction lock {}: {error}",
            path.display()
        ))
    })?;
    if !file.metadata()?.is_file() {
        return Err(PhantomError::VaultError(format!(
            "Project transaction lock is not a regular file: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.lock_exclusive().map_err(|error| {
        PhantomError::VaultError(format!(
            "Cannot acquire project transaction lock {}: {error}",
            path.display()
        ))
    })?;
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
}
