//! Cooperative project transaction serialization for Phantom writers.
//!
//! The OS releases the advisory lock if a process crashes. This is not a data
//! durability primitive and does not fsync transaction payloads. The guard also
//! retains the exact canonical project root so payload operations can remain
//! descriptor-relative after acquisition. On Windows the
//! lock directory inherits its surrounding ACL; this module does not claim that
//! the ACL is user-only, so same-user or otherwise-authorized processes remain
//! outside the coordination guarantee. Current writers coordinate on a stable
//! direct child of the trusted app-data anchor and also take the historical
//! descendant lock as a one-release compatibility bridge.

use phantom_core::error::{PhantomError, Result};
use phantom_core::fs::{
    AnchoredCreatedDirectory, AnchoredDirectoryCreation, AnchoredLock, AnchoredTarget,
    FileIdentity, TrustedAnchor,
};
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
    project: TrustedAnchor,
    requested_root: PathBuf,
    canonical_root: PathBuf,
}

/// Receipt-bearing preparation of one direct child directory beneath the
/// retained project root.
#[derive(Debug)]
pub enum ProjectDirectoryPreparation {
    Existing(TrustedAnchor),
    Created(AnchoredCreatedDirectory),
    CreatedVerifiedButDurabilityUncertain(AnchoredCreatedDirectory),
    CommittedButUncertain {
        receipt: Option<AnchoredCreatedDirectory>,
        error: std::io::Error,
    },
}

impl ProjectDirectoryPreparation {
    /// Borrow the retained child anchor when its exact identity is known.
    pub fn anchor(&self) -> Option<&TrustedAnchor> {
        match self {
            Self::Existing(anchor) => Some(anchor),
            Self::Created(created) | Self::CreatedVerifiedButDurabilityUncertain(created) => {
                Some(created.anchor())
            }
            Self::CommittedButUncertain { receipt, .. } => {
                receipt.as_ref().map(AnchoredCreatedDirectory::anchor)
            }
        }
    }
}

struct ProjectLockPaths {
    identity: PathBuf,
    requested_root: PathBuf,
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
    let requested_root = if project_dir.is_absolute() {
        project_dir.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| {
                PhantomError::VaultError(format!(
                    "Cannot resolve the current directory for project transaction locking: {error}"
                ))
            })?
            .join(project_dir)
    };
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
        requested_root,
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
    let project = TrustedAnchor::open(&paths.identity).map_err(|error| {
        PhantomError::VaultError(format!(
            "Cannot retain canonical project root {}: {error}",
            paths.identity.display()
        ))
    })?;
    let filesystem = acquire_filesystem_locks(&paths)?;
    Ok(ProjectTransactionLock {
        _process: process,
        _stable: filesystem.stable,
        _legacy: filesystem.legacy,
        project,
        requested_root: paths.requested_root,
        canonical_root: paths.identity,
    })
}

impl ProjectTransactionLock {
    /// Canonical project path spelling captured when the lock was acquired.
    ///
    /// This is a diagnostic label, not a live pathname: it deliberately does
    /// not change if the retained directory is renamed while the lock is held.
    pub fn project_root_at_acquisition(&self) -> &Path {
        &self.canonical_root
    }

    /// Stable identity of the retained project directory.
    ///
    /// Callers that must resolve other machine-local authority before taking
    /// the transaction lock can pre-open the reviewed root and compare this
    /// value after acquisition. Path spelling alone cannot detect a
    /// rename-and-replacement decoy at the same canonical pathname.
    pub fn project_identity_at_acquisition(&self) -> FileIdentity {
        self.project.identity()
    }

    /// Resolve one project-relative payload through the retained root.
    ///
    /// Absolute paths are accepted only when they are lexically beneath the
    /// exact project spelling supplied at lock acquisition or its canonical
    /// spelling. No ambient canonicalization occurs after the lock is held.
    pub fn target(&self, path: impl AsRef<Path>) -> Result<AnchoredTarget> {
        let relative = self.relative_payload(path.as_ref())?;
        self.project.target(relative).map_err(|error| {
            PhantomError::VaultError(format!(
                "Cannot retain project payload target {}: {error}",
                path.as_ref().display()
            ))
        })
    }

    /// Open or privately create one direct project child directory.
    ///
    /// Creation never collapses a committed-but-uncertain namespace effect
    /// into an ordinary error. Callers must stop on that variant and, when a
    /// receipt is present, drop descendant handles before attempting the
    /// receipt's exact cleanup operation.
    pub fn prepare_private_child(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<ProjectDirectoryPreparation> {
        let path = path.as_ref();
        let relative = self.relative_payload(path)?;
        let mut components = relative.components();
        let Some(std::path::Component::Normal(name)) = components.next() else {
            return Err(PhantomError::VaultError(format!(
                "Project child directory must be one normal relative component: {}",
                path.display()
            )));
        };
        if components.next().is_some() {
            return Err(PhantomError::VaultError(format!(
                "Project child directory must be a direct child of {}: {}",
                self.canonical_root.display(),
                path.display()
            )));
        }

        match self.project.open_subdirectory(Path::new(name)) {
            Ok(anchor) => Ok(ProjectDirectoryPreparation::Existing(anchor)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match self.project.create_private_child(Path::new(name)) {
                    Ok(AnchoredDirectoryCreation::Durable(created)) => {
                        Ok(ProjectDirectoryPreparation::Created(created))
                    }
                    Ok(AnchoredDirectoryCreation::CommittedVerifiedButDurabilityUncertain {
                        receipt,
                    }) => Ok(
                        ProjectDirectoryPreparation::CreatedVerifiedButDurabilityUncertain(receipt),
                    ),
                    Ok(AnchoredDirectoryCreation::CommittedButUncertain { receipt, error }) => {
                        Ok(ProjectDirectoryPreparation::CommittedButUncertain { receipt, error })
                    }
                    Err(error) => Err(PhantomError::VaultError(format!(
                        "Cannot create private project child directory {}: {error}",
                        path.display()
                    ))),
                }
            }
            Err(error) => Err(PhantomError::VaultError(format!(
                "Cannot retain project child directory {}: {error}",
                path.display()
            ))),
        }
    }

    pub(crate) fn project_anchor(&self) -> &TrustedAnchor {
        &self.project
    }

    pub(crate) fn relative_project_path(&self, path: &Path) -> Result<PathBuf> {
        self.relative_payload(path).map(Path::to_path_buf)
    }

    fn relative_payload<'a>(&'a self, path: &'a Path) -> Result<&'a Path> {
        if !path.is_absolute() {
            return Ok(path);
        }
        path.strip_prefix(&self.requested_root)
            .or_else(|_| path.strip_prefix(&self.canonical_root))
            .map_err(|_| {
                PhantomError::VaultError(format!(
                    "Project payload target {} is outside canonical project root {}",
                    path.display(),
                    self.canonical_root.display()
                ))
            })
    }
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
        assert!(transaction_source.contains("let project = TrustedAnchor::open(&paths.identity)"));
        assert!(transaction_source.contains("let stable = anchor.acquire_lock"));
        assert!(transaction_source.contains("let legacy = anchor.acquire_lock"));
        assert!(transaction_source.contains("_stable: AnchoredLock"));
        assert!(transaction_source.contains("_legacy: AnchoredLock"));
        assert!(transaction_source.contains("project: TrustedAnchor"));
        assert!(transaction_source.contains("No ambient canonicalization occurs"));
        assert!(transaction_source.contains("does not claim that"));
        assert!(transaction_source.contains("the ACL is user-only"));
    }

    #[test]
    fn project_payload_target_must_stay_beneath_the_locked_root() {
        let project = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let lock_root = tempdir().unwrap();
        let paths = lock_paths_at(project.path(), lock_root.path()).unwrap();
        let lock = acquire_project_transaction_lock_at(paths).unwrap();

        lock.target(project.path().join("state")).unwrap();
        lock.target("state").unwrap();
        let error = lock.target(outside.path().join("state")).unwrap_err();
        assert!(error.to_string().contains("outside canonical project root"));
    }

    #[cfg(unix)]
    #[test]
    fn retained_project_root_ignores_rename_replacement_decoy() {
        let container = tempdir().unwrap();
        let project = container.path().join("project");
        let moved = container.path().join("moved-project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("state"), b"reviewed").unwrap();
        let canonical_project = project.canonicalize().unwrap();
        let lock_root = tempdir().unwrap();
        let paths = lock_paths_at(&project, lock_root.path()).unwrap();
        let lock = acquire_project_transaction_lock_at(paths).unwrap();
        assert_eq!(lock.project_root_at_acquisition(), canonical_project);
        assert_eq!(
            lock.project_identity_at_acquisition(),
            TrustedAnchor::open(&project).unwrap().identity()
        );
        let target = lock.target(project.join("state")).unwrap();
        let before = target.read_regular().unwrap().unwrap();

        std::fs::rename(&project, &moved).unwrap();
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("state"), b"decoy").unwrap();

        assert!(matches!(
            target
                .replace_if_exact(Some(&before), b"committed")
                .unwrap(),
            phantom_core::fs::AnchoredEffect::Durable(_)
        ));
        assert_eq!(std::fs::read(moved.join("state")).unwrap(), b"committed");
        assert_eq!(std::fs::read(project.join("state")).unwrap(), b"decoy");
    }

    #[test]
    fn project_payload_capability_contract_is_cross_platform() {
        let transaction_source = include_str!("transaction_lock.rs");
        let implementation = transaction_source
            .split("impl ProjectTransactionLock")
            .nth(1)
            .expect("project transaction capability implementation")
            .split("#[cfg(test)]")
            .next()
            .expect("implementation boundary");
        assert!(implementation.contains("self.project.target(relative)"));
        assert!(!implementation.contains("std::fs"));

        let anchored_source = include_str!("../../phantom-core/src/fs/anchored.rs");
        assert!(anchored_source.contains("FILE_SHARE_READ | FILE_SHARE_WRITE"));
        assert!(anchored_source.contains("Intentionally omit FILE_SHARE_DELETE"));
        assert!(anchored_source.contains("FILE_FLAG_OPEN_REPARSE_POINT"));
        assert!(anchored_source.contains("open_dir_nofollow"));
    }

    #[test]
    fn direct_child_preparation_returns_exact_created_receipt() {
        let project = tempdir().unwrap();
        let lock_root = tempdir().unwrap();
        let paths = lock_paths_at(project.path(), lock_root.path()).unwrap();
        let lock = acquire_project_transaction_lock_at(paths).unwrap();

        let created = match lock.prepare_private_child(".phantom").unwrap() {
            ProjectDirectoryPreparation::Created(created)
            | ProjectDirectoryPreparation::CreatedVerifiedButDurabilityUncertain(created) => {
                created
            }
            other => panic!("unexpected preparation: {other:?}"),
        };
        let target = created.anchor().target("active-env").unwrap();
        assert!(matches!(
            target.replace_if_exact(None, b"development").unwrap(),
            phantom_core::fs::AnchoredEffect::Durable(_)
                | phantom_core::fs::AnchoredEffect::CommittedVerifiedButDurabilityUncertain { .. }
        ));
        let current = target.read_regular().unwrap().unwrap();
        assert!(matches!(
            target.unlink_if_exact(&current).unwrap(),
            phantom_core::fs::AnchoredEffect::Durable(())
                | phantom_core::fs::AnchoredEffect::CommittedVerifiedButDurabilityUncertain {
                    value: ()
                }
        ));
        drop(target);
        assert!(matches!(
            created.remove_if_empty_exact().unwrap(),
            phantom_core::fs::AnchoredEffect::Durable(())
                | phantom_core::fs::AnchoredEffect::CommittedVerifiedButDurabilityUncertain {
                    value: ()
                }
        ));
        assert!(!project.path().join(".phantom").exists());
    }

    #[test]
    fn direct_child_preparation_rejects_nested_and_outside_paths() {
        let project = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let lock_root = tempdir().unwrap();
        let paths = lock_paths_at(project.path(), lock_root.path()).unwrap();
        let lock = acquire_project_transaction_lock_at(paths).unwrap();

        assert!(lock.prepare_private_child("nested/child").is_err());
        assert!(lock
            .prepare_private_child(outside.path().join("child"))
            .is_err());
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
