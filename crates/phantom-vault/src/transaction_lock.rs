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
//!
//! A cross-project transaction (a copy from one project into another) holds
//! both projects' locks through [`acquire_project_transaction_locks`]. Every
//! acquisition, single or paired, follows one global order so two copies in
//! opposite directions cannot deadlock: first the process-local shard
//! mutexes in ascending shard index (each shard once), then each project's
//! filesystem locks in ascending stable lock name (the digest of the
//! canonical project path, identical in every process sharing the anchor),
//! stable before legacy within a project. Two spellings of one canonical
//! project resolve to one lock, which is taken once.

use phantom_core::error::{PhantomError, Result};
use phantom_core::fs::{
    AnchoredCreatedDirectory, AnchoredDirectoryCreation, AnchoredLock, AnchoredTarget,
    FileIdentity, TrustedAnchor,
};
use sha2::{Digest, Sha256};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

const LOCK_TIMEOUT: Duration = Duration::from_secs(120);

const PROCESS_LOCK_SHARDS: usize = 64;

/// An advisory project lock shared by init and token-remap transactions.
/// Keeping the guard alive spans snapshot, commit, verification, and rollback.
pub struct ProjectTransactionLock {
    /// Process-local shard guards, held in ascending shard index. The second
    /// project of a [`ProjectTransactionLockPair`] holds none: the pair's
    /// primary holds every shard both projects need.
    _process: Vec<ShardGuard>,
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

fn process_lock_index(identity: &Path) -> usize {
    let mut hasher = DefaultHasher::new();
    identity.hash(&mut hasher);
    hasher.finish() as usize % PROCESS_LOCK_SHARDS
}

/// One coarse `Mutex<()>` per shard. Serializes all threads contending for
/// any project within that shard.
static SHARD_MUTEXES: OnceLock<Vec<Mutex<()>>> = OnceLock::new();

// Per-thread reference count per shard. Value at index `i` is the number
// of active ShardGuard instances the current thread holds for shard `i`.
// Re-entrant acquisition from the same thread is detected by a non-zero
// counter; the shard mutex is only acquired once per thread.
thread_local! {
    /// Shard ref counts for the current thread.
    pub(crate) static SHARD_OWNERSHIP: std::cell::Cell<[u32; PROCESS_LOCK_SHARDS]> = const {
        std::cell::Cell::new([0; PROCESS_LOCK_SHARDS])
    };
}

/// RAII guard for one shard. On construction the per-thread ref counter is
/// incremented; if this is the first reference the shard mutex is acquired.
/// On drop the counter is decremented; at zero the mutex is released for
/// other threads. Not `Send` because it stores a `MutexGuard`; never cross
/// thread boundaries.
#[derive(Debug)]
struct ShardGuard {
    index: usize,
    guard: Option<MutexGuard<'static, ()>>,
    _not_send: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl ShardGuard {
    fn acquire(index: usize, deadline: Instant) -> Result<Self> {
        SHARD_OWNERSHIP.with(|counts| {
            let refs = counts.get();
            if refs[index] > 0 {
                // Same thread already owns this shard -- re-entrant.
                // No mutex acquisition needed; just increment the counter.
                let mut refs = refs;
                refs[index] = refs[index].saturating_add(1);
                counts.set(refs);
                return Ok(Self { index, guard: None, _not_send: std::marker::PhantomData });
            }

            // First reference for this thread -- acquire the shard mutex.
            let locks = SHARD_MUTEXES.get_or_init(|| {
                (0..PROCESS_LOCK_SHARDS).map(|_| Mutex::new(())).collect()
            });

            // Wait for the mutex with a deadline, polling on contention.
            loop {
                match locks[index].try_lock() {
                    Ok(guard) => {
                        let mut refs = refs;
                        refs[index] = 1;
                        counts.set(refs);
                        return Ok(Self {
                            index,
                            guard: Some(guard),
                            _not_send: std::marker::PhantomData,
                        });
                    }
                    Err(_) => {
                        let remaining =
                            deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            return Err(PhantomError::VaultError(
                                "Timed out waiting for project transaction lock; another writer is active. Retry after it finishes.".into(),
                            ));
                        }
                        std::thread::sleep(
                            remaining.min(Duration::from_millis(10)),
                        );
                    }
                }
            }
        })
    }
}

impl Drop for ShardGuard {
    fn drop(&mut self) {
        SHARD_OWNERSHIP.with(|counts| {
            let mut refs = counts.get();
            refs[self.index] = refs[self.index].saturating_sub(1);
            if refs[self.index] == 0 {
                // Last reference -- release the shard mutex.
                drop(self.guard.take());
            }
        });
    }
}

/// Acquire every distinct shard for the given identities in ascending index
/// order. Each shard is locked once regardless of how many identities hash
/// to it. Per-thread reference counting provides re-entrant acquisition;
/// distinct threads contend on the shard mutex with a bounded deadline.
fn process_locks_for(identities: &[&Path], deadline: Instant) -> Result<Vec<ShardGuard>> {
    let indices: std::collections::BTreeSet<usize> = identities
        .iter()
        .map(|identity| process_lock_index(identity))
        .collect();
    indices
        .into_iter()
        .map(|i| ShardGuard::acquire(i, deadline))
        .collect()
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
/// Contention across all lock steps has a shared 120 second deadline.
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

#[cfg(test)]
fn acquire_filesystem_locks(paths: &ProjectLockPaths) -> Result<ProjectFilesystemLocks> {
    acquire_filesystem_locks_until(paths, Instant::now() + LOCK_TIMEOUT)
}

fn acquire_filesystem_locks_until(
    paths: &ProjectLockPaths,
    deadline: Instant,
) -> Result<ProjectFilesystemLocks> {
    let anchor = open_lock_anchor(&paths.anchor)?;

    // The direct-child lock is the durable coordination identity. Acquiring it
    // first means replacing the legacy descendant directory cannot split two
    // current Phantom writers into different lock domains.
    let stable = anchor
        .acquire_lock_until(&paths.stable, deadline)
        .map_err(|error| {
            PhantomError::VaultError(format!(
                "Cannot acquire stable project transaction lock {}: {error}",
                paths.stable.display()
            ))
        })?;

    // One-release bridge for Phantom versions that only know the historical
    // transaction-locks/<digest>.lock location. Always take it second to keep
    // lock ordering deterministic. Do not remove the legacy file on drop.
    let legacy = anchor
        .acquire_lock_until(&paths.legacy, deadline)
        .map_err(|error| {
            PhantomError::VaultError(format!(
                "Cannot acquire legacy project transaction lock {}: {error}",
                paths.legacy.display()
            ))
        })?;
    Ok(ProjectFilesystemLocks { stable, legacy })
}

fn retain_project_root(paths: &ProjectLockPaths) -> Result<TrustedAnchor> {
    let project = TrustedAnchor::open(&paths.identity).map_err(|error| {
        PhantomError::VaultError(format!(
            "Cannot retain canonical project root {}: {error}",
            paths.identity.display()
        ))
    })?;
    Ok(project)
}

fn assemble_lock(
    process: Vec<ShardGuard>,
    filesystem: ProjectFilesystemLocks,
    project: TrustedAnchor,
    paths: ProjectLockPaths,
) -> ProjectTransactionLock {
    ProjectTransactionLock {
        _process: process,
        _stable: filesystem.stable,
        _legacy: filesystem.legacy,
        project,
        requested_root: paths.requested_root,
        canonical_root: paths.identity,
    }
}

fn acquire_project_transaction_lock_at(paths: ProjectLockPaths) -> Result<ProjectTransactionLock> {
    let deadline = Instant::now() + LOCK_TIMEOUT;
    let process = process_locks_for(&[&paths.identity], deadline)?;
    let project = retain_project_root(&paths)?;
    let filesystem = acquire_filesystem_locks_until(&paths, deadline)?;
    Ok(assemble_lock(process, filesystem, project, paths))
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

/// Both project locks of a cross-project transaction, held together.
///
/// The primary is the project the transaction writes; its retained root is
/// the payload capability. The secondary (the project a copy reads from) is
/// held only to exclude its cooperating writers until the pair is dropped.
/// When both directories resolve to one canonical project there is one lock
/// and no secondary.
pub struct ProjectTransactionLockPair {
    // Field order is drop order: the secondary's filesystem locks are
    // released before the primary releases the project guards it holds for
    // both projects. Release order cannot deadlock either way.
    secondary: Option<ProjectTransactionLock>,
    primary: ProjectTransactionLock,
}

impl ProjectTransactionLockPair {
    pub(crate) fn single(primary: ProjectTransactionLock) -> Self {
        Self {
            secondary: None,
            primary,
        }
    }

    /// The lock of the project the transaction writes.
    pub fn primary(&self) -> &ProjectTransactionLock {
        &self.primary
    }

    /// The other project's lock, or `None` when both directories are the
    /// same canonical project and its lock was taken once.
    pub fn secondary(&self) -> Option<&ProjectTransactionLock> {
        self.secondary.as_ref()
    }
}

/// Acquire the transaction locks of two projects in Phantom's global lock
/// order (see the module documentation), so a concurrent pair acquisition in
/// the opposite direction waits instead of deadlocking. Every lock is a
/// cooperative lock with a shared 120 second acquisition deadline. Deterministic
/// ordering excludes deadlock; the deadline bounds contention.
pub fn acquire_project_transaction_locks(
    primary: &Path,
    secondary: &Path,
) -> Result<ProjectTransactionLockPair> {
    let anchor = lock_anchor();
    let primary = lock_paths_at(primary, &anchor)?;
    let secondary = lock_paths_at(secondary, &anchor)?;
    acquire_project_transaction_locks_at(primary, secondary)
}

fn acquire_project_transaction_locks_at(
    primary: ProjectLockPaths,
    secondary: ProjectLockPaths,
) -> Result<ProjectTransactionLockPair> {
    // The stable lock name is derived from the canonical identity, so equal
    // names are one project, and one lock that must be taken exactly once.
    if primary.stable == secondary.stable {
        return acquire_project_transaction_lock_at(primary)
            .map(ProjectTransactionLockPair::single);
    }
    let deadline = Instant::now() + LOCK_TIMEOUT;
    let process = process_locks_for(&[&primary.identity, &secondary.identity], deadline)?;
    let primary_root = retain_project_root(&primary)?;
    let secondary_root = retain_project_root(&secondary)?;
    let (primary_filesystem, secondary_filesystem) = if primary.stable < secondary.stable {
        let first = acquire_filesystem_locks_until(&primary, deadline)?;
        (first, acquire_filesystem_locks_until(&secondary, deadline)?)
    } else {
        let first = acquire_filesystem_locks_until(&secondary, deadline)?;
        (acquire_filesystem_locks_until(&primary, deadline)?, first)
    };
    Ok(ProjectTransactionLockPair {
        secondary: Some(assemble_lock(
            Vec::new(),
            secondary_filesystem,
            secondary_root,
            secondary,
        )),
        primary: assemble_lock(process, primary_filesystem, primary_root, primary),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use tempfile::tempdir;

    #[test]
    fn contention_timeout_releases_partial_locks() {
        let project = tempdir().unwrap();
        let root = tempdir().unwrap();
        let paths = lock_paths_at(project.path(), root.path()).unwrap();
        let anchor = open_lock_anchor(root.path()).unwrap();
        // A legacy holder forces failure after the stable lock was acquired.
        let legacy = anchor.acquire_lock(&paths.legacy).unwrap();
        let error =
            acquire_filesystem_locks_until(&paths, Instant::now() + Duration::from_millis(50))
                .err()
                .expect("contention must time out");
        assert!(error
            .to_string()
            .contains("Timed out waiting for project transaction lock"));
        assert!(error.to_string().contains("another writer is active"));
        // The failed acquisition must release its stable lock.
        let stable = anchor
            .acquire_lock_until(&paths.stable, Instant::now())
            .unwrap();
        drop(stable);
        drop(legacy);
        acquire_filesystem_locks(&paths).unwrap();
    }

    #[test]
    fn process_shard_contention_has_a_clear_timeout() {
        let project = tempdir().unwrap();
        let identity = project.path().canonicalize().unwrap();
        // Main thread holds the shard. A spawned contender times out.
        // ShardGuard is !Send so we communicate via a channel.
        let held = process_locks_for(&[&identity], Instant::now() + LOCK_TIMEOUT).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let identity2 = identity.clone();
        std::thread::spawn(move || {
            let result =
                process_locks_for(&[&identity2], Instant::now() + Duration::from_millis(20));
            let _ = tx.send(result.map(|_| ()).map_err(|e| e.to_string()));
        });
        let error = rx
            .recv()
            .expect("contender must finish")
            .expect_err("cross-thread contention must time out");
        assert!(error.contains("Timed out waiting for project transaction lock"));
        drop(held);
        process_locks_for(&[&identity], Instant::now() + LOCK_TIMEOUT).unwrap();
    }
    // Run only in a subprocess with private fixture paths, never the user's vault.
    #[test]
    fn crash_holder_child() {
        let Some(root) = std::env::var_os("PHANTOM_LOCK_TEST_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        let paths = lock_paths_at(&root.join("project"), &root.join("locks")).unwrap();
        let held = acquire_project_transaction_lock_at(paths).unwrap();
        // Windows locks deny reads; report identities from the retained handles.
        std::fs::write(
            root.join("ready.tmp"),
            format!(
                "{:?}\n{:?}",
                held._stable.identity(),
                held._legacy.identity()
            ),
        )
        .unwrap();
        std::fs::rename(root.join("ready.tmp"), root.join("ready")).unwrap();
        loop {
            std::thread::park();
        }
    }

    struct ChildHolder(std::process::Child);

    impl Drop for ChildHolder {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn killed_holder_leaves_reusable_stale_lock_files() {
        let root = tempdir().unwrap();
        std::fs::create_dir(root.path().join("project")).unwrap();
        let mut child = ChildHolder(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "transaction_lock::tests::crash_holder_child",
                    "--nocapture",
                ])
                .env("PHANTOM_LOCK_TEST_ROOT", root.path())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while !root.path().join("ready").exists() {
            if Instant::now() >= deadline || child.0.try_wait().unwrap().is_some() {
                let _ = child.0.kill();
                let _ = child.0.wait();
                panic!("lock holder did not become ready");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let paths =
            lock_paths_at(&root.path().join("project"), &root.path().join("locks")).unwrap();
        let before = std::fs::read_to_string(root.path().join("ready")).unwrap();
        let blocked =
            acquire_filesystem_locks_until(&paths, Instant::now() + Duration::from_millis(30));
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let error = blocked.err().expect("live holder must remain exclusive");
        assert!(error
            .to_string()
            .contains("Timed out waiting for project transaction lock"));
        let held = acquire_project_transaction_lock_at(paths).unwrap();
        assert!(root.path().join("locks/transaction-locks").is_dir());
        assert_eq!(
            format!(
                "{:?}\n{:?}",
                held._stable.identity(),
                held._legacy.identity()
            ),
            before,
            "both persistent lock files must retain their identity after a crash",
        );
        drop(held);
        // A normal release also leaves persistent files that must be reusable.
        let paths =
            lock_paths_at(&root.path().join("project"), &root.path().join("locks")).unwrap();
        acquire_project_transaction_lock_at(paths).unwrap();
    }

    #[test]
    fn project_transaction_lock_serializes_threads() {
        let project = tempdir().unwrap();
        let barrier = Arc::new(Barrier::new(24));
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut workers = Vec::new();
        for _ in 0..24 {
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

    /// Run `work` on its own thread and fail instead of hanging when it does
    /// not finish in time, which is how a lock-order deadlock shows up.
    fn finishes_within<T: Send + 'static>(
        limit: std::time::Duration,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(work());
        });
        finished
            .recv_timeout(limit)
            .expect("work must finish within its bound (no lock-order deadlock)")
    }

    fn pair_at(primary: &Path, secondary: &Path, root: &Path) -> ProjectTransactionLockPair {
        acquire_project_transaction_locks_at(
            lock_paths_at(primary, root).unwrap(),
            lock_paths_at(secondary, root).unwrap(),
        )
        .unwrap()
    }

    /// Two threads repeatedly take the same two projects' locks in opposite
    /// argument orders. The global order makes them serialize instead of
    /// each holding one project while waiting for the other.
    #[test]
    fn paired_locks_in_opposite_directions_serialize_without_deadlock() {
        let first = tempdir().unwrap();
        let second = tempdir().unwrap();
        let lock_root = tempdir().unwrap();
        let root = lock_root.path().canonicalize().unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let worker = |primary: PathBuf, secondary: PathBuf| {
            let (root, barrier, active, peak) = (
                root.clone(),
                Arc::clone(&barrier),
                Arc::clone(&active),
                Arc::clone(&peak),
            );
            move || {
                barrier.wait();
                for _ in 0..50 {
                    let pair = pair_at(&primary, &secondary, &root);
                    assert!(pair.secondary().is_some());
                    let now = active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    peak.fetch_max(now, std::sync::atomic::Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
        };
        let forward = worker(first.path().to_path_buf(), second.path().to_path_buf());
        let backward = worker(second.path().to_path_buf(), first.path().to_path_buf());

        finishes_within(std::time::Duration::from_secs(60), move || {
            let forward = std::thread::spawn(forward);
            let backward = std::thread::spawn(backward);
            forward.join().unwrap();
            backward.join().unwrap();
        });
        assert_eq!(peak.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// A pair holds each project against a single-project writer until the
    /// pair is dropped, for the secondary project as well as the primary.
    #[test]
    fn paired_lock_excludes_single_project_writers_on_both_projects() {
        let primary = tempdir().unwrap();
        let secondary = tempdir().unwrap();
        let lock_root = tempdir().unwrap();
        let root = lock_root.path().canonicalize().unwrap();
        let pair = pair_at(primary.path(), secondary.path(), &root);

        let mut writers = Vec::new();
        for project in [primary.path().to_path_buf(), secondary.path().to_path_buf()] {
            let root = root.clone();
            let (entered, entered_signal) = std::sync::mpsc::channel();
            let handle = std::thread::spawn(move || {
                let _lock =
                    acquire_project_transaction_lock_at(lock_paths_at(&project, &root).unwrap())
                        .unwrap();
                let _ = entered.send(());
            });
            writers.push((handle, entered_signal));
        }
        for (_, entered_signal) in &writers {
            assert!(entered_signal
                .recv_timeout(std::time::Duration::from_millis(300))
                .is_err());
        }

        drop(pair);
        for (handle, entered_signal) in writers {
            assert!(entered_signal
                .recv_timeout(std::time::Duration::from_secs(30))
                .is_ok());
            handle.join().unwrap();
        }
    }

    /// Two spellings of one canonical project are one lock, taken once: the
    /// pair neither waits on itself nor holds a second lock.
    #[test]
    fn paired_lock_of_one_project_is_taken_once() {
        let project = tempdir().unwrap();
        let lock_root = tempdir().unwrap();
        let root = lock_root.path().canonicalize().unwrap();
        let primary = project.path().to_path_buf();
        let spelling = project.path().join(".");

        let held_once = finishes_within(std::time::Duration::from_secs(30), move || {
            let pair = pair_at(&primary, &spelling, &root);
            pair.secondary().is_none()
                && pair.primary().project_root_at_acquisition() == primary.canonicalize().unwrap()
        });
        assert!(held_once);
    }

    /// Distinct projects can hash to one process shard. That shard mutex is
    /// not reentrant, so the pair must take it once rather than wait on
    /// itself.
    #[test]
    fn distinct_projects_sharing_a_process_shard_pair_without_self_deadlock() {
        // With more directories than shards, two must share one.
        let projects: Vec<_> = (0..=PROCESS_LOCK_SHARDS)
            .map(|_| tempdir().unwrap())
            .collect();
        let mut by_shard = std::collections::HashMap::new();
        let (first, second) = projects
            .iter()
            .find_map(|project| {
                let canonical = project.path().canonicalize().unwrap();
                by_shard
                    .insert(process_lock_index(&canonical), canonical.clone())
                    .map(|earlier| (earlier, canonical))
            })
            .expect("pigeonhole guarantees a shared shard");
        let lock_root = tempdir().unwrap();
        let root = lock_root.path().canonicalize().unwrap();

        let paired = finishes_within(std::time::Duration::from_secs(30), move || {
            pair_at(&first, &second, &root).secondary().is_some()
        });
        assert!(paired);
    }

    #[test]
    fn retained_lock_contract_is_visible_to_cross_platform_review() {
        let transaction_source = include_str!("transaction_lock.rs");
        assert!(transaction_source.contains("TrustedAnchor::open_canonical_private"));
        assert!(transaction_source.contains("let project = TrustedAnchor::open(&paths.identity)"));
        assert!(transaction_source.contains(".acquire_lock_until(&paths.stable, deadline)"));
        assert!(transaction_source.contains(".acquire_lock_until(&paths.legacy, deadline)"));
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
