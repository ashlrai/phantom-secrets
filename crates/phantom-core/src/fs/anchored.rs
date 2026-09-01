//! Descriptor-anchored filesystem operations for security-sensitive state.
//!
//! A [`TrustedAnchor`] retains an open directory handle. Every
//! [`AnchoredTarget`] additionally retains one no-follow handle for each
//! existing ancestor beneath that anchor. This matters on Windows as well as
//! Unix: `cap-std` directory handles are opened without `FILE_SHARE_DELETE`,
//! so an owned ancestor cannot be renamed or removed during an operation.
//!
//! The exact-write and exact-unlink methods compare both content and stable
//! file identity. Callers must still hold their domain transaction lock from
//! the original read through commit: no portable filesystem API offers an
//! atomic "replace this particular inode" operation against an uncooperative
//! same-user process.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, DirBuilder, File, OpenOptions};
use fs2::FileExt as _;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;
#[cfg(unix)]
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const TEMP_CREATE_ATTEMPTS: usize = 32;

/// Stable filesystem identity captured from an open handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileIdentity {
    volume: u64,
    object: u128,
}

/// Permission intent captured from and applied to file handles.
///
/// Unix retains exact permission bits. Other supported platforms retain the
/// portable read-only attribute; this deliberately does not claim to capture
/// or reproduce an entire Windows ACL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchoredFilePermissions {
    unix_mode: Option<u32>,
    readonly: bool,
}

impl AnchoredFilePermissions {
    pub const fn private() -> Self {
        Self {
            #[cfg(unix)]
            unix_mode: Some(0o600),
            #[cfg(not(unix))]
            unix_mode: None,
            readonly: false,
        }
    }

    pub const fn executable() -> Self {
        Self {
            #[cfg(unix)]
            unix_mode: Some(0o755),
            #[cfg(not(unix))]
            unix_mode: None,
            readonly: false,
        }
    }

    /// Whether the captured portable permission token carries a Unix execute
    /// bit. Non-Unix platforms do not model executable permission bits here.
    pub const fn is_executable(&self) -> bool {
        #[cfg(unix)]
        {
            matches!(self.unix_mode, Some(mode) if mode & 0o111 != 0)
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
}

/// An exact, value-bearing before-image read through an anchored handle.
///
/// The identity is intentionally part of equality: replacing a file with a
/// byte-for-byte decoy is still drift and is rejected.
#[derive(Eq, PartialEq)]
pub struct AnchoredRead {
    bytes: Vec<u8>,
    identity: FileIdentity,
    permissions: AnchoredFilePermissions,
}

impl fmt::Debug for AnchoredRead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnchoredRead")
            .field("byte_len", &self.bytes.len())
            .field("identity", &self.identity)
            .field("permissions", &self.permissions)
            .finish()
    }
}

/// Result of an anchored namespace mutation.
///
/// The outer [`io::Result`] returned by mutation methods is reserved for
/// failures known to have happened before the rename or unlink took effect.
/// Once the namespace mutation succeeds, later durability or verification
/// failures are represented explicitly here so callers cannot mistake a
/// committed effect for a no-effect error and attempt unsafe compensation.
#[derive(Debug)]
#[must_use = "anchored mutation outcomes distinguish durable and uncertain commits"]
pub enum AnchoredEffect<T> {
    /// The namespace effect, parent-directory sync, and any required
    /// post-publish verification all completed.
    Durable(T),
    /// The namespace effect completed, but its durability or post-publish
    /// verification could not be established.
    CommittedButUncertain { value: T, error: io::Error },
}

/// Outcome of creating a directory when post-create retention or durability
/// can fail. A missing receipt means creation/cleanup reached an uncertain
/// namespace state and the caller must stop rather than guessing by path.
#[derive(Debug)]
#[must_use = "directory creation may have a committed or uncertain namespace effect"]
pub enum AnchoredDirectoryCreation {
    Durable(AnchoredCreatedDirectory),
    CommittedButUncertain {
        receipt: Option<AnchoredCreatedDirectory>,
        error: io::Error,
    },
}

impl AnchoredRead {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn identity(&self) -> FileIdentity {
        self.identity
    }

    pub fn permissions(&self) -> AnchoredFilePermissions {
        self.permissions
    }

    pub fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

impl Drop for AnchoredRead {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// A retained capability for one trusted directory tree.
pub struct TrustedAnchor {
    directories: Vec<Dir>,
    identity: FileIdentity,
    display_path: PathBuf,
}

/// Exact capability receipt for a directory created beneath an anchor.
pub struct AnchoredCreatedDirectory {
    parent: Dir,
    anchor: TrustedAnchor,
    leaf: OsString,
    identity: FileIdentity,
    relative: PathBuf,
}

impl fmt::Debug for AnchoredCreatedDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnchoredCreatedDirectory")
            .field("identity", &self.identity)
            .field("relative", &self.relative)
            .finish_non_exhaustive()
    }
}

impl AnchoredCreatedDirectory {
    pub fn anchor(&self) -> &TrustedAnchor {
        &self.anchor
    }

    pub fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Remove this operation's empty directory only if the retained parent
    /// still names the exact created identity. A successful namespace removal
    /// with an uncertain parent sync is returned as an explicit receipt.
    pub fn remove_if_empty_exact(self) -> io::Result<AnchoredEffect<()>> {
        let current = self.parent.open_dir_nofollow(&self.leaf)?;
        if directory_identity(&current)? != self.identity || self.anchor.identity() != self.identity
        {
            return Err(drift_error(&self.relative));
        }
        drop(current);

        // cap-std intentionally denies FILE_SHARE_DELETE for retained Windows
        // directory handles. Consume and close the child handle after exact
        // validation, while retaining the parent capability for relative
        // removal.
        let AnchoredCreatedDirectory {
            parent,
            anchor,
            leaf,
            identity: _,
            relative: _,
        } = self;
        drop(anchor);
        parent.remove_dir(&leaf)?;
        let durability = maybe_inject_failure(TestFailurePoint::RemoveDirectoryParentSync)
            .and_then(|()| sync_directory(&parent));
        Ok(match durability {
            Ok(()) => AnchoredEffect::Durable(()),
            Err(error) => AnchoredEffect::CommittedButUncertain { value: (), error },
        })
    }
}

impl fmt::Debug for TrustedAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedAnchor")
            .field("identity", &self.identity)
            .field("display_path", &self.display_path)
            .finish_non_exhaustive()
    }
}

impl TrustedAnchor {
    /// Open an existing real directory without following a final symlink or
    /// Windows reparse point.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::open_inner(path.as_ref(), false)
    }

    /// Open an existing real directory and restrict its POSIX mode to 0700.
    pub fn open_private(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::open_inner(path.as_ref(), true)
    }

    /// Resolve an explicitly trusted ambient base once, then anchor the
    /// canonical directory without following a final link during the open.
    ///
    /// This is intended for OS-provided roots whose spelling legitimately
    /// traverses an alias (for example macOS `/var` -> `/private/var`). Do not
    /// use it to turn an untrusted user-selected symlink into authority.
    pub fn open_canonical(path: impl AsRef<Path>) -> io::Result<Self> {
        let canonical = std::fs::canonicalize(path)?;
        Self::open_inner(&canonical, false)
    }

    /// Canonical trusted-base variant that also repairs POSIX mode to 0700.
    pub fn open_canonical_private(path: impl AsRef<Path>) -> io::Result<Self> {
        let canonical = std::fs::canonicalize(path)?;
        Self::open_inner(&canonical, true)
    }

    fn open_inner(path: &Path, repair_private: bool) -> io::Result<Self> {
        let file = open_anchor_directory(path)?;
        let root = Dir::from_std_file(file);
        if repair_private {
            repair_private_directory(&root)?;
        }
        let identity = directory_identity(&root)?;
        Ok(Self {
            directories: vec![root],
            identity,
            display_path: path.to_path_buf(),
        })
    }

    pub fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Resolve a target while rejecting absolute paths, `.` and `..`, and
    /// following no symlink/reparse-point ancestor.
    pub fn target(&self, relative: impl AsRef<Path>) -> io::Result<AnchoredTarget> {
        self.target_inner(relative.as_ref(), false)
    }

    /// Resolve a target, creating and descriptor-repairing missing parent
    /// directories to POSIX mode 0700.
    pub fn target_with_private_parents(
        &self,
        relative: impl AsRef<Path>,
    ) -> io::Result<AnchoredTarget> {
        self.target_inner(relative.as_ref(), true)
    }

    fn target_inner(&self, relative: &Path, create_private: bool) -> io::Result<AnchoredTarget> {
        let components = normal_components(relative)?;
        let (leaf, parents) = components
            .split_last()
            .ok_or_else(|| invalid_relative(relative))?;
        let directories = self.walk_directories(parents, create_private)?;
        Ok(AnchoredTarget {
            directories,
            leaf: leaf.clone(),
            relative: relative.to_path_buf(),
        })
    }

    /// Create or open a nested directory and repair every relative component
    /// to POSIX mode 0700 using its retained handle.
    pub fn ensure_private_directory(&self, relative: impl AsRef<Path>) -> io::Result<()> {
        let components = normal_components(relative.as_ref())?;
        self.walk_directories(&components, true)?;
        Ok(())
    }

    /// Create/open a private descendant directory without returning to an
    /// ambient path. The returned anchor retains the complete handle chain.
    pub fn private_subdirectory(&self, relative: impl AsRef<Path>) -> io::Result<TrustedAnchor> {
        let relative = relative.as_ref();
        let components = normal_components(relative)?;
        let directories = self.walk_directories(&components, true)?;
        let identity = directory_identity(
            directories
                .last()
                .expect("private subdirectory retains its directory"),
        )?;
        Ok(TrustedAnchor {
            directories,
            identity,
            display_path: self.display_path.join(relative),
        })
    }

    /// Open an existing real descendant directory and retain its complete
    /// no-follow handle chain without creating any component.
    pub fn open_subdirectory(&self, relative: impl AsRef<Path>) -> io::Result<TrustedAnchor> {
        let relative = relative.as_ref();
        let components = normal_components(relative)?;
        let directories = self.walk_directories(&components, false)?;
        let identity = directory_identity(
            directories
                .last()
                .expect("opened subdirectory retains its directory"),
        )?;
        Ok(TrustedAnchor {
            directories,
            identity,
            display_path: self.display_path.join(relative),
        })
    }

    /// Create one private child directory and return an identity-bound receipt.
    /// Existing children are rejected; callers can use [`Self::open_subdirectory`]
    /// when they deliberately accept a pre-existing directory.
    pub fn create_private_child(
        &self,
        name: impl AsRef<Path>,
    ) -> io::Result<AnchoredDirectoryCreation> {
        let name = name.as_ref();
        let components = normal_components(name)?;
        if components.len() != 1 {
            return Err(invalid_relative(name));
        }
        let leaf = components[0].clone();
        // Allocate every retained ancestor before the create commit point so
        // a clone failure is unambiguously no-effect.
        let mut directories = self
            .directories
            .iter()
            .map(Dir::try_clone)
            .collect::<io::Result<Vec<_>>>()?;
        let parent = directories
            .last()
            .expect("anchor directory is retained")
            .try_clone()?;
        create_private_directory(&parent, &leaf)?;

        let child = match maybe_inject_failure(TestFailurePoint::CreateDirectoryOpen)
            .and_then(|()| parent.open_dir_nofollow(&leaf))
        {
            Ok(child) => child,
            Err(open_error) => {
                return rollback_unretained_directory(&parent, &leaf, open_error);
            }
        };
        let identity = match maybe_inject_failure(TestFailurePoint::CreateDirectoryIdentity)
            .and_then(|()| directory_identity(&child))
        {
            Ok(identity) => identity,
            Err(identity_error) => {
                drop(child);
                return rollback_unretained_directory(&parent, &leaf, identity_error);
            }
        };
        directories.push(child);
        let created = AnchoredCreatedDirectory {
            parent,
            anchor: TrustedAnchor {
                directories,
                identity,
                display_path: self.display_path.join(name),
            },
            leaf,
            identity,
            relative: name.to_path_buf(),
        };

        let durability = repair_private_directory(
            created
                .anchor
                .directories
                .last()
                .expect("created directory handle is retained"),
        )
        .and_then(|()| maybe_inject_failure(TestFailurePoint::CreateDirectoryParentSync))
        .and_then(|()| sync_directory(&created.parent));
        Ok(match durability {
            Ok(()) => AnchoredDirectoryCreation::Durable(created),
            Err(error) => AnchoredDirectoryCreation::CommittedButUncertain {
                receipt: Some(created),
                error,
            },
        })
    }

    /// Acquire an exclusive lock file through this anchor. Missing parents are
    /// created privately; the lock itself is required to be a single-link,
    /// non-reparse regular file and is repaired to POSIX mode 0600 by handle.
    pub fn acquire_lock(&self, relative: impl AsRef<Path>) -> io::Result<AnchoredLock> {
        self.target_with_private_parents(relative)?
            .acquire_exclusive_lock()
    }

    fn walk_directories(
        &self,
        components: &[OsString],
        create_private: bool,
    ) -> io::Result<Vec<Dir>> {
        let mut retained = self
            .directories
            .iter()
            .map(Dir::try_clone)
            .collect::<io::Result<Vec<_>>>()?;
        for component in components {
            let current = retained.last().expect("anchor directory is retained");
            let next = match current.open_dir_nofollow(component) {
                Ok(directory) => directory,
                Err(error) if error.kind() == io::ErrorKind::NotFound && create_private => {
                    match create_private_directory(current, component) {
                        Ok(()) => sync_directory(current)?,
                        Err(create_error)
                            if create_error.kind() == io::ErrorKind::AlreadyExists => {}
                        Err(create_error) => return Err(create_error),
                    }
                    current.open_dir_nofollow(component)?
                }
                Err(error) => return Err(error),
            };
            if create_private {
                repair_private_directory(&next)?;
            }
            retained.push(next);
        }
        Ok(retained)
    }
}

/// A file target whose complete parent chain is retained by handle.
pub struct AnchoredTarget {
    // Keep every ancestor live. On Windows cap-std opens directory handles
    // with FILE_SHARE_READ | FILE_SHARE_WRITE (without FILE_SHARE_DELETE).
    directories: Vec<Dir>,
    leaf: OsString,
    relative: PathBuf,
}

impl fmt::Debug for AnchoredTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnchoredTarget")
            .field("relative", &self.relative)
            .field("retained_directory_count", &self.directories.len())
            .finish_non_exhaustive()
    }
}

impl AnchoredTarget {
    fn parent(&self) -> &Dir {
        self.directories
            .last()
            .expect("anchored target always retains its root")
    }

    pub fn relative_path(&self) -> &Path {
        &self.relative
    }

    /// Read a single-link regular file twice through no-follow handles and
    /// reject any observable identity or content drift.
    pub fn read_regular(&self) -> io::Result<Option<AnchoredRead>> {
        read_regular_at(self.parent(), &self.leaf, &self.relative)
    }

    /// Atomically publish `contents` only when the target still has the exact
    /// reviewed identity and bytes (or is still absent when `expected` is
    /// `None`). The staging file is random, same-directory, mode 0600, synced,
    /// and renamed through the retained directory capability.
    pub fn replace_if_exact(
        &self,
        expected: Option<&AnchoredRead>,
        contents: &[u8],
    ) -> io::Result<AnchoredEffect<AnchoredRead>> {
        self.replace_if_exact_with_permissions(
            expected,
            contents,
            AnchoredFilePermissions::private(),
        )
    }

    /// Exact replacement variant that applies explicit permissions through
    /// the staging handle before publication.
    pub fn replace_if_exact_with_permissions(
        &self,
        expected: Option<&AnchoredRead>,
        contents: &[u8],
        permissions: AnchoredFilePermissions,
    ) -> io::Result<AnchoredEffect<AnchoredRead>> {
        self.require_exact(expected)?;
        let (temp_name, temp, temp_identity) = self.create_private_temp()?;
        let mut temp = Some(temp);
        let result = (|| {
            let staging = temp.as_mut().expect("staging handle is live");
            staging.write_all(contents)?;
            apply_file_permissions(staging, permissions)?;
            staging.sync_all()?;
            ensure_regular_single_link(staging, &self.relative)?;
            if file_identity(staging)? != temp_identity {
                return Err(drift_error(&self.relative));
            }

            // Windows cannot rename a file while our no-delete-share staging
            // handle is open. Closing here is safe because the randomized
            // pathname and identity are revalidated by the exact cleanup path.
            drop(temp.take().expect("staging handle is live"));

            // Recheck after staging and immediately before the atomic publish.
            self.require_exact(expected)?;
            require_temp_exact(
                self.parent(),
                &temp_name,
                temp_identity,
                contents,
                permissions,
                &self.relative,
            )?;
            // cap-std Dir::rename is specified to replace an existing file;
            // on Windows 3.4.6 resolves against retained directory handles and
            // delegates to std::fs::rename (MoveFileExW replacement semantics).
            self.parent()
                .rename(&temp_name, self.parent(), &self.leaf)?;
            let committed = AnchoredRead {
                bytes: contents.to_vec(),
                identity: temp_identity,
                permissions,
            };
            let verification = (|| {
                maybe_inject_failure(TestFailurePoint::ReplaceParentSync)?;
                sync_directory(self.parent())?;
                maybe_inject_failure(TestFailurePoint::ReplaceVerification)?;
                let published = self
                    .read_regular()?
                    .ok_or_else(|| drift_error(&self.relative))?;
                if published != committed {
                    return Err(drift_error(&self.relative));
                }
                Ok(published)
            })();
            Ok(match verification {
                Ok(published) => AnchoredEffect::Durable(published),
                Err(error) => AnchoredEffect::CommittedButUncertain {
                    value: committed,
                    error,
                },
            })
        })();

        drop(temp.take());
        if result.is_err() {
            remove_if_identity(self.parent(), &temp_name, temp_identity);
        }
        result
    }

    /// Remove the target only when it still has the exact reviewed identity
    /// and bytes. Missing, replaced, linked, or modified targets are rejected.
    pub fn unlink_if_exact(&self, expected: &AnchoredRead) -> io::Result<AnchoredEffect<()>> {
        self.require_exact(Some(expected))?;
        // One last independent handle-bound comparison immediately before the
        // relative unlink. Domain callers must hold their transaction lock.
        self.require_exact(Some(expected))?;
        self.parent().remove_file(&self.leaf)?;
        let durability = maybe_inject_failure(TestFailurePoint::UnlinkParentSync)
            .and_then(|()| sync_directory(self.parent()));
        Ok(match durability {
            Ok(()) => AnchoredEffect::Durable(()),
            Err(error) => AnchoredEffect::CommittedButUncertain { value: (), error },
        })
    }

    /// Acquire an exclusive lock at this exact anchored target.
    pub fn acquire_exclusive_lock(&self) -> io::Result<AnchoredLock> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        configure_no_follow(&mut options);
        configure_private_create(&mut options);
        let cap_file = self.parent().open_with(&self.leaf, &options)?;
        ensure_regular_single_link(&cap_file, &self.relative)?;
        repair_private_file(&cap_file)?;
        let identity = file_identity(&cap_file)?;
        let file = cap_file.into_std();
        file.lock_exclusive()?;

        let current = open_regular(self.parent(), &self.leaf, &self.relative)?;
        if file_identity(&current)? != identity {
            let _ = fs2::FileExt::unlock(&file);
            return Err(drift_error(&self.relative));
        }
        let directories = self
            .directories
            .iter()
            .map(Dir::try_clone)
            .collect::<io::Result<Vec<_>>>()?;
        Ok(AnchoredLock {
            file,
            identity,
            _directories: directories,
        })
    }

    /// Restrict an existing single-link regular file to POSIX mode 0600 using
    /// its open handle. Returns `true` when a wider mode was repaired.
    pub fn repair_private_regular(&self) -> io::Result<bool> {
        let file = open_regular(self.parent(), &self.leaf, &self.relative)?;
        let identity = file_identity(&file)?;
        let changed = file_needs_private_repair(&file)?;
        if changed {
            repair_private_file(&file)?;
        }
        let reopened = open_regular(self.parent(), &self.leaf, &self.relative)?;
        if file_identity(&reopened)? != identity {
            return Err(drift_error(&self.relative));
        }
        Ok(changed)
    }

    fn require_exact(&self, expected: Option<&AnchoredRead>) -> io::Result<()> {
        let current = self.read_regular()?;
        if current.as_ref() != expected {
            return Err(drift_error(&self.relative));
        }
        Ok(())
    }

    fn create_private_temp(&self) -> io::Result<(OsString, File, FileIdentity)> {
        for _ in 0..TEMP_CREATE_ATTEMPTS {
            let mut random = [0_u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut random);
            let name = OsString::from(format!(".phantom-tmp-{}", hex::encode(random)));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            configure_no_follow(&mut options);
            configure_private_create(&mut options);
            match self.parent().open_with(&name, &options) {
                Ok(file) => {
                    ensure_regular_single_link(&file, &self.relative)?;
                    repair_private_file(&file)?;
                    let identity = file_identity(&file)?;
                    return Ok((name, file, identity));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique anchored staging file",
        ))
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestFailurePoint {
    ReplaceParentSync,
    ReplaceVerification,
    UnlinkParentSync,
    CreateDirectoryParentSync,
    CreateDirectoryOpen,
    CreateDirectoryIdentity,
    CreateDirectoryRollbackRemove,
    CreateDirectoryRollbackSync,
    RemoveDirectoryParentSync,
}

#[cfg(test)]
thread_local! {
    static TEST_FAILURE_POINTS: std::cell::RefCell<std::collections::VecDeque<TestFailurePoint>> = const {
        std::cell::RefCell::new(std::collections::VecDeque::new())
    };
}

#[cfg(test)]
fn inject_failure_once(point: TestFailurePoint) {
    TEST_FAILURE_POINTS.with(|points| points.borrow_mut().push_back(point));
}

#[cfg(test)]
fn maybe_inject_failure(point: TestFailurePoint) -> io::Result<()> {
    TEST_FAILURE_POINTS.with(|points| {
        let mut points = points.borrow_mut();
        if points.front().copied() == Some(point) {
            points.pop_front();
            Err(io::Error::other(format!(
                "injected anchored post-effect failure: {point:?}"
            )))
        } else {
            Ok(())
        }
    })
}

#[cfg(not(test))]
#[derive(Clone, Copy)]
enum TestFailurePoint {
    ReplaceParentSync,
    ReplaceVerification,
    UnlinkParentSync,
    CreateDirectoryParentSync,
    CreateDirectoryOpen,
    CreateDirectoryIdentity,
    CreateDirectoryRollbackRemove,
    CreateDirectoryRollbackSync,
    RemoveDirectoryParentSync,
}

#[cfg(not(test))]
fn maybe_inject_failure(_point: TestFailurePoint) -> io::Result<()> {
    Ok(())
}

fn rollback_unretained_directory(
    parent: &Dir,
    leaf: &OsStr,
    original_error: io::Error,
) -> io::Result<AnchoredDirectoryCreation> {
    let cleanup = maybe_inject_failure(TestFailurePoint::CreateDirectoryRollbackRemove)
        .and_then(|()| parent.remove_dir(leaf))
        .and_then(|()| maybe_inject_failure(TestFailurePoint::CreateDirectoryRollbackSync))
        .and_then(|()| sync_directory(parent));
    match cleanup {
        Ok(()) => Err(original_error),
        Err(cleanup_error) => Ok(AnchoredDirectoryCreation::CommittedButUncertain {
            receipt: None,
            error: io::Error::other(format!(
                "directory creation could not be retained ({original_error}) and exact durable cleanup is uncertain ({cleanup_error})"
            )),
        }),
    }
}

/// Exclusive lock guard. Dropping it releases the OS lock and the open handle.
#[derive(Debug)]
pub struct AnchoredLock {
    file: std::fs::File,
    identity: FileIdentity,
    _directories: Vec<Dir>,
}

impl AnchoredLock {
    pub fn identity(&self) -> FileIdentity {
        self.identity
    }

    pub fn unlock(self) -> io::Result<()> {
        fs2::FileExt::unlock(&self.file)
    }
}

fn normal_components(relative: &Path) -> io::Result<Vec<OsString>> {
    if relative.as_os_str().is_empty() || relative.is_absolute() {
        return Err(invalid_relative(relative));
    }
    let mut components = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(value) => components.push(value.to_os_string()),
            _ => return Err(invalid_relative(relative)),
        }
    }
    if components.is_empty() {
        return Err(invalid_relative(relative));
    }
    Ok(components)
}

fn invalid_relative(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "anchored target must contain only normal relative components: {}",
            path.display()
        ),
    )
}

fn drift_error(path: &Path) -> io::Error {
    io::Error::other(format!(
        "anchored target changed after review; refusing effect: {}",
        path.display()
    ))
}

fn open_regular(parent: &Dir, leaf: &OsStr, display: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    configure_no_follow(&mut options);
    let file = parent.open_with(leaf, &options)?;
    ensure_regular_single_link(&file, display)?;
    Ok(file)
}

fn read_regular_at(parent: &Dir, leaf: &OsStr, display: &Path) -> io::Result<Option<AnchoredRead>> {
    let mut first = match open_regular(parent, leaf, display) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let first_identity = file_identity(&first)?;
    let first_permissions = file_permissions(&first)?;
    // Both transient buffers may hold plaintext `.env` contents. Keep them
    // zeroizing even when a later identity, permission, or read check fails
    // before an `AnchoredRead` can take ownership.
    let mut first_bytes = Zeroizing::new(Vec::new());
    first.read_to_end(&mut first_bytes)?;

    let mut second = open_regular(parent, leaf, display)?;
    if file_identity(&second)? != first_identity {
        return Err(drift_error(display));
    }
    if file_permissions(&second)? != first_permissions {
        return Err(drift_error(display));
    }
    let mut second_bytes = Zeroizing::new(Vec::new());
    second.read_to_end(&mut second_bytes)?;
    if second_bytes != first_bytes {
        return Err(drift_error(display));
    }
    Ok(Some(AnchoredRead {
        bytes: std::mem::take(&mut *first_bytes),
        identity: first_identity,
        permissions: first_permissions,
    }))
}

fn ensure_regular_single_link(file: &File, display: &Path) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.is_symlink() || file_link_count(file)? != 1 {
        return Err(io::Error::other(format!(
            "refusing non-regular, reparse, or multiply-linked anchored file: {}",
            display.display()
        )));
    }
    Ok(())
}

fn remove_if_identity(parent: &Dir, name: &OsStr, expected: FileIdentity) {
    let Ok(file) = open_regular(parent, name, Path::new(name)) else {
        return;
    };
    if file_identity(&file).is_ok_and(|identity| identity == expected) {
        drop(file);
        let _ = parent.remove_file(name);
        let _ = sync_directory(parent);
    }
}

fn require_temp_exact(
    parent: &Dir,
    name: &OsStr,
    identity: FileIdentity,
    contents: &[u8],
    permissions: AnchoredFilePermissions,
    display: &Path,
) -> io::Result<()> {
    let current = read_regular_at(parent, name, display)?
        .ok_or_else(|| io::Error::other("anchored staging file disappeared before commit"))?;
    if current.identity != identity
        || current.bytes != contents
        || current.permissions != permissions
    {
        return Err(drift_error(display));
    }
    Ok(())
}

fn configure_no_follow(options: &mut OpenOptions) {
    options.follow(FollowSymlinks::No);
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
        // Keep the final file name pinned while its handle is live.
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
}

fn configure_private_create(_options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        _options.mode(PRIVATE_FILE_MODE);
    }
}

fn create_private_directory(parent: &Dir, name: &OsStr) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    {
        use cap_std::fs::DirBuilderExt;
        builder.mode(PRIVATE_DIRECTORY_MODE);
    }
    #[cfg(not(target_os = "wasi"))]
    {
        parent.create_dir_with(name, &builder)
    }
    #[cfg(target_os = "wasi")]
    {
        let _ = builder;
        parent.create_dir(name)
    }
}

#[cfg(unix)]
fn file_needs_private_repair(file: &File) -> io::Result<bool> {
    use cap_std::fs::MetadataExt;
    Ok(file.metadata()?.mode() & 0o777 != PRIVATE_FILE_MODE)
}

#[cfg(not(unix))]
fn file_needs_private_repair(_file: &File) -> io::Result<bool> {
    Ok(false)
}

#[cfg(unix)]
fn open_anchor_directory(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(windows)]
fn open_anchor_directory(path: &Path) -> io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        // Intentionally omit FILE_SHARE_DELETE: the anchor cannot be renamed
        // or removed while this capability is live.
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(path)?;
    let information = windows_file_information_std(&file)?;
    if !file.metadata()?.is_dir()
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(io::Error::other("trusted anchor is not a real directory"));
    }
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn open_anchor_directory(_path: &Path) -> io::Result<std::fs::File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "descriptor-anchored filesystem operations require Unix or Windows",
    ))
}

#[cfg(unix)]
fn repair_private_file(file: &File) -> io::Result<()> {
    apply_file_permissions(file, AnchoredFilePermissions::private())
}

#[cfg(unix)]
fn apply_file_permissions(file: &File, permissions: AnchoredFilePermissions) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let mode = permissions.unix_mode.unwrap_or(PRIVATE_FILE_MODE);
    if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn repair_private_file(_file: &File) -> io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn apply_file_permissions(file: &File, permissions: AnchoredFilePermissions) -> io::Result<()> {
    let mut current = file.metadata()?.permissions();
    current.set_readonly(permissions.readonly);
    file.set_permissions(current)
}

#[cfg(unix)]
fn file_permissions(file: &File) -> io::Result<AnchoredFilePermissions> {
    use cap_std::fs::MetadataExt;
    let metadata = file.metadata()?;
    Ok(AnchoredFilePermissions {
        unix_mode: Some(metadata.mode() & 0o7777),
        readonly: metadata.permissions().readonly(),
    })
}

#[cfg(not(unix))]
fn file_permissions(file: &File) -> io::Result<AnchoredFilePermissions> {
    Ok(AnchoredFilePermissions {
        unix_mode: None,
        readonly: file.metadata()?.permissions().readonly(),
    })
}

#[cfg(unix)]
fn repair_private_directory(directory: &Dir) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    if unsafe {
        libc::fchmod(
            directory.as_raw_fd(),
            PRIVATE_DIRECTORY_MODE as libc::mode_t,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn repair_private_directory(_directory: &Dir) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(directory: &Dir) -> io::Result<()> {
    directory.try_clone()?.into_std_file().sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Dir) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn file_identity(file: &File) -> io::Result<FileIdentity> {
    use cap_std::fs::MetadataExt;
    let metadata = file.metadata()?;
    Ok(FileIdentity {
        volume: metadata.dev(),
        object: u128::from(metadata.ino()),
    })
}

#[cfg(windows)]
fn file_identity(file: &File) -> io::Result<FileIdentity> {
    let information = windows_file_information(file)?;
    Ok(FileIdentity {
        volume: u64::from(information.dwVolumeSerialNumber),
        object: u128::from(
            (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
        ),
    })
}

#[cfg(not(any(unix, windows)))]
fn file_identity(_file: &File) -> io::Result<FileIdentity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stable file identity requires Unix or Windows",
    ))
}

fn directory_identity(directory: &Dir) -> io::Result<FileIdentity> {
    let file = directory.try_clone()?.into_std_file();
    std_file_identity(&file)
}

#[cfg(unix)]
fn std_file_identity(file: &std::fs::File) -> io::Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    Ok(FileIdentity {
        volume: metadata.dev(),
        object: u128::from(metadata.ino()),
    })
}

#[cfg(windows)]
fn std_file_identity(file: &std::fs::File) -> io::Result<FileIdentity> {
    let information = windows_file_information_std(file)?;
    Ok(FileIdentity {
        volume: u64::from(information.dwVolumeSerialNumber),
        object: u128::from(
            (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
        ),
    })
}

#[cfg(not(any(unix, windows)))]
fn std_file_identity(_file: &std::fs::File) -> io::Result<FileIdentity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stable directory identity requires Unix or Windows",
    ))
}

#[cfg(unix)]
fn file_link_count(file: &File) -> io::Result<u64> {
    use cap_std::fs::MetadataExt;
    Ok(file.metadata()?.nlink())
}

#[cfg(windows)]
fn file_link_count(file: &File) -> io::Result<u64> {
    Ok(u64::from(windows_file_information(file)?.nNumberOfLinks))
}

#[cfg(not(any(unix, windows)))]
fn file_link_count(_file: &File) -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "hard-link validation requires Unix or Windows",
    ))
}

#[cfg(windows)]
fn windows_file_information(
    file: &File,
) -> io::Result<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION> {
    use std::os::windows::io::AsRawHandle;
    windows_file_information_for_handle(file.as_raw_handle())
}

#[cfg(windows)]
fn windows_file_information_std(
    file: &std::fs::File,
) -> io::Result<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION> {
    use std::os::windows::io::AsRawHandle;
    windows_file_information_for_handle(file.as_raw_handle())
}

#[cfg(windows)]
fn windows_file_information_for_handle(
    handle: std::os::windows::io::RawHandle,
) -> io::Result<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION> {
    let mut information = unsafe { std::mem::zeroed() };
    let result = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(
            handle,
            &mut information,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(information)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn relative_paths_must_contain_only_normal_components() {
        let dir = TempDir::new().unwrap();
        let anchor = TrustedAnchor::open(dir.path()).unwrap();
        for path in ["", ".", "..", "../escape", "nested/../escape"] {
            assert!(anchor.target(path).is_err(), "accepted {path:?}");
        }
        anchor.target("one").unwrap();
        anchor.target_with_private_parents("nested/file").unwrap();
    }

    #[test]
    fn exact_replace_rejects_same_bytes_in_a_decoy_inode() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("state"), b"reviewed").unwrap();
        let anchor = TrustedAnchor::open(dir.path()).unwrap();
        let target = anchor.target("state").unwrap();
        let reviewed = target.read_regular().unwrap().unwrap();

        std::fs::rename(dir.path().join("state"), dir.path().join("owner")).unwrap();
        std::fs::write(dir.path().join("state"), b"reviewed").unwrap();
        target
            .replace_if_exact(Some(&reviewed), b"phantom")
            .unwrap_err();

        assert_eq!(
            std::fs::read(dir.path().join("state")).unwrap(),
            b"reviewed"
        );
        assert_eq!(
            std::fs::read(dir.path().join("owner")).unwrap(),
            b"reviewed"
        );
    }

    #[test]
    fn exact_unlink_rejects_decoy_and_preserves_it() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("state"), b"reviewed").unwrap();
        let anchor = TrustedAnchor::open(dir.path()).unwrap();
        let target = anchor.target("state").unwrap();
        let reviewed = target.read_regular().unwrap().unwrap();

        std::fs::rename(dir.path().join("state"), dir.path().join("owner")).unwrap();
        std::fs::write(dir.path().join("state"), b"reviewed").unwrap();
        target.unlink_if_exact(&reviewed).unwrap_err();
        assert_eq!(
            std::fs::read(dir.path().join("state")).unwrap(),
            b"reviewed"
        );
    }

    #[test]
    fn replace_sync_failure_returns_committed_receipt() {
        let dir = TempDir::new().unwrap();
        let anchor = TrustedAnchor::open(dir.path()).unwrap();
        let target = anchor.target("state").unwrap();
        inject_failure_once(TestFailurePoint::ReplaceParentSync);

        let outcome = target.replace_if_exact(None, b"published").unwrap();
        match outcome {
            AnchoredEffect::CommittedButUncertain { value, error } => {
                assert_eq!(value.bytes(), b"published");
                assert!(error.to_string().contains("ReplaceParentSync"));
            }
            AnchoredEffect::Durable(_) => panic!("injected sync failure reported durable"),
        }
        assert_eq!(
            std::fs::read(dir.path().join("state")).unwrap(),
            b"published"
        );
        assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".phantom-tmp-")));
    }

    #[test]
    fn anchored_read_and_effect_debug_are_value_redacted() {
        let dir = TempDir::new().unwrap();
        let anchor = TrustedAnchor::open(dir.path()).unwrap();
        let target = anchor.target("state").unwrap();
        let sentinel = b"super-secret-sentinel";
        let read = match target.replace_if_exact(None, sentinel).unwrap() {
            AnchoredEffect::Durable(read) => read,
            AnchoredEffect::CommittedButUncertain { .. } => panic!("unexpected uncertainty"),
        };
        let read_debug = format!("{read:?}");
        assert!(!read_debug.contains("super-secret-sentinel"));

        inject_failure_once(TestFailurePoint::ReplaceVerification);
        let effect = target.replace_if_exact(Some(&read), sentinel).unwrap();
        let effect_debug = format!("{effect:?}");
        assert!(!effect_debug.contains("super-secret-sentinel"));
    }

    #[test]
    fn replace_verification_failure_returns_committed_receipt() {
        let dir = TempDir::new().unwrap();
        let anchor = TrustedAnchor::open(dir.path()).unwrap();
        let target = anchor.target("state").unwrap();
        inject_failure_once(TestFailurePoint::ReplaceVerification);

        let outcome = target.replace_if_exact(None, b"published").unwrap();
        assert!(matches!(
            outcome,
            AnchoredEffect::CommittedButUncertain { .. }
        ));
        assert_eq!(
            std::fs::read(dir.path().join("state")).unwrap(),
            b"published"
        );
    }

    #[test]
    fn unlink_sync_failure_returns_committed_receipt() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("state"), b"reviewed").unwrap();
        let anchor = TrustedAnchor::open(dir.path()).unwrap();
        let target = anchor.target("state").unwrap();
        let reviewed = target.read_regular().unwrap().unwrap();
        inject_failure_once(TestFailurePoint::UnlinkParentSync);

        let outcome = target.unlink_if_exact(&reviewed).unwrap();
        assert!(matches!(
            outcome,
            AnchoredEffect::CommittedButUncertain { value: (), .. }
        ));
        assert!(!dir.path().join("state").exists());
    }

    #[cfg(unix)]
    #[test]
    fn exact_replace_preserves_or_sets_permissions_by_handle() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let state = dir.path().join("state");
        std::fs::write(&state, b"reviewed").unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o751)).unwrap();
        let anchor = TrustedAnchor::open(dir.path()).unwrap();
        let target = anchor.target("state").unwrap();
        let reviewed = target.read_regular().unwrap().unwrap();
        let preserved = reviewed.permissions();
        assert!(matches!(
            target
                .replace_if_exact_with_permissions(Some(&reviewed), b"updated", preserved)
                .unwrap(),
            AnchoredEffect::Durable(_)
        ));
        assert_eq!(
            std::fs::metadata(&state).unwrap().permissions().mode() & 0o7777,
            0o751
        );

        let executable = anchor.target("script").unwrap();
        assert!(matches!(
            executable
                .replace_if_exact_with_permissions(
                    None,
                    b"#!/bin/sh\n",
                    AnchoredFilePermissions::executable(),
                )
                .unwrap(),
            AnchoredEffect::Durable(_)
        ));
        assert_eq!(
            std::fs::metadata(dir.path().join("script"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o755
        );
    }

    #[cfg(unix)]
    #[test]
    fn created_directory_removal_rejects_decoy_identity() {
        let dir = TempDir::new().unwrap();
        let anchor = TrustedAnchor::open(dir.path()).unwrap();
        let created = match anchor.create_private_child("created").unwrap() {
            AnchoredDirectoryCreation::Durable(created) => created,
            AnchoredDirectoryCreation::CommittedButUncertain { .. } => {
                panic!("unexpected uncertainty")
            }
        };
        std::fs::rename(dir.path().join("created"), dir.path().join("owner")).unwrap();
        std::fs::create_dir(dir.path().join("created")).unwrap();

        created.remove_if_empty_exact().unwrap_err();
        assert!(dir.path().join("created").is_dir());
        assert!(dir.path().join("owner").is_dir());
    }

    #[test]
    fn created_directory_sync_failures_return_effect_receipts() {
        let dir = TempDir::new().unwrap();
        let anchor = TrustedAnchor::open(dir.path()).unwrap();
        inject_failure_once(TestFailurePoint::CreateDirectoryParentSync);
        let created = match anchor.create_private_child("created").unwrap() {
            AnchoredDirectoryCreation::CommittedButUncertain {
                receipt: Some(value),
                error,
            } => {
                assert!(error.to_string().contains("CreateDirectoryParentSync"));
                value
            }
            AnchoredDirectoryCreation::CommittedButUncertain { receipt: None, .. } => {
                panic!("created directory receipt was lost")
            }
            AnchoredDirectoryCreation::Durable(_) => {
                panic!("injected create sync failure reported durable")
            }
        };
        assert!(dir.path().join("created").is_dir());

        inject_failure_once(TestFailurePoint::RemoveDirectoryParentSync);
        let removed = created.remove_if_empty_exact().unwrap();
        assert!(matches!(
            removed,
            AnchoredEffect::CommittedButUncertain { value: (), .. }
        ));
        assert!(!dir.path().join("created").exists());
    }

    #[test]
    fn post_create_retention_failure_is_rolled_back_before_error() {
        for point in [
            TestFailurePoint::CreateDirectoryOpen,
            TestFailurePoint::CreateDirectoryIdentity,
        ] {
            let dir = TempDir::new().unwrap();
            let anchor = TrustedAnchor::open(dir.path()).unwrap();
            inject_failure_once(point);
            anchor.create_private_child("created").unwrap_err();
            assert!(
                !dir.path().join("created").exists(),
                "outer error left a namespace effect for {point:?}"
            );
        }
    }

    #[test]
    fn uncertain_post_create_cleanup_has_typed_unknown_receipt() {
        let dir = TempDir::new().unwrap();
        let anchor = TrustedAnchor::open(dir.path()).unwrap();
        inject_failure_once(TestFailurePoint::CreateDirectoryOpen);
        inject_failure_once(TestFailurePoint::CreateDirectoryRollbackRemove);

        let outcome = anchor.create_private_child("created").unwrap();
        match outcome {
            AnchoredDirectoryCreation::CommittedButUncertain {
                receipt: None,
                error,
            } => assert!(error.to_string().contains("cleanup is uncertain")),
            other => panic!("unexpected directory creation outcome: {other:?}"),
        }
        assert!(dir.path().join("created").is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn canonical_open_is_explicit_for_a_trusted_ambient_alias() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("real")).unwrap();
        symlink(dir.path().join("real"), dir.path().join("alias")).unwrap();

        assert!(TrustedAnchor::open(dir.path().join("alias")).is_err());
        let anchor = TrustedAnchor::open_canonical(dir.path().join("alias")).unwrap();
        let _outcome = anchor
            .target("state")
            .unwrap()
            .replace_if_exact(None, b"anchored")
            .unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("real/state")).unwrap(),
            b"anchored"
        );
    }

    #[cfg(unix)]
    #[test]
    fn retained_ancestor_ignores_path_swap_and_preserves_decoy() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("owned")).unwrap();
        std::fs::write(dir.path().join("owned/state"), b"reviewed").unwrap();
        let anchor = TrustedAnchor::open(dir.path()).unwrap();
        let target = anchor.target("owned/state").unwrap();
        let reviewed = target.read_regular().unwrap().unwrap();

        std::fs::rename(dir.path().join("owned"), dir.path().join("moved")).unwrap();
        std::fs::create_dir(dir.path().join("owned")).unwrap();
        std::fs::write(dir.path().join("owned/state"), b"decoy").unwrap();
        let _outcome = target
            .replace_if_exact(Some(&reviewed), b"published")
            .unwrap();

        assert_eq!(
            std::fs::read(dir.path().join("moved/state")).unwrap(),
            b"published"
        );
        assert_eq!(
            std::fs::read(dir.path().join("owned/state")).unwrap(),
            b"decoy"
        );
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_derived_subanchor_survives_directory_name_swap() {
        let dir = TempDir::new().unwrap();
        let base = TrustedAnchor::open(dir.path()).unwrap();
        let vaults = base.private_subdirectory("vaults").unwrap();
        std::fs::write(dir.path().join("vaults/state"), b"reviewed").unwrap();
        let state = vaults.target("state").unwrap();
        let reviewed = state.read_regular().unwrap().unwrap();

        std::fs::rename(dir.path().join("vaults"), dir.path().join("moved")).unwrap();
        std::fs::create_dir(dir.path().join("vaults")).unwrap();
        std::fs::write(dir.path().join("vaults/state"), b"decoy").unwrap();
        let _outcome = state
            .replace_if_exact(Some(&reviewed), b"published")
            .unwrap();

        assert_eq!(
            std::fs::read(dir.path().join("moved/state")).unwrap(),
            b"published"
        );
        assert_eq!(
            std::fs::read(dir.path().join("vaults/state")).unwrap(),
            b"decoy"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_ancestor_and_leaf_are_rejected() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("real")).unwrap();
        std::fs::write(dir.path().join("real/owner"), b"owner").unwrap();
        symlink(dir.path().join("real"), dir.path().join("linked-dir")).unwrap();
        symlink(
            dir.path().join("real/owner"),
            dir.path().join("linked-file"),
        )
        .unwrap();
        let anchor = TrustedAnchor::open(dir.path()).unwrap();

        assert!(anchor.target("linked-dir/owner").is_err());
        assert!(anchor
            .target("linked-file")
            .unwrap()
            .read_regular()
            .is_err());
        assert_eq!(
            std::fs::read(dir.path().join("real/owner")).unwrap(),
            b"owner"
        );
    }

    #[cfg(unix)]
    #[test]
    fn hard_link_is_rejected_without_touching_owner() {
        let dir = TempDir::new().unwrap();
        let owner = dir.path().join("owner");
        std::fs::write(&owner, b"owner").unwrap();
        std::fs::hard_link(&owner, dir.path().join("state")).unwrap();
        let anchor = TrustedAnchor::open(dir.path()).unwrap();
        let target = anchor.target("state").unwrap();

        assert!(target.read_regular().is_err());
        assert_eq!(std::fs::read(owner).unwrap(), b"owner");
    }

    #[cfg(unix)]
    #[test]
    fn private_creation_repairs_modes_by_handle() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("private")).unwrap();
        std::fs::set_permissions(
            dir.path().join("private"),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        let anchor = TrustedAnchor::open(dir.path()).unwrap();
        let target = anchor
            .target_with_private_parents("private/nested/state")
            .unwrap();
        let _outcome = target.replace_if_exact(None, b"secret").unwrap();

        for path in ["private", "private/nested"] {
            let mode = std::fs::metadata(dir.path().join(path))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700);
        }
        let mode = std::fs::metadata(dir.path().join("private/nested/state"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        std::fs::set_permissions(
            dir.path().join("private/nested/state"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(target.repair_private_regular().unwrap());
        assert!(!target.repair_private_regular().unwrap());
    }

    #[test]
    fn lock_is_anchored_private_and_stable() {
        let dir = TempDir::new().unwrap();
        let anchor = TrustedAnchor::open(dir.path()).unwrap();
        let lock = anchor.acquire_lock("locks/state.lock").unwrap();
        let target = anchor.target("locks/state.lock").unwrap();
        let current = target.read_regular().unwrap().unwrap();
        assert_eq!(current.identity(), lock.identity());
        lock.unlock().unwrap();
    }

    #[test]
    fn windows_contract_retains_non_delete_shared_handles_and_reparse_guards() {
        let source = include_str!("anchored.rs");
        assert!(source.contains("FILE_SHARE_READ | FILE_SHARE_WRITE"));
        assert!(source.contains("Intentionally omit FILE_SHARE_DELETE"));
        assert!(source.contains("FILE_FLAG_OPEN_REPARSE_POINT"));
        assert!(source.contains("open_dir_nofollow"));
        assert!(source.contains("GetFileInformationByHandle"));
        assert!(source.contains("Dir::rename is specified to replace an existing file"));
        assert!(source.contains("create_dir_with(name, &builder)"));
        assert!(source.contains("builder.mode(PRIVATE_DIRECTORY_MODE)"));
        assert!(source.contains("let mut first_bytes = Zeroizing::new(Vec::new())"));
        assert!(source.contains("let mut second_bytes = Zeroizing::new(Vec::new())"));
        assert!(
            source.contains("#[cfg(not(unix))]\n            unix_mode: None"),
            "non-Unix permission intents must compare equal to handle reads"
        );
        assert!(source.contains("current.set_readonly(permissions.readonly)"));
        assert!(source.contains("file.set_permissions(current)"));

        let close = source
            .find("drop(temp.take().expect(\"staging handle is live\"))")
            .expect("staging handle must close before commit");
        let rename = source[close..]
            .find(".rename(&temp_name")
            .map(|offset| offset + close)
            .expect("anchored rename must publish staging");
        assert!(close < rename, "Windows staging handle must close first");
        let recheck = source[close..]
            .find("require_temp_exact(")
            .map(|offset| offset + close)
            .expect("closed staging path must be revalidated before rename");
        assert!(
            close < recheck && recheck < rename,
            "staging identity and bytes must be revalidated at commit edge"
        );
        assert!(
            source[recheck..rename].contains("permissions,"),
            "staging permissions must be part of the pre-publish exact check"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_normal_replace_can_report_durable() {
        let dir = TempDir::new().unwrap();
        let anchor = TrustedAnchor::open(dir.path()).unwrap();
        let outcome = anchor
            .target("state")
            .unwrap()
            .replace_if_exact(None, b"published")
            .unwrap();
        assert!(matches!(outcome, AnchoredEffect::Durable(_)));
    }

    #[cfg(windows)]
    #[test]
    fn windows_readonly_attribute_round_trips_by_handle() {
        let dir = TempDir::new().unwrap();
        let anchor = TrustedAnchor::open(dir.path()).unwrap();
        let target = anchor.target("state").unwrap();
        let read = match target.replace_if_exact(None, b"published").unwrap() {
            AnchoredEffect::Durable(read) => read,
            AnchoredEffect::CommittedButUncertain { .. } => panic!("unexpected uncertainty"),
        };
        let file = open_regular(target.parent(), &target.leaf, target.relative_path()).unwrap();
        apply_file_permissions(
            &file,
            AnchoredFilePermissions {
                unix_mode: None,
                readonly: true,
            },
        )
        .unwrap();
        assert!(file_permissions(&file).unwrap().readonly);
        assert_ne!(target.read_regular().unwrap().unwrap(), read);
    }
}
