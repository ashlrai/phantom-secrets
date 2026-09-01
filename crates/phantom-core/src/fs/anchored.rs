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
use cap_std::fs::{Dir, File, OpenOptions};
use fs2::FileExt as _;
use rand::RngCore;

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

/// An exact, value-bearing before-image read through an anchored handle.
///
/// The identity is intentionally part of equality: replacing a file with a
/// byte-for-byte decoy is still drift and is rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchoredRead {
    bytes: Vec<u8>,
    identity: FileIdentity,
}

impl AnchoredRead {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn identity(&self) -> FileIdentity {
        self.identity
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// A retained capability for one trusted directory tree.
pub struct TrustedAnchor {
    directories: Vec<Dir>,
    identity: FileIdentity,
    display_path: PathBuf,
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
                    match current.create_dir(component) {
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
    ) -> io::Result<AnchoredRead> {
        self.require_exact(expected)?;
        let (temp_name, temp, temp_identity) = self.create_private_temp()?;
        let mut temp = Some(temp);
        let result = (|| {
            let staging = temp.as_mut().expect("staging handle is live");
            staging.write_all(contents)?;
            repair_private_file(staging)?;
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
                &self.relative,
            )?;
            // cap-std Dir::rename is specified to replace an existing file;
            // on Windows 3.4.6 resolves against retained directory handles and
            // delegates to std::fs::rename (MoveFileExW replacement semantics).
            self.parent()
                .rename(&temp_name, self.parent(), &self.leaf)?;
            sync_directory(self.parent())?;
            let published = self
                .read_regular()?
                .ok_or_else(|| drift_error(&self.relative))?;
            if published.bytes != contents {
                return Err(drift_error(&self.relative));
            }
            Ok(published)
        })();

        drop(temp.take());
        if result.is_err() {
            remove_if_identity(self.parent(), &temp_name, temp_identity);
        }
        result
    }

    /// Remove the target only when it still has the exact reviewed identity
    /// and bytes. Missing, replaced, linked, or modified targets are rejected.
    pub fn unlink_if_exact(&self, expected: &AnchoredRead) -> io::Result<()> {
        self.require_exact(Some(expected))?;
        // One last independent handle-bound comparison immediately before the
        // relative unlink. Domain callers must hold their transaction lock.
        self.require_exact(Some(expected))?;
        self.parent().remove_file(&self.leaf)?;
        sync_directory(self.parent())
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
    let mut first_bytes = Vec::new();
    first.read_to_end(&mut first_bytes)?;

    let mut second = open_regular(parent, leaf, display)?;
    if file_identity(&second)? != first_identity {
        return Err(drift_error(display));
    }
    let mut second_bytes = Vec::new();
    second.read_to_end(&mut second_bytes)?;
    if second_bytes != first_bytes {
        return Err(drift_error(display));
    }
    Ok(Some(AnchoredRead {
        bytes: first_bytes,
        identity: first_identity,
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
    display: &Path,
) -> io::Result<()> {
    let current = read_regular_at(parent, name, display)?
        .ok_or_else(|| io::Error::other("anchored staging file disappeared before commit"))?;
    if current.identity != identity || current.bytes != contents {
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
    use std::os::fd::AsRawFd;
    if unsafe { libc::fchmod(file.as_raw_fd(), PRIVATE_FILE_MODE as libc::mode_t) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn repair_private_file(_file: &File) -> io::Result<()> {
    Ok(())
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

    #[cfg(unix)]
    #[test]
    fn canonical_open_is_explicit_for_a_trusted_ambient_alias() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("real")).unwrap();
        symlink(dir.path().join("real"), dir.path().join("alias")).unwrap();

        assert!(TrustedAnchor::open(dir.path().join("alias")).is_err());
        let anchor = TrustedAnchor::open_canonical(dir.path().join("alias")).unwrap();
        anchor
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
        target
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
        state
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
        target.replace_if_exact(None, b"secret").unwrap();

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
    }
}
