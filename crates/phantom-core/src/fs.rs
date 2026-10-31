//! Filesystem helpers for secret-bearing writes.
//!
//! The central primitive is [`atomic_write`]: it writes content to a temp file
//! next to the target, fsyncs, then renames over the target. On POSIX the
//! temp file is created with mode 0o600 (tempfile's default) so the plaintext
//! never lives on disk with a wider default umask during the write window.
//!
//! Callers should use this for every write that touches secrets or that must
//! survive a crash / `kill -9` mid-write (e.g. `.env`, `.phantom.toml`, and
//! the vault file).

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

pub mod anchored;
mod private_dir;
pub use anchored::{
    AnchoredCreatedDirectory, AnchoredDirectoryCreation, AnchoredEffect, AnchoredFilePermissions,
    AnchoredLock, AnchoredRead, AnchoredTarget, FileIdentity, TrustedAnchor,
};
pub use private_dir::PrivateStateDir;

/// Atomically write `contents` to `path`.
///
/// Writes to a same-directory temp file, fsyncs, then renames over the target.
/// Rename within one filesystem is atomic on POSIX; on Windows Rust's
/// `fs::rename` uses `MoveFileEx` with `MOVEFILE_REPLACE_EXISTING` so it
/// overwrites atomically for files on the same volume.
///
/// On POSIX the temp file is created with mode 0o600 by `tempfile`, so secrets
/// are never visible to group/other during the write window.
pub fn atomic_write(path: &Path, contents: &[u8]) -> io::Result<()> {
    atomic_write_with_permissions(path, contents, None)
}

/// Read a regular file without following a symlink at the final path.
///
/// An absent path returns `Ok(None)`. Directories, device files, FIFOs, and
/// symlinks are rejected so callers can safely bind an exact before-image to a
/// later [`atomic_write_if_unchanged`] call.
pub fn read_regular_file(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(io::Error::other(format!(
                "refusing non-regular or symlink file target: {}",
                path.display()
            )))
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    }

    // The lookup above is an early answer only; the open below re-checks on
    // the handle, which is what decides.
    let mut file = match open_regular_nofollow(path) {
        Ok(Some(file)) => file,
        Ok(None) => return Ok(None),
        Err(RegularOpenError::NotRegular) => {
            return Err(io::Error::other(format!(
                "refusing non-regular or symlink file target: {}",
                path.display()
            )))
        }
        Err(RegularOpenError::Reopen(detail)) => {
            return Err(io::Error::other(format!(
                "refusing Windows reparse-point file target ({detail}): {}",
                path.display()
            )))
        }
        Err(RegularOpenError::Open(error) | RegularOpenError::Inspect(error)) => return Err(error),
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;

    // Re-inspect the pathname after reading. Atomic replacement by an
    // uncooperative same-user process cannot be made impossible with portable
    // pathname APIs, but an observable swap is rejected before these bytes are
    // accepted as the reviewed before-image.
    ensure_path_still_names_open_file(path, &file)?;
    Ok(Some(bytes))
}

/// Why [`open_regular_nofollow`] gave no handle.
#[derive(Debug)]
pub(crate) enum RegularOpenError {
    /// A symlink, junction, directory, FIFO, device or other non-regular file.
    NotRegular,
    /// Windows: a reparse file that is not a link (a OneDrive/Cloud Files
    /// file, a deduplicated file) whose contents could not be reopened from
    /// the same handle. The text says why.
    #[cfg_attr(not(windows), allow(dead_code))]
    Reopen(String),
    /// The open itself failed for another reason.
    Open(io::Error),
    /// The opened handle could not be inspected.
    Inspect(io::Error),
}

/// Open `path` read-only without following a final symlink, then confirm on
/// the opened handle (fstat, not a second path lookup) that it is a regular
/// file. `Ok(None)` when nothing is there.
///
/// On Unix the open uses `O_NOFOLLOW | O_NONBLOCK | O_NOCTTY`: a FIFO swapped
/// in is refused rather than waited on, and a terminal device cannot become
/// the controlling terminal before it is refused. On Windows it uses
/// `FILE_FLAG_OPEN_REPARSE_POINT`; a symlink or junction is refused, and any
/// other reparse file is reopened from the same handle for its real contents
/// (see [`windows_reopen_contents`]).
pub(crate) fn open_regular_nofollow(
    path: &Path,
) -> Result<Option<std::fs::File>, RegularOpenError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        // O_NOFOLLOW on a symlink: ELOOP on Linux and macOS, EMLINK on FreeBSD.
        #[cfg(unix)]
        Err(error) if matches!(error.raw_os_error(), Some(libc::ELOOP) | Some(libc::EMLINK)) => {
            return Err(RegularOpenError::NotRegular)
        }
        Err(error) => return Err(RegularOpenError::Open(error)),
    };
    let metadata = file.metadata().map_err(RegularOpenError::Inspect)?;
    // On Windows `is_symlink()` covers every name-surrogate reparse point:
    // symlinks and junctions.
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RegularOpenError::NotRegular);
    }
    #[cfg(windows)]
    if is_reparse_point(&metadata) {
        return windows_reopen_contents(&file).map(Some);
    }
    Ok(Some(file))
}

#[cfg(windows)]
pub(crate) fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// A non-name-surrogate reparse file: a OneDrive/Cloud Files file (hydrated
/// files keep the tag, so a project under a synced folder is full of them), a
/// deduplicated file, an app execution alias. Opened with
/// FILE_FLAG_OPEN_REPARSE_POINT it reads as its stub. ReOpenFile without that
/// flag re-opens the same file object, with no new path lookup, so the filter
/// serves the real contents. The reopen must be the same file object and
/// still a regular file; a failed reopen is a refusal.
#[cfg(windows)]
pub(crate) fn windows_reopen_contents(
    file: &std::fs::File,
) -> Result<std::fs::File, RegularOpenError> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Win32::Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        ReOpenFile, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let before = anchored::std_file_identity(file).map_err(RegularOpenError::Inspect)?;
    // SAFETY: the handle is owned by `file` and valid for the call; the
    // returned handle, when valid, is owned by the File built from it.
    let handle = unsafe {
        ReOpenFile(
            file.as_raw_handle(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(RegularOpenError::Reopen(format!(
            "Windows could not reopen the reparse point for its contents: {}",
            io::Error::last_os_error()
        )));
    }
    // SAFETY: `handle` is a valid handle that nothing else owns.
    let reopened = unsafe { std::fs::File::from_raw_handle(handle) };
    // The reopen must be the same file object the checks judged, as
    // fs/anchored.rs requires of its own reopens.
    let after = anchored::std_file_identity(&reopened).map_err(RegularOpenError::Inspect)?;
    if after != before {
        return Err(RegularOpenError::Reopen(
            "Windows reopened a different file object".to_string(),
        ));
    }
    let metadata = reopened.metadata().map_err(RegularOpenError::Inspect)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RegularOpenError::NotRegular);
    }
    Ok(reopened)
}

#[cfg(unix)]
fn ensure_path_still_names_open_file(path: &Path, opened: &std::fs::File) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let original = opened.metadata()?;
    let mut options = std::fs::OpenOptions::new();
    use std::os::unix::fs::OpenOptionsExt;
    // Same flags as the first open: a FIFO swapped in after the read must
    // fail the identity check, not wait for a writer, and a terminal device
    // must not become the controlling terminal.
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY);
    let current = options.open(path)?.metadata()?;
    if original.dev() != current.dev() || original.ino() != current.ino() {
        return Err(io::Error::other(format!(
            "file target changed while it was being read: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn ensure_path_still_names_open_file(path: &Path, opened: &std::fs::File) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;

    let original = windows_file_information(opened)?;
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    let current = options.open(path)?;
    // A link now at the path is a swap. Any other reparse file (a OneDrive
    // file) is the same object as long as its identity matches.
    let current_type = current.metadata()?.file_type();
    let current = windows_file_information(&current)?;
    if current_type.is_symlink()
        || !current_type.is_file()
        || original.dwVolumeSerialNumber != current.dwVolumeSerialNumber
        || original.nFileIndexHigh != current.nFileIndexHigh
        || original.nFileIndexLow != current.nFileIndexLow
    {
        return Err(io::Error::other(format!(
            "file target changed while it was being read: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn ensure_path_still_names_open_file(path: &Path, _opened: &std::fs::File) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_symlink() && metadata.is_file() => Ok(()),
        Ok(_) => Err(io::Error::other(format!(
            "file target changed to an unsafe object while being read: {}",
            path.display()
        ))),
        Err(error) => Err(error),
    }
}

#[cfg(windows)]
fn windows_file_information(
    file: &std::fs::File,
) -> io::Result<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION> {
    use std::os::windows::io::AsRawHandle;

    let mut information = unsafe { std::mem::zeroed() };
    let result = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(
            file.as_raw_handle(),
            &mut information,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(information)
}

/// Atomically replace `path` only if its bytes still equal `expected_before`.
///
/// Callers should hold the appropriate Phantom transaction lock from their
/// initial read through this commit. The exact re-check also rejects edits by
/// cooperative writers that occurred before the lock was acquired. Existing
/// permissions are applied to the staging file before it is published.
pub fn atomic_write_if_unchanged(
    path: &Path,
    expected_before: Option<&[u8]>,
    contents: &[u8],
) -> io::Result<()> {
    // The before-image can be `.env` plaintext: wipe it when dropped.
    let current = read_regular_file(path)?.map(zeroize::Zeroizing::new);
    if current.as_ref().map(|bytes| bytes.as_slice()) != expected_before {
        return Err(io::Error::other(format!(
            "file changed after it was read; refusing to overwrite {}",
            path.display()
        )));
    }
    let permissions = match std::fs::symlink_metadata(path) {
        Ok(metadata) => Some(metadata.permissions()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    atomic_write_with_permissions(path, contents, permissions)
}

/// Create missing parent directories one component at a time while rejecting
/// symlinks or non-directory objects at every path that is inspected.
///
/// A directory this call creates inside Phantom's state tree (one named
/// `.phantom`, or any directory beneath one, such as `~/.phantom/shadows`) is
/// created 0700 on Unix; other missing directories get ordinary umask
/// permissions. An existing Phantom state directory on the way to `path`
/// that is a real directory owned by the current user is tightened to 0700
/// if it has group or other bits; one owned by someone else, or any state
/// directory reached through a symlinked `.phantom` ancestor, is left as it
/// is. Existing directories outside a `.phantom` tree (the home directory or
/// project root) are never chmod-ed.
pub fn ensure_real_parent(path: &Path) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "safe file target has no parent directory",
        )
    })?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let mut missing: Vec<PathBuf> = Vec::new();
    let mut cursor = parent;
    loop {
        match std::fs::symlink_metadata(cursor) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(io::Error::other(format!(
                    "file target parent is not a real directory: {}",
                    cursor.display()
                )))
            }
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(cursor.to_path_buf());
                cursor = cursor.parent().ok_or_else(|| {
                    io::Error::other("could not find an existing parent directory")
                })?;
            }
            Err(error) => return Err(error),
        }
    }
    missing.reverse();
    for directory in missing {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        if is_phantom_state_path(&directory) {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let metadata = std::fs::symlink_metadata(&directory)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(io::Error::other(format!(
                        "file target parent became unsafe: {}",
                        directory.display()
                    )));
                }
            }
            Err(error) => return Err(error),
        }
    }
    #[cfg(unix)]
    tighten_phantom_state_dirs(parent)?;
    Ok(())
}

/// Whether `path` is a `.phantom` directory or lies beneath one: Phantom's
/// own state tree, whose newly created directories are kept private.
#[cfg(unix)]
fn is_phantom_state_path(path: &Path) -> bool {
    path.components().any(
        |component| matches!(component, std::path::Component::Normal(name) if name == ".phantom"),
    )
}

/// Tighten every existing Phantom state directory from the outermost
/// `.phantom` down to `directory` (inclusive) to 0700, so state written by an
/// older release under a 0755 `~/.phantom` stops being listable by other
/// local users. Walks top-down and stops at the first symlink or
/// non-directory, so nothing reached through a redirected `.phantom` tree is
/// chmod-ed. Directories above the `.phantom` component are never touched.
#[cfg(unix)]
fn tighten_phantom_state_dirs(directory: &Path) -> io::Result<()> {
    // `~/.phantom/..` names the home directory, not Phantom state.
    if directory
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Ok(());
    }
    let mut chain: Vec<&Path> = directory
        .ancestors()
        .take_while(|ancestor| is_phantom_state_path(ancestor))
        .collect();
    chain.reverse();
    for state_directory in chain {
        match std::fs::symlink_metadata(state_directory) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            _ => return Ok(()),
        }
        match tighten_owned_directory(state_directory) {
            Ok(()) => {}
            // Swapped for a symlink or non-directory since the lookup: stop
            // without chmod-ing anything beneath it.
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ELOOP) | Some(libc::ENOTDIR)
                ) =>
            {
                return Ok(())
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Chmod `path` to 0700 if it is a real directory owned by the current user
/// with any group or other bits. The check and the chmod go through one
/// `O_NOFOLLOW` handle so a swap after the caller's lookup cannot redirect
/// the chmod; a directory owned by someone else is left as it is.
#[cfg(unix)]
fn tighten_owned_directory(path: &Path) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = directory.metadata()?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let owned = metadata.uid() == unsafe { libc::geteuid() };
    if owned && metadata.mode() & 0o077 != 0 {
        // SAFETY: the descriptor is owned by `directory` and open.
        if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Open a Phantom-owned directory without following a symlink at `name`.
///
/// With `parent` set, `name` must be one plain path component and is opened
/// relative to that directory descriptor; without it, `name` is a path whose
/// ancestors resolve normally (so a symlinked data or temp directory keeps
/// working) and only the final component is judged. The result must be a
/// real directory owned by the current user and, when `require_private`,
/// have no group or other access. Anything else is refused with
/// `ErrorKind::InvalidData`; an absent entry is `ErrorKind::NotFound`.
///
/// Callers chain these descriptors and finish with [`open_owned_file_at`] so
/// a directory swapped after an earlier path-based check cannot redirect the
/// final open.
#[cfg(unix)]
pub fn open_owned_directory(
    parent: Option<&std::fs::File>,
    name: &Path,
    require_private: bool,
) -> io::Result<std::fs::File> {
    use std::os::unix::fs::MetadataExt;
    let directory = open_nofollow_at(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )?;
    let metadata = directory.metadata()?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_dir()
        || metadata.uid() != effective_uid
        || (require_private && metadata.mode() & 0o077 != 0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Phantom directory is not a private directory owned by the current user: {}",
                name.display()
            ),
        ));
    }
    Ok(directory)
}

/// Open (and with `create`, create with mode 0600) the regular file `name`
/// inside `directory`, relative to that descriptor and without following a
/// symlink. The file is opened read-write and close-on-exec; one that is not
/// a regular file or is owned by another user is refused with
/// `ErrorKind::InvalidData`. An existing file is never truncated.
#[cfg(unix)]
pub fn open_owned_file_at(
    directory: &std::fs::File,
    name: &Path,
    create: bool,
) -> io::Result<std::fs::File> {
    use std::os::unix::fs::MetadataExt;
    let mut flags =
        libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY;
    if create {
        flags |= libc::O_CREAT;
    }
    let file = open_nofollow_at(Some(directory), name, flags, 0o600)?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Phantom file is not a regular file owned by the current user: {}",
                name.display()
            ),
        ));
    }
    Ok(file)
}

#[cfg(unix)]
fn open_nofollow_at(
    parent: Option<&std::fs::File>,
    name: &Path,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    let single_component = matches!(
        name.components().collect::<Vec<_>>().as_slice(),
        [std::path::Component::Normal(_)]
    ) && !name.as_os_str().as_bytes().contains(&b'/');
    if parent.is_some() && !single_component {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("not a single path component: {}", name.display()),
        ));
    }
    let c_name = std::ffi::CString::new(name.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path contains a NUL byte: {}", name.display()),
        )
    })?;
    let directory_fd = parent.map_or(libc::AT_FDCWD, |parent| parent.as_raw_fd());
    // SAFETY: `directory_fd` is AT_FDCWD or a descriptor borrowed for this
    // call, and `c_name` is NUL-terminated.
    let descriptor = unsafe {
        libc::openat(
            directory_fd,
            c_name.as_ptr(),
            flags,
            libc::c_uint::from(mode),
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new descriptor that nothing else owns.
    Ok(unsafe { std::fs::File::from_raw_fd(descriptor) })
}

/// Create `path` as a new file holding `contents`, never replacing anything.
///
/// The bytes are staged in a same-directory temp file (mode 0600 on POSIX),
/// fsynced, then published with a no-replace link/rename. If any object,
/// including a dangling symlink, already holds the name, this returns
/// `ErrorKind::AlreadyExists` and leaves that object untouched.
pub fn write_new_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    ensure_real_parent(path)?;
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let mut tmp = NamedTempFile::new_in(dir)?;
    tmp.write_all(contents)?;
    tmp.as_file_mut().sync_all()?;
    tmp.persist_noclobber(path).map_err(|e| e.error)?;
    sync_parent_dir(dir)
}

/// Create Phantom's own state directory (for example `~/.phantom`) if it is
/// missing and keep it private.
///
/// Missing ancestors are created as [`ensure_real_parent`] does (0700 when
/// they are inside a `.phantom` tree, so `~/.phantom/shadows/<project>`
/// leaves `~/.phantom` and `~/.phantom/shadows` private too, and existing
/// owned ones are tightened); the final
/// directory is created with mode 0700 on Unix. A symlink or non-directory at
/// `path` is refused. An existing directory owned by the current user is
/// tightened to 0700; one owned by someone else is left as it is.
pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
    ensure_real_parent(path)?;
    ensure_private_leaf_dir(path)
}

/// Create Phantom's own directory `path` inside an existing parent and keep
/// it private, without judging the parent chain.
///
/// Unlike [`ensure_private_dir`], ancestors are resolved normally, so a user
/// whose `~/.local/share` (or `XDG_DATA_HOME`) or temp directory is itself a
/// symlink keeps working. Only the final component is Phantom's: it is
/// created with mode 0700 on Unix, a symlink or non-directory there is
/// refused, and an existing directory owned by the current user is tightened
/// to 0700 through a no-follow descriptor. One owned by someone else is left
/// as it is; callers that need sole ownership check that themselves.
pub fn ensure_private_leaf_dir(path: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::other(format!(
            "Phantom state directory is not a real directory: {}",
            path.display()
        )));
    }
    // Judge and repair through one handle so a swap after the lookup above
    // cannot redirect the chmod.
    #[cfg(unix)]
    tighten_owned_directory(path)?;
    Ok(())
}

/// Validate a user-supplied output as one project-relative filename.
///
/// This deliberately excludes directory separators and `..` anywhere in the
/// value. It is intended for narrow generated artifacts such as `.env.example`,
/// not for general path selection.
pub fn validate_project_filename(value: &str) -> io::Result<()> {
    if value.is_empty()
        || value == "."
        || value.contains("..")
        || value.contains('/')
        || value.contains('\\')
        || Path::new(value).is_absolute()
        || !matches!(
            Path::new(value).components().collect::<Vec<_>>().as_slice(),
            [std::path::Component::Normal(_)]
        )
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "output must be one safe project-relative filename without separators or `..`",
        ));
    }
    Ok(())
}

fn atomic_write_with_permissions(
    path: &Path,
    contents: &[u8],
    permissions: Option<std::fs::Permissions>,
) -> io::Result<()> {
    ensure_real_parent(path)?;
    let dir = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic_write: path has no parent directory",
        )
    })?;
    // `Path::new(".env").parent()` is the empty path, which means the current
    // directory to path resolution but is not accepted by `open(2)` or
    // `NamedTempFile::new_in`. Preserve relative-target semantics explicitly.
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };

    // Using NamedTempFile::new_in keeps the temp on the same filesystem as the
    // target, which is required for rename() to be atomic on POSIX.
    let mut tmp = NamedTempFile::new_in(dir)?;
    tmp.write_all(contents)?;
    if let Some(permissions) = permissions {
        tmp.as_file().set_permissions(permissions)?;
    }
    tmp.as_file_mut().sync_all()?;

    // persist consumes the NamedTempFile and renames into place; on error we
    // return the underlying io::Error (the unpersisted temp is cleaned up).
    tmp.persist(path).map_err(|e| e.error)?;
    sync_parent_dir(dir)?;
    Ok(())
}

/// Persist a directory entry update on platforms that support syncing an open
/// directory. This closes the common POSIX crash window where the file bytes
/// are durable but the final rename is not. Windows does not expose the same
/// directory-handle contract through `std`, so callers must not infer a
/// cross-platform durability guarantee from this helper.
#[cfg(unix)]
pub fn sync_parent_dir(dir: &Path) -> io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
pub fn sync_parent_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn write_new_file_creates_and_never_replaces() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("new");
        write_new_file(&target, b"first").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"first");
        let error = write_new_file(&target, b"second").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&target).unwrap(), b"first");
    }

    #[cfg(unix)]
    #[test]
    fn write_new_file_is_private_and_refuses_a_dangling_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("new");
        write_new_file(&target, b"x").unwrap();
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let link = dir.path().join("link");
        let pointee = dir.path().join("pointee");
        std::os::unix::fs::symlink(&pointee, &link).unwrap();
        let error = write_new_file(&link, b"y").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(!pointee.exists());
    }

    #[cfg(unix)]
    #[test]
    fn ensure_private_dir_creates_tightens_and_refuses_links() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let state = dir.path().join("home/.phantom");
        ensure_private_dir(&state).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&state), 0o700);

        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&state).unwrap();
        assert_eq!(mode(&state), 0o700);

        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = dir.path().join("linked");
        std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
        assert!(ensure_private_dir(&link).is_err());
        assert_eq!(mode(&elsewhere), 0o755);

        let file = dir.path().join("plain");
        std::fs::write(&file, b"").unwrap();
        assert!(ensure_private_dir(&file).is_err());
    }

    /// Windows: `read_regular_file` shares the dotenv open. A plain file reads
    /// through the post-read identity check, and a file symlink is refused.
    /// The reparse reopen itself is driven in `managed_dotenv`'s tests (a
    /// Cloud Files placeholder needs a sync provider a CI runner lacks).
    #[cfg(windows)]
    #[test]
    fn windows_read_regular_file_reads_plain_and_refuses_a_symlink() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("target"), b"A=1\n").unwrap();
        assert_eq!(
            read_regular_file(&dir.path().join("target"))
                .unwrap()
                .unwrap(),
            b"A=1\n"
        );
        if std::os::windows::fs::symlink_file("target", dir.path().join(".env")).is_err() {
            eprintln!("skipping: cannot create a file symlink here");
            return;
        }
        let error = read_regular_file(&dir.path().join(".env")).unwrap_err();
        assert!(error.to_string().contains("symlink"), "{error}");
        assert!(matches!(
            open_regular_nofollow(&dir.path().join(".env")),
            Err(RegularOpenError::NotRegular)
        ));
    }

    /// A FIFO swapped in after the read fails the post-read check promptly
    /// instead of blocking that check's reopen until a writer appears.
    #[cfg(unix)]
    #[test]
    fn post_read_check_does_not_hang_on_a_fifo_swapped_in() {
        use std::os::unix::ffi::OsStrExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".env");
        std::fs::write(&path, b"A=1\n").unwrap();
        let opened = std::fs::File::open(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: c_path is a valid NUL-terminated path for the call's duration.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        let (sender, receiver) = std::sync::mpsc::channel();
        let check_path = path.clone();
        std::thread::spawn(move || {
            let _ = sender.send(ensure_path_still_names_open_file(&check_path, &opened).is_err());
        });
        let refused = receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the post-read check blocked on the FIFO");
        assert!(refused);
    }

    /// The shared open refuses a symlink from the open itself.
    #[cfg(unix)]
    #[test]
    fn open_regular_nofollow_refuses_a_symlink_and_a_fifo() {
        use std::os::unix::ffi::OsStrExt;
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("target"), b"A=1\n").unwrap();
        std::os::unix::fs::symlink("target", dir.path().join("link")).unwrap();
        assert!(matches!(
            open_regular_nofollow(&dir.path().join("link")),
            Err(RegularOpenError::NotRegular)
        ));
        let fifo = dir.path().join("fifo");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: c_path is a valid NUL-terminated path for the call's duration.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert!(matches!(
            open_regular_nofollow(&fifo),
            Err(RegularOpenError::NotRegular)
        ));
        assert!(open_regular_nofollow(&dir.path().join("absent"))
            .unwrap()
            .is_none());
    }

    fn list_dir(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn test_atomic_write_creates_new_file() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("new.env");
        atomic_write(&target, b"KEY=value\n").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"KEY=value\n");
    }

    #[test]
    fn test_atomic_write_overwrites_existing() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("x.env");
        std::fs::write(&target, b"OLD").unwrap();
        atomic_write(&target, b"NEW").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"NEW");
    }

    #[test]
    fn test_atomic_write_supports_relative_target_in_current_directory() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let target = std::path::PathBuf::from(format!(
            ".phantom-atomic-write-test-{}-{unique}",
            std::process::id()
        ));
        atomic_write(&target, b"KEY=value\n").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"KEY=value\n");
        std::fs::remove_file(target).unwrap();
    }

    #[test]
    fn test_atomic_write_leaves_no_temp_files_on_success() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("clean.env");
        atomic_write(&target, b"X").unwrap();
        let files = list_dir(dir.path());
        // Only the target should exist; no leftover .tmp / tmpXXX files.
        assert_eq!(files, vec!["clean.env"], "unexpected files: {files:?}");
    }

    #[test]
    fn test_atomic_write_rejects_path_without_parent() {
        let err = atomic_write(Path::new("/"), b"x").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[test]
    fn test_atomic_write_creates_file_with_0600_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("perm.env");
        atomic_write(&target, b"SECRET=xyz\n").unwrap();
        let mode = std::fs::metadata(&target).unwrap().permissions().mode();
        // tempfile creates with 0o600; persist preserves mode. Strip file-type
        // bits and compare the permission bits only.
        assert_eq!(mode & 0o777, 0o600, "got mode {:o}", mode & 0o777);
    }

    #[test]
    fn exact_write_rejects_concurrent_change() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("package.json");
        std::fs::write(&target, b"before").unwrap();
        let before = read_regular_file(&target).unwrap().unwrap();
        std::fs::write(&target, b"concurrent-owner").unwrap();

        let error = atomic_write_if_unchanged(&target, Some(&before), b"phantom").unwrap_err();
        assert!(error.to_string().contains("changed after it was read"));
        assert_eq!(std::fs::read(&target).unwrap(), b"concurrent-owner");
    }

    #[test]
    fn exact_write_rejects_target_that_appeared() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join(".env.example");
        assert!(read_regular_file(&target).unwrap().is_none());
        std::fs::write(&target, b"concurrent-owner").unwrap();

        atomic_write_if_unchanged(&target, None, b"phantom").unwrap_err();
        assert_eq!(std::fs::read(&target).unwrap(), b"concurrent-owner");
    }

    #[cfg(unix)]
    #[test]
    fn exact_write_rejects_symlink_target() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let owner = dir.path().join("owner");
        let target = dir.path().join("package.json");
        std::fs::write(&owner, b"owner").unwrap();
        symlink(&owner, &target).unwrap();

        let error = read_regular_file(&target).unwrap_err();
        assert!(error.to_string().contains("symlink"));
        assert_eq!(std::fs::read(&owner).unwrap(), b"owner");
    }

    /// Phantom state directories created on the way to a private directory
    /// (`~/.phantom`, `~/.phantom/shadows`) are 0700 like the final one. An
    /// existing ancestor (the home directory) keeps its mode, and a missing
    /// ancestor outside the Phantom state tree gets ordinary permissions.
    #[cfg(unix)]
    #[test]
    fn ensure_private_dir_creates_phantom_ancestors_private() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir = TempDir::new().unwrap();
        let reference = dir.path().join("reference");
        std::fs::create_dir(&reference).unwrap();
        let ordinary = mode(&reference);

        let home = dir.path().join("home");
        std::fs::create_dir(&home).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o751)).unwrap();
        let store = home.join(".phantom").join("shadows").join("project");
        ensure_private_dir(&store).unwrap();
        assert_eq!(mode(&home), 0o751);
        assert_eq!(mode(&home.join(".phantom")), 0o700);
        assert_eq!(mode(&home.join(".phantom").join("shadows")), 0o700);
        assert_eq!(mode(&store), 0o700);

        let missing_home = dir.path().join("fresh-home");
        ensure_private_dir(&missing_home.join(".phantom").join("reports")).unwrap();
        assert_eq!(mode(&missing_home), ordinary);
        assert_eq!(mode(&missing_home.join(".phantom")), 0o700);
    }

    /// `ensure_real_parent` applies the same rule to a file target's missing
    /// parents: inside a `.phantom` tree they are 0700, elsewhere ordinary.
    #[cfg(unix)]
    #[test]
    fn ensure_real_parent_creates_phantom_state_parents_private() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir = TempDir::new().unwrap();
        let reference = dir.path().join("reference");
        std::fs::create_dir(&reference).unwrap();
        let ordinary = mode(&reference);

        let state = dir.path().join("home").join(".phantom");
        ensure_real_parent(&state.join("backups").join("manifest.json")).unwrap();
        assert_eq!(mode(&dir.path().join("home")), ordinary);
        assert_eq!(mode(&state), 0o700);
        assert_eq!(mode(&state.join("backups")), 0o700);

        let plain = dir.path().join("project").join("out");
        ensure_real_parent(&plain.join("report.txt")).unwrap();
        assert_eq!(mode(&dir.path().join("project")), ordinary);
        assert_eq!(mode(&plain), ordinary);

        let lookalike = dir.path().join("x.phantom").join("sub");
        ensure_real_parent(&lookalike.join("f")).unwrap();
        assert_eq!(mode(&lookalike), ordinary);
    }

    /// An existing Phantom state directory left group/other accessible (by an
    /// older release or a loose umask) is tightened to 0700 when a file is
    /// written beneath it. The directory above the `.phantom` tree (the home
    /// or project root) keeps its mode.
    #[cfg(unix)]
    #[test]
    fn ensure_real_parent_tightens_existing_phantom_state_parents() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir = TempDir::new().unwrap();
        let home = dir.path().join("home");
        let state = home.join(".phantom");
        let backups = state.join("backups");
        std::fs::create_dir_all(&backups).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o751)).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&backups, std::fs::Permissions::from_mode(0o775)).unwrap();

        ensure_real_parent(&backups.join("manifest.json")).unwrap();
        assert_eq!(mode(&home), 0o751);
        assert_eq!(mode(&state), 0o700);
        assert_eq!(mode(&backups), 0o700);

        // A file directly inside an existing project `.phantom`.
        let project = dir.path().join("project");
        let project_state = project.join(".phantom");
        std::fs::create_dir_all(&project_state).unwrap();
        std::fs::set_permissions(&project, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&project_state, std::fs::Permissions::from_mode(0o755)).unwrap();
        atomic_write(&project_state.join("env"), b"dev").unwrap();
        assert_eq!(mode(&project), 0o755);
        assert_eq!(mode(&project_state), 0o700);

        // A `..` step out of the state tree never tightens what it names.
        let sibling = home.join("x");
        std::fs::create_dir(&sibling).unwrap();
        std::fs::set_permissions(&sibling, std::fs::Permissions::from_mode(0o755)).unwrap();
        ensure_real_parent(&state.join("..").join("x").join("f")).unwrap();
        assert_eq!(mode(&home), 0o751);
        assert_eq!(mode(&sibling), 0o755);

        // Directories outside a `.phantom` tree are never tightened.
        let plain = dir.path().join("plain");
        std::fs::create_dir(&plain).unwrap();
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o755)).unwrap();
        ensure_real_parent(&plain.join("report.txt")).unwrap();
        assert_eq!(mode(&plain), 0o755);
    }

    /// `ensure_private_dir` tightens an existing loose `~/.phantom` (and an
    /// intermediate state directory) on the way to a nested store, not only
    /// the final directory.
    #[cfg(unix)]
    #[test]
    fn ensure_private_dir_tightens_existing_phantom_ancestors() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir = TempDir::new().unwrap();
        let home = dir.path().join("home");
        let state = home.join(".phantom");
        let shadows = state.join("shadows");
        std::fs::create_dir_all(&shadows).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&shadows, std::fs::Permissions::from_mode(0o750)).unwrap();

        let store = shadows.join("project");
        ensure_private_dir(&store).unwrap();
        assert_eq!(mode(&home), 0o755);
        assert_eq!(mode(&state), 0o700);
        assert_eq!(mode(&shadows), 0o700);
        assert_eq!(mode(&store), 0o700);
    }

    /// A symlinked `.phantom` is still refused and its target is never
    /// chmod-ed, whether it is the file's parent or a further ancestor.
    #[cfg(unix)]
    #[test]
    fn existing_phantom_state_symlink_is_refused_and_target_untouched() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir = TempDir::new().unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir_all(elsewhere.join("sub")).unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(
            elsewhere.join("sub"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let state = home.join(".phantom");
        std::os::unix::fs::symlink(&elsewhere, &state).unwrap();

        assert!(ensure_real_parent(&state.join("audit.log")).is_err());
        assert!(ensure_private_dir(&state).is_err());
        assert_eq!(mode(&elsewhere), 0o755);

        // Below a symlinked `.phantom`, nothing in the redirected tree is
        // tightened either.
        let _ = ensure_real_parent(&state.join("sub").join("f"));
        let _ = ensure_private_dir(&state.join("sub"));
        assert_eq!(mode(&elsewhere), 0o755);
        assert_eq!(mode(&elsewhere.join("sub")), 0o755);
    }

    #[test]
    fn ensure_real_parent_rejects_non_directory_component() {
        let dir = TempDir::new().unwrap();
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"not-a-directory").unwrap();
        let error = ensure_real_parent(&blocker.join("target")).unwrap_err();
        assert!(error.to_string().contains("not a real directory"));
    }

    #[test]
    fn project_filename_rejects_escape_forms() {
        for invalid in [
            "",
            ".",
            "..",
            "../owner",
            "nested/file",
            "nested\\file",
            "owner..backup",
            "/tmp/owner",
        ] {
            assert!(
                validate_project_filename(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        validate_project_filename(".env.example").unwrap();
        validate_project_filename("env-example").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn owned_file_at_is_created_private_and_never_follows_a_symlink() {
        use std::os::unix::fs::{symlink, MetadataExt};
        let dir = TempDir::new().unwrap();
        let state = dir.path().join("state");
        ensure_private_leaf_dir(&state).unwrap();
        let handle = open_owned_directory(None, &state, true).unwrap();
        open_owned_file_at(&handle, Path::new("one.lock"), true).unwrap();
        let metadata = std::fs::metadata(state.join("one.lock")).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.len(), 0);

        let victim = dir.path().join("victim");
        symlink(&victim, state.join("two.lock")).unwrap();
        assert!(open_owned_file_at(&handle, Path::new("two.lock"), true).is_err());
        assert!(std::fs::symlink_metadata(&victim).is_err());

        std::fs::create_dir(state.join("three.lock")).unwrap();
        assert!(open_owned_file_at(&handle, Path::new("three.lock"), true).is_err());
        assert!(state.join("three.lock").is_dir());

        let fifo = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(
            state.join("fifo.lock").as_os_str(),
        ))
        .unwrap();
        // SAFETY: `fifo` is a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let error = open_owned_file_at(&handle, Path::new("fifo.lock"), true).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let missing = open_owned_file_at(&handle, Path::new("four.lock"), false).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
        assert!(!state.join("four.lock").exists());

        for nested in ["a/b", "..", "", "/abs"] {
            assert!(open_owned_file_at(&handle, Path::new(nested), true).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn owned_directory_refuses_symlinks_and_open_modes_when_private_is_required() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = TempDir::new().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();
        open_owned_directory(None, &real, false).unwrap();
        let error = open_owned_directory(None, &real, true).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();
        assert!(open_owned_directory(None, &link, false).is_err());

        let parent = open_owned_directory(None, dir.path(), false).unwrap();
        assert!(open_owned_directory(Some(&parent), Path::new("link"), false).is_err());
        open_owned_directory(Some(&parent), Path::new("real"), false).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn owned_file_and_directory_of_another_user_are_refused() {
        // Staging foreign ownership needs privilege; skip when unprivileged.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let dir = TempDir::new().unwrap();
        let foreign_dir = dir.path().join("foreign");
        std::fs::create_dir(&foreign_dir).unwrap();
        std::os::unix::fs::chown(&foreign_dir, Some(65534), Some(65534)).unwrap();
        let error = open_owned_directory(None, &foreign_dir, false).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let own = open_owned_directory(None, dir.path(), false).unwrap();
        std::fs::write(dir.path().join("foreign.lock"), b"").unwrap();
        std::os::unix::fs::chown(dir.path().join("foreign.lock"), Some(65534), Some(65534))
            .unwrap();
        let error = open_owned_file_at(&own, Path::new("foreign.lock"), true).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn windows_reader_contract_is_handle_bound_and_reparse_safe() {
        let source = include_str!("fs.rs");
        assert!(source.contains("FILE_FLAG_OPEN_REPARSE_POINT"));
        assert!(source.contains("FILE_ATTRIBUTE_REPARSE_POINT"));
        assert!(source.contains("GetFileInformationByHandle"));
        assert!(source.contains("dwVolumeSerialNumber"));
        assert!(source.contains("nFileIndexHigh"));
        assert!(source.contains("nFileIndexLow"));
    }
}
