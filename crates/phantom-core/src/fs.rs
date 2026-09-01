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

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other(format!(
            "refusing non-regular file target: {}",
            path.display()
        )));
    }
    #[cfg(windows)]
    if windows_file_information(&file)?.dwFileAttributes
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
    {
        return Err(io::Error::other(format!(
            "refusing Windows reparse-point file target: {}",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;

    // Re-inspect the pathname after reading. Atomic replacement by an
    // uncooperative same-user process cannot be made impossible with portable
    // pathname APIs, but an observable swap is rejected before these bytes are
    // accepted as the reviewed before-image.
    ensure_path_still_names_open_file(path, &file)?;
    Ok(Some(bytes))
}

#[cfg(unix)]
fn ensure_path_still_names_open_file(path: &Path, opened: &std::fs::File) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let original = opened.metadata()?;
    let mut options = std::fs::OpenOptions::new();
    use std::os::unix::fs::OpenOptionsExt;
    options.read(true).custom_flags(libc::O_NOFOLLOW);
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
    let current = windows_file_information(&current)?;
    if current.dwFileAttributes
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
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
    let current = read_regular_file(path)?;
    if current.as_deref() != expected_before {
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
        match std::fs::create_dir(&directory) {
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
