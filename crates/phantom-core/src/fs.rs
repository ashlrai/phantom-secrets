//! Filesystem helpers for secret-bearing writes.
//!
//! The central primitive is [`atomic_write`]: it writes content to a temp file
//! next to the target, fsyncs, then renames over the target. On POSIX the
//! temp file is created with mode 0o600 (tempfile's default) so the plaintext
//! never lives on disk with a wider default umask during the write window.
//!
//! Callers should use this for every write that touches secrets or that must
//! survive a crash / `kill -9` mid-write (e.g. `.env`, `.phantom.toml`,
//! `.phantom.pid`, the vault file).

use std::io::{self, Write};
use std::path::Path;

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
    let dir = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic_write: path has no parent directory",
        )
    })?;

    // Using NamedTempFile::new_in keeps the temp on the same filesystem as the
    // target, which is required for rename() to be atomic on POSIX.
    let mut tmp = NamedTempFile::new_in(dir)?;
    tmp.write_all(contents)?;
    tmp.as_file_mut().sync_all()?;

    // persist consumes the NamedTempFile and renames into place; on error we
    // return the underlying io::Error (the unpersisted temp is cleaned up).
    tmp.persist(path).map_err(|e| e.error)?;
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
}
