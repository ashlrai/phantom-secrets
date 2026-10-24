//! `--output <path>` for long reports: write the full report to a new file
//! and let the caller print a short summary, so an agent's context gets a
//! few lines instead of the whole report.

use anyhow::{Context, Result};
use std::io::Write;
use std::path::Path;

/// Create `path` (it must not exist yet; an existing file or symlink is never
/// overwritten or followed) and write `contents`. On Unix the file is 0600.
pub fn write_new(path: &Path, contents: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).with_context(|| {
        format!(
            "could not create {} (it must not already exist)",
            path.display()
        )
    })?;
    file.write_all(contents)
        .and_then(|_| file.sync_all())
        .with_context(|| format!("could not write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_a_new_file_and_refuses_an_existing_one() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("r.txt");
        write_new(&p, b"one").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"one");
        assert!(write_new(&p, b"two").is_err());
        assert_eq!(std::fs::read(&p).unwrap(), b"one");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            let target = dir.path().join("target.txt");
            std::os::unix::fs::symlink(&target, dir.path().join("link")).unwrap();
            assert!(write_new(&dir.path().join("link"), b"x").is_err());
            assert!(!target.exists(), "a symlink must not be followed");
        }
    }
}
