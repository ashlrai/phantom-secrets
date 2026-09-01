use anyhow::{Context, Result};
use fs2::FileExt;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

pub(crate) struct ProxyLifetimeLock(File);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProxyLockState {
    Missing,
    Available,
    Held,
}

fn lock_root() -> Result<PathBuf> {
    directories::ProjectDirs::from("ai", "phantom", "phantom-secrets")
        .map(|dirs| dirs.data_dir().join("proxy-locks"))
        .context("Cannot resolve the machine-local Phantom data directory")
}

pub(crate) fn lock_path(local_project_id: &str) -> Result<PathBuf> {
    if local_project_id.len() != 64
        || !local_project_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        anyhow::bail!("Invalid machine-local project identifier for proxy locking");
    }
    Ok(lock_root()?.join(format!("{local_project_id}.lock")))
}

fn validate_parent(parent: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(parent).with_context(|| {
        format!(
            "Failed to inspect proxy lock directory {}",
            parent.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "Proxy lock directory is not a real directory: {}",
            parent.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn open_existing(path: &Path) -> io::Result<File> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("proxy lock path is not a regular file: {}", path.display()),
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("proxy lock path is not a regular file: {}", path.display()),
        ));
    }
    #[cfg(windows)]
    ensure_windows_file_identity(&file, path)?;
    Ok(file)
}

fn open_or_create(path: &Path) -> Result<File> {
    let parent = path.parent().context("proxy lock path has no parent")?;
    std::fs::create_dir_all(parent)?;
    validate_parent(parent)?;
    match open_existing(path) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
                options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            }
            match options.open(path) {
                Ok(file) => {
                    #[cfg(windows)]
                    ensure_windows_file_identity(&file, path)?;
                    Ok(file)
                }
                Err(race) if race.kind() == io::ErrorKind::AlreadyExists => {
                    open_existing(path).map_err(Into::into)
                }
                Err(error) => Err(error.into()),
            }
        }
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn try_acquire(local_project_id: &str) -> Result<Option<ProxyLifetimeLock>> {
    let path = lock_path(local_project_id)?;
    let file = open_or_create(&path)
        .with_context(|| format!("Failed to open machine-local proxy lock {}", path.display()))?;
    match file.try_lock_exclusive() {
        Ok(()) => {
            #[cfg(windows)]
            ensure_windows_file_identity(&file, &path)?;
            Ok(Some(ProxyLifetimeLock(file)))
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(error).with_context(|| format!("Failed to lock {}", path.display())),
    }
}

#[cfg(windows)]
fn windows_file_information(
    file: &File,
) -> io::Result<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION> {
    use std::os::windows::io::AsRawHandle;

    let mut information =
        windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION::default();
    let status = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(
            file.as_raw_handle(),
            &mut information,
        )
    };
    if status == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(information)
}

#[cfg(windows)]
pub(crate) fn ensure_windows_file_identity(file: &File, path: &Path) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let original = windows_file_information(file)?;
    if original.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file is a Windows reparse point: {}", path.display()),
        ));
    }
    let current = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let current = windows_file_information(&current)?;
    if current.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || original.dwVolumeSerialNumber != current.dwVolumeSerialNumber
        || original.nFileIndexHigh != current.nFileIndexHigh
        || original.nFileIndexLow != current.nFileIndexLow
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Windows file path changed while opening: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// Inspect without creating either the machine-local directory or lock file.
pub(crate) fn inspect(local_project_id: &str) -> Result<ProxyLockState> {
    let path = lock_path(local_project_id)?;
    let file = match open_existing(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(ProxyLockState::Missing)
        }
        Err(error) => {
            return Err(error).with_context(|| format!("Failed to inspect {}", path.display()))
        }
    };
    match file.try_lock_exclusive() {
        Ok(()) => {
            FileExt::unlock(&file)?;
            Ok(ProxyLockState::Available)
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(ProxyLockState::Held),
        Err(error) => Err(error).with_context(|| format!("Failed to inspect {}", path.display())),
    }
}

impl Drop for ProxyLifetimeLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_lock_file_is_never_unlinked_between_owners() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stable.lock");
        let first_file = open_or_create(&path).unwrap();
        first_file.try_lock_exclusive().unwrap();
        assert!(path.is_file());
        drop(first_file);
        let before = std::fs::metadata(&path).unwrap();
        let second_file = open_or_create(&path).unwrap();
        second_file.try_lock_exclusive().unwrap();
        drop(second_file);
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(before.len(), after.len());
        assert!(path.is_file(), "stable lock inode must not be unlinked");
    }
}
