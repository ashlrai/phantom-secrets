use anyhow::{Context, Result};
use fs2::FileExt;
use std::fs::File;
#[cfg(not(unix))]
use std::fs::OpenOptions;
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
    if let Some(project_dirs) = directories::ProjectDirs::from("ai", "phantom", "phantom-secrets") {
        return Ok(project_dirs.data_dir().join("proxy-locks"));
    }
    dirs::home_dir()
        .map(|home| home.join(".phantom").join("proxy-locks"))
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

/// Prepare `<data dir>/<app dir>/proxy-locks` for the lifecycle lock.
///
/// The data directory (for example `~/.local/share` or `XDG_DATA_HOME`) is
/// the user's and may legitimately be a symlink, so it is created and
/// resolved normally. The two final components are Phantom's own: each is
/// created 0700, a symlink or non-directory there is refused, and an existing
/// owned directory is tightened through a no-follow descriptor so a swap
/// after the lookup cannot redirect the chmod.
fn prepare_lock_dir(lock_dir: &Path) -> Result<()> {
    let app_dir = lock_dir
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("proxy lock directory has no parent")?;
    if let Some(data_dir) = app_dir
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(data_dir)
            .with_context(|| format!("Failed to create data directory {}", data_dir.display()))?;
    }
    for directory in [app_dir, lock_dir] {
        phantom_core::fs::ensure_private_leaf_dir(directory).with_context(|| {
            format!(
                "Proxy lock directory is not a private real directory: {}",
                directory.display()
            )
        })?;
    }
    Ok(())
}

#[cfg(not(unix))]
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

#[cfg(test)]
thread_local! {
    /// Test seam: runs once between the lock directory checks and the lock
    /// file open, so a directory swap in that window can be staged.
    static AFTER_DIRECTORY_CHECKS: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

fn after_directory_checks() {
    #[cfg(test)]
    if let Some(hook) = AFTER_DIRECTORY_CHECKS.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
}

/// Open `<app dir>/proxy-locks` as a descriptor chain that never follows a
/// symlink at either Phantom-owned component, and require both to be real
/// directories owned by the current user (and private when acquiring).
#[cfg(unix)]
fn open_lock_dir(lock_dir: &Path, require_private: bool) -> io::Result<File> {
    let app_dir = lock_dir
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "lock directory has no parent")
        })?;
    let name = lock_dir
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "lock directory has no name"))?;
    let app = phantom_core::fs::open_owned_directory(None, app_dir, require_private)?;
    phantom_core::fs::open_owned_directory(Some(&app), Path::new(name), require_private)
}

/// Open the lock file relative to the verified `proxy-locks` descriptor, so
/// swapping either directory after the path-based checks cannot redirect it.
#[cfg(unix)]
fn open_lock_file(path: &Path, create: bool) -> io::Result<File> {
    let lock_dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "lock path has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "lock path has no name"))?;
    let directory = open_lock_dir(lock_dir, create)?;
    after_directory_checks();
    phantom_core::fs::open_owned_file_at(&directory, Path::new(name), create)
}

#[cfg(unix)]
fn open_or_create(path: &Path) -> Result<File> {
    let parent = path.parent().context("proxy lock path has no parent")?;
    prepare_lock_dir(parent)?;
    open_lock_file(path, true).map_err(Into::into)
}

#[cfg(not(unix))]
fn open_or_create(path: &Path) -> Result<File> {
    let parent = path.parent().context("proxy lock path has no parent")?;
    prepare_lock_dir(parent)?;
    after_directory_checks();
    match open_existing(path) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
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
    inspect_path(&lock_path(local_project_id)?)
}

fn inspect_path(path: &Path) -> Result<ProxyLockState> {
    #[cfg(unix)]
    let opened = open_lock_file(path, false);
    #[cfg(not(unix))]
    let opened = open_existing(path);
    let file = match opened {
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
        let path = dir
            .path()
            .join("phantom-secrets")
            .join("proxy-locks")
            .join("stable.lock");
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

    #[cfg(unix)]
    mod unix {
        use super::super::open_or_create;
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
        use std::path::Path;

        fn mode(path: &Path) -> u32 {
            std::fs::symlink_metadata(path).unwrap().mode() & 0o777
        }

        fn lock_in(data_dir: &Path) -> std::path::PathBuf {
            data_dir
                .join("phantom-secrets")
                .join("proxy-locks")
                .join("project.lock")
        }

        #[test]
        fn fresh_app_and_lock_directories_are_private() {
            let dir = tempfile::tempdir().unwrap();
            let data_dir = dir.path().join("share");
            let path = lock_in(&data_dir);
            open_or_create(&path).unwrap();
            assert_eq!(mode(&data_dir.join("phantom-secrets")), 0o700);
            assert_eq!(mode(&data_dir.join("phantom-secrets/proxy-locks")), 0o700);
            assert_eq!(mode(&path), 0o600);
        }

        #[test]
        fn symlinked_app_directory_is_refused_and_target_untouched() {
            let dir = tempfile::tempdir().unwrap();
            let data_dir = dir.path().join("share");
            std::fs::create_dir(&data_dir).unwrap();
            let target = dir.path().join("elsewhere");
            std::fs::create_dir(&target).unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
            symlink(&target, data_dir.join("phantom-secrets")).unwrap();

            assert!(open_or_create(&lock_in(&data_dir)).is_err());
            assert_eq!(mode(&target), 0o755);
            assert!(!target.join("proxy-locks").exists());
        }

        #[test]
        fn symlinked_lock_directory_is_refused_and_target_untouched() {
            let dir = tempfile::tempdir().unwrap();
            let app_dir = dir.path().join("share").join("phantom-secrets");
            std::fs::create_dir_all(&app_dir).unwrap();
            let target = dir.path().join("elsewhere");
            std::fs::create_dir(&target).unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
            symlink(&target, app_dir.join("proxy-locks")).unwrap();

            assert!(open_or_create(&lock_in(&dir.path().join("share"))).is_err());
            assert_eq!(mode(&target), 0o755);
            assert!(!target.join("project.lock").exists());
        }

        #[test]
        fn symlinked_lock_file_is_refused_and_victim_not_created() {
            let dir = tempfile::tempdir().unwrap();
            let data_dir = dir.path().join("share");
            let path = lock_in(&data_dir);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let victim = dir.path().join("victim-file");
            symlink(&victim, &path).unwrap();

            assert!(open_or_create(&path).is_err());
            assert!(std::fs::symlink_metadata(&victim).is_err());
        }

        #[test]
        fn existing_open_app_directory_is_tightened() {
            let dir = tempfile::tempdir().unwrap();
            let app_dir = dir.path().join("share").join("phantom-secrets");
            std::fs::create_dir_all(&app_dir).unwrap();
            std::fs::set_permissions(&app_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            open_or_create(&lock_in(&dir.path().join("share"))).unwrap();
            assert_eq!(mode(&app_dir), 0o700);
        }

        #[test]
        fn symlinked_data_directory_parent_still_works() {
            let dir = tempfile::tempdir().unwrap();
            let real_share = dir.path().join("real-share");
            std::fs::create_dir(&real_share).unwrap();
            let linked_share = dir.path().join("linked-share");
            symlink(&real_share, &linked_share).unwrap();

            open_or_create(&lock_in(&linked_share)).unwrap();
            assert!(lock_in(&real_share).is_file());
            assert_eq!(mode(&real_share.join("phantom-secrets")), 0o700);
        }
        #[test]
        fn lock_directory_swapped_after_checks_never_redirects_the_lock_file() {
            let dir = tempfile::tempdir().unwrap();
            let data_dir = dir.path().join("share");
            let path = lock_in(&data_dir);
            let lock_dir = path.parent().unwrap().to_path_buf();
            std::fs::create_dir_all(&lock_dir).unwrap();
            let moved = dir.path().join("moved-locks");
            let decoy = dir.path().join("decoy");
            std::fs::create_dir(&decoy).unwrap();
            std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o755)).unwrap();
            let (hook_lock_dir, hook_moved, hook_decoy) =
                (lock_dir.clone(), moved.clone(), decoy.clone());
            super::super::AFTER_DIRECTORY_CHECKS.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    std::fs::rename(&hook_lock_dir, &hook_moved).unwrap();
                    symlink(&hook_decoy, &hook_lock_dir).unwrap();
                }));
            });

            let outcome = open_or_create(&path);
            assert!(
                !decoy.join("project.lock").exists(),
                "lock file must not be created through a swapped directory"
            );
            assert_eq!(mode(&decoy), 0o755);
            if outcome.is_ok() {
                assert!(moved.join("project.lock").is_file());
            }
        }

        #[test]
        fn lock_file_owned_by_another_user_is_refused() {
            // Changing ownership needs privilege; unprivileged runs cannot
            // stage a foreign-owned file and skip.
            if unsafe { libc::geteuid() } != 0 {
                return;
            }
            let dir = tempfile::tempdir().unwrap();
            let path = lock_in(&dir.path().join("share"));
            open_or_create(&path).unwrap();
            std::os::unix::fs::chown(&path, Some(65534), Some(65534)).unwrap();
            assert!(open_or_create(&path).is_err());
            assert_eq!(std::fs::metadata(&path).unwrap().uid(), 65534);
        }

        #[test]
        fn lock_directory_owned_by_another_user_is_refused() {
            if unsafe { libc::geteuid() } != 0 {
                return;
            }
            let dir = tempfile::tempdir().unwrap();
            let path = lock_in(&dir.path().join("share"));
            let lock_dir = path.parent().unwrap();
            std::fs::create_dir_all(lock_dir).unwrap();
            std::os::unix::fs::chown(lock_dir, Some(65534), Some(65534)).unwrap();
            assert!(open_or_create(&path).is_err());
            assert!(!path.exists());
        }

        #[test]
        fn non_regular_lock_path_is_refused() {
            let dir = tempfile::tempdir().unwrap();
            let path = lock_in(&dir.path().join("share"));
            std::fs::create_dir_all(&path).unwrap();
            assert!(open_or_create(&path).is_err());
            assert!(path.is_dir());
        }

        #[test]
        fn existing_lock_file_keeps_private_mode() {
            let dir = tempfile::tempdir().unwrap();
            let path = lock_in(&dir.path().join("share"));
            open_or_create(&path).unwrap();
            open_or_create(&path).unwrap();
            assert_eq!(mode(&path), 0o600);
        }
        #[test]
        fn inspect_never_creates_and_never_follows_a_swapped_lock_directory() {
            use super::super::{inspect_path, ProxyLockState};
            use fs2::FileExt;
            let dir = tempfile::tempdir().unwrap();
            let data_dir = dir.path().join("share");
            let path = lock_in(&data_dir);
            assert_eq!(inspect_path(&path).unwrap(), ProxyLockState::Missing);
            assert!(!data_dir.join("phantom-secrets").exists());

            let held = open_or_create(&path).unwrap();
            held.try_lock_exclusive().unwrap();
            assert_eq!(inspect_path(&path).unwrap(), ProxyLockState::Held);
            drop(held);
            assert_eq!(inspect_path(&path).unwrap(), ProxyLockState::Available);

            let lock_dir = path.parent().unwrap();
            let decoy = dir.path().join("decoy");
            std::fs::create_dir(&decoy).unwrap();
            std::fs::write(decoy.join("project.lock"), b"").unwrap();
            std::fs::rename(lock_dir, dir.path().join("moved-locks")).unwrap();
            symlink(&decoy, lock_dir).unwrap();
            assert!(inspect_path(&path).is_err());
        }
    }
}
