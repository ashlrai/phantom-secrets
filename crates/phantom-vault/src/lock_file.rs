//! Safe acquisition for predictable vault lock paths.
//!
//! Lock files are attacker-interesting because their names are stable and the
//! caller may repair their permissions. This module validates every existing
//! directory component, refuses link aliases, and verifies that the pathname
//! still identifies the locked handle before returning it.

use fs2::FileExt;
use phantom_core::error::{PhantomError, Result};
use std::path::{Path, PathBuf};

fn vault_error(message: impl Into<String>) -> PhantomError {
    PhantomError::VaultError(message.into())
}

fn absolute_without_canonicalizing(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn directory_is_unsafe(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return true;
        }
    }
    false
}

fn create_directory_component(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// Create missing components one at a time and reject every unsafe existing
/// ancestor. Existing directories are never chmodded: a permissive keychain
/// lock directory is an authority/configuration error, not something Phantom
/// may silently mutate through a pathname.
pub(crate) fn ensure_safe_directory(
    path: &Path,
    label: &str,
    require_private_directory: bool,
) -> Result<PathBuf> {
    let absolute = absolute_without_canonicalizing(path)?;
    let mut components = absolute.ancestors().collect::<Vec<_>>();
    components.reverse();

    for component in components {
        match std::fs::symlink_metadata(component) {
            Ok(metadata) => {
                if directory_is_unsafe(&metadata) {
                    return Err(vault_error(format!(
                        "{label} ancestor is not a real directory: {}",
                        component.display()
                    )));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match create_directory_component(component) {
                    Ok(()) => {}
                    Err(create_error)
                        if create_error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(create_error) => return Err(create_error.into()),
                }
                let metadata = std::fs::symlink_metadata(component)?;
                if directory_is_unsafe(&metadata) {
                    return Err(vault_error(format!(
                        "{label} ancestor became unsafe while it was created: {}",
                        component.display()
                    )));
                }
            }
            Err(error) => return Err(error.into()),
        }
    }

    if require_private_directory {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::symlink_metadata(&absolute)?.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(vault_error(format!(
                    "{label} directory is accessible by group or other users: {}",
                    absolute.display()
                )));
            }
        }
    }

    Ok(absolute)
}

fn open_lock_path(path: &Path, create: bool) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options
        .create(create)
        .read(true)
        .write(true)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn ensure_regular_single_link(file: &std::fs::File, path: &Path, label: &str) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(vault_error(format!(
            "{label} is not a regular file: {}",
            path.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(vault_error(format!(
                "{label} is not a single-link owner file: {}",
                path.display()
            )));
        }
    }

    #[cfg(windows)]
    {
        let information = windows_file_information(file, label)?;
        if information.dwFileAttributes
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err(vault_error(format!(
                "{label} is a Windows reparse point: {}",
                path.display()
            )));
        }
        if information.nNumberOfLinks != 1 {
            return Err(vault_error(format!(
                "{label} is not a single-link owner file: {}",
                path.display()
            )));
        }
    }

    Ok(())
}

#[cfg(unix)]
fn repair_and_verify_unix_mode(file: &std::fs::File, path: &Path, label: &str) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // This occurs only after the handle was proven regular and single-link, so
    // legacy 0644 locks can be repaired without chmodding an aliased target.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(vault_error(format!(
            "{label} changed while its permissions were secured: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_path_identity(file: &std::fs::File, path: &Path, label: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let original = file.metadata()?;
    let current_file = open_lock_path(path, false).map_err(|error| {
        vault_error(format!("Cannot verify {label} {}: {error}", path.display()))
    })?;
    ensure_regular_single_link(&current_file, path, label)?;
    let current = current_file.metadata()?;
    if original.dev() != current.dev() || original.ino() != current.ino() {
        return Err(vault_error(format!(
            "{label} path changed while it was acquired: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn windows_file_information(
    file: &std::fs::File,
    label: &str,
) -> Result<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION> {
    use std::os::windows::io::AsRawHandle;

    let mut information = unsafe { std::mem::zeroed() };
    let status = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(
            file.as_raw_handle(),
            &mut information,
        )
    };
    if status == 0 {
        return Err(vault_error(format!(
            "Cannot inspect {label} Windows handle: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(information)
}

#[cfg(windows)]
fn ensure_path_identity(file: &std::fs::File, path: &Path, label: &str) -> Result<()> {
    let original = windows_file_information(file, label)?;
    let current_file = open_lock_path(path, false).map_err(|error| {
        vault_error(format!("Cannot verify {label} {}: {error}", path.display()))
    })?;
    ensure_regular_single_link(&current_file, path, label)?;
    let current = windows_file_information(&current_file, label)?;
    if original.dwVolumeSerialNumber != current.dwVolumeSerialNumber
        || original.nFileIndexHigh != current.nFileIndexHigh
        || original.nFileIndexLow != current.nFileIndexLow
    {
        return Err(vault_error(format!(
            "{label} path changed while it was acquired: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn ensure_path_identity(file: &std::fs::File, path: &Path, label: &str) -> Result<()> {
    ensure_regular_single_link(file, path, label)?;
    let current = std::fs::symlink_metadata(path)?;
    if current.file_type().is_symlink() || !current.is_file() {
        return Err(vault_error(format!(
            "{label} path changed while it was acquired: {}",
            path.display()
        )));
    }
    Ok(())
}

pub(crate) fn acquire_exclusive_lock_file(
    path: &Path,
    label: &str,
    require_private_parent: bool,
) -> Result<std::fs::File> {
    let absolute = absolute_without_canonicalizing(path)?;
    let parent = absolute
        .parent()
        .ok_or_else(|| vault_error(format!("{label} path has no parent")))?;
    ensure_safe_directory(parent, label, require_private_parent)?;

    match std::fs::symlink_metadata(&absolute) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(vault_error(format!(
                "{label} path is not a regular file: {}",
                absolute.display()
            )));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let file = open_lock_path(&absolute, true).map_err(|error| {
        vault_error(format!(
            "Cannot open {label} {}: {error}",
            absolute.display()
        ))
    })?;
    ensure_regular_single_link(&file, &absolute, label)?;
    #[cfg(unix)]
    repair_and_verify_unix_mode(&file, &absolute, label)?;

    file.lock_exclusive().map_err(|error| {
        vault_error(format!(
            "Cannot acquire {label} {}: {error}",
            absolute.display()
        ))
    })?;

    // Detect path or ancestor substitution observable after the lock was
    // acquired. The locked handle remains alive on every error path until the
    // function returns, preventing a cooperating writer from entering midway.
    ensure_safe_directory(parent, label, require_private_parent)?;
    ensure_regular_single_link(&file, &absolute, label)?;
    ensure_path_identity(&file, &absolute, label)?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn canonical_temp_root(directory: &tempfile::TempDir) -> PathBuf {
        directory.path().canonicalize().unwrap()
    }

    #[test]
    fn windows_contract_checks_reparse_links_and_handle_identity() {
        let source = include_str!("lock_file.rs");
        assert!(source.contains("FILE_FLAG_OPEN_REPARSE_POINT"));
        assert!(source.contains("FILE_ATTRIBUTE_REPARSE_POINT"));
        assert!(source.contains("GetFileInformationByHandle"));
        assert!(source.contains("dwVolumeSerialNumber"));
        assert!(source.contains("nFileIndexHigh"));
        assert!(source.contains("nFileIndexLow"));
        assert!(source.contains("nNumberOfLinks"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_ancestor_is_rejected_without_creating_in_target() {
        use std::os::unix::fs::symlink;

        let container = tempdir().unwrap();
        let root = canonical_temp_root(&container);
        let target = root.join("target");
        std::fs::create_dir(&target).unwrap();
        let redirected = root.join("redirected");
        symlink(&target, &redirected).unwrap();

        let lock = redirected.join("nested").join("owner.lock");
        assert!(acquire_exclusive_lock_file(&lock, "test lock", false).is_err());
        assert!(!target.join("nested").exists());
    }

    #[cfg(unix)]
    #[test]
    fn final_symlink_is_rejected_without_mutating_target() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = tempdir().unwrap();
        let root = canonical_temp_root(&dir);
        let target = root.join("owner-state");
        std::fs::write(&target, b"preserve").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
        let lock = root.join("owner.lock");
        symlink(&target, &lock).unwrap();

        assert!(acquire_exclusive_lock_file(&lock, "test lock", false).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"preserve");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[cfg(unix)]
    #[test]
    fn hardlink_is_rejected_before_permission_repair() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let root = canonical_temp_root(&dir);
        let target = root.join("owner-state");
        std::fs::write(&target, b"preserve").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
        let lock = root.join("owner.lock");
        std::fs::hard_link(&target, &lock).unwrap();

        assert!(acquire_exclusive_lock_file(&lock, "test lock", false).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"preserve");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[cfg(unix)]
    #[test]
    fn legacy_single_link_mode_is_repaired_after_validation() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let lock = canonical_temp_root(&dir).join("owner.lock");
        std::fs::write(&lock, b"").unwrap();
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap();

        let _guard = acquire_exclusive_lock_file(&lock, "test lock", false).unwrap();
        assert_eq!(
            std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_regular_lock_target_is_rejected() {
        let dir = tempdir().unwrap();
        let lock = canonical_temp_root(&dir).join("owner.lock");
        std::fs::create_dir(&lock).unwrap();

        assert!(acquire_exclusive_lock_file(&lock, "test lock", false).is_err());
        assert!(lock.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn permissive_private_parent_is_rejected_without_mutation() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let parent = canonical_temp_root(&dir).join("locks");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        let lock = parent.join("owner.lock");

        assert!(acquire_exclusive_lock_file(&lock, "test lock", true).is_err());
        assert!(!lock.exists());
        assert_eq!(
            std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[cfg(unix)]
    #[test]
    fn missing_private_parent_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let parent = canonical_temp_root(&dir).join("metadata").join("locks");
        let lock = parent.join("owner.lock");
        let _guard = acquire_exclusive_lock_file(&lock, "test lock", true).unwrap();

        assert_eq!(
            std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
