//! Safe acquisition for predictable vault lock paths.
//!
//! Lock files are attacker-interesting because their names are stable and the
//! caller may repair their permissions. A caller supplies the trusted base
//! directory selected by the OS or explicit configuration. Phantom resolves
//! that anchor once (so supported aliases such as macOS `/var` work), then
//! validates every Phantom-owned component beneath it, refuses link aliases,
//! and verifies that the pathname still identifies the locked handle before
//! returning it.
//!
//! This helper does not pin a configured/OS anchor against later replacement,
//! and it does not make vault payload or keychain-sidecar I/O descriptor
//! relative. Those broader descendant-path races require an anchored I/O API.

use fs2::FileExt;
use phantom_core::error::{PhantomError, Result};
use std::path::{Path, PathBuf};

fn vault_error(message: impl Into<String>) -> PhantomError {
    PhantomError::VaultError(message.into())
}

fn trusted_canonical_anchor(path: &Path, label: &str) -> Result<PathBuf> {
    // The anchor is an explicit authority boundary: ProjectDirs, HOME/XDG, or
    // a caller-selected vault base. It may itself be an OS-managed alias or a
    // configured symlink/junction, so do not apply Phantom-owned no-follow
    // rules until after it has been resolved. This is not an ancestor-swap
    // defense: callers must never derive the anchor from untrusted project
    // input. Descriptor-relative data I/O is a separate boundary.
    std::fs::create_dir_all(path).map_err(|error| {
        vault_error(format!(
            "Cannot create trusted {label} anchor {}: {error}",
            path.display()
        ))
    })?;
    let canonical = path.canonicalize().map_err(|error| {
        vault_error(format!(
            "Cannot resolve trusted {label} anchor {}: {error}",
            path.display()
        ))
    })?;
    let metadata = std::fs::metadata(&canonical)?;
    if !metadata.is_dir() {
        return Err(vault_error(format!(
            "Trusted {label} anchor is not a directory: {}",
            canonical.display()
        )));
    }
    Ok(canonical)
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

fn validate_owned_relative_path(path: &Path, label: &str) -> Result<()> {
    use std::path::Component;

    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(vault_error(format!(
            "{label} must be a non-empty relative path without traversal: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn normalize_private_directory(path: &Path, label: &str) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let before = std::fs::symlink_metadata(path)?;
    if directory_is_unsafe(&before) {
        return Err(vault_error(format!(
            "{label} private directory is not a real directory: {}",
            path.display()
        )));
    }

    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            vault_error(format!(
                "Cannot open {label} private directory {}: {error}",
                path.display()
            ))
        })?;
    let opened = directory.metadata()?;
    if !opened.is_dir() || before.dev() != opened.dev() || before.ino() != opened.ino() {
        return Err(vault_error(format!(
            "{label} private directory changed before it could be secured: {}",
            path.display()
        )));
    }

    // Repair legacy 0755 directories through the already-validated handle.
    // Pathname chmod is deliberately forbidden here because a concurrent
    // rename could otherwise redirect the permission change to unrelated data.
    directory.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    let secured = directory.metadata()?;
    if !secured.is_dir() || secured.permissions().mode() & 0o777 != 0o700 {
        return Err(vault_error(format!(
            "{label} private directory permissions could not be secured: {}",
            path.display()
        )));
    }

    let current = std::fs::symlink_metadata(path)?;
    if directory_is_unsafe(&current)
        || current.dev() != secured.dev()
        || current.ino() != secured.ino()
    {
        return Err(vault_error(format!(
            "{label} private directory changed while it was secured: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn normalize_private_directory(path: &Path, label: &str) -> Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let open_directory = || {
        let mut options = std::fs::OpenOptions::new();
        options
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        options.open(path)
    };
    let directory = open_directory().map_err(|error| {
        vault_error(format!(
            "Cannot open {label} private directory {}: {error}",
            path.display()
        ))
    })?;
    let opened = windows_file_information(&directory, label)?;
    if opened.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(vault_error(format!(
            "{label} private directory is not a real directory: {}",
            path.display()
        )));
    }

    let current = open_directory()?;
    let current = windows_file_information(&current, label)?;
    if opened.dwVolumeSerialNumber != current.dwVolumeSerialNumber
        || opened.nFileIndexHigh != current.nFileIndexHigh
        || opened.nFileIndexLow != current.nFileIndexLow
    {
        return Err(vault_error(format!(
            "{label} private directory changed while it was verified: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn normalize_private_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if directory_is_unsafe(&metadata) {
        return Err(vault_error(format!(
            "{label} private directory is not a real directory: {}",
            path.display()
        )));
    }
    Ok(())
}

/// Resolve the trusted base once, then create missing Phantom-owned components
/// one at a time and reject every unsafe existing component below that anchor.
pub(crate) fn ensure_safe_directory(
    trusted_anchor: &Path,
    owned_relative: &Path,
    label: &str,
    require_private_directory: bool,
) -> Result<PathBuf> {
    validate_owned_relative_path(owned_relative, label)?;
    let anchor = trusted_canonical_anchor(trusted_anchor, label)?;
    let absolute = anchor.join(owned_relative);
    let mut component = anchor;

    for owned_component in owned_relative.components() {
        component.push(owned_component.as_os_str());
        match std::fs::symlink_metadata(&component) {
            Ok(metadata) => {
                if directory_is_unsafe(&metadata) {
                    return Err(vault_error(format!(
                        "{label} ancestor is not a real directory: {}",
                        component.display()
                    )));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match create_directory_component(&component) {
                    Ok(()) => {}
                    Err(create_error)
                        if create_error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(create_error) => return Err(create_error.into()),
                }
                let metadata = std::fs::symlink_metadata(&component)?;
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
        normalize_private_directory(&absolute, label)?;
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
    trusted_anchor: &Path,
    owned_relative_path: &Path,
    label: &str,
    require_private_parent: bool,
) -> Result<std::fs::File> {
    validate_owned_relative_path(owned_relative_path, label)?;
    let relative_parent = owned_relative_path
        .parent()
        .ok_or_else(|| vault_error(format!("{label} path has no parent")))?;
    if relative_parent.as_os_str().is_empty() {
        return Err(vault_error(format!(
            "{label} must live in a Phantom-owned directory"
        )));
    }
    let parent = ensure_safe_directory(
        trusted_anchor,
        relative_parent,
        label,
        require_private_parent,
    )?;
    let file_name = owned_relative_path
        .file_name()
        .ok_or_else(|| vault_error(format!("{label} path has no file name")))?;
    let absolute = parent.join(file_name);

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
    let verified_parent = ensure_safe_directory(
        trusted_anchor,
        relative_parent,
        label,
        require_private_parent,
    )?;
    if verified_parent != parent {
        return Err(vault_error(format!(
            "{label} trusted anchor changed while the lock was acquired"
        )));
    }
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
        assert!(source.contains("trusted_canonical_anchor"));
        assert!(source.contains("FILE_FLAG_BACKUP_SEMANTICS"));
        assert!(source.contains("FILE_READ_ATTRIBUTES"));
        assert!(source.contains("FILE_SHARE_DELETE"));
        assert!(source.contains("FILE_FLAG_OPEN_REPARSE_POINT"));
        assert!(source.contains("FILE_ATTRIBUTE_REPARSE_POINT"));
        assert!(source.contains("GetFileInformationByHandle"));
        assert!(source.contains("dwVolumeSerialNumber"));
        assert!(source.contains("nFileIndexHigh"));
        assert!(source.contains("nFileIndexLow"));
        assert!(source.contains("nNumberOfLinks"));
    }

    #[test]
    fn owned_path_cannot_escape_the_trusted_anchor() {
        let directory = tempdir().unwrap();
        let root = canonical_temp_root(&directory);
        for relative in [Path::new("../owner.lock"), Path::new("/owner.lock")] {
            assert!(acquire_exclusive_lock_file(&root, relative, "test lock", true).is_err());
        }
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

        let relative = Path::new("redirected").join("nested").join("owner.lock");
        assert!(acquire_exclusive_lock_file(&root, &relative, "test lock", false).is_err());
        assert!(!target.join("nested").exists());
    }

    #[cfg(unix)]
    #[test]
    fn trusted_symlink_anchor_is_resolved_before_owned_checks() {
        use std::os::unix::fs::symlink;

        let container = tempdir().unwrap();
        let root = canonical_temp_root(&container);
        let target = root.join("configured-data");
        std::fs::create_dir(&target).unwrap();
        let configured_anchor = root.join("xdg-data");
        symlink(&target, &configured_anchor).unwrap();

        let _guard = acquire_exclusive_lock_file(
            &configured_anchor,
            Path::new("transaction-locks/owner.lock"),
            "test lock",
            true,
        )
        .unwrap();
        assert!(target.join("transaction-locks/owner.lock").is_file());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_var_alias_is_a_supported_trusted_anchor() {
        let directory = tempdir().unwrap();
        let canonical = directory.path().canonicalize().unwrap();
        let canonical_text = canonical.to_string_lossy();
        let Some(alias_suffix) = canonical_text.strip_prefix("/private/var/") else {
            return;
        };
        let var_alias = Path::new("/var").join(alias_suffix);
        let _guard = acquire_exclusive_lock_file(
            &var_alias,
            Path::new("phantom-owned/owner.lock"),
            "test lock",
            true,
        )
        .unwrap();
        assert!(canonical.join("phantom-owned/owner.lock").is_file());
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
        let locks = root.join("locks");
        std::fs::create_dir(&locks).unwrap();
        let lock = locks.join("owner.lock");
        symlink(&target, &lock).unwrap();

        assert!(acquire_exclusive_lock_file(
            &root,
            Path::new("locks/owner.lock"),
            "test lock",
            false
        )
        .is_err());
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
        let locks = root.join("locks");
        std::fs::create_dir(&locks).unwrap();
        let lock = locks.join("owner.lock");
        std::fs::hard_link(&target, &lock).unwrap();

        assert!(acquire_exclusive_lock_file(
            &root,
            Path::new("locks/owner.lock"),
            "test lock",
            false
        )
        .is_err());
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
        let root = canonical_temp_root(&dir);
        let locks = root.join("locks");
        std::fs::create_dir(&locks).unwrap();
        let lock = locks.join("owner.lock");
        std::fs::write(&lock, b"").unwrap();
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap();

        let _guard =
            acquire_exclusive_lock_file(&root, Path::new("locks/owner.lock"), "test lock", false)
                .unwrap();
        assert_eq!(
            std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_regular_lock_target_is_rejected() {
        let dir = tempdir().unwrap();
        let root = canonical_temp_root(&dir);
        let locks = root.join("locks");
        std::fs::create_dir(&locks).unwrap();
        let lock = locks.join("owner.lock");
        std::fs::create_dir(&lock).unwrap();

        assert!(acquire_exclusive_lock_file(
            &root,
            Path::new("locks/owner.lock"),
            "test lock",
            false
        )
        .is_err());
        assert!(lock.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn permissive_legacy_private_parent_is_repaired_through_handle() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let parent = canonical_temp_root(&dir).join("locks");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        let lock = parent.join("owner.lock");

        let _guard = acquire_exclusive_lock_file(
            &canonical_temp_root(&dir),
            Path::new("locks/owner.lock"),
            "test lock",
            true,
        )
        .unwrap();
        assert!(lock.exists());
        assert_eq!(
            std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[cfg(unix)]
    #[test]
    fn missing_private_parent_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let parent = canonical_temp_root(&dir).join("metadata").join("locks");
        let lock = parent.join("owner.lock");
        let _guard = acquire_exclusive_lock_file(
            &canonical_temp_root(&dir),
            Path::new("metadata/locks/owner.lock"),
            "test lock",
            true,
        )
        .unwrap();

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
