//! Descriptor-owned flat-file storage for the replay ledger.
//!
//! The Unix backend retains the opened root directory for its entire lifetime
//! and performs every file operation relative to that descriptor. Workspace
//! separation is checked by walking directory descriptors, so the identity
//! actually opened is authoritative even if an ancestor pathname changes.
//! It is not a monotonic rollback anchor and does not defend a hostile same-user
//! process that can mutate the already-open directory itself. Bind-mount aliases
//! are outside this local ancestry check and must be excluded by the host.

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod imp {
    use fs2::FileExt;
    use rand::{rngs::OsRng, RngCore};
    use std::ffi::CString;
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::Path;
    #[cfg(test)]
    use std::sync::atomic::{AtomicU8, Ordering};

    const ROOT_MODE: u32 = 0o700;
    const FILE_MODE: u32 = 0o600;
    const MAX_ANCESTRY_DEPTH: usize = 1024;
    const TRANSACTION_LOCK: &str = "replay-state.v2.lock";
    const INSTANCE_LOCK: &str = "replay-instance.v2.lock";

    pub(crate) struct ReplayStorage {
        root: File,
        #[cfg(test)]
        replace_fault: AtomicU8,
    }

    pub(crate) struct TransactionLock(File);
    pub(crate) struct InstanceLock(File);

    impl ReplayStorage {
        pub(crate) fn bootstrap(root: &Path, workspace: &Path) -> Result<Self, ReplayStorageError> {
            match fs::symlink_metadata(root) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() {
                        return Err(ReplayStorageError::SymlinkRejected);
                    }
                    if !metadata.is_dir() {
                        return Err(ReplayStorageError::InvalidRoot);
                    }
                    let storage = Self::open_root(root, false)?;
                    if storage.overlaps_directory(workspace)? {
                        return Err(ReplayStorageError::StorageOverlapsWorkspace);
                    }
                    storage.harden_root_permissions()?;
                    Ok(storage)
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let parent = root.parent().ok_or(ReplayStorageError::InvalidRoot)?;
                    let name = root.file_name().ok_or(ReplayStorageError::InvalidRoot)?;
                    if name.as_bytes().is_empty()
                        || name.as_bytes().contains(&b'/')
                        || name == "."
                        || name == ".."
                    {
                        return Err(ReplayStorageError::InvalidRoot);
                    }
                    let parent =
                        open_directory(parent).map_err(|_| ReplayStorageError::InvalidRoot)?;
                    let workspace = open_directory(workspace)
                        .map_err(|_| ReplayStorageError::InvalidWorkspace)?;
                    if is_ancestor(&workspace, &parent)? {
                        return Err(ReplayStorageError::StorageOverlapsWorkspace);
                    }
                    let name = CString::new(name.as_bytes())
                        .map_err(|_| ReplayStorageError::InvalidRoot)?;
                    if unsafe {
                        libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), ROOT_MODE as libc::mode_t)
                    } != 0
                    {
                        return Err(ReplayStorageError::Io);
                    }
                    let descriptor = unsafe {
                        libc::openat(
                            parent.as_raw_fd(),
                            name.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    if descriptor < 0 {
                        unsafe {
                            libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR);
                        }
                        return Err(map_last_open_error());
                    }
                    let storage = Self::from_root(unsafe { File::from_raw_fd(descriptor) })?;
                    let result = (|| {
                        if is_ancestor(&storage.root, &workspace)?
                            || is_ancestor(&workspace, &storage.root)?
                        {
                            return Err(ReplayStorageError::StorageOverlapsWorkspace);
                        }
                        storage.harden_root_permissions()?;
                        parent.sync_all().map_err(|_| ReplayStorageError::Io)?;
                        Ok(())
                    })();
                    if let Err(error) = result {
                        drop(storage);
                        unsafe {
                            libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR);
                        }
                        return Err(error);
                    }
                    Ok(storage)
                }
                Err(_) => Err(ReplayStorageError::Io),
            }
        }

        pub(crate) fn open_existing(root: &Path) -> Result<Self, ReplayStorageError> {
            Self::open_root(root, true)
        }

        fn open_root(root: &Path, require_private_mode: bool) -> Result<Self, ReplayStorageError> {
            let mut options = OpenOptions::new();
            options
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
            let directory = options
                .open(root)
                .map_err(|error| map_root_open_error(root, error))?;
            let storage = Self::from_root(directory)?;
            if require_private_mode {
                validate_root(&storage.root)?;
            }
            Ok(storage)
        }

        fn from_root(directory: File) -> Result<Self, ReplayStorageError> {
            validate_root_identity(&directory)?;
            Ok(Self {
                root: directory,
                #[cfg(test)]
                replace_fault: AtomicU8::new(ReplaceFault::None as u8),
            })
        }

        fn harden_root_permissions(&self) -> Result<(), ReplayStorageError> {
            if unsafe { libc::fchmod(self.root.as_raw_fd(), ROOT_MODE as libc::mode_t) } != 0 {
                return Err(ReplayStorageError::Io);
            }
            validate_root(&self.root)
        }

        pub(crate) fn overlaps_directory(
            &self,
            directory: &Path,
        ) -> Result<bool, ReplayStorageError> {
            let workspace =
                open_directory(directory).map_err(|_| ReplayStorageError::InvalidWorkspace)?;
            Ok(is_ancestor(&self.root, &workspace)? || is_ancestor(&workspace, &self.root)?)
        }

        pub(crate) fn lock_transaction(&self) -> Result<TransactionLock, ReplayStorageError> {
            let file = self.open_or_create_private(TRANSACTION_LOCK)?;
            file.lock_exclusive()
                .map_err(|_| ReplayStorageError::LockUnavailable)?;
            Ok(TransactionLock(file))
        }

        pub(crate) fn try_lock_instance(&self) -> Result<InstanceLock, ReplayStorageError> {
            let file = self.open_or_create_private(INSTANCE_LOCK)?;
            if let Err(error) = file.try_lock_exclusive() {
                return if error.kind() == std::io::ErrorKind::WouldBlock {
                    Err(ReplayStorageError::InstanceAlreadyActive)
                } else {
                    Err(ReplayStorageError::Io)
                };
            }
            Ok(InstanceLock(file))
        }

        fn open_or_create_private(&self, name: &str) -> Result<File, ReplayStorageError> {
            let name = c_name(name)?;
            let descriptor = unsafe {
                libc::openat(
                    self.root.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    FILE_MODE,
                )
            };
            if descriptor < 0 {
                return Err(map_last_open_error());
            }
            // SAFETY: openat returned a new owned descriptor.
            let file = unsafe { File::from_raw_fd(descriptor) };
            validate_private_file(&file)?;
            self.root.sync_all().map_err(|_| ReplayStorageError::Io)?;
            Ok(file)
        }

        pub(crate) fn exists(&self, name: &str) -> Result<bool, ReplayStorageError> {
            let name = c_name(name)?;
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            let result = unsafe {
                libc::fstatat(
                    self.root.as_raw_fd(),
                    name.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if result == 0 {
                let stat = unsafe { stat.assume_init() };
                if (stat.st_mode & libc::S_IFMT) == libc::S_IFLNK {
                    return Err(ReplayStorageError::SymlinkRejected);
                }
                if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
                    return Err(ReplayStorageError::InvalidFile);
                }
                return Ok(true);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                Ok(false)
            } else {
                Err(ReplayStorageError::Io)
            }
        }

        pub(crate) fn read(&self, name: &str, max: u64) -> Result<Vec<u8>, ReplayStorageError> {
            let name = c_name(name)?;
            let descriptor = unsafe {
                libc::openat(
                    self.root.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if descriptor < 0 {
                return Err(map_last_open_error());
            }
            let file = unsafe { File::from_raw_fd(descriptor) };
            validate_private_file(&file)?;
            let len = file.metadata().map_err(|_| ReplayStorageError::Io)?.len();
            if len > max {
                return Err(ReplayStorageError::TooLarge);
            }
            let mut bytes = Vec::with_capacity(len as usize);
            file.take(max + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| ReplayStorageError::Io)?;
            if bytes.len() as u64 > max {
                return Err(ReplayStorageError::TooLarge);
            }
            Ok(bytes)
        }

        pub(crate) fn replace(&self, name: &str, bytes: &[u8]) -> Result<(), ReplayStorageError> {
            if self.exists(name)? {
                let existing = self.open_existing_file(name)?;
                validate_private_file(&existing)?;
            }
            let target = c_name(name)?;
            let mut random = [0_u8; 12];
            OsRng.fill_bytes(&mut random);
            let temp_name = CString::new(format!(".replay-state.{}.tmp", hex::encode(random)))
                .map_err(|_| ReplayStorageError::InvalidName)?;
            let descriptor = unsafe {
                libc::openat(
                    self.root.as_raw_fd(),
                    temp_name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    FILE_MODE,
                )
            };
            if descriptor < 0 {
                return Err(map_last_open_error());
            }
            let mut temp = unsafe { File::from_raw_fd(descriptor) };
            let result = (|| {
                validate_private_file(&temp)?;
                temp.write_all(bytes).map_err(|_| ReplayStorageError::Io)?;
                temp.sync_all().map_err(|_| ReplayStorageError::Io)?;
                if unsafe {
                    libc::renameat(
                        self.root.as_raw_fd(),
                        temp_name.as_ptr(),
                        self.root.as_raw_fd(),
                        target.as_ptr(),
                    )
                } != 0
                {
                    return Err(ReplayStorageError::Io);
                }
                #[cfg(test)]
                if self.fail_replace_at(ReplaceFault::AfterRenameBeforeDirectorySync) {
                    return Err(ReplayStorageError::Io);
                }
                self.root.sync_all().map_err(|_| ReplayStorageError::Io)?;
                #[cfg(test)]
                if self.fail_replace_at(ReplaceFault::AfterDirectorySync) {
                    return Err(ReplayStorageError::Io);
                }
                Ok(())
            })();
            if result.is_err() {
                unsafe {
                    libc::unlinkat(self.root.as_raw_fd(), temp_name.as_ptr(), 0);
                }
            }
            result
        }

        #[cfg(test)]
        pub(crate) fn inject_replace_fault(&self, fault: ReplaceFault) {
            self.replace_fault.store(fault as u8, Ordering::Release);
        }

        #[cfg(test)]
        fn fail_replace_at(&self, fault: ReplaceFault) -> bool {
            self.replace_fault
                .compare_exchange(
                    fault as u8,
                    ReplaceFault::None as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
        }

        fn open_existing_file(&self, name: &str) -> Result<File, ReplayStorageError> {
            let name = c_name(name)?;
            let descriptor = unsafe {
                libc::openat(
                    self.root.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if descriptor < 0 {
                return Err(map_last_open_error());
            }
            Ok(unsafe { File::from_raw_fd(descriptor) })
        }
    }

    #[cfg(test)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u8)]
    pub(crate) enum ReplaceFault {
        None = 0,
        AfterRenameBeforeDirectorySync = 1,
        AfterDirectorySync = 2,
    }

    impl Drop for TransactionLock {
        fn drop(&mut self) {
            let _ = self.0.unlock();
        }
    }

    impl Drop for InstanceLock {
        fn drop(&mut self) {
            let _ = self.0.unlock();
        }
    }

    fn validate_root(file: &File) -> Result<(), ReplayStorageError> {
        validate_root_identity(file)?;
        let metadata = file.metadata().map_err(|_| ReplayStorageError::Io)?;
        if metadata.permissions().mode() & 0o777 != ROOT_MODE {
            return Err(ReplayStorageError::UnsafePermissions);
        }
        Ok(())
    }

    fn validate_root_identity(file: &File) -> Result<(), ReplayStorageError> {
        let metadata = file.metadata().map_err(|_| ReplayStorageError::Io)?;
        if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(ReplayStorageError::UnsafePermissions);
        }
        Ok(())
    }

    fn open_directory(path: &Path) -> Result<File, ReplayStorageError> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let directory = options.open(path).map_err(map_open_error)?;
        if !directory
            .metadata()
            .map_err(|_| ReplayStorageError::Io)?
            .is_dir()
        {
            return Err(ReplayStorageError::InvalidWorkspace);
        }
        Ok(directory)
    }

    fn is_ancestor(ancestor: &File, descendant: &File) -> Result<bool, ReplayStorageError> {
        let ancestor_identity = file_identity(ancestor)?;
        let mut current = descendant.try_clone().map_err(|_| ReplayStorageError::Io)?;
        for _ in 0..MAX_ANCESTRY_DEPTH {
            let current_identity = file_identity(&current)?;
            if current_identity == ancestor_identity {
                return Ok(true);
            }
            let parent_name = c_name("..")?;
            let descriptor = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    parent_name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if descriptor < 0 {
                return Err(map_last_open_error());
            }
            let parent = unsafe { File::from_raw_fd(descriptor) };
            let parent_identity = file_identity(&parent)?;
            if parent_identity == current_identity {
                return Ok(false);
            }
            current = parent;
        }
        Err(ReplayStorageError::IdentityChanged)
    }

    fn file_identity(file: &File) -> Result<(u64, u64), ReplayStorageError> {
        let metadata = file.metadata().map_err(|_| ReplayStorageError::Io)?;
        Ok((metadata.dev(), metadata.ino()))
    }

    fn validate_private_file(file: &File) -> Result<(), ReplayStorageError> {
        let metadata = file.metadata().map_err(|_| ReplayStorageError::Io)?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(ReplayStorageError::InvalidFile);
        }
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o777 != FILE_MODE
        {
            return Err(ReplayStorageError::UnsafePermissions);
        }
        Ok(())
    }

    fn c_name(name: &str) -> Result<CString, ReplayStorageError> {
        if name.is_empty() || name.as_bytes().contains(&b'/') {
            return Err(ReplayStorageError::InvalidName);
        }
        CString::new(name.as_bytes()).map_err(|_| ReplayStorageError::InvalidName)
    }

    fn map_open_error(error: std::io::Error) -> ReplayStorageError {
        match error.raw_os_error() {
            Some(libc::ELOOP) => ReplayStorageError::SymlinkRejected,
            Some(libc::ENOENT) => ReplayStorageError::Missing,
            _ => ReplayStorageError::Io,
        }
    }

    fn map_root_open_error(path: &Path, error: std::io::Error) -> ReplayStorageError {
        if fs::symlink_metadata(path)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            ReplayStorageError::SymlinkRejected
        } else {
            map_open_error(error)
        }
    }

    fn map_last_open_error() -> ReplayStorageError {
        map_open_error(std::io::Error::last_os_error())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn overlap_follows_the_open_descriptor_after_root_is_moved() {
            let temp = tempfile::tempdir().unwrap();
            let safe_parent = temp.path().join("host-state");
            let workspace = temp.path().join("workspace");
            fs::create_dir(&safe_parent).unwrap();
            fs::create_dir(&workspace).unwrap();

            let original = safe_parent.join("broker");
            let moved = workspace.join("broker");
            let storage = ReplayStorage::bootstrap(&original, &workspace).unwrap();
            assert!(!storage.overlaps_directory(&workspace).unwrap());

            fs::rename(&original, &moved).unwrap();
            assert!(storage.overlaps_directory(&workspace).unwrap());
        }

        #[test]
        fn overlap_detects_a_workspace_nested_below_the_open_root() {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("broker");
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(ROOT_MODE)).unwrap();
            let workspace = root.join("workspace");
            fs::create_dir(&workspace).unwrap();
            let storage = ReplayStorage::open_existing(&root).unwrap();

            assert!(storage.overlaps_directory(&workspace).unwrap());
        }
    }

    #[allow(dead_code)]
    #[derive(Debug, thiserror::Error)]
    pub(crate) enum ReplayStorageError {
        #[error("replay storage is unsupported on this platform")]
        UnsupportedPlatform,
        #[error("replay storage root is invalid")]
        InvalidRoot,
        #[error("workspace directory is invalid")]
        InvalidWorkspace,
        #[error("replay storage overlaps the workspace")]
        StorageOverlapsWorkspace,
        #[error("replay storage entry is missing")]
        Missing,
        #[error("replay storage symlink was rejected")]
        SymlinkRejected,
        #[error("replay storage file is unsafe")]
        InvalidFile,
        #[error("replay storage ownership or permissions are unsafe")]
        UnsafePermissions,
        #[error("replay storage identity changed while opening")]
        IdentityChanged,
        #[error("replay storage file is too large")]
        TooLarge,
        #[error("replay storage name is invalid")]
        InvalidName,
        #[error("replay storage lock is unavailable")]
        LockUnavailable,
        #[error("another replay broker instance is active")]
        InstanceAlreadyActive,
        #[error("replay storage I/O failed")]
        Io,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod imp {
    use std::path::Path;

    pub(crate) struct ReplayStorage;
    pub(crate) struct TransactionLock;
    pub(crate) struct InstanceLock;

    impl ReplayStorage {
        pub(crate) fn bootstrap(_: &Path, _: &Path) -> Result<Self, ReplayStorageError> {
            Err(ReplayStorageError::UnsupportedPlatform)
        }
        pub(crate) fn open_existing(_: &Path) -> Result<Self, ReplayStorageError> {
            Err(ReplayStorageError::UnsupportedPlatform)
        }
        pub(crate) fn overlaps_directory(&self, _: &Path) -> Result<bool, ReplayStorageError> {
            Err(ReplayStorageError::UnsupportedPlatform)
        }
        pub(crate) fn lock_transaction(&self) -> Result<TransactionLock, ReplayStorageError> {
            Err(ReplayStorageError::UnsupportedPlatform)
        }
        pub(crate) fn try_lock_instance(&self) -> Result<InstanceLock, ReplayStorageError> {
            Err(ReplayStorageError::UnsupportedPlatform)
        }
        pub(crate) fn exists(&self, _: &str) -> Result<bool, ReplayStorageError> {
            Err(ReplayStorageError::UnsupportedPlatform)
        }
        pub(crate) fn read(&self, _: &str, _: u64) -> Result<Vec<u8>, ReplayStorageError> {
            Err(ReplayStorageError::UnsupportedPlatform)
        }
        pub(crate) fn replace(&self, _: &str, _: &[u8]) -> Result<(), ReplayStorageError> {
            Err(ReplayStorageError::UnsupportedPlatform)
        }
    }

    #[allow(dead_code)]
    #[derive(Debug, thiserror::Error)]
    pub(crate) enum ReplayStorageError {
        #[error("replay storage is unsupported on this platform")]
        UnsupportedPlatform,
        #[error("replay storage root is invalid")]
        InvalidRoot,
        #[error("workspace directory is invalid")]
        InvalidWorkspace,
        #[error("replay storage overlaps the workspace")]
        StorageOverlapsWorkspace,
        #[error("replay storage entry is missing")]
        Missing,
        #[error("replay storage symlink was rejected")]
        SymlinkRejected,
        #[error("replay storage file is unsafe")]
        InvalidFile,
        #[error("replay storage ownership or permissions are unsafe")]
        UnsafePermissions,
        #[error("replay storage identity changed while opening")]
        IdentityChanged,
        #[error("replay storage file is too large")]
        TooLarge,
        #[error("replay storage name is invalid")]
        InvalidName,
        #[error("replay storage lock is unavailable")]
        LockUnavailable,
        #[error("another replay broker instance is active")]
        InstanceAlreadyActive,
        #[error("replay storage I/O failed")]
        Io,
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
pub(crate) use imp::ReplaceFault;
pub(crate) use imp::{InstanceLock, ReplayStorage, ReplayStorageError};
