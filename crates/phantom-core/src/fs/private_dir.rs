//! A Phantom-owned private state directory held open by descriptor.
//!
//! [`PrivateStateDir`] is the shared replacement for the per-crate
//! "create a 0700 directory, then open files in it by path" helpers. On Unix
//! the directory is created with mode 0700 (never umask-wide first), opened
//! with `O_NOFOLLOW`, required to be owned by the current user, tightened to
//! 0700 through that same descriptor, and retained: every later file create,
//! open, replace and fsync is resolved relative to the retained descriptor,
//! so a directory renamed away and replaced by a symlink after the check
//! cannot redirect a Phantom write.
//!
//! Refusals (a symlink, a non-directory or non-regular entry, a multiply
//! linked file, or an entry owned by another user) are reported as
//! `io::ErrorKind::InvalidData` so callers can map them onto their own
//! unsafe-storage error; a missing entry stays `io::ErrorKind::NotFound`.
//!
//! On other platforms the same API falls back to path-based operations that
//! refuse symlinks and reparse points at the final component.

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const TEMP_CREATE_ATTEMPTS: usize = 32;

/// A Phantom-owned private directory retained for descriptor-relative file
/// operations. See the module documentation.
#[derive(Debug)]
pub struct PrivateStateDir {
    path: PathBuf,
    #[cfg(unix)]
    handle: File,
}

impl PrivateStateDir {
    /// Create (mode 0700) or open the Phantom directory `path` and keep it.
    ///
    /// Ancestors of `path` are resolved normally, as in
    /// [`super::ensure_private_leaf_dir`]; only the final component is
    /// Phantom's. A symlink or non-directory there is refused, as is a
    /// directory owned by another user. An existing owned directory with
    /// group or other bits is tightened to 0700 through the retained
    /// descriptor. When the directory is created, its parent is fsynced.
    pub fn ensure(path: &Path) -> io::Result<Self> {
        let created = create_private_directory(path)?;
        #[cfg(unix)]
        let state = {
            let handle =
                super::open_owned_directory(None, path, false).map_err(|e| refusal(e, path))?;
            make_private(&handle, path)?;
            Self {
                path: path.to_path_buf(),
                handle,
            }
        };
        #[cfg(not(unix))]
        let state = {
            require_real_directory(path)?;
            Self {
                path: path.to_path_buf(),
            }
        };
        if created {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                super::sync_parent_dir(parent)?;
            }
        }
        Ok(state)
    }

    /// Create (mode 0700) or open the private child directory `name` (one
    /// plain path component) relative to this directory, with the same
    /// checks as [`Self::ensure`]. When the child is created, this directory
    /// is fsynced.
    pub fn ensure_child(&self, name: &str) -> io::Result<Self> {
        let path = self.path.join(name);
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let c_name = single_component(name)?;
            // SAFETY: the descriptor is owned by `self.handle` and open, and
            // `c_name` is NUL-terminated.
            let created =
                unsafe { libc::mkdirat(self.handle.as_raw_fd(), c_name.as_ptr(), 0o700) } == 0;
            if !created {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(refusal(error, &path));
                }
            }
            let handle = super::open_owned_directory(Some(&self.handle), Path::new(name), false)
                .map_err(|e| refusal(e, &path))?;
            make_private(&handle, &path)?;
            if created {
                self.handle.sync_all()?;
            }
            Ok(Self { path, handle })
        }
        #[cfg(not(unix))]
        {
            single_component(name)?;
            Self::ensure(&path)
        }
    }

    /// The path this directory was opened at. Informational only: file
    /// operations never re-resolve it on Unix.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Open the regular file `name` (one plain path component) read-write,
    /// creating it with mode 0600 when `create` is set. The file must be a
    /// single-link regular file owned by the current user; its mode is
    /// repaired to 0600 through the opened handle. A symlink is never
    /// followed and an existing file is never truncated.
    pub fn open_file(&self, name: &str, create: bool) -> io::Result<File> {
        let path = self.path.join(name);
        #[cfg(unix)]
        {
            single_component(name)?;
            let file = super::open_owned_file_at(&self.handle, Path::new(name), create)
                .map_err(|e| refusal(e, &path))?;
            require_single_link(&file, &path)?;
            repair_private_file(&file)?;
            Ok(file)
        }
        #[cfg(not(unix))]
        {
            single_component(name)?;
            refuse_link_entry(&path)?;
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true).create(create);
            no_reparse(&mut options);
            let file = options.open(&path)?;
            if !file.metadata()?.is_file() {
                return Err(unsafe_entry(&path));
            }
            Ok(file)
        }
    }

    /// Create `name` (one plain path component) as a new mode-0600 regular
    /// file. Any existing entry, including a dangling symlink, yields
    /// `ErrorKind::AlreadyExists` and is left untouched.
    pub fn create_new_file(&self, name: &str) -> io::Result<File> {
        let path = self.path.join(name);
        #[cfg(unix)]
        {
            single_component(name)?;
            let file = super::open_nofollow_at(
                Some(&self.handle),
                Path::new(name),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
            .map_err(|e| refusal(e, &path))?;
            repair_private_file(&file)?;
            Ok(file)
        }
        #[cfg(not(unix))]
        {
            single_component(name)?;
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true).create_new(true);
            no_reparse(&mut options);
            options.open(&path)
        }
    }

    /// Atomically replace `name` (one plain path component) with `contents`.
    ///
    /// The bytes go to a fresh same-directory mode-0600 staging file that is
    /// fsynced and renamed over `name` relative to this directory, which is
    /// then fsynced. The staging file is removed on failure. When no unique
    /// staging name can be allocated this returns `ErrorKind::AlreadyExists`.
    pub fn replace_file(&self, name: &str, contents: &[u8]) -> io::Result<()> {
        single_component(name)?;
        for _ in 0..TEMP_CREATE_ATTEMPTS {
            let temp = format!(".phantom-state-{:016x}.tmp", rand::random::<u64>());
            let mut file = match self.create_new_file(&temp) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            };
            let result = file
                .write_all(contents)
                .and_then(|()| file.sync_all())
                .and_then(|()| {
                    drop(file);
                    self.rename(&temp, name)
                })
                .and_then(|()| self.sync());
            if result.is_err() {
                self.remove_staging(&temp);
            }
            return result;
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique Phantom staging file",
        ))
    }

    /// Fsync this directory so entry updates inside it are durable (a no-op
    /// where the platform offers no directory handle sync).
    pub fn sync(&self) -> io::Result<()> {
        #[cfg(unix)]
        {
            self.handle.sync_all()
        }
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }

    #[cfg(unix)]
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let c_from = single_component(from)?;
        let c_to = single_component(to)?;
        let fd = self.handle.as_raw_fd();
        // SAFETY: both names are NUL-terminated and resolved relative to the
        // descriptor owned by `self.handle`.
        if unsafe { libc::renameat(fd, c_from.as_ptr(), fd, c_to.as_ptr()) } != 0 {
            return Err(refusal(io::Error::last_os_error(), &self.path.join(to)));
        }
        Ok(())
    }

    #[cfg(windows)]
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        };
        let wide = |path: &Path| {
            path.as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect::<Vec<_>>()
        };
        let from = wide(&self.path.join(from));
        let to = wide(&self.path.join(to));
        // SAFETY: both buffers are NUL-terminated UTF-16 paths that outlive
        // the call.
        if unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(not(any(unix, windows)))]
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        std::fs::rename(self.path.join(from), self.path.join(to))
    }

    fn remove_staging(&self, name: &str) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if let Ok(c_name) = single_component(name) {
                // SAFETY: the name is NUL-terminated and resolved relative to
                // the descriptor owned by `self.handle`.
                unsafe { libc::unlinkat(self.handle.as_raw_fd(), c_name.as_ptr(), 0) };
            }
        }
        #[cfg(not(unix))]
        {
            let _ = std::fs::remove_file(self.path.join(name));
        }
    }
}

/// Create `path` with mode 0700 (Unix). Returns whether it was created; an
/// existing entry of any kind is left for the caller's no-follow open to
/// judge.
fn create_private_directory(path: &Path) -> io::Result<bool> {
    #[allow(unused_mut)]
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error),
    }
}

/// Validate `name` as one plain path component and return it NUL-terminated.
fn single_component(name: &str) -> io::Result<std::ffi::CString> {
    let plain = matches!(
        Path::new(name).components().collect::<Vec<_>>().as_slice(),
        [std::path::Component::Normal(_)]
    ) && !name.contains('/')
        && !name.contains('\\');
    if !plain {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("not a single path component: {name}"),
        ));
    }
    std::ffi::CString::new(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path contains a NUL byte: {name}"),
        )
    })
}

fn unsafe_entry(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "Phantom state entry is a symlink, not the expected type, multiply linked, or not owned by the current user: {}",
            path.display()
        ),
    )
}

/// Normalize the no-follow refusals of `openat`/`renameat` (a symlink, a
/// directory where a file was expected, or the reverse) to `InvalidData`.
#[cfg(unix)]
fn refusal(error: io::Error, path: &Path) -> io::Error {
    let refused = matches!(
        error.raw_os_error(),
        Some(libc::ELOOP) | Some(libc::ENOTDIR) | Some(libc::EISDIR) | Some(libc::EMLINK)
    ) || error.kind() == io::ErrorKind::InvalidData;
    if refused {
        unsafe_entry(path)
    } else {
        error
    }
}

/// Require the retained directory to be private, tightening an owned one
/// with group or other bits through its descriptor first.
#[cfg(unix)]
fn make_private(directory: &File, path: &Path) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    if directory.metadata()?.mode() & 0o077 != 0 {
        // SAFETY: the descriptor is owned by `directory` and open; ownership
        // was checked by `open_owned_directory`.
        if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    if directory.metadata()?.mode() & 0o077 != 0 {
        return Err(unsafe_entry(path));
    }
    Ok(())
}

#[cfg(unix)]
fn require_single_link(file: &File, path: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    if file.metadata()?.nlink() != 1 {
        return Err(unsafe_entry(path));
    }
    Ok(())
}

#[cfg(unix)]
fn repair_private_file(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    if file.metadata()?.mode() & 0o7777 != 0o600 {
        // SAFETY: the descriptor is owned by `file` and open.
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_real_directory(path: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || is_reparse(&metadata) {
        return Err(unsafe_entry(path));
    }
    Ok(())
}

#[cfg(not(unix))]
fn refuse_link_entry(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || is_reparse(&metadata) =>
        {
            Err(unsafe_entry(path))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(not(unix))]
fn is_reparse(_metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        super::is_reparse_point(_metadata)
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(not(unix))]
fn no_reparse(_options: &mut std::fs::OpenOptions) {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        _options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    }

    #[test]
    fn ensure_creates_private_and_tightens_existing_owned_directory() {
        let temp = tempfile::tempdir().unwrap();
        let created = temp.path().join("state");
        PrivateStateDir::ensure(&created).unwrap();
        assert_eq!(mode(&created), 0o700);

        let existing = temp.path().join("existing");
        std::fs::create_dir(&existing).unwrap();
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o755)).unwrap();
        let state = PrivateStateDir::ensure(&existing).unwrap();
        assert_eq!(mode(&existing), 0o700);
        let child = state.ensure_child("nested").unwrap();
        assert_eq!(mode(child.path()), 0o700);
    }

    #[test]
    fn symlinked_directory_is_refused_and_its_target_left_alone() {
        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = temp.path().join("state");
        symlink(&outside, &link).unwrap();

        let error = PrivateStateDir::ensure(&link).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(mode(&outside), 0o755);

        let state = PrivateStateDir::ensure(&temp.path().join("real")).unwrap();
        symlink(&outside, temp.path().join("real/child")).unwrap();
        let error = state.ensure_child("child").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(mode(&outside), 0o755);
    }

    #[test]
    fn files_resolve_through_the_retained_directory_after_a_swap() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state");
        let state = PrivateStateDir::ensure(&path).unwrap();
        let outside = temp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::rename(&path, temp.path().join("moved")).unwrap();
        symlink(&outside, &path).unwrap();

        state.open_file("lock", true).unwrap();
        state.replace_file("record", b"one").unwrap();
        state.create_new_file("fresh").unwrap();

        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
        assert_eq!(
            std::fs::read(temp.path().join("moved/record")).unwrap(),
            b"one"
        );
        assert_eq!(mode(&temp.path().join("moved/record")), 0o600);
    }

    #[test]
    fn symlinked_and_hard_linked_files_are_refused_without_changing_targets() {
        let temp = tempfile::tempdir().unwrap();
        let state = PrivateStateDir::ensure(&temp.path().join("state")).unwrap();
        let target = temp.path().join("target");
        std::fs::write(&target, b"sentinel").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();

        symlink(&target, state.path().join("linked")).unwrap();
        let error = state.open_file("linked", true).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let error = state.create_new_file("linked").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);

        std::fs::hard_link(&target, state.path().join("hard")).unwrap();
        let error = state.open_file("hard", false).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        assert_eq!(mode(&target), 0o644);
        assert_eq!(std::fs::read(&target).unwrap(), b"sentinel");
    }

    #[test]
    fn names_must_be_one_plain_component() {
        let temp = tempfile::tempdir().unwrap();
        let state = PrivateStateDir::ensure(&temp.path().join("state")).unwrap();
        for name in ["", ".", "..", "a/b", "../escape"] {
            assert_eq!(
                state.open_file(name, true).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                state.replace_file(name, b"x").unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                state.ensure_child(name).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert!(std::fs::read_dir(temp.path())
            .unwrap()
            .all(|entry| entry.unwrap().file_name() == "state"));
    }

    #[test]
    fn directory_owned_by_another_user_is_refused_and_left_alone() {
        // Only a privileged test run can stage a directory another user owns.
        // SAFETY: geteuid has no preconditions and cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let foreign = temp.path().join("foreign");
        std::fs::create_dir(&foreign).unwrap();
        std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::chown(&foreign, Some(65_534), Some(65_534)).unwrap();

        let error = PrivateStateDir::ensure(&foreign).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(mode(&foreign), 0o755);
    }
}
