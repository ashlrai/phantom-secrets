//! Consistent machine-local home-directory resolution.

use std::ffi::OsString;
use std::io;
use std::path::PathBuf;

/// Resolve Phantom's machine-local home without accepting relative or
/// drive-relative environment overrides.
///
/// In particular, a native Windows process must not interpret an MSYS path
/// such as `/c/Users/name` relative to its current drive. A native absolute
/// `HOME` remains the first choice so callers and tests can intentionally
/// isolate Phantom; otherwise `USERPROFILE` and the platform resolver follow.
pub fn home_dir() -> io::Result<PathBuf> {
    resolve_home_dir(None)
}

/// Resolve the home directory with the operating system's account database as
/// a final fallback. Callers that historically required an explicit process
/// home can use [`home_dir`] to preserve that fail-closed contract.
pub fn home_dir_with_platform_fallback() -> io::Result<PathBuf> {
    resolve_home_dir(dirs::home_dir())
}

fn resolve_home_dir(platform_fallback: Option<PathBuf>) -> io::Result<PathBuf> {
    select_home_dir(
        std::env::var_os("HOME"),
        std::env::var_os("USERPROFILE"),
        platform_fallback,
    )
    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "cannot resolve home directory"))
}

pub(crate) fn select_home_dir(
    home: Option<OsString>,
    user_profile: Option<OsString>,
    platform_fallback: Option<PathBuf>,
) -> Option<PathBuf> {
    home.into_iter()
        .chain(user_profile)
        .map(PathBuf::from)
        .chain(platform_fallback)
        .find(|path| !path.as_os_str().is_empty() && path.is_absolute())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn selection_prefers_valid_home_and_rejects_relative_overrides() {
        let home = tempdir().unwrap();
        let user_profile = tempdir().unwrap();
        let platform = tempdir().unwrap();

        assert_eq!(
            select_home_dir(
                Some(home.path().as_os_str().to_owned()),
                Some(user_profile.path().as_os_str().to_owned()),
                Some(platform.path().to_path_buf()),
            )
            .unwrap(),
            home.path()
        );
        assert_eq!(
            select_home_dir(
                Some(OsString::from("relative-home")),
                Some(user_profile.path().as_os_str().to_owned()),
                Some(platform.path().to_path_buf()),
            )
            .unwrap(),
            user_profile.path()
        );
    }

    #[cfg(windows)]
    #[test]
    fn msys_home_falls_back_to_native_windows_profile() {
        let user_profile = dirs::home_dir().expect("Windows test requires a native home");
        assert_eq!(
            select_home_dir(
                Some(OsString::from("/c/Users/phantom-test")),
                Some(user_profile.clone().into_os_string()),
                None,
            )
            .unwrap(),
            user_profile
        );
    }
}
