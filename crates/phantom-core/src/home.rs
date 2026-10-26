//! Consistent machine-local home-directory resolution.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

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

/// Render `path` as `~/...` when it lies under `home`, joining the
/// home-relative components with `/` on every platform so user-facing and
/// JSON output names the same location identically on Windows and Unix.
/// Returns `None` when `path` is not under `home`.
pub fn tilde_path(path: &Path, home: &Path) -> Option<String> {
    let suffix = path.strip_prefix(home).ok()?;
    let parts: Vec<String> = suffix
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect();
    Some(format!("~/{}", parts.join("/")))
}

/// [`tilde_path`] against [`home_dir_with_platform_fallback`], falling back
/// to the native display of `path` when it is outside the home directory.
pub fn display_home_relative(path: &Path) -> String {
    home_dir_with_platform_fallback()
        .ok()
        .and_then(|home| tilde_path(path, &home))
        .unwrap_or_else(|| path.display().to_string())
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

    #[test]
    fn tilde_path_uses_forward_slashes_under_home() {
        let home = tempdir().unwrap();
        let nested = home.path().join(".gemini").join("settings.json");
        assert_eq!(
            tilde_path(&nested, home.path()).as_deref(),
            Some("~/.gemini/settings.json")
        );
        let deeper = home
            .path()
            .join(".codeium")
            .join("windsurf")
            .join("mcp_config.json");
        assert_eq!(
            tilde_path(&deeper, home.path()).as_deref(),
            Some("~/.codeium/windsurf/mcp_config.json")
        );
        let outside = tempdir().unwrap();
        assert_eq!(
            tilde_path(&outside.path().join("x.json"), home.path()),
            None
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
