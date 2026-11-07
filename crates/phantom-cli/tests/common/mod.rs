use std::time::{Duration, Instant};
use tempfile::TempDir;

/// Create an integration-test directory beneath the platform temp directory's
/// canonical path. On macOS, `temp_dir()` is commonly rooted at `/var`, which
/// is a symlink to `/private/var`; passing that lexical alias as `HOME` or cwd
/// makes Phantom's no-follow transaction-lock checks correctly reject it.
pub fn canonical_tempdir() -> TempDir {
    let root = std::env::temp_dir()
        .canonicalize()
        .expect("resolve the platform temporary directory");
    tempfile::Builder::new()
        .prefix("phantom-cli-test-")
        .tempdir_in(root)
        .expect("create a temporary directory under its canonical root")
}

/// Poll a condition until it returns a value or the timeout expires.
/// Yielding between checks keeps process and filesystem waits responsive
/// without imposing a fixed sleep on the successful path.
#[allow(dead_code)] // Common is compiled once per integration-test binary.
pub fn poll<T>(timeout: Duration, mut check: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(value) = check() {
            return Some(value);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::yield_now();
    }
}

/// Run `phantom init --from .env` for a prepared test project.
#[allow(dead_code)] // Common is compiled once per integration-test binary.
pub fn init_project(dir: &TempDir, passphrase: &str) {
    phantom(dir, passphrase)
        .args(["init", "--from", ".env"])
        .assert()
        .success();
}

/// Build a CLI command scoped to a temporary project and test vault.
#[allow(dead_code)] // Common is compiled once per integration-test binary.
pub fn phantom(dir: &TempDir, passphrase: &str) -> assert_cmd::Command {
    phantom_with_home(dir, dir, passphrase)
}

/// Build a CLI command whose machine profile lives in `home`, a directory
/// separate from the project directory in `dir`.
///
/// Tests that assert a rejected invocation leaves the project tree untouched
/// need this: the Windows Known-Folder resolver requires both AppData
/// folders to exist, so `phantom` creates them under the profile — which
/// must not be the project directory for those assertions to hold.
#[allow(dead_code)] // Common is compiled once per integration-test binary.
pub fn phantom_with_home(dir: &TempDir, home: &TempDir, passphrase: &str) -> assert_cmd::Command {
    // Known Folders expands USERPROFILE and verifies both AppData folders.
    // Use an ordinary Win32 path: canonical temp roots may carry `\\?\`.
    let profile = profile_path(home.path());
    #[cfg(windows)]
    for folder in ["Roaming", "Local"] {
        std::fs::create_dir_all(profile.join("AppData").join(folder)).unwrap();
    }
    let mut command = assert_cmd::Command::cargo_bin("phantom").expect("binary not found");
    command
        .current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", passphrase)
        .env("HOME", home.path())
        .env("USERPROFILE", &profile)
        .env("APPDATA", profile.join("AppData/Roaming"))
        .env("LOCALAPPDATA", profile.join("AppData/Local"))
        .env("XDG_DATA_HOME", home.path().join("data"));
    command
}

/// Windows profile APIs expect ordinary drive/UNC paths, unlike filesystem APIs
/// which also accept canonical verbatim paths. Preserve UNC's leading slashes.
#[allow(dead_code)]
pub fn profile_path(path: &std::path::Path) -> std::path::PathBuf {
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        let mut components = path.components();
        if let Some(Component::Prefix(prefix)) = components.next() {
            let ordinary = match prefix.kind() {
                Prefix::VerbatimDisk(drive) => format!("{}:", char::from(drive)),
                Prefix::VerbatimUNC(server, share) => {
                    let mut root = std::path::PathBuf::from(r"\\");
                    root.push(server);
                    root.push(share);
                    return root.join(components.as_path());
                }
                _ => return path.to_path_buf(),
            };
            return std::path::PathBuf::from(ordinary).join(components.as_path());
        }
    }
    path.to_path_buf()
}

/// Exact data directory selected by the environment in `phantom()`.
/// Never search the operator's vault or accept an unrelated fallback file.
#[allow(dead_code)]
pub fn encrypted_file(dir: &TempDir, project_id: &str) -> std::path::PathBuf {
    #[cfg(windows)]
    let base = profile_path(dir.path()).join("AppData/Roaming/phantom/phantom-secrets/data");
    #[cfg(target_os = "macos")]
    let base = dir
        .path()
        .join("Library/Application Support/ai.phantom.phantom-secrets");
    #[cfg(not(any(windows, target_os = "macos")))]
    let base = dir.path().join("data/phantom-secrets");
    base.join("vaults").join(format!("{project_id}.vault"))
}
