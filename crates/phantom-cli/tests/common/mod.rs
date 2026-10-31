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
    let mut command = assert_cmd::Command::cargo_bin("phantom").expect("binary not found");
    command
        .current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", passphrase)
        .env("HOME", dir.path())
        .env("USERPROFILE", dir.path())
        .env("APPDATA", dir.path().join("appdata"))
        .env("LOCALAPPDATA", dir.path().join("localappdata"))
        .env("XDG_DATA_HOME", dir.path().join("data"));
    command
}

/// Locate only this fixture project's vault, including an empty vault's lock.
///
/// The child resolves its vault directory through the platform data-dir
/// resolver against the environment `phantom()` sets. On Unix that is
/// `$XDG_DATA_HOME`/`$HOME`, so the vault lands beneath this tempdir. On
/// Windows the Known-Folder lookup expands `%USERPROFILE%` from the child
/// environment *and verifies the folder exists*: `<tempdir>\AppData\Roaming`
/// is absent, so the child falls back to the real profile's `<home>/.phantom`
/// rather than the roaming data dir this process resolves. Search the
/// tempdir first, then both resolver outcomes; panic naming everything
/// checked when init left no vault anywhere.
#[allow(dead_code)]
pub fn encrypted_file(dir: &TempDir, project_id: &str) -> std::path::PathBuf {
    fn find(root: &std::path::Path, project_id: &str) -> Option<std::path::PathBuf> {
        let path = root.join("vaults").join(format!("{project_id}.vault"));
        if path.is_file() || path.with_extension("lock").is_file() {
            return Some(path);
        }
        for entry in std::fs::read_dir(root).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                if let Some(path) = find(&entry.path(), project_id) {
                    return Some(path);
                }
            }
        }
        None
    }
    if let Some(found) = find(dir.path(), project_id) {
        return found;
    }
    let mut candidates = Vec::new();
    if let Ok(path) = phantom_vault::encrypted_file_vault_path(project_id) {
        candidates.push(path);
    }
    candidates.push(
        phantom_vault::file_vault_fallback_dir()
            .join("vaults")
            .join(format!("{project_id}.vault")),
    );
    for candidate in &candidates {
        if candidate.is_file() || candidate.with_extension("lock").is_file() {
            return candidate.clone();
        }
    }
    panic!("init provisioned no vault for {project_id} under {dir:?} or {candidates:?}")
}
