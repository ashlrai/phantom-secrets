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
        .env("HOME", dir.path());
    command
}
