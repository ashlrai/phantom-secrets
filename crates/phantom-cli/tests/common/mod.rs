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
