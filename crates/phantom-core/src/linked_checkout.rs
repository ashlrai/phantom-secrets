//! Opt-in linked-checkout binding for fleet worktrees.
//!
//! The machine-local vault namespace is derived from the canonical directory
//! that holds `.phantom.toml` (see [`crate::config::PhantomConfig::load_from_bytes`]).
//! A `git worktree` of a checkout therefore opens a different, normally empty,
//! vault. This module lets a caller (the fleet) name a source checkout
//! explicitly. The binding is accepted only when:
//!
//! 1. The caller supplied the source path. Repository content never selects it.
//! 2. Both `.phantom.toml` files are regular files (no symlinks) and byte-identical.
//! 3. Both directories resolve to the same canonical git common dir, so the
//!    worktree really is a linked worktree of the source repository.
//! 4. The source and worktree are different directories.
//!
//! Any failure refuses the binding. There is no fallback to a partial match.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Maximum `.phantom.toml` size compared for a binding.
pub const MAX_BOUND_CONFIG_BYTES: u64 = 1024 * 1024;

/// Why a linked-checkout binding was refused. Value-free: no paths or bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindRefusal {
    SourceMissing,
    SameDirectory,
    ConfigMissing,
    ConfigSymlink,
    ConfigNotRegularFile,
    ConfigTooLarge,
    ConfigMismatch,
    NotAGitCheckout,
    CommonDirMismatch,
}

impl BindRefusal {
    /// Stable kebab-case id for logs and JSON.
    pub fn id(self) -> &'static str {
        match self {
            Self::SourceMissing => "source-missing",
            Self::SameDirectory => "same-directory",
            Self::ConfigMissing => "config-missing",
            Self::ConfigSymlink => "config-symlink",
            Self::ConfigNotRegularFile => "config-not-regular-file",
            Self::ConfigTooLarge => "config-too-large",
            Self::ConfigMismatch => "config-mismatch",
            Self::NotAGitCheckout => "not-a-git-checkout",
            Self::CommonDirMismatch => "common-dir-mismatch",
        }
    }
}

impl std::fmt::Display for BindRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "linked checkout binding refused: {}", self.id())
    }
}

impl std::error::Error for BindRefusal {}

/// Verify that `worktree` may use the custody namespace of `source`.
/// Returns the canonical source directory on success.
pub fn verify_linked_checkout(
    worktree: &Path,
    source: &Path,
) -> std::result::Result<PathBuf, BindRefusal> {
    let source = std::fs::canonicalize(source).map_err(|_| BindRefusal::SourceMissing)?;
    let worktree = std::fs::canonicalize(worktree).map_err(|_| BindRefusal::NotAGitCheckout)?;
    if source == worktree {
        return Err(BindRefusal::SameDirectory);
    }
    let source_bytes = read_regular_config(&source)?;
    let worktree_bytes = read_regular_config(&worktree)?;
    if source_bytes != worktree_bytes {
        return Err(BindRefusal::ConfigMismatch);
    }
    let source_common = git_common_dir(&source)?;
    let worktree_common = git_common_dir(&worktree)?;
    if source_common != worktree_common {
        return Err(BindRefusal::CommonDirMismatch);
    }
    Ok(source)
}

fn read_regular_config(dir: &Path) -> std::result::Result<Vec<u8>, BindRefusal> {
    let path = dir.join(".phantom.toml");
    let meta = std::fs::symlink_metadata(&path).map_err(|_| BindRefusal::ConfigMissing)?;
    if meta.file_type().is_symlink() {
        return Err(BindRefusal::ConfigSymlink);
    }
    if !meta.file_type().is_file() {
        return Err(BindRefusal::ConfigNotRegularFile);
    }
    if meta.len() > MAX_BOUND_CONFIG_BYTES {
        return Err(BindRefusal::ConfigTooLarge);
    }
    std::fs::read(&path).map_err(|_| BindRefusal::ConfigMissing)
}

fn git_common_dir(dir: &Path) -> std::result::Result<PathBuf, BindRefusal> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .env_remove("GIT_DIR")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_WORK_TREE")
        .output()
        .map_err(|_| BindRefusal::NotAGitCheckout)?;
    if !output.status.success() {
        return Err(BindRefusal::NotAGitCheckout);
    }
    let text = String::from_utf8(output.stdout).map_err(|_| BindRefusal::NotAGitCheckout)?;
    let trimmed = text.trim_end_matches(['\n', '\r']);
    if trimmed.is_empty() {
        return Err(BindRefusal::NotAGitCheckout);
    }
    std::fs::canonicalize(trimmed).map_err(|_| BindRefusal::NotAGitCheckout)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::process::Command;

    const CONFIG: &str = "[phantom]\nversion = \"1\"\nproject_id = \"fake-project\"\n";

    fn git(dir: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
            .args(args)
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .status()
            .expect("git runs");
        assert!(status.success(), "git {args:?}");
    }

    /// Source repo with a committed `.phantom.toml` and one linked worktree.
    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        std::fs::create_dir(&source).unwrap();
        git(&source, &["init", "-q"]);
        std::fs::write(source.join(".phantom.toml"), CONFIG).unwrap();
        git(&source, &["add", ".phantom.toml"]);
        git(&source, &["commit", "-q", "-m", "init"]);
        let worktree = tmp.path().join("wt");
        git(
            &source,
            &[
                "worktree",
                "add",
                "-q",
                worktree.to_str().unwrap(),
                "-b",
                "w",
            ],
        );
        (tmp, source, worktree)
    }

    #[test]
    fn linked_worktree_with_identical_config_binds_to_source() {
        let (_tmp, source, worktree) = fixture();
        let bound = verify_linked_checkout(&worktree, &source).unwrap();
        assert_eq!(bound, std::fs::canonicalize(&source).unwrap());
    }

    #[test]
    fn unrelated_repo_with_identical_config_is_refused() {
        let (tmp, _source, _worktree) = fixture();
        let other = tmp.path().join("other");
        std::fs::create_dir(&other).unwrap();
        git(&other, &["init", "-q"]);
        std::fs::write(other.join(".phantom.toml"), CONFIG).unwrap();
        let (_tmp2, source2, _) = fixture();
        assert_eq!(
            verify_linked_checkout(&other, &source2),
            Err(BindRefusal::CommonDirMismatch)
        );
    }

    #[test]
    fn non_git_directory_is_refused() {
        let (tmp, source, _worktree) = fixture();
        let plain = tmp.path().join("plain");
        std::fs::create_dir(&plain).unwrap();
        std::fs::write(plain.join(".phantom.toml"), CONFIG).unwrap();
        assert_eq!(
            verify_linked_checkout(&plain, &source),
            Err(BindRefusal::NotAGitCheckout)
        );
    }

    #[test]
    fn different_config_bytes_are_refused() {
        let (_tmp, source, worktree) = fixture();
        std::fs::write(worktree.join(".phantom.toml"), format!("{CONFIG}# edit\n")).unwrap();
        assert_eq!(
            verify_linked_checkout(&worktree, &source),
            Err(BindRefusal::ConfigMismatch)
        );
    }

    #[test]
    fn symlinked_worktree_config_is_refused() {
        let (_tmp, source, worktree) = fixture();
        std::fs::remove_file(worktree.join(".phantom.toml")).unwrap();
        std::os::unix::fs::symlink(source.join(".phantom.toml"), worktree.join(".phantom.toml"))
            .unwrap();
        assert_eq!(
            verify_linked_checkout(&worktree, &source),
            Err(BindRefusal::ConfigSymlink)
        );
    }

    #[test]
    fn symlinked_source_config_is_refused() {
        let (tmp, source, worktree) = fixture();
        let elsewhere = tmp.path().join("elsewhere.toml");
        std::fs::write(&elsewhere, CONFIG).unwrap();
        std::fs::remove_file(source.join(".phantom.toml")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, source.join(".phantom.toml")).unwrap();
        assert_eq!(
            verify_linked_checkout(&worktree, &source),
            Err(BindRefusal::ConfigSymlink)
        );
    }

    #[test]
    fn symlink_to_the_worktree_as_source_is_same_directory() {
        let (tmp, _source, worktree) = fixture();
        let alias = tmp.path().join("alias");
        std::os::unix::fs::symlink(&worktree, &alias).unwrap();
        assert_eq!(
            verify_linked_checkout(&worktree, &alias),
            Err(BindRefusal::SameDirectory)
        );
    }

    #[test]
    fn missing_configs_and_source_are_refused() {
        let (tmp, source, worktree) = fixture();
        assert_eq!(
            verify_linked_checkout(&worktree, &tmp.path().join("nope")),
            Err(BindRefusal::SourceMissing)
        );
        std::fs::remove_file(worktree.join(".phantom.toml")).unwrap();
        assert_eq!(
            verify_linked_checkout(&worktree, &source),
            Err(BindRefusal::ConfigMissing)
        );
    }

    #[test]
    fn config_directory_is_not_a_regular_file() {
        let (_tmp, source, worktree) = fixture();
        std::fs::remove_file(worktree.join(".phantom.toml")).unwrap();
        std::fs::create_dir(worktree.join(".phantom.toml")).unwrap();
        assert_eq!(
            verify_linked_checkout(&worktree, &source),
            Err(BindRefusal::ConfigNotRegularFile)
        );
    }

    #[test]
    fn git_dir_environment_cannot_fake_the_common_dir() {
        let (tmp, source, _worktree) = fixture();
        let other = tmp.path().join("other");
        std::fs::create_dir(&other).unwrap();
        git(&other, &["init", "-q"]);
        std::fs::write(other.join(".phantom.toml"), CONFIG).unwrap();
        // A hostile environment pointing GIT_DIR at the source must not help.
        std::env::set_var("GIT_DIR", source.join(".git"));
        let result = verify_linked_checkout(&other, &source);
        std::env::remove_var("GIT_DIR");
        assert_eq!(result, Err(BindRefusal::CommonDirMismatch));
    }
}
