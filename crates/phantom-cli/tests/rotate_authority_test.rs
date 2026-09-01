mod common;

use assert_cmd::Command;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const VAULT_PASS: &str = "test-rotate-authority-passphrase";

fn phantom(dir: &TempDir) -> Command {
    let mut command = Command::cargo_bin("phantom").expect("binary not found");
    command
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env_remove("PHANTOM_AUDIT");
    command
}

fn snapshot_tree(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn visit(root: &Path, current: &Path, output: &mut Vec<(PathBuf, Vec<u8>)>) {
        let mut entries = fs::read_dir(current)
            .expect("read snapshot directory")
            .map(|entry| entry.expect("read snapshot entry"))
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).expect("snapshot metadata");
            if metadata.is_dir() {
                visit(root, &path, output);
            } else if metadata.is_file() {
                output.push((
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    fs::read(path).expect("snapshot file"),
                ));
            }
        }
    }

    let mut output = Vec::new();
    visit(root, root, &mut output);
    output
}

#[test]
fn headless_rotate_is_denied_before_vault_access_and_preserves_all_state() {
    let dir = common::canonical_tempdir();
    fs::write(
        dir.path().join(".env"),
        "ALPHA_KEY=sk-original-alpha-value\nBETA_KEY=sk-original-beta-value\n",
    )
    .unwrap();
    phantom(&dir)
        .args(["init", "--from", ".env"])
        .assert()
        .success();

    let config_before = fs::read(dir.path().join(".phantom.toml")).unwrap();
    let dotenv_before = fs::read(dir.path().join(".env")).unwrap();
    let tree_before = snapshot_tree(dir.path());

    // A deliberately wrong vault passphrase proves the terminal denial occurs
    // before the command attempts to open or decrypt the vault.
    let denied = phantom(&dir)
        .env("PHANTOM_VAULT_PASSPHRASE", "wrong-passphrase")
        .arg("rotate")
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&denied.get_output().stderr);
    assert!(
        stderr.contains("requires attached stdin, stdout, and stderr terminals")
            && stderr.contains("No vault values were read")
            && !stderr.contains("decrypt"),
        "unexpected denial: {stderr}"
    );

    assert_eq!(
        fs::read(dir.path().join(".phantom.toml")).unwrap(),
        config_before,
        "config changed after denied token remap"
    );
    assert_eq!(
        fs::read(dir.path().join(".env")).unwrap(),
        dotenv_before,
        "managed dotenv changed after denied token remap"
    );
    assert_eq!(
        snapshot_tree(dir.path()),
        tree_before,
        "vault or project files changed after denied token remap"
    );
}
