mod common;

use assert_cmd::Command;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const VAULT_PASS: &str = "test-add-overwrite-authority-passphrase";

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
fn existing_name_is_denied_before_stdin_read_and_preserves_all_state() {
    let dir = common::canonical_tempdir();
    fs::write(
        dir.path().join(".env"),
        "EXISTING_KEY=sk-original-test-value\n",
    )
    .unwrap();
    phantom(&dir)
        .args(["init", "--from", ".env"])
        .assert()
        .success();

    let config_before = fs::read(dir.path().join(".phantom.toml")).unwrap();
    let dotenv_before = fs::read(dir.path().join(".env")).unwrap();
    let tree_before = snapshot_tree(dir.path());

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_phantom"))
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env_remove("PHANTOM_AUDIT")
        .args(["add", "EXISTING_KEY", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn overwrite attempt");

    // Keep the pipe open and provide no bytes. Reading stdin would block; a
    // prompt exit therefore proves the existing-name denial happened first.
    let open_stdin = child.stdin.take().expect("piped stdin");
    // CI runners may spend several seconds starting the debug binary and
    // deriving the test vault key before reaching the existing-name check.
    // Keep stdin open long enough to distinguish that work from an actual
    // blocked read without turning ordinary runner load into a false failure.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if child.try_wait().expect("poll overwrite attempt").is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("existing-name add blocked waiting for stdin");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(open_stdin);

    let output = child.wait_with_output().expect("collect overwrite denial");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("is already protected")
            && stderr.contains("refuses replacement before reading a value"),
        "unexpected denial: {stderr}"
    );

    assert_eq!(
        fs::read(dir.path().join(".phantom.toml")).unwrap(),
        config_before,
        "config changed after denied replacement"
    );
    assert_eq!(
        fs::read(dir.path().join(".env")).unwrap(),
        dotenv_before,
        "managed dotenv changed after denied replacement"
    );
    assert_eq!(
        snapshot_tree(dir.path()),
        tree_before,
        "vault or project files changed after denied replacement"
    );

    let listed = phantom(&dir).arg("list").assert().success();
    assert!(String::from_utf8_lossy(&listed.get_output().stdout).contains("EXISTING_KEY"));
}
