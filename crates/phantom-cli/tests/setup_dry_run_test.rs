mod common;

use assert_cmd::Command;
use std::fs;

#[test]
fn dry_run_shows_a_diff_writes_nothing_and_never_prints_env_values() {
    let dir = common::canonical_tempdir();
    let cursor = dir.path().join(".cursor");
    fs::create_dir_all(&cursor).unwrap();
    let path = cursor.join("mcp.json");
    let original =
        br#"{"mcpServers":{"phantom":{"command":"/old","args":[],"env":{"K":"do-not-print-me"}}}}"#;
    fs::write(&path, original).unwrap();

    let out = Command::cargo_bin("phantom")
        .unwrap()
        .args(["setup", "--client", "cursor", "--dry-run"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("Nothing will be written"));
    assert!(text.contains("/old"));
    assert!(text.contains("env"));
    assert!(!text.contains("do-not-print-me"));
    assert_eq!(fs::read(&path).unwrap(), original);
}

#[test]
fn dry_run_creates_no_files_when_config_is_missing() {
    let dir = common::canonical_tempdir();
    Command::cargo_bin("phantom")
        .unwrap()
        .args(["setup", "--client", "gemini", "--dry-run"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .assert()
        .success();
    assert!(!dir.path().join(".gemini").exists());
}

#[test]
fn dry_run_is_refused_for_claude_and_conflicts_with_print() {
    let dir = common::canonical_tempdir();
    Command::cargo_bin("phantom")
        .unwrap()
        .args(["setup", "--client", "claude", "--dry-run"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .assert()
        .failure();
    Command::cargo_bin("phantom")
        .unwrap()
        .args(["setup", "--client", "cursor", "--dry-run", "--print"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .assert()
        .failure();
    assert!(!dir.path().join(".mcp.json").exists());
}
