mod common;

use assert_cmd::Command;
use std::fs;

fn phantom(dir: &std::path::Path, args: &[&str]) -> assert_cmd::assert::Assert {
    Command::cargo_bin("phantom")
        .unwrap()
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .assert()
}

#[test]
fn undo_after_real_replace_defaults_to_dry_run_then_restores_without_printing_values() {
    let dir = common::canonical_tempdir();
    let cursor = dir.path().join(".cursor");
    fs::create_dir_all(&cursor).unwrap();
    let path = cursor.join("mcp.json");
    let original =
        br#"{"mcpServers":{"phantom":{"command":"/old","args":[],"env":{"K":"do-not-print-me"}}}}"#;
    fs::write(&path, original).unwrap();

    phantom(dir.path(), &["setup", "--client", "cursor", "--replace"]).success();
    let written = fs::read(&path).unwrap();
    assert_ne!(written, original);

    let out = phantom(dir.path(), &["setup", "--undo"])
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("Dry run"));
    assert!(text.contains("would restore"));
    assert!(!text.contains("do-not-print-me"));
    assert_eq!(fs::read(&path).unwrap(), written);

    let out = phantom(dir.path(), &["setup", "--undo", "--apply"])
        .success()
        .get_output()
        .stdout
        .clone();
    assert!(!String::from_utf8_lossy(&out).contains("do-not-print-me"));
    assert_eq!(fs::read(&path).unwrap(), original);
}

#[test]
fn undo_flags_are_validated() {
    let dir = common::canonical_tempdir();
    phantom(dir.path(), &["setup", "--apply"]).failure();
    phantom(dir.path(), &["setup", "--force-undo"]).failure();
    phantom(dir.path(), &["setup", "--undo", "--client", "cursor"]).failure();
    phantom(dir.path(), &["setup", "--undo", "--force-undo"]).failure();
}
