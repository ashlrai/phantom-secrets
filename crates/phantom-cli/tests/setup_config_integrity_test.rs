mod common;

use assert_cmd::Command;
use std::fs;

#[test]
fn explicit_claude_setup_preserves_invalid_json() {
    let dir = common::canonical_tempdir();
    let claude_dir = dir.path().join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();
    let settings_path = claude_dir.join("settings.local.json");
    let original = b"{ invalid json\n";
    fs::write(&settings_path, original).unwrap();

    Command::cargo_bin("phantom")
        .unwrap()
        .args(["setup", "--client", "claude"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .assert()
        .failure();

    assert_eq!(fs::read(settings_path).unwrap(), original);
}

#[test]
fn cursor_setup_preserves_empty_existing_json() {
    let dir = common::canonical_tempdir();
    let cursor_dir = dir.path().join(".cursor");
    fs::create_dir_all(&cursor_dir).unwrap();
    let config_path = cursor_dir.join("mcp.json");
    fs::write(&config_path, b"").unwrap();

    Command::cargo_bin("phantom")
        .unwrap()
        .args(["setup", "--client", "cursor"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .assert()
        .failure();

    assert!(fs::read(config_path).unwrap().is_empty());
}

#[test]
fn codex_setup_preserves_invalid_toml() {
    let dir = common::canonical_tempdir();
    let codex_dir = dir.path().join(".codex");
    fs::create_dir_all(&codex_dir).unwrap();
    let config_path = codex_dir.join("config.toml");
    let original = b"[mcp_servers\ninvalid = true\n";
    fs::write(&config_path, original).unwrap();

    Command::cargo_bin("phantom")
        .unwrap()
        .args(["setup", "--client", "codex"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .assert()
        .failure();

    assert_eq!(fs::read(config_path).unwrap(), original);
}
