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
    assert!(!dir.path().join(".mcp.json").exists());
}

#[test]
fn explicit_claude_setup_rejects_invalid_project_mcp_before_settings_changes() {
    let dir = common::canonical_tempdir();
    let claude_dir = dir.path().join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();
    let settings_path = claude_dir.join("settings.local.json");
    let original = br#"{"permissions":{"allow":["Read(./.env)"]}}"#;
    fs::write(&settings_path, original).unwrap();
    let mcp_path = dir.path().join(".mcp.json");
    let invalid = b"{ invalid project mcp\n";
    fs::write(&mcp_path, invalid).unwrap();

    Command::cargo_bin("phantom")
        .unwrap()
        .args(["setup", "--client", "claude"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .assert()
        .failure();

    assert_eq!(fs::read(settings_path).unwrap(), original);
    assert_eq!(fs::read(mcp_path).unwrap(), invalid);
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

/// `phantom setup --status` listed Gemini CLI, but `--client gemini` was
/// rejected by clap, so that row could never become `wired`.
#[test]
fn gemini_setup_wires_mcp_servers_and_keeps_other_settings() {
    let dir = common::canonical_tempdir();
    let gemini_dir = dir.path().join(".gemini");
    fs::create_dir_all(&gemini_dir).unwrap();
    let settings_path = gemini_dir.join("settings.json");
    fs::write(
        &settings_path,
        br#"{"theme":"GitHub","mcpServers":{"other":{"command":"other-mcp"}}}"#,
    )
    .unwrap();

    Command::cargo_bin("phantom")
        .unwrap()
        .args(["setup", "--client", "gemini"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .assert()
        .success();

    let settings: serde_json::Value =
        serde_json::from_slice(&fs::read(&settings_path).unwrap()).unwrap();
    assert_eq!(settings["theme"], "GitHub");
    assert_eq!(settings["mcpServers"]["other"]["command"], "other-mcp");
    let phantom = &settings["mcpServers"]["phantom"];
    assert!(phantom["command"].as_str().is_some_and(|c| !c.is_empty()));
    assert!(phantom["args"].is_array());

    let status = Command::cargo_bin("phantom")
        .unwrap()
        .args(["setup", "--status", "--json"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(status.status.success());
    let rows: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    let gemini = rows
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == "gemini")
        .unwrap();
    assert_eq!(gemini["state"], "wired", "{rows}");

    let printed = Command::cargo_bin("phantom")
        .unwrap()
        .args(["setup", "--client", "gemini", "--print"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(printed.status.success());
    assert!(String::from_utf8_lossy(&printed.stdout).contains("~/.gemini/settings.json"));
}
