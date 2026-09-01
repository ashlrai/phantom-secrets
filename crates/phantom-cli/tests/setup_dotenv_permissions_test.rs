mod common;

use assert_cmd::Command;
use serde_json::{json, Value};
use std::fs;
use tempfile::TempDir;

fn legacy_settings() -> Value {
    json!({
        "permissions": {
            "allow": [
                "Read(./.env)",
                "Read(./.env.*)",
                "Read(./.env.example)",
                "Bash(cargo test:*)"
            ],
            "deny": ["Read(./.env)", "Read(./.env.*)", "Read(./secrets/**)"]
        }
    })
}

fn write_legacy_settings(dir: &TempDir) -> std::path::PathBuf {
    let claude_dir = dir.path().join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();
    let path = claude_dir.join("settings.local.json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&legacy_settings()).unwrap(),
    )
    .unwrap();
    path
}

fn assert_hardened(path: &std::path::Path) {
    let settings: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(
        settings["permissions"]["allow"],
        json!(["Read(./.env.example)", "Bash(cargo test:*)"])
    );
    assert_eq!(
        settings["permissions"]["deny"],
        json!(["Read(./.env)", "Read(./.env.*)", "Read(./secrets/**)"])
    );
}

#[test]
fn explicit_claude_setup_removes_only_legacy_exact_allows() {
    let dir = common::canonical_tempdir();
    let settings_path = write_legacy_settings(&dir);

    Command::cargo_bin("phantom")
        .unwrap()
        .args(["setup", "--client", "claude"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .assert()
        .success();

    assert_hardened(&settings_path);
}

#[test]
fn init_auto_setup_removes_only_legacy_exact_allows() {
    let dir = common::canonical_tempdir();
    let settings_path = write_legacy_settings(&dir);
    fs::write(
        dir.path().join(".env"),
        "OPENAI_API_KEY=sk-test-only-value\n",
    )
    .unwrap();

    Command::cargo_bin("phantom")
        .unwrap()
        .args(["init", "--from", ".env"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env(
            "PHANTOM_VAULT_PASSPHRASE",
            "setup-permission-test-vault-passphrase",
        )
        .assert()
        .success();

    assert_hardened(&settings_path);
}

#[test]
fn init_migrates_npx_to_the_bundled_local_runtime() {
    let dir = common::canonical_tempdir();
    let claude_dir = dir.path().join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();
    let settings_path = claude_dir.join("settings.local.json");
    fs::write(
        &settings_path,
        serde_json::to_vec_pretty(&json!({
            "mcpServers": {
                "phantom": {
                    "command": "npx",
                    "args": ["-y", "phantom-secrets-mcp"]
                },
                "other": {"command": "other-server"}
            },
            "theme": "dark"
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        dir.path().join(".env"),
        "OPENAI_API_KEY=sk-test-only-value\n",
    )
    .unwrap();

    Command::cargo_bin("phantom")
        .unwrap()
        .args(["init", "--from", ".env"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env(
            "PHANTOM_VAULT_PASSPHRASE",
            "setup-local-runtime-test-vault-passphrase",
        )
        .assert()
        .success();

    let settings: Value = serde_json::from_slice(&fs::read(settings_path).unwrap()).unwrap();
    let phantom = &settings["mcpServers"]["phantom"];
    assert_ne!(phantom["command"], "npx");
    assert_eq!(phantom["args"], json!(["mcp", "serve"]));
    assert_eq!(settings["mcpServers"]["other"]["command"], "other-server");
    assert_eq!(settings["theme"], "dark");
    assert!(!settings.to_string().contains("phantom-secrets-mcp"));
}

#[test]
fn rerun_init_migrates_stale_setup_without_rotating_tokens() {
    let dir = common::canonical_tempdir();
    std::process::Command::new("git")
        .arg("init")
        .arg("--quiet")
        .current_dir(dir.path())
        .status()
        .unwrap();
    let claude_dir = dir.path().join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();
    let settings_path = claude_dir.join("settings.local.json");
    fs::write(&settings_path, b"{}\n").unwrap();
    let env_path = dir.path().join(".env");
    fs::write(&env_path, "OPENAI_API_KEY=sk-test-only-value\n").unwrap();

    let init = || {
        Command::cargo_bin("phantom")
            .unwrap()
            .args(["init", "--from", ".env"])
            .current_dir(dir.path())
            .env("HOME", dir.path())
            .env(
                "PHANTOM_VAULT_PASSPHRASE",
                "setup-rerun-migration-test-vault-passphrase",
            )
            .assert()
            .success();
    };
    init();
    let protected_env = fs::read(&env_path).unwrap();
    let original_config = fs::read(dir.path().join(".phantom.toml")).unwrap();

    fs::write(
        &settings_path,
        serde_json::to_vec_pretty(&json!({
            "mcpServers": {
                "phantom": {
                    "command": "npx",
                    "args": ["-y", "phantom-secrets-mcp"]
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let hook_path = dir.path().join(".git/hooks/pre-commit");
    fs::write(
        &hook_path,
        "#!/bin/sh\necho existing\nexit 0\n# Phantom Secrets pre-commit hook\nnpx phantom-secrets check --staged\n",
    )
    .unwrap();

    init();

    assert_eq!(fs::read(&env_path).unwrap(), protected_env);
    assert_eq!(
        fs::read(dir.path().join(".phantom.toml")).unwrap(),
        original_config
    );
    let settings: Value = serde_json::from_slice(&fs::read(&settings_path).unwrap()).unwrap();
    assert_ne!(settings["mcpServers"]["phantom"]["command"], "npx");
    assert_eq!(
        settings["mcpServers"]["phantom"]["args"],
        json!(["mcp", "serve"])
    );
    let repaired_hook = fs::read_to_string(&hook_path).unwrap();
    assert!(phantom_core::precommit_hook::is_current(&repaired_hook));
    assert!(!repaired_hook.contains("npx"));
    assert!(repaired_hook.find("phantom check").unwrap() < repaired_hook.find("exit 0").unwrap());

    let stable_settings = fs::read(&settings_path).unwrap();
    init();
    assert_eq!(fs::read(&env_path).unwrap(), protected_env);
    assert_eq!(fs::read(&settings_path).unwrap(), stable_settings);
    assert_eq!(fs::read_to_string(&hook_path).unwrap(), repaired_hook);
}

#[test]
fn init_invalid_claude_config_fails_before_project_mutation() {
    let dir = common::canonical_tempdir();
    let claude_dir = dir.path().join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();
    let settings_path = claude_dir.join("settings.local.json");
    let invalid_settings = b"{ invalid json\n";
    fs::write(&settings_path, invalid_settings).unwrap();
    let env_path = dir.path().join(".env");
    let original_env = b"OPENAI_API_KEY=sk-test-only-value\n";
    fs::write(&env_path, original_env).unwrap();

    Command::cargo_bin("phantom")
        .unwrap()
        .args(["init", "--from", ".env"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env(
            "PHANTOM_VAULT_PASSPHRASE",
            "setup-invalid-config-test-vault-passphrase",
        )
        .assert()
        .failure();

    assert_eq!(fs::read(&settings_path).unwrap(), invalid_settings);
    assert_eq!(fs::read(&env_path).unwrap(), original_env);
    assert!(!dir.path().join(".phantom.toml").exists());
    assert!(!dir.path().join(".env.example").exists());
}
