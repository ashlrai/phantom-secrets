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
    let dir = TempDir::new().unwrap();
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
    let dir = TempDir::new().unwrap();
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
