mod common;

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

fn phantom(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("phantom").expect("binary not found");
    cmd.current_dir(dir.path())
        .env("HOME", dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", "test-passphrase");
    cmd
}

#[test]
fn agent_report_json_is_stable_and_blocks_unsafe_repo() {
    let dir = common::canonical_tempdir();
    fs::write(dir.path().join(".env"), "OPENAI_API_KEY=sk-test\n").unwrap();

    let output = phantom(&dir)
        .args(["agent", "report", "--json"])
        .assert()
        .failure();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    let value: Value = serde_json::from_str(&stdout).expect("valid readiness json");

    assert_eq!(value["status"], "unsafe");
    assert_eq!(value["risk_level"], "high");
    assert_eq!(value["exit_code"], 1);
    assert!(value["findings"].as_array().unwrap().iter().any(|finding| {
        finding["id"] == "missing-config" || finding["id"] == "unprotected-env-secrets"
    }));
    assert!(value["commands"]
        .as_array()
        .unwrap()
        .iter()
        .any(|command| command == "phantom init"));
}

#[test]
fn agent_setup_dry_run_prints_report_without_mutating_files() {
    let dir = common::canonical_tempdir();
    fs::write(dir.path().join(".env"), "OPENAI_API_KEY=sk-test\n").unwrap();

    let output = phantom(&dir)
        .args(["agent", "setup", "--dry-run"])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(stdout.contains("Phantom Agent Setup Dry Run"));
    assert!(stdout.contains("\"status\": \"unsafe\""));
    assert!(!dir.path().join(".phantom.toml").exists());
    assert!(!dir.path().join(".env.example").exists());
}
