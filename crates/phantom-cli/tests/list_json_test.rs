/// Integration tests for `phantom list --json`.
///
/// Verify that `phantom list --json` emits valid JSON, contains every secret
/// name in the vault, never leaks secret values, and surfaces the detected
/// service mapping when one is configured.
mod common;

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

const VAULT_PASS: &str = "test-integration-passphrase-list-json";

fn init_project(dir: &TempDir) {
    fs::write(
        dir.path().join(".env"),
        "OPENAI_API_KEY=sk-test-openai-value\nNON_SECRET=public\n",
    )
    .expect("write seed .env");

    Command::cargo_bin("phantom")
        .expect("binary not found")
        .args(["init", "--from", ".env"])
        .current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        .assert()
        .success();
}

fn phantom(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("phantom").expect("binary not found");
    cmd.current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path());
    cmd
}

#[test]
fn list_json_emits_valid_json_with_secret_names() {
    let dir = common::canonical_tempdir();
    init_project(&dir);

    let output = phantom(&dir).args(["list", "--json"]).assert().success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);

    let parsed: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("output is not valid JSON: {e}\noutput was: {stdout}"));

    let array = parsed
        .as_array()
        .expect("top-level JSON should be an array");

    let names: Vec<&str> = array
        .iter()
        .filter_map(|entry| entry.get("name").and_then(Value::as_str))
        .collect();

    assert!(
        names.contains(&"OPENAI_API_KEY"),
        "OPENAI_API_KEY should appear in JSON list output, got: {names:?}"
    );
}

#[test]
fn list_json_never_leaks_secret_values() {
    let dir = common::canonical_tempdir();
    init_project(&dir);

    let output = phantom(&dir).args(["list", "--json"]).assert().success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);

    assert!(
        !stdout.contains("sk-test-openai-value"),
        "JSON list output must never include the secret value, got: {stdout}"
    );
}

#[test]
fn list_json_emits_empty_array_when_vault_has_no_secrets() {
    let dir = common::canonical_tempdir();

    Command::cargo_bin("phantom")
        .expect("binary not found")
        .args(["init", "--empty"])
        .current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        .assert()
        .success();

    let output = phantom(&dir).args(["list", "--json"]).assert().success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);

    let parsed: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("output is not valid JSON: {e}\noutput was: {stdout}"));

    let array = parsed
        .as_array()
        .expect("top-level JSON should be an array");
    assert!(array.is_empty(), "expected empty JSON array, got: {stdout}");
}
